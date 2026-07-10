# SPDX-License-Identifier: Apache-2.0
"""EMPIC-style escrow payments with pull and pubsub settlement.

The plugin keeps Nanda Town's ``Payments`` protocol intact while exposing
EMPIC-shaped lifecycle methods for scenarios that model providers, consumers,
deliveries, and acceptance-gated release.

Example::

    payments = EMPICEscrowPayments(AgentId("consumer"), initial_balance=1000)
    payments.register_service(
        service_id=ServiceRef("weather"),
        provider=AgentId("provider"),
        price=Money(amount=50),
    )
    await payments.open_pull_escrow(AgentId("provider"), Money(amount=50), PaymentRef("p1"))
    await payments.fulfill(PaymentRef("p1"))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus, Quote, Receipt, ServiceRef

ESCROW_AGENT = AgentId("empic-escrow")
DeliveryMode = Literal["pull", "pubsub"]


@dataclass(frozen=True)
class PubsubTerms:
    """Subscription terms for an EMPIC-style pubsub service.

    Example::

        terms = PubsubTerms(rate_per_tick=10, max_total=100, min_valid_ratio=0.75)
    """

    rate_per_tick: int
    max_total: int
    duration_ticks: int
    min_valid_ratio: float = 1.0
    min_msg_count: int = 1
    auto_renew: bool = False


@dataclass(frozen=True)
class EMPICServiceRecord:
    """Provider service metadata registered with the payment adapter.

    Example::

        record = EMPICServiceRecord(
            service_id=ServiceRef("weather"),
            provider=AgentId("provider-0"),
            provider_did="did:empic:sandbox:provider-0",
            price=Money(amount=50),
            delivery_modes=("pull", "pubsub"),
        )
    """

    service_id: ServiceRef
    provider: AgentId
    provider_did: str
    price: Money
    delivery_modes: tuple[DeliveryMode, ...] = ("pull",)
    schema: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())
    pubsub_terms: PubsubTerms | None = None
    metadata: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())


@dataclass(frozen=True)
class EMPICDeliveryRecord:
    """Data delivery evidence observed for an escrow or stream.

    Example::

        delivery = EMPICDeliveryRecord(
            delivery_id="d1",
            ref=PaymentRef("p1"),
            service_id=ServiceRef("weather"),
            provider=AgentId("provider-0"),
            mode="pull",
            tick=3,
            accepted=True,
            data={"temperature_c": 20.0},
        )
    """

    delivery_id: str
    ref: PaymentRef
    service_id: ServiceRef
    provider: AgentId
    mode: DeliveryMode
    tick: int
    accepted: bool
    data: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())
    reason: str = ""


@dataclass
class EMPICPaymentRecord:
    """Internal escrow state for pull payments and pubsub streams.

    Example::

        record = payments.payment_record(PaymentRef("p1"))
        assert record.status is PaymentStatus.PENDING
    """

    ref: PaymentRef
    payer: AgentId
    payee: AgentId
    amount: Money
    mode: DeliveryMode
    status: PaymentStatus
    service_id: ServiceRef | None = None
    escrow_id: str = ""
    opened_at_tick: int = 0
    closed_at_tick: int | None = None
    rate_per_tick: int = 0
    max_total: int = 0
    escrowed: int = 0
    released: int = 0
    refunded: int = 0
    deliveries: list[EMPICDeliveryRecord] = field(default_factory=list[EMPICDeliveryRecord])
    billed_deliveries: set[str] = field(default_factory=set[str])
    metadata: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())


class EMPICEscrowPayments:
    """Deterministic EMPIC-shaped payment adapter for Nanda Town.

    Plain ``pay`` follows the generic Nanda Town ``Payments`` contract and
    confirms immediately. EMPIC pull escrows use ``open_pull_escrow`` and
    release funds only after a consumer accepts provider data and calls
    ``fulfill``. Pubsub streams pre-fund a maximum amount, release one tick of
    payment for each accepted delivery, and refund unused escrow on close.

    Example::

        pay = EMPICEscrowPayments(AgentId("buyer"), initial_balance=1000)
        receipt = await pay.pay(AgentId("seller"), Money(amount=25), PaymentRef("p1"))
        assert receipt.amount.amount == 25
        assert await pay.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, EMPICPaymentRecord] | None = None,
        services: dict[ServiceRef, EMPICServiceRecord] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._balances.setdefault(ESCROW_AGENT, 0)
        self._payments = payments if payments is not None else {}
        self._services = services if services is not None else {}

    def balance(self, agent: AgentId) -> int:
        """Return the local simulation balance for an agent.

        Example::

            assert payments.balance(AgentId("buyer")) >= 0
        """
        return self._balances.get(agent, 0)

    def register_service(
        self,
        service_id: ServiceRef,
        provider: AgentId,
        price: Money,
        *,
        provider_did: str | None = None,
        delivery_modes: tuple[DeliveryMode, ...] = ("pull",),
        schema: dict[str, Any] | None = None,
        pubsub_terms: PubsubTerms | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EMPICServiceRecord:
        """Register provider service metadata in the deterministic registry.

        Example::

            payments.register_service(ServiceRef("weather"), AgentId("p0"), Money(amount=50))
        """
        if price.amount <= 0:
            msg = f"service price must be positive: {price.amount}"
            raise ValueError(msg)
        if not delivery_modes:
            msg = "service must declare at least one delivery mode"
            raise ValueError(msg)
        if "pubsub" in delivery_modes and pubsub_terms is None:
            msg = "pubsub services require pubsub_terms"
            raise ValueError(msg)

        record = EMPICServiceRecord(
            service_id=service_id,
            provider=provider,
            provider_did=provider_did or f"did:empic:sandbox:{provider}",
            price=price,
            delivery_modes=delivery_modes,
            schema=schema or {},
            pubsub_terms=pubsub_terms,
            metadata=metadata or {},
        )
        self._services[service_id] = record
        self._balances.setdefault(provider, 0)
        return record

    def service_record(self, service_id: ServiceRef) -> EMPICServiceRecord | None:
        """Return registered service metadata, if any.

        Example::

            service = payments.service_record(ServiceRef("weather"))
        """
        return self._services.get(service_id)

    async def quote(self, service: ServiceRef) -> Quote:
        """Quote a registered service, defaulting to ten credits if unknown.

        Example::

            quote = await payments.quote(ServiceRef("weather"))
        """
        record = self._services.get(service)
        if record is None:
            return Quote(service=service, price=Money(amount=10))
        return Quote(
            service=service,
            price=record.price,
            metadata={
                "provider": str(record.provider),
                "provider_did": record.provider_did,
                "delivery_modes": list(record.delivery_modes),
            },
        )

    async def pay(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
        *,
        service_id: ServiceRef | None = None,
    ) -> Receipt:
        """Execute a generic immediate payment.

        When ``service_id`` is provided, this delegates to ``open_pull_escrow``
        for backwards-compatible EMPIC scenario support. Generic callers that
        use only the ``Payments`` protocol receive immediate settlement.

        Example::

            await payments.pay(
                AgentId("provider"),
                Money(amount=50),
                PaymentRef("pull-1"),
            )
        """
        if service_id is not None:
            return await self.open_pull_escrow(to, amount, ref, service_id=service_id)

        self._validate_new_payment(to, amount.amount, ref)
        self._move(self._agent_id, to, amount.amount)
        record = EMPICPaymentRecord(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=amount,
            mode="pull",
            status=PaymentStatus.CONFIRMED,
            escrow_id=f"generic:{ref}",
            max_total=amount.amount,
            released=amount.amount,
            metadata={"settlement": "immediate"},
        )
        self._payments[ref] = record
        return Receipt(ref=ref, payer=self._agent_id, payee=to, amount=amount)

    async def open_pull_escrow(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
        *,
        service_id: ServiceRef | None = None,
    ) -> Receipt:
        """Create an EMPIC pull escrow payment to a provider.

        The payer's balance moves into the escrow account. Provider credit only
        happens after ``fulfill``.

        Example::

            await payments.open_pull_escrow(
                AgentId("provider"),
                Money(amount=50),
                PaymentRef("pull-1"),
                service_id=ServiceRef("weather"),
            )
        """
        self._validate_new_payment(to, amount.amount, ref)
        self._move(self._agent_id, ESCROW_AGENT, amount.amount)
        record = EMPICPaymentRecord(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=amount,
            mode="pull",
            status=PaymentStatus.PENDING,
            service_id=service_id,
            escrow_id=f"empic-pull:{ref}",
            max_total=amount.amount,
            escrowed=amount.amount,
        )
        self._payments[ref] = record
        return Receipt(ref=ref, payer=self._agent_id, payee=to, amount=amount)

    async def open_stream(
        self,
        to: AgentId,
        rate_per_tick: int,
        max_total: int,
        ref: PaymentRef,
        *,
        service_id: ServiceRef | None = None,
        opened_at_tick: int = 0,
    ) -> EMPICPaymentRecord:
        """Open a pubsub stream with pre-funded maximum escrow.

        Example::

            record = await payments.open_stream(
                AgentId("provider"),
                rate_per_tick=5,
                max_total=25,
                ref=PaymentRef("stream-1"),
            )
        """
        if rate_per_tick <= 0:
            msg = f"rate_per_tick must be positive: {rate_per_tick}"
            raise ValueError(msg)
        if max_total < rate_per_tick:
            msg = f"max_total ({max_total}) must be >= rate_per_tick ({rate_per_tick})"
            raise ValueError(msg)
        self._validate_new_payment(to, max_total, ref)
        self._move(self._agent_id, ESCROW_AGENT, max_total)
        record = EMPICPaymentRecord(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=Money(amount=max_total),
            mode="pubsub",
            status=PaymentStatus.STREAMING,
            service_id=service_id,
            escrow_id=f"empic-pubsub:{ref}",
            opened_at_tick=opened_at_tick,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            escrowed=max_total,
        )
        self._payments[ref] = record
        return record

    def record_delivery(
        self,
        ref: PaymentRef,
        *,
        delivery_id: str,
        service_id: ServiceRef,
        provider: AgentId,
        mode: DeliveryMode,
        tick: int,
        accepted: bool,
        data: dict[str, Any] | None = None,
        reason: str = "",
    ) -> EMPICDeliveryRecord:
        """Attach provider delivery evidence to an escrow record.

        Example::

            payments.record_delivery(
                PaymentRef("p1"),
                delivery_id="d1",
                service_id=ServiceRef("weather"),
                provider=AgentId("provider"),
                mode="pull",
                tick=2,
                accepted=True,
                data={"temperature_c": 20.0},
            )
        """
        record = self._require_record(ref)
        delivery = EMPICDeliveryRecord(
            delivery_id=delivery_id,
            ref=ref,
            service_id=service_id,
            provider=provider,
            mode=mode,
            tick=tick,
            accepted=accepted,
            data=data or {},
            reason=reason,
        )
        record.deliveries.append(delivery)
        return delivery

    async def tick_stream(self, ref: PaymentRef, current_tick: int) -> bool:
        """Release one pubsub tick for an accepted unbilled delivery.

        Example::

            still_open = await payments.tick_stream(PaymentRef("stream-1"), 3)
        """
        record = self._require_record(ref)
        if record.mode != "pubsub":
            msg = f"Payment is not a pubsub stream: {ref}"
            raise ValueError(msg)
        if record.closed_at_tick is not None or record.status is not PaymentStatus.STREAMING:
            return False

        delivery = self._next_billable_delivery(record, current_tick)
        if delivery is None:
            return True

        amount = min(record.rate_per_tick, record.escrowed)
        if amount <= 0:
            record.closed_at_tick = current_tick
            record.status = PaymentStatus.CONFIRMED
            return False

        self._move(ESCROW_AGENT, record.payee, amount)
        record.escrowed -= amount
        record.released += amount
        record.billed_deliveries.add(delivery.delivery_id)

        if record.escrowed == 0 or record.released >= record.max_total:
            record.closed_at_tick = current_tick
            record.status = PaymentStatus.CONFIRMED
            return False
        return True

    async def close_stream(self, ref: PaymentRef, current_tick: int = 0) -> Receipt:
        """Close a pubsub stream and refund unused escrow.

        Example::

            receipt = await payments.close_stream(PaymentRef("stream-1"), current_tick=10)
        """
        record = self._require_record(ref)
        if record.mode != "pubsub":
            msg = f"Payment is not a pubsub stream: {ref}"
            raise ValueError(msg)
        if record.closed_at_tick is None:
            record.closed_at_tick = current_tick
        if record.escrowed > 0:
            self._move(ESCROW_AGENT, record.payer, record.escrowed)
            record.refunded += record.escrowed
            record.escrowed = 0
        record.status = PaymentStatus.CONFIRMED if record.released > 0 else PaymentStatus.REFUNDED
        return Receipt(
            ref=ref,
            payer=record.payer,
            payee=record.payee,
            amount=Money(amount=record.released),
        )

    async def fulfill(
        self,
        ref: PaymentRef,
        evidence: EMPICDeliveryRecord | None = None,
    ) -> Receipt:
        """Release a pull escrow to the provider after acceptable delivery.

        Example::

            receipt = await payments.fulfill(PaymentRef("pull-1"))
        """
        record = self._require_record(ref)
        if record.mode != "pull":
            msg = f"Payment is not a pull escrow: {ref}"
            raise ValueError(msg)
        if record.status is not PaymentStatus.PENDING:
            msg = f"Payment is not pending: {ref}"
            raise ValueError(msg)
        if evidence is None:
            evidence = next(
                (
                    d
                    for d in record.deliveries
                    if d.accepted and self._delivery_matches_record(record, d)
                ),
                None,
            )
        if (
            evidence is None
            or not evidence.accepted
            or not self._delivery_matches_record(record, evidence)
        ):
            msg = f"Cannot fulfill {ref}: no acceptable delivery evidence"
            raise ValueError(msg)

        amount = record.escrowed
        self._move(ESCROW_AGENT, record.payee, amount)
        record.escrowed = 0
        record.released += amount
        record.status = PaymentStatus.CONFIRMED
        return Receipt(ref=ref, payer=record.payer, payee=record.payee, amount=Money(amount=amount))

    async def reject(
        self,
        ref: PaymentRef,
        *,
        reason: str,
        data_ref: str = "",
    ) -> None:
        """Reject provider data and refund the remaining escrow.

        Example::

            await payments.reject(PaymentRef("pull-1"), reason="temperature out of range")
        """
        record = self._require_record(ref)
        record.metadata["reject_reason"] = reason
        if data_ref:
            record.metadata["data_ref"] = data_ref
        await self.refund(ref)

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Return the current payment or stream status.

        Example::

            assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING
        """
        record = self._payments.get(ref)
        if record is None:
            return PaymentStatus.FAILED
        return record.status

    async def refund(self, ref: PaymentRef) -> None:
        """Refund remaining escrow to the payer.

        Example::

            await payments.refund(PaymentRef("p1"))
        """
        record = self._require_record(ref)
        if record.status in (PaymentStatus.CONFIRMED, PaymentStatus.REFUNDED):
            msg = f"Payment already terminal: {ref}"
            raise ValueError(msg)
        if record.escrowed > 0:
            self._move(ESCROW_AGENT, record.payer, record.escrowed)
            record.refunded += record.escrowed
            record.escrowed = 0
        record.closed_at_tick = record.closed_at_tick if record.closed_at_tick is not None else 0
        record.status = PaymentStatus.REFUNDED

    def payment_record(self, ref: PaymentRef) -> EMPICPaymentRecord | None:
        """Return internal EMPIC escrow state for inspection.

        Example::

            record = payments.payment_record(PaymentRef("p1"))
        """
        return self._payments.get(ref)

    def _validate_new_payment(self, to: AgentId, amount: int, ref: PaymentRef) -> None:
        if amount <= 0:
            msg = f"Payment amount must be positive: {amount}"
            raise ValueError(msg)
        if ref in self._payments:
            msg = f"Duplicate payment reference: {ref}"
            raise ValueError(msg)
        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount:
            msg = f"Insufficient balance: {payer_balance} < {amount}"
            raise ValueError(msg)
        self._balances.setdefault(to, 0)

    def _require_record(self, ref: PaymentRef) -> EMPICPaymentRecord:
        record = self._payments.get(ref)
        if record is None:
            msg = f"Payment not found: {ref}"
            raise ValueError(msg)
        return record

    def _move(self, src: AgentId, dst: AgentId, amount: int) -> None:
        if amount < 0:
            msg = f"Cannot move negative amount: {amount}"
            raise ValueError(msg)
        if self._balances.get(src, 0) < amount:
            msg = f"Insufficient balance for {src}: {self._balances.get(src, 0)} < {amount}"
            raise ValueError(msg)
        self._balances[src] = self._balances.get(src, 0) - amount
        self._balances[dst] = self._balances.get(dst, 0) + amount

    def _next_billable_delivery(
        self,
        record: EMPICPaymentRecord,
        current_tick: int,
    ) -> EMPICDeliveryRecord | None:
        for delivery in record.deliveries:
            if delivery.delivery_id in record.billed_deliveries:
                continue
            if not delivery.accepted:
                continue
            if not self._delivery_matches_record(record, delivery):
                continue
            if delivery.tick != current_tick:
                continue
            return delivery
        return None

    def _delivery_matches_record(
        self,
        record: EMPICPaymentRecord,
        delivery: EMPICDeliveryRecord,
    ) -> bool:
        if delivery.ref != record.ref:
            return False
        if delivery.provider != record.payee:
            return False
        if delivery.mode != record.mode:
            return False
        return record.service_id is None or delivery.service_id == record.service_id
