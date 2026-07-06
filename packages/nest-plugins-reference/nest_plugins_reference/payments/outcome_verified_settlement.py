# SPDX-License-Identifier: Apache-2.0
"""Outcome-verified settlement plugin: per-tick metered streams with deterministic cancellation.

This plugin satisfies the :class:`nest_core.layers.payments.Payments` protocol and
adds a streaming surface: a payer opens a stream that drains funds to a payee one
logical tick at a time, capped at a maximum total, and either party may close the
stream at any tick. The unused remainder is never spent.

No code is ported from any on-chain system; only the spending-bound semantics
(pay for the delivered prefix, stop authorizing on close) are reused.

Example::

    pay = OutcomeVerifiedSettlement(AgentId("a1"), initial_balance=1000)
    handle = await pay.open_stream(
        AgentId("a2"), rate_per_tick=5, max_total=50,
        ref=PaymentRef("s1"), opened_at_tick=0,
    )
    await pay.advance(PaymentRef("s1"), now_tick=3)  # drains 15
    receipt = await pay.close_stream(PaymentRef("s1"), now_tick=3)
"""

from __future__ import annotations

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)
from pydantic import BaseModel


class StreamHandle(BaseModel):
    """State record for a single payment stream, keyed by its ``PaymentRef``.

    Example::

        handle = StreamHandle(
            ref=PaymentRef("s1"), payer=AgentId("a1"), payee=AgentId("a2"),
            rate_per_tick=5, max_total=50, opened_at_tick=0, last_tick=0,
        )
    """

    ref: PaymentRef
    payer: AgentId
    payee: AgentId
    rate_per_tick: int
    max_total: int
    opened_at_tick: int
    last_tick: int
    drained: int = 0
    closed_at_tick: int | None = None
    status: str = "open"


class OutcomeVerifiedSettlement:
    """Per-tick metered payment streams with deterministic mid-stream cancellation.

    Drop-in superset of the prepaid-credits ledger: shares the same ``balances``
    dict convention, adds ``open_stream`` / ``advance`` / ``close_stream``, and keeps
    the full :class:`nest_core.layers.payments.Payments` protocol (``quote`` /
    ``pay`` / ``verify_payment`` / ``refund``) working. ``pay`` is exactly a one-tick
    stream that drains the whole amount.

    Example::

        pay = OutcomeVerifiedSettlement(AgentId("a1"), initial_balance=1000)
        receipt = await pay.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        streams: dict[PaymentRef, StreamHandle] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
        half_open_status: PaymentStatus = PaymentStatus.STREAMING,
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._streams = streams if streams is not None else {}
        self._payments = payments if payments is not None else {}
        self._half_open_status = half_open_status

    def balance(self, agent: AgentId) -> int:
        """Check an agent's balance.

        Example::

            bal = pay.balance(AgentId("a1"))
        """
        return self._balances.get(agent, 0)

    # -- streaming surface --------------------------------------------------

    async def open_stream(
        self,
        to: AgentId,
        rate_per_tick: int,
        max_total: int,
        ref: PaymentRef,
        *,
        opened_at_tick: int = 0,
    ) -> StreamHandle:
        """Open a payment stream from this agent to ``to``.

        No funds move at open; draining happens per :meth:`advance`. The current
        tick is passed in explicitly (the caller reads the logical clock), so this
        plugin never reads wall-clock time.

        Example::

            handle = await pay.open_stream(
                AgentId("a2"), rate_per_tick=5, max_total=50,
                ref=PaymentRef("s1"), opened_at_tick=0,
            )
        """
        if rate_per_tick <= 0:
            msg = f"rate_per_tick must be positive: {rate_per_tick}"
            raise ValueError(msg)
        if max_total <= 0:
            msg = f"max_total must be positive: {max_total}"
            raise ValueError(msg)
        if ref in self._streams or ref in self._payments:
            msg = f"Duplicate payment reference: {ref}"
            raise ValueError(msg)

        handle = StreamHandle(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            opened_at_tick=opened_at_tick,
            last_tick=opened_at_tick,
        )
        self._streams[ref] = handle
        return handle

    async def advance(self, ref: PaymentRef, *, now_tick: int) -> int:
        """Drain the stream up to ``now_tick`` and return the units drained this call.

        Idempotent and monotonic: advancing to a tick already billed drains 0, the
        cumulative drain never exceeds ``max_total``, and a closed stream is a no-op.
        Every drained unit is debited from the payer and credited to the payee in the
        same step, so the ledger always conserves value.

        Example::

            units = await pay.advance(PaymentRef("s1"), now_tick=3)
        """
        handle = self._streams.get(ref)
        if handle is None:
            msg = f"Stream not found: {ref}"
            raise ValueError(msg)
        if handle.status != "open":
            return 0

        ticks_elapsed = max(0, now_tick - handle.last_tick)
        remaining = handle.max_total - handle.drained
        units = min(ticks_elapsed * handle.rate_per_tick, remaining)

        if units > 0:
            payer_balance = self._balances.get(handle.payer, 0)
            if payer_balance < units:
                msg = f"Insufficient balance: {payer_balance} < {units}"
                raise ValueError(msg)
            self._balances[handle.payer] = payer_balance - units
            self._balances[handle.payee] = self._balances.get(handle.payee, 0) + units
            handle.drained += units

        if now_tick > handle.last_tick:
            handle.last_tick = now_tick
        return units

    async def close_stream(self, ref: PaymentRef, *, now_tick: int | None = None) -> Receipt:
        """Close the stream at ``now_tick``, freezing it at the already-billed total.

        Billing is delivery-driven (see :meth:`advance`), so closing bills nothing
        further: it only freezes ``drained`` and records the close tick. Either party
        may call this. Idempotent: closing an already-closed stream returns the same
        receipt. The unused remainder (``max_total - drained``) is never spent.

        Example::

            receipt = await pay.close_stream(PaymentRef("s1"), now_tick=3)
        """
        handle = self._streams.get(ref)
        if handle is None:
            msg = f"Stream not found: {ref}"
            raise ValueError(msg)

        if handle.status == "open":
            handle.closed_at_tick = now_tick if now_tick is not None else handle.last_tick
            handle.status = "closed"
            receipt = Receipt(
                ref=ref,
                payer=handle.payer,
                payee=handle.payee,
                amount=Money(amount=handle.drained),
            )
            self._payments[ref] = receipt
        return self._payments[ref]

    # -- Payments protocol --------------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

            q = await pay.quote(ServiceRef("svc"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a one-shot payment: a stream that drains the whole amount in one tick.

        Example::

            receipt = await pay.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)
        await self.open_stream(
            to,
            rate_per_tick=amount.amount,
            max_total=amount.amount,
            ref=ref,
            opened_at_tick=0,
        )
        await self.advance(ref, now_tick=1)
        return await self.close_stream(ref, now_tick=1)

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify a payment/stream status by reference.

        Open streams return the half-open status (default
        :attr:`PaymentStatus.STREAMING`); closed streams and one-shot payments
        return :attr:`PaymentStatus.CONFIRMED`; refunded streams return
        :attr:`PaymentStatus.REFUNDED`; unknown references return
        :attr:`PaymentStatus.FAILED`.

        Example::

            status = await pay.verify_payment(PaymentRef("s1"))
        """
        handle = self._streams.get(ref)
        if handle is not None:
            if handle.status == "open":
                return self._half_open_status
            if handle.status == "refunded":
                return PaymentStatus.REFUNDED
            return PaymentStatus.CONFIRMED
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a closed stream or one-shot payment, reversing the drained amount.

        Open streams cannot be refunded; close them first.

        Example::

            await pay.refund(PaymentRef("p1"))
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            msg = f"Payment not found or stream still open: {ref}"
            raise ValueError(msg)

        payee_balance = self._balances.get(receipt.payee, 0)
        if payee_balance < receipt.amount.amount:
            msg = (
                f"Insufficient balance for refund: {receipt.payee} has "
                f"{payee_balance}, needs {receipt.amount.amount}"
            )
            raise ValueError(msg)

        self._balances[receipt.payee] = payee_balance - receipt.amount.amount
        self._balances[receipt.payer] = self._balances.get(receipt.payer, 0) + receipt.amount.amount
        del self._payments[ref]
        stream = self._streams.get(ref)
        if stream is not None:
            stream.status = "refunded"
