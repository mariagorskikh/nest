# SPDX-License-Identifier: Apache-2.0
"""PravaPayments — NANDA Town Payments Protocol adapter for Prava.

Example::

    from nest_plugins_prava import PravaPayments
    from nest_sdk import AgentId, Money, PaymentRef

    pay = PravaPayments(AgentId("alice"), initial_balance=1000)
    receipt = await pay.pay(AgentId("bob"), Money(amount=50), PaymentRef("p1"))
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from typing import Any

from nest_sdk import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)

from nest_plugins_prava.client import (
    MockPravaClient,
    PaymentResultView,
    PravaClient,
    build_client,
    default_service_price,
)
from nest_plugins_prava.errors import (
    DuplicatePaymentRefError,
    InsufficientFundsError,
    InvalidPaymentStateError,
    PaymentNotFoundError,
    PravaAdapterError,
    PravaDeclinedError,
    PravaTimeoutError,
    QuoteExpiredError,
)
from nest_plugins_prava.journal import hydrate_from_journal, persist_record
from nest_plugins_prava.mapping import (
    DEFAULT_CURRENCY,
    DEFAULT_MERCHANT_COUNTRY,
    DEFAULT_MERCHANT_NAME,
    DEFAULT_MERCHANT_URL,
    agent_to_email,
    agent_to_user_id,
    credits_to_decimal_amount,
)
from nest_plugins_prava.secrets import assert_no_secrets
from nest_plugins_prava.state import PaymentPhase, PaymentRecord, QuoteRecord

# Sidecar store so marketplace-shared plain dicts still carry Prava records.
_RECORDS_BY_LEDGER: dict[int, dict[PaymentRef, PaymentRecord]] = {}
_QUOTES_BY_LEDGER: dict[int, dict[str, QuoteRecord]] = {}
_CLIENT_BY_LEDGER: dict[int, PravaClient] = {}
_LOCKS_BY_LEDGER: dict[int, asyncio.Lock] = {}
# Cross-thread gate (asyncio.Lock alone does NOT protect ThreadPoolExecutor).
_THREAD_LOCKS_BY_LEDGER: dict[int, threading.Lock] = {}


def _records_for(payments: dict[PaymentRef, Any]) -> dict[PaymentRef, PaymentRecord]:
    key = id(payments)
    store = _RECORDS_BY_LEDGER.get(key)
    if store is None:
        store = {}
        _RECORDS_BY_LEDGER[key] = store
    return store


def _quotes_for(payments: dict[PaymentRef, Any]) -> dict[str, QuoteRecord]:
    key = id(payments)
    store = _QUOTES_BY_LEDGER.get(key)
    if store is None:
        store = {}
        _QUOTES_BY_LEDGER[key] = store
    return store


def _lock_for(payments: dict[PaymentRef, Any]) -> asyncio.Lock:
    key = id(payments)
    lock = _LOCKS_BY_LEDGER.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS_BY_LEDGER[key] = lock
    return lock


def _thread_lock_for(payments: dict[PaymentRef, Any]) -> threading.Lock:
    key = id(payments)
    lock = _THREAD_LOCKS_BY_LEDGER.get(key)
    if lock is None:
        lock = threading.Lock()
        _THREAD_LOCKS_BY_LEDGER[key] = lock
    return lock


async def _acquire_thread_lock(lock: threading.Lock) -> None:
    """Acquire a threading.Lock without blocking the event loop or deadlocking tasks."""
    while True:
        if lock.acquire(blocking=False):
            return
        await asyncio.sleep(0.001)


class PravaPayments:
    """Payments Protocol implementation backed by Prava sandbox/mock.

    Compatible with NANDA marketplace construction::

        PravaPayments(agent_id, initial_balance=0, balances=shared, payments=shared)

    Example::

        pay = PravaPayments(AgentId("a1"), initial_balance=1000)
        q = await pay.quote(ServiceRef("compute"))
        receipt = await pay.pay(AgentId("a2"), q.price, PaymentRef("r1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Any] | None = None,
        *,
        client: PravaClient | None = None,
        mode: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        currency: str = DEFAULT_CURRENCY,
        credits_per_unit: int = 100,
        default_fee: int | None = None,
        poll_attempts: int = 8,
        poll_interval_s: float = 0.01,
        merchant_name: str = DEFAULT_MERCHANT_NAME,
        merchant_url: str = DEFAULT_MERCHANT_URL,
        merchant_country: str = DEFAULT_MERCHANT_COUNTRY,
        journal: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._payments = payments if payments is not None else {}
        self._records = _records_for(self._payments)
        self._quotes = _quotes_for(self._payments)
        self._lock = _lock_for(self._payments)
        self._thread_lock = _thread_lock_for(self._payments)
        self._journal = journal
        self._currency = currency
        self._credits_per_unit = credits_per_unit
        self._default_fee = default_fee
        self._poll_attempts = poll_attempts
        self._poll_interval_s = poll_interval_s
        self._merchant_name = merchant_name
        self._merchant_url = merchant_url
        self._merchant_country = merchant_country

        if journal:
            hydrate_from_journal(journal, self._records, self._payments)

        ledger_key = id(self._payments)
        if client is not None:
            self._client = client
            _CLIENT_BY_LEDGER[ledger_key] = client
        elif ledger_key in _CLIENT_BY_LEDGER:
            self._client = _CLIENT_BY_LEDGER[ledger_key]
        else:
            self._client = build_client(mode=mode, api_key=api_key, base_url=base_url)
            _CLIENT_BY_LEDGER[ledger_key] = self._client

    @property
    def client(self) -> PravaClient:
        """Underlying Prava client (mock/live/hybrid)."""
        return self._client

    def balance(self, agent: AgentId) -> int:
        """Return an agent's available credit balance.

        Example::

            bal = pay.balance(AgentId("alice"))
        """
        return self._balances.get(agent, 0)

    def top_up(self, agent: AgentId, amount: int) -> int:
        """Credit an agent's local budget (simulation helper).

        Example::

            pay.top_up(AgentId("alice"), 100)
        """
        if amount <= 0:
            msg = f"top_up amount must be positive: {amount}"
            raise ValueError(msg)
        self._balances[agent] = self._balances.get(agent, 0) + amount
        return self._balances[agent]

    def payment_record(self, ref: PaymentRef) -> PaymentRecord | None:
        """Return the internal record for diagnostics (no secrets).

        Example::

            rec = pay.payment_record(PaymentRef("p1"))
        """
        return self._records.get(ref)

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a price quote for a service and cache it with TTL.

        Example::

            q = await pay.quote(ServiceRef("data-cleaning"))
        """
        price = (
            self._default_fee
            if self._default_fee is not None
            else default_service_price(str(service))
        )
        ttl = 300
        self._quotes[str(service)] = QuoteRecord(
            service=str(service),
            price_credits=price,
            expires_at=time.time() + ttl,
            currency="credits",
        )
        return Quote(
            service=service,
            price=Money(amount=price, currency="credits"),
            ttl_seconds=ttl,
            metadata={
                "rail": "prava",
                "prava_currency": self._currency,
                "prava_amount": credits_to_decimal_amount(
                    price, credits_per_unit=self._credits_per_unit
                ),
            },
        )

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a payment: local budget lock → Prava session → confirm.

        Example::

            receipt = await pay.pay(AgentId("bob"), Money(amount=50), PaymentRef("p1"))
        """
        # Thread gate first (ThreadPoolExecutor), then asyncio gate (same-loop tasks).
        await _acquire_thread_lock(self._thread_lock)
        try:
            async with self._lock:
                return await self._pay_locked(to, amount, ref)
        finally:
            self._thread_lock.release()

    async def _pay_locked(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)

        existing = self._records.get(ref)
        if existing is not None:
            if (
                existing.payee == to
                and existing.amount.amount == amount.amount
                and existing.status in {PaymentStatus.CONFIRMED, PaymentStatus.PENDING}
            ):
                return existing.to_receipt()
            if existing.status == PaymentStatus.FAILED:
                # Allow retry on the same ref after a clean failure.
                self._records.pop(ref, None)
                self._payments.pop(ref, None)
            else:
                raise DuplicatePaymentRefError(
                    f"Duplicate payment reference with conflicting state: {ref}",
                    code="DUPLICATE_REF",
                )

        # Optional quote TTL enforcement when a quote exists for this amount.
        self._enforce_quote_freshness(amount.amount)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            raise InsufficientFundsError(
                f"Insufficient balance: {payer_balance} < {amount.amount}",
                code="INSUFFICIENT_FUNDS",
            )

        # Atomic local lock before any network call (prevents overspend on retry).
        self._balances[self._agent_id] = payer_balance - amount.amount
        record = PaymentRecord(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=amount,
            phase=PaymentPhase.BUDGET_LOCKED,
            status=PaymentStatus.PENDING,
            locked_credits=amount.amount,
        )
        self._records[ref] = record
        self._payments[ref] = record.to_receipt()

        try:
            session = await self._client.create_session(self._session_body(to, amount, ref))
            record.session_id = session.session_id
            record.order_id = session.order_id
            record.response_id = session.response_id
            record.phase = PaymentPhase.SESSION_CREATED
            record.touch()
            assert_no_secrets(session.public_view(), label="session")

            result = await self._poll_until_ready(session.session_id)
            record.txn_ref_id = result.txn_ref_id
            record.response_id = result.response_id or record.response_id
            record.phase = PaymentPhase.AWAITING_RESULT
            record.touch()
            assert_no_secrets(result.public_view(), label="payment_result")

            if result.status == "failed":
                raise PravaDeclinedError(
                    f"Prava payment-result status=failed for session={session.session_id}",
                    code="PAYMENT_FAILED",
                    response_id=result.response_id,
                )

            txn_ref = result.txn_ref_id or f"tli-{ref}"
            report = await self._client.report_status(
                session.session_id,
                txn_ref_id=txn_ref,
                txn_status="APPROVED",
            )
            record.phase = PaymentPhase.REPORTED
            record.response_id = report.response_id or record.response_id
            record.touch()

            if report.txn_status != "APPROVED":
                raise PravaDeclinedError(
                    f"Prava declined payment ref={ref} txn_status={report.txn_status}",
                    code="DECLINED",
                    response_id=report.response_id,
                )

            # Settle to payee only after rail confirmation.
            self._balances[to] = self._balances.get(to, 0) + amount.amount
            record.phase = PaymentPhase.CONFIRMED
            record.status = PaymentStatus.CONFIRMED
            record.locked_credits = 0
            record.touch()
            receipt = record.to_receipt()
            self._payments[ref] = receipt
            persist_record(self._journal, record)
            assert_no_secrets(record.public_view(), label="payment_record")
            return receipt
        except PravaAdapterError as exc:
            await self._fail_and_release(record, exc)
            raise
        except Exception as exc:
            wrapped = PravaAdapterError(str(exc), code="UNEXPECTED")
            await self._fail_and_release(record, wrapped)
            raise wrapped from exc

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify payment status by reference.

        Example::

            status = await pay.verify_payment(PaymentRef("p1"))
        """
        record = self._records.get(ref)
        if record is None:
            return PaymentStatus.FAILED
        if (
            record.status == PaymentStatus.PENDING
            and record.session_id
            and record.phase
            in {PaymentPhase.SESSION_CREATED, PaymentPhase.AWAITING_RESULT, PaymentPhase.REPORTED}
        ):
            try:
                view = await self._client.get_payment_result(record.session_id)
                if view.status == "completed":
                    return PaymentStatus.PENDING
                if view.status == "failed":
                    return PaymentStatus.FAILED
            except PravaAdapterError:
                return record.status
        return record.status

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a confirmed payment back to the payer.

        Example::

            await pay.refund(PaymentRef("p1"))
        """
        await _acquire_thread_lock(self._thread_lock)
        try:
            async with self._lock:
                await self._refund_locked(ref)
        finally:
            self._thread_lock.release()

    async def _refund_locked(self, ref: PaymentRef) -> None:
        record = self._records.get(ref)
        if record is None:
            raise PaymentNotFoundError(f"Payment not found: {ref}", code="NOT_FOUND")
        if record.status == PaymentStatus.REFUNDED:
            # Idempotent no-op: do NOT call Prava again, do NOT double-credit.
            return
        if record.status == PaymentStatus.PENDING:
            raise InvalidPaymentStateError(
                f"Cannot refund PENDING payment: {ref}",
                code="INVALID_STATE",
            )
        if record.status != PaymentStatus.CONFIRMED:
            # Covers FAILED / declined — never invent a Prava refund rail call.
            raise InvalidPaymentStateError(
                f"Payment not refundable in status={record.status.value}: {ref}",
                code="INVALID_STATE",
            )

        payee_balance = self._balances.get(record.payee, 0)
        if payee_balance < record.amount.amount:
            raise InsufficientFundsError(
                f"Insufficient balance for refund: {record.payee} has "
                f"{payee_balance}, needs {record.amount.amount}",
                code="INSUFFICIENT_FUNDS",
            )

        self._balances[record.payee] = payee_balance - record.amount.amount
        self._balances[record.payer] = self._balances.get(record.payer, 0) + record.amount.amount
        record.status = PaymentStatus.REFUNDED
        record.phase = PaymentPhase.REFUNDED
        record.touch()
        # Keep record for idempotent re-refund; drop receipt mapping.
        self._payments.pop(ref, None)
        persist_record(self._journal, record)
        # NOTE: refund is local-ledger only today — no Prava refund API is invoked.

    def _enforce_quote_freshness(self, amount: int) -> None:
        # If any quote matches this amount and all such quotes are expired, reject.
        matching = [q for q in self._quotes.values() if q.price_credits == amount]
        if not matching:
            return
        now = time.time()
        if all(q.expires_at < now for q in matching):
            raise QuoteExpiredError(
                f"Quote(s) for amount={amount} expired; re-quote before pay",
                code="QUOTE_EXPIRED",
            )

    def _session_body(self, to: AgentId, amount: Money, ref: PaymentRef) -> dict[str, Any]:
        decimal_amount = credits_to_decimal_amount(
            amount.amount, credits_per_unit=self._credits_per_unit
        )
        return {
            "user_id": agent_to_user_id(self._agent_id),
            "user_email": agent_to_email(self._agent_id),
            "total_amount": decimal_amount,
            "currency": self._currency,
            "purchase_context": [
                {
                    "merchant_details": {
                        "name": self._merchant_name,
                        "url": self._merchant_url,
                        "country_code_iso2": self._merchant_country,
                    },
                    "product_details": [
                        {
                            "description": f"NANDA transfer {self._agent_id}->{to} ref={ref}",
                            "unit_price": decimal_amount,
                            "quantity": 1,
                        }
                    ],
                }
            ],
            "integration_type": "full_checkout",
            "callback_url": f"{self._merchant_url}/prava/callback",
        }

    async def _poll_until_ready(self, session_id: str) -> PaymentResultView:
        last: PaymentResultView | None = None
        for attempt in range(self._poll_attempts):
            last = await self._client.get_payment_result(session_id)
            if last.status in {"awaiting_result", "completed", "failed"}:
                return last
            await asyncio.sleep(self._poll_interval_s * (1 + attempt * 0.1))
        last_status = last.status if last is not None else None
        raise PravaTimeoutError(
            f"Timed out polling payment-result for session={session_id} last={last_status}",
            code="POLL_TIMEOUT",
        )

    async def _fail_and_release(self, record: PaymentRecord, exc: PravaAdapterError) -> None:
        if record.locked_credits > 0 and record.status != PaymentStatus.CONFIRMED:
            self._balances[record.payer] = (
                self._balances.get(record.payer, 0) + record.locked_credits
            )
            record.locked_credits = 0
        if record.session_id:
            # Best-effort cleanup; original error is what callers need.
            with contextlib.suppress(Exception):
                await self._client.revoke_session(record.session_id)
        record.status = PaymentStatus.FAILED
        record.phase = PaymentPhase.FAILED
        record.error_code = exc.code
        record.error_message = str(exc)
        record.response_id = exc.response_id or record.response_id
        record.touch()
        self._payments[record.ref] = record.to_receipt()
        persist_record(self._journal, record)


def reset_ledger_sidecars() -> None:
    """Test helper: clear process-wide ledger sidecars."""
    _RECORDS_BY_LEDGER.clear()
    _QUOTES_BY_LEDGER.clear()
    _CLIENT_BY_LEDGER.clear()
    _LOCKS_BY_LEDGER.clear()
    _THREAD_LOCKS_BY_LEDGER.clear()


def attach_mock_client(payments: PravaPayments, mock: MockPravaClient) -> None:
    """Test helper: force a mock client onto an existing ledger."""
    payments._client = mock  # pyright: ignore[reportPrivateUsage]
    _CLIENT_BY_LEDGER[id(payments._payments)] = mock  # pyright: ignore[reportPrivateUsage]
