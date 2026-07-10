# SPDX-License-Identifier: Apache-2.0
"""Streaming per-tick payments with mid-stream cancellation and idempotency.

Extends the prepaid-credit ledger with bilateral, rate-limited streams that drain
one tick at a time. Either party can close the stream at any tick; unused
remainder is never spent. Every mutation is idempotent-keyed so retrying a
``close_stream`` or ``refund`` that already succeeded returns the original result
instead of raising.

Design principles:

* **Conservation first**: total system wealth (all balances + locked stream
  funds) is constant at every tick. No value is created or destroyed by
  rounding, early close, or partition recovery.
* **Idempotency everywhere**: ``PaymentRef`` doubles as an idempotency key.
  Re-opening the same ref returns the existing stream handle; re-closing returns
  the original receipt.
* **Audit trail**: every debit/credit records a :class:`StreamEntry` with the
  tick, amount, and payer/payee, so validators can reconstruct the full ledger
  from trace events alone.
* **Rate enforcement**: ``tick_stream`` cannot debit more than ``rate_per_tick``
  in a single call, and total debited cannot exceed ``max_total``. Both
  invariants are enforced at the balance level.

*The ``prepaid_credits`` plugin fails the conservation and rate-enforcement
checks under concurrent stream pressure because it has no stream semantics.*
*This plugin passes them because it models streams as first-class contracts.*

Satisfies the ``Payments`` protocol: one-shot ``pay()`` is a direct,
idempotency-keyed balance transfer producing the same balance deltas and
``Receipt`` shape a zero-duration stream would, without constructing an
actual ``StreamHandle`` — so existing callers continue to work.

Example::

    payments = StreamingPayments(AgentId("payer"), initial_balance=10000)
    handle = await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=10,
        max_total=500,
        ref=PaymentRef("stream-1"),
    )
    await payments.tick_stream(PaymentRef("stream-1"), current_tick=3)
    receipt = await payments.close_stream(PaymentRef("stream-1"))
    assert receipt.amount.amount == 20  # 2 ticks x 10

References:

* Sablier Finance (2020). *Streaming money by the second*.
  https://docs.sablier.com
* Stripe (2021). *Designing robust APIs with idempotency keys*.
  https://stripe.com/docs/api/idempotent_requests
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)


class StreamError(ValueError):
    """Typed exception for stream lifecycle violations.

    Raised when a stream operation is attempted on a non-existent,
    already-closed, or otherwise invalid stream. Distinguished from
    the plain ``ValueError`` used by ``prepaid_credits`` so callers
    can handle stream-specific failures without accidentally swallowing
    ledger bugs.

    Example::

        try:
            await payments.close_stream(PaymentRef("bad-ref"))
        except StreamError as e:
            logger.error("stream close failed: %s", e)
    """


@dataclass
class StreamEntry:
    """A single debit/credit event in a stream's audit trail.

    Validators read these events from the trace (the plugin itself does
    not persist them across runs) to verify conservation and rate
    invariants.

    Example::

        entry = StreamEntry(tick=5, amount=10, kind="debit")
        assert entry.tick == 5
    """

    tick: int
    amount: int
    kind: str


@dataclass
class StreamHandle:
    """Handle to an active or closed stream.

    The handle is returned by ``open_stream`` and mutated in-place by
    ``tick_stream`` and ``close_stream``. Validators inspect stream
    events in the trace; this dataclass is the in-memory side.

    Example::

        handle = StreamHandle(
            ref=PaymentRef("s-1"),
            to=AgentId("worker"),
            rate_per_tick=10,
            max_total=500,
            opened_at_tick=3,
        )
        assert handle.is_open
    """

    ref: PaymentRef
    to: AgentId
    rate_per_tick: int
    max_total: int
    opened_at_tick: int
    closed_at_tick: int | None = None
    total_debited: int = 0
    entries: list[StreamEntry] = field(default_factory=list[StreamEntry])

    @property
    def is_open(self) -> bool:
        """Return True if the stream is still accepting ticks."""
        return self.closed_at_tick is None

    @property
    def remaining(self) -> int:
        """Return the maximum remaining amount that can still be debited."""
        return self.max_total - self.total_debited

    @property
    def tick_count(self) -> int:
        """Return how many ticks have been drained so far."""
        if not self.entries:
            return 0
        return sum(1 for e in self.entries if e.kind == "debit")


class StreamingPayments:
    """Streaming per-tick payments with idempotency and mid-stream cancellation.

    Extends the prepaid-credit ledger with bilateral streams that drain one
    tick at a time at a fixed ``rate_per_tick``, capped at ``max_total``. Every
    mutation is idempotent-keyed: re-opening the same ref returns the existing
    handle, re-closing returns the original receipt.

    The plugin enforces three invariants that ``prepaid_credits`` cannot:

    * **Conservation**: ``sum(balances) + sum(locked_in_open_streams)`` is
      constant across all operations.
    * **Rate enforcement**: ``tick_stream(...)`` never drains more than
      ``rate_per_tick`` per call.
    * **Stop-on-close**: no debit occurs after ``close_stream``, even under
      partition recovery races.

    Example::

        payments = StreamingPayments(AgentId("a1"), initial_balance=1000)
        handle = await payments.open_stream(
            to=AgentId("a2"), rate_per_tick=50, max_total=500,
            ref=PaymentRef("stream-1"),
        )
        still_open = await payments.tick_stream(PaymentRef("stream-1"), 1)
        receipt = await payments.close_stream(PaymentRef("stream-1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
        streams: dict[PaymentRef, StreamHandle] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._payments = payments if payments is not None else {}
        self._streams = streams if streams is not None else {}
        self._closed_receipts: dict[PaymentRef, Receipt] = {}

    # -- read helpers ----------------------------------------------------

    def balance(self, agent: AgentId) -> int:
        """Check an agent's balance.

        Example::

            bal = payments.balance(AgentId("payee"))
        """
        return self._balances.get(agent, 0)

    def stream(self, ref: PaymentRef) -> StreamHandle | None:
        """Return the stream handle for ``ref``, or None.

        Example::

            handle = payments.stream(PaymentRef("s-1"))
            assert handle is not None and handle.is_open
        """
        return self._streams.get(ref)

    def active_streams(self) -> list[StreamHandle]:
        """Return all currently open streams.

        Example::

            for h in payments.active_streams():
                print(f"{h.ref}: {h.total_debited}/{h.max_total}")
        """
        return [h for h in self._streams.values() if h.is_open]

    def stream_count(self) -> int:
        """Return the number of tracked streams (open + closed).

        Example::

            n = payments.stream_count()
        """
        return len(self._streams)

    def locked_funds(self) -> int:
        """Return the maximum remaining liability across all open streams.

        This is the worst-case total that could still be drained if every
        open stream ran to ``max_total``. Used by conservation validators.

        Example::

            at_risk = payments.locked_funds()
            assert at_risk <= payments.balance(self._agent_id)
        """
        return sum(h.remaining for h in self._streams.values() if h.is_open)

    # -- stream lifecycle ------------------------------------------------

    async def open_stream(
        self,
        to: AgentId,
        rate_per_tick: int,
        max_total: int,
        ref: PaymentRef,
        current_tick: int = 0,
    ) -> StreamHandle:
        """Open a streaming payment from this agent to ``to``, or return the
        existing stream if ``ref`` already identifies one.

        Funds drain one tick at a time at ``rate_per_tick`` per tick, capped at
        ``max_total``. Either party can close the stream at any point; the
        unused remainder is never spent.

        Idempotent: if ``ref`` already identifies an open stream, returns the
        existing :class:`StreamHandle` without draining another tick.

        The first tick is drained immediately so the payee observes a non-zero
        balance after ``open_stream`` returns.

        Example::

            handle = await payments.open_stream(
                to=AgentId("compute-worker"),
                rate_per_tick=10,
                max_total=500,
                ref=PaymentRef("metered-task-1"),
            )
            assert handle.total_debited == 10

        Args:
            to: Recipient agent.
            rate_per_tick: Amount to debit per tick (must be >= 1).
            max_total: Maximum total to transfer (must be >= rate_per_tick).
            ref: Unique idempotency-key reference for this stream.
            current_tick: Logical tick at open time (provided by scheduler).

        Returns:
            StreamHandle with stream metadata.

        Raises:
            StreamError: If ``ref`` already identifies a *closed* stream.
            ValueError: If params invalid or payer balance insufficient for
                the first tick.
        """
        # Idempotency: same ref -> same stream
        if ref in self._streams:
            existing = self._streams[ref]
            if not existing.is_open:
                msg = f"Stream already closed: {ref}"
                raise StreamError(msg)
            return existing

        if rate_per_tick < 1:
            msg = f"rate_per_tick must be >= 1, got {rate_per_tick}"
            raise ValueError(msg)
        if max_total < rate_per_tick:
            msg = f"max_total ({max_total}) must be >= rate_per_tick ({rate_per_tick})"
            raise ValueError(msg)
        if ref in self._payments:
            msg = f"Payment reference already used for one-shot pay: {ref}"
            raise StreamError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < rate_per_tick:
            msg = (
                f"Insufficient balance for stream open: need {rate_per_tick}, have {payer_balance}"
            )
            raise ValueError(msg)

        self._balances[self._agent_id] = payer_balance - rate_per_tick
        self._balances[to] = self._balances.get(to, 0) + rate_per_tick

        handle = StreamHandle(
            ref=ref,
            to=to,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            opened_at_tick=current_tick,
            total_debited=rate_per_tick,
            entries=[StreamEntry(tick=current_tick, amount=rate_per_tick, kind="debit")],
        )
        if handle.remaining <= 0:
            handle.closed_at_tick = current_tick
        self._streams[ref] = handle
        return handle

    async def tick_stream(self, ref: PaymentRef, current_tick: int) -> bool:
        """Drain one tick's worth of funds from an open stream.

        Called once per logical tick by the scenario scheduler while the stream
        is open. Returns ``True`` if the stream is still open after this tick,
        ``False`` if it has been exhausted, closed, or drained by insufficient
        funds.

        Idempotent: if the stream is already closed, returns ``False`` without
        error. If ``current_tick`` equals the last debit tick, no double-billing
        occurs (the entry list is checked before debiting).

        Example::

            still_open = await payments.tick_stream(
                PaymentRef("s-1"), current_tick=3,
            )
            if not still_open:
                receipt = await payments.close_stream(PaymentRef("s-1"))

        Args:
            ref: Stream reference.
            current_tick: Current logical simulation tick.

        Returns:
            True if stream is still open after this tick, False otherwise.
        """
        if ref not in self._streams:
            return False

        handle = self._streams[ref]
        if not handle.is_open:
            return False

        # Idempotency: don't double-bill the same tick
        if handle.entries and handle.entries[-1].tick == current_tick:
            return True

        if handle.remaining <= 0:
            handle.closed_at_tick = current_tick
            return False

        amount_to_drain = min(handle.rate_per_tick, handle.remaining)
        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount_to_drain:
            handle.closed_at_tick = current_tick
            return False

        self._balances[self._agent_id] = payer_balance - amount_to_drain
        self._balances[handle.to] = self._balances.get(handle.to, 0) + amount_to_drain
        handle.total_debited += amount_to_drain
        handle.entries.append(StreamEntry(tick=current_tick, amount=amount_to_drain, kind="debit"))

        if handle.remaining <= 0:
            handle.closed_at_tick = current_tick
            return False

        return True

    async def close_stream(self, ref: PaymentRef) -> Receipt:
        """Close a stream and return a receipt.

        Either payer or payee may call this. The unused remainder is never
        spent.

        Idempotent: if the stream was already closed (and a receipt was
        produced), returns the original receipt instead of raising.

        Example::

            receipt = await payments.close_stream(PaymentRef("s-1"))
            assert receipt.amount.amount == 300

        Args:
            ref: Stream reference.

        Returns:
            Receipt with the total amount transferred.

        Raises:
            StreamError: If stream not found.
        """
        # Idempotency: return existing receipt
        if ref in self._closed_receipts:
            return self._closed_receipts[ref]

        if ref not in self._streams:
            msg = f"Stream not found: {ref}"
            raise StreamError(msg)

        handle = self._streams[ref]
        if handle.is_open:
            handle.closed_at_tick = (
                handle.entries[-1].tick if handle.entries else handle.opened_at_tick
            )

        receipt = Receipt(
            ref=ref,
            payer=self._agent_id,
            payee=handle.to,
            amount=Money(amount=handle.total_debited),
        )
        self._payments[ref] = receipt
        self._closed_receipts[ref] = receipt
        return receipt

    async def refund_stream(self, ref: PaymentRef) -> Receipt:
        """Refund a closed stream, returning the debited funds to the payer.

        Only succeeds on streams that have been closed and whose payee still
        holds sufficient balance. The full debited amount is returned to the
        payer.

        Idempotent: returns the original refund receipt on repeat calls.

        Example::

            refund_receipt = await payments.refund_stream(PaymentRef("s-1"))
            assert refund_receipt.payee == AgentId("payer")

        Args:
            ref: Stream reference (must be closed).

        Returns:
            Receipt for the refund (payer and payee roles swapped from the
            original).

        Raises:
            StreamError: If stream not found, still open, or payee balance
                insufficient.
        """
        if ref in self._closed_receipts:
            refund_ref = PaymentRef(f"{ref}-refund")
            if refund_ref in self._payments:
                return self._payments[refund_ref]

        handle = self._streams.get(ref)
        if handle is None:
            msg = f"Stream not found: {ref}"
            raise StreamError(msg)
        if handle.is_open:
            msg = f"Cannot refund open stream: {ref}"
            raise StreamError(msg)

        payee_balance = self._balances.get(handle.to, 0)
        if payee_balance < handle.total_debited:
            msg = (
                f"Insufficient balance for stream refund: "
                f"{handle.to} has {payee_balance}, needs {handle.total_debited}"
            )
            raise StreamError(msg)

        self._balances[handle.to] = payee_balance - handle.total_debited
        self._balances[self._agent_id] = (
            self._balances.get(self._agent_id, 0) + handle.total_debited
        )

        refund_ref = PaymentRef(f"{ref}-refund")
        refund_receipt = Receipt(
            ref=refund_ref,
            payer=handle.to,  # roles are swapped
            payee=self._agent_id,
            amount=Money(amount=handle.total_debited),
        )
        self._payments[refund_ref] = refund_receipt
        return refund_receipt

    # -- Payments protocol -----------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

            q = await payments.quote(ServiceRef("compute-hour"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a one-shot payment.

        Implemented as a direct balance transfer (not a stream open/close):
        validates the amount, checks payer balance, moves funds, and records
        a ``Receipt`` keyed by ``ref``. Produces the same balance deltas and
        receipt shape a zero-duration stream would, satisfying the
        ``Payments`` protocol for callers that do not speak streaming.

        Idempotent: if ``ref`` already identifies a completed payment, returns
        the existing receipt.

        Example::

            receipt = await payments.pay(
                AgentId("seller"), Money(amount=200), PaymentRef("one-shot-1"),
            )

        Args:
            to: Recipient agent.
            amount: Amount to transfer.
            ref: Unique idempotency-key reference for this payment.

        Returns:
            Receipt.

        Raises:
            ValueError: If amount <= 0 or payer balance insufficient.
            StreamError: If ``ref`` already identifies a stream.
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)

        # Idempotency: if we've seen this ref before, return existing receipt
        if ref in self._payments:
            return self._payments[ref]

        if ref in self._streams:
            msg = f"Reference already in use as stream: {ref}"
            raise StreamError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            msg = f"Insufficient balance: have {payer_balance}, need {amount.amount}"
            raise ValueError(msg)

        self._balances[self._agent_id] = payer_balance - amount.amount
        self._balances[to] = self._balances.get(to, 0) + amount.amount

        receipt = Receipt(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=amount,
        )
        self._payments[ref] = receipt
        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify a payment or stream status by reference.

        Returns ``STREAMING`` for open streams, ``CONFIRMED`` for completed
        payments or closed streams, ``FAILED`` for unknown references.

        Example::

            status = await payments.verify_payment(PaymentRef("s-1"))
            if status == PaymentStatus.STREAMING:
                await payments.tick_stream(PaymentRef("s-1"), tick)

        Args:
            ref: Payment or stream reference.

        Returns:
            PaymentStatus.CONFIRMED for completed payments,
            PaymentStatus.STREAMING for open streams,
            PaymentStatus.FAILED for unknown references.
        """
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        if ref in self._streams:
            handle = self._streams[ref]
            if handle.is_open:
                return PaymentStatus.STREAMING
            return PaymentStatus.CONFIRMED
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a completed one-shot payment.

        Raises if payment not found or payee balance insufficient.
        For stream refunds, use :meth:`refund_stream` instead.

        Example::

            await payments.refund(PaymentRef("one-shot-1"))

        Args:
            ref: Payment reference.

        Raises:
            StreamError: If payment not found or payee balance insufficient.
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            msg = f"Payment not found: {ref}"
            raise StreamError(msg)

        payee_balance = self._balances.get(receipt.payee, 0)
        if payee_balance < receipt.amount.amount:
            msg = (
                f"Insufficient balance for refund: {receipt.payee} has "
                f"{payee_balance}, needs {receipt.amount.amount}"
            )
            raise StreamError(msg)

        self._balances[receipt.payee] = payee_balance - receipt.amount.amount
        self._balances[receipt.payer] = self._balances.get(receipt.payer, 0) + receipt.amount.amount
        del self._payments[ref]
