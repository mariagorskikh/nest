# SPDX-License-Identifier: Apache-2.0
"""Streaming per-tick payments plugin with mid-stream cancellation.

Billing is **delivery-gated**: the payer records each delivered work unit
(``record_delivery``) and only then drains one tick's worth of funds
(``tick_stream``). A unit the payee never delivered — because either side
closed the stream, a message was dropped, or the parties were partitioned —
is never billed. This is the per-request metering shape of x402-style
HTTP-payment proposals, expressed on the simulator's logical clock.

Example::

    balances: dict[AgentId, int] = {}
    payments: dict[PaymentRef, Receipt] = {}
    streams: dict[PaymentRef, StreamHandle] = {}
    payer = StreamingPayments(
        AgentId("payer"),
        initial_balance=10_000,
        balances=balances,
        payments=payments,
        streams=streams,
    )
    handle = await payer.open_stream(
        to=AgentId("payee"),
        rate_per_tick=10,
        max_total=500,
        ref=PaymentRef("stream-1"),
    )
    payer.record_delivery(PaymentRef("stream-1"), unit=1)
    await payer.tick_stream(PaymentRef("stream-1"), current_tick=1)  # drains 10
    receipt = await payer.close_stream(PaymentRef("stream-1"))       # remainder never spent
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
    """Raised on invalid stream operations (unknown ref, bad params, refund of an open stream).

    Example::

        try:
            await payments.close_stream(PaymentRef("nope"))
        except StreamError:
            ...
    """


@dataclass
class StreamHandle:
    """Handle to a payment stream.

    ``delivered_units`` holds work units the payee delivered that are not yet
    billed; ``billed_units`` holds units already drained. The split is what
    makes billing delivery-gated: ``tick_stream`` moves money only when a
    recorded delivery is waiting.

    Example::

        handle = StreamHandle(
            ref=PaymentRef("s-1"),
            payer=AgentId("buyer"),
            to=AgentId("worker"),
            rate_per_tick=10,
            max_total=500,
            opened_at_tick=3,
        )
        assert handle.total_debited == 0
    """

    ref: PaymentRef
    payer: AgentId
    to: AgentId
    rate_per_tick: int
    max_total: int
    opened_at_tick: int
    closed_at_tick: int | None = None
    total_debited: int = 0
    delivered_units: list[int] = field(default_factory=lambda: list[int]())
    billed_units: list[int] = field(default_factory=lambda: list[int]())


class StreamingPayments:
    """Streaming per-tick payments with mid-stream cancellation.

    Satisfies the ``Payments`` protocol (``quote``/``pay``/``verify_payment``/
    ``refund``) and adds the streaming surface the problem brief asks for:
    ``open_stream``/``close_stream``, plus ``record_delivery``/``tick_stream``
    for delivery-gated draining. Deterministic: ticks come from the caller
    (the simulator's logical clock); no wall clock, no RNG.

    Pass the same ``balances``/``payments``/``streams`` dicts to every
    party's instance (the escrow-plugin convention) so payer and payee
    operate on one ledger.

    Example::

        payments = StreamingPayments(AgentId("a1"), initial_balance=1000)
        handle = await payments.open_stream(
            to=AgentId("a2"),
            rate_per_tick=50,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        payments.record_delivery(PaymentRef("stream-1"), unit=1)
        await payments.tick_stream(PaymentRef("stream-1"), current_tick=1)
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

    def balance(self, agent: AgentId) -> int:
        """Check an agent's balance.

        Example::

            bal = payments.balance(AgentId("payee"))
        """
        return self._balances.get(agent, 0)

    def stream(self, ref: PaymentRef) -> StreamHandle | None:
        """Return the handle for ``ref``, or None if no such stream exists.

        Example::

            handle = payments.stream(PaymentRef("s-1"))
            if handle is not None and handle.closed_at_tick is None:
                ...  # still open
        """
        return self._streams.get(ref)

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

            q = await payments.quote(ServiceRef("compute-hour"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def open_stream(
        self,
        to: AgentId,
        rate_per_tick: int,
        max_total: int,
        ref: PaymentRef,
        at_tick: int = 0,
    ) -> StreamHandle:
        """Open a streaming payment from this agent to another.

        Nothing is debited at open: money follows delivered work units, so a
        stream that never delivers costs nothing. Either party can call
        ``close_stream`` at any point; the unused remainder is never spent.

        Example::

            handle = await payments.open_stream(
                to=AgentId("compute-worker"),
                rate_per_tick=10,
                max_total=500,
                ref=PaymentRef("metered-task-1"),
                at_tick=7,
            )
            assert handle.total_debited == 0

        Args:
            to: Recipient agent.
            rate_per_tick: Amount to debit per delivered unit (must be positive).
            max_total: Maximum total to transfer (must be >= rate_per_tick).
            ref: Unique reference for this stream.
            at_tick: Logical tick the stream opens at (from the simulator clock).

        Returns:
            StreamHandle with stream metadata.

        Raises:
            StreamError: If params are invalid, the ref exists, or the payer
                cannot cover even one tick.
        """
        if rate_per_tick <= 0:
            msg = f"rate_per_tick must be positive: {rate_per_tick}"
            raise StreamError(msg)
        if max_total < rate_per_tick:
            msg = f"max_total ({max_total}) must be >= rate_per_tick ({rate_per_tick})"
            raise StreamError(msg)
        if ref in self._payments or ref in self._streams:
            msg = f"Payment or stream reference already exists: {ref}"
            raise StreamError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < rate_per_tick:
            msg = f"Insufficient balance for stream: {payer_balance} < {rate_per_tick}"
            raise StreamError(msg)

        handle = StreamHandle(
            ref=ref,
            payer=self._agent_id,
            to=to,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            opened_at_tick=at_tick,
        )
        self._streams[ref] = handle
        return handle

    def record_delivery(self, ref: PaymentRef, unit: int) -> bool:
        """Record that the payee delivered work unit ``unit`` on stream ``ref``.

        Idempotent per unit: recording the same unit twice queues it once, so
        a duplicated ack can never double-bill. Deliveries against a closed
        or unknown stream are refused — that is the drain-after-close guard.

        Example::

            accepted = payments.record_delivery(PaymentRef("s-1"), unit=3)

        Args:
            ref: Stream reference.
            unit: Work-unit number the payee delivered.

        Returns:
            True if the delivery was queued for billing, False if refused
            (unknown ref, closed stream, or duplicate unit).
        """
        handle = self._streams.get(ref)
        if handle is None or handle.closed_at_tick is not None:
            return False
        if unit in handle.delivered_units or unit in handle.billed_units:
            return False
        handle.delivered_units.append(unit)
        return True

    async def tick_stream(self, ref: PaymentRef, current_tick: int) -> int:
        """Drain one tick's worth of funds for the oldest unbilled delivery.

        No recorded delivery → no debit: a partitioned payee stops acking,
        so the payer stops paying. Hitting ``max_total`` or running the
        payer's balance dry closes the stream at ``current_tick``.

        Example::

            payments.record_delivery(PaymentRef("s-1"), unit=1)
            drained = await payments.tick_stream(PaymentRef("s-1"), current_tick=3)
            assert drained in (0, handle.rate_per_tick)

        Args:
            ref: Stream reference.
            current_tick: Current logical tick (from the simulator clock).

        Returns:
            The amount actually drained by this call (0 if the stream is
            unknown, closed, undelivered, or the payer's balance ran dry).
        """
        handle = self._streams.get(ref)
        if handle is None or handle.closed_at_tick is not None:
            return 0

        if not handle.delivered_units:
            return 0  # nothing delivered since last drain — bill nothing

        amount = min(handle.rate_per_tick, handle.max_total - handle.total_debited)
        if amount <= 0:
            handle.closed_at_tick = current_tick
            return 0

        payer_balance = self._balances.get(handle.payer, 0)
        if payer_balance < amount:
            handle.closed_at_tick = current_tick
            return 0

        unit = handle.delivered_units.pop(0)
        handle.billed_units.append(unit)
        self._balances[handle.payer] = payer_balance - amount
        self._balances[handle.to] = self._balances.get(handle.to, 0) + amount
        handle.total_debited += amount

        if handle.total_debited >= handle.max_total:
            handle.closed_at_tick = current_tick
        return amount

    async def close_stream(self, ref: PaymentRef, at_tick: int | None = None) -> Receipt:
        """Close a stream and return the settlement receipt.

        Either payer or payee can call this; the receipt always names the
        stream's actual payer. Closing is idempotent — closing an
        already-settled stream returns the stored receipt — and final: no
        delivery or drain is accepted for ``ref`` afterwards.

        Example::

            receipt = await payments.close_stream(PaymentRef("s-1"), at_tick=12)
            assert receipt.amount.amount <= 500  # never more than max_total

        Args:
            ref: Stream reference.
            at_tick: Logical tick of closure; defaults to the stream's open
                tick when omitted.

        Returns:
            Receipt for the total actually transferred (never the max).

        Raises:
            StreamError: If no stream exists for ``ref``.
        """
        existing = self._payments.get(ref)
        if existing is not None:
            return existing

        handle = self._streams.get(ref)
        if handle is None:
            msg = f"Stream not found: {ref}"
            raise StreamError(msg)

        if handle.closed_at_tick is None:
            handle.closed_at_tick = at_tick if at_tick is not None else handle.opened_at_tick
        handle.delivered_units.clear()  # unbilled deliveries die with the stream

        receipt = Receipt(
            ref=ref,
            payer=handle.payer,
            payee=handle.to,
            amount=Money(amount=handle.total_debited),
        )
        self._payments[ref] = receipt
        return receipt

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a one-shot payment: a stream that drains the full amount in one tick.

        Literally implemented as ``open_stream`` at rate ``amount`` + one
        delivered unit + one drain + ``close_stream``, so one-shot and
        streaming settlements share every invariant and code path.

        Example::

            receipt = await payments.pay(
                AgentId("seller"),
                Money(amount=200),
                PaymentRef("one-shot-1"),
            )

        Args:
            to: Recipient agent.
            amount: Amount to transfer.
            ref: Unique reference for this payment.

        Returns:
            Receipt.

        Raises:
            StreamError: If the amount is not positive, the ref is a
                duplicate, or the balance is insufficient.
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise StreamError(msg)
        await self.open_stream(
            to=to,
            rate_per_tick=amount.amount,
            max_total=amount.amount,
            ref=ref,
        )
        self.record_delivery(ref, unit=1)
        await self.tick_stream(ref, current_tick=0)
        return await self.close_stream(ref)

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify a payment or stream status by reference.

        A half-drained open stream is ``STREAMING``, not ``PENDING``: every
        tick already drained is final and irrevocable, so the settlement is
        neither absent nor awaited — it is in progress. ``CONFIRMED`` is
        reserved for settled refs (one-shot payments and closed streams).

        Example::

            status = await payments.verify_payment(PaymentRef("s-1"))
            if status == PaymentStatus.STREAMING:
                await payments.tick_stream(PaymentRef("s-1"), tick)

        Args:
            ref: Payment or stream reference.

        Returns:
            ``CONFIRMED`` for settled refs, ``STREAMING`` for open streams,
            ``FAILED`` for unknown refs.
        """
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        handle = self._streams.get(ref)
        if handle is not None:
            if handle.closed_at_tick is not None:
                return PaymentStatus.CONFIRMED
            return PaymentStatus.STREAMING
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a settled payment in full.

        Only settled refs can be refunded; an open stream must be closed
        first so the refundable amount is fixed.

        Example::

            await payments.refund(PaymentRef("one-shot-1"))

        Args:
            ref: Payment reference.

        Raises:
            StreamError: If the ref is unknown, the stream is still open, or
                the payee cannot cover the refund.
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            handle = self._streams.get(ref)
            if handle is not None and handle.closed_at_tick is None:
                msg = f"Cannot refund an open stream, close it first: {ref}"
                raise StreamError(msg)
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
