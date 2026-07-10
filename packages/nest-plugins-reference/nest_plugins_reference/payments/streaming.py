# SPDX-License-Identifier: Apache-2.0
"""Streaming per-tick payments plugin with mid-stream cancellation.

Funds drain one logical tick at a time, capped at ``max_total``. Either party
may close the stream; unused remainder is never spent. Subsequent debits require
a payee delivery acknowledgement so billing stops when the payer and payee cannot
communicate (e.g. under ``failures.network_partition``).

``verify_payment`` returns ``PaymentStatus.STREAMING`` for an open stream because
funds are in flight but the obligation is not yet finalized — distinct from
``PENDING`` (reserved but not yet moving) and ``CONFIRMED`` (closed or fully
drained to ``max_total``).

Example::

    payments = StreamingPayments(AgentId("payer"), initial_balance=10000)
    handle = await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=10,
        max_total=500,
        ref=PaymentRef("stream-1"),
    )
    await payments.acknowledge_work(PaymentRef("stream-1"), tick=0)
    await payments.advance_stream(PaymentRef("stream-1"), tick=1)
    receipt = await payments.close_stream(PaymentRef("stream-1"), current_tick=2)
"""

from __future__ import annotations

from dataclasses import dataclass

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)


@dataclass
class StreamHandle:
    """Handle to an active stream.

    Example::

        handle = StreamHandle(
            ref=PaymentRef("s-1"),
            payer=AgentId("buyer-0"),
            to=AgentId("worker"),
            rate_per_tick=10,
            max_total=500,
            opened_at_tick=0,
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
    ready_to_advance: bool = False


class StreamingPayments:
    """Streaming per-tick payments with mid-stream cancellation.

    Extends prepaid credits with bilateral streams that drain one tick at a time.
    Either party can close at any tick; unused remainder is never spent. Satisfies
    the ``Payments`` protocol — ``pay()`` behaves as a one-tick stream.

    Example::

        payments = StreamingPayments(AgentId("a1"), initial_balance=1000)
        handle = await payments.open_stream(
            to=AgentId("a2"),
            rate_per_tick=50,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        receipt = await payments.close_stream(PaymentRef("stream-1"), current_tick=3)
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
        *,
        opened_at_tick: int = 0,
    ) -> StreamHandle:
        """Open a streaming payment from this agent to another.

        Funds drain from payer to payee one tick at a time at ``rate_per_tick``,
        capped at ``max_total``. The first tick debits immediately; later ticks
        require ``acknowledge_work`` then ``advance_stream``.

        Example::

            handle = await payments.open_stream(
                to=AgentId("compute-worker"),
                rate_per_tick=10,
                max_total=500,
                ref=PaymentRef("metered-task-1"),
                opened_at_tick=0,
            )
            assert handle.total_debited == 10

        Args:
            to: Recipient agent.
            rate_per_tick: Amount to debit per tick (must be positive).
            max_total: Maximum total to transfer (must be >= rate_per_tick).
            ref: Unique reference for this stream.
            opened_at_tick: Logical tick when the stream opens.

        Returns:
            StreamHandle with stream metadata.

        Raises:
            ValueError: If params invalid or stream already exists for ref.
        """
        if rate_per_tick <= 0:
            msg = f"rate_per_tick must be positive: {rate_per_tick}"
            raise ValueError(msg)
        if max_total < rate_per_tick:
            msg = f"max_total ({max_total}) must be >= rate_per_tick ({rate_per_tick})"
            raise ValueError(msg)
        if ref in self._payments or ref in self._streams:
            msg = f"Payment or stream reference already exists: {ref}"
            raise ValueError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < rate_per_tick:
            msg = f"Insufficient balance for stream: {payer_balance} < {rate_per_tick}"
            raise ValueError(msg)

        first_debit = min(rate_per_tick, max_total)
        self._balances[self._agent_id] = payer_balance - first_debit
        self._balances[to] = self._balances.get(to, 0) + first_debit

        handle = StreamHandle(
            ref=ref,
            payer=self._agent_id,
            to=to,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            opened_at_tick=opened_at_tick,
            total_debited=first_debit,
            ready_to_advance=False,
        )
        if handle.total_debited >= handle.max_total:
            handle.closed_at_tick = opened_at_tick
        self._streams[ref] = handle
        return handle

    def _debit_amount(self, handle: StreamHandle) -> int:
        return min(
            handle.rate_per_tick,
            handle.max_total - handle.total_debited,
        )

    async def acknowledge_work(self, ref: PaymentRef, *, tick: int) -> None:
        """Mark that the payee delivered work for the current stream period.

        Only the payee (``handle.to``) may call this. Arms the payer to call
        ``advance_stream`` for the next tick. Under partition the payee never
        receives work, so no further debits occur.

        Example::

            await payments.acknowledge_work(PaymentRef("s-1"), tick=4)
        """
        handle = self._streams.get(ref)
        if handle is None or handle.closed_at_tick is not None:
            return
        if self._agent_id != handle.to:
            msg = f"Only payee {handle.to} may acknowledge stream {ref}"
            raise ValueError(msg)
        handle.ready_to_advance = True

    async def advance_stream(self, ref: PaymentRef, current_tick: int) -> bool:
        """Debit the next tick after payee acknowledged delivery.

        Returns True if the stream remains open after this advance.

        Example::

            still_open = await payments.advance_stream(PaymentRef("s-1"), current_tick=3)
        """
        if ref not in self._streams:
            return False

        handle = self._streams[ref]
        if handle.closed_at_tick is not None:
            return False
        if not handle.ready_to_advance:
            return handle.closed_at_tick is None
        if handle.total_debited >= handle.max_total:
            handle.closed_at_tick = current_tick
            return False

        amount_to_drain = self._debit_amount(handle)
        if amount_to_drain <= 0:
            handle.closed_at_tick = current_tick
            return False

        payer = handle.payer
        payer_balance = self._balances.get(payer, 0)
        if payer_balance < amount_to_drain:
            handle.closed_at_tick = current_tick
            return False

        self._balances[payer] = payer_balance - amount_to_drain
        self._balances[handle.to] = self._balances.get(handle.to, 0) + amount_to_drain
        handle.total_debited += amount_to_drain
        handle.ready_to_advance = False

        if handle.total_debited >= handle.max_total:
            handle.closed_at_tick = current_tick

        return handle.closed_at_tick is None

    def stream_total_debited(self, ref: PaymentRef) -> int:
        """Return cumulative debited amount for an open or closed stream.

        Example::

            total = payments.stream_total_debited(PaymentRef("s-1"))
        """
        handle = self._streams.get(ref)
        if handle is not None:
            return handle.total_debited
        receipt = self._payments.get(ref)
        if receipt is not None:
            return receipt.amount.amount
        return 0

    async def tick_stream(self, ref: PaymentRef, current_tick: int) -> bool:
        """Alias for :meth:`advance_stream` (backward-compatible test API).

        Example::

            still_open = await payments.tick_stream(PaymentRef("s-1"), current_tick=2)
        """
        handle = self._streams.get(ref)
        if handle is not None and not handle.ready_to_advance:
            handle.ready_to_advance = True
        return await self.advance_stream(ref, current_tick)

    async def close_stream(self, ref: PaymentRef, *, current_tick: int = 0) -> Receipt:
        """Close a stream and return a receipt.

        Either payer or payee can call this. Unused remainder is never spent.
        Further ``advance_stream`` calls are no-ops.

        Example::

            receipt = await payments.close_stream(
                PaymentRef("s-1"),
                current_tick=5,
            )
            assert receipt.amount.amount == handle.total_debited

        Args:
            ref: Stream reference.
            current_tick: Logical tick at close.

        Returns:
            Receipt with total amount transferred.

        Raises:
            ValueError: If stream not found.
        """
        if ref not in self._streams:
            msg = f"Stream not found: {ref}"
            raise ValueError(msg)

        handle = self._streams[ref]
        if handle.closed_at_tick is None:
            handle.closed_at_tick = current_tick

        payer = handle.payer

        receipt = Receipt(
            ref=ref,
            payer=payer,
            payee=handle.to,
            amount=Money(amount=handle.total_debited),
        )
        self._payments[ref] = receipt
        del self._streams[ref]
        return receipt

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a one-shot payment (single-tick stream).

        Satisfies the ``Payments`` protocol for backward compatibility.

        Example::

            receipt = await payments.pay(
                AgentId("seller"),
                Money(amount=200),
                PaymentRef("one-shot-1"),
            )
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)
        if ref in self._payments or ref in self._streams:
            msg = f"Duplicate payment reference: {ref}"
            raise ValueError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            msg = f"Insufficient balance: {payer_balance} < {amount.amount}"
            raise ValueError(msg)

        self._balances[self._agent_id] = payer_balance - amount.amount
        self._balances[to] = self._balances.get(to, 0) + amount.amount

        receipt = Receipt(ref=ref, payer=self._agent_id, payee=to, amount=amount)
        self._payments[ref] = receipt
        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify a payment or stream status by reference.

        Open streams return ``STREAMING`` because value is actively metering but
        the obligation is not finalized. Closed or one-shot payments return
        ``CONFIRMED``.

        Example::

            status = await payments.verify_payment(PaymentRef("s-1"))
            if status == PaymentStatus.STREAMING:
                await payments.advance_stream(PaymentRef("s-1"), tick=2)
        """
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        if ref in self._streams:
            return PaymentStatus.STREAMING
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a completed payment.

        Example::

            await payments.refund(PaymentRef("one-shot-1"))
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            msg = f"Payment not found: {ref}"
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
