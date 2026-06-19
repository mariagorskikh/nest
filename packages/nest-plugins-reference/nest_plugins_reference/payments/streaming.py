# SPDX-License-Identifier: Apache-2.0
"""Streaming per-tick payments plugin with mid-stream cancellation.

Example::

    payments = StreamingPayments(AgentId("payer"), initial_balance=10000)
    handle = await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=10,
        max_total=500,
        ref=PaymentRef("stream-1"),
    )
    # ... ticks pass ...
    receipt = await payments.close_stream(PaymentRef("stream-1"))
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
            to=AgentId("worker"),
            rate_per_tick=10,
            max_total=500,
            opened_at_tick=0,
        )
        assert handle.total_debited == 0
    """

    ref: PaymentRef
    to: AgentId
    rate_per_tick: int
    max_total: int
    opened_at_tick: int
    closed_at_tick: int | None = None
    total_debited: int = 0


class StreamingPayments:
    """Streaming per-tick payments with mid-stream cancellation.

    Extends prepaid credits with the ability to open bilateral streams that drain
    one tick at a time. Either party can close the stream at any tick; unused
    remainder is never spent. Satisfies the ``Payments`` protocol.

    Example::

        payments = StreamingPayments(AgentId("a1"), initial_balance=1000)
        handle = await payments.open_stream(
            to=AgentId("a2"),
            rate_per_tick=50,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        # Later...
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
    ) -> StreamHandle:
        """Open a streaming payment from this agent to another.

        Funds drain from payer to payee one tick at a time at ``rate_per_tick``
        per tick, capped at ``max_total``. Either party can call ``close_stream``
        at any point; unused remainder is never spent.

        Example::

            handle = await payments.open_stream(
                to=AgentId("compute-worker"),
                rate_per_tick=10,
                max_total=500,
                ref=PaymentRef("metered-task-1"),
            )
            assert handle.total_debited == 10  # first tick drained immediately

        Args:
            to: Recipient agent.
            rate_per_tick: Amount to debit per tick (must be positive).
            max_total: Maximum total to transfer (must be >= rate_per_tick).
            ref: Unique reference for this stream.

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

        # Drain first tick immediately
        self._balances[self._agent_id] = payer_balance - rate_per_tick
        self._balances[to] = self._balances.get(to, 0) + rate_per_tick

        handle = StreamHandle(
            ref=ref,
            to=to,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            opened_at_tick=0,  # Will be set by context in real scenario
            total_debited=rate_per_tick,
        )
        self._streams[ref] = handle
        return handle

    async def tick_stream(self, ref: PaymentRef, current_tick: int) -> bool:
        """Drain one tick's worth of funds from an open stream.

        Called automatically by the scheduler. Returns True if stream still open.

        Example::

            still_open = await payments.tick_stream(PaymentRef("s-1"), current_tick=3)
            if not still_open:
                receipt = await payments.close_stream(PaymentRef("s-1"))

        Args:
            ref: Stream reference.
            current_tick: Current simulation tick.

        Returns:
            True if stream is still open after this tick, False if closed.
        """
        if ref not in self._streams:
            return False

        handle = self._streams[ref]
        if handle.closed_at_tick is not None:
            return False

        # Check if we've hit the max
        if handle.total_debited >= handle.max_total:
            handle.closed_at_tick = current_tick
            return False

        # Drain one tick
        amount_to_drain = min(
            handle.rate_per_tick,
            handle.max_total - handle.total_debited,
        )
        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount_to_drain:
            # Insufficient funds; stream stops
            handle.closed_at_tick = current_tick
            return False

        self._balances[self._agent_id] = payer_balance - amount_to_drain
        self._balances[handle.to] = self._balances.get(handle.to, 0) + amount_to_drain
        handle.total_debited += amount_to_drain

        if handle.total_debited >= handle.max_total:
            handle.closed_at_tick = current_tick

        return handle.closed_at_tick is None

    async def close_stream(self, ref: PaymentRef) -> Receipt:
        """Close a stream and return a receipt.

        Either payer or payee can call this. Unused remainder is never spent.

        Example::

            receipt = await payments.close_stream(PaymentRef("s-1"))
            assert receipt.amount.amount == handle.total_debited

        Args:
            ref: Stream reference.

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
            handle.closed_at_tick = 0  # Assume current tick; real usage sets it

        # Create receipt
        receipt = Receipt(
            ref=ref,
            payer=self._agent_id,
            payee=handle.to,
            amount=Money(amount=handle.total_debited),
        )
        self._payments[ref] = receipt
        return receipt

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a one-shot payment (one-tick stream).

        Satisfies the Payments protocol for backward compatibility.

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
            ValueError: If insufficient balance or duplicate ref.
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

        Example::

            status = await payments.verify_payment(PaymentRef("s-1"))
            if status == PaymentStatus.STREAMING:
                await payments.tick_stream(PaymentRef("s-1"), tick)

        Args:
            ref: Payment or stream reference.

        Returns:
            PaymentStatus.CONFIRMED for completed payments,
            PaymentStatus.STREAMING for open streams,
            PaymentStatus.FAILED otherwise.
        """
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        if ref in self._streams:
            handle = self._streams[ref]
            if handle.closed_at_tick is not None:
                return PaymentStatus.CONFIRMED
            return PaymentStatus.STREAMING
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a payment.

        Example::

            await payments.refund(PaymentRef("one-shot-1"))

        Args:
            ref: Payment reference.

        Raises:
            ValueError: If payment not found or insufficient balance for refund.
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
