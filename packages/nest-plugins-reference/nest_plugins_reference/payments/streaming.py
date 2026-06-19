# SPDX-License-Identifier: Apache-2.0
<<<<<<< HEAD
"""Streaming pay-per-second payments plugin with mid-stream cancellation.

Implements the `Payments` protocol and adds streaming methods
(`open_stream`, `close_stream`, `drain_tick`) so agents can meter
services per-simulation-tick instead of paying a flat amount upfront.

Key behaviours
--------------
- ``open_stream(to, rate_per_tick, max_total, ref)`` opens a stream.
  No funds move yet — debits happen one tick at a time inside
  ``drain_tick``.
- ``drain_tick()`` iterates every *open* stream, debiting
  ``rate_per_tick`` from the payer and crediting the payee (capped
  at ``max_total``). If the payer runs out of funds mid-stream,
  the stream silently stops billing for that tick and future ticks.
- ``close_stream(ref)`` permanently stops the stream. The unused
  remainder of ``max_total`` is never spent.
- ``pay(to, amount, ref)`` behaves identically to the reference
  prepaid-credits plugin — a one-shot atomic transfer that does not
  interact with the streaming subsystem.
- ``verify_payment(ref)`` returns ``STREAMING`` for active streams,
  ``CONFIRMED`` for closed streams, ``FAILED`` for unknown refs.

Conservation invariant
----------------------
At every tick boundary (after ``drain_tick`` returns) the sum of all
agent balances equals the sum at construction, because every debit
has a matching credit.  The adversarial validator enforces this.

Example::

    pay = StreamingPayments(AgentId("a1"), initial_balance=1000)
    await pay.open_stream(AgentId("a2"), rate_per_tick=5, max_total=100, ref="s1")
    pay.drain_tick()   # 5 debited from a1, credited to a2
    pay.drain_tick()   # another 5
    receipt = await pay.close_stream(PaymentRef("s1"))  # 90 refunded (unused)
=======
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
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
"""

from __future__ import annotations

from dataclasses import dataclass
<<<<<<< HEAD
from typing import ClassVar
=======
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967

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
<<<<<<< HEAD
class StreamState:
    """Internal bookkeeping for a single open stream."""

    ref: PaymentRef
    payer: AgentId
    payee: AgentId
    rate_per_tick: int
    max_total: int
    tick_opened: int
    total_billed: int = 0
    closed: bool = False


class StreamingPayments:
    """Payments plugin with streaming (pay-per-tick) support.

    Example::

        pay = StreamingPayments(AgentId("a1"), initial_balance=1000)
        await pay.open_stream(AgentId("a2"), rate_per_tick=5, max_total=100, ref="s1")

        for _ in range(10):
            pay.drain_tick()
        # 50 credits moved from a1 → a2

        receipt = await pay.close_stream(PaymentRef("s1"))
        assert receipt.amount.amount == 50
    """

    _STREAMING_PAYMENT_STATUS: ClassVar[PaymentStatus] = PaymentStatus.PENDING
    """Status returned by ``verify_payment`` for an active (not yet closed) stream.

    We reuse ``PENDING`` rather than adding a new enum variant because:
    - The existing protocol consumers already handle ``PENDING`` gracefully
      (they treat it as "not yet final").
    - A stream *is* a pending payment — funds are committed but the final
      amount is not yet determined.
    - Adding a new enum variant would be a breaking change to the Payments
      protocol interface, which the hackathon charter says to avoid unless
      the problem explicitly requires it.
=======
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
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
<<<<<<< HEAD
=======
        streams: dict[PaymentRef, StreamHandle] | None = None,
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
<<<<<<< HEAD
        self._payments: dict[PaymentRef, Receipt] = payments if payments is not None else {}
        self._streams: dict[PaymentRef, StreamState] = {}
        self._tick: int = 0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
=======
        self._payments = payments if payments is not None else {}
        self._streams = streams if streams is not None else {}
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967

    def balance(self, agent: AgentId) -> int:
        """Check an agent's balance.

        Example::

<<<<<<< HEAD
            bal = pay.balance(AgentId("a1"))
        """
        return self._balances.get(agent, 0)

    @property
    def tick(self) -> int:
        """Current simulation tick (read-only)."""
        return self._tick

    @property
    def active_streams(self) -> int:
        """Number of streams that are still open (not closed)."""
        return sum(1 for s in self._streams.values() if not s.closed)

    # ------------------------------------------------------------------
    # Payments protocol (one-shot)
    # ------------------------------------------------------------------

=======
            bal = payments.balance(AgentId("payee"))
        """
        return self._balances.get(agent, 0)

>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

<<<<<<< HEAD
            q = await pay.quote(ServiceRef("svc"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a one-shot payment (non-streaming).

        This is the standard atomic transfer.  It does **not** interact
        with any open streams.

        Example::

            receipt = await pay.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
=======
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
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
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

<<<<<<< HEAD
        - Active stream → ``PENDING`` (streaming, final amount unknown).
        - Closed stream → ``CONFIRMED``.
        - Unknown ref → ``FAILED``.

        Example::

            status = await pay.verify_payment(PaymentRef("p1"))
        """
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        stream = self._streams.get(ref)
        if stream is not None:
            return PaymentStatus.CONFIRMED if stream.closed else PaymentStatus.PENDING
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a one-shot payment.

        Does **not** apply to streams — call ``close_stream`` instead.

        Example::

            await pay.refund(PaymentRef("p1"))
=======
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
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
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
<<<<<<< HEAD
        self._balances[receipt.payer] = (
            self._balances.get(receipt.payer, 0) + receipt.amount.amount
        )
        del self._payments[ref]

    # ------------------------------------------------------------------
    # Streaming API
    # ------------------------------------------------------------------

    async def open_stream(
        self,
        to: AgentId,
        rate_per_tick: int,
        max_total: int,
        ref: PaymentRef,
    ) -> PaymentRef:
        """Open a streaming payment channel.

        No funds move yet — debits happen one tick at a time inside
        ``drain_tick()``.

        Args:
            to: The payee agent.
            rate_per_tick: Credits to debit each tick while the stream
                is open.
            max_total: Absolute cap — the payer will never be debited
                more than this, even if the stream runs forever.
            ref: Unique reference handle for this stream.

        Returns:
            The ``ref`` that was passed in, usable as a stream handle.

        Raises:
            ValueError: If ``rate_per_tick <= 0``, ``max_total <= 0``,
                ``rate_per_tick > max_total``, or the ref is already in use.

        Example::

            handle = await pay.open_stream(
                AgentId("a2"), rate_per_tick=5, max_total=100, ref="s1",
            )
        """
        if rate_per_tick <= 0:
            msg = f"rate_per_tick must be positive: {rate_per_tick}"
            raise ValueError(msg)
        if max_total <= 0:
            msg = f"max_total must be positive: {max_total}"
            raise ValueError(msg)
        if rate_per_tick > max_total:
            msg = f"rate_per_tick ({rate_per_tick}) > max_total ({max_total})"
            raise ValueError(msg)
        if ref in self._streams or ref in self._payments:
            msg = f"Duplicate reference: {ref}"
            raise ValueError(msg)

        self._streams[ref] = StreamState(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            tick_opened=self._tick,
        )
        return ref

    async def close_stream(self, ref: PaymentRef) -> Receipt:
        """Close a stream and produce a final receipt.

        After this call the stream can never be drained again.
        The unused remainder of ``max_total`` is *never* spent.

        Args:
            ref: The stream reference returned by ``open_stream``.

        Returns:
            A ``Receipt`` with the total amount billed over the
            stream's lifetime.

        Raises:
            ValueError: If ``ref`` is not an active stream.

        Example::

            receipt = await pay.close_stream(PaymentRef("s1"))
            print(receipt.amount.amount)  # total billed
        """
        stream = self._streams.get(ref)
        if stream is None:
            msg = f"Stream not found: {ref}"
            raise ValueError(msg)
        if stream.closed:
            msg = f"Stream already closed: {ref}"
            raise ValueError(msg)

        stream.closed = True
        receipt = Receipt(
            ref=ref,
            payer=stream.payer,
            payee=stream.payee,
            amount=Money(amount=stream.total_billed),
        )
        self._payments[ref] = receipt
        return receipt

    # ------------------------------------------------------------------
    # Per-tick drain
    # ------------------------------------------------------------------

    def drain_tick(self) -> None:
        """Advance one simulation tick and drain all open streams.

        For every stream that is still open:
        - If the payer has at least ``rate_per_tick`` credits and
          ``total_billed < max_total``, debit ``rate_per_tick`` from
          the payer and credit the payee.
        - If the payer has insufficient balance, the stream is
          *silently paused* for this tick (no partial debit, no
          error).  It resumes on a future tick if the payer's
          balance recovers.

        The stream's ``total_billed`` is capped at ``max_total``.
        Once the cap is reached the stream remains open but no
        further debits occur (it becomes a zero-rate stream).

        **Conservation invariant:** The sum of all agent balances is
        unchanged by this method because every debit has a matching
        credit.

        Example::

            for _ in range(100):
                pay.drain_tick()
        """
        self._tick += 1
        for _ref, stream in self._streams.items():
            if stream.closed:
                continue
            if stream.total_billed >= stream.max_total:
                continue

            available = stream.max_total - stream.total_billed
            debit = min(stream.rate_per_tick, available)

            payer_balance = self._balances.get(stream.payer, 0)
            if payer_balance < debit:
                # Payer can't cover this tick — stream pauses silently.
                continue

            self._balances[stream.payer] = payer_balance - debit
            self._balances[stream.payee] = (
                self._balances.get(stream.payee, 0) + debit
            )
            stream.total_billed += debit

    # ------------------------------------------------------------------
    # Total balance (for conservation checks)
    # ------------------------------------------------------------------

    def total_balance(self) -> int:
        """Return the sum of all agent balances.

        Used by the adversarial validator to verify the conservation
        invariant after every tick drain.

        Example::

            assert pay.total_balance() == 5000  # must never change
        """
        return sum(self._balances.values())
=======
        self._balances[receipt.payer] = self._balances.get(receipt.payer, 0) + receipt.amount.amount
        del self._payments[ref]
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
