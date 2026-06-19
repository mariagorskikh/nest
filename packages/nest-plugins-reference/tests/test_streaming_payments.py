# SPDX-License-Identifier: Apache-2.0
<<<<<<< HEAD
"""Adversarial validator for the streaming payments plugin.

Validates two specific attack classes required by the hackathon problem:

1. **Drain-after-close**: Payer closes the stream but a buggy plugin
   keeps debiting.  Enforced: ``total_debited == total_credited`` at
   every tick boundary and a closed stream never moves funds.

2. **Over-bill on partition**: Payer is partitioned (balance drained
   externally) mid-stream; the plugin must not keep billing for ticks
   the payee can't deliver.  Enforced: payer balance never goes
   negative and conservation holds even when payers run dry.

NOTE: This test avoids importing ``nest_core.types`` (which pulls in
pydantic) so it can run in environments where pydantic_core DLLs are
restricted.  ``AgentId`` and ``PaymentRef`` are ``NewType("…", str)``
at runtime, so plain strings are equivalent.
=======
"""Tests for streaming payments plugin.

Tests conservation of funds, mid-stream cancellation, and streaming state.
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
"""

from __future__ import annotations

<<<<<<< HEAD
import asyncio

from nest_plugins_reference.payments.streaming import StreamingPayments

AgentId = str
PaymentRef = str


# ---------------------------------------------------------------------------
# Attack 1 — Drain-after-close
# ---------------------------------------------------------------------------


def test_conservation_under_normal_operation() -> None:
    """Every tick drain preserves the total balance.

    Open two streams between three agents, run them for 50 ticks,
    close one early, run another 50 ticks.  The total balance must
    never change.
    """
    pay_a = StreamingPayments(AgentId("a"), initial_balance=1000)
    pay_b = StreamingPayments(AgentId("b"), initial_balance=500)
    pay_c = StreamingPayments(AgentId("c"), initial_balance=200)

    ledger: dict[AgentId, int] = {
        AgentId("a"): 1000,
        AgentId("b"): 500,
        AgentId("c"): 200,
    }
    pay_a._balances = ledger
    pay_b._balances = ledger
    pay_c._balances = ledger

    initial_total = pay_a.total_balance()

    async def _setup() -> None:
        await pay_a.open_stream(AgentId("b"), rate_per_tick=3, max_total=150, ref=PaymentRef("s1"))
        await pay_b.open_stream(AgentId("c"), rate_per_tick=2, max_total=80, ref=PaymentRef("s2"))

    asyncio.run(_setup())

    for _ in range(50):
        pay_a.drain_tick()
        pay_b.drain_tick()
        pay_c.drain_tick()
    assert pay_a.total_balance() == initial_total, "Conservation violated after 50 ticks"

    asyncio.run(pay_a.close_stream(PaymentRef("s1")))

    balance_after_close = pay_a.total_balance()
    for _ in range(50):
        pay_a.drain_tick()
        pay_b.drain_tick()
        pay_c.drain_tick()
    assert pay_a.total_balance() == initial_total, "Conservation violated after close"
    assert pay_a.total_balance() == balance_after_close, (
        "Drain-after-close: balance changed after stream was closed"
    )


def test_closed_stream_never_debits_again() -> None:
    """After close_stream, drain_tick does not move any more funds."""
    pay = StreamingPayments(AgentId("payer"), initial_balance=1000)
    ledger: dict[AgentId, int] = {AgentId("payer"): 1000, AgentId("payee"): 0}
    pay._balances = ledger

    asyncio.run(
        pay.open_stream(
            AgentId("payee"), rate_per_tick=10, max_total=500,
            ref=PaymentRef("s1"),
        )
    )

    for _ in range(5):
        pay.drain_tick()
    payer_before = ledger[AgentId("payer")]

    asyncio.run(pay.close_stream(PaymentRef("s1")))

    for _ in range(100):
        pay.drain_tick()

    assert ledger[AgentId("payer")] == payer_before, (
        f"Drain-after-close: payer lost funds after close "
        f"({payer_before} -> {ledger[AgentId('payer')]})"
    )


# ---------------------------------------------------------------------------
# Attack 2 — Over-bill on partition
# ---------------------------------------------------------------------------


def test_over_bill_on_partition_payer_runs_dry() -> None:
    """Payer runs dry mid-stream: balance must stay >= 0, conservation holds."""
    pay_a = StreamingPayments(AgentId("a"), initial_balance=30)
    pay_b = StreamingPayments(AgentId("b"), initial_balance=500)
    ledger: dict[AgentId, int] = {AgentId("a"): 30, AgentId("b"): 500}
    pay_a._balances = ledger
    pay_b._balances = ledger

    initial_total = pay_a.total_balance()
    asyncio.run(
        pay_a.open_stream(
            AgentId("b"), rate_per_tick=10, max_total=200,
            ref=PaymentRef("p1"),
        )
    )

    for _ in range(10):
        pay_a.drain_tick()
        pay_b.drain_tick()

    assert ledger[AgentId("a")] >= 0, f"Over-bill: payer balance negative ({ledger[AgentId('a')]})"
    assert pay_a.total_balance() == initial_total, "Conservation violated after payer ran dry"


def test_partitioned_payer_stops_billing() -> None:
    """Payer at zero balance: no further debits occur."""
    pay = StreamingPayments(AgentId("p"), initial_balance=5)
    ledger: dict[AgentId, int] = {AgentId("p"): 5, AgentId("q"): 0}
    pay._balances = ledger

    asyncio.run(pay.open_stream(AgentId("q"), rate_per_tick=5, max_total=100, ref=PaymentRef("x1")))

    pay.drain_tick()
    assert ledger[AgentId("p")] == 0
    assert ledger[AgentId("q")] == 5

    for _ in range(50):
        pay.drain_tick()
    assert ledger[AgentId("p")] == 0, "Payer balance went negative"
    assert ledger[AgentId("q")] == 5, "Payee credited after payer ran dry"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_stream_capped_at_max_total() -> None:
    """Stream never bills more than max_total."""
    pay = StreamingPayments(AgentId("a"), initial_balance=1000)
    ledger: dict[AgentId, int] = {AgentId("a"): 1000, AgentId("b"): 0}
    pay._balances = ledger

    asyncio.run(
        pay.open_stream(
            AgentId("b"), rate_per_tick=50, max_total=200,
            ref=PaymentRef("cap_test"),
        )
    )

    for _ in range(100):
        pay.drain_tick()

    assert ledger[AgentId("a")] == 800, f"Expected 800, got {ledger[AgentId('a')]}"
    assert ledger[AgentId("b")] == 200, f"Expected 200, got {ledger[AgentId('b')]}"


def test_multiple_streams_same_payer() -> None:
    """Multiple concurrent streams from one payer obey conservation."""
    pay = StreamingPayments(AgentId("payer"), initial_balance=1000)
    ledger: dict[AgentId, int] = {AgentId("payer"): 1000, AgentId("a"): 0, AgentId("b"): 0}
    pay._balances = ledger

    initial_total = pay.total_balance()

    async def _setup() -> None:
        await pay.open_stream(AgentId("a"), rate_per_tick=3, max_total=90, ref=PaymentRef("m1"))
        await pay.open_stream(AgentId("b"), rate_per_tick=7, max_total=140, ref=PaymentRef("m2"))

    asyncio.run(_setup())

    for _ in range(30):
        pay.drain_tick()

    assert pay.total_balance() == initial_total
    assert ledger[AgentId("a")] == 90
    assert ledger[AgentId("b")] == 140
    assert ledger[AgentId("payer")] == 1000 - 90 - 140


def test_stream_close_receipt() -> None:
    """Closing a stream returns an accurate receipt."""
    pay = StreamingPayments(AgentId("me"), initial_balance=500)
    ledger: dict[AgentId, int] = {AgentId("me"): 500, AgentId("you"): 0}
    pay._balances = ledger

    asyncio.run(
        pay.open_stream(
            AgentId("you"), rate_per_tick=10, max_total=500,
            ref=PaymentRef("early"),
        )
    )

    for _ in range(3):
        pay.drain_tick()
    assert ledger[AgentId("me")] == 470
    assert ledger[AgentId("you")] == 30

    receipt = asyncio.run(pay.close_stream(PaymentRef("early")))
    assert receipt.amount.amount == 30
    # Future ticks must not bill
    for _ in range(10):
        pay.drain_tick()
    assert ledger[AgentId("me")] == 470
    assert ledger[AgentId("you")] == 30
=======
import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus
from nest_plugins_reference.payments.streaming import StreamingPayments


class TestStreamingPayments:
    """Test suite for StreamingPayments plugin."""

    @pytest.fixture
    def payments(self) -> StreamingPayments:
        """Create a fresh StreamingPayments instance."""
        return StreamingPayments(AgentId("payer"), initial_balance=10000)

    def test_init(self, payments: StreamingPayments) -> None:
        """Test initialization."""
        assert payments.balance(AgentId("payer")) == 10000

    def test_balance(self, payments: StreamingPayments) -> None:
        """Test balance queries."""
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0

    @pytest.mark.asyncio
    async def test_one_shot_pay(self, payments: StreamingPayments) -> None:
        """Test backward-compatible one-shot pay() method."""
        receipt = await payments.pay(
            AgentId("payee"),
            Money(amount=100),
            PaymentRef("pay-1"),
        )
        assert receipt.payer == AgentId("payer")
        assert receipt.payee == AgentId("payee")
        assert receipt.amount.amount == 100
        assert payments.balance(AgentId("payer")) == 9900
        assert payments.balance(AgentId("payee")) == 100

    @pytest.mark.asyncio
    async def test_pay_insufficient_balance(self, payments: StreamingPayments) -> None:
        """Test that pay() rejects if insufficient balance."""
        with pytest.raises(ValueError, match="Insufficient balance"):
            await payments.pay(
                AgentId("payee"),
                Money(amount=20000),
                PaymentRef("pay-1"),
            )

    @pytest.mark.asyncio
    async def test_pay_duplicate_ref(self, payments: StreamingPayments) -> None:
        """Test that pay() rejects duplicate payment reference."""
        await payments.pay(
            AgentId("payee"),
            Money(amount=100),
            PaymentRef("pay-1"),
        )
        with pytest.raises(ValueError, match="Duplicate"):
            await payments.pay(
                AgentId("payee"),
                Money(amount=100),
                PaymentRef("pay-1"),
            )

    @pytest.mark.asyncio
    async def test_open_stream_basic(self, payments: StreamingPayments) -> None:
        """Test opening a stream."""
        handle = await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        assert handle.ref == PaymentRef("stream-1")
        assert handle.to == AgentId("payee")
        assert handle.rate_per_tick == 100
        assert handle.max_total == 500
        assert handle.total_debited == 100  # First tick drained immediately
        assert payments.balance(AgentId("payer")) == 9900
        assert payments.balance(AgentId("payee")) == 100

    @pytest.mark.asyncio
    async def test_open_stream_insufficient_balance(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that open_stream() rejects if insufficient balance for first tick."""
        with pytest.raises(ValueError, match="Insufficient balance"):
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=20000,
                max_total=20000,
                ref=PaymentRef("stream-1"),
            )

    @pytest.mark.asyncio
    async def test_open_stream_invalid_rate(self, payments: StreamingPayments) -> None:
        """Test that open_stream() rejects invalid rate."""
        with pytest.raises(ValueError, match="rate_per_tick must be positive"):
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=0,
                max_total=100,
                ref=PaymentRef("stream-1"),
            )

    @pytest.mark.asyncio
    async def test_open_stream_max_less_than_rate(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that open_stream() rejects max_total < rate_per_tick."""
        with pytest.raises(ValueError, match="max_total"):
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=100,
                max_total=50,
                ref=PaymentRef("stream-1"),
            )

    @pytest.mark.asyncio
    async def test_tick_stream(self, payments: StreamingPayments) -> None:
        """Test draining ticks from a stream."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )

        # Tick 1: drain 100
        still_open = await payments.tick_stream(PaymentRef("stream-1"), 1)
        assert still_open
        assert payments.balance(AgentId("payer")) == 9800
        assert payments.balance(AgentId("payee")) == 200

        # Tick 2: drain 100
        still_open = await payments.tick_stream(PaymentRef("stream-1"), 2)
        assert still_open
        assert payments.balance(AgentId("payer")) == 9700
        assert payments.balance(AgentId("payee")) == 300

    @pytest.mark.asyncio
    async def test_tick_stream_hits_max(self, payments: StreamingPayments) -> None:
        """Test that stream closes when max_total is reached."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=300,
            ref=PaymentRef("stream-1"),
        )

        # First tick already drained 100
        # Tick 1: drain 100 (total 200)
        still_open = await payments.tick_stream(PaymentRef("stream-1"), 1)
        assert still_open

        # Tick 2: drain 100 (total 300 = max) -> stream closes
        still_open = await payments.tick_stream(PaymentRef("stream-1"), 2)
        assert not still_open
        assert payments.balance(AgentId("payee")) == 300

    @pytest.mark.asyncio
    async def test_tick_stream_insufficient_balance(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that stream closes if payer runs out of balance."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=5000,
            max_total=50000,
            ref=PaymentRef("stream-1"),
        )

        # First tick drained 5000 -> balance is 5000
        # Tick 1: drain 5000 -> balance 0
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        assert payments.balance(AgentId("payer")) == 0

        # Tick 2: insufficient funds -> stream closes
        still_open = await payments.tick_stream(PaymentRef("stream-1"), 2)
        assert not still_open

    @pytest.mark.asyncio
    async def test_close_stream(self, payments: StreamingPayments) -> None:
        """Test closing a stream."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )

        # Drain 2 more ticks
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-1"), 2)

        # Close the stream (300 transferred so far)
        receipt = await payments.close_stream(PaymentRef("stream-1"))
        assert receipt.payer == AgentId("payer")
        assert receipt.payee == AgentId("payee")
        assert receipt.amount.amount == 300

    @pytest.mark.asyncio
    async def test_verify_payment_confirmed(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test verify_payment for completed payments."""
        await payments.pay(
            AgentId("payee"),
            Money(amount=100),
            PaymentRef("pay-1"),
        )
        status = await payments.verify_payment(PaymentRef("pay-1"))
        assert status == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_verify_payment_streaming(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test verify_payment for open streams."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        status = await payments.verify_payment(PaymentRef("stream-1"))
        assert status == PaymentStatus.STREAMING

    @pytest.mark.asyncio
    async def test_verify_payment_failed(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test verify_payment for non-existent ref."""
        status = await payments.verify_payment(PaymentRef("nonexistent"))
        assert status == PaymentStatus.FAILED

    @pytest.mark.asyncio
    async def test_conservation_invariant(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test conservation: total debited == total credited."""
        payee1 = AgentId("payee1")
        payee2 = AgentId("payee2")

        # Open two streams
        await payments.open_stream(
            to=payee1,
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        await payments.open_stream(
            to=payee2,
            rate_per_tick=50,
            max_total=250,
            ref=PaymentRef("stream-2"),
        )

        # Initial: payer 10000 - 100 - 50 = 9850
        assert payments.balance(AgentId("payer")) == 9850
        assert payments.balance(payee1) == 100
        assert payments.balance(payee2) == 50

        # Tick both streams
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-2"), 1)

        # payer: 9850 - 100 - 50 = 9700; payee1: 200; payee2: 100
        assert payments.balance(AgentId("payer")) == 9700
        assert payments.balance(payee1) == 200
        assert payments.balance(payee2) == 100

        # Verify conservation
        total_paid_out = (
            payments.balance(payee1) + payments.balance(payee2) + payments.balance(AgentId("payer"))
        )
        assert total_paid_out == 10000  # Total system wealth preserved

    @pytest.mark.asyncio
    async def test_refund(self, payments: StreamingPayments) -> None:
        """Test refunding a payment."""
        await payments.pay(
            AgentId("payee"),
            Money(amount=100),
            PaymentRef("pay-1"),
        )
        assert payments.balance(AgentId("payer")) == 9900
        assert payments.balance(AgentId("payee")) == 100

        await payments.refund(PaymentRef("pay-1"))
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0
>>>>>>> 2c00cf854e3591edeb9cd98d9aef6a4b80640967
