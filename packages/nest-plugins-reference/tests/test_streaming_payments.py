# SPDX-License-Identifier: Apache-2.0
"""Tests for the streaming payments plugin.

Covers delivery-gated draining, mid-stream cancellation, the drain-after-
close guard, one-shot ``pay()`` equivalence, verify/refund semantics, and
the conservation invariant.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus
from nest_plugins_reference.payments.streaming import StreamError, StreamingPayments


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
        """One-shot pay() moves the full amount and issues a receipt."""
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
    async def test_pay_equivalent_to_one_tick_stream(self, payments: StreamingPayments) -> None:
        """pay() behaves exactly like a stream that drains everything in one tick."""
        await payments.pay(AgentId("payee"), Money(amount=250), PaymentRef("pay-1"))
        handle = payments.stream(PaymentRef("pay-1"))
        assert handle is not None
        assert handle.rate_per_tick == 250
        assert handle.max_total == 250
        assert handle.total_debited == 250
        assert handle.closed_at_tick is not None
        assert await payments.verify_payment(PaymentRef("pay-1")) == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_pay_insufficient_balance(self, payments: StreamingPayments) -> None:
        """pay() rejects if insufficient balance, and moves nothing."""
        with pytest.raises(StreamError, match="Insufficient balance"):
            await payments.pay(
                AgentId("payee"),
                Money(amount=20000),
                PaymentRef("pay-1"),
            )
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0

    @pytest.mark.asyncio
    async def test_pay_duplicate_ref(self, payments: StreamingPayments) -> None:
        """pay() rejects a reused payment reference."""
        await payments.pay(
            AgentId("payee"),
            Money(amount=100),
            PaymentRef("pay-1"),
        )
        with pytest.raises(StreamError, match="already exists"):
            await payments.pay(
                AgentId("payee"),
                Money(amount=100),
                PaymentRef("pay-1"),
            )

    @pytest.mark.asyncio
    async def test_open_stream_debits_nothing(self, payments: StreamingPayments) -> None:
        """Opening a stream moves no money — billing follows delivery."""
        handle = await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
            at_tick=7,
        )
        assert handle.ref == PaymentRef("stream-1")
        assert handle.payer == AgentId("payer")
        assert handle.to == AgentId("payee")
        assert handle.rate_per_tick == 100
        assert handle.max_total == 500
        assert handle.opened_at_tick == 7
        assert handle.total_debited == 0
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0

    @pytest.mark.asyncio
    async def test_open_stream_insufficient_balance(
        self,
        payments: StreamingPayments,
    ) -> None:
        """open_stream() rejects a payer who cannot cover even one tick."""
        with pytest.raises(StreamError, match="Insufficient balance"):
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=20000,
                max_total=20000,
                ref=PaymentRef("stream-1"),
            )

    @pytest.mark.asyncio
    async def test_open_stream_invalid_rate(self, payments: StreamingPayments) -> None:
        """open_stream() rejects a non-positive rate."""
        with pytest.raises(StreamError, match="rate_per_tick must be positive"):
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
        """open_stream() rejects max_total < rate_per_tick."""
        with pytest.raises(StreamError, match="max_total"):
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=100,
                max_total=50,
                ref=PaymentRef("stream-1"),
            )

    @pytest.mark.asyncio
    async def test_tick_without_delivery_bills_nothing(
        self,
        payments: StreamingPayments,
    ) -> None:
        """No recorded delivery → tick_stream drains nothing (partition shape)."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        for tick in range(1, 50):
            assert await payments.tick_stream(PaymentRef("stream-1"), tick) == 0
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0

    @pytest.mark.asyncio
    async def test_tick_stream_drains_per_delivery(self, payments: StreamingPayments) -> None:
        """Each delivered unit is billed exactly once."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )

        assert payments.record_delivery(PaymentRef("stream-1"), unit=1)
        assert await payments.tick_stream(PaymentRef("stream-1"), 1) == 100
        assert payments.balance(AgentId("payer")) == 9900
        assert payments.balance(AgentId("payee")) == 100

        assert payments.record_delivery(PaymentRef("stream-1"), unit=2)
        assert await payments.tick_stream(PaymentRef("stream-1"), 2) == 100
        assert payments.balance(AgentId("payer")) == 9800
        assert payments.balance(AgentId("payee")) == 200

        # No new delivery: nothing further drains.
        assert await payments.tick_stream(PaymentRef("stream-1"), 3) == 0
        assert payments.balance(AgentId("payee")) == 200

    @pytest.mark.asyncio
    async def test_duplicate_delivery_never_double_bills(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Recording the same unit twice queues it once."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        assert payments.record_delivery(PaymentRef("stream-1"), unit=1)
        assert not payments.record_delivery(PaymentRef("stream-1"), unit=1)
        assert await payments.tick_stream(PaymentRef("stream-1"), 1) == 100
        assert not payments.record_delivery(PaymentRef("stream-1"), unit=1)
        assert await payments.tick_stream(PaymentRef("stream-1"), 2) == 0
        assert payments.balance(AgentId("payee")) == 100

    @pytest.mark.asyncio
    async def test_tick_stream_hits_max(self, payments: StreamingPayments) -> None:
        """The stream closes itself when max_total is reached."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=300,
            ref=PaymentRef("stream-1"),
        )
        for unit in (1, 2, 3):
            payments.record_delivery(PaymentRef("stream-1"), unit)
            await payments.tick_stream(PaymentRef("stream-1"), unit)

        handle = payments.stream(PaymentRef("stream-1"))
        assert handle is not None
        assert handle.closed_at_tick == 3
        assert payments.balance(AgentId("payee")) == 300

        # A fourth delivery is refused: the stream is closed.
        assert not payments.record_delivery(PaymentRef("stream-1"), 4)
        assert await payments.tick_stream(PaymentRef("stream-1"), 4) == 0

    @pytest.mark.asyncio
    async def test_tick_stream_insufficient_balance_stops_stream(self) -> None:
        """The stream closes when the payer runs dry mid-stream."""
        payments = StreamingPayments(AgentId("payer"), initial_balance=150)
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        payments.record_delivery(PaymentRef("stream-1"), 1)
        assert await payments.tick_stream(PaymentRef("stream-1"), 1) == 100
        payments.record_delivery(PaymentRef("stream-1"), 2)
        assert await payments.tick_stream(PaymentRef("stream-1"), 2) == 0

        handle = payments.stream(PaymentRef("stream-1"))
        assert handle is not None
        assert handle.closed_at_tick == 2
        assert payments.balance(AgentId("payer")) == 50
        assert payments.balance(AgentId("payee")) == 100

    @pytest.mark.asyncio
    async def test_close_stream_mid_stream(self, payments: StreamingPayments) -> None:
        """Closing mid-stream settles only what was billed; remainder never spent."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        for unit in (1, 2, 3):
            payments.record_delivery(PaymentRef("stream-1"), unit)
            await payments.tick_stream(PaymentRef("stream-1"), unit)

        receipt = await payments.close_stream(PaymentRef("stream-1"), at_tick=5)
        assert receipt.payer == AgentId("payer")
        assert receipt.payee == AgentId("payee")
        assert receipt.amount.amount == 300
        assert payments.balance(AgentId("payer")) == 9700

    @pytest.mark.asyncio
    async def test_close_stream_stops_the_bleed(self, payments: StreamingPayments) -> None:
        """After close, no delivery and no drain is accepted — at any tick."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        payments.record_delivery(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.close_stream(PaymentRef("stream-1"), at_tick=2)

        assert not payments.record_delivery(PaymentRef("stream-1"), 2)
        for tick in range(3, 30):
            assert await payments.tick_stream(PaymentRef("stream-1"), tick) == 0
        assert payments.balance(AgentId("payee")) == 100

    @pytest.mark.asyncio
    async def test_close_pending_deliveries_die_with_the_stream(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Deliveries recorded but not yet billed are not billed after close."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        payments.record_delivery(PaymentRef("stream-1"), 1)
        payments.record_delivery(PaymentRef("stream-1"), 2)
        await payments.close_stream(PaymentRef("stream-1"), at_tick=1)
        assert await payments.tick_stream(PaymentRef("stream-1"), 2) == 0
        assert payments.balance(AgentId("payee")) == 0

    @pytest.mark.asyncio
    async def test_close_stream_idempotent(self, payments: StreamingPayments) -> None:
        """A second close returns the stored receipt unchanged."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        first = await payments.close_stream(PaymentRef("stream-1"), at_tick=1)
        second = await payments.close_stream(PaymentRef("stream-1"), at_tick=99)
        assert first == second

    @pytest.mark.asyncio
    async def test_close_stream_unknown_ref(self, payments: StreamingPayments) -> None:
        """Closing a nonexistent stream raises."""
        with pytest.raises(StreamError, match="Stream not found"):
            await payments.close_stream(PaymentRef("nope"))

    @pytest.mark.asyncio
    async def test_payee_can_close_and_receipt_names_true_payer(self) -> None:
        """Either party can close; the receipt names the stream's payer."""
        balances: dict[AgentId, int] = {}
        payments_dict: dict[PaymentRef, object] = {}
        streams: dict[PaymentRef, object] = {}
        payer = StreamingPayments(
            AgentId("payer"),
            initial_balance=1000,
            balances=balances,
            payments=payments_dict,  # type: ignore[arg-type]
            streams=streams,  # type: ignore[arg-type]
        )
        payee = StreamingPayments(
            AgentId("payee"),
            initial_balance=0,
            balances=balances,
            payments=payments_dict,  # type: ignore[arg-type]
            streams=streams,  # type: ignore[arg-type]
        )
        await payer.open_stream(
            to=AgentId("payee"),
            rate_per_tick=10,
            max_total=100,
            ref=PaymentRef("s-1"),
        )
        payer.record_delivery(PaymentRef("s-1"), 1)
        await payer.tick_stream(PaymentRef("s-1"), 1)

        receipt = await payee.close_stream(PaymentRef("s-1"), at_tick=2)
        assert receipt.payer == AgentId("payer")
        assert receipt.payee == AgentId("payee")
        assert receipt.amount.amount == 10
        # And the payer's instance sees the same settled state.
        assert await payer.verify_payment(PaymentRef("s-1")) == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_verify_payment_confirmed(
        self,
        payments: StreamingPayments,
    ) -> None:
        """verify_payment for completed payments."""
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
        """A half-drained open stream reports STREAMING."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        payments.record_delivery(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        status = await payments.verify_payment(PaymentRef("stream-1"))
        assert status == PaymentStatus.STREAMING

    @pytest.mark.asyncio
    async def test_verify_payment_failed(
        self,
        payments: StreamingPayments,
    ) -> None:
        """verify_payment for a nonexistent ref."""
        status = await payments.verify_payment(PaymentRef("nonexistent"))
        assert status == PaymentStatus.FAILED

    @pytest.mark.asyncio
    async def test_conservation_invariant(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Conservation: system wealth is constant through stream activity."""
        payee1 = AgentId("payee1")
        payee2 = AgentId("payee2")

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

        for tick in (1, 2):
            payments.record_delivery(PaymentRef("stream-1"), tick)
            payments.record_delivery(PaymentRef("stream-2"), tick)
            await payments.tick_stream(PaymentRef("stream-1"), tick)
            await payments.tick_stream(PaymentRef("stream-2"), tick)

        assert payments.balance(AgentId("payer")) == 10000 - 200 - 100
        assert payments.balance(payee1) == 200
        assert payments.balance(payee2) == 100

        total = (
            payments.balance(payee1) + payments.balance(payee2) + payments.balance(AgentId("payer"))
        )
        assert total == 10000

    @pytest.mark.asyncio
    async def test_refund(self, payments: StreamingPayments) -> None:
        """A settled payment can be refunded in full."""
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

    @pytest.mark.asyncio
    async def test_refund_open_stream_rejected(self, payments: StreamingPayments) -> None:
        """An open stream cannot be refunded — it must be closed first."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        with pytest.raises(StreamError, match="close it first"):
            await payments.refund(PaymentRef("stream-1"))

    @pytest.mark.asyncio
    async def test_refund_closed_stream(self, payments: StreamingPayments) -> None:
        """A closed stream refunds exactly the billed total."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        payments.record_delivery(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.close_stream(PaymentRef("stream-1"), at_tick=2)

        await payments.refund(PaymentRef("stream-1"))
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0
