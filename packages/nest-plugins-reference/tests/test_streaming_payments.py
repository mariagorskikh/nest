# SPDX-License-Identifier: Apache-2.0
"""Tests for streaming payments plugin.

Tests conservation of funds, mid-stream cancellation, and streaming state.
"""

from __future__ import annotations

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
