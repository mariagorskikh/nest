# SPDX-License-Identifier: Apache-2.0
"""Tests for streaming payments plugin.

Tests conservation of funds, mid-stream cancellation, idempotency,
stream refund, audit trail, and streaming state.

Example::

    pytest packages/nest-plugins-reference/tests/test_streaming_payments.py -v
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus
from nest_plugins_reference.payments.streaming import (
    StreamEntry,
    StreamError,
    StreamingPayments,
)


class TestStreamingPayments:
    """Test suite for StreamingPayments plugin."""

    @pytest.fixture
    def payments(self) -> StreamingPayments:
        """Create a fresh StreamingPayments instance."""
        return StreamingPayments(AgentId("payer"), initial_balance=10000)

    def test_init(self, payments: StreamingPayments) -> None:
        """Test initialization."""
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.stream_count() == 0

    def test_balance(self, payments: StreamingPayments) -> None:
        """Test balance queries."""
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0

    # -- one-shot payments ------------------------------------------------

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
    async def test_pay_idempotent(self, payments: StreamingPayments) -> None:
        """Test that pay() is idempotent for the same ref."""
        r1 = await payments.pay(
            AgentId("payee"),
            Money(amount=100),
            PaymentRef("pay-1"),
        )
        r2 = await payments.pay(
            AgentId("payee"),
            Money(amount=100),
            PaymentRef("pay-1"),
        )
        assert r1.ref == r2.ref
        assert r1.amount.amount == r2.amount.amount
        assert payments.balance(AgentId("payer")) == 9900  # Not double-debited

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
    async def test_pay_duplicate_ref_with_stream(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that pay() rejects ref already used as a stream."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=10,
            max_total=500,
            ref=PaymentRef("s-1"),
        )
        with pytest.raises(StreamError, match="Reference already in use"):
            await payments.pay(
                AgentId("payee"),
                Money(amount=100),
                PaymentRef("s-1"),
            )

    # -- stream open -------------------------------------------------------

    @pytest.mark.asyncio
    async def test_open_stream_basic(self, payments: StreamingPayments) -> None:
        """Test opening a stream drains first tick immediately."""
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
        assert handle.total_debited == 100
        assert handle.is_open
        assert handle.tick_count == 1
        assert payments.balance(AgentId("payer")) == 9900
        assert payments.balance(AgentId("payee")) == 100

    @pytest.mark.asyncio
    async def test_open_stream_idempotent(self, payments: StreamingPayments) -> None:
        """Test that open_stream() is idempotent."""
        h1 = await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        h2 = await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        assert h1 is h2  # Same object
        assert payments.balance(AgentId("payer")) == 9900  # Not double-drained

    @pytest.mark.asyncio
    async def test_open_stream_rejects_already_closed(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that open_stream() raises for an already-closed stream."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=100,
            ref=PaymentRef("stream-1"),
        )
        # Close by maxing out the first tick (already drained 100 = max_total)
        assert payments.balance(AgentId("payee")) == 100
        with pytest.raises(StreamError, match="already closed"):
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=100,
                max_total=100,
                ref=PaymentRef("stream-1"),
            )

    @pytest.mark.asyncio
    async def test_open_stream_insufficient_balance(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that open_stream() rejects insufficient balance for first tick."""
        with pytest.raises(ValueError, match="Insufficient balance"):
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=20000,
                max_total=20000,
                ref=PaymentRef("stream-1"),
            )

    @pytest.mark.asyncio
    async def test_open_stream_invalid_rate(self, payments: StreamingPayments) -> None:
        """Test that open_stream() rejects zero/negative rate."""
        with pytest.raises(ValueError, match="rate_per_tick must be >= 1"):
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

    # -- tick stream -------------------------------------------------------

    @pytest.mark.asyncio
    async def test_tick_stream(self, payments: StreamingPayments) -> None:
        """Test draining ticks from a stream."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )

        still_open = await payments.tick_stream(PaymentRef("stream-1"), 1)
        assert still_open
        assert payments.balance(AgentId("payer")) == 9800
        assert payments.balance(AgentId("payee")) == 200

        still_open = await payments.tick_stream(PaymentRef("stream-1"), 2)
        assert still_open
        assert payments.balance(AgentId("payer")) == 9700
        assert payments.balance(AgentId("payee")) == 300

    @pytest.mark.asyncio
    async def test_tick_stream_idempotent(self, payments: StreamingPayments) -> None:
        """Test that tick_stream() does not double-bill the same tick."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )

        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-1"), 1)  # Same tick
        assert payments.balance(AgentId("payee")) == 200  # Only one debit for tick 1

    @pytest.mark.asyncio
    async def test_tick_stream_hits_max(self, payments: StreamingPayments) -> None:
        """Test that stream closes when max_total is reached."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=300,
            ref=PaymentRef("stream-1"),
        )

        still_open = await payments.tick_stream(PaymentRef("stream-1"), 1)
        assert still_open

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

        await payments.tick_stream(PaymentRef("stream-1"), 1)
        assert payments.balance(AgentId("payer")) == 0

        still_open = await payments.tick_stream(PaymentRef("stream-1"), 2)
        assert not still_open

    @pytest.mark.asyncio
    async def test_tick_stream_never_exceeds_rate(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that a single tick never drains more than rate_per_tick."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=10,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        # The open already drained 10.  Balance: payer=9990, payee=10
        bal_before = payments.balance(AgentId("payee"))
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        bal_after = payments.balance(AgentId("payee"))
        assert bal_after - bal_before == 10  # Exactly rate_per_tick

    # -- close stream ------------------------------------------------------

    @pytest.mark.asyncio
    async def test_close_stream(self, payments: StreamingPayments) -> None:
        """Test closing a stream produces correct receipt."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-1"), 2)

        receipt = await payments.close_stream(PaymentRef("stream-1"))
        assert receipt.payer == AgentId("payer")
        assert receipt.payee == AgentId("payee")
        assert receipt.amount.amount == 300  # 3 ticks x 100

    @pytest.mark.asyncio
    async def test_close_stream_idempotent(self, payments: StreamingPayments) -> None:
        """Test that close_stream() is idempotent."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        r1 = await payments.close_stream(PaymentRef("stream-1"))
        r2 = await payments.close_stream(PaymentRef("stream-1"))
        assert r1.amount.amount == r2.amount.amount  # Same receipt

    @pytest.mark.asyncio
    async def test_close_stream_not_found(self, payments: StreamingPayments) -> None:
        """Test that close_stream() raises for unknown ref."""
        with pytest.raises(StreamError, match="not found"):
            await payments.close_stream(PaymentRef("nonexistent"))

    # -- stream refund -----------------------------------------------------

    @pytest.mark.asyncio
    async def test_refund_stream(self, payments: StreamingPayments) -> None:
        """Test refunding a closed stream returns funds to payer."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-1"), 2)
        await payments.close_stream(PaymentRef("stream-1"))

        assert payments.balance(AgentId("payer")) == 9700
        assert payments.balance(AgentId("payee")) == 300

        refund = await payments.refund_stream(PaymentRef("stream-1"))
        assert refund.payer == AgentId("payee")  # roles swapped
        assert refund.payee == AgentId("payer")
        assert refund.amount.amount == 300
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0

    @pytest.mark.asyncio
    async def test_refund_stream_open_raises(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that refund_stream() raises for an open stream."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        with pytest.raises(StreamError, match="Cannot refund open"):
            await payments.refund_stream(PaymentRef("stream-1"))

    @pytest.mark.asyncio
    async def test_refund_stream_insufficient_balance(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that refund_stream() raises if payee spent the funds."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        await payments.close_stream(PaymentRef("stream-1"))
        # Spend the payee's balance
        payee_plugin = StreamingPayments(
            AgentId("payee"),
            balances=payments._balances,  # pyright: ignore[reportPrivateUsage]
        )
        await payee_plugin.pay(
            AgentId("payer"),
            Money(amount=100),
            PaymentRef("spend-it"),
        )
        with pytest.raises(StreamError, match="Insufficient balance"):
            await payments.refund_stream(PaymentRef("stream-1"))

    # -- verify_payment ----------------------------------------------------

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
    async def test_verify_payment_closed_stream(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test verify_payment for closed streams returns CONFIRMED."""
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        await payments.close_stream(PaymentRef("stream-1"))
        status = await payments.verify_payment(PaymentRef("stream-1"))
        assert status == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_verify_payment_failed(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test verify_payment for non-existent ref."""
        status = await payments.verify_payment(PaymentRef("nonexistent"))
        assert status == PaymentStatus.FAILED

    # -- conservation invariant --------------------------------------------

    @pytest.mark.asyncio
    async def test_conservation_invariant(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test conservation: total system wealth is preserved."""
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

        assert payments.balance(AgentId("payer")) == 9850
        assert payments.balance(payee1) == 100
        assert payments.balance(payee2) == 50

        await payments.tick_stream(PaymentRef("stream-1"), 1)
        await payments.tick_stream(PaymentRef("stream-2"), 1)

        assert payments.balance(AgentId("payer")) == 9700
        assert payments.balance(payee1) == 200
        assert payments.balance(payee2) == 100

        total = (
            payments.balance(AgentId("payer")) + payments.balance(payee1) + payments.balance(payee2)
        )
        assert total == 10000

    # -- locked funds tracking ---------------------------------------------

    @pytest.mark.asyncio
    async def test_locked_funds(self, payments: StreamingPayments) -> None:
        """Test locked_funds() reports remaining liability."""
        assert payments.locked_funds() == 0

        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=100,
            max_total=500,
            ref=PaymentRef("stream-1"),
        )
        # Opened + 1 tick: 100 debited, 400 remaining cap
        assert payments.locked_funds() == 400

        await payments.tick_stream(PaymentRef("stream-1"), 1)
        assert payments.locked_funds() == 300

        await payments.close_stream(PaymentRef("stream-1"))
        assert payments.locked_funds() == 0

    # -- refund ------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_refund_one_shot(self, payments: StreamingPayments) -> None:
        """Test refunding a one-shot payment."""
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

    # -- stream query helpers ----------------------------------------------

    @pytest.mark.asyncio
    async def test_active_streams(self, payments: StreamingPayments) -> None:
        """Test active_streams() returns only open streams."""
        assert len(payments.active_streams()) == 0

        await payments.open_stream(
            to=AgentId("payee1"),
            rate_per_tick=10,
            max_total=100,
            ref=PaymentRef("s-1"),
        )
        await payments.open_stream(
            to=AgentId("payee2"),
            rate_per_tick=10,
            max_total=100,
            ref=PaymentRef("s-2"),
        )
        assert len(payments.active_streams()) == 2

        await payments.close_stream(PaymentRef("s-1"))
        assert len(payments.active_streams()) == 1
        assert payments.active_streams()[0].ref == PaymentRef("s-2")

    # -- audit trail -------------------------------------------------------

    @pytest.mark.asyncio
    async def test_stream_entries_audit_trail(
        self,
        payments: StreamingPayments,
    ) -> None:
        """Test that stream entries record every debit with tick and amount."""
        h = await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=10,
            max_total=50,
            ref=PaymentRef("s-1"),
            current_tick=5,
        )
        await payments.tick_stream(PaymentRef("s-1"), 6)
        await payments.tick_stream(PaymentRef("s-1"), 7)

        assert len(h.entries) == 3
        assert h.entries[0] == StreamEntry(tick=5, amount=10, kind="debit")
        assert h.entries[1] == StreamEntry(tick=6, amount=10, kind="debit")
        assert h.entries[2] == StreamEntry(tick=7, amount=10, kind="debit")
        assert h.tick_count == 3
