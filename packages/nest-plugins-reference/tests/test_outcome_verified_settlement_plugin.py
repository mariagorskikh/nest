# SPDX-License-Identifier: Apache-2.0
"""Tests for the ChainAIM outcome-verified settlement plugin."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.payments import Payments
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus
from nest_plugins_reference.payments.outcome_verified_settlement import (
    OutcomeVerifiedSettlement,
    StreamHandle,
)


def _make(balance: int = 1000) -> tuple[OutcomeVerifiedSettlement, dict[AgentId, int]]:
    balances: dict[AgentId, int] = {}
    plugin = OutcomeVerifiedSettlement(AgentId("payer"), initial_balance=balance, balances=balances)
    return plugin, balances


class TestProtocolCompat:
    def test_isinstance_payments(self) -> None:
        plugin, _ = _make()
        assert isinstance(plugin, Payments)

    async def test_pay_is_one_tick_full_drain(self) -> None:
        plugin, balances = _make(balance=100)
        receipt = await plugin.pay(AgentId("payee"), Money(amount=30), PaymentRef("p1"))
        assert receipt.amount.amount == 30
        assert balances[AgentId("payer")] == 70
        assert balances[AgentId("payee")] == 30
        assert await plugin.verify_payment(PaymentRef("p1")) == PaymentStatus.CONFIRMED

    async def test_pay_rejects_non_positive(self) -> None:
        plugin, _ = _make()
        with pytest.raises(ValueError, match="positive"):
            await plugin.pay(AgentId("payee"), Money(amount=0), PaymentRef("p0"))


class TestStreaming:
    async def test_open_returns_handle(self) -> None:
        plugin, _ = _make()
        handle = await plugin.open_stream(
            AgentId("payee"), 5, 50, PaymentRef("s1"), opened_at_tick=0
        )
        assert isinstance(handle, StreamHandle)
        assert handle.status == "open"
        assert handle.drained == 0

    async def test_advance_drains_per_tick(self) -> None:
        plugin, balances = _make()
        await plugin.open_stream(AgentId("payee"), 5, 50, PaymentRef("s1"), opened_at_tick=0)
        drained = await plugin.advance(PaymentRef("s1"), now_tick=3)
        assert drained == 15
        assert balances[AgentId("payer")] == 1000 - 15
        assert balances[AgentId("payee")] == 15

    async def test_advance_caps_at_max_total(self) -> None:
        plugin, _ = _make()
        await plugin.open_stream(AgentId("payee"), 5, 12, PaymentRef("s1"), opened_at_tick=0)
        drained = await plugin.advance(PaymentRef("s1"), now_tick=100)
        assert drained == 12  # capped, not 500

    async def test_advance_is_idempotent_per_tick(self) -> None:
        plugin, _ = _make()
        await plugin.open_stream(AgentId("payee"), 1, 50, PaymentRef("s1"), opened_at_tick=0)
        first = await plugin.advance(PaymentRef("s1"), now_tick=3)
        second = await plugin.advance(PaymentRef("s1"), now_tick=3)
        assert first == 3
        assert second == 0

    async def test_close_freezes_and_remainder_unspent(self) -> None:
        plugin, balances = _make()
        await plugin.open_stream(AgentId("payee"), 1, 40, PaymentRef("s1"), opened_at_tick=0)
        await plugin.advance(PaymentRef("s1"), now_tick=2)
        receipt = await plugin.close_stream(PaymentRef("s1"), now_tick=2)
        assert receipt.amount.amount == 2
        # remainder (40 - 2) never spent
        assert balances[AgentId("payer")] == 1000 - 2
        assert balances[AgentId("payee")] == 2

    async def test_no_drain_after_close(self) -> None:
        plugin, _ = _make()
        await plugin.open_stream(AgentId("payee"), 1, 40, PaymentRef("s1"), opened_at_tick=0)
        await plugin.advance(PaymentRef("s1"), now_tick=2)
        await plugin.close_stream(PaymentRef("s1"), now_tick=2)
        after = await plugin.advance(PaymentRef("s1"), now_tick=10)
        assert after == 0

    async def test_verify_open_then_closed(self) -> None:
        plugin, _ = _make()
        await plugin.open_stream(AgentId("payee"), 1, 40, PaymentRef("s1"), opened_at_tick=0)
        assert await plugin.verify_payment(PaymentRef("s1")) == PaymentStatus.STREAMING
        await plugin.close_stream(PaymentRef("s1"), now_tick=3)
        assert await plugin.verify_payment(PaymentRef("s1")) == PaymentStatus.CONFIRMED

    async def test_verify_unknown_ref(self) -> None:
        plugin, _ = _make()
        assert await plugin.verify_payment(PaymentRef("nope")) == PaymentStatus.FAILED

    async def test_open_rejects_bad_params(self) -> None:
        plugin, _ = _make()
        with pytest.raises(ValueError, match="rate_per_tick"):
            await plugin.open_stream(AgentId("payee"), 0, 50, PaymentRef("s1"), opened_at_tick=0)
        with pytest.raises(ValueError, match="max_total"):
            await plugin.open_stream(AgentId("payee"), 1, 0, PaymentRef("s2"), opened_at_tick=0)

    async def test_close_returns_zero_drained_when_never_advanced(self) -> None:
        plugin, balances = _make()
        await plugin.open_stream(AgentId("payee"), 5, 50, PaymentRef("s1"), opened_at_tick=7)
        receipt = await plugin.close_stream(PaymentRef("s1"), now_tick=7)
        assert receipt.amount.amount == 0
        assert balances.get(AgentId("payee"), 0) == 0


class TestConservationProperty:
    @settings(max_examples=50, deadline=None)
    @given(
        rate=st.integers(min_value=1, max_value=10),
        max_total=st.integers(min_value=1, max_value=100),
        deltas=st.lists(st.integers(min_value=0, max_value=20), max_size=20),
    )
    @pytest.mark.asyncio
    async def test_debit_equals_credit_and_capped(
        self, rate: int, max_total: int, deltas: list[int]
    ) -> None:
        """For any monotonic advance sequence: payer debit == payee credit <= cap."""
        balances: dict[AgentId, int] = {}
        plugin = OutcomeVerifiedSettlement(
            AgentId("payer"), initial_balance=100000, balances=balances
        )
        ref = PaymentRef("s")
        await plugin.open_stream(AgentId("payee"), rate, max_total, ref, opened_at_tick=0)
        payer0 = balances[AgentId("payer")]
        now = 0
        total = 0
        for d in deltas:
            now += d
            total += await plugin.advance(ref, now_tick=now)
        receipt = await plugin.close_stream(ref, now_tick=now)
        assert balances[AgentId("payer")] == payer0 - total
        assert balances.get(AgentId("payee"), 0) == total
        assert total <= max_total
        assert receipt.amount.amount == total

    @settings(max_examples=50, deadline=None)
    @given(
        deltas=st.lists(st.integers(min_value=0, max_value=15), max_size=15),
        pay_amt=st.integers(min_value=1, max_value=50),
    )
    @pytest.mark.asyncio
    async def test_total_funds_conserved_under_random_ops(
        self, deltas: list[int], pay_amt: int
    ) -> None:
        """No op creates or destroys credits: total balance is invariant throughout.

        Adaptation of PR #7's ``test_conservation_under_random_op_sequence`` -- the
        conservation-of-funds invariant the spec names for drain-after-close.
        Asserted after every open/advance/close/pay/refund, not just at the end.
        """
        balances: dict[AgentId, int] = {}
        plugin = OutcomeVerifiedSettlement(
            AgentId("payer"), initial_balance=100000, balances=balances
        )
        balances.setdefault(AgentId("payee"), 0)
        total0 = sum(balances.values())

        ref = PaymentRef("s")
        await plugin.open_stream(AgentId("payee"), 1, 1000, ref, opened_at_tick=0)
        assert sum(balances.values()) == total0
        now = 0
        for d in deltas:
            now += d
            await plugin.advance(ref, now_tick=now)
            assert sum(balances.values()) == total0
        await plugin.close_stream(ref, now_tick=now)
        assert sum(balances.values()) == total0

        await plugin.pay(AgentId("payee"), Money(amount=pay_amt), PaymentRef("p"))
        assert sum(balances.values()) == total0
        await plugin.refund(PaymentRef("p"))
        assert sum(balances.values()) == total0


class TestRefund:
    async def test_refund_reverses_closed_stream(self) -> None:
        plugin, balances = _make()
        await plugin.open_stream(AgentId("payee"), 1, 40, PaymentRef("s1"), opened_at_tick=0)
        await plugin.advance(PaymentRef("s1"), now_tick=3)
        await plugin.close_stream(PaymentRef("s1"), now_tick=3)
        assert balances[AgentId("payer")] == 1000 - 3
        assert balances[AgentId("payee")] == 3
        await plugin.refund(PaymentRef("s1"))
        assert balances[AgentId("payer")] == 1000
        assert balances[AgentId("payee")] == 0
        assert await plugin.verify_payment(PaymentRef("s1")) == PaymentStatus.REFUNDED

    async def test_refund_one_shot_pay(self) -> None:
        plugin, balances = _make(balance=100)
        await plugin.pay(AgentId("payee"), Money(amount=30), PaymentRef("p1"))
        await plugin.refund(PaymentRef("p1"))
        assert balances[AgentId("payer")] == 100
        assert balances[AgentId("payee")] == 0
        assert await plugin.verify_payment(PaymentRef("p1")) == PaymentStatus.REFUNDED

    async def test_refund_unknown_raises(self) -> None:
        plugin, _ = _make()
        with pytest.raises(ValueError, match="not found"):
            await plugin.refund(PaymentRef("nope"))

    async def test_refund_open_stream_raises(self) -> None:
        plugin, _ = _make()
        await plugin.open_stream(AgentId("payee"), 1, 40, PaymentRef("s1"), opened_at_tick=0)
        await plugin.advance(PaymentRef("s1"), now_tick=2)
        with pytest.raises(ValueError, match="still open"):
            await plugin.refund(PaymentRef("s1"))


class TestSpecSignatures:
    async def test_open_and_close_with_spec_signatures(self) -> None:
        # Spec API shape: open_stream(to, rate, max, ref) and close_stream(ref).
        plugin, _ = _make()
        handle = await plugin.open_stream(AgentId("payee"), 1, 10, PaymentRef("s1"))
        assert handle.status == "open"
        await plugin.advance(PaymentRef("s1"), now_tick=2)
        receipt = await plugin.close_stream(PaymentRef("s1"))
        assert receipt.amount.amount == 2
