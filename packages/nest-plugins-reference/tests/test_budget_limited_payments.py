# SPDX-License-Identifier: Apache-2.0
"""Tests for the budget-limited payments plugin.

Covers the cumulative spend cap (distinct from balance), currency isolation,
refund releasing budget, and a Hypothesis invariant that confirmed spend can
never exceed the budget across arbitrary payment sequences.
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus
from nest_plugins_reference.payments.budget_limited import BudgetLimitedPayments


class TestBudgetLimitedPayments:
    """Example-based tests for BudgetLimitedPayments."""

    @pytest.fixture
    def payments(self) -> BudgetLimitedPayments:
        """A payer with ample balance but a tight budget of 1000."""
        return BudgetLimitedPayments(AgentId("payer"), initial_balance=10000, budget=1000)

    def test_init(self, payments: BudgetLimitedPayments) -> None:
        """Balance, spend, and remaining start as configured."""
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.spent() == 0
        assert payments.remaining() == 1000

    @pytest.mark.asyncio
    async def test_pay_within_budget(self, payments: BudgetLimitedPayments) -> None:
        """A payment within budget moves funds and decrements remaining."""
        receipt = await payments.pay(AgentId("payee"), Money(amount=400), PaymentRef("p1"))
        assert receipt.amount.amount == 400
        assert payments.balance(AgentId("payer")) == 9600
        assert payments.balance(AgentId("payee")) == 400
        assert payments.spent() == 400
        assert payments.remaining() == 600

    @pytest.mark.asyncio
    async def test_spend_accumulates(self, payments: BudgetLimitedPayments) -> None:
        """Cumulative spend accrues across payments."""
        await payments.pay(AgentId("payee"), Money(amount=400), PaymentRef("p1"))
        await payments.pay(AgentId("payee"), Money(amount=400), PaymentRef("p2"))
        assert payments.spent() == 800
        assert payments.remaining() == 200

    @pytest.mark.asyncio
    async def test_over_budget_refused_without_moving_funds(
        self, payments: BudgetLimitedPayments
    ) -> None:
        """An over-budget payment raises and leaves all state untouched."""
        await payments.pay(AgentId("payee"), Money(amount=800), PaymentRef("p1"))
        with pytest.raises(ValueError, match="Budget exceeded"):
            await payments.pay(AgentId("payee"), Money(amount=400), PaymentRef("p2"))
        # No funds moved, spend unchanged, ref not recorded.
        assert payments.spent() == 800
        assert payments.balance(AgentId("payer")) == 9200
        assert await payments.verify_payment(PaymentRef("p2")) == PaymentStatus.FAILED

    def test_within_budget(self, payments: BudgetLimitedPayments) -> None:
        """within_budget reflects remaining headroom and currency."""
        assert payments.within_budget(Money(amount=1000)) is True
        assert payments.within_budget(Money(amount=1001)) is False
        assert payments.within_budget(Money(amount=100, currency="usd")) is False

    @pytest.mark.asyncio
    async def test_currency_mismatch_refused(self, payments: BudgetLimitedPayments) -> None:
        """A payment in a different currency is rejected, not summed."""
        with pytest.raises(ValueError, match="Currency mismatch"):
            await payments.pay(AgentId("payee"), Money(amount=10, currency="usd"), PaymentRef("p1"))

    @pytest.mark.asyncio
    async def test_non_positive_amount_refused(self, payments: BudgetLimitedPayments) -> None:
        """Zero or negative amounts are rejected."""
        with pytest.raises(ValueError, match="must be positive"):
            await payments.pay(AgentId("payee"), Money(amount=0), PaymentRef("p1"))

    @pytest.mark.asyncio
    async def test_duplicate_ref_refused(self, payments: BudgetLimitedPayments) -> None:
        """A reused payment reference is rejected."""
        await payments.pay(AgentId("payee"), Money(amount=100), PaymentRef("p1"))
        with pytest.raises(ValueError, match="Duplicate payment reference"):
            await payments.pay(AgentId("payee"), Money(amount=100), PaymentRef("p1"))

    @pytest.mark.asyncio
    async def test_insufficient_balance_refused(self) -> None:
        """Budget headroom does not bypass an insufficient balance."""
        payments = BudgetLimitedPayments(AgentId("payer"), initial_balance=50, budget=1000)
        with pytest.raises(ValueError, match="Insufficient balance"):
            await payments.pay(AgentId("payee"), Money(amount=100), PaymentRef("p1"))

    @pytest.mark.asyncio
    async def test_refund_releases_budget(self, payments: BudgetLimitedPayments) -> None:
        """Refunding a payment restores balances and frees budget."""
        await payments.pay(AgentId("payee"), Money(amount=400), PaymentRef("p1"))
        await payments.refund(PaymentRef("p1"))
        assert payments.spent() == 0
        assert payments.remaining() == 1000
        assert payments.balance(AgentId("payer")) == 10000
        assert payments.balance(AgentId("payee")) == 0
        assert await payments.verify_payment(PaymentRef("p1")) == PaymentStatus.FAILED

    def test_negative_budget_rejected(self) -> None:
        """A negative budget is a construction error."""
        with pytest.raises(ValueError, match="Budget must be non-negative"):
            BudgetLimitedPayments(AgentId("payer"), budget=-1)

    # --- adversarial cases (payments-risk threat model) ---

    @pytest.mark.asyncio
    async def test_cannot_overspend_by_attrition(self) -> None:
        """Many small in-budget payments cannot cumulatively breach the cap."""
        pay = BudgetLimitedPayments(AgentId("payer"), initial_balance=10000, budget=250)
        for i in range(5):  # 5 x 50 == 250, exactly the cap
            await pay.pay(AgentId("v"), Money(amount=50), PaymentRef(f"p{i}"))
        assert pay.spent() == 250
        with pytest.raises(ValueError, match="Budget exceeded"):
            await pay.pay(AgentId("v"), Money(amount=1), PaymentRef("p-over"))

    @pytest.mark.asyncio
    async def test_currency_confusion_does_not_free_headroom(
        self, payments: BudgetLimitedPayments
    ) -> None:
        """A foreign-currency payment is rejected, never counted as free spend."""
        with pytest.raises(ValueError, match="Currency mismatch"):
            await payments.pay(AgentId("v"), Money(amount=999, currency="usd"), PaymentRef("x"))
        assert payments.spent() == 0
        assert payments.remaining() == 1000

    @pytest.mark.asyncio
    async def test_cannot_inflate_budget_via_refund_replay(
        self, payments: BudgetLimitedPayments
    ) -> None:
        """A refund releases the amount once; replaying it cannot inflate budget."""
        await payments.pay(AgentId("v"), Money(amount=400), PaymentRef("p1"))
        await payments.refund(PaymentRef("p1"))
        assert payments.remaining() == 1000
        with pytest.raises(ValueError, match="Payment not found"):
            await payments.refund(PaymentRef("p1"))
        assert payments.remaining() == 1000  # not inflated past the budget

    @pytest.mark.asyncio
    async def test_shared_budget_across_sources(self) -> None:
        """Two wallets sharing one spend holder draw down a single budget.

        This is the cross-source case: each source has its own money on its own
        rail, but they share one budget, so the second source is refused because
        of what the first spent — which no per-wallet cap could enforce.
        """
        shared_spent: dict[str, int] = {"value": 0}
        balances: dict[AgentId, int] = {}
        source_a = BudgetLimitedPayments(
            AgentId("source-a"),
            initial_balance=10000,
            budget=1000,
            spent=shared_spent,
            balances=balances,
        )
        source_b = BudgetLimitedPayments(
            AgentId("source-b"),
            initial_balance=10000,
            budget=1000,
            spent=shared_spent,
            balances=balances,
        )
        # source-a spends 700 against the shared budget.
        await source_a.pay(AgentId("m1"), Money(amount=700), PaymentRef("a1"))
        # source-b sees only 300 left, even though it has spent nothing itself.
        assert source_b.remaining() == 300
        with pytest.raises(ValueError, match="Budget exceeded"):
            await source_b.pay(AgentId("m2"), Money(amount=400), PaymentRef("b1"))
        # A 300 purchase from source-b fits exactly and closes the shared budget.
        await source_b.pay(AgentId("m2"), Money(amount=300), PaymentRef("b2"))
        assert source_a.spent() == 1000  # shared: reflects both sources' spend
        assert source_b.remaining() == 0


@settings(max_examples=200)
@given(
    budget=st.integers(min_value=0, max_value=5000),
    amounts=st.lists(st.integers(min_value=1, max_value=1000), max_size=30),
)
@pytest.mark.asyncio
async def test_spend_never_exceeds_budget(budget: int, amounts: list[int]) -> None:
    """No sequence of payments can push confirmed spend over the budget."""
    payments = BudgetLimitedPayments(AgentId("payer"), initial_balance=10**9, budget=budget)
    for i, amount in enumerate(amounts):
        with contextlib.suppress(ValueError):
            # over-budget (or other) refusals are expected
            await payments.pay(AgentId("payee"), Money(amount=amount), PaymentRef(f"p{i}"))
        assert payments.spent() <= budget
        assert payments.remaining() == budget - payments.spent()
