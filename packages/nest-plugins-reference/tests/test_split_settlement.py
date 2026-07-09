# SPDX-License-Identifier: Apache-2.0
"""Unit and edge-case tests for the split_settlement fan-out payments plugin.

Covers the largest-remainder allocator, the open/settle lifecycle, every typed
rejection the plugin promises, atomicity on failure, role binding across a shared
ledger, and the Payments-protocol surface (pay/verify/refund).
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus
from nest_plugins_reference.payments.split_settlement import (
    SplitContract,
    SplitError,
    SplitSettlement,
    allocate_by_weight,
)


def _pair(name: str, weight: int) -> tuple[AgentId, int]:
    return (AgentId(name), weight)


class TestAllocateByWeight:
    """The pure largest-remainder allocator."""

    def test_even_split_no_dust(self) -> None:
        alloc = allocate_by_weight(1000, [_pair("a", 40), _pair("b", 40), _pair("c", 20)])
        assert alloc == [_pair("a", 400), _pair("b", 400), _pair("c", 200)]

    def test_dust_goes_to_largest_remainder(self) -> None:
        alloc = allocate_by_weight(1001, [_pair("a", 3), _pair("b", 1), _pair("c", 1)])
        assert alloc == [_pair("a", 601), _pair("b", 200), _pair("c", 200)]
        assert sum(credit for _, credit in alloc) == 1001

    def test_two_dust_units_split_across_ties(self) -> None:
        # 777 across (40, 40, 20): floors 310/310/155 = 775, remainders 80/80/40,
        # the two dust units go to the two tied-largest contributors.
        alloc = allocate_by_weight(
            777, [_pair("contrib-0", 40), _pair("contrib-1", 40), _pair("platform-0", 20)]
        )
        assert alloc == [_pair("contrib-0", 311), _pair("contrib-1", 311), _pair("platform-0", 155)]

    def test_single_dust_unit_breaks_tie_by_payee_id(self) -> None:
        # 1001 across (40, 40, 20): one dust unit, tie between the two contributors
        # broken by the lexicographically smaller id.
        alloc = allocate_by_weight(
            1001, [_pair("contrib-1", 40), _pair("contrib-0", 40), _pair("platform-0", 20)]
        )
        assert alloc == [_pair("contrib-1", 400), _pair("contrib-0", 401), _pair("platform-0", 200)]

    def test_single_payee_takes_everything(self) -> None:
        assert allocate_by_weight(999, [_pair("solo", 7)]) == [_pair("solo", 999)]

    def test_zero_amount_allocates_zero(self) -> None:
        assert allocate_by_weight(0, [_pair("a", 1), _pair("b", 2)]) == [
            _pair("a", 0),
            _pair("b", 0),
        ]

    def test_empty_weights_raise(self) -> None:
        with pytest.raises(SplitError, match="at least one payee"):
            allocate_by_weight(100, [])

    def test_non_positive_weight_raises(self) -> None:
        with pytest.raises(SplitError, match="positive integer"):
            allocate_by_weight(100, [_pair("a", 1), _pair("b", 0)])

    def test_negative_amount_raises(self) -> None:
        with pytest.raises(SplitError, match="non-negative"):
            allocate_by_weight(-1, [_pair("a", 1)])


class TestSplitLifecycle:
    """open_split / settle_split happy path and bookkeeping."""

    @pytest.fixture
    def pay(self) -> SplitSettlement:
        return SplitSettlement(AgentId("buyer"), initial_balance=5000)

    @pytest.mark.asyncio
    async def test_open_locks_weights(self, pay: SplitSettlement) -> None:
        contract = await pay.open_split(
            [_pair("author", 8), _pair("platform", 2)], PaymentRef("r1")
        )
        assert isinstance(contract, SplitContract)
        assert contract.state == "OPEN"
        assert contract.total_weight == 10
        assert contract.payees == (_pair("author", 8), _pair("platform", 2))
        assert await pay.verify_payment(PaymentRef("r1")) == PaymentStatus.PENDING

    @pytest.mark.asyncio
    async def test_settle_credits_and_conserves(self, pay: SplitSettlement) -> None:
        await pay.open_split([_pair("author", 8), _pair("platform", 2)], PaymentRef("r1"))
        receipts = await pay.settle_split(PaymentRef("r1"), Money(amount=1000))
        assert [(str(r.payee), r.amount.amount) for r in receipts] == [
            ("author", 800),
            ("platform", 200),
        ]
        assert pay.balance(AgentId("buyer")) == 4000
        assert pay.balance(AgentId("author")) == 800
        assert pay.balance(AgentId("platform")) == 200
        assert await pay.verify_payment(PaymentRef("r1")) == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_settlement_record_queryable(self, pay: SplitSettlement) -> None:
        await pay.split_pay(
            [_pair("author", 8), _pair("platform", 2)], Money(amount=1001), PaymentRef("r1")
        )
        record = pay.settlement(PaymentRef("r1"))
        assert record is not None
        assert record.settled_amount == 1001
        assert record.allocations == (_pair("author", 801), _pair("platform", 200))
        rebuilt = pay.receipts(PaymentRef("r1"))
        assert sum(r.amount.amount for r in rebuilt) == 1001

    @pytest.mark.asyncio
    async def test_open_split_returns_none_settlement_until_settled(
        self, pay: SplitSettlement
    ) -> None:
        await pay.open_split([_pair("author", 1)], PaymentRef("r1"))
        assert pay.settlement(PaymentRef("r1")) is None
        with pytest.raises(SplitError, match="no settled split"):
            pay.receipts(PaymentRef("r1"))

    @pytest.mark.asyncio
    async def test_split_pay_one_call(self, pay: SplitSettlement) -> None:
        receipts = await pay.split_pay(
            [_pair("a", 1), _pair("b", 1), _pair("c", 1)], Money(amount=1000), PaymentRef("r1")
        )
        # 1000 / (1,1,1): floors 333 each = 999, one dust to lexicographically first.
        assert [(str(r.payee), r.amount.amount) for r in receipts] == [
            ("a", 334),
            ("b", 333),
            ("c", 333),
        ]


class TestPaymentsProtocol:
    """The bare Payments surface: pay / quote / verify / refund."""

    @pytest.fixture
    def pay(self) -> SplitSettlement:
        return SplitSettlement(AgentId("buyer"), initial_balance=5000)

    @pytest.mark.asyncio
    async def test_pay_is_single_payee_split(self, pay: SplitSettlement) -> None:
        receipt = await pay.pay(AgentId("author"), Money(amount=250), PaymentRef("p1"))
        assert receipt.payer == AgentId("buyer")
        assert receipt.payee == AgentId("author")
        assert receipt.amount.amount == 250
        assert pay.balance(AgentId("buyer")) == 4750
        assert pay.balance(AgentId("author")) == 250

    @pytest.mark.asyncio
    async def test_verify_unknown_ref_is_failed(self, pay: SplitSettlement) -> None:
        assert await pay.verify_payment(PaymentRef("nope")) == PaymentStatus.FAILED

    @pytest.mark.asyncio
    async def test_refund_reverses_every_allocation(self, pay: SplitSettlement) -> None:
        await pay.split_pay(
            [_pair("a", 3), _pair("b", 1), _pair("c", 1)], Money(amount=1001), PaymentRef("r1")
        )
        assert pay.balance(AgentId("buyer")) == 5000 - 1001
        await pay.refund(PaymentRef("r1"))
        assert pay.balance(AgentId("buyer")) == 5000
        assert pay.balance(AgentId("a")) == 0
        assert pay.balance(AgentId("b")) == 0
        assert pay.balance(AgentId("c")) == 0
        assert await pay.verify_payment(PaymentRef("r1")) == PaymentStatus.REFUNDED

    @pytest.mark.asyncio
    async def test_refund_requires_payee_still_holds_share(self, pay: SplitSettlement) -> None:
        balances: dict[AgentId, int] = {}
        contracts: dict[PaymentRef, SplitContract] = {}
        buyer = SplitSettlement(
            AgentId("buyer"), initial_balance=5000, balances=balances, contracts=contracts
        )
        spender = SplitSettlement(
            AgentId("a"), initial_balance=0, balances=balances, contracts=contracts
        )
        await buyer.split_pay([_pair("a", 1)], Money(amount=100), PaymentRef("r1"))
        await spender.pay(
            AgentId("sink"), Money(amount=100), PaymentRef("r2")
        )  # a spends its credit
        with pytest.raises(SplitError, match="lacks"):
            await buyer.refund(PaymentRef("r1"))

    @pytest.mark.asyncio
    async def test_quote_is_fixed(self, pay: SplitSettlement) -> None:
        from nest_core.types import ServiceRef

        quote = await pay.quote(ServiceRef("bundle"))
        assert quote.price.amount == 10


class TestRejections:
    """Typed rejections for every failure mode the plugin documents."""

    @pytest.fixture
    def pay(self) -> SplitSettlement:
        return SplitSettlement(AgentId("buyer"), initial_balance=1000)

    @pytest.mark.asyncio
    async def test_empty_split(self, pay: SplitSettlement) -> None:
        with pytest.raises(SplitError, match="at least one payee"):
            await pay.open_split([], PaymentRef("r1"))

    @pytest.mark.asyncio
    async def test_non_positive_weight(self, pay: SplitSettlement) -> None:
        with pytest.raises(SplitError, match="positive integer"):
            await pay.open_split([_pair("a", 1), _pair("b", -3)], PaymentRef("r1"))

    @pytest.mark.asyncio
    async def test_duplicate_payee(self, pay: SplitSettlement) -> None:
        with pytest.raises(SplitError, match="duplicate payee"):
            await pay.open_split([_pair("a", 1), _pair("a", 2)], PaymentRef("r1"))

    @pytest.mark.asyncio
    async def test_self_dealing_rejected(self, pay: SplitSettlement) -> None:
        with pytest.raises(SplitError, match="may not be a payee"):
            await pay.open_split([_pair("buyer", 1), _pair("a", 1)], PaymentRef("r1"))

    @pytest.mark.asyncio
    async def test_unknown_payee_when_roster_supplied(self, pay: SplitSettlement) -> None:
        roster = frozenset({AgentId("a")})
        with pytest.raises(SplitError, match="unknown payee"):
            await pay.open_split(
                [_pair("a", 1), _pair("b", 1)], PaymentRef("r1"), known_payees=roster
            )

    @pytest.mark.asyncio
    async def test_duplicate_ref(self, pay: SplitSettlement) -> None:
        await pay.open_split([_pair("a", 1)], PaymentRef("r1"))
        with pytest.raises(SplitError, match="already used"):
            await pay.open_split([_pair("b", 1)], PaymentRef("r1"))

    @pytest.mark.asyncio
    async def test_settle_unknown_ref(self, pay: SplitSettlement) -> None:
        with pytest.raises(SplitError, match="no split for reference"):
            await pay.settle_split(PaymentRef("missing"), Money(amount=10))

    @pytest.mark.asyncio
    async def test_settle_non_positive_amount(self, pay: SplitSettlement) -> None:
        await pay.open_split([_pair("a", 1)], PaymentRef("r1"))
        with pytest.raises(SplitError, match="must be positive"):
            await pay.settle_split(PaymentRef("r1"), Money(amount=0))

    @pytest.mark.asyncio
    async def test_double_settle_rejected(self, pay: SplitSettlement) -> None:
        await pay.split_pay([_pair("a", 1)], Money(amount=100), PaymentRef("r1"))
        with pytest.raises(SplitError, match="already SETTLED"):
            await pay.settle_split(PaymentRef("r1"), Money(amount=100))

    @pytest.mark.asyncio
    async def test_insufficient_balance_is_atomic(self, pay: SplitSettlement) -> None:
        with pytest.raises(SplitError, match="insufficient balance"):
            await pay.split_pay(
                [_pair("a", 1), _pair("b", 1)], Money(amount=9999), PaymentRef("r1")
            )
        # split_pay rolls back: no money moved, no husk contract, ref reusable.
        assert pay.balance(AgentId("buyer")) == 1000
        assert pay.balance(AgentId("a")) == 0
        assert await pay.verify_payment(PaymentRef("r1")) == PaymentStatus.FAILED

    @pytest.mark.asyncio
    async def test_two_phase_settle_failure_leaves_contract_open_for_retry(
        self, pay: SplitSettlement
    ) -> None:
        await pay.open_split([_pair("a", 1)], PaymentRef("r1"))
        with pytest.raises(SplitError, match="insufficient balance"):
            await pay.settle_split(PaymentRef("r1"), Money(amount=9999))
        # Two-phase settle is retryable: the contract stays OPEN.
        assert await pay.verify_payment(PaymentRef("r1")) == PaymentStatus.PENDING
        receipts = await pay.settle_split(PaymentRef("r1"), Money(amount=500))
        assert receipts[0].amount.amount == 500


class TestRoleBinding:
    """Only the contract's payer may advance it, even on a shared ledger."""

    @pytest.mark.asyncio
    async def test_non_payer_cannot_settle(self) -> None:
        balances: dict[AgentId, int] = {}
        contracts: dict[PaymentRef, SplitContract] = {}
        buyer = SplitSettlement(
            AgentId("buyer"), initial_balance=5000, balances=balances, contracts=contracts
        )
        other = SplitSettlement(
            AgentId("other"), initial_balance=5000, balances=balances, contracts=contracts
        )
        await buyer.open_split([_pair("author", 1)], PaymentRef("r1"))
        with pytest.raises(SplitError, match="only payer"):
            await other.settle_split(PaymentRef("r1"), Money(amount=100))

    @pytest.mark.asyncio
    async def test_non_payer_cannot_refund(self) -> None:
        balances: dict[AgentId, int] = {}
        contracts: dict[PaymentRef, SplitContract] = {}
        buyer = SplitSettlement(
            AgentId("buyer"), initial_balance=5000, balances=balances, contracts=contracts
        )
        other = SplitSettlement(
            AgentId("other"), initial_balance=5000, balances=balances, contracts=contracts
        )
        await buyer.split_pay([_pair("author", 1)], Money(amount=100), PaymentRef("r1"))
        with pytest.raises(SplitError, match="only payer"):
            await other.refund(PaymentRef("r1"))
