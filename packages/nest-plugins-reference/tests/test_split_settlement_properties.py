# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for split_settlement.

Pins the invariants example-based tests cannot enumerate:

* **Conservation.** ``sum(allocations) == amount`` for any weight vector and any
  amount -- no money is created or destroyed by rounding.
* **Bounded fairness.** Every payee receives its exact floor quota or one unit
  more, and exactly ``dust`` payees receive the extra unit.
* **Largest-remainder + stable tie-break.** The payees rounded up are exactly the
  ones with the largest fractional remainders, ties broken by payee id.
* **Order independence.** Permuting the split entries never changes any payee's
  credit.
* **Whole-ledger conservation and atomicity** across random op sequences,
  including settlements that fail on insufficient funds.
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Money, PaymentRef
from nest_plugins_reference.payments.split_settlement import (
    SplitContract,
    SplitError,
    SplitSettlement,
    allocate_by_weight,
)

# Distinct payee ids (never "buyer", so the self-dealing guard never fires) with
# positive integer weights.
_splits = st.lists(
    st.tuples(st.integers(min_value=0, max_value=40), st.integers(min_value=1, max_value=1000)),
    min_size=1,
    max_size=8,
    unique_by=lambda item: item[0],
).map(lambda items: [(AgentId(f"p{index}"), weight) for index, weight in items])

_amount = st.integers(min_value=0, max_value=1_000_000_000)


def _floor_quota(amount: int, weight: int, total: int) -> int:
    return (amount * weight) // total


@given(amount=_amount, splits=_splits)
@settings(max_examples=400, deadline=None)
def test_conservation(amount: int, splits: list[tuple[AgentId, int]]) -> None:
    """Credits always sum back to the amount, for any weights and any amount."""
    alloc = allocate_by_weight(amount, splits)
    assert sum(credit for _, credit in alloc) == amount


@given(amount=_amount, splits=_splits)
@settings(max_examples=400, deadline=None)
def test_each_credit_is_floor_or_floor_plus_one(
    amount: int, splits: list[tuple[AgentId, int]]
) -> None:
    """No payee is off its exact floor quota by more than a single unit."""
    total = sum(weight for _, weight in splits)
    alloc = allocate_by_weight(amount, splits)
    for (payee, weight), (out_payee, credit) in zip(splits, alloc, strict=True):
        assert payee == out_payee
        floor = _floor_quota(amount, weight, total)
        assert credit in (floor, floor + 1)


@given(amount=_amount, splits=_splits)
@settings(max_examples=400, deadline=None)
def test_dust_count_matches_rounded_up(amount: int, splits: list[tuple[AgentId, int]]) -> None:
    """Exactly ``amount - sum(floors)`` payees are rounded up -- no more, no fewer."""
    total = sum(weight for _, weight in splits)
    alloc = allocate_by_weight(amount, splits)
    floors = [_floor_quota(amount, weight, total) for _, weight in splits]
    dust = amount - sum(floors)
    rounded_up = sum(
        1 for (_, credit), floor in zip(alloc, floors, strict=True) if credit == floor + 1
    )
    assert rounded_up == dust


@given(amount=_amount, splits=_splits)
@settings(max_examples=400, deadline=None)
def test_largest_remainder_with_stable_tiebreak(
    amount: int, splits: list[tuple[AgentId, int]]
) -> None:
    """Every rounded-up payee outranks every rounded-down one by (remainder, id)."""
    total = sum(weight for _, weight in splits)
    alloc = allocate_by_weight(amount, splits)
    ups: list[tuple[int, str]] = []
    downs: list[tuple[int, str]] = []
    for (payee, weight), (_, credit) in zip(splits, alloc, strict=True):
        remainder = (amount * weight) % total
        floor = _floor_quota(amount, weight, total)
        (ups if credit == floor + 1 else downs).append((remainder, str(payee)))
    for up_rem, up_id in ups:
        for down_rem, down_id in downs:
            # up must rank strictly ahead: larger remainder, or equal remainder
            # with a lexicographically smaller id (the documented tie-break).
            assert up_rem > down_rem or (up_rem == down_rem and up_id < down_id)


@given(amount=_amount, splits=_splits, perm_seed=st.integers(min_value=0, max_value=10_000))
@settings(max_examples=300, deadline=None)
def test_permutation_invariance(
    amount: int, splits: list[tuple[AgentId, int]], perm_seed: int
) -> None:
    """Reordering the split entries never changes any payee's credit."""
    import random

    shuffled = list(splits)
    random.Random(perm_seed).shuffle(shuffled)
    base = dict(allocate_by_weight(amount, splits))
    other = dict(allocate_by_weight(amount, shuffled))
    assert base == other


@given(amount=st.integers(min_value=1, max_value=10_000), splits=_splits)
@settings(max_examples=300, deadline=None)
@pytest.mark.asyncio
async def test_open_settle_equals_split_pay(amount: int, splits: list[tuple[AgentId, int]]) -> None:
    """Two-phase open+settle produces the same receipts as one-shot split_pay."""
    two_phase = SplitSettlement(AgentId("buyer"), initial_balance=10**12)
    await two_phase.open_split(splits, PaymentRef("r"))
    a = await two_phase.settle_split(PaymentRef("r"), Money(amount=amount))
    one_shot = SplitSettlement(AgentId("buyer"), initial_balance=10**12)
    b = await one_shot.split_pay(splits, Money(amount=amount), PaymentRef("r"))
    assert [(str(r.payee), r.amount.amount) for r in a] == [
        (str(r.payee), r.amount.amount) for r in b
    ]


@given(
    ops=st.lists(
        st.tuples(_splits, st.integers(min_value=1, max_value=10_000)),
        min_size=1,
        max_size=20,
    )
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_random_op_sequence_conserves_ledger_and_stays_atomic(
    ops: list[tuple[list[tuple[AgentId, int]], int]],
) -> None:
    """Across arbitrary settlement sequences the total ledger is invariant.

    Some settlements will exhaust the payer's balance; each such failure must be
    atomic (no partial credit) so the whole-marketplace total never drifts.
    """
    initial = 50_000
    balances: dict[AgentId, int] = {}
    contracts: dict[PaymentRef, SplitContract] = {}
    buyer = SplitSettlement(
        AgentId("buyer"), initial_balance=initial, balances=balances, contracts=contracts
    )

    def total_ledger() -> int:
        return sum(balances.values())

    assert total_ledger() == initial
    for index, (splits, amount) in enumerate(ops):
        with contextlib.suppress(SplitError):
            await buyer.split_pay(splits, Money(amount=amount), PaymentRef(f"r{index}"))
        # Whether the settlement succeeded or was rejected, nothing leaked.
        assert total_ledger() == initial


@given(
    amount=st.integers(min_value=1, max_value=10_000), payee=st.integers(min_value=0, max_value=40)
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_pay_equals_weight_one_split(amount: int, payee: int) -> None:
    """pay(to, amount) credits exactly ``amount`` to a single payee."""
    pay = SplitSettlement(AgentId("buyer"), initial_balance=10**9)
    receipt = await pay.pay(AgentId(f"p{payee}"), Money(amount=amount), PaymentRef("r"))
    assert receipt.amount.amount == amount
    assert pay.balance(AgentId(f"p{payee}")) == amount
