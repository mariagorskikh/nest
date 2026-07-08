# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for the streaming payments plugin.

Adapts the conservation-under-random-op-sequence invariant from the escrow
plugin's property suite to streams:

* System wealth is constant under any interleaving of deliveries, drains,
  and closes across concurrent streams.
* No stream ever bills past ``max_total``, in any op order.
* After close, no op sequence can move another credit.
* The settled receipt always equals the payee's credited total.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, PaymentRef
from nest_plugins_reference.payments.streaming import StreamError, StreamingPayments

_PAYER = AgentId("payer")
_PAYEES = (AgentId("payee-a"), AgentId("payee-b"))
_REFS = (PaymentRef("s-a"), PaymentRef("s-b"))

# An op is (op_kind, stream_index, unit) applied in sequence.
_OPS = st.lists(
    st.tuples(
        st.sampled_from(["deliver", "tick", "close"]),
        st.integers(min_value=0, max_value=1),
        st.integers(min_value=1, max_value=12),
    ),
    max_size=60,
)


def _total_wealth(payments: StreamingPayments) -> int:
    """Sum every party's balance.

    Example::

        assert _total_wealth(payments) == 1000
    """
    return payments.balance(_PAYER) + payments.balance(_PAYEES[0]) + payments.balance(_PAYEES[1])


async def _apply_ops(
    payments: StreamingPayments,
    ops: list[tuple[str, int, int]],
) -> None:
    """Apply a random op sequence against two open streams.

    Example::

        await _apply_ops(payments, [("deliver", 0, 1), ("tick", 0, 1)])
    """
    for tick, (op, stream_idx, unit) in enumerate(ops, start=1):
        ref = _REFS[stream_idx]
        if op == "deliver":
            payments.record_delivery(ref, unit)
        elif op == "tick":
            await payments.tick_stream(ref, tick)
        else:
            await payments.close_stream(ref, at_tick=tick)


@given(ops=_OPS, initial=st.integers(min_value=200, max_value=5000))
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_conservation_under_random_op_sequence(
    ops: list[tuple[str, int, int]],
    initial: int,
) -> None:
    """For any op interleaving, total system wealth never changes."""
    payments = StreamingPayments(_PAYER, initial_balance=initial)
    await payments.open_stream(to=_PAYEES[0], rate_per_tick=7, max_total=70, ref=_REFS[0])
    await payments.open_stream(to=_PAYEES[1], rate_per_tick=13, max_total=39, ref=_REFS[1])
    before = _total_wealth(payments)
    await _apply_ops(payments, ops)
    assert _total_wealth(payments) == before


@given(ops=_OPS)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_never_bills_past_max_total(ops: list[tuple[str, int, int]]) -> None:
    """No op order can push a stream's total past its declared cap."""
    payments = StreamingPayments(_PAYER, initial_balance=10_000)
    await payments.open_stream(to=_PAYEES[0], rate_per_tick=7, max_total=70, ref=_REFS[0])
    await payments.open_stream(to=_PAYEES[1], rate_per_tick=13, max_total=39, ref=_REFS[1])
    await _apply_ops(payments, ops)
    for ref, cap in zip(_REFS, (70, 39), strict=True):
        handle = payments.stream(ref)
        assert handle is not None
        assert handle.total_debited <= cap


@given(ops=_OPS)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_close_is_final_under_any_following_ops(
    ops: list[tuple[str, int, int]],
) -> None:
    """Once closed, no subsequent op sequence moves another credit."""
    payments = StreamingPayments(_PAYER, initial_balance=10_000)
    await payments.open_stream(to=_PAYEES[0], rate_per_tick=7, max_total=700, ref=_REFS[0])
    await payments.open_stream(to=_PAYEES[1], rate_per_tick=13, max_total=390, ref=_REFS[1])

    payments.record_delivery(_REFS[0], 1)
    await payments.tick_stream(_REFS[0], 1)
    receipt = await payments.close_stream(_REFS[0], at_tick=2)
    credited_at_close = payments.balance(_PAYEES[0])
    assert receipt.amount.amount == credited_at_close

    await _apply_ops(payments, ops)
    assert payments.balance(_PAYEES[0]) == credited_at_close


@given(ops=_OPS)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_settled_receipt_equals_payee_credit(
    ops: list[tuple[str, int, int]],
) -> None:
    """After any op sequence, closing settles exactly what the payee received."""
    payments = StreamingPayments(_PAYER, initial_balance=10_000)
    await payments.open_stream(to=_PAYEES[0], rate_per_tick=7, max_total=70, ref=_REFS[0])
    await payments.open_stream(to=_PAYEES[1], rate_per_tick=13, max_total=39, ref=_REFS[1])
    await _apply_ops(payments, ops)
    receipt_a = await payments.close_stream(_REFS[0], at_tick=999)
    receipt_b = await payments.close_stream(_REFS[1], at_tick=999)
    assert receipt_a.amount.amount == payments.balance(_PAYEES[0])
    assert receipt_b.amount.amount == payments.balance(_PAYEES[1])


@given(bad_rate=st.integers(max_value=0))
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_non_positive_rate_always_raises(bad_rate: int) -> None:
    """Any rate <= 0 raises — no off-by-one survives."""
    payments = StreamingPayments(_PAYER, initial_balance=1000)
    with pytest.raises(StreamError):
        await payments.open_stream(
            to=_PAYEES[0],
            rate_per_tick=bad_rate,
            max_total=100,
            ref=_REFS[0],
        )
