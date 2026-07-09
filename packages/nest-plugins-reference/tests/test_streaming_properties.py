# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for the streaming payments plugin.

Pins invariants the example-based tests cannot enumerate:

* Conservation of total ledger across random sequences of opens, ticks, closes,
  and refunds.
* Idempotency: repeating open/close/tick with the same arguments is safe.
* Rate enforcement: no single tick ever drains more than rate_per_tick.
* Stop-on-close: no debit after close_stream succeeds.
* Determinism: identical operation sequences on identical initial state produce
  identical final state.

Adversarial invariants:

* Drain-after-close: a Byzantine caller must not be able to debit a closed
  stream.
* Over-bill: a payer cannot drain more than max_total across a stream's
  lifetime.
* Double-open: re-opening a closed ref must raise.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from nest_core.types import AgentId, Money, PaymentRef
from nest_plugins_reference.payments.streaming import (
    StreamError,
    StreamingPayments,
)

# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _fresh_payments(initial_balance: int = 10_000) -> StreamingPayments:
    return StreamingPayments(AgentId("payer"), initial_balance=initial_balance)


def _system_total(p: StreamingPayments, agents: list[AgentId]) -> int:
    return sum(p.balance(a) for a in agents)


# ---------------------------------------------------------------------------
# Stream lifecycle property: random valid sequences preserve conservation
# ---------------------------------------------------------------------------


async def _apply_op(
    payments: StreamingPayments,
    op: tuple[Any, ...],
    tick: int,
) -> None:
    """Apply a single operation, swallowing expected errors."""
    try:
        if op[0] == "open_stream":
            rate = int(op[1])
            mt = int(op[2])
            ref = op[3]
            await payments.open_stream(
                to=AgentId("payee"),
                rate_per_tick=rate,
                max_total=mt,
                ref=ref,
                current_tick=tick,
            )
        elif op[0] == "tick_stream":
            ref = op[1]
            ct = int(op[2])
            await payments.tick_stream(ref, ct)
        elif op[0] == "close_stream":
            await payments.close_stream(op[1])
        elif op[0] == "refund_stream":
            await payments.refund_stream(op[1])
        elif op[0] == "noop":
            pass
    except (StreamError, ValueError):
        pass  # Expected: invalid state transitions are fine


_stream_rate: SearchStrategy[int] = st.integers(min_value=1, max_value=100)
_stream_max_total: SearchStrategy[int] = st.integers(min_value=1, max_value=5000)
_stream_ref: SearchStrategy[PaymentRef] = st.integers(min_value=1, max_value=20).map(
    lambda i: PaymentRef(f"stream-{i}"),
)
_stream_tick: SearchStrategy[int] = st.integers(min_value=0, max_value=100)

_stream_op: SearchStrategy[tuple[Any, ...]] = st.one_of(
    st.tuples(
        st.just("open_stream"),
        _stream_rate,
        _stream_max_total,
        _stream_ref,
    ),
    st.tuples(
        st.just("tick_stream"),
        _stream_ref,
        _stream_tick,
    ),
    st.tuples(
        st.just("close_stream"),
        _stream_ref,
    ),
    st.tuples(
        st.just("refund_stream"),
        _stream_ref,
    ),
    st.just(("noop",)),
)


@settings(deadline=None, max_examples=300)
@given(
    op_seq=st.lists(_stream_op, min_size=1, max_size=40),
)
@pytest.mark.asyncio
async def test_conservation_across_random_op_sequences(
    op_seq: list[tuple[Any, ...]],
) -> None:
    """For any sequence of valid stream operations, total system wealth
    (sum of all balances) is preserved."""
    payments = _fresh_payments(initial_balance=100000)
    agents = [AgentId("payer"), AgentId("payee")]
    total_before = _system_total(payments, agents)

    for i, op in enumerate(op_seq):
        await _apply_op(payments, op, i)

    total_after = _system_total(payments, agents)
    assert total_before == total_after, f"conservation violated: {total_before} -> {total_after}"


# ---------------------------------------------------------------------------
# Idempotency: closing the same ref twice returns the same receipt
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=10, max_value=100),
    max_total=st.integers(min_value=100, max_value=500),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_close_stream_idempotent_property(rate: int, max_total: int) -> None:
    """Closing the same stream twice returns identical receipts."""
    avail = max(max_total, rate + 10)
    payments = _fresh_payments()
    await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=avail,
        ref=PaymentRef("s"),
    )
    r1 = await payments.close_stream(PaymentRef("s"))
    r2 = await payments.close_stream(PaymentRef("s"))
    assert r1.amount.amount == r2.amount.amount
    assert r1.ref == r2.ref


@given(
    amount=st.integers(min_value=1, max_value=5000),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_pay_idempotent_property(amount: int) -> None:
    """Paying the same ref twice returns the same receipt."""
    payments = _fresh_payments()
    r1 = await payments.pay(
        AgentId("payee"),
        Money(amount=amount),
        PaymentRef("p"),
    )
    r2 = await payments.pay(
        AgentId("payee"),
        Money(amount=amount),
        PaymentRef("p"),
    )
    assert r1.amount.amount == r2.amount.amount


# ---------------------------------------------------------------------------
# Rate enforcement: no single tick drains more than rate_per_tick
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=1, max_value=100),
    max_total=st.integers(min_value=100, max_value=500),
    num_ticks=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_rate_never_exceeded(rate: int, max_total: int, num_ticks: int) -> None:
    """For any rate and number of ticks, no tick drains more than rate."""
    payments = _fresh_payments(initial_balance=max(max_total, 5000))
    await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=max_total,
        ref=PaymentRef("s"),
    )
    for t in range(1, num_ticks + 1):
        bal_before = payments.balance(AgentId("payee"))
        await payments.tick_stream(PaymentRef("s"), t)
        drained = payments.balance(AgentId("payee")) - bal_before
        assert drained <= rate, f"tick {t} drained {drained}, exceeds rate {rate}"


# ---------------------------------------------------------------------------
# Stop-on-close: no debit after close
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=1, max_value=100),
    max_total=st.integers(min_value=100, max_value=500),
    close_tick=st.integers(min_value=1, max_value=5),
    post_close_tick=st.integers(min_value=10, max_value=20),
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_no_drain_after_close_property(
    rate: int,
    max_total: int,
    close_tick: int,
    post_close_tick: int,
) -> None:
    """Once close_stream() succeeds, subsequent ticks do nothing."""
    payments = _fresh_payments(initial_balance=max(max_total, 5000))
    await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=max_total,
        ref=PaymentRef("s"),
        current_tick=0,
    )
    for t in range(1, close_tick):
        await payments.tick_stream(PaymentRef("s"), t)

    await payments.close_stream(PaymentRef("s"))
    bal_after_close = payments.balance(AgentId("payee"))

    await payments.tick_stream(PaymentRef("s"), post_close_tick)
    assert payments.balance(AgentId("payee")) == bal_after_close, (
        f"payee balance changed after close: {bal_after_close} -> "
        f"{payments.balance(AgentId('payee'))}"
    )


# ---------------------------------------------------------------------------
# Max total enforcement: total never exceeds max_total
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=1, max_value=100),
    max_total=st.integers(min_value=100, max_value=500),
    num_ticks=st.integers(min_value=1, max_value=20),
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_total_never_exceeds_max(
    rate: int,
    max_total: int,
    num_ticks: int,
) -> None:
    """Total debited across a stream's lifetime never exceeds max_total."""
    payments = _fresh_payments(initial_balance=max(max_total + rate, 5000))
    h = await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=max_total,
        ref=PaymentRef("s"),
    )
    for t in range(1, num_ticks + 1):
        await payments.tick_stream(PaymentRef("s"), t)
    assert h.total_debited <= max_total, f"total debited {h.total_debited} > max_total {max_total}"


# ---------------------------------------------------------------------------
# Adversarial: re-opening a closed stream raises
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_reopen_closed_stream_raises(rate: int) -> None:
    """A Byzantine caller reopening a closed ref gets a StreamError."""
    payments = _fresh_payments()
    await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=rate,
        ref=PaymentRef("s"),
    )
    # Stream is closed because first tick exhausted max_total
    with pytest.raises(StreamError, match="already closed"):
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=rate,
            max_total=rate,
            ref=PaymentRef("s"),
        )


# ---------------------------------------------------------------------------
# Adversarial: refunding an open stream raises
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=1, max_value=100),
    max_total=st.integers(min_value=100, max_value=500),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_refund_open_stream_raises(rate: int, max_total: int) -> None:
    """A Byzantine caller refunding an open stream gets a StreamError."""
    payments = _fresh_payments()
    mt = max(max_total, rate + 1)
    await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=mt,
        ref=PaymentRef("s"),
    )
    with pytest.raises(StreamError, match="Cannot refund open"):
        await payments.refund_stream(PaymentRef("s"))


# ---------------------------------------------------------------------------
# Determinism: same sequence yields identical final state
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=10, max_value=50),
    max_total=st.integers(min_value=100, max_value=300),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_deterministic_state_after_sequence(
    rate: int,
    max_total: int,
) -> None:
    """Running the same sequence twice yields identical final state."""

    async def run_sequence() -> dict[str, int]:
        p = _fresh_payments(initial_balance=10000)
        agents = [AgentId("payer"), AgentId("payee")]
        await p.open_stream(
            to=AgentId("payee"),
            rate_per_tick=rate,
            max_total=max_total,
            ref=PaymentRef("s"),
        )
        for t in range(1, 6):
            await p.tick_stream(PaymentRef("s"), t)
        await p.close_stream(PaymentRef("s"))
        return {str(a): p.balance(a) for a in agents}

    s1 = await run_sequence()
    s2 = await run_sequence()
    assert s1 == s2, f"non-deterministic state: {s1} != {s2}"


# ---------------------------------------------------------------------------
# Adversarial: no double-billing the same tick
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=10, max_value=100),
    repeat_count=st.integers(min_value=2, max_value=5),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_no_double_bill_same_tick(rate: int, repeat_count: int) -> None:
    """Repeating tick_stream with the same tick does not double-bill."""
    payments = _fresh_payments(initial_balance=5000)
    await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=5000,
        ref=PaymentRef("s"),
    )

    bal_before = payments.balance(AgentId("payee"))
    for _ in range(repeat_count):
        await payments.tick_stream(PaymentRef("s"), 1)

    drained = payments.balance(AgentId("payee")) - bal_before
    assert drained == rate, (
        f"double-billed: expected {rate}, got {drained} after {repeat_count} "
        f"repeats of the same tick"
    )


# ---------------------------------------------------------------------------
# Adversarial: conservation under stream open + refund cycle
# ---------------------------------------------------------------------------


@given(
    rate=st.integers(min_value=1, max_value=50),
    max_total=st.integers(min_value=50, max_value=200),
    ticks=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_conservation_through_open_tick_close_refund(
    rate: int,
    max_total: int,
    ticks: int,
) -> None:
    """Conservation holds through a full lifecycle: open, tick, close, refund."""
    payments = _fresh_payments(initial_balance=10000)
    agents = [AgentId("payer"), AgentId("payee")]
    total_before = _system_total(payments, agents)

    await payments.open_stream(
        to=AgentId("payee"),
        rate_per_tick=rate,
        max_total=max_total,
        ref=PaymentRef("s"),
    )
    for t in range(1, ticks + 1):
        still_open = await payments.tick_stream(PaymentRef("s"), t)
        if not still_open:
            break
    await payments.close_stream(PaymentRef("s"))

    with contextlib.suppress(StreamError):
        await payments.refund_stream(PaymentRef("s"))

    total_after = _system_total(payments, agents)
    assert total_before == total_after, f"conservation violated: {total_before} -> {total_after}"


# ---------------------------------------------------------------------------
# Edge case: invalid parameters are always rejected
# ---------------------------------------------------------------------------


@given(
    bad_rate=st.one_of(st.integers(max_value=0), st.integers(min_value=10_001)),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_open_stream_rejects_invalid_rate(bad_rate: int) -> None:
    """Any non-positive or absurdly-large rate is rejected."""
    payments = _fresh_payments()
    with pytest.raises(ValueError, match="rate_per_tick"):
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=bad_rate,
            max_total=100,
            ref=PaymentRef("s"),
        )


@given(
    rate=st.integers(min_value=10, max_value=100),
    max_total=st.integers(min_value=1, max_value=9),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_open_stream_rejects_max_less_than_rate(
    rate: int,
    max_total: int,
) -> None:
    """max_total < rate_per_tick is always rejected."""
    payments = _fresh_payments()
    with pytest.raises(ValueError, match="max_total"):
        await payments.open_stream(
            to=AgentId("payee"),
            rate_per_tick=rate,
            max_total=max_total,
            ref=PaymentRef("s"),
        )
