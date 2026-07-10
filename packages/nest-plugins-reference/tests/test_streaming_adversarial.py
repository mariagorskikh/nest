# SPDX-License-Identifier: Apache-2.0
"""Adversarial and property tests for streaming payments.

Proves the validator suite catches drain-after-close and over-bill-on-partition
attacks, and that ``prepaid_credits`` fails the streaming lifecycle check.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus
from nest_core.validators import (
    validate_streaming_conservation,
    validate_streaming_lifecycle,
    validate_streaming_no_drain_after_close,
    validate_streaming_no_overbill_on_partition,
)
from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits
from nest_plugins_reference.payments.streaming import StreamingPayments


def _shared_pair(
    payer_balance: int,
) -> tuple[StreamingPayments, StreamingPayments]:
    balances: dict[AgentId, int] = {AgentId("payer"): payer_balance, AgentId("payee"): 0}
    payments: dict[PaymentRef, object] = {}
    streams: dict[PaymentRef, object] = {}
    payer = StreamingPayments(
        AgentId("payer"),
        initial_balance=0,
        balances=balances,
        payments=payments,  # type: ignore[arg-type]
        streams=streams,  # type: ignore[arg-type]
    )
    payee = StreamingPayments(
        AgentId("payee"),
        initial_balance=0,
        balances=balances,
        payments=payments,  # type: ignore[arg-type]
        streams=streams,  # type: ignore[arg-type]
    )
    return payer, payee


class BuggyStreamingPayments(StreamingPayments):
    """Intentionally broken plugin that debits after close (drain-after-close attack)."""

    async def advance_stream(self, ref: PaymentRef, current_tick: int) -> bool:
        if ref not in self._streams:
            return False
        handle = self._streams[ref]
        handle.ready_to_advance = True
        result = await super().advance_stream(ref, current_tick)
        if ref in self._streams:
            amount = min(handle.rate_per_tick, handle.max_total - handle.total_debited)
            if amount > 0 and handle.closed_at_tick is not None:
                payer_balance = self._balances.get(handle.payer, 0)
                if payer_balance >= amount:
                    self._balances[handle.payer] = payer_balance - amount
                    self._balances[handle.to] = self._balances.get(handle.to, 0) + amount
                    handle.total_debited += amount
        return result


@pytest.mark.asyncio
async def test_drain_after_close_attack_fails_validator() -> None:
    """Drain-after-close: debits after close must fail the adversarial validator."""
    events = [
        {"event_type": "stream_opened", "stream_ref": "s-attack", "tick": 0},
        {"kind": "payment_debited", "stream_ref": "s-attack", "tick": 1},
        {"event_type": "stream_closed", "stream_ref": "s-attack", "tick": 2},
        {"kind": "payment_debited", "stream_ref": "s-attack", "tick": 5},
    ]
    results = validate_streaming_no_drain_after_close(events)
    assert not results[0].passed
    assert "debited after close" in results[0].detail


@pytest.mark.asyncio
async def test_overbill_on_partition_attack_fails_validator() -> None:
    """Over-bill on partition: debits after drop must fail the adversarial validator."""
    events = [
        {
            "event_type": "stream_opened",
            "stream_ref": "s1",
            "agent": "buyer-0",
            "to": "seller-0",
            "tick": 0,
        },
        {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
        {"kind": "dropped", "from": "buyer-0", "agent": "seller-0", "tick": 2},
        {"kind": "payment_debited", "stream_ref": "s1", "tick": 5},
    ]
    results = validate_streaming_no_overbill_on_partition(events)
    assert not results[0].passed
    assert "partitioned" in results[0].detail


@pytest.mark.asyncio
async def test_correct_streaming_passes_adversarial_validators() -> None:
    """Correct plugin behavior produces a trace the adversarial validators accept."""
    payee = AgentId("payee")
    ref = PaymentRef("s-good")
    payer, payee_plugin = _shared_pair(1000)
    await payer.open_stream(payee, 25, 100, ref, opened_at_tick=0)

    events: list[dict[str, object]] = [
        {
            "event_type": "stream_opened",
            "stream_ref": str(ref),
            "agent": "payer",
            "to": "payee",
            "tick": 0,
        },
        {
            "kind": "payment_debited",
            "stream_ref": str(ref),
            "agent": "payer",
            "amount": 25,
            "tick": 0,
        },
        {
            "kind": "payment_credited",
            "stream_ref": str(ref),
            "agent": "payee",
            "amount": 25,
            "tick": 0,
        },
    ]

    await payee_plugin.acknowledge_work(ref, tick=1)
    await payer.advance_stream(ref, 1)
    events.extend(
        [
            {
                "kind": "payment_debited",
                "stream_ref": str(ref),
                "agent": "payer",
                "amount": 25,
                "tick": 1,
            },
            {
                "kind": "payment_credited",
                "stream_ref": str(ref),
                "agent": "payee",
                "amount": 25,
                "tick": 1,
            },
        ]
    )
    await payer.close_stream(ref, current_tick=2)
    events.append({"event_type": "stream_closed", "stream_ref": str(ref), "tick": 2})

    assert all(r.passed for r in validate_streaming_lifecycle(events))  # type: ignore[arg-type]
    assert all(r.passed for r in validate_streaming_conservation(events))  # type: ignore[arg-type]
    assert all(r.passed for r in validate_streaming_no_drain_after_close(events))  # type: ignore[arg-type]
    assert all(r.passed for r in validate_streaming_no_overbill_on_partition(events))  # type: ignore[arg-type]


def test_prepaid_credits_fails_streaming_lifecycle() -> None:
    """Old prepaid_credits plugin leaves no stream events — validators must fail."""
    events = [
        {"kind": "send", "agent": "buyer-0", "to": "seller-0", "msg": "buy:item:50"},
        {"kind": "receive", "agent": "seller-0", "from": "buyer-0", "msg": "sold:item:50"},
    ]
    results = validate_streaming_lifecycle(events)
    assert not results[0].passed
    assert "no stream_opened" in results[0].detail


@pytest.mark.asyncio
async def test_prepaid_has_no_streaming_api() -> None:
    """prepaid_credits cannot open streams — proves old plugin is unsuitable."""
    payments = PrepaidCredits(AgentId("payer"), initial_balance=1000)
    open_stream = getattr(payments, "open_stream", None)
    assert open_stream is None or not callable(open_stream)
    receipt = await payments.pay(AgentId("payee"), Money(amount=50), PaymentRef("p1"))
    assert await payments.verify_payment(PaymentRef("p1")) == PaymentStatus.CONFIRMED
    assert receipt.amount.amount == 50


@given(
    advances=st.integers(min_value=0, max_value=8),
    rate=st.integers(min_value=1, max_value=20),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_conservation_under_stream_sequence(advances: int, rate: int) -> None:
    """Conservation holds across open / advance / close sequences (PR #7 pattern)."""
    max_total = rate * (advances + 2)
    balances: dict[AgentId, int] = {AgentId("payer"): max_total * 2, AgentId("payee"): 0}
    payments: dict[PaymentRef, object] = {}
    streams: dict[PaymentRef, object] = {}
    payer = StreamingPayments(
        AgentId("payer"),
        initial_balance=0,
        balances=balances,
        payments=payments,  # type: ignore[arg-type]
        streams=streams,  # type: ignore[arg-type]
    )
    payee = StreamingPayments(
        AgentId("payee"),
        initial_balance=0,
        balances=balances,
        payments=payments,  # type: ignore[arg-type]
        streams=streams,  # type: ignore[arg-type]
    )
    total_before = balances[AgentId("payer")] + balances[AgentId("payee")]
    ref = PaymentRef("s-prop")
    await payer.open_stream(AgentId("payee"), rate, max_total, ref)
    for tick in range(1, advances + 1):
        await payee.acknowledge_work(ref, tick=tick)
        await payer.advance_stream(ref, tick)
    await payer.close_stream(ref, current_tick=advances + 1)
    total_after = balances[AgentId("payer")] + balances[AgentId("payee")]
    assert total_before == total_after
