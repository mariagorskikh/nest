# SPDX-License-Identifier: Apache-2.0
"""Synthetic attack traces for the streaming payments validators.

Each test hand-builds the exact trace a buggy or malicious payments plugin
would leave behind and proves the validator catches it:

* drain-after-close: debits keep flowing after ``stream:closed``;
* double-bill: the same work unit billed twice;
* over-bill on partition: debits for units whose acks were dropped;
* receipt mismatch: settled total disagrees with the sum of debits;
* silent pre-pay: no streaming lifecycle at all.
"""

from __future__ import annotations

from typing import Any

from nest_core.validators import (
    validate_streaming_conservation,
    validate_streaming_no_drain_after_close,
    validate_streaming_no_overbill_on_partition,
)


def _broadcast(agent: str, msg: str, ts: float = 0.0) -> dict[str, Any]:
    """A trace broadcast event as the simulator records it."""
    return {"ts": ts, "agent": agent, "kind": "broadcast", "size": len(msg), "msg": msg}


def _receive(agent: str, sender: str, msg: str, ts: float = 0.0) -> dict[str, Any]:
    """A delivered-message trace event."""
    return {"ts": ts, "agent": agent, "kind": "receive", "from": sender, "msg": msg}


def _dropped(agent: str, sender: str, msg: str, ts: float = 0.0) -> dict[str, Any]:
    """A dropped-message trace event (failure injection)."""
    return {"ts": ts, "agent": agent, "kind": "dropped", "from": sender, "msg": msg}


def _opened(ref: str, max_total: int = 25) -> dict[str, Any]:
    """A stream:opened broadcast for ``ref``."""
    return _broadcast(
        "buyer-0",
        f"stream:opened:ref={ref}:payer=buyer-0:payee=seller-0:rate=5:max={max_total}:tick=1",
    )


def _lifecycle(ref: str = "s-buyer-0-0") -> list[dict[str, Any]]:
    """A minimal well-formed stream: open, two acked+billed units, close."""
    return [
        _opened(ref),
        _receive("buyer-0", "seller-0", f"stream:ack:ref={ref}:unit=1"),
        _broadcast("buyer-0", f"stream:debit:ref={ref}:amount=5:unit=1:tick=1"),
        _receive("buyer-0", "seller-0", f"stream:ack:ref={ref}:unit=2"),
        _broadcast("buyer-0", f"stream:debit:ref={ref}:amount=5:unit=2:tick=1"),
        _broadcast("buyer-0", f"stream:closed:ref={ref}:total=10:tick=2:by=buyer-0:reason=done"),
    ]


def test_well_formed_lifecycle_passes_all_three() -> None:
    """The clean lifecycle satisfies every streaming validator."""
    events = _lifecycle()
    for validator in (
        validate_streaming_conservation,
        validate_streaming_no_drain_after_close,
        validate_streaming_no_overbill_on_partition,
    ):
        results = validator(events)
        assert all(r.passed for r in results), results


def test_drain_after_close_is_caught() -> None:
    """A debit landing after the stream closed fails the close validator."""
    events = _lifecycle()
    events.append(_receive("buyer-0", "seller-0", "stream:ack:ref=s-buyer-0-0:unit=3"))
    events.append(_broadcast("buyer-0", "stream:debit:ref=s-buyer-0-0:amount=5:unit=3:tick=3"))
    results = validate_streaming_no_drain_after_close(events)
    assert not all(r.passed for r in results)
    assert "after the stream closed" in results[0].detail


def test_double_billed_unit_is_caught() -> None:
    """Billing the same unit twice fails the close validator."""
    events = _lifecycle()
    # Duplicate the unit-2 debit *before* the close broadcast.
    events.insert(5, _broadcast("buyer-0", "stream:debit:ref=s-buyer-0-0:amount=5:unit=2:tick=1"))
    results = validate_streaming_no_drain_after_close(events)
    assert not all(r.passed for r in results)
    assert "billed twice" in results[0].detail


def test_overbill_without_delivered_ack_is_caught() -> None:
    """A debit whose ack was dropped (partition) fails the over-bill validator."""
    ref = "s-buyer-0-0"
    events = [
        _opened(ref),
        # The ack never arrives — the failure injector killed it.
        _dropped("buyer-0", "seller-0", f"stream:ack:ref={ref}:unit=1"),
        # A buggy plugin bills the tick anyway.
        _broadcast("buyer-0", f"stream:debit:ref={ref}:amount=5:unit=1:tick=1"),
        _broadcast("buyer-0", f"stream:closed:ref={ref}:total=5:tick=2:by=buyer-0:reason=done"),
    ]
    results = validate_streaming_no_overbill_on_partition(events)
    assert not all(r.passed for r in results)
    assert "without a previously delivered ack" in results[0].detail


def test_debit_before_its_ack_is_caught() -> None:
    """Billing ahead of delivery (time-travel billing) also fails."""
    ref = "s-buyer-0-0"
    events = [
        _opened(ref),
        _broadcast("buyer-0", f"stream:debit:ref={ref}:amount=5:unit=1:tick=1"),
        _receive("buyer-0", "seller-0", f"stream:ack:ref={ref}:unit=1"),
        _broadcast("buyer-0", f"stream:closed:ref={ref}:total=5:tick=2:by=buyer-0:reason=done"),
    ]
    results = validate_streaming_no_overbill_on_partition(events)
    assert not all(r.passed for r in results)


def test_receipt_total_mismatch_is_caught() -> None:
    """A settled total that disagrees with the debit sum fails conservation."""
    events = _lifecycle()
    events[-1] = _broadcast(
        "buyer-0",
        "stream:closed:ref=s-buyer-0-0:total=25:tick=2:by=buyer-0:reason=done",
    )
    results = validate_streaming_conservation(events)
    assert not all(r.passed for r in results)
    assert "!= sum of debits" in results[0].detail


def test_billing_past_max_total_is_caught() -> None:
    """Debits summing past the declared cap fail conservation."""
    ref = "s-buyer-0-0"
    events = [
        _opened(ref, max_total=10),
    ]
    for unit in (1, 2, 3):
        events.append(_receive("buyer-0", "seller-0", f"stream:ack:ref={ref}:unit={unit}"))
        events.append(_broadcast("buyer-0", f"stream:debit:ref={ref}:amount=5:unit={unit}:tick=1"))
    results = validate_streaming_conservation(events)
    assert not all(r.passed for r in results)
    assert "past max_total" in results[0].detail


def test_missing_lifecycle_fails_not_passes() -> None:
    """A trace with no stream events fails all three — never vacuously passes."""
    events = [_broadcast("buyer-0", "sold:widget:100")]
    assert not all(r.passed for r in validate_streaming_conservation(events))
    assert not all(r.passed for r in validate_streaming_no_drain_after_close(events))
    assert not all(r.passed for r in validate_streaming_no_overbill_on_partition(events))
