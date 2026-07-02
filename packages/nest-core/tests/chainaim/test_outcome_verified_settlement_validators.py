# SPDX-License-Identifier: Apache-2.0
"""Tests for the ChainAIM outcome-verified-settlement validators."""

from __future__ import annotations

from typing import Any

from nest_core.chainaim.outcome_verified_settlement_validator import (
    validate_outcome_verified_settlement_no_drain_after_close,
    validate_outcome_verified_settlement_no_overbill,
)
from nest_core.validators import validate_events

type Event = dict[str, Any]


def _send(agent: str, to: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _recv(agent: str, frm: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "receive", "from": frm, "msg": msg}


def _clean_stream(ref: str = "buyer-0-stream", rate: int = 1, ticks: int = 5) -> list[Event]:
    """A fully delivered stream: every tick acked, drained == rate * ticks."""
    events: list[Event] = [
        _send("buyer-0", "seller-0", f"stream-open:{ref}:buyer-0:seller-0:{rate}:20:0"),
    ]
    for seq in range(ticks):
        now = seq + 1
        events.append(_send("buyer-0", "seller-0", f"tick:{ref}:{seq}:{rate}:{now}", ts=now))
        events.append(_recv("buyer-0", "seller-0", f"ack:{ref}:{seq}", ts=now))
    drained = rate * ticks
    events.append(
        _send("buyer-0", "seller-0", f"stream-close:{ref}:{ticks}:{drained}:{ticks}:done", ts=ticks)
    )
    return events


class TestNoOverbill:
    def test_pass_fully_delivered(self) -> None:
        results = validate_outcome_verified_settlement_no_overbill(_clean_stream())
        assert results[0].passed is True

    def test_pass_partitioned_bills_nothing(self) -> None:
        # Open + one tick sent (dropped: no ack received) + close with drained 0.
        ref = "buyer-4-stream"
        events = [
            _send("buyer-4", "seller-4", f"stream-open:{ref}:buyer-4:seller-4:1:20:0"),
            _send("buyer-4", "seller-4", f"tick:{ref}:0:1:1", ts=1),
            _send("buyer-4", "seller-4", f"stream-close:{ref}:0:0:3:timeout", ts=3),
        ]
        results = validate_outcome_verified_settlement_no_overbill(events)
        assert results[0].passed is True

    def test_fail_billed_without_delivery(self) -> None:
        # drained 1 but no ack ever received (over-bill on partition).
        ref = "buyer-4-stream"
        events = [
            _send("buyer-4", "seller-4", f"stream-open:{ref}:buyer-4:seller-4:1:20:0"),
            _send("buyer-4", "seller-4", f"tick:{ref}:0:1:1", ts=1),
            _send("buyer-4", "seller-4", f"stream-close:{ref}:1:1:3:timeout", ts=3),
        ]
        results = validate_outcome_verified_settlement_no_overbill(events)
        assert results[0].passed is False
        assert ref in results[0].detail


class TestNoDrainAfterClose:
    def test_pass_clean(self) -> None:
        results = validate_outcome_verified_settlement_no_drain_after_close(_clean_stream())
        assert results[0].passed is True

    def test_fail_tick_after_close(self) -> None:
        events = _clean_stream()
        # A stray metered tick at now=9, after close_tick=5.
        events.append(_send("buyer-0", "seller-0", "tick:buyer-0-stream:9:1:9", ts=9))
        results = validate_outcome_verified_settlement_no_drain_after_close(events)
        assert results[0].passed is False
        assert "after close" in results[0].detail

    def test_fail_exceeds_cap(self) -> None:
        ref = "buyer-0-stream"
        events = [
            _send("buyer-0", "seller-0", f"stream-open:{ref}:buyer-0:seller-0:1:20:0"),
            _send("buyer-0", "seller-0", f"stream-close:{ref}:25:25:25:done", ts=25),
        ]
        results = validate_outcome_verified_settlement_no_drain_after_close(events)
        assert results[0].passed is False
        assert "cap" in results[0].detail


class TestRegistryIntegration:
    def test_validate_events_runs_both(self) -> None:
        results = validate_events(_clean_stream(), "outcome_verified_settlement")
        assert len(results) == 4
        assert all(r.passed for r in results)


class TestMalformedTrace:
    def test_validators_survive_garbage(self) -> None:
        # Truncated, non-numeric, and grammar-less lines must not crash the validators.
        events: list[Event] = [
            _send("x", "y", "stream-open:only:three"),
            _send("x", "y", "tick:s1:notanint:1:2"),
            _send("x", "y", "garbage-line-no-colons"),
            _recv("x", "y", ""),
            _send("x", "y", "stream-close:s1:bad:bad:bad:done"),
        ]
        r_overbill = validate_outcome_verified_settlement_no_overbill(events)
        r_drain = validate_outcome_verified_settlement_no_drain_after_close(events)
        assert len(r_overbill) == 1
        assert len(r_drain) == 1
