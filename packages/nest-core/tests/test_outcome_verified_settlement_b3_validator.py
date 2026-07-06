# SPDX-License-Identifier: Apache-2.0
"""Iteration-3 (outcome_verified_settlement_b3) tests for the over-bill validator.

``validate_outcome_verified_settlement_no_overbill_on_failed_verification`` applies
only to content-gated streams (those that emit ``gate:`` verdict lines): a closed
stream must never bill more than ``rate * (#pass verdicts)``. Default ack-gated
streams carry no ``gate:`` lines and are skipped (PASS), so the two original
validators are unaffected.
"""

from __future__ import annotations

from typing import Any

from nest_core.validators import (
    VALIDATORS,
    validate_events,
    validate_outcome_verified_settlement_no_drain_after_close,
    validate_outcome_verified_settlement_no_overbill,
    validate_outcome_verified_settlement_no_overbill_on_failed_verification,
    validate_outcome_verified_settlement_verdicts_match_committed_criterion,
)

type Event = dict[str, Any]


def _send(agent: str, to: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _recv(agent: str, frm: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "receive", "from": frm, "msg": msg}


def _content_gated_stream(
    ref: str = "buyer-0-stream",
    rate: int = 1,
    passes: int = 2,
    fails: int = 1,
    drained: int | None = None,
) -> list[Event]:
    """A closed content-gated stream: ``passes`` pass verdicts then ``fails`` fails.

    ``drained`` defaults to the correct ``rate * passes``; override it to inject an
    over-bill. Each tick is delivered (a content ack) and carries a gate verdict,
    matching the driver's content-gate grammar.
    """
    events: list[Event] = [
        _send("buyer-0", "seller-0", f"stream-open:{ref}:buyer-0:seller-0:{rate}:20:0"),
    ]
    seq = 0
    for verdict in ["pass"] * passes + ["fail"] * fails:
        now = seq + 1
        events.append(_send("buyer-0", "seller-0", f"tick:{ref}:{seq}:{rate}:{now}", ts=now))
        events.append(_recv("buyer-0", "seller-0", f"ack:{ref}:{seq}:cafe:babe", ts=now))
        events.append(_send("buyer-0", "seller-0", f"gate:{ref}:{seq}:{verdict}", ts=now))
        seq += 1
    final = rate * passes if drained is None else drained
    events.append(
        _send("buyer-0", "seller-0", f"stream-close:{ref}:{seq}:{final}:{seq}:degrade", ts=seq)
    )
    return events


def _clean_stream(ref: str = "buyer-0-stream", rate: int = 1, ticks: int = 5) -> list[Event]:
    """A fully delivered default (ack-gated) stream: no gate: lines, drained == rate * ticks."""
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


def test_outcome_verified_settlement_b3_fails_overbill_on_failed_verification() -> None:
    """A content-gated stream billing past its pass verdicts (bill_regardless) FAILS."""
    # 2 pass + 1 fail, but drained=3: the failing tick was billed anyway (the bug).
    events = _content_gated_stream(passes=2, fails=1, drained=3)
    results = validate_outcome_verified_settlement_no_overbill_on_failed_verification(events)
    assert len(results) == 1
    assert results[0].passed is False
    assert "buyer-0-stream" in results[0].detail


def test_outcome_verified_settlement_b3_passes_correct_degrade() -> None:
    """A content-gated stream that bills exactly its pass verdicts PASSES."""
    # 2 pass + 1 fail, drained=2 == rate * passes: the failing tick was not billed.
    events = _content_gated_stream(passes=2, fails=1)
    results = validate_outcome_verified_settlement_no_overbill_on_failed_verification(events)
    assert len(results) == 1
    assert results[0].passed is True


def test_outcome_verified_settlement_b3_survives_malformed_gate_line() -> None:
    """Garbage / short gate: lines must not crash the validator."""
    ref = "buyer-0-stream"
    events: list[Event] = [
        _send("buyer-0", "seller-0", f"stream-open:{ref}:buyer-0:seller-0:1:20:0"),
        _send("buyer-0", "seller-0", f"gate:{ref}"),  # too short, no seq/verdict
        _send("buyer-0", "seller-0", f"gate:{ref}:0:pass"),
        _send("buyer-0", "seller-0", f"gate:{ref}:1:garbage"),  # unknown verdict
        _send("buyer-0", "seller-0", "gate:only:two"),  # short, dropped
        _send("buyer-0", "seller-0", "garbage-line-no-colons"),
        _send("buyer-0", "seller-0", f"stream-close:{ref}:2:1:2:degrade"),
    ]
    results = validate_outcome_verified_settlement_no_overbill_on_failed_verification(events)
    assert len(results) == 1
    # 1 pass verdict, drained=1 -> 1 <= 1*1 -> PASS; the point is it did not crash.
    assert results[0].passed is True


def test_outcome_verified_settlement_b3_original_two_validators_unaffected() -> None:
    """A clean default trace runs all 4 registered validators and all PASS (the
    content-gated ones skip a stream with no gate: lines)."""
    events = _clean_stream()
    funcs = VALIDATORS["outcome_verified_settlement"]
    assert validate_outcome_verified_settlement_no_drain_after_close in funcs
    assert validate_outcome_verified_settlement_no_overbill in funcs
    assert validate_outcome_verified_settlement_no_overbill_on_failed_verification in funcs
    assert validate_outcome_verified_settlement_verdicts_match_committed_criterion in funcs
    assert len(funcs) == 4
    results = validate_events(events, "outcome_verified_settlement")
    assert len(results) == 4
    assert all(r.passed for r in results)
