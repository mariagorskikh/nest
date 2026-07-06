# SPDX-License-Identifier: Apache-2.0
"""Iteration-8 (outcome_verified_settlement_b8) tests for the verdict-honesty
validator (P1).

``validate_outcome_verified_settlement_verdicts_match_committed_criterion``
re-derives the integrity component of every content-gated ``gate:pass|fail``
verdict directly from the logged ``ack:`` line -- never trusting the plugin's
own claim. Scope is deliberately one-directional (see the validator's own
docstring): a ``gate:pass`` issued despite a checksum mismatch is a provable
lie and is flagged; a ``gate:fail`` is NEVER flagged, even when integrity is
honest, because that is the expected shape of a legitimate L3 conformance
rejection (see the b5/b6 nonconform tests), not evidence of dishonesty.

The single most important test here is
``test_outcome_verified_settlement_b8_honest_l3_fail_not_flagged``: getting
this backwards would break the exact nonconform-detection feature b5/b6 just
shipped.
"""

from __future__ import annotations

import hashlib
from typing import Any

from nest_core.validators import (
    validate_events,
    validate_outcome_verified_settlement_verdicts_match_committed_criterion,
)

type Event = dict[str, Any]

_REF = "buyer-0-stream"


def _send(agent: str, to: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _recv(agent: str, frm: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "receive", "from": frm, "msg": msg}


def _ack(ref: str, seq: int, chunk: bytes, declared: str, ts: float) -> Event:
    """A content-gated ack event carrying *chunk* and a (possibly dishonest) *declared*.

    Example::

        ev = _ack("buyer-0-stream", 0, b"chunk", "deadbeef", ts=1)
    """
    return _recv("buyer-0", "seller-0", f"ack:{ref}:{seq}:{chunk.hex()}:{declared}", ts=ts)


def _gate(ref: str, seq: int, verdict: str, ts: float) -> Event:
    """A gate: verdict send event.

    Example::

        ev = _gate("buyer-0-stream", 0, "pass", ts=1)
    """
    return _send("buyer-0", "seller-0", f"gate:{ref}:{seq}:{verdict}", ts=ts)


def test_outcome_verified_settlement_b8_honest_pass_not_flagged() -> None:
    """A gate:pass with a genuinely matching checksum is not a violation."""
    chunk = b"buyer-0-stream#0"
    declared = hashlib.sha256(chunk).hexdigest()
    events = [_ack(_REF, 0, chunk, declared, 1), _gate(_REF, 0, "pass", 1)]
    results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    assert len(results) == 1
    assert results[0].passed is True
    assert "checked 1" in results[0].detail


def test_outcome_verified_settlement_b8_dishonest_pass_flagged() -> None:
    """THE core catch: gate:pass issued despite a mismatched checksum is a
    provable lie."""
    chunk = b"buyer-0-stream#0"
    wrong_declared = hashlib.sha256(b"something-else-entirely").hexdigest()
    events = [_ack(_REF, 0, chunk, wrong_declared, 1), _gate(_REF, 0, "pass", 1)]
    results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    assert len(results) == 1
    assert results[0].passed is False
    assert f"{_REF}:0" in results[0].detail


def test_outcome_verified_settlement_b8_honest_l3_fail_not_flagged() -> None:
    """THE critical asymmetry: an integrity-honest gate:fail (a legitimate L3
    conformance rejection, e.g. the nonconform case from b5/b6) must NOT be
    flagged. Getting this backwards would break nonconform detection."""
    replayed = b"buyer-0-stream#2"  # honest for what was sent, wrong for seq 3's slot
    declared = hashlib.sha256(replayed).hexdigest()
    events = [_ack(_REF, 3, replayed, declared, 1), _gate(_REF, 3, "fail", 1)]
    results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    assert len(results) == 1
    assert results[0].passed is True


def test_outcome_verified_settlement_b8_dishonest_checksum_fail_not_flagged() -> None:
    """A gate:fail from a genuinely mismatched checksum (the existing degrade
    case) is also not flagged -- the gate correctly failed for the right reason."""
    intended = b"buyer-0-stream#2"
    corrupted = intended + b"!"
    declared = hashlib.sha256(intended).hexdigest()  # honest about intended, not delivered
    events = [_ack(_REF, 2, corrupted, declared, 1), _gate(_REF, 2, "fail", 1)]
    results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    assert len(results) == 1
    assert results[0].passed is True


def test_outcome_verified_settlement_b8_no_content_gated_ack_skips() -> None:
    """A default (ack_received-gated) stream has no gate: lines at all --
    nothing to check, checked=0, trivially PASS."""
    events = [_recv("buyer-0", "seller-0", f"ack:{_REF}:0", ts=1)]  # 3-part, no chunk/checksum
    results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    assert len(results) == 1
    assert results[0].passed is True
    assert "checked 0" in results[0].detail


def test_outcome_verified_settlement_b8_gate_with_no_matching_ack_skips() -> None:
    """A gate: line with no recorded content-gated ack for its (ref, seq) is
    skipped, not treated as a violation (nothing to re-derive)."""
    events = [_gate(_REF, 0, "pass", 1)]  # no ack: line at all
    results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    assert len(results) == 1
    assert results[0].passed is True
    assert "checked 0" in results[0].detail


def test_outcome_verified_settlement_b8_survives_malformed_lines() -> None:
    """Garbage / short ack and gate: lines must not crash the validator."""
    events: list[Event] = [
        _recv("buyer-0", "seller-0", "ack:only:three"),
        _recv("buyer-0", "seller-0", f"ack:{_REF}:notanint:cafe:babe"),
        _send("buyer-0", "seller-0", f"gate:{_REF}"),
        _send("buyer-0", "seller-0", f"gate:{_REF}:notanint:pass"),
        _send("buyer-0", "seller-0", "garbage-line-no-colons"),
    ]
    results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    assert len(results) == 1
    assert results[0].passed is True  # nothing crashed, nothing legitimately checked


def test_outcome_verified_settlement_b8_registered_and_runs_via_registry() -> None:
    """Reachable through the full registry alongside the other three validators."""
    chunk = b"buyer-0-stream#0"
    declared = hashlib.sha256(chunk).hexdigest()
    events = [
        _send("buyer-0", "seller-0", f"stream-open:{_REF}:buyer-0:seller-0:1:20:0"),
        _send("buyer-0", "seller-0", f"tick:{_REF}:0:1:1", ts=1),
        _ack(_REF, 0, chunk, declared, 1),
        _gate(_REF, 0, "pass", 1),
        _send("buyer-0", "seller-0", f"stream-close:{_REF}:1:1:1:done", ts=1),
    ]
    results = validate_events(events, "outcome_verified_settlement")
    assert len(results) == 4
    assert all(r.passed for r in results), [(r.name, r.detail) for r in results if not r.passed]
