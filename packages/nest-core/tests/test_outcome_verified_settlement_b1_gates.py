# SPDX-License-Identifier: Apache-2.0
"""Iteration-1 (outcome_verified_settlement_b1) unit tests for the settlement gate seam.

Pin the pure gate contract before any driver wires it to the trace: the default
delivery gate must mirror today's ack-gated billing, the content gate must
accept a matching checksum and reject a tampered one, gates must be pure
(repeatable, no per-call state), and the ``from_name`` factory must default to
the delivery gate and reject unknown names.
"""

from __future__ import annotations

import hashlib

import pytest
from nest_core.scenarios_builtin.gates import (
    AckReceivedGate,
    ChecksumGate,
    Gate,
    UnitContext,
    Verdict,
)


def test_outcome_verified_settlement_b1_ack_gate_matches_today() -> None:
    """Delivery gate settles iff the unit's ack was received (== today's billing)."""
    gate = AckReceivedGate()
    acked = gate.should_settle(UnitContext(ref="buyer-0-stream", seq=2, ack_received=True))
    assert acked == Verdict(passed=True, ref="buyer-0-stream", seq=2)
    missed = gate.should_settle(UnitContext(ref="buyer-0-stream", seq=3, ack_received=False))
    assert missed == Verdict(passed=False, ref="buyer-0-stream", seq=3)


def test_outcome_verified_settlement_b1_checksum_gate_accepts_match() -> None:
    """Content gate passes when the recomputed checksum equals the declared one."""
    chunk = b"metered-unit-payload"
    declared = hashlib.sha256(chunk).hexdigest()
    gate = ChecksumGate(algo="sha256")
    verdict = gate.should_settle(
        UnitContext(ref="buyer-0-stream", seq=0, chunk=chunk, declared_checksum=declared)
    )
    assert verdict == Verdict(passed=True, ref="buyer-0-stream", seq=0)


def test_outcome_verified_settlement_b1_checksum_gate_rejects_tamper() -> None:
    """Content gate fails on a tampered chunk and on a missing declared checksum."""
    chunk = b"metered-unit-payload"
    declared = hashlib.sha256(chunk).hexdigest()
    gate = ChecksumGate()
    tampered = gate.should_settle(
        UnitContext(ref="buyer-0-stream", seq=1, chunk=b"tampered", declared_checksum=declared)
    )
    assert tampered.passed is False
    no_claim = gate.should_settle(
        UnitContext(ref="buyer-0-stream", seq=2, chunk=chunk, declared_checksum=None)
    )
    assert no_claim.passed is False


def test_outcome_verified_settlement_b1_gate_is_pure() -> None:
    """Gates are repeatable and carry no per-call state (no hidden RNG/clock/counter)."""
    gate = ChecksumGate()
    chunk = b"abc"
    declared = hashlib.sha256(chunk).hexdigest()
    ctx0 = UnitContext(ref="r", seq=0, chunk=chunk, declared_checksum=declared)
    ctx1 = UnitContext(ref="r", seq=1, chunk=b"xyz", declared_checksum=declared)
    first = gate.should_settle(ctx0)
    _interleaved = gate.should_settle(ctx1)
    third = gate.should_settle(ctx0)
    assert first.passed is True
    assert first == third
    assert gate.should_settle(ctx0) == first
    ack = AckReceivedGate()
    ack_ctx = UnitContext(ref="r", seq=9, ack_received=True)
    assert ack.should_settle(ack_ctx) == ack.should_settle(ack_ctx)


def test_outcome_verified_settlement_b1_gate_from_name_default() -> None:
    """from_name defaults to the delivery gate, builds the content gate, rejects unknowns."""
    assert isinstance(Gate.from_name(), AckReceivedGate)
    assert isinstance(Gate.from_name("ack_received"), AckReceivedGate)
    assert isinstance(Gate.from_name("checksum"), ChecksumGate)
    assert isinstance(Gate.from_name("checksum", algo="sha256"), ChecksumGate)
    with pytest.raises(ValueError):
        Gate.from_name("bogus")
