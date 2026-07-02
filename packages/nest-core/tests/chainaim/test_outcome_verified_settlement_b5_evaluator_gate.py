# SPDX-License-Identifier: Apache-2.0
"""Iteration-5 (outcome_verified_settlement_b5) unit tests for the L3 conformance gate.

Pin the pure ``EvaluatorGate`` contract before any driver wires it to the trace
(that's b6): the default reference-match criterion accepts matching content and
rejects mismatched content, integrity failures short-circuit before the
criterion ever runs, ``require_integrity=False`` skips the inner checksum gate,
unknown criteria and unknown gate names both fail fast, and the gate is pure
(repeatable, no per-call state). The single most important test here is
``test_outcome_verified_settlement_b5_checksum_passes_criterion_fails``: it is
the proof that L3 is not redundant with L2.
"""

from __future__ import annotations

import hashlib

import pytest
from nest_core.scenarios_builtin.chainaim.gates import (
    ChecksumGate,
    EvaluatorGate,
    Gate,
    UnitContext,
    Verdict,
    canonical_chunk,
)


def _honest_ctx(ref: str, seq: int, chunk: bytes) -> UnitContext:
    """Build a UnitContext with a declared checksum that honestly matches ``chunk``.

    Example::

        ctx = _honest_ctx("buyer-0-stream", 3, b"buyer-0-stream#2")
    """
    declared = hashlib.sha256(chunk).hexdigest()
    return UnitContext(ref=ref, seq=seq, ack_received=True, chunk=chunk, declared_checksum=declared)


def test_outcome_verified_settlement_b5_evaluator_passes_matching_content() -> None:
    """Default reference_match criterion passes when chunk == canonical(ref, seq)."""
    ref, seq = "buyer-0-stream", 0
    ctx = _honest_ctx(ref, seq, canonical_chunk(ref, seq))
    verdict = EvaluatorGate().should_settle(ctx)
    assert verdict == Verdict(passed=True, ref=ref, seq=seq)


def test_outcome_verified_settlement_b5_checksum_passes_criterion_fails() -> None:
    """THE proof case: an honestly-checksummed reply to the WRONG unit passes L2
    and must fail L3 -- this is what makes EvaluatorGate more than ChecksumGate.

    The seller replays seq 2's real content at seq 3's slot, with an honest
    checksum of what it actually sent (seq 2's bytes). A bare ChecksumGate sees
    self-consistent bytes and passes. EvaluatorGate's composed inner
    ChecksumGate therefore ALSO passes -- integrity does not short-circuit here
    -- but reference_match compares against seq 3's canonical bytes and fails.
    """
    ref = "buyer-0-stream"
    replayed_seq2_bytes = canonical_chunk(ref, 2)
    ctx = _honest_ctx(ref, seq=3, chunk=replayed_seq2_bytes)

    bare_checksum_verdict = ChecksumGate().should_settle(ctx)
    assert bare_checksum_verdict.passed is True, "sanity: the checksum IS honest for what was sent"

    evaluator_verdict = EvaluatorGate().should_settle(ctx)
    assert evaluator_verdict == Verdict(passed=False, ref=ref, seq=3)


def test_outcome_verified_settlement_b5_evaluator_short_circuits_on_bad_integrity() -> None:
    """A tampered checksum fails at the inner ChecksumGate; the criterion never runs.

    Content matches canonical (would pass reference_match on its own), but the
    declared checksum does not match the delivered bytes -- L2 fails first.
    """
    ref, seq = "buyer-0-stream", 1
    chunk = canonical_chunk(ref, seq)
    ctx = UnitContext(ref=ref, seq=seq, ack_received=True, chunk=chunk, declared_checksum="0" * 64)
    verdict = EvaluatorGate().should_settle(ctx)
    assert verdict == Verdict(passed=False, ref=ref, seq=seq)


def test_outcome_verified_settlement_b5_require_integrity_false_skips_checksum() -> None:
    """With require_integrity=False, a bad/missing checksum is irrelevant -- only
    the criterion decides."""
    ref, seq = "buyer-0-stream", 2
    chunk = canonical_chunk(ref, seq)
    ctx = UnitContext(ref=ref, seq=seq, ack_received=True, chunk=chunk, declared_checksum=None)
    verdict = EvaluatorGate(require_integrity=False).should_settle(ctx)
    assert verdict == Verdict(passed=True, ref=ref, seq=seq)


def test_outcome_verified_settlement_b5_unknown_criterion_raises() -> None:
    """Constructing EvaluatorGate with an unregistered criterion name fails fast."""
    with pytest.raises(ValueError, match="unknown criterion"):
        EvaluatorGate(criterion="not_a_real_criterion")


def test_outcome_verified_settlement_b5_gate_from_name_evaluator() -> None:
    """from_name builds EvaluatorGate, forwards criterion/algo, and lists it
    among known gate names on failure."""
    gate = Gate.from_name("evaluator", criterion="reference_match")
    assert isinstance(gate, EvaluatorGate)
    with pytest.raises(ValueError, match="evaluator"):
        Gate.from_name("bogus_gate_name")


def test_outcome_verified_settlement_b5_evaluator_is_pure() -> None:
    """Gate is repeatable and carries no per-call state (no hidden RNG/clock/counter)."""
    ref = "buyer-0-stream"
    ok_ctx = _honest_ctx(ref, 0, canonical_chunk(ref, 0))
    bad_ctx = _honest_ctx(ref, 1, canonical_chunk(ref, 0))  # wrong content for seq 1
    gate = EvaluatorGate()
    first = gate.should_settle(ok_ctx)
    _interleaved = gate.should_settle(bad_ctx)
    third = gate.should_settle(ok_ctx)
    assert first.passed is True
    assert first == third
    assert gate.should_settle(ok_ctx) == first
