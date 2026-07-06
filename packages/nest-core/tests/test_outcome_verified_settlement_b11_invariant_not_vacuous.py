# SPDX-License-Identifier: Apache-2.0
"""Iteration-11 (outcome_verified_settlement_b11) comparative discipline tests:
the ``no_overbill_on_failed_verification`` invariant is NOT vacuous.

Hand-built event traces (the ``b3``/``b8`` pattern -- deterministic, no runner,
no mocks of anything real) put TWO billing disciplines on the *identical* unit
sequence: five delivered, honestly-checksummed units of which the last two fail
L3 conformance (a different real unit's bytes at this unit's slot -- the
nonconform case only ``reference_match`` catches):

* **Clock/delivery-billed discipline** (the upstream streaming baseline): bill
  one unit per delivered ack, verdicts notwithstanding -> drained 5. This is
  correct BY ITS OWN SPEC -- it satisfies ``no_overbill`` exactly (drained <=
  rate x acks), which is the invariant delivery billing commits to. It is NOT
  a bug and is not framed as one (repo precedent for validating a baseline
  against a stricter discipline's invariant:
  ``test_prepaid_credits_fails_validators``,
  ``test_datafacts_v1_fails_all_adversarial_checks``). But it bills past the
  verified prefix, so ``no_overbill_on_failed_verification`` FAILS.
* **Outcome-verified discipline**: identical inputs, bill only pass verdicts
  -> drained 3. All four validators PASS.

The two traces are byte-identical except the single ``drained`` figure in the
``stream-close`` line -- so the flipped verdict is attributable to the billing
discipline alone, proving the new invariant genuinely discriminates between
the two disciplines rather than passing vacuously on everything.
"""

from __future__ import annotations

import hashlib
from typing import Any

from nest_core.scenarios_builtin.gates import canonical_chunk
from nest_core.validators import validate_events

type Event = dict[str, Any]

_REF = "buyer-0-stream"
_KEY = "outcome_verified_settlement"
_NOVELTY = "outcome_verified_settlement_no_overbill_on_failed_verification"
_HONESTY = "outcome_verified_settlement_verdicts_match_committed_criterion"
_DRAIN = "outcome_verified_settlement_no_drain_after_close"
_OVERBILL = "outcome_verified_settlement_no_overbill"

_UNITS = 5  # seqs 0..4
_NONCONFORM_FROM = 3  # seqs 3-4 deliver the PREVIOUS unit's bytes, honestly checksummed
_RATE = 1
_CAP = 20


def _send(agent: str, to: str, msg: str, ts: float) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _recv(agent: str, frm: str, msg: str, ts: float) -> Event:
    return {"ts": ts, "agent": agent, "kind": "receive", "from": frm, "msg": msg}


def _delivered_units() -> list[tuple[int, bytes, str, str]]:
    """The shared unit sequence: (seq, delivered_chunk, honest_declared, verdict).

    Seqs below ``_NONCONFORM_FROM`` deliver their own canonical bytes (verdict
    ``pass``); from ``_NONCONFORM_FROM`` onward they deliver the previous unit's
    real canonical bytes with an HONEST checksum of what was actually sent
    (verdict ``fail`` -- checksum-honest, conformance-failing; the b8 honesty
    validator must not flag these).

    Example::

        units = _delivered_units()
    """
    units: list[tuple[int, bytes, str, str]] = []
    for seq in range(_UNITS):
        conforming = seq < _NONCONFORM_FROM
        chunk = canonical_chunk(_REF, seq if conforming else seq - 1)
        declared = hashlib.sha256(chunk).hexdigest()
        units.append((seq, chunk, declared, "pass" if conforming else "fail"))
    return units


def _trace(*, drained: int) -> list[Event]:
    """One full stream over the shared unit sequence, billing *drained* total.

    The ONLY degree of freedom is ``drained`` -- everything else (opens, ticks,
    delivered bytes, checksums, verdicts, close tick) is byte-identical across
    disciplines, so a validator verdict flip is attributable to billing alone.

    Example::

        events = _trace(drained=3)
    """
    events: list[Event] = [
        _send("buyer-0", "seller-0", f"stream-open:{_REF}:buyer-0:seller-0:{_RATE}:{_CAP}:0", 0.0)
    ]
    for seq, chunk, declared, verdict in _delivered_units():
        ts = float(seq + 1)
        events.append(_send("buyer-0", "seller-0", f"tick:{_REF}:{seq}:{_RATE}:{seq + 1}", ts))
        events.append(
            _recv("buyer-0", "seller-0", f"ack:{_REF}:{seq}:{chunk.hex()}:{declared}", ts)
        )
        events.append(_send("buyer-0", "seller-0", f"gate:{_REF}:{seq}:{verdict}", ts))
    events.append(
        _send("buyer-0", "seller-0", f"stream-close:{_REF}:{_UNITS}:{drained}:6:done", 6.0)
    )
    return events


def _by_name(events: list[Event]) -> dict[str, Any]:
    """Run all four registered validators and index results by name.

    Example::

        results = _by_name(_trace(drained=3))
    """
    return {r.name: r for r in validate_events(events, _KEY)}


def test_outcome_verified_settlement_b11_clock_billing_fails_only_new_invariant() -> None:
    """Delivery-billed discipline: correct by its OWN spec, fails ONLY the new invariant.

    drained 5 == rate x 5 delivered acks, so ``no_overbill`` (the delivery
    discipline's own commitment) PASSES -- the baseline is not a bug. But 2 of
    the 5 verdicts failed verification, so drained 5 > verified 3 and
    ``no_overbill_on_failed_verification`` FAILS: the invariant sees a
    difference delivery billing is blind to.
    """
    results = _by_name(_trace(drained=_RATE * _UNITS))
    assert len(results) == 4
    assert not results[_NOVELTY].passed, results[_NOVELTY].detail
    assert "exceeds verified" in results[_NOVELTY].detail
    assert results[_OVERBILL].passed, results[_OVERBILL].detail
    assert results[_DRAIN].passed, results[_DRAIN].detail
    assert results[_HONESTY].passed, results[_HONESTY].detail


def test_outcome_verified_settlement_b11_outcome_verified_passes_on_identical_inputs() -> None:
    """Outcome-verified discipline on the IDENTICAL unit sequence: all four PASS.

    Same opens, ticks, delivered bytes, checksums, and verdicts -- billing only
    the 3 pass-verdict units (drained 3) satisfies every validator, including
    the new invariant.
    """
    results = _by_name(_trace(drained=_RATE * _NONCONFORM_FROM))
    assert len(results) == 4
    assert all(r.passed for r in results.values()), [
        (r.name, r.detail) for r in results.values() if not r.passed
    ]


def test_outcome_verified_settlement_b11_traces_identical_except_billed_total() -> None:
    """The two disciplines' traces differ ONLY in the stream-close drained figure.

    This pins the comparison down: every event except the final close line is
    byte-identical, so the validator flip in the two tests above is
    attributable to the billing discipline alone -- the invariant is
    discriminating, not vacuous.
    """
    clock = _trace(drained=_RATE * _UNITS)
    verified = _trace(drained=_RATE * _NONCONFORM_FROM)
    assert len(clock) == len(verified)
    assert clock[:-1] == verified[:-1]
    assert clock[-1] != verified[-1]
    assert str(clock[-1]["msg"]).startswith("stream-close:")
    assert str(verified[-1]["msg"]).startswith("stream-close:")
