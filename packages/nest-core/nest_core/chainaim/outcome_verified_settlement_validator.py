# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the outcome-verified-settlement scenario.

Four trace-only invariants distinguish a correct outcome-verified-settlement
plugin from a buggy one. All read the colon-delimited grammar emitted by the
agents (``stream-open`` / ``tick`` / ``ack`` / ``gate`` / ``stream-close``):

* ``validate_outcome_verified_settlement_no_drain_after_close`` -- a stream never
  bills past its cap (``max_total``) and never emits a metered ``tick`` after its
  close tick.
* ``validate_outcome_verified_settlement_no_overbill`` -- a stream never bills
  (``drained``) more than the payee actually acknowledged receiving. This defeats
  over-billing during a network partition: when acks cannot return, a correct
  stream bills nothing, while a plugin that bills on send over-bills and is caught
  here.
* ``validate_outcome_verified_settlement_no_overbill_on_failed_verification`` -- a
  content-gated stream never bills past its verified (pass-verdict) ticks
  (``drained`` <= ``rate`` * pass verdicts). A plugin that bills on a failing
  verdict over-bills past what was verified and is caught here.
* ``validate_outcome_verified_settlement_verdicts_match_committed_criterion`` --
  a ``gate:pass`` verdict requires the recomputed checksum of the delivered
  bytes to actually match the declared checksum, re-derived independently from
  the logged ``ack:`` line, never trusting the plugin's own claim. SCOPE, stated
  rather than hidden: this validates the *integrity* component of a verdict
  only, both because that is the necessary condition shared by both content
  gates (``checksum`` and ``evaluator``) and because full criterion-level
  re-derivation (e.g. re-running ``reference_match``) would require the trace
  to commit which criterion was configured for the stream -- ``criterion_hash``
  on the wire is a roadmap item, not shipped in this iteration. Deliberately
  one-directional: a legitimate L3 conformance failure (integrity honest, gate
  correctly fails on the criterion) is NOT flagged -- only a ``pass`` verdict
  issued despite a checksum mismatch is.

``ValidationResult`` is imported lazily inside each function to avoid an import
cycle with ``nest_core.validators`` (which imports these functions at module
load to populate its registry).

Example::

    from nest_core.chainaim.outcome_verified_settlement_validator import (
        validate_outcome_verified_settlement_no_overbill,
    )
    results = validate_outcome_verified_settlement_no_overbill(events)
"""

from __future__ import annotations

import contextlib
import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nest_core.validators import ValidationResult


@dataclass
class _StreamRec:
    """Per-stream facts reconstructed from the trace."""

    rate: int | None = None
    max_total: int | None = None
    opened: int | None = None
    payer: str | None = None
    payee: str | None = None
    drained: int = 0
    close_tick: int | None = None
    closed: bool = False
    acked: int = 0
    gate_pass: int = 0
    gate_total: int = 0
    tick_sends: list[tuple[int, int]] = field(default_factory=lambda: list[tuple[int, int]]())


def _body(ev: dict[str, Any]) -> str:
    """Return payload text without the signature suffix added by reference agents."""
    return str(ev.get("msg", "")).rsplit("|sig:", 1)[0]


def _parse_streams(events: list[dict[str, Any]]) -> dict[str, _StreamRec]:
    """Group stream trace lines into per-ref records.

    ``stream-open`` / ``tick`` / ``stream-close`` are buyer *sends* (always
    recorded even when delivery is dropped); ``ack`` is counted only when the
    buyer actually *receives* it (a dropped ack is not a delivered tick).

    Example::

        streams = _parse_streams(events)
    """
    streams: dict[str, _StreamRec] = {}
    for ev in events:
        kind = ev.get("kind")
        if kind not in ("send", "receive", "broadcast"):
            continue
        parts = _body(ev).split(":")
        tag = parts[0]
        if tag == "stream-open" and kind in ("send", "broadcast") and len(parts) >= 7:
            rec = streams.setdefault(parts[1], _StreamRec())
            rec.payer, rec.payee = parts[2], parts[3]
            with contextlib.suppress(ValueError):
                rec.rate = int(parts[4])
                rec.max_total = int(parts[5])
                rec.opened = int(parts[6])
        elif tag == "tick" and kind == "send" and len(parts) >= 5:
            rec = streams.setdefault(parts[1], _StreamRec())
            with contextlib.suppress(ValueError):
                rec.tick_sends.append((int(parts[2]), int(parts[4])))
        elif tag == "ack" and kind == "receive" and len(parts) >= 3:
            rec = streams.setdefault(parts[1], _StreamRec())
            rec.acked += 1
        elif tag == "gate" and kind == "send" and len(parts) >= 4:
            rec = streams.setdefault(parts[1], _StreamRec())
            rec.gate_total += 1
            if parts[3] == "pass":
                rec.gate_pass += 1
        elif tag == "stream-close" and kind in ("send", "broadcast") and len(parts) >= 6:
            rec = streams.setdefault(parts[1], _StreamRec())
            rec.closed = True
            with contextlib.suppress(ValueError):
                rec.drained = int(parts[3])
                rec.close_tick = int(parts[4])
    return streams


def validate_outcome_verified_settlement_no_drain_after_close(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Fail if any closed stream exceeded its cap or billed a tick after closing.

    Example::

        results = validate_outcome_verified_settlement_no_drain_after_close(events)
    """
    from nest_core.validators import ValidationResult

    streams = _parse_streams(events)
    violations: list[str] = []
    checked = 0
    for ref, rec in streams.items():
        if not rec.closed:
            continue
        checked += 1
        if rec.max_total is not None and rec.drained > rec.max_total:
            violations.append(f"{ref}: drained {rec.drained} exceeds cap {rec.max_total}")
        if rec.close_tick is not None:
            late = [seq for (seq, now) in rec.tick_sends if now > rec.close_tick]
            if late:
                violations.append(
                    f"{ref}: {len(late)} tick(s) billed after close at {rec.close_tick}"
                )

    if violations:
        return [
            ValidationResult(
                "outcome_verified_settlement_no_drain_after_close", False, "; ".join(violations)
            )
        ]
    return [
        ValidationResult(
            "outcome_verified_settlement_no_drain_after_close", True, f"checked {checked} streams"
        )
    ]


def validate_outcome_verified_settlement_no_overbill(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Fail if a stream billed more than the payee acknowledged receiving.

    ``drained`` must not exceed ``rate * (acks the payer received)``. Under a
    partition the acks never arrive, so a correct stream drains nothing while a
    bill-on-send plugin over-bills and is flagged here.

    Example::

        results = validate_outcome_verified_settlement_no_overbill(events)
    """
    from nest_core.validators import ValidationResult

    streams = _parse_streams(events)
    violations: list[str] = []
    checked = 0
    for ref, rec in streams.items():
        if not rec.closed:
            continue
        checked += 1
        rate = rec.rate if rec.rate is not None else 0
        if rate > 0 and rec.drained > rate * rec.acked:
            violations.append(
                f"{ref}: drained {rec.drained} exceeds delivered {rec.acked} x rate {rate}"
            )

    if violations:
        return [
            ValidationResult(
                "outcome_verified_settlement_no_overbill", False, "; ".join(violations)
            )
        ]
    return [
        ValidationResult(
            "outcome_verified_settlement_no_overbill", True, f"checked {checked} streams"
        )
    ]


def validate_outcome_verified_settlement_no_overbill_on_failed_verification(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Fail if a content-gated stream billed past its verified (pass-verdict) ticks.

    Applies only to streams that emit ``gate:<ref>:<seq>:pass|fail`` verdict lines
    (the content gate). For each such closed stream, ``drained`` must not exceed
    ``rate * (pass verdicts)``: a stream that bills on a failing verdict (the
    ``bill_regardless`` bug) over-bills past what was verified and is flagged here.
    Default ack-gated streams emit no ``gate:`` lines and are skipped (PASS).

    Example::

        results = validate_outcome_verified_settlement_no_overbill_on_failed_verification(events)
    """
    from nest_core.validators import ValidationResult

    streams = _parse_streams(events)
    violations: list[str] = []
    checked = 0
    for ref, rec in streams.items():
        if not rec.closed:
            continue
        if rec.gate_total == 0:
            continue
        checked += 1
        rate = rec.rate if rec.rate is not None else 0
        verified = rate * rec.gate_pass
        if rec.drained > verified:
            violations.append(
                f"{ref}: drained {rec.drained} exceeds verified {verified} "
                f"(rate {rate} x {rec.gate_pass} pass of {rec.gate_total} verdicts)"
            )

    if violations:
        return [
            ValidationResult(
                "outcome_verified_settlement_no_overbill_on_failed_verification",
                False,
                "; ".join(violations),
            )
        ]
    return [
        ValidationResult(
            "outcome_verified_settlement_no_overbill_on_failed_verification",
            True,
            f"checked {checked} content-gated streams",
        )
    ]


def validate_outcome_verified_settlement_verdicts_match_committed_criterion(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Fail if any gate:pass verdict was issued despite a checksum mismatch.

    Re-derives the integrity component of every content-gated verdict directly
    from the logged ``ack:<ref>:<seq>:<chunk_hex>:<declared_checksum>`` line --
    independent of, and never trusting, the plugin's own ``gate:pass|fail``
    claim. A unit with no content-gated ack on record (e.g. a default
    ack-gated stream, which emits no ``gate:`` lines at all) contributes
    nothing to check.

    SCOPE (see module docstring): integrity-honesty only, one-directional. A
    ``gate:fail`` is never flagged, even when integrity is honest -- that is
    the expected shape of a legitimate L3 conformance rejection, not evidence
    of dishonesty. Only a ``pass`` issued despite a checksum mismatch is a
    provable lie and is flagged.

    Example::

        results = validate_outcome_verified_settlement_verdicts_match_committed_criterion(events)
    """
    from nest_core.validators import ValidationResult

    declared_by_unit: dict[tuple[str, int], tuple[bytes, str]] = {}
    violations: list[str] = []
    checked = 0

    for ev in events:
        kind = ev.get("kind")
        if kind not in ("send", "receive", "broadcast"):
            continue
        parts = _body(ev).split(":")
        tag = parts[0]
        if tag == "ack" and kind == "receive" and len(parts) >= 5:
            ref = parts[1]
            with contextlib.suppress(ValueError):
                seq = int(parts[2])
                chunk = bytes.fromhex(parts[3])
                declared = parts[4]
                declared_by_unit[(ref, seq)] = (chunk, declared)
        elif tag == "gate" and kind == "send" and len(parts) >= 4:
            ref = parts[1]
            with contextlib.suppress(ValueError):
                seq = int(parts[2])
                verdict = parts[3]
                unit = declared_by_unit.get((ref, seq))
                if unit is None:
                    continue  # no content-gated ack observed; nothing to re-derive
                checked += 1
                chunk, declared = unit
                recomputed = hashlib.sha256(chunk).hexdigest()
                if verdict == "pass" and recomputed != declared:
                    violations.append(
                        f"{ref}:{seq}: gate:pass but recomputed checksum {recomputed} "
                        f"!= declared {declared}"
                    )

    if violations:
        return [
            ValidationResult(
                "outcome_verified_settlement_verdicts_match_committed_criterion",
                False,
                "; ".join(violations),
            )
        ]
    return [
        ValidationResult(
            "outcome_verified_settlement_verdicts_match_committed_criterion",
            True,
            f"checked {checked} content-gated verdicts",
        )
    ]
