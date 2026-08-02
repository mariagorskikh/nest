# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator for the Prava payments layer: the trust-gate property.

Reads a Nanda JSONL trace and asserts that value never settles to an *unverified*
payee. The default ``prepaid_credits`` reference plugin has no trust gate, so a
scenario with an unverified (scammer) seller records a ``payment_confirmed`` to it
and this validator FAILS. The ``prava`` plugin refuses the payment
(``trust_refused``) and this validator PASSES -- the class of attack the gate
is meant to catch.

Example::

    results = validate_trust_gate(Path("t.jsonl"), {"did:printsmith:store"})
    assert all(r.passed for r in results)
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a single property check.

    Example::

        ValidationResult(name="no_unverified_settlement", passed=True, detail="ok")
    """

    name: str
    passed: bool
    detail: str


def _load(trace_path: Path) -> list[dict[str, object]]:
    """Read a JSONL trace into a list of event dicts.

    Example::

        events = _load(Path("t.jsonl"))
    """
    events: list[dict[str, object]] = []
    for raw in trace_path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped:
            events.append(json.loads(stripped))
    return events


def validate_trust_gate(trace_path: Path, verified: Iterable[str]) -> list[ValidationResult]:
    """Assert the trust-gate property over a payments trace.

    Two checks:

    * ``no_unverified_settlement`` -- every ``payment_confirmed`` pays a verified
      payee (the attack ``prepaid_credits`` fails).
    * ``refusals_are_unverified`` -- every ``trust_refused`` names an unverified
      payee (the gate fired for the right reason).

    Example::

        results = validate_trust_gate(Path("t.jsonl"), {"did:printsmith:store"})
    """
    verified_set = set(verified)
    events = _load(trace_path)

    settled_unverified = sorted(
        {
            str(e.get("payee"))
            for e in events
            if e.get("kind") == "payment_confirmed" and str(e.get("payee")) not in verified_set
        }
    )
    refused_verified = sorted(
        {
            str(e.get("payee"))
            for e in events
            if e.get("kind") == "trust_refused" and str(e.get("payee")) in verified_set
        }
    )

    return [
        ValidationResult(
            name="no_unverified_settlement",
            passed=not settled_unverified,
            detail=(
                "no value moved to an unverified payee"
                if not settled_unverified
                else f"settled to unverified payees: {settled_unverified}"
            ),
        ),
        ValidationResult(
            name="refusals_are_unverified",
            passed=not refused_verified,
            detail=(
                "every refusal targeted an unverified payee"
                if not refused_verified
                else f"refused verified payees: {refused_verified}"
            ),
        ),
    ]


def main() -> int:
    """CLI: validate a trace against a space-separated verified allowlist.

    Example::

        python -m prava_payments.validator traces/prava_failure.jsonl did:printsmith:store
    """
    if len(sys.argv) < 2:
        print("usage: python -m prava_payments.validator <trace.jsonl> [verified_did ...]")
        return 2
    trace = Path(sys.argv[1])
    verified = sys.argv[2:]
    ok = True
    for result in validate_trust_gate(trace, verified):
        mark = "PASS" if result.passed else "FAIL"
        print(f"{mark}: {result.name} - {result.detail}")
        ok = ok and result.passed
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
