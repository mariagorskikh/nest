# SPDX-License-Identifier: Apache-2.0
"""Pure deterministic aggregation for the 1 result and exit table."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .models import ULID, CheckResult, TestObservation

AggregationCondition = Literal["user_interrupted", "town_defect", "pre_admission"]


@dataclass(frozen=True)
class Aggregation:
    """Terminal result state with its derived process exit code."""

    execution_status: Literal["completed", "incomplete", "error"]
    verdict: Literal["pass", "fail", "inconclusive", "not_evaluated"]
    exit_code: Literal[0, 1, 2, 3, 4, 130]


def aggregate(
    checks: list[CheckResult],
    *,
    observations: Sequence[TestObservation],
    run_id: ULID,
    condition: AggregationCondition | None = None,
) -> Aggregation:
    """Apply the frozen table without serializing a CLI exit into a result."""
    if condition == "user_interrupted":
        return Aggregation("incomplete", "inconclusive", 130)
    if condition == "town_defect":
        return Aggregation("error", "not_evaluated", 3)
    if condition == "pre_admission" or not any(check.required for check in checks):
        return Aggregation("error", "not_evaluated", 2)
    required = [check for check in checks if check.required]
    if not _conclusive_evidence_resolves(checks, observations, run_id):
        return Aggregation("incomplete", "inconclusive", 4)
    if any(check.status in {"inconclusive", "error"} for check in required):
        return Aggregation("incomplete", "inconclusive", 4)
    if any(check.status == "fail" for check in required):
        return Aggregation("completed", "fail", 1)
    if any(check.status == "not_tested" for check in required):
        return Aggregation("incomplete", "inconclusive", 4)
    return Aggregation("completed", "pass", 0)


def _conclusive_evidence_resolves(
    checks: Sequence[CheckResult], observations: Sequence[TestObservation], run_id: ULID
) -> bool:
    """Require every conclusive check reference to name one same-run trace event."""
    by_sequence: dict[int, TestObservation] = {}
    for observation in observations:
        event = observation.root
        if event.run_id != run_id or event.seq in by_sequence:
            return False
        by_sequence[event.seq] = observation
    for check in checks:
        if check.status not in {"pass", "fail"}:
            continue
        for reference in check.evidence_refs:
            if not reference.startswith("trace.jsonl#seq="):
                return False
            sequence = int(reference.removeprefix("trace.jsonl#seq="))
            if sequence not in by_sequence:
                return False
    return True
