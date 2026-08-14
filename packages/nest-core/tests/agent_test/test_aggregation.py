# SPDX-License-Identifier: Apache-2.0
"""Pure result aggregation and process-exit mapping tests."""

from __future__ import annotations

from typing import Literal

import pytest
from nest_core.agent_test.aggregation import AggregationCondition, aggregate
from nest_core.agent_test.models import CheckResult, TestObservation

RUN_ID = "01K00000000000000000000001"


def _check(
    status: Literal["pass", "fail", "not_tested", "inconclusive", "error"],
    required: bool = True,
) -> CheckResult:
    return CheckResult(
        id="driver.contract",
        required=required,
        status=status,
        summary="checked",
        evidence_refs=["trace.jsonl#seq=1"] if status in {"pass", "fail"} else [],
    )


def _observation(*, sequence: int = 1, run_id: str = RUN_ID) -> TestObservation:
    return TestObservation.model_validate(
        {
            "schema_version": "town.test-observation/1",
            "seq": sequence,
            "event_id": "01K00000000000000000000002",
            "run_id": run_id,
            "kind": "test.driver.run_admitted",
            "logical_time": 0.0,
            "observed_at": "2026-08-13T12:00:00Z",
            "duration_ms": None,
            "observer": "town.agent-test-runner",
            "subject_participant_id": "provider-0",
            "message_id": None,
            "correlation_id": None,
            "request_digest": None,
            "response_digest": None,
            "data": {
                "adapter_instance_id": "adapter-0",
                "profile_digest": "sha256:" + "0" * 64,
                "driver_sequence": 0,
                "intent_kind": "declare_capability",
            },
        }
    )


def _aggregate(checks: list[CheckResult], *, condition: AggregationCondition | None = None):
    return aggregate(checks, observations=[_observation()], run_id=RUN_ID, condition=condition)


def test_unresolved_required_event_evidence_cannot_pass() -> None:
    """A bare or missing event reference is incomplete, never a false pass."""
    check = _check("pass").model_copy(update={"evidence_refs": ["missing.jsonl#seq=1"]})
    result = aggregate([check], observations=[_observation()], run_id=RUN_ID)
    assert (result.execution_status, result.verdict, result.exit_code) == (
        "incomplete",
        "inconclusive",
        4,
    )


def test_unresolved_optional_conclusive_evidence_makes_result_incomplete() -> None:
    """Optional checks do not decide the verdict, but their evidence must still resolve."""
    optional = _check("pass", required=False).model_copy(
        update={"evidence_refs": ["trace.jsonl#seq=99"]}
    )
    result = aggregate([_check("pass"), optional], observations=[_observation()], run_id=RUN_ID)
    assert (result.execution_status, result.verdict, result.exit_code) == (
        "incomplete",
        "inconclusive",
        4,
    )


def test_required_inconclusive_status_precedes_required_failure() -> None:
    """A mixed required result is incomplete rather than a conclusive failure."""
    result = _aggregate([_check("fail"), _check("inconclusive")])
    assert (result.execution_status, result.verdict, result.exit_code) == (
        "incomplete",
        "inconclusive",
        4,
    )


def test_required_failure_precedes_causally_downstream_not_tested() -> None:
    """A conclusive failure stays failed when a dependent check was not attempted."""
    result = _aggregate([_check("fail"), _check("not_tested")])
    assert (result.execution_status, result.verdict, result.exit_code) == (
        "completed",
        "fail",
        1,
    )


@pytest.mark.parametrize(
    ("checks", "condition", "status", "verdict", "exit_code"),
    [
        ([_check("pass")], None, "completed", "pass", 0),
        ([_check("fail")], None, "completed", "fail", 1),
        ([], "pre_admission", "error", "not_evaluated", 2),
        ([], "town_defect", "error", "not_evaluated", 3),
        ([_check("inconclusive")], None, "incomplete", "inconclusive", 4),
        ([_check("pass")], "user_interrupted", "incomplete", "inconclusive", 130),
    ],
)
def test_aggregation_table(
    checks: list[CheckResult],
    condition: AggregationCondition | None,
    status: str,
    verdict: str,
    exit_code: int,
) -> None:
    """The documented result table is deterministic and complete."""
    result = _aggregate(checks, condition=condition)
    actual = (result.execution_status, result.verdict, result.exit_code)
    assert actual == (status, verdict, exit_code)


@pytest.mark.parametrize("status", ["not_tested", "inconclusive", "error"])
def test_required_nonconclusive_check_can_never_pass(
    status: Literal["not_tested", "inconclusive", "error"],
) -> None:
    """Missing required evidence and errors remain inconclusive."""
    result = _aggregate([_check(status)])
    assert (result.verdict, result.exit_code) == ("inconclusive", 4)


def test_zero_required_checks_is_invalid_profile_configuration() -> None:
    """An empty required-check set never becomes a false pass."""
    result = _aggregate([_check("pass", required=False)])
    assert (result.execution_status, result.verdict, result.exit_code) == (
        "error",
        "not_evaluated",
        2,
    )
