# SPDX-License-Identifier: Apache-2.0
"""Generic result and evidence envelopes shared by every Test Profile codec."""

from __future__ import annotations

import math
from typing import Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, RootModel, model_validator

from .contracts import (
    ULID,
    AdapterInstanceId,
    ArtifactPath,
    DiagnosticCode,
    Digest,
    EventEvidenceReference,
    MediaType,
    ProfileReference,
    SafeId,
    SafeText128,
    SafeText256,
    SafeText512,
    StrictModel,
    UtcRfc3339,
)


class CheckResult(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"status": {"enum": ["pass", "fail"]}}},
                    "then": {"properties": {"evidence_refs": {"minItems": 1}}},
                }
            ]
        },
    )
    id: SafeId
    required: bool
    status: Literal["pass", "fail", "not_tested", "inconclusive", "error"]
    summary: SafeText512
    evidence_refs: list[EventEvidenceReference] = Field(max_length=64)

    @model_validator(mode="after")
    def _evidence_is_required_when_conclusive(self) -> CheckResult:
        if self.status in {"pass", "fail"} and not self.evidence_refs:
            raise ValueError("conclusive checks require evidence")
        return self


class CoverageResult(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"status": {"const": "exercised"}}},
                    "then": {"properties": {"evidence_refs": {"minItems": 1}}},
                },
                {
                    "if": {"properties": {"status": {"enum": ["not_tested", "unknown"]}}},
                    "then": {"properties": {"reason_code": {"type": "string"}}},
                },
            ]
        },
    )
    claim: SafeId
    status: Literal["exercised", "configured_only", "not_tested", "unknown"]
    reason_code: DiagnosticCode | None
    evidence_refs: list[EventEvidenceReference] = Field(max_length=64)

    @model_validator(mode="after")
    def _coverage_evidence_is_well_formed(self) -> CoverageResult:
        if self.status in {"not_tested", "unknown"} and not self.reason_code:
            raise ValueError("not-tested and unknown coverage require a reason code")
        if self.status == "exercised" and not self.evidence_refs:
            raise ValueError("exercised coverage requires evidence")
        return self


class ResultArtifact(StrictModel):
    kind: SafeId
    path: ArtifactPath
    media_type: MediaType
    digest: Digest


class Diagnostic(StrictModel):
    code: DiagnosticCode
    stage: Literal[
        "configuration",
        "profile",
        "readiness",
        "admission",
        "driver",
        "registry",
        "delivery",
        "evaluation",
        "cleanup",
        "artifacts",
        "town",
    ]
    severity: Literal["warning", "error"]
    summary: SafeText512
    next: SafeText512 | None


class ToolMetadata(StrictModel):
    name: SafeText256
    version: SafeText256
    commit: SafeText256 | None


class ResultTarget(StrictModel):
    kind: Literal["agent"]
    label: SafeText128
    attribution: Literal["self_asserted_loopback_adapter_instance"]


class ResultDriver(StrictModel):
    contract: Literal["town-agent-driver/1"]
    kind: Literal["loopback-http"]
    adapter_instance_id: AdapterInstanceId | None
    endpoint_origin: SafeText256

    @model_validator(mode="after")
    def _loopback_origin(self) -> ResultDriver:
        parsed = urlsplit(self.endpoint_origin)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("endpoint_origin must be a literal loopback HTTP origin")
        return self


class Execution(StrictModel):
    status: Literal["completed", "incomplete", "error"]
    started_at: UtcRfc3339
    finished_at: UtcRfc3339
    duration_ms: int = Field(ge=0)
    scenario: SafeId
    seed: int = Field(ge=0)
    logical_time_end: int = Field(ge=0)
    decision_timeout_ms: int = Field(ge=0)


class Evaluation(StrictModel):
    verdict: Literal["pass", "fail", "inconclusive", "not_evaluated"]
    checks: list[CheckResult] = Field(max_length=64)

    @model_validator(mode="after")
    def _checks_match_verdict(self) -> Evaluation:
        if self.verdict == "not_evaluated" and self.checks:
            raise ValueError("not_evaluated has no checks")
        if self.verdict != "not_evaluated" and not self.checks:
            raise ValueError("evaluated result requires checks")
        return self


class TestResult(StrictModel):
    """Profile-generic result structure; profile conformance requires a bound codec."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"execution": {"properties": {"status": {"const": "error"}}}}
                    },
                    "then": {
                        "properties": {
                            "evaluation": {
                                "properties": {
                                    "verdict": {"const": "not_evaluated"},
                                    "checks": {"maxItems": 0},
                                }
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "execution": {"properties": {"status": {"const": "incomplete"}}}
                        }
                    },
                    "then": {
                        "properties": {
                            "evaluation": {
                                "properties": {
                                    "verdict": {"const": "inconclusive"},
                                    "checks": {
                                        "contains": {
                                            "properties": {
                                                "required": {"const": True},
                                                "status": {
                                                    "enum": ["not_tested", "inconclusive", "error"]
                                                },
                                            }
                                        }
                                    },
                                }
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "execution": {"properties": {"status": {"const": "completed"}}}
                        }
                    },
                    "then": {
                        "properties": {
                            "evaluation": {"properties": {"verdict": {"enum": ["pass", "fail"]}}}
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "execution": {"properties": {"status": {"const": "completed"}}},
                            "evaluation": {"properties": {"verdict": {"const": "pass"}}},
                        }
                    },
                    "then": {
                        "properties": {
                            "evaluation": {
                                "properties": {
                                    "checks": {
                                        "minItems": 1,
                                        "contains": {"properties": {"required": {"const": True}}},
                                        "items": {
                                            "if": {"properties": {"required": {"const": True}}},
                                            "then": {"properties": {"status": {"const": "pass"}}},
                                        },
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "execution": {"properties": {"status": {"const": "completed"}}},
                            "evaluation": {"properties": {"verdict": {"const": "fail"}}},
                        }
                    },
                    "then": {
                        "properties": {
                            "evaluation": {
                                "properties": {
                                    "checks": {
                                        "contains": {
                                            "properties": {
                                                "required": {"const": True},
                                                "status": {"const": "fail"},
                                            }
                                        },
                                        "items": {
                                            "if": {"properties": {"required": {"const": True}}},
                                            "then": {
                                                "properties": {
                                                    "status": {
                                                        "enum": ["pass", "fail", "not_tested"]
                                                    }
                                                }
                                            },
                                        },
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
    )
    __test__ = False
    schema_version: Literal["town.test-result/1"]
    run_id: ULID
    tool: ToolMetadata
    target: ResultTarget
    driver: ResultDriver
    profile: ProfileReference
    execution: Execution
    evaluation: Evaluation
    coverage: list[CoverageResult] = Field(min_length=1, max_length=64)
    artifacts: list[ResultArtifact] = Field(max_length=16)
    diagnostics: list[Diagnostic] = Field(max_length=64)

    @model_validator(mode="after")
    def _result_state_is_consistent(self) -> TestResult:
        required = [check for check in self.evaluation.checks if check.required]
        required_statuses = {check.status for check in required}
        if self.execution.status == "error":
            if self.evaluation.verdict != "not_evaluated" or self.evaluation.checks:
                raise ValueError("error execution requires not_evaluated with no checks")
        elif self.execution.status == "incomplete":
            if self.evaluation.verdict != "inconclusive" or not required_statuses & {
                "not_tested",
                "inconclusive",
                "error",
            }:
                raise ValueError("incomplete execution requires an inconclusive required check")
        elif self.evaluation.verdict == "pass":
            if not required or required_statuses != {"pass"}:
                raise ValueError("completed pass requires every required check to pass")
        elif self.evaluation.verdict == "fail":
            if "fail" not in required_statuses or required_statuses & {"inconclusive", "error"}:
                raise ValueError(
                    "completed fail requires one failure and no inconclusive or error checks"
                )
        else:
            raise ValueError("completed execution requires pass or fail")
        return self


class ObservationBase[ObserverT](StrictModel):
    """Generic top-level observation fields shared across profile evidence codecs."""

    schema_version: Literal["town.test-observation/1"]
    seq: int = Field(ge=1)
    event_id: ULID
    run_id: ULID
    logical_time: float = Field(ge=0)
    observed_at: UtcRfc3339
    duration_ms: int | None = Field(ge=0)
    observer: ObserverT
    subject_participant_id: SafeId
    message_id: SafeId | None
    correlation_id: SafeId | None
    request_digest: Digest | None
    response_digest: Digest | None

    @model_validator(mode="after")
    def _finite_logical_time(self) -> ObservationBase[ObserverT]:
        if not math.isfinite(self.logical_time):
            raise ValueError("logical_time must be finite")
        return self


class TestObservationEnvelope[ObservationT: StrictModel](RootModel[ObservationT]):
    """Generic closed observation envelope parameterized by profile evidence variants."""

    __test__ = False
    model_config = ConfigDict(strict=True)
