# SPDX-License-Identifier: Apache-2.0
"""Generation 1 capability-fulfillment Test Profile payloads and driver codec.

Generation 1 is the first frozen agent-test contract/profile generation, not a
Town or nest-core 1.0 release.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .capability_evidence import CapabilityTestObservation
from .contracts import (
    DriverIntentBase,
    DriverObservationBase,
    DriverRequestEnvelope,
    DriverResponseEnvelope,
    ProfileCodec,
    SafeId,
    SafeText4096,
    StrictModel,
    TestProfileEnvelope,
)
from .evidence import TestResult

CAPABILITY_PROFILE_ID = "nanda/agent/capability-fulfillment"
CAPABILITY_PROFILE_VERSION = "1"
CAPABILITY_PROFILE_DIGEST = (
    "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"
)
CAPABILITY_REQUIRED_CHECKS = (
    "driver.contract",
    "registry.provider-registered",
    "registry.provider-discovered",
    "delivery.request-routed",
    "capability.synthetic-request-fulfilled",
)
CAPABILITY_EXERCISED_CLAIMS = (
    "town.agent-driver.loopback",
    "nanda.registry.run-local-discovery",
    "town.simulator.in-memory-routing",
    "nanda.agent.synthetic-capability-fulfillment",
)
CAPABILITY_NOT_TESTED_CLAIMS = (
    "nanda.index.persistent-discovery",
    "nanda.comms.real-network-delivery",
    "nanda.identity",
    "nanda.authorization",
    "nanda.trust",
    "nanda.payments",
    "nanda.negotiation",
    "agent.safety",
    "agent.long-term-reliability",
)


class ProfileScenario(StrictModel):
    id: Literal["capability_fulfillment"]
    seed: Literal[7]
    subject_participant_id: Literal["provider-0"]
    reference_participant_id: Literal["requester-0"]
    registry_plugin: Literal["in_memory"]
    lookup_delay_ticks: Literal[0]


class ProfileDriver(StrictModel):
    contract: Literal["town-agent-driver/1"]
    required_evaluation_events: list[Literal["start", "message"]] = Field(min_length=1)
    best_effort_cleanup_events: list[Literal["stop"]] = Field(min_length=1)
    decision_timeout_ms: Literal[60000]
    max_http_body_bytes: Literal[65536]
    max_message_bytes: Literal[4096]


class TextFixture[TextT](StrictModel):
    media_type: Literal["text/plain; charset=utf-8"]
    text: TextT


class ProfileFixture(StrictModel):
    capability: Literal["sell"]
    request: TextFixture[Literal["buy:widget:2"]]
    expected_response: TextFixture[Literal["sold:widget:2"]]

    @model_validator(mode="after")
    def _is_expected_vector(self) -> ProfileFixture:
        if self.request.text != "buy:widget:2" or self.expected_response.text != "sold:widget:2":
            raise ValueError("must use the frozen capability-fulfillment vectors")
        return self


class ProfileEvaluator(StrictModel):
    id: Literal["nanda.agent.capability-fulfillment"]
    version: Literal["1"]
    required_checks: list[SafeId] = Field(min_length=1, max_length=64)


class ProfileCoverage(StrictModel):
    exercised: list[SafeId] = Field(min_length=1, max_length=64)
    not_tested: list[SafeId] = Field(min_length=1, max_length=64)


class TestProfile(
    TestProfileEnvelope[
        Literal["nanda/agent/capability-fulfillment"],
        Literal["1"],
        Literal["agent"],
        ProfileScenario,
        ProfileDriver,
        ProfileFixture,
        ProfileEvaluator,
        ProfileCoverage,
    ]
):
    """The one shipped Generation 1 capability-fulfillment Test Profile."""

    __test__ = False


class _CapabilityTestResult(TestResult):
    """Capability-owned semantic policy reached only through its bound codec."""

    __test__ = False

    @model_validator(mode="after")
    def _matches_capability_profile(self) -> _CapabilityTestResult:
        if (
            self.profile.id,
            self.profile.version,
            self.profile.digest,
        ) != (
            CAPABILITY_PROFILE_ID,
            CAPABILITY_PROFILE_VERSION,
            CAPABILITY_PROFILE_DIGEST,
        ):
            raise ValueError("result profile does not match the capability codec")
        if self.execution.scenario != "capability_fulfillment":
            raise ValueError("result scenario does not match the capability profile")
        if self.execution.seed != 7:
            raise ValueError("result seed does not match the capability profile")
        if self.execution.decision_timeout_ms != 60000:
            raise ValueError("result timeout does not match the capability profile")

        check_ids = [check.id for check in self.evaluation.checks]
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("result has duplicate check IDs")
        if self.execution.status != "error":
            if set(check_ids) != set(CAPABILITY_REQUIRED_CHECKS):
                raise ValueError("result checks do not match the capability profile")
            if any(not check.required for check in self.evaluation.checks):
                raise ValueError("result required flags do not match the capability profile")

        coverage_claims = [coverage.claim for coverage in self.coverage]
        expected_coverage = {
            *CAPABILITY_EXERCISED_CLAIMS,
            *CAPABILITY_NOT_TESTED_CLAIMS,
        }
        if (
            len(coverage_claims) != len(set(coverage_claims))
            or set(coverage_claims) != expected_coverage
        ):
            raise ValueError("result coverage does not match the capability profile")
        coverage_by_claim = {coverage.claim: coverage for coverage in self.coverage}
        for claim in CAPABILITY_NOT_TESTED_CLAIMS:
            coverage = coverage_by_claim[claim]
            if (
                coverage.status != "not_tested"
                or coverage.reason_code != "OUT_OF_PROFILE"
                or coverage.evidence_refs
            ):
                raise ValueError("result coverage overstates an out-of-profile claim")
        for claim in CAPABILITY_EXERCISED_CLAIMS:
            coverage = coverage_by_claim[claim]
            is_exercised = (
                coverage.status == "exercised"
                and coverage.reason_code is None
                and bool(coverage.evidence_refs)
            )
            is_unknown = (
                coverage.status == "unknown"
                and coverage.reason_code == "NOT_OBSERVED"
                and not coverage.evidence_refs
            )
            if not is_exercised and not is_unknown:
                raise ValueError("result coverage status does not match terminal evidence")
        return self


class CapabilityProfileReference(StrictModel):
    id: Literal["nanda/agent/capability-fulfillment"]
    version: Literal["1"]
    digest: Literal["sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"]


class CapabilityParticipant(StrictModel):
    """Exact capability-profile participant selected by the shipped scenario."""

    id: Literal["provider-0"]
    role: Literal["provider"]


StartAllowedIntents = Annotated[
    list[Literal["declare_capability", "none"]],
    Field(
        min_length=2,
        max_length=2,
        json_schema_extra={"const": ["declare_capability", "none"]},
    ),
]


class StartDriverObservation(DriverObservationBase[Literal["start"], StartAllowedIntents]):
    @field_validator("allowed_intents")
    @classmethod
    def _exact_allowed_intents(cls, value: list[str]) -> list[str]:
        if value != ["declare_capability", "none"]:
            raise ValueError("start allowed_intents must use the frozen order")
        return value


class DriverMessage(StrictModel):
    id: SafeId
    sender_id: Literal["requester-0"]
    media_type: Literal["text/plain; charset=utf-8"]
    text: Literal["buy:widget:2"]


MessageAllowedIntents = Annotated[
    list[Literal["send_to_sender", "none"]],
    Field(
        min_length=2,
        max_length=2,
        json_schema_extra={"const": ["send_to_sender", "none"]},
    ),
]


class MessageDriverObservation(DriverObservationBase[Literal["message"], MessageAllowedIntents]):
    message: DriverMessage

    @field_validator("allowed_intents")
    @classmethod
    def _exact_allowed_intents(cls, value: list[str]) -> list[str]:
        if value != ["send_to_sender", "none"]:
            raise ValueError("message allowed_intents must use the frozen order")
        return value


StopAllowedIntents = Annotated[
    list[Literal["none"]],
    Field(
        min_length=1,
        max_length=1,
        json_schema_extra={"const": ["none"]},
    ),
]


class StopDriverObservation(DriverObservationBase[Literal["stop"], StopAllowedIntents]):
    reason: Literal["run_complete", "run_failed", "run_incomplete", "user_interrupted"]


DriverObservation = Annotated[
    StartDriverObservation | MessageDriverObservation | StopDriverObservation,
    Field(discriminator="kind"),
]


class DriverRequest(
    DriverRequestEnvelope[CapabilityParticipant, CapabilityProfileReference, DriverObservation]
):
    """Concrete capability request returned by the capability codec."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "x-town-semantic-validation": [
                "event sequence is valid for the capability observation kind",
            ]
        },
    )

    @model_validator(mode="after")
    def _sequence_matches_observation(self) -> DriverRequest:
        kind = self.observation.kind
        if kind == "start" and self.sequence != 0:
            raise ValueError("start observation requires sequence zero")
        if kind == "message" and self.sequence != 1:
            raise ValueError("message observation requires sequence one")
        if kind == "stop" and self.sequence not in {1, 2}:
            raise ValueError("stop observation requires sequence one or two")
        if (
            isinstance(self.observation, StopDriverObservation)
            and self.sequence == 1
            and self.observation.reason == "run_complete"
        ):
            raise ValueError("sequence-one stop cannot report run_complete")
        return self


class DeclareCapabilityIntent(DriverIntentBase[Literal["declare_capability"]]):
    capabilities: list[Literal["sell"]] = Field(
        min_length=1,
        max_length=1,
        json_schema_extra={"const": ["sell"]},
    )


class SendToSenderIntent(DriverIntentBase[Literal["send_to_sender"]]):
    media_type: Literal["text/plain; charset=utf-8"]
    text: SafeText4096

    @field_validator("text")
    @classmethod
    def _profile_message_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 4096:
            raise ValueError("text exceeds the profile UTF-8 byte limit")
        return value


class NoneIntent(DriverIntentBase[Literal["none"]]):
    pass


DriverIntent = Annotated[
    DeclareCapabilityIntent | SendToSenderIntent | NoneIntent,
    Field(discriminator="kind"),
]


class DriverResponse(DriverResponseEnvelope[DriverIntent]):
    """Concrete capability response returned by the capability codec."""


CAPABILITY_PROFILE_CODEC = ProfileCodec(
    profile_id=CAPABILITY_PROFILE_ID,
    profile_version=CAPABILITY_PROFILE_VERSION,
    profile_digest=CAPABILITY_PROFILE_DIGEST,
    profile_model=TestProfile,
    request_model=DriverRequest,
    response_model=DriverResponse,
    observation_model=CapabilityTestObservation,
    result_model=_CapabilityTestResult,
)
