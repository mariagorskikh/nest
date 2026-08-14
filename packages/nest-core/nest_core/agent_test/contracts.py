# SPDX-License-Identifier: Apache-2.0
"""Generic public contracts and schema-visible scalar constraints for agent tests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
)

_ULID_RE = re.compile(r"[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_PROFILE_ID_RE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z")
_ADAPTER_INSTANCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_DIAGNOSTIC_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_RFC3339_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_SAFE_TEXT_PATTERN = r"^[^\s\x00-\x1f\x7f](?:[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f])?$"
_MEDIA_TYPE_PATTERN = r"^[!-.0-~](?:[ -.0-~]*[!-.0-~])?/[!-.0-~](?:[ -.0-~]*[!-.0-~])?$"
_NO_ASCII_CONTROLS_SCHEMA = {"not": {"pattern": r"[\u0000-\u001f\u007f]"}}


def _ulid(value: str) -> str:
    if not _ULID_RE.fullmatch(value):
        raise ValueError("must be a 26-character Crockford ULID")
    return value


def _digest(value: str) -> str:
    if not _DIGEST_RE.fullmatch(value):
        raise ValueError("must be a lowercase sha256 digest")
    return value


def _safe_id(value: str) -> str:
    if not _SAFE_ID_RE.fullmatch(value):
        raise ValueError("must be a 1..64 character ASCII safe ID")
    return value


def _profile_id(value: str) -> str:
    if len(value) > 128 or not _PROFILE_ID_RE.fullmatch(value):
        raise ValueError("must be a 1..128 character slash-separated ASCII profile ID")
    return value


def _adapter_instance_id(value: str) -> str:
    if not _ADAPTER_INSTANCE_ID_RE.fullmatch(value):
        raise ValueError("must be a 1..256 character ASCII adapter instance ID")
    return value


def _safe_text(value: str, maximum: int) -> str:
    if value != value.strip() or not value:
        raise ValueError("must be nonempty and trimmed")
    if len(value) > maximum:
        raise ValueError(f"must be at most {maximum} Unicode code points")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("must not contain ASCII control characters")
    return value


def _safe_text_128(value: str) -> str:
    return _safe_text(value, 128)


def _safe_text_256(value: str) -> str:
    return _safe_text(value, 256)


def _safe_text_512(value: str) -> str:
    return _safe_text(value, 512)


def _safe_text_4096(value: str) -> str:
    return _safe_text(value, 4096)


def _diagnostic_code(value: str) -> str:
    if not _DIAGNOSTIC_CODE_RE.fullmatch(value):
        raise ValueError("must be a diagnostic code")
    return value


def _media_type(value: str) -> str:
    if value.count("/") != 1:
        raise ValueError("must contain exactly one slash")
    return _safe_text(value, 128)


def _event_evidence_reference(value: str) -> str:
    if len(value) > 512 or not re.fullmatch(r"trace\.jsonl#seq=[1-9][0-9]*", value):
        raise ValueError("must be a bounded trace.jsonl#seq=<positive-integer> event reference")
    return value


def _artifact_path(value: str) -> str:
    if not value or len(value) > 240 or "#" in value or value.startswith("/") or "\\" in value:
        raise ValueError("must be a bounded nonempty relative POSIX artifact path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("artifact path must not contain control characters")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("artifact path must not contain empty, dot, or dot-dot components")
    return value


def _utc_rfc3339(value: str) -> str:
    if not _RFC3339_UTC_RE.fullmatch(value):
        raise ValueError("must be a UTC RFC 3339 timestamp ending in Z")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("must be a valid UTC RFC 3339 timestamp") from exc
    return value


ULID = Annotated[
    str,
    StringConstraints(min_length=26, max_length=26, pattern=r"^[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$"),
    AfterValidator(_ulid),
]
Digest = Annotated[
    str,
    StringConstraints(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$"),
    AfterValidator(_digest),
]
SafeId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]{1,64}$"),
    AfterValidator(_safe_id),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": r"^[A-Za-z0-9._-]{1,64}$",
            "not": {"pattern": r"[\r\n]"},
        }
    ),
]
ProfileId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$",
    ),
    AfterValidator(_profile_id),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$",
            "not": {"pattern": r"[\r\n]"},
        }
    ),
]
VersionId = SafeId
AdapterInstanceId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$",
    ),
    AfterValidator(_adapter_instance_id),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$",
            "not": {"pattern": r"[\r\n]"},
        }
    ),
]


def _safe_text_schema(maximum: int) -> dict[str, object]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": maximum,
        "pattern": _SAFE_TEXT_PATTERN,
        **_NO_ASCII_CONTROLS_SCHEMA,
    }


SafeText128 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=_SAFE_TEXT_PATTERN),
    AfterValidator(_safe_text_128),
    WithJsonSchema(_safe_text_schema(128)),
]
SafeText256 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=256, pattern=_SAFE_TEXT_PATTERN),
    AfterValidator(_safe_text_256),
    WithJsonSchema(_safe_text_schema(256)),
]
SafeText512 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512, pattern=_SAFE_TEXT_PATTERN),
    AfterValidator(_safe_text_512),
    WithJsonSchema(_safe_text_schema(512)),
]
SafeText4096 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096, pattern=_SAFE_TEXT_PATTERN),
    AfterValidator(_safe_text_4096),
    WithJsonSchema(_safe_text_schema(4096)),
]
DiagnosticCode = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]{0,63}$"),
    AfterValidator(_diagnostic_code),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": r"^[A-Z][A-Z0-9_]{0,63}$",
            "not": {"pattern": r"[\r\n]"},
        }
    ),
]
EventEvidenceReference = Annotated[
    str,
    StringConstraints(min_length=17, max_length=512, pattern=r"^trace\.jsonl#seq=[1-9][0-9]*$"),
    AfterValidator(_event_evidence_reference),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 17,
            "maxLength": 512,
            "pattern": r"^trace\.jsonl#seq=[1-9][0-9]*$",
            "not": {"pattern": r"[\r\n]"},
        }
    ),
]
ArtifactPath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=240),
    AfterValidator(_artifact_path),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 240,
            "pattern": (
                r"^(?!/)(?!.*\\)(?!.*//)(?!.*[/]$)"
                r"(?!.*(?:^|/)(?:\.|\.\.)(?:/|$))[^\x00-\x1f\x7f#]+$"
            ),
        }
    ),
]
MediaType = Annotated[
    str,
    StringConstraints(min_length=3, max_length=128, pattern=_MEDIA_TYPE_PATTERN),
    AfterValidator(_media_type),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 3,
            "maxLength": 128,
            "pattern": _MEDIA_TYPE_PATTERN,
            "not": {"pattern": r"[\r\n]"},
        }
    ),
]
UtcRfc3339 = Annotated[
    str,
    StringConstraints(
        min_length=20,
        max_length=64,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$",
    ),
    AfterValidator(_utc_rfc3339),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 20,
            "maxLength": 64,
            "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$",
            "not": {"pattern": r"[\r\n]"},
        }
    ),
]


class StrictModel(BaseModel):
    """Base model that rejects coercion and unknown contract fields."""

    __test__ = False
    model_config = ConfigDict(extra="forbid", strict=True)


class ProfileReference(StrictModel):
    """Generic immutable identity for exact profile bytes."""

    id: ProfileId
    version: VersionId
    digest: Digest


class Participant(StrictModel):
    """Generic driver participant identity and role."""

    id: SafeId
    role: SafeId


class DriverObservationBase[ObservationKindT, AllowedIntentsT](StrictModel):
    """Generic observation fields shared by every profile-defined variant."""

    kind: ObservationKindT
    logical_time: int = Field(ge=0)
    allowed_intents: AllowedIntentsT


class DriverIntentBase[IntentKindT](StrictModel):
    """Generic discriminator shared by every profile-defined intent variant."""

    kind: IntentKindT


class DriverRequestEnvelope[
    ParticipantT: StrictModel,
    ProfileReferenceT: StrictModel,
    ObservationT: StrictModel,
](StrictModel):
    """Closed generic request envelope parameterized by a strict profile observation."""

    schema_version: Literal["town-agent-driver/1"]
    run_id: ULID
    event_id: ULID
    sequence: int = Field(ge=0)
    participant: ParticipantT
    profile: ProfileReferenceT
    observation: ObservationT


class DriverResponseEnvelope[IntentT: StrictModel](StrictModel):
    """Closed generic response envelope parameterized by a strict profile intent."""

    schema_version: Literal["town-agent-driver/1"]
    run_id: ULID
    event_id: ULID
    sequence: int = Field(ge=0)
    adapter_instance_id: AdapterInstanceId
    request_digest: Digest
    intent: IntentT


class TestProfileEnvelope[
    ProfileIdT,
    ProfileVersionT,
    SubjectKindT,
    ScenarioT: StrictModel,
    DriverProfileT: StrictModel,
    FixtureT: StrictModel,
    EvaluatorT: StrictModel,
    CoverageT: StrictModel,
](StrictModel):
    """Closed generic Test Profile envelope with profile-defined strict sections."""

    __test__ = False
    schema_version: Literal["town.test-profile/1"]
    id: ProfileIdT
    version: ProfileVersionT
    subject_kind: SubjectKindT
    scenario: ScenarioT
    driver: DriverProfileT
    fixture: FixtureT
    evaluator: EvaluatorT
    coverage: CoverageT


class ReadyLimits(StrictModel):
    max_active_runs: int = Field(gt=0)
    max_request_bytes: int = Field(gt=0)
    max_response_bytes: int = Field(gt=0)


class DriverReady(StrictModel):
    schema_version: Literal["town-agent-driver-ready/1"]
    adapter_instance_id: AdapterInstanceId
    contracts: list[Literal["town-agent-driver/1"]] = Field(min_length=1)
    profiles: list[ProfileReference] = Field(min_length=1, max_length=64)
    accepting_runs: bool
    limits: ReadyLimits


class EffectiveDriverLimits(StrictModel):
    """Profile-and-adapter limits enforced by a transport implementation."""

    max_request_bytes: int = Field(gt=0)
    max_response_bytes: int = Field(gt=0)


class DriverReadiness(StrictModel):
    """Validated readiness plus the effective local enforcement limits."""

    ready: DriverReady
    effective_limits: EffectiveDriverLimits


DriverErrorCode = Literal[
    "AUTHENTICATION_FAILED",
    "RUN_BUSY",
    "EVENT_CONFLICT",
    "OUT_OF_ORDER",
    "BODY_TOO_LARGE",
    "UNSUPPORTED_CONTRACT",
    "UNSUPPORTED_PROFILE",
    "SCHEMA_INVALID",
    "ADAPTER_INTERNAL",
]


class DriverErrorDetail(StrictModel):
    code: DriverErrorCode
    retryable: bool
    message: SafeText512


class DriverError(StrictModel):
    schema_version: Literal["town-agent-driver-error/1"]
    adapter_instance_id: AdapterInstanceId | None
    run_id: ULID | None
    event_id: ULID | None
    sequence: int | None = Field(ge=0)
    request_digest: Digest | None
    error: DriverErrorDetail


@dataclass(frozen=True, slots=True)
class ProfileCodec:
    """One explicit profile's strict document, request, and response model family."""

    profile_id: str
    profile_version: str
    profile_digest: str
    profile_model: type[StrictModel]
    request_model: type[StrictModel]
    response_model: type[StrictModel]
    observation_model: type[BaseModel]
    result_model: type[StrictModel]

    def __post_init__(self) -> None:
        _profile_id(self.profile_id)
        _safe_id(self.profile_version)
        _digest(self.profile_digest)
