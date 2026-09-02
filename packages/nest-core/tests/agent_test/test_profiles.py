# SPDX-License-Identifier: Apache-2.0
"""Immutable built-in profile tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError
from importlib import resources
from pathlib import Path
from typing import Any, cast

import jsonschema
import nest_core.agent_test as agent_test
import pytest
from nest_core.agent_test import profiles
from nest_core.agent_test.ids import new_ulid
from nest_core.agent_test.models import DriverRequest, TestProfile, TestResult
from nest_core.agent_test.profiles import (
    load_profile,
    profile_bytes,
    profile_digest,
    resolve_profile,
)
from pydantic import ValidationError


def test_alias_and_exact_reference_resolve_to_immutable_packaged_bytes() -> None:
    """Friendly and pinned references identify exactly the same profile bytes."""
    alias = resolve_profile("capability-fulfillment")
    exact = resolve_profile("nanda/agent/capability-fulfillment@1")
    assert alias == exact == profile_bytes("capability-fulfillment")
    assert profile_digest("capability-fulfillment") == "sha256:" + hashlib.sha256(alias).hexdigest()
    assert alias.endswith(b"\n")
    assert load_profile("capability-fulfillment").schema_version == "town.test-profile/1"


def test_resolved_profile_binds_parsed_document_to_exact_reference() -> None:
    """Runtime authority comes from one immutable resolution result."""
    packaged = resolve_profile("capability-fulfillment")
    resolved = profiles.resolve_test_profile("capability-fulfillment")

    assert resolved.document == TestProfile.model_validate_json(packaged)
    assert resolved.reference.model_dump(mode="json") == {
        "id": "nanda/agent/capability-fulfillment",
        "version": "1",
        "digest": "sha256:" + hashlib.sha256(packaged).hexdigest(),
    }


def test_resolved_profile_snapshots_packaged_bytes_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Document and digest are derived from one immutable resolution-time byte snapshot."""
    packaged = resolve_profile("capability-fulfillment")
    reads = 0

    class _ChangingResource:
        def joinpath(self, _name: str) -> _ChangingResource:
            return self

        def read_bytes(self) -> bytes:
            nonlocal reads
            reads += 1
            return packaged if reads == 1 else b"{}"

    def changing_files(_package: object) -> _ChangingResource:
        return _ChangingResource()

    monkeypatch.setattr(profiles.resources, "files", changing_files)

    resolved = profiles.resolve_test_profile("capability-fulfillment")
    first_document = resolved.document
    first_reference = resolved.reference

    assert reads == 1
    assert resolved.document == first_document
    assert resolved.reference == first_reference
    assert reads == 1


def test_profile_codec_registry_is_explicit_extensible_and_fail_closed() -> None:
    """A second profile opts in explicitly while the default rejects it as unknown."""
    from typing import Annotated, Literal

    from nest_core.agent_test.capability_evidence import RunAdmittedObservation
    from nest_core.agent_test.capability_profile import CAPABILITY_PROFILE_CODEC
    from nest_core.agent_test.contracts import (
        DriverIntentBase,
        DriverObservationBase,
        DriverRequestEnvelope,
        DriverResponseEnvelope,
        StrictModel,
        TestProfileEnvelope,
    )
    from nest_core.agent_test.evidence import ObservationBase, TestObservationEnvelope
    from nest_core.agent_test.profile_codecs import ProfileCodec, ProfileCodecRegistry
    from pydantic import Field

    class _PingReference(StrictModel):
        id: Literal["example/agent/ping"]
        version: Literal["1"]
        digest: Literal["sha256:1111111111111111111111111111111111111111111111111111111111111111"]

    class _PingParticipant(StrictModel):
        id: Literal["worker-2"]
        role: Literal["auditor"]

    ping_allowed_intents = Annotated[
        list[Literal["pong"]],
        Field(min_length=1, max_length=1, json_schema_extra={"const": ["pong"]}),
    ]

    class _PingObservation(DriverObservationBase[Literal["ping"], ping_allowed_intents]):
        text: Literal["ping"]

    class _PongIntent(DriverIntentBase[Literal["pong"]]):
        text: Literal["pong"]

    class _SharedNoneIntent(DriverIntentBase[Literal["none"]]):
        pass

    ping_intent = Annotated[
        _PongIntent | _SharedNoneIntent,
        Field(discriminator="kind"),
    ]

    class _PingScenario(StrictModel):
        id: Literal["ping_roundtrip"]

    class _PingSection(StrictModel):
        kind: Literal["ping"]

    class _PingProfile(
        TestProfileEnvelope[
            Literal["example/agent/ping"],
            Literal["1"],
            Literal["agent"],
            _PingScenario,
            _PingSection,
            _PingSection,
            _PingSection,
            _PingSection,
        ]
    ):
        pass

    class _PingRequest(DriverRequestEnvelope[_PingParticipant, _PingReference, _PingObservation]):
        pass

    class _PingResponse(
        DriverResponseEnvelope[ping_intent]  # pyright: ignore[reportInvalidTypeArguments]
    ):
        pass

    class _PingEvidenceData(StrictModel):
        text: Literal["pong"]

    class _PingEvidence(ObservationBase[Literal["example.ping-evaluator"]]):
        kind: Literal["test.ping"]
        data: _PingEvidenceData

    ping_evidence = Annotated[
        _PingEvidence | RunAdmittedObservation,
        Field(discriminator="kind"),
    ]

    class _PingTestObservation(
        TestObservationEnvelope[
            ping_evidence  # pyright: ignore[reportInvalidTypeArguments]
        ]
    ):
        pass

    ping_codec = ProfileCodec(
        profile_id="example/agent/ping",
        profile_version="1",
        profile_digest="sha256:" + "1" * 64,
        profile_model=_PingProfile,
        request_model=_PingRequest,
        response_model=_PingResponse,
        observation_model=_PingTestObservation,
        result_model=TestResult,
    )
    default = ProfileCodecRegistry((CAPABILITY_PROFILE_CODEC,))
    extended = default.with_codec(ping_codec)
    request_data = {
        "schema_version": "town-agent-driver/1",
        "run_id": "01K00000000000000000000001",
        "event_id": "01K00000000000000000000002",
        "sequence": 0,
        "participant": {"id": "worker-2", "role": "auditor"},
        "profile": {
            "id": "example/agent/ping",
            "version": "1",
            "digest": "sha256:" + "1" * 64,
        },
        "observation": {
            "kind": "ping",
            "logical_time": 0,
            "allowed_intents": ["pong"],
            "text": "ping",
        },
    }
    profile_data = {
        "schema_version": "town.test-profile/1",
        "id": "example/agent/ping",
        "version": "1",
        "subject_kind": "agent",
        "scenario": {"id": "ping_roundtrip"},
        "driver": {"kind": "ping"},
        "fixture": {"kind": "ping"},
        "evaluator": {"kind": "ping"},
        "coverage": {"kind": "ping"},
    }
    observation_data = {
        "schema_version": "town.test-observation/1",
        "seq": 1,
        "event_id": "01K00000000000000000000003",
        "run_id": "01K00000000000000000000001",
        "kind": "test.ping",
        "logical_time": 0.0,
        "observed_at": "2026-08-13T12:00:00Z",
        "duration_ms": None,
        "observer": "example.ping-evaluator",
        "subject_participant_id": "worker-2",
        "message_id": None,
        "correlation_id": None,
        "request_digest": None,
        "response_digest": None,
        "data": {"text": "pong"},
    }
    shared_observation_data = {
        **observation_data,
        "kind": "test.driver.run_admitted",
        "observer": "town.driven-agent",
        "data": {
            "adapter_instance_id": "adapter:dev",
            "profile_digest": "sha256:" + "1" * 64,
            "driver_sequence": 0,
            "intent_kind": "none",
        },
    }
    shared_response_data = {
        "schema_version": "town-agent-driver/1",
        "run_id": "01K00000000000000000000001",
        "event_id": "01K00000000000000000000002",
        "sequence": 0,
        "adapter_instance_id": "adapter:dev",
        "request_digest": "sha256:" + "0" * 64,
        "intent": {"kind": "none"},
    }
    result_data = json.loads((Path(__file__).parent / "fixtures" / "result-pass.json").read_text())
    result_data["profile"] = request_data["profile"]
    result_data["execution"]["scenario"] = "ping_roundtrip"

    with pytest.raises(KeyError, match="unknown Test Profile codec"):
        default.validate_request(request_data)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(request_data, default.driver_request_schema())
    validated = extended.validate_request(request_data)
    validated_profile = extended.validate_profile(profile_data)
    ping_binding = extended.bind(_PingReference.model_validate(request_data["profile"]))
    validated_observation = ping_binding.validate_observation(observation_data)

    assert isinstance(validated, _PingRequest)
    assert isinstance(validated_profile, _PingProfile)
    assert isinstance(validated_observation, _PingTestObservation)
    assert isinstance(ping_binding.validate_result(result_data), TestResult)
    assert validated.participant.id == "worker-2"
    assert default is not extended
    jsonschema.validate(request_data, extended.driver_request_schema())
    jsonschema.validate(profile_data, extended.test_profile_schema())
    jsonschema.validate(observation_data, extended.test_observation_schema())
    jsonschema.validate(shared_response_data, extended.driver_response_schema())
    jsonschema.validate(shared_observation_data, extended.test_observation_schema())
    assert isinstance(
        ping_binding.validate_response(shared_response_data),
        _PingResponse,
    )
    assert isinstance(
        ping_binding.validate_observation(shared_observation_data),
        _PingTestObservation,
    )
    jsonschema.validate(
        json.loads(profile_bytes("capability-fulfillment")), extended.test_profile_schema()
    )
    capability_binding = extended.bind(
        profiles.resolve_test_profile("capability-fulfillment").reference
    )
    with pytest.raises(ValidationError):
        capability_binding.validate_observation(observation_data)
    with pytest.raises(ValueError, match="result profile context"):
        capability_binding.validate_result(result_data)
    with pytest.raises(ValueError, match="already registered"):
        extended.with_codec(ping_codec)
    with pytest.raises(KeyError, match="unknown Test Profile reference"):
        profiles.resolve_test_profile("example/agent/ping@1")


@pytest.mark.parametrize(
    "model_attribute",
    [
        "profile_model",
        "request_model",
        "response_model",
        "observation_model",
        "result_model",
    ],
)
def test_profile_codec_registry_rejects_non_strict_model_families(
    model_attribute: str,
) -> None:
    """A codec cannot silently discard attacker-controlled extension fields."""
    from dataclasses import replace

    from nest_core.agent_test.capability_profile import CAPABILITY_PROFILE_CODEC
    from nest_core.agent_test.profile_codecs import ProfileCodecRegistry
    from pydantic import BaseModel

    class _LooseContract(BaseModel):
        value: str

    assert _LooseContract.model_validate(
        {"value": "accepted", "attacker_extension": True}
    ).model_dump() == {"value": "accepted"}
    loose_codec = replace(
        CAPABILITY_PROFILE_CODEC,
        **cast("Any", {model_attribute: _LooseContract}),
    )

    with pytest.raises(TypeError, match=model_attribute):
        ProfileCodecRegistry((loose_codec,))


def test_profile_codec_registry_rejects_unconstrained_payload_models() -> None:
    """Strict wrappers cannot smuggle an unconstrained Any payload into a codec."""
    from dataclasses import replace

    from nest_core.agent_test.capability_profile import CAPABILITY_PROFILE_CODEC
    from nest_core.agent_test.contracts import StrictModel
    from nest_core.agent_test.profile_codecs import ProfileCodecRegistry
    from pydantic import ConfigDict, RootModel

    class _LooseRoot(RootModel[Any]):
        model_config = ConfigDict(strict=True)

    class _AnyField(StrictModel):
        payload: Any

    for model_attribute, model in (
        ("observation_model", _LooseRoot),
        ("response_model", _AnyField),
    ):
        loose_codec = replace(
            CAPABILITY_PROFILE_CODEC,
            **cast("Any", {model_attribute: model}),
        )
        with pytest.raises(TypeError, match=model_attribute):
            ProfileCodecRegistry((loose_codec,))


def _capability_result_vector() -> dict[str, Any]:
    result = json.loads((Path(__file__).parent / "fixtures" / "result-pass.json").read_text())
    profile = json.loads(profile_bytes("capability-fulfillment"))
    check_template = result["evaluation"]["checks"][0]
    result["evaluation"]["checks"] = [
        {**check_template, "id": check_id} for check_id in profile["evaluator"]["required_checks"]
    ]
    result["coverage"] = [
        {
            "claim": claim,
            "status": "exercised",
            "reason_code": None,
            "evidence_refs": ["trace.jsonl#seq=1"],
        }
        for claim in profile["coverage"]["exercised"]
    ] + [
        {
            "claim": claim,
            "status": "not_tested",
            "reason_code": "OUT_OF_PROFILE",
            "evidence_refs": [],
        }
        for claim in profile["coverage"]["not_tested"]
    ]
    return result


def test_bound_codec_validates_capability_result_policy_after_structural_parse() -> None:
    """Generic result structure alone never proves profile-owned result conformance."""
    resolved = profiles.resolve_test_profile("capability-fulfillment")
    data = _capability_result_vector()

    generic = TestResult.model_validate(data)
    validated = resolved.codec.validate_result(generic)

    assert validated.profile == resolved.reference
    incomplete = json.loads(json.dumps(data))
    incomplete["execution"]["status"] = "incomplete"
    incomplete["evaluation"]["verdict"] = "inconclusive"
    incomplete["evaluation"]["checks"][0]["status"] = "inconclusive"
    incomplete["evaluation"]["checks"][0]["evidence_refs"] = []
    assert resolved.codec.validate_result(incomplete).execution.status == "incomplete"

    mutations: list[tuple[str, dict[str, Any]]] = []
    wrong_profile_id = json.loads(json.dumps(data))
    wrong_profile_id["profile"]["id"] = "example/agent/ping"
    mutations.append(("profile", wrong_profile_id))
    wrong_profile_version = json.loads(json.dumps(data))
    wrong_profile_version["profile"]["version"] = "0.2"
    mutations.append(("profile", wrong_profile_version))
    wrong_profile = json.loads(json.dumps(data))
    wrong_profile["profile"]["digest"] = "sha256:" + "0" * 64
    mutations.append(("profile", wrong_profile))
    wrong_scenario = json.loads(json.dumps(data))
    wrong_scenario["execution"]["scenario"] = "ping_roundtrip"
    mutations.append(("scenario", wrong_scenario))
    wrong_seed = json.loads(json.dumps(data))
    wrong_seed["execution"]["seed"] = 8
    mutations.append(("seed", wrong_seed))
    wrong_timeout = json.loads(json.dumps(data))
    wrong_timeout["execution"]["decision_timeout_ms"] = 1
    mutations.append(("timeout", wrong_timeout))
    missing_check = json.loads(json.dumps(data))
    missing_check["evaluation"]["checks"].pop()
    mutations.append(("checks", missing_check))
    unknown_check = json.loads(json.dumps(data))
    unknown_check["evaluation"]["checks"][0]["id"] = "example.unknown"
    mutations.append(("checks", unknown_check))
    wrong_required = json.loads(json.dumps(data))
    wrong_required["evaluation"]["checks"][0]["required"] = False
    mutations.append(("required", wrong_required))
    duplicate_check = json.loads(json.dumps(data))
    duplicate_check["evaluation"]["checks"].append(duplicate_check["evaluation"]["checks"][0])
    mutations.append(("duplicate", duplicate_check))
    missing_coverage = json.loads(json.dumps(data))
    missing_coverage["coverage"].pop()
    mutations.append(("coverage", missing_coverage))
    unknown_coverage = json.loads(json.dumps(data))
    unknown_coverage["coverage"][0]["claim"] = "example.unknown"
    mutations.append(("coverage", unknown_coverage))
    duplicate_coverage = json.loads(json.dumps(data))
    duplicate_coverage["coverage"].append(duplicate_coverage["coverage"][0])
    mutations.append(("coverage", duplicate_coverage))
    overstated_coverage = json.loads(json.dumps(data))
    not_tested_claim = next(
        item for item in overstated_coverage["coverage"] if item["claim"] == "agent.safety"
    )
    not_tested_claim.update(
        status="exercised",
        reason_code=None,
        evidence_refs=["trace.jsonl#seq=1"],
    )
    mutations.append(("coverage", overstated_coverage))
    wrong_not_tested_reason = json.loads(json.dumps(data))
    next(item for item in wrong_not_tested_reason["coverage"] if item["claim"] == "agent.safety")[
        "reason_code"
    ] = "NOT_OBSERVED"
    mutations.append(("coverage", wrong_not_tested_reason))
    evidenced_not_tested = json.loads(json.dumps(data))
    next(item for item in evidenced_not_tested["coverage"] if item["claim"] == "agent.safety")[
        "evidence_refs"
    ] = ["trace.jsonl#seq=1"]
    mutations.append(("coverage", evidenced_not_tested))
    configured_exercised_scope = json.loads(json.dumps(data))
    configured_claim = next(
        item
        for item in configured_exercised_scope["coverage"]
        if item["claim"] == "town.agent-driver.loopback"
    )
    configured_claim.update(status="configured_only", evidence_refs=[])
    mutations.append(("coverage", configured_exercised_scope))
    wrong_unknown_reason = json.loads(json.dumps(data))
    unknown_claim = next(
        item
        for item in wrong_unknown_reason["coverage"]
        if item["claim"] == "town.agent-driver.loopback"
    )
    unknown_claim.update(
        status="unknown",
        reason_code="OUT_OF_PROFILE",
        evidence_refs=[],
    )
    mutations.append(("coverage", wrong_unknown_reason))

    for label, mutation in mutations:
        TestResult.model_validate(mutation)
        with pytest.raises((ValidationError, ValueError), match=label):
            resolved.codec.validate_result(mutation)

    for fixture_name in ("result-pass.json", "result-incomplete.json"):
        generic_golden = TestResult.model_validate(
            json.loads((Path(__file__).parent / "fixtures" / fixture_name).read_text())
        )
        with pytest.raises((ValidationError, ValueError), match="checks"):
            resolved.codec.validate_result(generic_golden)


def test_schema_definition_namespaces_are_injective_for_valid_profile_ids() -> None:
    """Distinct safe profile IDs cannot collide only when aggregate schemas are generated."""
    from typing import Annotated, Literal

    from nest_core.agent_test.capability_profile import CAPABILITY_PROFILE_CODEC
    from nest_core.agent_test.contracts import (
        DriverObservationBase,
        DriverRequestEnvelope,
        StrictModel,
        TestProfileEnvelope,
    )
    from nest_core.agent_test.profile_codecs import ProfileCodec, ProfileCodecRegistry
    from pydantic import Field

    class _CollisionParticipant(StrictModel):
        id: Literal["worker-0"]
        role: Literal["provider"]

    allowed_intents = Annotated[
        list[Literal["none"]],
        Field(min_length=1, max_length=1, json_schema_extra={"const": ["none"]}),
    ]

    class _CollisionObservation(DriverObservationBase[Literal["start"], allowed_intents]):
        pass

    class _DashReference(StrictModel):
        id: Literal["example/a-b"]
        version: Literal["1"]
        digest: Literal["sha256:2222222222222222222222222222222222222222222222222222222222222222"]

    class _UnderscoreReference(StrictModel):
        id: Literal["example/a_b"]
        version: Literal["1"]
        digest: Literal["sha256:3333333333333333333333333333333333333333333333333333333333333333"]

    class _DashRequest(
        DriverRequestEnvelope[_CollisionParticipant, _DashReference, _CollisionObservation]
    ):
        pass

    class _UnderscoreRequest(
        DriverRequestEnvelope[
            _CollisionParticipant,
            _UnderscoreReference,
            _CollisionObservation,
        ]
    ):
        pass

    class _CollisionSection(StrictModel):
        kind: Literal["collision"]

    class _DashProfile(
        TestProfileEnvelope[
            Literal["example/a-b"],
            Literal["1"],
            Literal["agent"],
            _CollisionSection,
            _CollisionSection,
            _CollisionSection,
            _CollisionSection,
            _CollisionSection,
        ]
    ):
        pass

    class _UnderscoreProfile(
        TestProfileEnvelope[
            Literal["example/a_b"],
            Literal["1"],
            Literal["agent"],
            _CollisionSection,
            _CollisionSection,
            _CollisionSection,
            _CollisionSection,
            _CollisionSection,
        ]
    ):
        pass

    codecs = (
        ProfileCodec(
            profile_id="example/a-b",
            profile_version="1",
            profile_digest="sha256:" + "2" * 64,
            profile_model=_DashProfile,
            request_model=_DashRequest,
            response_model=CAPABILITY_PROFILE_CODEC.response_model,
            observation_model=CAPABILITY_PROFILE_CODEC.observation_model,
            result_model=TestResult,
        ),
        ProfileCodec(
            profile_id="example/a_b",
            profile_version="1",
            profile_digest="sha256:" + "3" * 64,
            profile_model=_UnderscoreProfile,
            request_model=_UnderscoreRequest,
            response_model=CAPABILITY_PROFILE_CODEC.response_model,
            observation_model=CAPABILITY_PROFILE_CODEC.observation_model,
            result_model=TestResult,
        ),
    )
    registry = ProfileCodecRegistry(codecs)

    assert len(registry.driver_request_schema()["oneOf"]) == 2
    assert len(registry.test_profile_schema()["oneOf"]) == 2
    assert len(registry.driver_response_schema()["anyOf"]) == 2
    assert len(registry.test_observation_schema()["anyOf"]) == 2


def test_registered_request_requires_the_codec_canonical_profile_digest() -> None:
    """A shaped but incorrect digest cannot select the packaged profile codec."""
    from nest_core.agent_test.profile_codecs import DEFAULT_PROFILE_CODECS

    request = json.loads(
        (Path(__file__).parent / "fixtures" / "driver-start-request.json").read_text()
    )
    request["profile"]["digest"] = "sha256:" + "0" * 64

    with pytest.raises(ValueError, match="profile context changed"):
        DEFAULT_PROFILE_CODECS.validate_request(request)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(request, DEFAULT_PROFILE_CODECS.driver_request_schema())


def test_bound_profile_codec_cannot_be_swapped_between_events() -> None:
    """A readiness-selected codec rejects later requests with any other profile identity."""
    from nest_core.agent_test.profile_codecs import DEFAULT_PROFILE_CODECS

    resolved = profiles.resolve_test_profile("capability-fulfillment")
    binding = DEFAULT_PROFILE_CODECS.bind(resolved.reference)
    request = json.loads(
        (Path(__file__).parent / "fixtures" / "driver-start-request.json").read_text()
    )
    request["profile"]["id"] = "example/agent/ping"

    with pytest.raises(ValueError, match="profile context changed"):
        binding.validate_request(request)


def test_response_is_decoded_with_originating_request_codec() -> None:
    """A response valid for another profile is never trusted under the active binding."""
    from typing import Literal

    from nest_core.agent_test.capability_profile import CAPABILITY_PROFILE_CODEC
    from nest_core.agent_test.contracts import (
        DriverIntentBase,
        DriverResponseEnvelope,
        ProfileReference,
    )
    from nest_core.agent_test.profile_codecs import ProfileCodec, ProfileCodecRegistry

    class _PingIntent(DriverIntentBase[Literal["ping_result"]]):
        text: Literal["pong"]

    class _PingResponse(DriverResponseEnvelope[_PingIntent]):
        pass

    ping_codec = ProfileCodec(
        profile_id="example/agent/ping",
        profile_version="1",
        profile_digest="sha256:" + "1" * 64,
        profile_model=TestProfile,
        request_model=CAPABILITY_PROFILE_CODEC.request_model,
        response_model=_PingResponse,
        observation_model=CAPABILITY_PROFILE_CODEC.observation_model,
        result_model=TestResult,
    )
    registry = ProfileCodecRegistry((CAPABILITY_PROFILE_CODEC, ping_codec))
    capability = profiles.resolve_test_profile("capability-fulfillment").reference
    ping = ProfileReference(
        id="example/agent/ping",
        version="1",
        digest="sha256:" + "1" * 64,
    )
    response = {
        "schema_version": "town-agent-driver/1",
        "run_id": "01K00000000000000000000001",
        "event_id": "01K00000000000000000000002",
        "sequence": 0,
        "adapter_instance_id": "adapter:dev",
        "request_digest": "sha256:" + "0" * 64,
        "intent": {"kind": "ping_result", "text": "pong"},
    }

    jsonschema.validate(response, registry.driver_response_schema())
    assert isinstance(registry.bind(ping).validate_response(response), _PingResponse)
    with pytest.raises(ValidationError):
        registry.bind(capability).validate_response(response)


def test_resolved_profile_does_not_expose_mutable_subject_authority() -> None:
    """Mutating a returned document cannot change the packaged resolution."""
    resolved = profiles.resolve_test_profile("capability-fulfillment")
    returned_document = profiles.capability_profile_document(resolved)

    cast("Any", returned_document.scenario).subject_participant_id = "requester-0"

    assert (
        profiles.capability_profile_document(resolved).scenario.subject_participant_id
        == "provider-0"
    )


def test_resolved_profile_does_not_expose_mutable_reference() -> None:
    resolved = profiles.resolve_test_profile("capability-fulfillment")
    returned_reference = resolved.reference

    cast("Any", returned_reference).digest = "sha256:" + "0" * 64

    assert resolved.reference.digest == (
        "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"
    )


def test_resolved_profile_public_construction_rejects_arbitrary_bytes() -> None:
    """Only the closed packaged resolver can mint profile authority."""
    constructor = cast("Any", profiles.ResolvedTestProfile)

    with pytest.raises(TypeError):
        constructor(_content=resolve_profile("capability-fulfillment"))


def test_resolved_profile_internal_factory_rejects_unlisted_resource() -> None:
    """The internal mint cannot name a resource outside the closed map."""
    with pytest.raises(ValueError, match="unknown canonical Test Profile resource"):
        cast("Any", profiles)._resolved_test_profile_from_resource("caller-profile.json")


def test_resolved_profile_snapshot_is_frozen_and_has_no_resource_handle() -> None:
    resolved = profiles.resolve_test_profile("capability-fulfillment")

    assert not hasattr(resolved, "_resource_name")
    with pytest.raises(FrozenInstanceError):
        cast("Any", resolved)._content = b"{}"


def test_agent_test_facade_exposes_resolved_profile() -> None:
    resolved = agent_test.resolve_test_profile("capability-fulfillment")

    assert isinstance(resolved, agent_test.ResolvedTestProfile)


@pytest.mark.parametrize("reference", ["unknown", "capability-fulfillment@0.2"])
def test_unknown_alias_or_version_fails_before_execution(reference: str) -> None:
    """1 has neither discovery fallback nor version negotiation."""
    with pytest.raises(KeyError):
        resolve_profile(reference)


def test_profile_is_strict_and_complete() -> None:
    """The packaged profile accepts no unknown field or incomplete required checks."""
    profile = load_profile("capability-fulfillment").model_dump(mode="json")
    profile["unknown"] = True
    with pytest.raises(ValidationError):
        TestProfile.model_validate(profile)


def test_packaged_profile_agrees_with_its_checked_in_schema() -> None:
    """The immutable resource has identical schema and runtime acceptance."""
    data = json.loads(profile_bytes("capability-fulfillment"))
    schema = json.loads(
        resources.files("nest_core.agent_test.resources.schemas")
        .joinpath("test-profile-1.schema.json")
        .read_text(encoding="utf-8")
    )
    jsonschema.validate(data, schema)
    TestProfile.model_validate(data)
    data["unknown"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


def test_profile_schema_and_model_reject_swapped_fixture_text_roles() -> None:
    """The schema preserves which exact text is the request and expected response."""
    data = json.loads(profile_bytes("capability-fulfillment"))
    request_text = data["fixture"]["request"]["text"]
    data["fixture"]["request"]["text"] = data["fixture"]["expected_response"]["text"]
    data["fixture"]["expected_response"]["text"] = request_text
    schema = json.loads(
        resources.files("nest_core.agent_test.resources.schemas")
        .joinpath("test-profile-1.schema.json")
        .read_text(encoding="utf-8")
    )

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestProfile.model_validate(data)


def test_profile_schema_and_model_reject_unsafe_profile_check_ids() -> None:
    """Profile-owned check IDs share the closed safe-ID contract."""
    data = json.loads(profile_bytes("capability-fulfillment"))
    data["evaluator"]["required_checks"][0] = "driver/contract"
    schema = json.loads(
        resources.files("nest_core.agent_test.resources.schemas")
        .joinpath("test-profile-1.schema.json")
        .read_text(encoding="utf-8")
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestProfile.model_validate(data)


def test_ulids_are_crockford_ordered_and_unique_under_frozen_clock() -> None:
    """Town's local ID generator is sortable without adding an ID dependency."""
    first = new_ulid(timestamp_ms=1_700_000_000_000)
    second = new_ulid(timestamp_ms=1_700_000_000_001)
    same_tick = {new_ulid(timestamp_ms=1_700_000_000) for _ in range(100)}
    assert len(first) == 26
    assert set(first) <= set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    assert first < second
    assert len(same_tick) == 100


def test_strict_driver_models_reject_malformed_town_ids() -> None:
    """Run and event IDs are never arbitrary adapter strings."""
    request = {
        "schema_version": "town-agent-driver/1",
        "run_id": "not-a-ulid",
        "event_id": "01K00000000000000000000002",
        "sequence": 0,
        "participant": {"id": "provider-0", "role": "provider"},
        "profile": {
            "id": "nanda/agent/capability-fulfillment",
            "version": "1",
            "digest": profile_digest("capability-fulfillment"),
        },
        "observation": {"kind": "start", "logical_time": 0, "allowed_intents": ["none"]},
    }
    with pytest.raises(ValidationError):
        DriverRequest.model_validate(request)
