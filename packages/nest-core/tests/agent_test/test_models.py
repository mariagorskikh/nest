# SPDX-License-Identifier: Apache-2.0
"""Strict 1 contract regression tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from nest_core.agent_test.models import (
    DriverError,
    DriverReady,
    DriverRequest,
    DriverResponse,
    IntentReturnedData,
    ResultDriver,
    RunAdmittedData,
    SendToSenderIntent,
    TestObservation,
    TestProfile,
    TestResult,
)
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMAS = Path(__file__).parents[2] / "nest_core" / "agent_test" / "resources" / "schemas"


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("fixture", "model", "schema"),
    [
        ("result-pass.json", TestResult, "test-result-1.schema.json"),
        ("result-incomplete.json", TestResult, "test-result-1.schema.json"),
        ("test-observation.json", TestObservation, "test-observation-1.schema.json"),
        ("driver-ready.json", DriverReady, "driver-ready-1.schema.json"),
        ("driver-start-request.json", DriverRequest, "driver-request-1.schema.json"),
        ("driver-message-request.json", DriverRequest, "driver-request-1.schema.json"),
        ("driver-stop-request.json", DriverRequest, "driver-request-1.schema.json"),
        ("driver-start-response.json", DriverResponse, "driver-response-1.schema.json"),
        ("driver-message-response.json", DriverResponse, "driver-response-1.schema.json"),
        ("driver-stop-response.json", DriverResponse, "driver-response-1.schema.json"),
        ("driver-error.json", DriverError, "driver-error-1.schema.json"),
    ],
)
def test_golden_vectors_agree_with_schema_and_strict_model(
    fixture: str, model: type[Any], schema: str
) -> None:
    """Every checked-in vector validates through both contract paths."""
    data = _fixture(fixture)
    jsonschema.validate(data, json.loads((SCHEMAS / schema).read_text(encoding="utf-8")))
    model.model_validate(data)


@pytest.mark.parametrize(
    ("fixture", "model", "schema"),
    [
        ("result-pass.json", TestResult, "test-result-1.schema.json"),
        ("test-observation.json", TestObservation, "test-observation-1.schema.json"),
        ("driver-ready.json", DriverReady, "driver-ready-1.schema.json"),
        ("driver-start-request.json", DriverRequest, "driver-request-1.schema.json"),
        ("driver-start-response.json", DriverResponse, "driver-response-1.schema.json"),
        ("driver-error.json", DriverError, "driver-error-1.schema.json"),
    ],
)
def test_contract_families_reject_unknown_fields(
    fixture: str, model: type[Any], schema: str
) -> None:
    """A contract cannot silently accept a newer or misspelled field."""
    data = _fixture(fixture)
    data["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, json.loads((SCHEMAS / schema).read_text(encoding="utf-8")))
    with pytest.raises(ValidationError):
        model.model_validate(data)


def test_exact_contract_identifiers_are_literals() -> None:
    """Generation one is the only accepted public contract identifier."""
    data = _fixture("driver-ready.json")
    data["schema_version"] = "town-agent-driver-ready/1"

    assert DriverReady.model_validate(data).schema_version == "town-agent-driver-ready/1"

    data["schema_version"] = "town-agent-driver-ready/0.1"
    with pytest.raises(ValidationError):
        DriverReady.model_validate(data)


def test_published_adapter_instance_grammar_is_shared_by_wire_result_and_evidence() -> None:
    """The frozen nonempty-string grammar, including colon, survives every recording path."""
    instance_id = "adapter:dev"
    for model, fixture in (
        (DriverReady, "driver-ready.json"),
        (DriverResponse, "driver-start-response.json"),
        (DriverError, "driver-error.json"),
    ):
        data = _fixture(fixture)
        data["adapter_instance_id"] = instance_id
        assert model.model_validate(data).adapter_instance_id == instance_id

    assert (
        ResultDriver(
            contract="town-agent-driver/1",
            kind="loopback-http",
            adapter_instance_id=instance_id,
            endpoint_origin="http://127.0.0.1:8787",
        ).adapter_instance_id
        == instance_id
    )
    assert (
        RunAdmittedData(
            adapter_instance_id=instance_id,
            profile_digest="sha256:" + "0" * 64,
            driver_sequence=0,
            intent_kind="declare_capability",
        ).adapter_instance_id
        == instance_id
    )
    assert (
        IntentReturnedData(
            adapter_instance_id=instance_id,
            driver_event_id="01K00000000000000000000002",
            driver_sequence=1,
            intent_kind="none",
        ).adapter_instance_id
        == instance_id
    )


@pytest.mark.parametrize("instance_id", ["", " adapter", "adapter\x00", "é" * 129])
def test_adapter_instance_metadata_remains_bounded_and_safe(instance_id: str) -> None:
    """Published string compatibility remains nonempty, trimmed, controlled, and bounded."""
    data = _fixture("driver-ready.json")
    data["adapter_instance_id"] = instance_id
    with pytest.raises(ValidationError):
        DriverReady.model_validate(data)


@pytest.mark.parametrize(
    ("model", "schema"),
    [
        (DriverReady, "driver-ready-1.schema.json"),
        (DriverResponse, "driver-response-1.schema.json"),
        (DriverError, "driver-error-1.schema.json"),
        (TestResult, "test-result-1.schema.json"),
        (TestObservation, "test-observation-1.schema.json"),
    ],
)
def test_packaged_schemas_match_runtime_models(model: type[Any], schema: str) -> None:
    """Each direct model remains the source of its registry-generated schema family."""
    from nest_core.agent_test.schema_contracts import generated_schemas

    del model
    assert generated_schemas()[schema] == json.loads((SCHEMAS / schema).read_text(encoding="utf-8"))


def test_all_seven_schemas_are_generated_and_current() -> None:
    """Ordinary pytest collection detects any checked-in contract drift without writes."""
    from nest_core.agent_test.schema_contracts import (
        check_packaged_schemas,
        generated_schema_bytes,
        generated_schemas,
    )

    generated = generated_schemas()
    generated_bytes = generated_schema_bytes()

    assert set(generated) == {
        "driver-error-1.schema.json",
        "driver-ready-1.schema.json",
        "driver-request-1.schema.json",
        "driver-response-1.schema.json",
        "test-observation-1.schema.json",
        "test-profile-1.schema.json",
        "test-result-1.schema.json",
    }
    assert set(generated_bytes) == set(generated)
    assert all(
        schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        for schema in generated.values()
    )
    assert all(
        content.endswith(b"\n") and b'\n  "' in content for content in generated_bytes.values()
    )
    assert all(
        (SCHEMAS / name).read_bytes() == content for name, content in generated_bytes.items()
    )
    check_packaged_schemas()


def test_driver_request_and_profile_join_schema_model_parity() -> None:
    """The two formerly omitted model families reject the same adversarial values."""
    vectors = [
        (
            DriverRequest,
            "driver-request-1.schema.json",
            "driver-start-request.json",
            ("profile", "id"),
            "nanda//capability",
        ),
        (
            DriverRequest,
            "driver-request-1.schema.json",
            "driver-start-request.json",
            ("participant", "role"),
            "opérator",
        ),
        (
            TestProfile,
            "test-profile-1.schema.json",
            None,
            ("id",),
            "nanda//capability",
        ),
    ]
    for model, schema_name, fixture_name, path, invalid in vectors:
        data = (
            _fixture(fixture_name)
            if fixture_name is not None
            else json.loads(
                (
                    Path(__file__).parents[2]
                    / "nest_core"
                    / "agent_test"
                    / "resources"
                    / "profiles"
                    / "capability-fulfillment-1.json"
                ).read_text(encoding="utf-8")
            )
        )
        target = data
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = invalid
        schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(data, schema)
        with pytest.raises(ValidationError):
            model.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [("id", "requester-0"), ("role", "auditor")],
)
def test_capability_request_keeps_its_exact_provider_participant(field: str, value: str) -> None:
    """Generic envelopes cannot widen the shipped capability participant contract."""
    data = _fixture("driver-start-request.json")
    data["participant"][field] = value
    schema = json.loads((SCHEMAS / "driver-request-1.schema.json").read_text())

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        DriverRequest.model_validate(data)


def test_safe_driver_text_uses_schema_visible_code_point_limits() -> None:
    """Structural code-point limits align; the stronger profile byte limit is explicit."""
    schema = json.loads((SCHEMAS / "driver-response-1.schema.json").read_text(encoding="utf-8"))
    data = _fixture("driver-message-response.json")
    from nest_core.agent_test.profile_codecs import DEFAULT_PROFILE_CODECS

    binding = DEFAULT_PROFILE_CODECS.bind(
        DEFAULT_PROFILE_CODECS.validate_request(_fixture("driver-message-request.json")).profile
    )
    data["intent"]["text"] = "a" * 4096
    jsonschema.validate(data, schema)
    assert binding.validate_response(data).intent.text == "a" * 4096

    data["intent"]["text"] = "é" * 4096
    jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        binding.validate_response(data)
    assert (
        "intent text is at most the profile UTF-8 byte limit"
        in schema["x-town-semantic-validation"]
    )

    data["intent"]["text"] = "a" * 4097
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        binding.validate_response(data)


@pytest.mark.parametrize(
    ("field_path", "accepted", "rejected"),
    [
        (("diagnostics", 0, "summary"), "é" * 512, "é" * 513),
        (("diagnostics", 0, "summary"), "safe summary", " leading"),
        (("diagnostics", 0, "summary"), "safe summary", "bad\x00summary"),
        (("evaluation", "checks", 0, "id"), "driver.contract", "driver.contract\n"),
    ],
)
def test_expressible_text_and_identifier_constraints_have_schema_runtime_parity(
    field_path: tuple[str | int, ...], accepted: str, rejected: str
) -> None:
    """Code-point limits, trimming, controls, and ASCII IDs agree cross-validator."""
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text(encoding="utf-8"))
    data = _fixture("result-incomplete.json")
    target: Any = data
    for part in field_path[:-1]:
        target = target[part]
    target[field_path[-1]] = accepted
    jsonschema.validate(data, schema)
    TestResult.model_validate(data)

    target[field_path[-1]] = rejected
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(data)


@pytest.mark.parametrize(
    ("fixture", "model", "schema_name", "field_path"),
    [
        (
            "driver-ready.json",
            DriverReady,
            "driver-ready-1.schema.json",
            ("adapter_instance_id",),
        ),
        (
            "result-pass.json",
            TestResult,
            "test-result-1.schema.json",
            ("artifacts", 0, "media_type"),
        ),
        (
            "result-pass.json",
            TestResult,
            "test-result-1.schema.json",
            ("evaluation", "checks", 0, "evidence_refs", 0),
        ),
        (
            "result-pass.json",
            TestResult,
            "test-result-1.schema.json",
            ("execution", "started_at"),
        ),
    ],
)
def test_schema_and_runtime_reject_final_newline_in_string_aliases(
    fixture: str,
    model: type[Any],
    schema_name: str,
    field_path: tuple[str | int, ...],
) -> None:
    """A regex end anchor cannot make CR/LF valid at the schema boundary."""
    data = _fixture(fixture)
    target: Any = data
    for part in field_path[:-1]:
        target = target[part]
    target[field_path[-1]] += "\n"
    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        model.model_validate(data)


@pytest.mark.parametrize("media_type", [" text/plain", "text/plain "])
def test_media_type_schema_and_runtime_both_require_trimmed_ascii(media_type: str) -> None:
    """Schema validation cannot admit whitespace that the runtime contract rejects."""
    data = _fixture("result-pass.json")
    data["artifacts"][0]["media_type"] = media_type
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text())

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(data)


def test_result_contract_is_profile_and_scenario_generic() -> None:
    """A second profile can reuse the result envelope without new wire identifiers."""
    data = _fixture("result-pass.json")
    data["profile"] = {
        "id": "example/agent/ping",
        "version": "2.0",
        "digest": "sha256:" + "1" * 64,
    }
    data["execution"]["scenario"] = "ping_roundtrip"
    data["evaluation"]["checks"][0]["id"] = "ping.response"
    data["coverage"][0]["claim"] = "example.ping.loopback"
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text(encoding="utf-8"))

    jsonschema.validate(data, schema)
    result = TestResult.model_validate(data)

    assert result.profile.id == "example/agent/ping"
    assert result.execution.scenario == "ping_roundtrip"


def test_result_attribution_is_self_asserted_not_authenticated_identity() -> None:
    """The bearer proves caller access, not the adapter's identity."""
    data = _fixture("result-pass.json")
    assert data["target"]["attribution"] == "self_asserted_loopback_adapter_instance"
    assert TestResult.model_validate(data).target.attribution == data["target"]["attribution"]


def test_semantic_only_validation_is_declared_in_schema_extensions() -> None:
    """Cross-field and parser rules that JSON Schema cannot prove remain explicit."""
    observation_schema = json.loads(
        (SCHEMAS / "test-observation-1.schema.json").read_text(encoding="utf-8")
    )
    result_schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text(encoding="utf-8"))
    response_schema = json.loads(
        (SCHEMAS / "driver-response-1.schema.json").read_text(encoding="utf-8")
    )

    assert set(observation_schema["x-town-semantic-validation"]) >= {
        "calendar-valid UTC RFC3339 timestamps",
        "payload_digest matches exact UTF-8 text",
    }
    assert "literal loopback HTTP origin" in result_schema["x-town-semantic-validation"]
    assert (
        "intent validated with the originating request profile codec"
        in response_schema["x-town-semantic-validation"]
    )

    observation = _fixture("test-observation.json")
    observation["observed_at"] = "2026-02-30T12:00:00Z"
    jsonschema.validate(observation, observation_schema)
    with pytest.raises(ValidationError):
        TestObservation.model_validate(observation)

    result = _fixture("result-pass.json")
    result["driver"]["endpoint_origin"] = "http://example.test:8787"
    jsonschema.validate(result, result_schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(result)


def test_observation_payload_digest_matches_text() -> None:
    """Trace payload evidence is tied to the exact UTF-8 message text."""
    data = _fixture("test-observation.json")
    data["data"]["payload_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError):
        TestObservation.model_validate(data)


@pytest.mark.parametrize("path", ["../trace.jsonl", "foo//bar", "foo/"])
def test_result_rejects_unsafe_artifact_paths_in_schema_and_model(path: str) -> None:
    """Result paths and human text have their approved safe grammar."""
    path_data = _fixture("result-pass.json")
    path_data["artifacts"][0]["path"] = path
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(path_data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(path_data)


def test_result_diagnostic_text_rejects_ascii_controls_but_not_secret_prose() -> None:
    """Safe text is structural; bearer canaries remain a separate runtime scan."""
    diagnostic_data = _fixture("result-incomplete.json")
    diagnostic_data["diagnostics"][0]["summary"] = "Authorization: Bearer secret"
    TestResult.model_validate(diagnostic_data)
    diagnostic_data["diagnostics"][0]["summary"] = "bad\x00text"
    with pytest.raises(ValidationError):
        TestResult.model_validate(diagnostic_data)


def test_result_schema_and_model_reject_contradictory_conclusive_evidence() -> None:
    """A completed pass cannot serialize an inconclusive required check."""
    data = _fixture("result-pass.json")
    data["evaluation"]["checks"][0]["status"] = "inconclusive"
    data["evaluation"]["checks"][0]["evidence_refs"] = []
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(data)


def test_completed_failure_allows_causally_downstream_not_tested_checks() -> None:
    """A proved semantic failure is terminal even if a later dependent check was not run."""
    data = _fixture("result-pass.json")
    data["execution"]["status"] = "completed"
    data["evaluation"] = {
        "verdict": "fail",
        "checks": [
            {
                "id": "driver.contract",
                "required": True,
                "status": "fail",
                "summary": "Adapter refused the required start intent",
                "evidence_refs": ["trace.jsonl#seq=1"],
            },
            {
                "id": "registry.provider-registered",
                "required": True,
                "status": "not_tested",
                "summary": "Provider registration depends on start admission",
                "evidence_refs": [],
            },
        ],
    }
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text(encoding="utf-8"))

    jsonschema.validate(data, schema)
    TestResult.model_validate(data)


@pytest.mark.parametrize("text", ["not the expected response", "café"])
def test_send_to_sender_intent_accepts_bounded_safe_utf8_text(text: str) -> None:
    """The driver may return any safe bounded response for semantic evaluation by Town."""
    intent = SendToSenderIntent(
        kind="send_to_sender",
        media_type="text/plain; charset=utf-8",
        text=text,
    )
    assert intent.text == text


def test_send_to_sender_intent_rejects_text_over_profile_message_limit() -> None:
    """A driver response cannot exceed the frozen profile's 4096-byte message boundary."""
    with pytest.raises(ValidationError):
        SendToSenderIntent(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="é" * 2049,
        )


def test_run_admitted_evidence_records_start_intent_kind() -> None:
    """Admission evidence positively distinguishes capability declaration from refusal."""
    admitted = RunAdmittedData(
        adapter_instance_id="adapter:dev",
        profile_digest="sha256:" + "0" * 64,
        driver_sequence=0,
        intent_kind="none",
    )
    assert admitted.intent_kind == "none"


def test_driver_exchange_failure_is_a_closed_safe_observation() -> None:
    """Driver failures retain only local classification metadata needed by the evaluator."""
    observation = TestObservation.model_validate(
        {
            "schema_version": "town.test-observation/1",
            "seq": 1,
            "event_id": "01K00000000000000000000002",
            "run_id": "01K00000000000000000000001",
            "kind": "test.driver.exchange_failed",
            "logical_time": 0.0,
            "observed_at": "2026-08-13T12:00:00Z",
            "duration_ms": None,
            "observer": "town.driven-agent",
            "subject_participant_id": "provider-0",
            "message_id": None,
            "correlation_id": None,
            "request_digest": None,
            "response_digest": None,
            "data": {
                "stage": "message",
                "disposition": "driver_contract",
                "error_code": "INTENT_NOT_ALLOWED",
                "driver_event_id": "01K00000000000000000000003",
                "driver_sequence": 1,
            },
        }
    )
    assert observation.root.kind == "test.driver.exchange_failed"

    data = observation.model_dump(mode="json")
    data["data"]["remote_text"] = "secret"
    with pytest.raises(ValidationError):
        TestObservation.model_validate(data)


@pytest.mark.parametrize("verdict", ["inconclusive", "not_evaluated"])
def test_result_schema_and_model_reject_completed_nonterminal_verdicts(verdict: str) -> None:
    """Completed results have only the two terminal verdicts."""
    data = _fixture("result-pass.json")
    data["evaluation"]["verdict"] = verdict
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(data)


def test_result_schema_and_model_reject_unbounded_or_malformed_evidence() -> None:
    """Result evidence uses closed event references with the approved limits."""
    data = _fixture("result-pass.json")
    data["evaluation"]["checks"][0]["evidence_refs"] = ["trace.jsonl"]
    schema = json.loads((SCHEMAS / "test-result-1.schema.json").read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(data)
    data = _fixture("result-pass.json")
    data["evaluation"]["checks"][0]["evidence_refs"] = []
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(data)
    data = _fixture("result-pass.json")
    data["run_id"] = "not-a-ulid"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValidationError):
        TestResult.model_validate(data)
