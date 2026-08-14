# SPDX-License-Identifier: Apache-2.0
"""Behavior tests for the standard-library reference adapter process."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import threading
from collections.abc import Generator
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from nest_core.agent_test.models import DriverError, DriverReady, DriverResponse

REPOSITORY_ROOT = Path(__file__).parents[4]
ADAPTER_PATH = REPOSITORY_ROOT / "examples" / "agent-test" / "reference_adapter.py"
TOKEN = "a" * 64
CONTRACT = "town-agent-driver/1"
PROFILE_DIGEST = "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"
FIXTURES = Path(__file__).parent / "fixtures"


def _load_adapter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("town_reference_adapter", ADAPTER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def _running_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[ModuleType, int, Any], None, None]:
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    module = _load_adapter()
    server = module.create_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield module, int(server.server_port), server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    response_body = response.read()
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return response.status, response_headers, response_body


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _headers(body: bytes | None = None, *, token: str = TOKEN) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Town-Driver-Contract": CONTRACT,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Town-Request-Digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
    return headers


def _post_data(port: int, data: dict[str, Any]) -> tuple[int, dict[str, str], bytes, bytes]:
    body = json.dumps(data, separators=(",", ":")).encode("utf-8")
    status, headers, response = _request(
        port,
        "POST",
        "/town-driver/1/decide",
        body=body,
        headers=_headers(body),
    )
    return status, headers, response, body


def _error_code(body: bytes) -> str:
    return DriverError.model_validate_json(body).error.code


def _stop_request(*, sequence: int, reason: str) -> dict[str, Any]:
    request = _fixture("driver-stop-request.json")
    request["sequence"] = sequence
    request["observation"]["logical_time"] = 0
    request["observation"]["reason"] = reason
    if sequence == 1:
        request["event_id"] = "01K00000000000000000000003"
    return request


def _second_start() -> dict[str, Any]:
    request = _fixture("driver-start-request.json")
    request["run_id"] = "01K00000000000000000000011"
    request["event_id"] = "01K00000000000000000000012"
    return request


def test_authentication_precedes_body_parsing_and_compatibility_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing authentication must yield only a generic 401, even for malformed JSON."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        status, headers, body = _request(
            port,
            "POST",
            "/town-driver/1/decide",
            body=b"not-json",
            headers={
                "Content-Type": "application/json",
                "Town-Driver-Contract": CONTRACT,
                "Town-Request-Digest": "sha256:" + "0" * 64,
            },
        )

    assert status == 401
    assert headers["content-type"] == "application/json"
    assert headers["town-driver-contract"] == CONTRACT
    payload = json.loads(body)
    assert payload["error"] == {
        "code": "AUTHENTICATION_FAILED",
        "message": "Authentication failed",
        "retryable": False,
    }
    assert payload["adapter_instance_id"] is None
    assert payload["run_id"] is None
    assert payload["event_id"] is None
    assert payload["sequence"] is None
    assert payload["request_digest"] is None
    assert b"town-reference-adapter" not in body
    assert b"capability-fulfillment" not in body


def test_readiness_is_exact_and_capacity_is_honest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing readiness identity, limits, or free capacity must fail this contract test."""
    with _running_adapter(monkeypatch) as (_, port, server):
        status, headers, body = _request(
            port,
            "GET",
            "/town-driver/1/ready",
            headers=_headers(),
        )

    assert status == 200
    assert headers["content-type"] == "application/json"
    assert headers["town-driver-contract"] == CONTRACT
    ready = DriverReady.model_validate_json(body)
    assert ready.model_dump(mode="json") == {
        "schema_version": "town-agent-driver-ready/1",
        "adapter_instance_id": "town-reference-adapter",
        "contracts": [CONTRACT],
        "profiles": [
            {
                "id": "nanda/agent/capability-fulfillment",
                "version": "1",
                "digest": PROFILE_DIGEST,
            }
        ],
        "accepting_runs": True,
        "limits": {
            "max_active_runs": 1,
            "max_request_bytes": 65536,
            "max_response_bytes": 65536,
        },
    }
    assert TOKEN not in repr(server.__dict__)


def test_valid_token_is_removed_from_environment_before_decisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retaining the raw bearer in the adapter environment must fail this test."""
    observed_tokens: list[str | None] = []
    with _running_adapter(monkeypatch) as (module, port, server):
        original = module.decide_intent

        def observe_environment(observation: dict[str, Any]) -> dict[str, Any]:
            observed_tokens.append(os.environ.get("TOWN_AGENT_TOKEN"))
            return original(observation)

        monkeypatch.setattr(module, "decide_intent", observe_environment)
        status, _, _, _ = _post_data(port, _fixture("driver-start-request.json"))

    assert status == 200
    assert observed_tokens == [None]
    assert "TOWN_AGENT_TOKEN" not in os.environ
    assert TOKEN not in repr(server.__dict__)


def test_start_returns_exact_declared_capability_and_request_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing start intent or digest binding must fail at the adapter boundary."""
    request = _fixture("driver-start-request.json")
    with _running_adapter(monkeypatch) as (_, port, _server):
        status, _headers_out, body, request_body = _post_data(port, request)

    assert status == 200
    response = DriverResponse.model_validate_json(body)
    assert response.run_id == request["run_id"]
    assert response.event_id == request["event_id"]
    assert response.sequence == 0
    assert response.adapter_instance_id == "town-reference-adapter"
    assert response.request_digest == "sha256:" + hashlib.sha256(request_body).hexdigest()
    assert response.intent.model_dump(mode="json") == {
        "kind": "declare_capability",
        "capabilities": ["sell"],
    }


def test_exact_duplicate_returns_byte_identical_cached_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing replay caching must make the byte-identity assertion fail."""
    request = _fixture("driver-start-request.json")
    with _running_adapter(monkeypatch) as (_, port, _server):
        first_status, _, first, _ = _post_data(port, request)
        second_status, _, second, _ = _post_data(port, request)

    assert first_status == second_status == 200
    assert first == second


def test_same_event_with_changed_body_is_a_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepting changed bytes under a successful event ID would break replay authority."""
    request = _fixture("driver-start-request.json")
    changed = json.loads(json.dumps(request))
    changed["observation"]["allowed_intents"] = ["none", "declare_capability"]
    with _running_adapter(monkeypatch) as (_, port, _server):
        first_status, _, _, _ = _post_data(port, request)
        conflict_status, _, conflict, _ = _post_data(port, changed)

    assert first_status == 200
    assert conflict_status == 409
    assert _error_code(conflict) == "EVENT_CONFLICT"


def test_message_before_start_is_rejected_as_out_of_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing sequence admission must allow this skipped start and fail the test."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        status, _, body, _ = _post_data(port, _fixture("driver-message-request.json"))

    assert status == 409
    assert _error_code(body) == "OUT_OF_ORDER"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("participant", "id"), "another-provider"),
        (("participant", "role"), "buyer"),
        (("profile", "digest"), "sha256:" + "0" * 64),
        (("observation", "allowed_intents"), ["none", "send_to_sender"]),
        (("observation", "message", "sender_id"), "another-requester"),
        (("observation", "message", "text"), "buy:other:9"),
    ],
)
def test_message_contract_rejects_wrong_participant_profile_or_payload(
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
    value: object,
) -> None:
    """Loosening any frozen message vector must make one mutation unexpectedly pass."""
    start = _fixture("driver-start-request.json")
    message = _fixture("driver-message-request.json")
    cursor: dict[str, Any] = message
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    with _running_adapter(monkeypatch) as (_, port, _server):
        assert _post_data(port, start)[0] == 200
        status, _, body, _ = _post_data(port, message)

    assert status == 422
    assert _error_code(body) == "SCHEMA_INVALID"


def test_unknown_profile_fails_closed_before_profile_payload_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unregistered safe profile ID is unsupported, never a generic trusted payload."""
    request = _fixture("driver-start-request.json")
    request["profile"]["id"] = "example/agent/ping"
    request["observation"] = {"untrusted": True}

    with _running_adapter(monkeypatch) as (_, port, _server):
        status, _, body, _ = _post_data(port, request)

    assert status == 422
    assert _error_code(body) == "UNSUPPORTED_PROFILE"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "nanda//agent"),
        ("version", "0/1"),
        ("digest", "sha256:not-a-digest"),
    ],
)
def test_malformed_profile_identity_precedes_unsupported_profile(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    """Only a well-formed unknown identity may receive UNSUPPORTED_PROFILE."""
    request = _fixture("driver-start-request.json")
    request["profile"][field] = value
    request["observation"] = {"untrusted": True}

    with _running_adapter(monkeypatch) as (_, port, _server):
        status, _, body, _ = _post_data(port, request)

    assert status == 422
    assert _error_code(body) == "SCHEMA_INVALID"


def test_one_active_run_is_enforced_at_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admitting a second run while the first is active must fail this capacity test."""
    first = _fixture("driver-start-request.json")
    second = _fixture("driver-start-request.json")
    second["run_id"] = "01K00000000000000000000011"
    second["event_id"] = "01K00000000000000000000012"
    with _running_adapter(monkeypatch) as (_, port, _server):
        assert _post_data(port, first)[0] == 200
        status, _, body, _ = _post_data(port, second)

    assert status == 409
    assert _error_code(body) == "RUN_BUSY"


def test_success_path_is_start_message_stop_and_releases_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrong transition, semantic response, or capacity release must fail this full sequence."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        start_status, _, _, _ = _post_data(port, _fixture("driver-start-request.json"))
        busy_status, _, busy_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )
        message_status, _, message_body, message_request_body = _post_data(
            port, _fixture("driver-message-request.json")
        )
        stop_status, _, stop_body, stop_request_body = _post_data(
            port, _fixture("driver-stop-request.json")
        )
        free_status, _, free_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )

    assert start_status == message_status == stop_status == busy_status == free_status == 200
    assert DriverReady.model_validate_json(busy_body).accepting_runs is False
    assert DriverReady.model_validate_json(free_body).accepting_runs is True
    message = DriverResponse.model_validate_json(message_body)
    assert message.request_digest == "sha256:" + hashlib.sha256(message_request_body).hexdigest()
    assert message.intent.model_dump(mode="json") == {
        "kind": "send_to_sender",
        "media_type": "text/plain; charset=utf-8",
        "text": "sold:widget:2",
    }
    stop = DriverResponse.model_validate_json(stop_body)
    assert stop.request_digest == "sha256:" + hashlib.sha256(stop_request_body).hexdigest()
    assert stop.intent.model_dump(mode="json") == {"kind": "none"}


def test_request_digest_header_and_body_bound_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ignoring a forged digest or an oversized body must fail this framing test."""
    request_body = json.dumps(_fixture("driver-start-request.json"), separators=(",", ":")).encode(
        "utf-8"
    )
    bad_headers = _headers(request_body)
    bad_headers["Town-Request-Digest"] = "sha256:" + "0" * 64
    oversized = b"{" + b" " * 65536 + b"}"
    with _running_adapter(monkeypatch) as (_, port, _server):
        digest_status, _, digest_body = _request(
            port,
            "POST",
            "/town-driver/1/decide",
            body=request_body,
            headers=bad_headers,
        )
        size_status, _, size_body = _request(
            port,
            "POST",
            "/town-driver/1/decide",
            body=oversized,
            headers=_headers(oversized),
        )

    assert digest_status == 422
    assert _error_code(digest_body) == "SCHEMA_INVALID"
    assert size_status == 413
    assert _error_code(size_body) == "BODY_TOO_LARGE"


@pytest.mark.parametrize("reason", ["run_failed", "run_incomplete", "user_interrupted"])
def test_stop_after_start_accepts_legal_terminal_reasons_and_releases_capacity(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    """Rejecting an early legal terminal stop would strand the one-run adapter capacity."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        assert _post_data(port, _fixture("driver-start-request.json"))[0] == 200
        stop = _stop_request(sequence=1, reason=reason)
        first_status, _, first_body, _ = _post_data(port, stop)
        replay_status, _, replay_body, _ = _post_data(port, stop)
        ready_status, _, ready_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )
        next_status, _, _, _ = _post_data(port, _second_start())

    assert first_status == replay_status == ready_status == next_status == 200
    assert first_body == replay_body
    assert DriverResponse.model_validate_json(first_body).intent.kind == "none"
    assert DriverReady.model_validate_json(ready_body).accepting_runs is True


@pytest.mark.parametrize(
    "reason", ["run_complete", "run_failed", "run_incomplete", "user_interrupted"]
)
def test_stop_after_message_accepts_every_legal_terminal_reason_and_releases_capacity(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    """A terminal outcome after the message must release capacity regardless of disposition."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        assert _post_data(port, _fixture("driver-start-request.json"))[0] == 200
        assert _post_data(port, _fixture("driver-message-request.json"))[0] == 200
        stop = _stop_request(sequence=2, reason=reason)
        first_status, _, first_body, _ = _post_data(port, stop)
        replay_status, _, replay_body, _ = _post_data(port, stop)
        ready_status, _, ready_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )
        next_status, _, _, _ = _post_data(port, _second_start())

    assert first_status == replay_status == ready_status == next_status == 200
    assert first_body == replay_body
    assert DriverResponse.model_validate_json(first_body).intent.kind == "none"
    assert DriverReady.model_validate_json(ready_body).accepting_runs is True


def test_run_complete_cannot_skip_the_required_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepting run_complete at sequence one would certify a skipped required exchange."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        assert _post_data(port, _fixture("driver-start-request.json"))[0] == 200
        status, _, body, _ = _post_data(port, _stop_request(sequence=1, reason="run_complete"))

    assert status == 422
    assert _error_code(body) == "SCHEMA_INVALID"


def test_start_hook_failure_is_safe_retryable_and_transactional(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failing custom hook must not leak, consume admission, or poison an exact retry."""
    with _running_adapter(monkeypatch) as (module, port, _server):
        original = module.decide_intent

        def fail(_observation: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError(f"Traceback: private hook detail {TOKEN}")

        monkeypatch.setattr(module, "decide_intent", fail)
        request = _fixture("driver-start-request.json")
        first_status, _, first_body, _ = _post_data(port, request)
        second_status, _, second_body, _ = _post_data(port, request)
        changed = json.loads(json.dumps(request))
        changed["observation"]["logical_time"] = 1
        conflict_status, _, conflict_body, _ = _post_data(port, changed)
        ready_status, _, ready_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )
        monkeypatch.setattr(module, "decide_intent", original)
        recovered_status, _, recovered_body, _ = _post_data(port, request)

    error = DriverError.model_validate_json(first_body)
    assert first_status == second_status == 500
    assert first_body == second_body
    assert error.error.code == "ADAPTER_INTERNAL"
    assert error.error.retryable is True
    assert error.error.message == "Adapter decision failed"
    assert conflict_status == 409
    assert _error_code(conflict_body) == "EVENT_CONFLICT"
    assert ready_status == recovered_status == 200
    assert DriverReady.model_validate_json(ready_body).accepting_runs is True
    assert DriverResponse.model_validate_json(recovered_body).intent.kind == "declare_capability"
    captured = capsys.readouterr()
    combined = (
        first_body + second_body + conflict_body + captured.out.encode() + captured.err.encode()
    )
    assert TOKEN.encode() not in combined
    assert b"Traceback" not in combined
    assert b"private hook detail" not in combined


def test_message_hook_failure_keeps_active_sequence_for_exact_recovery(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Advancing before a failed message hook would make the same event unrecoverable."""
    with _running_adapter(monkeypatch) as (module, port, _server):
        original = module.decide_intent
        assert _post_data(port, _fixture("driver-start-request.json"))[0] == 200

        def fail(_observation: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError(f"private message failure {TOKEN}")

        monkeypatch.setattr(module, "decide_intent", fail)
        request = _fixture("driver-message-request.json")
        first_status, _, first_body, _ = _post_data(port, request)
        second_status, _, second_body, _ = _post_data(port, request)
        changed = json.loads(json.dumps(request))
        changed["observation"]["logical_time"] += 1
        conflict_status, _, conflict_body, _ = _post_data(port, changed)
        busy_status, _, busy_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )
        monkeypatch.setattr(module, "decide_intent", original)
        recovered_status, _, recovered_body, _ = _post_data(port, request)
        stop_status, _, _, _ = _post_data(port, _stop_request(sequence=2, reason="run_complete"))
        free_status, _, free_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )

    assert first_status == second_status == 500
    assert first_body == second_body
    assert DriverError.model_validate_json(first_body).error.code == "ADAPTER_INTERNAL"
    assert conflict_status == 409
    assert _error_code(conflict_body) == "EVENT_CONFLICT"
    assert busy_status == recovered_status == stop_status == free_status == 200
    assert DriverReady.model_validate_json(busy_body).accepting_runs is False
    assert DriverResponse.model_validate_json(recovered_body).intent.kind == "send_to_sender"
    assert DriverReady.model_validate_json(free_body).accepting_runs is True
    captured = capsys.readouterr()
    combined = (
        first_body + second_body + conflict_body + captured.out.encode() + captured.err.encode()
    )
    assert TOKEN.encode() not in combined
    assert b"Traceback" not in combined


def test_message_hook_failure_can_be_aborted_without_stranding_capacity(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Town must be able to terminate a run whose message decision failed internally."""
    with _running_adapter(monkeypatch) as (module, port, _server):
        original = module.decide_intent
        start = _fixture("driver-start-request.json")
        message = _fixture("driver-message-request.json")
        assert _post_data(port, start)[0] == 200

        def fail(_observation: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError(f"Traceback: private message failure {TOKEN}")

        monkeypatch.setattr(module, "decide_intent", fail)
        message_status, _, message_body, _ = _post_data(port, message)
        stop = _stop_request(sequence=2, reason="run_incomplete")
        stop_status, _, stop_body, _ = _post_data(port, stop)
        replay_status, _, replay_body, _ = _post_data(port, stop)
        changed_stop = json.loads(json.dumps(stop))
        changed_stop["observation"]["reason"] = "run_failed"
        conflict_status, _, conflict_body, _ = _post_data(port, changed_stop)
        ready_status, _, ready_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )
        stale_status, _, stale_body, _ = _post_data(port, message)
        monkeypatch.setattr(module, "decide_intent", original)
        next_status, _, _, _ = _post_data(port, _second_start())

    error = DriverError.model_validate_json(message_body)
    assert message_status == 500
    assert error.error.model_dump(mode="json") == {
        "code": "ADAPTER_INTERNAL",
        "message": "Adapter decision failed",
        "retryable": True,
    }
    assert stop_status == replay_status == ready_status == next_status == 200
    assert stop_body == replay_body
    assert DriverResponse.model_validate_json(stop_body).intent.kind == "none"
    assert conflict_status == 409
    assert _error_code(conflict_body) == "EVENT_CONFLICT"
    assert stale_status == 409
    assert _error_code(stale_body) == "OUT_OF_ORDER"
    assert DriverReady.model_validate_json(ready_body).accepting_runs is True
    captured = capsys.readouterr()
    combined = (
        message_body
        + stop_body
        + replay_body
        + conflict_body
        + stale_body
        + captured.out.encode()
        + captured.err.encode()
    )
    assert TOKEN.encode() not in combined
    assert b"Traceback" not in combined
    assert b"private message failure" not in combined


@pytest.mark.parametrize("reason", ["run_failed", "run_incomplete", "user_interrupted"])
def test_sequence_two_abort_can_release_a_run_when_message_never_arrived(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    """A terminal abort may account for a missing message without claiming completion."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        assert _post_data(port, _fixture("driver-start-request.json"))[0] == 200
        status, _, body, _ = _post_data(port, _stop_request(sequence=2, reason=reason))
        ready_status, _, ready_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )

    assert status == ready_status == 200
    assert DriverResponse.model_validate_json(body).intent.kind == "none"
    assert DriverReady.model_validate_json(ready_body).accepting_runs is True


def test_sequence_two_run_complete_cannot_skip_the_required_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful terminal reason must never jump over the required message exchange."""
    with _running_adapter(monkeypatch) as (_, port, _server):
        assert _post_data(port, _fixture("driver-start-request.json"))[0] == 200
        status, _, body, _ = _post_data(port, _stop_request(sequence=2, reason="run_complete"))
        ready_status, _, ready_body = _request(
            port, "GET", "/town-driver/1/ready", headers=_headers()
        )

    assert status == 409
    assert _error_code(body) == "OUT_OF_ORDER"
    assert ready_status == 200
    assert DriverReady.model_validate_json(ready_body).accepting_runs is False
