# SPDX-License-Identifier: Apache-2.0
"""Real-socket component tests for the authenticated loopback HTTP driver."""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import threading
import time
from collections.abc import Callable, Generator, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest
from nest_core.agent_test.driver import (
    DriverCompatibilityError,
    DriverConfigurationError,
    DriverContractError,
    DriverIncompleteError,
    TownDriverError,
)
from nest_core.agent_test.http_driver import LoopbackHttpAgentDriver
from nest_core.agent_test.models import DriverRequest, ResultDriver
from nest_core.agent_test.profiles import resolve_test_profile

FIXTURES = Path(__file__).parent / "fixtures"
TOKEN = "0123456789abcdef" * 4
INSTANCE = "01K00000000000000000000000"
REMOTE_RESPONSE_CANARY = "REMOTE_RESPONSE_CANARY"
REMOTE_MODEL_CANARY = "REMOTE_MODEL_CANARY"
JSON_HEADERS = {
    "Content-Type": "application/json",
    "Town-Driver-Contract": "town-agent-driver/1",
}


@dataclass(frozen=True, slots=True)
class _RecordedRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class _Response:
    status: int = 200
    headers: Mapping[str, str] = field(default_factory=lambda: JSON_HEADERS)
    chunks: tuple[bytes, ...] = ()
    include_length: bool = True
    close_without_response: bool = False
    delay_seconds: float = 0.0
    chunk_delay_seconds: float = 0.0
    first_chunk_sent: threading.Event | None = None


Responder = Callable[[_RecordedRequest, int], _Response]


class _Server(ThreadingHTTPServer):
    responder: Responder
    requests: list[_RecordedRequest]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._respond()

    def do_POST(self) -> None:  # noqa: N802
        self._respond()

    def _respond(self) -> None:
        server = cast("_Server", self.server)
        content_length = int(self.headers.get("Content-Length", "0"))
        request = _RecordedRequest(
            method=self.command,
            path=self.path,
            headers={key.lower(): value for key, value in self.headers.items()},
            body=self.rfile.read(content_length),
        )
        server.requests.append(request)
        response = server.responder(request, len(server.requests))
        if response.delay_seconds:
            time.sleep(response.delay_seconds)
        if response.close_without_response:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        if response.include_length and "content-length" not in {
            key.lower() for key in response.headers
        }:
            self.send_header("Content-Length", str(sum(map(len, response.chunks))))
        self.end_headers()
        try:
            for index, chunk in enumerate(response.chunks):
                if response.chunk_delay_seconds:
                    time.sleep(response.chunk_delay_seconds)
                self.wfile.write(chunk)
                self.wfile.flush()
                if index == 0 and response.first_chunk_sent is not None:
                    response.first_chunk_sent.set()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass


@contextmanager
def _serve(responder: Responder) -> Generator[_Server]:
    server = _Server(("127.0.0.1", 0), _Handler)
    server.responder = responder
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _ready_data(**changes: object) -> dict[str, Any]:
    data = _fixture("driver-ready.json")
    for key, value in changes.items():
        data[key] = value
    return data


def _request(name: str = "driver-start-request.json") -> DriverRequest:
    return DriverRequest.model_validate(_fixture(name))


def _success_data(request: _RecordedRequest, *, instance: str = INSTANCE) -> dict[str, Any]:
    received = json.loads(request.body)
    intent: dict[str, object]
    if received["observation"]["kind"] == "start":
        intent = {"kind": "declare_capability", "capabilities": ["sell"]}
    elif received["observation"]["kind"] == "message":
        intent = {
            "kind": "send_to_sender",
            "media_type": "text/plain; charset=utf-8",
            "text": "sold:widget:2",
        }
    else:
        intent = {"kind": "none"}
    return {
        "schema_version": "town-agent-driver/1",
        "run_id": received["run_id"],
        "event_id": received["event_id"],
        "sequence": received["sequence"],
        "adapter_instance_id": instance,
        "request_digest": "sha256:" + hashlib.sha256(request.body).hexdigest(),
        "intent": intent,
    }


def _error_data(request: _RecordedRequest, code: str, *, message: str = "safe") -> dict[str, Any]:
    received = json.loads(request.body)
    return {
        "schema_version": "town-agent-driver-error/1",
        "adapter_instance_id": INSTANCE,
        "run_id": received["run_id"],
        "event_id": received["event_id"],
        "sequence": received["sequence"],
        "request_digest": "sha256:" + hashlib.sha256(request.body).hexdigest(),
        "error": {"code": code, "retryable": False, "message": message},
    }


def _ready_error_data(code: str, *, instance: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "town-agent-driver-error/1",
        "adapter_instance_id": (
            instance
            if instance is not None
            else (None if code == "AUTHENTICATION_FAILED" else INSTANCE)
        ),
        "run_id": None,
        "event_id": None,
        "sequence": None,
        "request_digest": None,
        "error": {"code": code, "retryable": False, "message": "safe"},
    }


def _standard_responder(request: _RecordedRequest, _: int) -> _Response:
    if request.path == "/town-driver/1/ready":
        return _Response(chunks=(_json_bytes(_ready_data()),))
    return _Response(chunks=(_json_bytes(_success_data(request)),))


def _origin(server: _Server) -> str:
    return f"http://127.0.0.1:{server.server_port}"


@pytest.mark.asyncio
async def test_real_socket_uses_fixed_paths_exact_headers_body_digest_and_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing paths, bytes, digest input, or proxy policy breaks interoperability or isolation."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    request = _request()
    expected_body = request.model_dump_json().encode()
    expected_digest = "sha256:" + hashlib.sha256(expected_body).hexdigest()

    with _serve(_standard_responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        readiness = await driver.ready(resolve_test_profile("capability-fulfillment"))
        response = await driver.decide(request)
        await driver.close()

    assert readiness.ready.accepting_runs is True
    assert response.request_digest == expected_digest
    assert [(item.method, item.path) for item in server.requests] == [
        ("GET", "/town-driver/1/ready"),
        ("POST", "/town-driver/1/decide"),
    ]
    ready_headers = server.requests[0].headers
    decide_headers = server.requests[1].headers
    for headers in (ready_headers, decide_headers):
        assert headers["authorization"] == f"Bearer {TOKEN}"
        assert headers["town-driver-contract"] == "town-agent-driver/1"
        assert headers["accept"] == "application/json"
        assert headers["accept-encoding"] == "identity"
        assert "cookie" not in headers
    assert "content-type" not in ready_headers
    assert "town-request-digest" not in ready_headers
    assert server.requests[0].body == b""
    assert decide_headers["content-type"] == "application/json"
    assert decide_headers["town-request-digest"] == expected_digest
    assert server.requests[1].body == expected_body


@pytest.mark.asyncio
async def test_advisory_accepting_runs_false_does_not_block_start() -> None:
    """Treating readiness capacity as a reservation would incorrectly skip a valid start."""

    def responder(request: _RecordedRequest, _: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data(accepting_runs=False)),))
        return _Response(chunks=(_json_bytes(_success_data(request)),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        readiness = await driver.ready(resolve_test_profile("capability-fulfillment"))
        response = await driver.decide(_request())

    assert readiness.ready.accepting_runs is False
    assert response.intent.kind == "declare_capability"
    assert len(server.requests) == 2


@pytest.mark.asyncio
async def test_effective_limits_are_minimum_and_oversized_town_request_is_not_sent() -> None:
    """Ignoring the adapter's smaller request limit could misattribute a Town defect."""

    def responder(request: _RecordedRequest, _: int) -> _Response:
        assert request.path.endswith("/ready")
        data = _ready_data(
            limits={"max_active_runs": 1, "max_request_bytes": 1, "max_response_bytes": 123}
        )
        return _Response(chunks=(_json_bytes(data),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        readiness = await driver.ready(resolve_test_profile("capability-fulfillment"))
        with pytest.raises(TownDriverError, match="BODY_TOO_LARGE"):
            await driver.decide(_request())

    assert readiness.effective_limits.max_request_bytes == 1
    assert readiness.effective_limits.max_response_bytes == 123
    assert len(server.requests) == 1


@pytest.mark.parametrize(
    ("mutation", "error_code"),
    [
        ({"schema_version": "town-agent-driver-ready/0.2"}, "UNSUPPORTED_CONTRACT"),
        ({"contracts": ["town-agent-driver/0.2"]}, "UNSUPPORTED_CONTRACT"),
        (
            {
                "profiles": [
                    {
                        "id": "nanda/agent/capability-fulfillment",
                        "version": "0.2",
                        "digest": "sha256:" + "0" * 64,
                    }
                ]
            },
            "UNSUPPORTED_PROFILE",
        ),
    ],
)
@pytest.mark.asyncio
async def test_readiness_requires_exact_contract_profile_version_and_digest(
    mutation: dict[str, object], error_code: str
) -> None:
    """Accepting merely similar readiness metadata could run the wrong contract or profile."""
    data = _ready_data(**mutation)

    with _serve(lambda _request, _count: _Response(chunks=(_json_bytes(data),))) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverCompatibilityError, match=error_code):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.asyncio
async def test_readiness_rejects_nonpositive_adapter_limits_as_malformed_output() -> None:
    """Accepting zero limits would make the negotiated boundary undefined."""
    data = _ready_data(
        limits={"max_active_runs": 1, "max_request_bytes": 0, "max_response_bytes": 65536}
    )

    with _serve(lambda _request, _count: _Response(chunks=(_json_bytes(data),))) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.asyncio
async def test_readiness_nested_schema_failure_is_not_mislabeled_as_compatibility() -> None:
    """Unknown identity fields are malformed adapter output, not an unsupported profile."""
    data = _ready_data()
    data["profiles"][0]["unexpected"] = True

    with _serve(lambda _request, _count: _Response(chunks=(_json_bytes(data),))) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.parametrize("identity", ["contract", "profile"])
@pytest.mark.asyncio
async def test_readiness_validates_full_shape_before_classifying_identity(identity: str) -> None:
    """A mixed malformed/mismatched readiness body is contract failure, not compatibility."""
    data = _ready_data(unexpected=True)
    if identity == "contract":
        data["contracts"] = ["town-agent-driver/0.2"]
    else:
        data["profiles"] = [
            {
                "id": "nanda/agent/capability-fulfillment",
                "version": "0.2",
                "digest": "sha256:" + "0" * 64,
            }
        ]

    with _serve(lambda _request, _count: _Response(chunks=(_json_bytes(data),))) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.parametrize(
    ("status", "code", "expected_type"),
    [
        (401, "AUTHENTICATION_FAILED", DriverConfigurationError),
        (422, "UNSUPPORTED_CONTRACT", DriverCompatibilityError),
        (422, "UNSUPPORTED_PROFILE", DriverCompatibilityError),
        (500, "ADAPTER_INTERNAL", DriverIncompleteError),
    ],
)
@pytest.mark.asyncio
async def test_readiness_non_2xx_uses_the_typed_error_mapping(
    status: int, code: str, expected_type: type[Exception]
) -> None:
    """Collapsing a valid readiness error into generic HTTP failure loses its disposition."""
    response = _Response(status=status, chunks=(_json_bytes(_ready_error_data(code)),))

    with _serve(lambda _request, _count: response) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(expected_type, match=code):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.parametrize(
    ("status", "code", "expected_type"),
    [
        (401, "AUTHENTICATION_FAILED", DriverIncompleteError),
        (422, "UNSUPPORTED_CONTRACT", DriverContractError),
        (422, "UNSUPPORTED_PROFILE", DriverContractError),
    ],
)
@pytest.mark.asyncio
async def test_readiness_error_mapping_is_admission_aware(
    status: int, code: str, expected_type: type[Exception]
) -> None:
    """Post-admission readiness errors cannot regain pre-admission classifications."""
    ready_calls = 0

    def responder(request: _RecordedRequest, _: int) -> _Response:
        nonlocal ready_calls
        if request.path.endswith("/ready"):
            ready_calls += 1
            if ready_calls == 1:
                return _Response(chunks=(_json_bytes(_ready_data()),))
            return _Response(status=status, chunks=(_json_bytes(_ready_error_data(code)),))
        return _Response(chunks=(_json_bytes(_success_data(request)),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        await driver.decide(_request())
        with pytest.raises(expected_type, match=code):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.parametrize(
    ("instance", "expected_type", "code"),
    [
        (None, DriverContractError, "ERROR_RESPONSE_MISMATCH"),
        ("adapter.restarted", DriverIncompleteError, "ADAPTER_INSTANCE_CHANGED"),
    ],
)
@pytest.mark.asyncio
async def test_authenticated_readiness_error_preserves_bound_instance(
    instance: str | None, expected_type: type[Exception], code: str
) -> None:
    """Authenticated readiness errors must contain the bound adapter instance."""
    ready_calls = 0

    def responder(request: _RecordedRequest, _: int) -> _Response:
        nonlocal ready_calls
        if request.path.endswith("/ready"):
            ready_calls += 1
            if ready_calls == 1:
                return _Response(chunks=(_json_bytes(_ready_data()),))
            data = _ready_error_data("ADAPTER_INTERNAL", instance=instance)
            if instance is None:
                data["adapter_instance_id"] = None
            return _Response(status=500, chunks=(_json_bytes(data),))
        return _Response(chunks=(_json_bytes(_success_data(request)),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        await driver.decide(_request())
        with pytest.raises(expected_type, match=code):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.asyncio
async def test_pre_admission_readiness_restart_keeps_valid_compatibility_classification() -> None:
    """Readiness does not reserve a run, so continuity begins only after start admission."""
    ready_calls = 0

    def responder(request: _RecordedRequest, _: int) -> _Response:
        nonlocal ready_calls
        if request.path.endswith("/ready"):
            ready_calls += 1
            if ready_calls == 1:
                return _Response(chunks=(_json_bytes(_ready_data()),))
            data = _ready_error_data("UNSUPPORTED_PROFILE", instance="adapter.restarted")
            return _Response(status=422, chunks=(_json_bytes(data),))
        raise AssertionError("pre-admission test must not decide")

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        with pytest.raises(DriverCompatibilityError, match="UNSUPPORTED_PROFILE"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.asyncio
async def test_adapter_instance_change_from_readiness_is_incomplete() -> None:
    """Attributing output across an adapter restart would make evidence identity ambiguous."""

    def responder(request: _RecordedRequest, _: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        body = _json_bytes(_success_data(request, instance="adapter.restarted"))
        return _Response(chunks=(body,))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        with pytest.raises(DriverIncompleteError, match="ADAPTER_INSTANCE_CHANGED"):
            await driver.decide(_request())


@pytest.mark.parametrize(
    ("status", "code", "admitted", "expected_type"),
    [
        (401, "AUTHENTICATION_FAILED", False, DriverConfigurationError),
        (401, "AUTHENTICATION_FAILED", True, DriverIncompleteError),
        (409, "RUN_BUSY", False, DriverIncompleteError),
        (409, "EVENT_CONFLICT", True, DriverContractError),
        (409, "OUT_OF_ORDER", True, DriverContractError),
        (413, "BODY_TOO_LARGE", False, DriverContractError),
        (422, "UNSUPPORTED_CONTRACT", False, DriverCompatibilityError),
        (422, "UNSUPPORTED_PROFILE", False, DriverCompatibilityError),
        (422, "UNSUPPORTED_CONTRACT", True, DriverContractError),
        (422, "SCHEMA_INVALID", False, TownDriverError),
        (500, "ADAPTER_INTERNAL", False, DriverIncompleteError),
    ],
)
@pytest.mark.asyncio
async def test_complete_typed_http_error_mapping(
    status: int,
    code: str,
    admitted: bool,
    expected_type: type[Exception],
) -> None:
    """Mapping a typed adapter status to the wrong disposition corrupts the final verdict."""
    call = 0

    def responder(request: _RecordedRequest, _: int) -> _Response:
        nonlocal call
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        call += 1
        if admitted and call == 1:
            return _Response(chunks=(_json_bytes(_success_data(request)),))
        return _Response(status=status, chunks=(_json_bytes(_error_data(request, code)),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        if admitted:
            await driver.decide(_request())
        request = _request("driver-message-request.json") if admitted else _request()
        with pytest.raises(expected_type, match=code):
            await driver.decide(request)


@pytest.mark.asyncio
async def test_authenticated_error_requires_nonnull_adapter_instance() -> None:
    """Treating a missing authenticated instance as a restart would hide malformed output."""

    def responder(request: _RecordedRequest, _: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        data = _error_data(request, "RUN_BUSY")
        data["adapter_instance_id"] = None
        return _Response(status=409, chunks=(_json_bytes(data),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        with pytest.raises(DriverContractError, match="ERROR_RESPONSE_MISMATCH"):
            await driver.decide(_request())


@pytest.mark.asyncio
async def test_untyped_non_2xx_is_authenticated_malformed_output() -> None:
    """Treating an untyped HTTP failure as target behavior would misattribute adapter output."""

    def responder(request: _RecordedRequest, _: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        return _Response(status=503, chunks=(b'{"error":"no typed envelope"}',))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        with pytest.raises(DriverContractError, match="MALFORMED_ERROR_RESPONSE"):
            await driver.decide(_request())


@pytest.mark.parametrize(
    "response",
    [
        _Response(headers={"Town-Driver-Contract": "town-agent-driver/1"}, chunks=(b"{}",)),
        _Response(
            headers={
                "Content-Type": "text/plain",
                "Town-Driver-Contract": "town-agent-driver/1",
            },
            chunks=(b"{}",),
        ),
        _Response(headers={"Content-Type": "application/json"}, chunks=(b"{}",)),
        _Response(
            headers={
                **JSON_HEADERS,
                "Content-Encoding": "gzip",
            },
            chunks=(b"not-gzip",),
        ),
        _Response(headers={**JSON_HEADERS, "Set-Cookie": "session=bad"}, chunks=(b"{}",)),
        _Response(status=307, headers={**JSON_HEADERS, "Location": "/elsewhere"}, chunks=(b"{}",)),
        _Response(chunks=(b"not json",)),
        _Response(chunks=(_json_bytes({**_ready_data(), "unexpected": True}),)),
        _Response(headers={**JSON_HEADERS, "Content-Length": "65537"}, chunks=()),
        _Response(chunks=(b"x" * 32768, b"y" * 32769), include_length=False),
    ],
)
@pytest.mark.asyncio
async def test_bounded_read_and_response_metadata_reject_malformed_adapter_output(
    response: _Response,
) -> None:
    """Allocating or accepting an unbounded/non-contract response crosses the strict boundary."""
    with _serve(lambda _request, _count: response) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverContractError):
            await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "01K00000000000000000000009"),
        ("event_id", "01K00000000000000000000009"),
        ("sequence", 9),
        ("request_digest", "sha256:" + "f" * 64),
    ],
)
@pytest.mark.asyncio
async def test_decide_rejects_wrong_echoed_request_identity(field: str, value: object) -> None:
    """Applying a response to the wrong request would break event attribution."""

    def responder(request: _RecordedRequest, _: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        response = _success_data(request)
        response[field] = value
        return _Response(chunks=(_json_bytes(response),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        with pytest.raises(DriverContractError, match="RESPONSE_MISMATCH"):
            await driver.decide(_request())


@pytest.mark.asyncio
async def test_redirect_is_not_followed_and_transport_failure_is_not_retried() -> None:
    """Following or retrying can replay an authenticated event without protocol authority."""

    def redirect(request: _RecordedRequest, _: int) -> _Response:
        return _Response(status=307, headers={**JSON_HEADERS, "Location": "/elsewhere"})

    with _serve(redirect) as redirect_server:
        driver = LoopbackHttpAgentDriver(_origin(redirect_server), TOKEN)
        with pytest.raises(DriverContractError, match="REDIRECT_RESPONSE"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))
    assert len(redirect_server.requests) == 1

    def disconnect(_request: _RecordedRequest, _count: int) -> _Response:
        return _Response(close_without_response=True)

    with _serve(disconnect) as disconnect_server:
        driver = LoopbackHttpAgentDriver(_origin(disconnect_server), TOKEN)
        with pytest.raises(DriverIncompleteError, match="TRANSPORT_LOSS"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))
    assert len(disconnect_server.requests) == 1


@pytest.mark.asyncio
async def test_timeout_is_incomplete_and_not_retried() -> None:
    """A wall timeout is absence of evidence, never a target verdict or replay permission."""
    response = _Response(chunks=(_json_bytes(_ready_data()),), delay_seconds=0.2)

    with _serve(lambda _request, _count: response) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN, timeout_seconds=0.03)
        with pytest.raises(DriverIncompleteError, match="TIMEOUT"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_timeout_is_a_wall_deadline_even_when_response_bytes_keep_arriving() -> None:
    """Slow drip traffic must not extend a decision beyond the configured wall deadline."""
    body = _json_bytes(_ready_data())
    response = _Response(
        chunks=tuple(body[index : index + 16] for index in range(0, len(body), 16)),
        chunk_delay_seconds=0.02,
    )

    with _serve(lambda _request, _count: response) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN, timeout_seconds=0.08)
        started = time.monotonic()
        with pytest.raises(DriverIncompleteError, match="TIMEOUT"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))
        elapsed = time.monotonic() - started

    assert elapsed < 0.35
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_set_cookie_is_rejected_without_persisting_it_to_a_later_request() -> None:
    """A rejected response must not seed ambient cookie state for later authenticated calls."""

    def responder(_request: _RecordedRequest, count: int) -> _Response:
        headers = {**JSON_HEADERS, **({"Set-Cookie": "session=secret"} if count == 1 else {})}
        return _Response(headers=headers, chunks=(_json_bytes(_ready_data()),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverContractError, match="COOKIE_RESPONSE"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))
        await driver.ready(resolve_test_profile("capability-fulfillment"))

    assert "cookie" not in server.requests[1].headers


def _recursive_text(value: object, seen: set[int] | None = None) -> str:
    seen = seen or set()
    if id(value) in seen:
        return ""
    seen.add(id(value))
    pieces = [str(value), repr(value)]
    if isinstance(value, BaseException):
        pieces.extend(_recursive_text(item, seen) for item in value.args)
        pieces.append(_recursive_text(value.__context__, seen))
        pieces.append(_recursive_text(value.__cause__, seen))
        pieces.append(_recursive_text(vars(value), seen))
    elif isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        for key, item in mapping.items():
            pieces.append(_recursive_text(key, seen))
            pieces.append(_recursive_text(item, seen))
    elif isinstance(value, (list, tuple, set)):
        iterable = cast("Iterable[object]", value)
        pieces.extend(_recursive_text(item, seen) for item in iterable)
    return "\n".join(pieces)


def _traceback_locals_text(error: BaseException) -> str:
    pieces: list[str] = []
    traceback = error.__traceback__
    while traceback is not None:
        for name, value in traceback.tb_frame.f_locals.items():
            pieces.append(f"{name}={value!r}")
        traceback = traceback.tb_next
    return "\n".join(pieces)


@pytest.mark.asyncio
async def test_failure_tracebacks_retain_no_bearer_or_remote_response_state() -> None:
    """Sanitized errors must be raised only after all secret-bearing frames have returned."""

    def responder(_request: _RecordedRequest, count: int) -> _Response:
        if count == 1:
            data = _ready_error_data("ADAPTER_INTERNAL")
            data["adapter_instance_id"] = REMOTE_MODEL_CANARY
            data["error"]["message"] = f"{TOKEN}-{REMOTE_RESPONSE_CANARY}"
            return _Response(status=500, chunks=(_json_bytes(data),))
        return _Response(close_without_response=True)

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        for expected_code in ("ADAPTER_INTERNAL", "TRANSPORT_LOSS"):
            try:
                await driver.ready(resolve_test_profile("capability-fulfillment"))
            except DriverIncompleteError as exc:
                assert exc.code == expected_code
                traceback_text = _traceback_locals_text(exc)
                assert TOKEN not in traceback_text
                assert REMOTE_RESPONSE_CANARY not in traceback_text
                assert REMOTE_MODEL_CANARY not in traceback_text
            else:
                raise AssertionError("failure response was accepted")


@pytest.mark.parametrize("payload_kind", ["huge_integer", "deep_json"])
@pytest.mark.asyncio
async def test_pathological_valid_json_is_a_sanitized_malformed_response(
    payload_kind: str,
) -> None:
    """Bounded parser limits cannot bypass the safe driver-contract failure boundary."""

    def responder(request: _RecordedRequest, _count: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        canary = json.dumps(f"{TOKEN}-{REMOTE_RESPONSE_CANARY}").encode()
        if payload_kind == "huge_integer":
            body = b'{"canary":' + canary + b',"value":' + (b"9" * 5000) + b"}"
        else:
            body = (
                b'{"canary":'
                + canary
                + b',"value":'
                + (b"[" * 10000)
                + b"0"
                + (b"]" * 10000)
                + b"}"
            )
        return _Response(chunks=(body,))

    caught: BaseException | None = None
    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        try:
            await driver.decide(_request())
        except BaseException as exc:  # cancellation is asserted separately below
            caught = exc

    if caught is None:
        raise AssertionError("pathological JSON response was accepted")
    traceback_text = _traceback_locals_text(caught)
    diagnostic = (
        type(caught).__name__,
        TOKEN in traceback_text,
        REMOTE_RESPONSE_CANARY in traceback_text,
        caught.__context__ is not None,
        caught.__cause__ is not None,
    )
    assert diagnostic == (
        "DriverContractError",
        False,
        False,
        False,
        False,
    ), f"safe diagnostic mismatch: {diagnostic!r}"
    assert isinstance(caught, DriverContractError)
    assert caught.code == "MALFORMED_RESPONSE"
    assert TOKEN not in _recursive_text(caught)
    assert REMOTE_RESPONSE_CANARY not in _recursive_text(caught)


@pytest.mark.asyncio
async def test_cancellation_preserves_native_state_without_sensitive_traceback_locals() -> None:
    """Cancellation must unwind bearer, raw-response, and parsed-model frames before resurfacing."""
    first_chunk_sent = threading.Event()

    def responder(request: _RecordedRequest, _: int) -> _Response:
        if request.path.endswith("/ready"):
            data = _ready_data(adapter_instance_id=REMOTE_MODEL_CANARY)
            return _Response(chunks=(_json_bytes(data),))
        data = _success_data(request, instance=REMOTE_MODEL_CANARY)
        data["unexpected"] = REMOTE_RESPONSE_CANARY
        body = _json_bytes(data)
        split = body.index(REMOTE_RESPONSE_CANARY.encode()) + len(REMOTE_RESPONSE_CANARY)
        return _Response(
            chunks=(body[:split], body[split:]),
            chunk_delay_seconds=0.2,
            first_chunk_sent=first_chunk_sent,
        )

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        task = asyncio.create_task(driver.decide(_request()))
        assert await asyncio.to_thread(first_chunk_sent.wait, 2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError as exc:
            traceback_text = _traceback_locals_text(exc)
            assert TOKEN not in traceback_text
            assert REMOTE_RESPONSE_CANARY not in traceback_text
            assert REMOTE_MODEL_CANARY not in traceback_text
        else:
            raise AssertionError("cancelled driver task returned normally")

    assert task.cancelled()


@pytest.mark.asyncio
async def test_successful_readiness_rejects_bearer_echo_before_public_model() -> None:
    """A hostile adapter cannot turn the configured bearer into public readiness metadata."""
    with _serve(
        lambda _request, _count: _Response(
            chunks=(_json_bytes(_ready_data(adapter_instance_id=TOKEN)),)
        )
    ) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE") as caught:
            await driver.ready(resolve_test_profile("capability-fulfillment"))

    assert TOKEN not in _recursive_text(caught.value)
    assert TOKEN not in _traceback_locals_text(caught.value)


@pytest.mark.parametrize("placement", ["prefix", "suffix"])
@pytest.mark.asyncio
async def test_successful_readiness_rejects_embedded_bearer_before_public_model(
    placement: str,
) -> None:
    """Adapter metadata cannot wrap the complete bearer in otherwise valid text."""

    def responder(_request: _RecordedRequest, _count: int) -> _Response:
        instance_id = f"adapter:{TOKEN}" if placement == "prefix" else f"{TOKEN}:adapter"
        return _Response(chunks=(_json_bytes(_ready_data(adapter_instance_id=instance_id)),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE") as caught:
            await driver.ready(resolve_test_profile("capability-fulfillment"))

    assert TOKEN not in _recursive_text(caught.value)
    assert TOKEN not in _traceback_locals_text(caught.value)


@pytest.mark.parametrize("placement", ["exact", "prefix", "suffix"])
@pytest.mark.asyncio
async def test_successful_decision_rejects_embedded_bearer_before_public_model(
    placement: str,
) -> None:
    """A successful adapter response cannot route the complete bearer into public state."""
    surfaced: list[object] = []
    caught: DriverContractError | None = None

    def responder(request: _RecordedRequest, _count: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        data = _success_data(request)
        received = json.loads(request.body)
        if received["observation"]["kind"] == "message":
            data["intent"]["text"] = {
                "exact": TOKEN,
                "prefix": f"adapter:{TOKEN}",
                "suffix": f"{TOKEN}:adapter",
            }[placement]
        return _Response(chunks=(_json_bytes(data),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        await driver.decide(_request())
        try:
            response = await driver.decide(_request("driver-message-request.json"))
        except DriverContractError as exc:
            caught = exc
        else:
            surfaced.extend(
                [
                    response,
                    response.model_dump_json(),
                    {"trace": response.intent.model_dump()},
                ]
            )

    assert TOKEN not in _recursive_text(surfaced)
    assert caught is not None
    assert caught.code == "MALFORMED_RESPONSE"
    assert TOKEN not in _recursive_text(caught)
    assert TOKEN not in _traceback_locals_text(caught)


@pytest.mark.asyncio
async def test_deep_successful_decision_secret_rejection_remains_sanitized() -> None:
    """Adapter nesting cannot bypass the safe driver-contract failure boundary."""

    def responder(request: _RecordedRequest, _count: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        data = _success_data(request)
        nested: object = TOKEN
        for _ in range(600):
            nested = [nested]
        data["future"] = nested
        return _Response(chunks=(_json_bytes(data),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE") as caught:
            await driver.decide(_request())

    assert TOKEN not in _recursive_text(caught.value)
    assert TOKEN not in _traceback_locals_text(caught.value)


@pytest.mark.parametrize(
    "response_text",
    [TOKEN[:-1], TOKEN.upper(), "sold:widget:2"],
    ids=["partial", "transformed", "unrelated"],
)
@pytest.mark.asyncio
async def test_nonmatching_successful_decision_text_remains_available(response_text: str) -> None:
    """The secret guard must not broaden to partial, transformed, or unrelated strings."""

    def responder(request: _RecordedRequest, _count: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        data = _success_data(request)
        received = json.loads(request.body)
        if received["observation"]["kind"] == "message":
            data["intent"]["text"] = response_text
        return _Response(chunks=(_json_bytes(data),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        await driver.ready(resolve_test_profile("capability-fulfillment"))
        await driver.decide(_request())
        response = await driver.decide(_request("driver-message-request.json"))

    assert response.intent.kind == "send_to_sender"
    assert response.intent.text == response_text


@pytest.mark.asyncio
async def test_bearer_echo_cannot_reach_result_driver_path() -> None:
    """Result metadata must never be constructed from echoed bearer readiness state."""
    with _serve(
        lambda _request, _count: _Response(
            chunks=(_json_bytes(_ready_data(adapter_instance_id=TOKEN)),)
        )
    ) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        try:
            readiness = await driver.ready(resolve_test_profile("capability-fulfillment"))
            result_driver = ResultDriver(
                contract="town-agent-driver/1",
                kind="loopback-http",
                adapter_instance_id=readiness.ready.adapter_instance_id,
                endpoint_origin=driver.endpoint_origin,
            )
        except DriverContractError as exc:
            assert exc.code == "MALFORMED_RESPONSE"
            assert TOKEN not in _recursive_text(exc)
        else:
            assert TOKEN not in result_driver.model_dump_json()


@pytest.mark.parametrize("placement", ["prefix", "suffix"])
@pytest.mark.asyncio
async def test_embedded_bearer_cannot_reach_result_driver_serialization(placement: str) -> None:
    """Result metadata cannot serialize an adapter instance containing the complete bearer."""

    def responder(_request: _RecordedRequest, _count: int) -> _Response:
        instance_id = f"adapter:{TOKEN}" if placement == "prefix" else f"{TOKEN}:adapter"
        return _Response(chunks=(_json_bytes(_ready_data(adapter_instance_id=instance_id)),))

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        try:
            readiness = await driver.ready(resolve_test_profile("capability-fulfillment"))
            result_driver = ResultDriver(
                contract="town-agent-driver/1",
                kind="loopback-http",
                adapter_instance_id=readiness.ready.adapter_instance_id,
                endpoint_origin=driver.endpoint_origin,
            )
        except DriverContractError as exc:
            assert exc.code == "MALFORMED_RESPONSE"
            assert TOKEN not in _recursive_text(exc)
            assert TOKEN not in _traceback_locals_text(exc)
        else:
            assert TOKEN not in result_driver.model_dump_json()


@pytest.mark.asyncio
async def test_request_time_origin_revalidation_rejects_private_mutation_without_transport() -> (
    None
):
    """Even adversarial private mutation must fail before the bearer reaches a socket."""
    with _serve(_standard_responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        object.__setattr__(driver, "_endpoint_origin", f"https://127.0.0.1:{server.server_port}")
        with pytest.raises(DriverConfigurationError, match="INVALID_ENDPOINT"):
            await driver.ready(resolve_test_profile("capability-fulfillment"))

    assert server.requests == []


@pytest.mark.asyncio
async def test_secret_canary_never_reaches_errors_diagnostics_digests_or_models() -> None:
    """Echoing the bearer from a hostile adapter must not leak it through surfaced state."""
    surfaced: list[object] = ["", ""]  # stdout/stderr surrogates

    def responder(request: _RecordedRequest, _: int) -> _Response:
        if request.path.endswith("/ready"):
            return _Response(chunks=(_json_bytes(_ready_data()),))
        return _Response(
            status=500,
            chunks=(_json_bytes(_error_data(request, "ADAPTER_INTERNAL", message=TOKEN)),),
        )

    with _serve(responder) as server:
        driver = LoopbackHttpAgentDriver(_origin(server), TOKEN)
        readiness = await driver.ready(resolve_test_profile("capability-fulfillment"))
        request = _request()
        try:
            await driver.decide(request)
        except DriverIncompleteError as exc:
            surfaced.append(exc)
        else:
            raise AssertionError("malicious error response was accepted")

    request_digest = "sha256:" + hashlib.sha256(server.requests[-1].body).hexdigest()
    surfaced.extend(
        [
            request_digest,
            readiness.model_dump_json(),
            request.model_dump_json(),
        ]
    )
    assert TOKEN not in _recursive_text(surfaced)
