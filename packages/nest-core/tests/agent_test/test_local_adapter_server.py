# SPDX-License-Identifier: Apache-2.0
"""Boundary tests for the reusable local Generation 1 adapter server."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from http.client import HTTPConnection
from types import MappingProxyType
from typing import Any

import pytest
from nest_core.agent_test.local_adapter_server import (
    AdapterDecisionContext,
    DecisionHook,
    create_local_adapter_server,
)
from nest_core.agent_test.models import DriverError, DriverResponse

TOKEN = "a" * 64
CONTRACT = "town-agent-driver/1"
ADAPTER_INSTANCE_ID = "test-local-adapter"


def _request_data(*, kind: str, sequence: int) -> dict[str, Any]:
    observations: dict[str, dict[str, Any]] = {
        "start": {
            "kind": "start",
            "logical_time": 0,
            "allowed_intents": ["declare_capability", "none"],
        },
        "message": {
            "kind": "message",
            "logical_time": 1,
            "allowed_intents": ["send_to_sender", "none"],
            "message": {
                "id": "message-001",
                "sender_id": "requester-0",
                "media_type": "text/plain; charset=utf-8",
                "text": "buy:widget:2",
            },
        },
        "stop": {
            "kind": "stop",
            "logical_time": 2,
            "allowed_intents": ["none"],
            "reason": "run_complete",
        },
    }
    return {
        "schema_version": CONTRACT,
        "run_id": "01K00000000000000000000001",
        "event_id": {
            "start": "01K00000000000000000000002",
            "message": "01K00000000000000000000003",
            "stop": "01K00000000000000000000004",
        }[kind],
        "sequence": sequence,
        "participant": {"id": "provider-0", "role": "provider"},
        "profile": {
            "id": "nanda/agent/capability-fulfillment",
            "version": "1",
            "digest": "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58",
        },
        "observation": observations[kind],
    }


def _headers(body: bytes) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {TOKEN}",
        "Town-Driver-Contract": CONTRACT,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
        "Town-Request-Digest": "sha256:" + hashlib.sha256(body).hexdigest(),
    }


def _post(port: int, request: dict[str, Any]) -> tuple[int, bytes]:
    body = json.dumps(request, separators=(",", ":")).encode("utf-8")
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request("POST", "/town-driver/1/decide", body=body, headers=_headers(body))
    response = connection.getresponse()
    response_body = response.read()
    connection.close()
    return response.status, response_body


def _assert_token_absent_from_traceback(error: BaseException) -> None:
    traceback = error.__traceback__
    while traceback is not None:
        assert TOKEN not in repr(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next


@contextmanager
def _running_server(
    callback: DecisionHook,
) -> Generator[tuple[int, object], None, None]:
    server = create_local_adapter_server(
        token=TOKEN,
        adapter_instance_id=ADAPTER_INSTANCE_ID,
        decide_intent=callback,
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port), server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_callback_receives_one_run_context_and_stop_is_local_none() -> None:
    """Calling the hook before validation or for stop would break sequencing authority."""
    contexts: list[AdapterDecisionContext] = []

    def decide(
        context: AdapterDecisionContext, observation: Mapping[str, object]
    ) -> Mapping[str, object]:
        contexts.append(context)
        if observation["kind"] == "start":
            return {"kind": "declare_capability", "capabilities": ["sell"]}
        return {
            "kind": "send_to_sender",
            "media_type": "text/plain; charset=utf-8",
            "text": "sold:widget:2",
        }

    with _running_server(decide) as (port, _server):
        start_status, start_body = _post(port, _request_data(kind="start", sequence=0))
        message_status, message_body = _post(port, _request_data(kind="message", sequence=1))
        stop_status, stop_body = _post(port, _request_data(kind="stop", sequence=2))

    assert start_status == message_status == stop_status == 200
    assert [(context.run_id, context.sequence) for context in contexts] == [
        ("01K00000000000000000000001", 0),
        ("01K00000000000000000000001", 1),
    ]
    assert DriverResponse.model_validate_json(start_body).intent.kind == "declare_capability"
    assert DriverResponse.model_validate_json(message_body).intent.kind == "send_to_sender"
    assert DriverResponse.model_validate_json(stop_body).intent.kind == "none"


def test_callback_failure_is_sanitized_and_server_state_never_retains_bearer() -> None:
    """Retaining bearer text or exposing callback details would disclose credentials."""

    def fail(
        _context: AdapterDecisionContext, _observation: Mapping[str, object]
    ) -> Mapping[str, object]:
        raise RuntimeError(f"private decision detail {TOKEN}")

    with _running_server(fail) as (port, server):
        status, body = _post(port, _request_data(kind="start", sequence=0))
        state = repr(server.__dict__)

    error = DriverError.model_validate_json(body)
    assert status == 500
    assert error.error.code == "ADAPTER_INTERNAL"
    assert error.error.message == "Adapter decision failed"
    assert TOKEN not in state
    assert TOKEN.encode() not in body
    assert b"private decision detail" not in body


def test_callback_accepts_a_non_dict_mapping_result() -> None:
    """Passing a valid Mapping to JSON unchanged would reject the advertised hook type."""
    response_intent = MappingProxyType({"kind": "declare_capability", "capabilities": ["sell"]})

    with _running_server(lambda _context, _observation: response_intent) as (port, _server):
        status, body = _post(port, _request_data(kind="start", sequence=0))

    assert status == 200
    assert DriverResponse.model_validate_json(body).intent.model_dump(mode="json") == {
        "kind": "declare_capability",
        "capabilities": ["sell"],
    }


def test_factory_exception_traceback_never_retains_bearer() -> None:
    """An occupied-port failure must not retain the bearer in a factory traceback frame."""
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.bind(("127.0.0.1", 0))
    port = int(occupied.getsockname()[1])
    try:
        with pytest.raises(OSError) as caught:
            create_local_adapter_server(
                token=TOKEN,
                adapter_instance_id=ADAPTER_INSTANCE_ID,
                decide_intent=lambda _context, _observation: {"kind": "none"},
                port=port,
            )
    finally:
        occupied.close()

    _assert_token_absent_from_traceback(caught.value)


def test_shutdown_releases_its_ephemeral_loopback_port() -> None:
    """Leaving a shutdown server bound would make managed local runs leak a listener."""
    server = create_local_adapter_server(
        token=TOKEN,
        adapter_instance_id=ADAPTER_INSTANCE_ID,
        decide_intent=lambda _context, _observation: {"kind": "none"},
        port=0,
    )
    port = int(server.server_port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert _post(port, _request_data(kind="start", sequence=0))[0] == 200
    server.shutdown()
    thread.join(timeout=2)
    assert not thread.is_alive()

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
    finally:
        probe.close()
