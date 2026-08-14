#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Minimal deterministic local adapter for NANDA Town's frozen Generation 1 profile.

Generation 1 is the first frozen agent-test contract/profile generation, not a
Town or nest-core 1.0 release.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

CONTRACT = "town-agent-driver/1"
TOKEN_ENV = "TOWN_AGENT_TOKEN"
ADAPTER_INSTANCE_ID = "town-reference-adapter"
PROFILE = {
    "id": "nanda/agent/capability-fulfillment",
    "version": "1",
    "digest": "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58",
}
MAX_BODY_BYTES = 65536
_TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z")
_ULID_RE = re.compile(r"[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}\Z")
_PROFILE_ID_RE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class _UnsupportedProfileError(ValueError):
    pass


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _error_payload(
    code: str,
    message: str,
    *,
    adapter_instance_id: str | None = ADAPTER_INSTANCE_ID,
    run_id: str | None = None,
    event_id: str | None = None,
    sequence: int | None = None,
    request_digest: str | None = None,
    retryable: bool = False,
) -> bytes:
    return _json_bytes(
        {
            "schema_version": "town-agent-driver-error/1",
            "adapter_instance_id": adapter_instance_id,
            "run_id": run_id,
            "event_id": event_id,
            "sequence": sequence,
            "request_digest": request_digest,
            "error": {"code": code, "retryable": retryable, "message": message},
        }
    )


class _ReferenceServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], token_digest: bytes) -> None:
        super().__init__(address, _ReferenceHandler)
        self._token_digest = token_digest
        self._state_lock = threading.Lock()
        self._active_run_id: str | None = None
        self._expected_sequence: dict[str, int] = {}
        self._event_digests: dict[tuple[str, str], str] = {}
        self._successes: dict[tuple[str, str], tuple[str, bytes]] = {}

    def is_authorized(self, header: str | None) -> bool:
        if header is None or not header.startswith("Bearer "):
            return False
        candidate = header.removeprefix("Bearer ")
        if _TOKEN_RE.fullmatch(candidate) is None:
            return False
        digest = hashlib.sha256(candidate.encode("ascii")).digest()
        return hmac.compare_digest(digest, self._token_digest)

    def readiness_bytes(self) -> bytes:
        with self._state_lock:
            accepting_runs = self._active_run_id is None
        return _json_bytes(
            {
                "schema_version": "town-agent-driver-ready/1",
                "adapter_instance_id": ADAPTER_INSTANCE_ID,
                "contracts": [CONTRACT],
                "profiles": [PROFILE],
                "accepting_runs": accepting_runs,
                "limits": {
                    "max_active_runs": 1,
                    "max_request_bytes": MAX_BODY_BYTES,
                    "max_response_bytes": MAX_BODY_BYTES,
                },
            }
        )

    def decide(self, request: dict[str, Any], request_digest: str) -> tuple[int, bytes]:
        context = _request_context(request, request_digest)
        if context is None:
            return 422, _error_payload("SCHEMA_INVALID", "Request schema is invalid")
        run_id, event_id, sequence = context
        key = (run_id, event_id)
        with self._state_lock:
            bound_digest = self._event_digests.get(key)
            if bound_digest is not None and bound_digest != request_digest:
                return 409, self._request_error(
                    "EVENT_CONFLICT",
                    "Event ID was reused with different request bytes",
                    run_id,
                    event_id,
                    sequence,
                    request_digest,
                )
            cached = self._successes.get(key)
            if cached is not None:
                cached_digest, cached_response = cached
                if cached_digest == request_digest:
                    return 200, cached_response
                return 409, self._request_error(
                    "EVENT_CONFLICT",
                    "Event ID was reused with different request bytes",
                    run_id,
                    event_id,
                    sequence,
                    request_digest,
                )

            try:
                kind = _validated_kind(request)
            except _UnsupportedProfileError:
                return 422, self._request_error(
                    "UNSUPPORTED_PROFILE",
                    "Test Profile is unsupported",
                    run_id,
                    event_id,
                    sequence,
                    request_digest,
                )
            if kind is None:
                return 422, self._request_error(
                    "SCHEMA_INVALID",
                    "Request does not match the frozen profile",
                    run_id,
                    event_id,
                    sequence,
                    request_digest,
                )
            self._event_digests[key] = request_digest
            observation = request["observation"]
            assert isinstance(observation, dict)
            is_sequence_two_abort = (
                kind == "stop"
                and self._active_run_id == run_id
                and self._expected_sequence.get(run_id) == 1
                and sequence == 2
                and observation["reason"] in {"run_failed", "run_incomplete", "user_interrupted"}
            )
            if kind == "start":
                if self._active_run_id is not None and self._active_run_id != run_id:
                    return 409, self._request_error(
                        "RUN_BUSY",
                        "The reference adapter already has one active run",
                        run_id,
                        event_id,
                        sequence,
                        request_digest,
                        retryable=True,
                    )
                if self._active_run_id == run_id or run_id in self._expected_sequence:
                    return 409, self._request_error(
                        "OUT_OF_ORDER",
                        "Expected the next event in the active run",
                        run_id,
                        event_id,
                        sequence,
                        request_digest,
                    )
            elif not is_sequence_two_abort and (
                self._active_run_id != run_id or self._expected_sequence.get(run_id) != sequence
            ):
                return 409, self._request_error(
                    "OUT_OF_ORDER",
                    "Expected the next event in the active run",
                    run_id,
                    event_id,
                    sequence,
                    request_digest,
                )

            try:
                intent = {"kind": "none"} if kind == "stop" else decide_intent(observation)
                response = _json_bytes(
                    {
                        "schema_version": CONTRACT,
                        "run_id": run_id,
                        "event_id": event_id,
                        "sequence": sequence,
                        "adapter_instance_id": ADAPTER_INSTANCE_ID,
                        "request_digest": request_digest,
                        "intent": intent,
                    }
                )
            except Exception:
                return 500, self._request_error(
                    "ADAPTER_INTERNAL",
                    "Adapter decision failed",
                    run_id,
                    event_id,
                    sequence,
                    request_digest,
                    retryable=True,
                )

            if kind == "start":
                self._active_run_id = run_id
                self._expected_sequence[run_id] = 1
            elif kind == "message":
                self._expected_sequence[run_id] = 2
            else:
                self._expected_sequence[run_id] = sequence + 1
                self._active_run_id = None
            self._successes[key] = (request_digest, response)
            return 200, response

    @staticmethod
    def _request_error(
        code: str,
        message: str,
        run_id: str,
        event_id: str,
        sequence: int,
        request_digest: str,
        *,
        retryable: bool = False,
    ) -> bytes:
        return _error_payload(
            code,
            message,
            run_id=run_id,
            event_id=event_id,
            sequence=sequence,
            request_digest=request_digest,
            retryable=retryable,
        )


class _ReferenceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def adapter(self) -> _ReferenceServer:
        assert isinstance(self.server, _ReferenceServer)
        return self.server

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if not self._authenticate():
            return
        if self.path != "/town-driver/1/ready":
            self._send(404, _error_payload("SCHEMA_INVALID", "Request rejected"))
            return
        if not self._common_headers_are_valid():
            self._send(
                422,
                _error_payload("UNSUPPORTED_CONTRACT", "Driver contract is unsupported"),
            )
            return
        self._send(200, self.adapter.readiness_bytes())

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if not self._authenticate():
            return
        if self.path != "/town-driver/1/decide":
            self._send(404, _error_payload("SCHEMA_INVALID", "Request rejected"))
            return
        body = self._read_body()
        if body is None:
            return
        request_digest = "sha256:" + hashlib.sha256(body).hexdigest()
        if not self._common_headers_are_valid():
            self._send(
                422,
                _error_payload("UNSUPPORTED_CONTRACT", "Driver contract is unsupported"),
            )
            return
        if (
            self.headers.get("Content-Type") != "application/json"
            or self.headers.get("Town-Request-Digest") != request_digest
        ):
            self._send(422, _error_payload("SCHEMA_INVALID", "Request framing is invalid"))
            return
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = None
        if not isinstance(parsed, dict):
            self._send(422, _error_payload("SCHEMA_INVALID", "Request schema is invalid"))
            return
        try:
            status, response = self.adapter.decide(parsed, request_digest)
        except Exception:
            context = _request_context(parsed, request_digest)
            if context is None:
                self._send(422, _error_payload("SCHEMA_INVALID", "Request schema is invalid"))
                return
            run_id, event_id, sequence = context
            status = 500
            response = _error_payload(
                "ADAPTER_INTERNAL",
                "Adapter decision failed",
                run_id=run_id,
                event_id=event_id,
                sequence=sequence,
                request_digest=request_digest,
                retryable=True,
            )
        self._send(status, response)

    def _authenticate(self) -> bool:
        if not self.adapter.is_authorized(self.headers.get("Authorization")):
            self._send(
                401,
                _error_payload(
                    "AUTHENTICATION_FAILED",
                    "Authentication failed",
                    adapter_instance_id=None,
                ),
            )
            return False
        return True

    def _common_headers_are_valid(self) -> bool:
        return (
            self.headers.get("Town-Driver-Contract") == CONTRACT
            and self.headers.get("Accept") == "application/json"
            and self.headers.get("Accept-Encoding") == "identity"
        )

    def _read_body(self) -> bytes | None:
        length_text = self.headers.get("Content-Length")
        if length_text is None or not length_text.isdecimal():
            self._send(422, _error_payload("SCHEMA_INVALID", "Content length is invalid"))
            return None
        length = int(length_text)
        if length > MAX_BODY_BYTES:
            self._send(413, _error_payload("BODY_TOO_LARGE", "Request body is too large"))
            return None
        return self.rfile.read(length)

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Town-Driver-Contract", CONTRACT)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _request_context(request: dict[str, Any], request_digest: str) -> tuple[str, str, int] | None:
    run_id = request.get("run_id")
    event_id = request.get("event_id")
    sequence = request.get("sequence")
    if (
        not isinstance(run_id, str)
        or _ULID_RE.fullmatch(run_id) is None
        or not isinstance(event_id, str)
        or _ULID_RE.fullmatch(event_id) is None
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", request_digest)
    ):
        return None
    return run_id, event_id, sequence


def _validated_kind(request: dict[str, Any]) -> str | None:
    if set(request) != {
        "schema_version",
        "run_id",
        "event_id",
        "sequence",
        "participant",
        "profile",
        "observation",
    }:
        return None
    if request["schema_version"] != CONTRACT:
        return None
    profile = request["profile"]
    if not isinstance(profile, dict) or set(profile) != {"id", "version", "digest"}:
        return None
    profile_id = profile.get("id")
    version = profile.get("version")
    digest = profile.get("digest")
    if (
        not isinstance(profile_id, str)
        or len(profile_id) > 128
        or _PROFILE_ID_RE.fullmatch(profile_id) is None
        or not isinstance(version, str)
        or _VERSION_RE.fullmatch(version) is None
        or not isinstance(digest, str)
        or _DIGEST_RE.fullmatch(digest) is None
    ):
        return None
    try:
        validator = _PROFILE_CODECS[(profile_id, version)]
    except KeyError as exc:
        raise _UnsupportedProfileError from exc
    if profile != PROFILE:
        return None
    return validator(request)


def _validated_capability_kind(request: dict[str, Any]) -> str | None:
    if request["participant"] != {"id": "provider-0", "role": "provider"}:
        return None
    observation = request["observation"]
    if not isinstance(observation, dict):
        return None
    logical_time = observation.get("logical_time")
    if not isinstance(logical_time, int) or isinstance(logical_time, bool) or logical_time < 0:
        return None
    sequence = request["sequence"]
    if (
        sequence == 0
        and set(observation) == {"kind", "logical_time", "allowed_intents"}
        and observation["kind"] == "start"
        and observation["allowed_intents"] == ["declare_capability", "none"]
    ):
        return "start"
    if (
        sequence == 1
        and set(observation) == {"kind", "logical_time", "allowed_intents", "message"}
        and observation["kind"] == "message"
        and observation["allowed_intents"] == ["send_to_sender", "none"]
        and observation["message"]
        == {
            "id": "message-001",
            "sender_id": "requester-0",
            "media_type": "text/plain; charset=utf-8",
            "text": "buy:widget:2",
        }
    ):
        return "message"
    if (
        sequence in {1, 2}
        and set(observation) == {"kind", "logical_time", "allowed_intents", "reason"}
        and observation["kind"] == "stop"
        and observation["allowed_intents"] == ["none"]
        and observation["reason"]
        in {"run_complete", "run_failed", "run_incomplete", "user_interrupted"}
        and not (sequence == 1 and observation["reason"] == "run_complete")
    ):
        return "stop"
    return None


_PROFILE_CODECS: dict[tuple[str, str], Callable[[dict[str, Any]], str | None]] = {
    ("nanda/agent/capability-fulfillment", "1"): _validated_capability_kind,
}


def decide_intent(observation: dict[str, Any]) -> dict[str, Any]:
    """Deterministic replace point: map one validated observation to one intent."""
    kind = observation["kind"]
    if kind == "start":
        return {"kind": "declare_capability", "capabilities": ["sell"]}
    if kind == "message":
        return {
            "kind": "send_to_sender",
            "media_type": "text/plain; charset=utf-8",
            "text": "sold:widget:2",
        }
    return {"kind": "none"}


def create_server(*, port: int = 8787) -> ThreadingHTTPServer:
    """Create a literal-loopback server using only the documented token variable."""
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 through 65535")
    token = os.environ.get(TOKEN_ENV)
    if token is None or _TOKEN_RE.fullmatch(token) is None:
        raise RuntimeError(f"{TOKEN_ENV} must contain exactly 64 lowercase hexadecimal characters")
    token_digest = hashlib.sha256(token.encode("ascii")).digest()
    os.environ.pop(TOKEN_ENV)
    del token
    return _ReferenceServer(("127.0.0.1", port), token_digest)


def main(argv: list[str] | None = None) -> int:
    """Run the local reference process without accepting credentials in arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        type=int,
        default=8787,
        help="literal 127.0.0.1 port (default: 8787; use 0 to select a free test port)",
    )
    arguments = parser.parse_args(argv)
    try:
        server = create_server(port=arguments.port)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Reference adapter could not start: {error}", file=sys.stderr)
        return 2
    print(
        f"Reference adapter listening on http://127.0.0.1:{server.server_port}",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
