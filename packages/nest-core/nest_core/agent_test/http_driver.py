# SPDX-License-Identifier: Apache-2.0
"""Strict authenticated HTTP transport for the local AgentDriver boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Never, cast

import httpx
from pydantic import Field, ValidationError

from .driver import (
    AgentDriverError,
    DriverCompatibilityError,
    DriverConfigurationError,
    DriverContractError,
    DriverIncompleteError,
    TownDriverError,
)
from .models import (
    AdapterInstanceId,
    Digest,
    DriverError,
    DriverReadiness,
    DriverReady,
    DriverRequest,
    DriverResponse,
    EffectiveDriverLimits,
    ProfileId,
    ProfileReference,
    ReadyLimits,
    SafeText128,
    StrictModel,
    VersionId,
)
from .profile_codecs import BoundProfileCodec
from .profiles import ResolvedTestProfile, capability_profile_document

_CONTRACT = "town-agent-driver/1"
_READY_PATH = "/town-driver/1/ready"
_DECIDE_PATH = "/town-driver/1/decide"
_TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z")
_ORIGIN_RE = re.compile(r"http://(?:127\.0\.0\.1|\[::1\]):([0-9]+)\Z")


@dataclass(frozen=True, slots=True)
class _SafeFailure:
    error_type: type[AgentDriverError]
    code: str


@dataclass(frozen=True, slots=True)
class _ReadySuccess:
    readiness: DriverReadiness
    profile: ProfileReference
    codec: BoundProfileCodec


@dataclass(frozen=True, slots=True)
class _ReadyOutcome:
    success: _ReadySuccess | None = None
    failure: _SafeFailure | None = None
    cancelled: bool = False


@dataclass(frozen=True, slots=True)
class _DecideOutcome:
    success: DriverResponse | None = None
    failure: _SafeFailure | None = None
    cancelled: bool = False


@dataclass(frozen=True, slots=True)
class _Cancelled:
    pass


_CANCELLED = _Cancelled()


class _ReadinessProfileIdentity(StrictModel):
    id: ProfileId
    version: VersionId
    digest: Digest


class _ReadinessShape(StrictModel):
    schema_version: SafeText128
    adapter_instance_id: AdapterInstanceId
    contracts: list[SafeText128] = Field(min_length=1)
    profiles: list[_ReadinessProfileIdentity] = Field(min_length=1)
    accepting_runs: bool
    limits: ReadyLimits


def parse_loopback_origin(origin: str) -> str:
    """Accept only an exact canonical loopback HTTP origin with a valid port."""
    matched = _ORIGIN_RE.fullmatch(origin)
    if matched is None:
        raise ValueError("endpoint must be a canonical loopback HTTP origin with explicit port")
    port = int(matched.group(1))
    if not 1 <= port <= 65535:
        raise ValueError("endpoint must be a canonical loopback HTTP origin with explicit port")
    return origin


class LoopbackHttpAgentDriver:
    """One-shot HTTP clients with strict request and response validation."""

    def __init__(self, endpoint_origin: str, token: str, *, timeout_seconds: float = 60.0) -> None:
        self._endpoint_origin = parse_loopback_origin(endpoint_origin)
        if _TOKEN_RE.fullmatch(token) is None:
            raise ValueError("bearer token must be exactly 64 lowercase hexadecimal characters")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._profile: ProfileReference | None = None
        self._profile_codec: BoundProfileCodec | None = None
        self._readiness: DriverReadiness | None = None
        self._admitted_run_id: str | None = None
        self._closed = False

    @property
    def endpoint_origin(self) -> str:
        """Return the validated read-only adapter origin."""
        return self._endpoint_origin

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(endpoint_origin={self.endpoint_origin!r}, "
            f"timeout_seconds={self._timeout_seconds!r})"
        )

    async def ready(self, profile: ResolvedTestProfile) -> DriverReadiness:
        self._require_open()
        outcome = await self._ready_outcome(profile)
        if outcome.cancelled:
            _raise_sanitized_cancellation()
        if outcome.failure is not None:
            _raise_sanitized_failure(outcome.failure)
        success = outcome.success
        if success is None:
            raise AssertionError("readiness produced no outcome")
        self._profile = success.profile
        self._profile_codec = success.codec
        self._readiness = success.readiness
        return success.readiness

    async def _ready_outcome(self, profile: ResolvedTestProfile) -> _ReadyOutcome:
        try:
            success = await self._ready_sensitive(profile)
        except AgentDriverError as error:
            return _ReadyOutcome(failure=_SafeFailure(type(error), error.code))
        if isinstance(success, _Cancelled):
            return _ReadyOutcome(cancelled=True)
        return _ReadyOutcome(success=success)

    async def _ready_sensitive(self, profile: ResolvedTestProfile) -> _ReadySuccess | _Cancelled:
        profile_document = capability_profile_document(profile)
        profile_reference = profile.reference
        profile_codec = profile.codec
        if self._profile_codec is not None and self._profile_codec != profile_codec:
            raise DriverCompatibilityError("PROFILE_CONTEXT_CHANGED")
        exchange = await self._exchange_with_status(
            method="GET",
            path=_READY_PATH,
            body=None,
            response_limit=profile_document.driver.max_http_body_bytes,
        )
        if isinstance(exchange, _Cancelled):
            return exchange
        status, body = exchange
        if status != 200:
            self._raise_ready_http_error(status, body)
            raise AssertionError("typed readiness HTTP error mapper returned")
        data = _json_object(body, "MALFORMED_RESPONSE")
        shape = _validate_readiness_shape(data)
        if self._token in shape.adapter_instance_id:
            raise DriverContractError("MALFORMED_RESPONSE")
        self._check_readiness_identity(shape, profile_reference)
        ready = _validate_ready(data)
        if (
            self._admitted_run_id is not None
            and self._readiness is not None
            and ready.adapter_instance_id != self._readiness.ready.adapter_instance_id
        ):
            raise DriverIncompleteError("ADAPTER_INSTANCE_CHANGED")
        effective = EffectiveDriverLimits(
            max_request_bytes=min(
                profile_document.driver.max_http_body_bytes, ready.limits.max_request_bytes
            ),
            max_response_bytes=min(
                profile_document.driver.max_http_body_bytes, ready.limits.max_response_bytes
            ),
        )
        readiness = DriverReadiness(ready=ready, effective_limits=effective)
        return _ReadySuccess(
            readiness=readiness,
            profile=profile_reference,
            codec=profile_codec,
        )

    async def decide(self, request: DriverRequest) -> DriverResponse:
        self._require_open()
        outcome = await self._decide_outcome(request)
        if outcome.cancelled:
            _raise_sanitized_cancellation()
        if outcome.failure is not None:
            _raise_sanitized_failure(outcome.failure)
        response = outcome.success
        if response is None:
            raise AssertionError("decision produced no outcome")
        if request.observation.kind == "start":
            self._admitted_run_id = request.run_id
        return response

    async def _decide_outcome(self, request: DriverRequest) -> _DecideOutcome:
        try:
            response = await self._decide_sensitive(request)
        except AgentDriverError as error:
            return _DecideOutcome(failure=_SafeFailure(type(error), error.code))
        if isinstance(response, _Cancelled):
            return _DecideOutcome(cancelled=True)
        return _DecideOutcome(success=response)

    async def _decide_sensitive(self, request: DriverRequest) -> DriverResponse | _Cancelled:
        readiness = self._readiness
        profile = self._profile
        profile_codec = self._profile_codec
        if readiness is None or profile is None or profile_codec is None:
            raise DriverConfigurationError("NOT_READY")
        if request.profile.model_dump(mode="json") != profile.model_dump(mode="json"):
            raise TownDriverError("PROFILE_MISMATCH")
        try:
            request = cast(
                "DriverRequest",
                profile_codec.validate_request(request.model_dump(mode="json")),
            )
        except (AttributeError, ValidationError, ValueError):
            raise TownDriverError("PROFILE_MISMATCH") from None
        if self._admitted_run_id is None and request.observation.kind != "start":
            raise TownDriverError("START_REQUIRED")
        if self._admitted_run_id is not None and request.run_id != self._admitted_run_id:
            raise TownDriverError("RUN_MISMATCH")

        body = request.model_dump_json().encode()
        limits = readiness.effective_limits
        if len(body) > limits.max_request_bytes:
            raise TownDriverError("BODY_TOO_LARGE")
        request_digest = "sha256:" + hashlib.sha256(body).hexdigest()
        exchange = await self._exchange_with_status(
            method="POST",
            path=_DECIDE_PATH,
            body=body,
            request_digest=request_digest,
            response_limit=limits.max_response_bytes,
        )
        if isinstance(exchange, _Cancelled):
            return exchange
        response_status, response_body = exchange
        if response_status != 200:
            self._raise_typed_http_error(
                response_status, response_body, request, request_digest, readiness
            )
            raise AssertionError("typed HTTP error mapper returned")

        data = _json_object(response_body, "MALFORMED_RESPONSE")
        if _contains_complete_secret(data, self._token):
            raise DriverContractError("MALFORMED_RESPONSE")
        response = _validate_response(data, profile_codec)
        if response.adapter_instance_id != readiness.ready.adapter_instance_id:
            raise DriverIncompleteError("ADAPTER_INSTANCE_CHANGED")
        if (
            response.run_id != request.run_id
            or response.event_id != request.event_id
            or response.sequence != request.sequence
            or response.request_digest != request_digest
        ):
            raise DriverContractError("RESPONSE_MISMATCH")
        if response.intent.kind not in request.observation.allowed_intents:
            raise DriverContractError("INTENT_NOT_ALLOWED")
        return response

    async def close(self) -> None:
        self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise DriverConfigurationError("DRIVER_CLOSED")

    async def _exchange_with_status(
        self,
        *,
        method: str,
        path: str,
        body: bytes | None,
        response_limit: int,
        request_digest: str | None = None,
    ) -> tuple[int, bytes] | _Cancelled:
        try:
            endpoint_origin = parse_loopback_origin(self._endpoint_origin)
        except ValueError:
            raise DriverConfigurationError("INVALID_ENDPOINT") from None
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Town-Driver-Contract": _CONTRACT,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            if request_digest is None:
                raise AssertionError("decide request digest is required")
            headers["Town-Request-Digest"] = request_digest

        failure_code: str | None = None
        result: tuple[int, bytes] | None = None
        try:
            transport = httpx.AsyncHTTPTransport(retries=0)
            async with asyncio.timeout(self._timeout_seconds):
                async with (
                    httpx.AsyncClient(
                        transport=transport,
                        trust_env=False,
                        follow_redirects=False,
                        timeout=self._timeout_seconds,
                    ) as client,
                    client.stream(
                        method,
                        endpoint_origin + path,
                        headers=headers,
                        content=body,
                    ) as response,
                ):
                    response_body = await _bounded_response_body(response, response_limit)
                    result = (response.status_code, response_body)
        except asyncio.CancelledError:
            return _CANCELLED
        except (TimeoutError, httpx.TimeoutException):
            failure_code = "TIMEOUT"
        except httpx.TransportError:
            failure_code = "TRANSPORT_LOSS"
        if failure_code is not None:
            raise DriverIncompleteError(failure_code)
        if result is None:
            raise AssertionError("HTTP exchange produced no result")
        return result

    @staticmethod
    def _check_readiness_identity(
        readiness: _ReadinessShape, profile_reference: ProfileReference
    ) -> None:
        if readiness.schema_version != "town-agent-driver-ready/1":
            raise DriverCompatibilityError("UNSUPPORTED_CONTRACT")
        if _CONTRACT not in readiness.contracts:
            raise DriverCompatibilityError("UNSUPPORTED_CONTRACT")
        expected = (profile_reference.id, profile_reference.version, profile_reference.digest)
        identities = {(item.id, item.version, item.digest) for item in readiness.profiles}
        if expected not in identities:
            raise DriverCompatibilityError("UNSUPPORTED_PROFILE")

    def _raise_typed_http_error(
        self,
        status: int,
        body: bytes,
        request: DriverRequest,
        request_digest: str,
        readiness: DriverReadiness,
    ) -> None:
        data = _json_object(body, "MALFORMED_ERROR_RESPONSE")
        error = _validate_error(data)
        code = error.error.code
        expected_status = {
            "AUTHENTICATION_FAILED": 401,
            "RUN_BUSY": 409,
            "EVENT_CONFLICT": 409,
            "OUT_OF_ORDER": 409,
            "BODY_TOO_LARGE": 413,
            "UNSUPPORTED_CONTRACT": 422,
            "UNSUPPORTED_PROFILE": 422,
            "SCHEMA_INVALID": 422,
            "ADAPTER_INTERNAL": 500,
        }[code]
        if status != expected_status:
            raise DriverContractError("STATUS_CODE_MISMATCH")
        if code != "AUTHENTICATION_FAILED":
            if (
                error.run_id != request.run_id
                or error.event_id != request.event_id
                or error.sequence != request.sequence
                or error.request_digest != request_digest
            ):
                raise DriverContractError("ERROR_RESPONSE_MISMATCH")
            if error.adapter_instance_id is None:
                raise DriverContractError("ERROR_RESPONSE_MISMATCH")
            if error.adapter_instance_id != readiness.ready.adapter_instance_id:
                raise DriverIncompleteError("ADAPTER_INSTANCE_CHANGED")

        if code == "AUTHENTICATION_FAILED":
            error_type = (
                DriverConfigurationError if self._admitted_run_id is None else DriverIncompleteError
            )
        elif code in {"RUN_BUSY", "ADAPTER_INTERNAL"}:
            error_type = DriverIncompleteError
        elif code in {"EVENT_CONFLICT", "OUT_OF_ORDER", "BODY_TOO_LARGE"}:
            error_type = DriverContractError
        elif code in {"UNSUPPORTED_CONTRACT", "UNSUPPORTED_PROFILE"}:
            error_type = (
                DriverCompatibilityError if self._admitted_run_id is None else DriverContractError
            )
        else:
            error_type = TownDriverError
        raise error_type(code)

    def _raise_ready_http_error(self, status: int, body: bytes) -> None:
        data = _json_object(body, "MALFORMED_ERROR_RESPONSE")
        error = _validate_error(data)
        code = error.error.code
        expected_status = {
            "AUTHENTICATION_FAILED": 401,
            "RUN_BUSY": 409,
            "EVENT_CONFLICT": 409,
            "OUT_OF_ORDER": 409,
            "BODY_TOO_LARGE": 413,
            "UNSUPPORTED_CONTRACT": 422,
            "UNSUPPORTED_PROFILE": 422,
            "SCHEMA_INVALID": 422,
            "ADAPTER_INTERNAL": 500,
        }[code]
        if status != expected_status:
            raise DriverContractError("STATUS_CODE_MISMATCH")
        if any(
            value is not None
            for value in (error.run_id, error.event_id, error.sequence, error.request_digest)
        ):
            raise DriverContractError("ERROR_RESPONSE_MISMATCH")
        if code != "AUTHENTICATION_FAILED":
            if error.adapter_instance_id is None:
                raise DriverContractError("ERROR_RESPONSE_MISMATCH")
            if (
                self._admitted_run_id is not None
                and self._readiness is not None
                and error.adapter_instance_id != self._readiness.ready.adapter_instance_id
            ):
                raise DriverIncompleteError("ADAPTER_INSTANCE_CHANGED")
        if code == "AUTHENTICATION_FAILED":
            error_type = (
                DriverConfigurationError if self._admitted_run_id is None else DriverIncompleteError
            )
        elif code in {"UNSUPPORTED_CONTRACT", "UNSUPPORTED_PROFILE"}:
            error_type = (
                DriverCompatibilityError if self._admitted_run_id is None else DriverContractError
            )
        elif code in {"RUN_BUSY", "ADAPTER_INTERNAL"}:
            error_type = DriverIncompleteError
        elif code == "SCHEMA_INVALID":
            error_type = TownDriverError
        else:
            error_type = DriverContractError
        raise error_type(code)


async def _bounded_response_body(response: httpx.Response, limit: int) -> bytes:
    if 300 <= response.status_code <= 399:
        raise DriverContractError("REDIRECT_RESPONSE")
    if response.headers.get("content-type") != "application/json":
        raise DriverContractError("CONTENT_TYPE_RESPONSE")
    if response.headers.get("town-driver-contract") != _CONTRACT:
        raise DriverContractError("CONTRACT_HEADER_RESPONSE")
    if "set-cookie" in response.headers:
        raise DriverContractError("COOKIE_RESPONSE")
    content_encoding = response.headers.get("content-encoding")
    if content_encoding not in {None, "identity"}:
        raise DriverContractError("COMPRESSED_RESPONSE")
    length_text = response.headers.get("content-length")
    if length_text is not None:
        try:
            content_length = int(length_text)
        except ValueError:
            content_length = -1
        if content_length < 0:
            raise DriverContractError("INVALID_CONTENT_LENGTH")
        if content_length > limit:
            raise DriverContractError("RESPONSE_TOO_LARGE")

    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_raw():
        size += len(chunk)
        if size > limit:
            raise DriverContractError("RESPONSE_TOO_LARGE")
        chunks.append(chunk)
    return b"".join(chunks)


def _json_object(body: bytes, error_code: str) -> dict[str, object]:
    parsed: object | None = None
    invalid = False
    try:
        parsed = json.loads(body)
    except (ValueError, RecursionError):
        invalid = True
    if invalid or not isinstance(parsed, dict):
        raise DriverContractError(error_code)
    return cast("dict[str, object]", parsed)


def _contains_complete_secret(value: object, secret: str) -> bool:
    pending: list[object] = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if secret in current:
                return True
        elif isinstance(current, dict):
            mapping = cast("dict[object, object]", current)
            for key, item in mapping.items():
                pending.extend((key, item))
        elif isinstance(current, list):
            pending.extend(cast("list[object]", current))
    return False


def _raise_sanitized_failure(failure: _SafeFailure) -> Never:
    raise failure.error_type(failure.code)


def _raise_sanitized_cancellation() -> Never:
    raise asyncio.CancelledError


def _validate_ready(data: dict[str, object]) -> DriverReady:
    value: DriverReady | None = None
    invalid = False
    try:
        value = DriverReady.model_validate(data)
    except ValidationError:
        invalid = True
    if invalid or value is None:
        raise DriverContractError("MALFORMED_RESPONSE")
    return value


def _validate_readiness_shape(data: dict[str, object]) -> _ReadinessShape:
    value: _ReadinessShape | None = None
    invalid = False
    try:
        value = _ReadinessShape.model_validate(data)
    except ValidationError:
        invalid = True
    if invalid or value is None:
        raise DriverContractError("MALFORMED_RESPONSE")
    return value


def _validate_response(data: dict[str, object], profile_codec: BoundProfileCodec) -> DriverResponse:
    value: DriverResponse | None = None
    invalid = False
    try:
        value = cast("DriverResponse", profile_codec.validate_response(data))
    except (ValidationError, ValueError):
        invalid = True
    if invalid or value is None:
        raise DriverContractError("MALFORMED_RESPONSE")
    return value


def _validate_error(data: dict[str, object]) -> DriverError:
    value: DriverError | None = None
    invalid = False
    try:
        value = DriverError.model_validate(data)
    except ValidationError:
        invalid = True
    if invalid or value is None:
        raise DriverContractError("MALFORMED_ERROR_RESPONSE")
    return value
