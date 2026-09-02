# SPDX-License-Identifier: Apache-2.0
"""Transport-neutral driver protocol and loopback-origin validation tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from nest_core.agent_test.driver import AgentDriver, DriverContractError
from nest_core.agent_test.http_driver import LoopbackHttpAgentDriver, parse_loopback_origin
from nest_core.agent_test.models import (
    DriverError,
    DriverReadiness,
    DriverReady,
    DriverRequest,
    DriverResponse,
    ResultDriver,
)
from nest_core.agent_test.profiles import ResolvedTestProfile, resolve_test_profile
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"


class _ProtocolDriver:
    def __init__(self) -> None:
        self.closed = False

    async def ready(self, profile: ResolvedTestProfile) -> DriverReadiness:
        raise DriverContractError("TEST_READY")

    async def decide(self, request: DriverRequest) -> DriverResponse:
        raise DriverContractError("TEST_DECIDE")

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_agent_driver_protocol_has_http_free_ready_decide_and_best_effort_close() -> None:
    """Changing the driver seam to expose HTTP concepts breaks transport neutrality."""
    implementation = _ProtocolDriver()
    driver = cast("AgentDriver", implementation)

    with pytest.raises(DriverContractError, match="TEST_READY"):
        await driver.ready(resolve_test_profile("capability-fulfillment"))
    with pytest.raises(DriverContractError, match="TEST_DECIDE"):
        await driver.decide(cast("DriverRequest", object()))
    await driver.close()

    assert implementation.closed


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:1",
        "http://127.0.0.1:65535",
        "http://[::1]:8080",
    ],
)
def test_loopback_origin_accepts_only_canonical_literals_with_explicit_ports(origin: str) -> None:
    """Rejecting a canonical explicit-port loopback origin would block the approved boundary."""
    assert parse_loopback_origin(origin) == origin


@pytest.mark.parametrize(
    "origin",
    [
        "localhost:8000",
        "http://localhost:8000",
        "http://example.test:8000",
        "https://127.0.0.1:8000",
        "http://user@127.0.0.1:8000",
        "http://user:pass@127.0.0.1:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:notaport",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1:8000/path",
        "http://127.0.0.1:8000?query=yes",
        "http://127.0.0.1:8000#fragment",
        "http://127.1:8000",
        "http://127.0.1:8000",
        "http://0177.0.0.1:8000",
        "http://2130706433:8000",
        "http://0x7f000001:8000",
        "http://[0:0:0:0:0:0:0:1]:8000",
        "http://[::1%25lo0]:8000",
        "http://::1:8000",
    ],
)
def test_loopback_origin_rejects_every_noncanonical_or_nonorigin_form(origin: str) -> None:
    """Relaxing origin syntax could cross the authenticated local-only boundary."""
    with pytest.raises(ValueError, match="loopback HTTP origin"):
        parse_loopback_origin(origin)


@pytest.mark.parametrize(
    "token",
    [
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "g" * 64,
        "0" * 63 + "-",
    ],
)
def test_driver_rejects_tokens_outside_exact_lowercase_hex_grammar(token: str) -> None:
    """Accepting a weakly shaped bearer value would weaken adapter authentication."""
    with pytest.raises(ValueError, match="bearer token"):
        LoopbackHttpAgentDriver("http://127.0.0.1:8000", token)


def test_driver_repr_never_contains_bearer_token() -> None:
    """Adding the secret to repr would leak it through diagnostics and logs."""
    token = "a1" * 32

    driver = LoopbackHttpAgentDriver("http://127.0.0.1:8000", token)

    assert token not in repr(driver)


def test_validated_endpoint_origin_is_read_only_after_construction() -> None:
    """Ordinary attribute assignment must not retarget an authenticated driver."""
    driver = LoopbackHttpAgentDriver("http://127.0.0.1:8000", "a1" * 32)

    with pytest.raises(AttributeError):
        setattr(driver, "endpoint_origin", "http://127.0.0.1:9000")  # noqa: B010


@pytest.mark.asyncio
async def test_bound_driver_accepts_wire_equal_concrete_profile_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A codec-specific reference must remain equal to its generic readiness identity."""
    driver = LoopbackHttpAgentDriver("http://127.0.0.1:8000", "a1" * 32)
    profile = resolve_test_profile("capability-fulfillment")
    request = DriverRequest.model_validate_json(
        (FIXTURES / "driver-start-request.json").read_bytes()
    )

    async def exchange(**kwargs: Any) -> tuple[int, bytes]:
        if kwargs["method"] == "GET":
            return 200, (FIXTURES / "driver-ready.json").read_bytes()
        response = json.loads((FIXTURES / "driver-start-response.json").read_text())
        body = cast("bytes", kwargs["body"])
        response["request_digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
        return 200, json.dumps(response, separators=(",", ":")).encode()

    monkeypatch.setattr(driver, "_exchange_with_status", exchange)

    await driver.ready(profile)
    response = await driver.decide(request)

    assert response.intent.kind == "declare_capability"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "nanda//agent"),
        ("version", "0/1"),
        ("digest", "sha256:not-a-digest"),
    ],
)
async def test_malformed_readiness_profile_identity_precedes_unsupported_profile(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    """Malformed authenticated identity is a contract error, never compatibility evidence."""
    driver = LoopbackHttpAgentDriver("http://127.0.0.1:8000", "a1" * 32)
    ready = json.loads((FIXTURES / "driver-ready.json").read_text())
    ready["profiles"][0][field] = value

    async def exchange(**_kwargs: Any) -> tuple[int, bytes]:
        return 200, json.dumps(ready, separators=(",", ":")).encode()

    monkeypatch.setattr(driver, "_exchange_with_status", exchange)

    with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE"):
        await driver.ready(resolve_test_profile("capability-fulfillment"))


@pytest.mark.parametrize("instance_id", ["", "a" * 257])
def test_wire_and_result_instance_ids_remain_bounded(instance_id: str) -> None:
    """The shared published-string boundary remains nonempty and bounded."""
    ready = json.loads((FIXTURES / "driver-ready.json").read_text())
    response = json.loads((FIXTURES / "driver-start-response.json").read_text())
    error = json.loads((FIXTURES / "driver-error.json").read_text())
    for model, data in (
        (DriverReady, ready),
        (DriverResponse, response),
        (DriverError, error),
    ):
        data["adapter_instance_id"] = instance_id
        with pytest.raises(ValidationError):
            model.model_validate(data)
    with pytest.raises(ValidationError):
        ResultDriver(
            contract="town-agent-driver/1",
            kind="loopback-http",
            adapter_instance_id=instance_id,
            endpoint_origin="http://127.0.0.1:8787",
        )
