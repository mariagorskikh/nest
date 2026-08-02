# SPDX-License-Identifier: Apache-2.0
"""Nothing this plugin emits may carry key, token or card material.

`find_violations` is a local re-implementation of upstream's
`nest_core.validators._empic_secret_violations`, so these tests hold the
plugin to the same bar the adversarial trace validator applies — without
reaching into a private upstream helper that could move.
"""

from __future__ import annotations

import json

import pytest
from nanda_town_prava import GmpHttpClient, PravaMandates, Principal, RefundNotSupportedError
from nanda_town_prava._redaction import find_violations, redact
from nanda_town_prava.client import EngineHTTPError, EngineTransportError
from nest_sdk import AgentId, Money, PaymentRef, ServiceRef

from .conftest import HostileEngine

SECRET = "sk_" + "live_51H9xQ2eZvKYlo2C"
PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIIBVgIBADAN"


def test_the_local_validator_agrees_with_upstreams_forbidden_key_set() -> None:
    """If upstream's set ever grows, this test is where we find out."""
    from nest_core import validators  # noqa: PLC0415

    upstream = getattr(validators, "_EMPIC_FORBIDDEN_SECRET_KEYS", None)
    if upstream is None:  # pragma: no cover - older nest-core
        pytest.skip("this nest-core has no _EMPIC_FORBIDDEN_SECRET_KEYS")

    from nanda_town_prava._redaction import FORBIDDEN_KEYS  # noqa: PLC0415

    assert set(upstream) <= FORBIDDEN_KEYS, "our set must remain a superset of upstream's"


def test_redact_drops_forbidden_keys_rather_than_masking_them() -> None:
    dirty = {
        "mandate_id": "md_1",
        "api_key": SECRET,
        "nested": [{"wallet_secret": "x", "ok": 1}],
        "authorization": "Bearer abc123",
        "note": f"failed with {SECRET}",
        "pem": PEM,
    }
    clean = redact(dirty)

    assert find_violations(clean) == []
    assert clean["mandate_id"] == "md_1", "non-secret data survives"
    assert "api_key" not in clean
    assert "authorization" not in clean
    assert SECRET not in json.dumps(clean)
    assert "[redacted]" in clean["note"]


async def test_nothing_the_plugin_returns_carries_secret_material() -> None:
    payments = PravaMandates(AgentId("buyer-0"), initial_balance=1000, await_seconds=0.0)

    quote = await payments.quote(ServiceRef("svc"))
    await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    group = await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=300),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh")],
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None

    surfaces = {
        "quote_metadata": quote.metadata,
        "authorization": auth.as_dict(),
        "conservation_report": payments.conservation_report(),
        "group_approval_urls": group.approval_urls,
        "receipt": json.loads(payments._receipts[PaymentRef("p1")].model_dump_json()),  # noqa: SLF001
    }
    for name, surface in surfaces.items():
        assert find_violations(surface, path=name) == [], name


async def test_a_hostile_engine_cannot_push_secrets_into_plugin_state() -> None:
    """The plugin copies named scalars out of a response, never the response."""
    payments = PravaMandates(
        AgentId("buyer-0"),
        initial_balance=1000,
        engine=HostileEngine(),
        await_seconds=0.0,
    )
    await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    await payments.verify_payment(PaymentRef("p1"))

    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert find_violations(auth.as_dict()) == []
    assert SECRET not in json.dumps(auth.as_dict())


def test_the_http_client_never_exposes_its_token() -> None:
    client = GmpHttpClient("http://localhost:4100", token="super-secret-token")

    assert "super-secret-token" not in repr(client)
    assert find_violations({"repr": repr(client)}) == []

    # No public attribute holds it, and it is name-mangled so it is not
    # reachable as `client._token` either. The one copy lives in
    # `_GmpHttpClient__token` and is written to exactly one header.
    public = {k: v for k, v in vars(client).items() if not k.startswith("_")}
    assert "super-secret-token" not in str(public)
    assert not hasattr(client, "_token")
    holders = [k for k, v in vars(client).items() if v == "super-secret-token"]
    assert holders == ["_GmpHttpClient__token"]


def test_error_messages_are_scrubbed() -> None:
    http = EngineHTTPError(401, f"rejected credential {SECRET} for Bearer abc123def")
    transport = EngineTransportError(f"connect failed using {SECRET}")

    for error in (http, transport):
        assert SECRET not in str(error)
        assert "[redacted]" in str(error)
    assert find_violations({"detail": http.detail}) == []


def test_refund_refusal_names_no_secrets() -> None:
    error = RefundNotSupportedError(ref="p1", captured=450, currency="USD")
    assert find_violations({"message": str(error), "remedy": error.remedy}) == []


def test_the_client_redacts_response_bodies_without_touching_the_network() -> None:
    """A stub opener — no sockets, no listener, no engine."""

    class _Response:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def read(self) -> bytes:
            return self._body

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    captured: dict[str, object] = {}

    def opener(request: object, timeout: float = 0.0) -> _Response:
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["headers"] = dict(request.headers)  # type: ignore[attr-defined]
        return _Response(
            json.dumps(
                {"group_id": "g_1", "api_key": SECRET, "nested": {"wallet_secret": "x"}}
            ).encode()
        )

    client = GmpHttpClient("http://engine.invalid", token="tok", opener=opener)
    body = client._request_sync("GET", "/v1/groups/g_1", None, authenticated=True)  # noqa: SLF001

    assert body == {"group_id": "g_1", "nested": {}}
    assert find_violations(body) == []
    # The token does reach the header — that is its job — and goes nowhere else.
    assert captured["headers"]["Authorization"] == "Bearer tok"
