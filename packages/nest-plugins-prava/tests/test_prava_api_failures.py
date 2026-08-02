# SPDX-License-Identifier: Apache-2.0
"""Item 3 + 8 + 9 — Prava API failure simulation, error mapping, retry audit."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from nest_plugins_prava import (
    PravaAuthError,
    PravaDeclinedError,
    PravaPayments,
    PravaTimeoutError,
)
from nest_plugins_prava.client import HttpPravaClient, MockPravaClient
from nest_plugins_prava.errors import PravaApiError, PravaValidationError
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


def _body() -> dict[str, Any]:
    return {
        "user_id": "nanda-alice",
        "user_email": "nanda-alice@agents.nandatown.local",
        "total_amount": "0.50",
        "currency": "USD",
        "purchase_context": [
            {
                "merchant_details": {
                    "name": "NANDA",
                    "url": "https://example.com",
                    "country_code_iso2": "US",
                },
                "product_details": [{"description": "x", "unit_price": "0.50", "quantity": 1}],
            }
        ],
        "integration_type": "full_checkout",
        "callback_url": "https://example.com/cb",
    }


@pytest.mark.asyncio
async def test_a_timeout_respects_retry_limit_deterministic() -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        raise httpx.TimeoutException("simulated hang", request=request)

    transport = httpx.MockTransport(handler)
    client = HttpPravaClient(
        api_key="sk_test_dummy",
        transport=transport,
        timeout_s=0.05,
        max_retries=2,
    )
    with pytest.raises(PravaTimeoutError) as ei:
        await client.create_session(_body())
    assert ei.value.code == "TIMEOUT"
    # initial + 2 retries = 3
    assert hits["n"] == 3
    print(f"timeout: attempts={hits['n']} error={type(ei.value).__name__}:{ei.value}")


@pytest.mark.asyncio
async def test_b_http_500_retries_then_typed_error_no_duplicate_pay() -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(
            500, json={"error": {"code": "SESSION_CREATE_ERROR", "message": "boom"}}
        )

    transport = httpx.MockTransport(handler)
    http = HttpPravaClient(api_key="sk_test_dummy", transport=transport, max_retries=2)
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=http)
    with pytest.raises(PravaApiError) as ei:
        await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("r500"))
    assert hits["n"] == 3  # retried
    assert isinstance(ei.value, PravaApiError)
    assert not isinstance(ei.value, PravaTimeoutError)
    assert pay.balance(AgentId("alice")) == 100  # released
    assert await pay.verify_payment(PaymentRef("r500")) is PaymentStatus.FAILED
    print(f"500: attempts={hits['n']} balance={pay.balance(AgentId('alice'))} err={ei.value.code}")


@pytest.mark.asyncio
async def test_b_generic_http_500_also_retries() -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(500, json={"message": "internal"})

    transport = httpx.MockTransport(handler)
    client = HttpPravaClient(api_key="sk_test_dummy", transport=transport, max_retries=2)
    with pytest.raises(PravaApiError):
        await client.create_session(_body())
    assert hits["n"] == 3
    print(f"generic_500: attempts={hits['n']}")


@pytest.mark.asyncio
async def test_c_http_401_no_retry() -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(401, json={"error": {"code": "AUTH_1001", "message": "bad key"}})

    transport = httpx.MockTransport(handler)
    client = HttpPravaClient(api_key="sk_test_dummy", transport=transport, max_retries=5)
    with pytest.raises(PravaAuthError) as ei:
        await client.create_session(_body())
    assert hits["n"] == 1  # NO retry loop
    assert ei.value.code == "AUTH_1001"
    print(f"401: attempts={hits['n']} err={type(ei.value).__name__}")


@pytest.mark.asyncio
async def test_c_http_403_no_retry() -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(403, json={"error": {"code": "AUTH_1001", "message": "forbidden"}})

    transport = httpx.MockTransport(handler)
    client = HttpPravaClient(api_key="sk_test_dummy", transport=transport, max_retries=5)
    with pytest.raises(PravaAuthError):
        await client.create_session(_body())
    assert hits["n"] == 1


@pytest.mark.asyncio
async def test_d_invalid_response_schema_validation_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "data"})

    transport = httpx.MockTransport(handler)
    client = HttpPravaClient(api_key="sk_test_dummy", transport=transport)
    with pytest.raises(PravaValidationError) as ei:
        await client.create_session(_body())
    assert ei.value.code == "VAL_SCHEMA"
    assert "session_id" in str(ei.value)
    print(f"schema: err={type(ei.value).__name__} code={ei.value.code} msg={ei.value}")


@pytest.mark.asyncio
async def test_declined_no_retry_and_typed() -> None:
    client = MockPravaClient(decline_report=True)
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaDeclinedError):
        await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("dec"))
    # create + poll + report (+ revoke on fail) — not a retry storm
    assert client.call_count <= 4
    assert pay.balance(AgentId("alice")) == 100


@pytest.mark.asyncio
async def test_error_mapping_never_raw_http_500_string_exception() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"code": "SESSION_CREATE_ERROR", "message": "x"}})

    client = HttpPravaClient(
        api_key="sk_test_dummy", transport=httpx.MockTransport(handler), max_retries=0
    )
    with pytest.raises(PravaApiError) as ei:
        await client.create_session(_body())
    assert type(ei.value) is PravaApiError
    assert "HTTP 500" not in type(ei.value).__name__
