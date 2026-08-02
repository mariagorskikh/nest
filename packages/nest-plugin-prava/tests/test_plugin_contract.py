# SPDX-License-Identifier: Apache-2.0
"""Offline contract tests: protocol conformance and refusal mapping.

These run anywhere, with no console and no network, so they stay green in
CI. The sandbox tests in ``test_sandbox_live.py`` cover real money.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from nest_core.layers.payments import Payments
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef

from nest_plugin_prava import PravaPaymentError, PravaPayments

if TYPE_CHECKING:
    import httpx

    from tests.conftest import JsonResponseFactory, MockClientFactory

QUOTE_BODY = {
    "runId": "nanda_test_run",
    "quoteId": "qt_test_0001",
    "amountCents": 1800,
    "currency": "USD",
    "counterpartyId": "agent_b",
    "pricingRule": "ceil(2h x 900c/GPU-h) = 1800c",
    "attributes": {"gpu": "L40S 48GB", "vram_gb": 48, "duration_h": 2},
    "ttlSeconds": 300,
}


def test_satisfies_payments_protocol() -> None:
    """The plugin structurally implements the Payments layer interface."""
    payments = PravaPayments(AgentId("agent_a"))
    assert isinstance(payments, Payments)


def test_accepts_marketplace_scenario_constructor() -> None:
    """The bundled marketplace scenario builds plugins with these kwargs."""
    shared: dict[PaymentRef, object] = {}
    payments = PravaPayments(
        AgentId("system"),
        initial_balance=0,
        balances={AgentId("a"): 1000},
        payments=shared,  # type: ignore[arg-type]
    )
    assert isinstance(payments, Payments)


async def test_quote_uses_merchant_price(
    mock_client: MockClientFactory, json_response: JsonResponseFactory
) -> None:
    """The quoted price comes from the merchant, unmodified."""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return json_response(200, QUOTE_BODY)

    payments = PravaPayments(AgentId("agent_a"), client=mock_client(handler))
    quote = await payments.quote(ServiceRef("gpu-compute-small"))

    assert quote.price == Money(amount=1800, currency="USD")
    assert quote.metadata["quote_id"] == "qt_test_0001"
    assert quote.metadata["pricing_rule"] == "ceil(2h x 900c/GPU-h) = 1800c"
    assert str(seen["url"]).endswith("/api/nanda/quote")


async def test_pay_without_quote_is_refused(
    mock_client: MockClientFactory, json_response: JsonResponseFactory
) -> None:
    """An agent cannot pay a price no merchant ever quoted."""
    client = mock_client(lambda request: json_response(200, {}))
    payments = PravaPayments(AgentId("agent_a"), client=client)
    with pytest.raises(PravaPaymentError) as exc:
        await payments.pay(AgentId("agent_b"), Money(amount=9999), PaymentRef("p-nq"))
    assert exc.value.code == "NO_QUOTE"


async def test_policy_refusal_is_surfaced_honestly(
    mock_client: MockClientFactory, json_response: JsonResponseFactory
) -> None:
    """A cap breach maps to the arbiter's verdict, clause path and detail."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/nanda/quote":
            return json_response(200, {**QUOTE_BODY, "amountCents": 7050})
        return json_response(
            402,
            {
                "error": {
                    "code": "POLICY_NEEDS_HUMAN",
                    "message": "amount $70.50 exceeds cap $47.00",
                    "details": {
                        "decision": "NEEDS_HUMAN",
                        "failingClausePath": "root.all_of[3]",
                        "onFail": "escalate",
                    },
                }
            },
        )

    payments = PravaPayments(AgentId("agent_a"), client=mock_client(handler))
    quote = await payments.quote(ServiceRef("gpu-compute-xl"))
    with pytest.raises(PravaPaymentError) as exc:
        await payments.pay(AgentId("agent_b"), quote.price, PaymentRef("p-cap"))

    assert exc.value.code == "POLICY_NEEDS_HUMAN"
    assert exc.value.details["failingClausePath"] == "root.all_of[3]"
    assert "exceeds cap" in exc.value.message


async def test_cycle_exhausted_routing_refusal(
    mock_client: MockClientFactory, json_response: JsonResponseFactory
) -> None:
    """No envelope with cycle capacity is a refusal, not a retry."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/nanda/quote":
            return json_response(200, QUOTE_BODY)
        return json_response(
            402,
            {
                "error": {
                    "code": "NO_ENVELOPE_CAPACITY",
                    "message": "no envelope with cycle capacity: A: cycle spent -> B: cycle spent",
                    "details": {"reason": "A: cycle spent -> B: cycle spent"},
                }
            },
        )

    payments = PravaPayments(AgentId("agent_a"), client=mock_client(handler))
    quote = await payments.quote(ServiceRef("gpu-compute-small"))
    with pytest.raises(PravaPaymentError) as exc:
        await payments.pay(AgentId("agent_b"), quote.price, PaymentRef("p-cycle"))

    assert exc.value.code == "NO_ENVELOPE_CAPACITY"
    assert "cycle spent" in exc.value.message


async def test_verify_requires_a_ledger_row(
    mock_client: MockClientFactory, json_response: JsonResponseFactory
) -> None:
    """A charge without an append-only ledger row is not CONFIRMED."""

    def pending(request: httpx.Request) -> httpx.Response:
        return json_response(200, {"status": "confirmed", "ledgerConfirmed": False})

    def settled(request: httpx.Request) -> httpx.Response:
        return json_response(200, {"status": "confirmed", "ledgerConfirmed": True})

    def failed(request: httpx.Request) -> httpx.Response:
        return json_response(200, {"status": "failed", "ledgerConfirmed": False})

    p1 = PravaPayments(AgentId("a"), client=mock_client(pending))
    p2 = PravaPayments(AgentId("a"), client=mock_client(settled))
    p3 = PravaPayments(AgentId("a"), client=mock_client(failed))

    assert await p1.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING
    assert await p2.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
    assert await p3.verify_payment(PaymentRef("p1")) is PaymentStatus.FAILED


async def test_refund_is_not_supported(
    mock_client: MockClientFactory, json_response: JsonResponseFactory
) -> None:
    """Refunds raise instead of silently succeeding."""
    client = mock_client(lambda request: json_response(200, {}))
    payments = PravaPayments(AgentId("a"), client=client)
    with pytest.raises(PravaPaymentError) as exc:
        await payments.refund(PaymentRef("p1"))
    assert exc.value.code == "REFUND_NOT_SUPPORTED"


async def test_unknown_service_is_rejected(
    mock_client: MockClientFactory, json_response: JsonResponseFactory
) -> None:
    """Unknown service refs fail loudly rather than guessing a need."""
    client = mock_client(lambda request: json_response(200, {}))
    payments = PravaPayments(AgentId("a"), client=client)
    with pytest.raises(PravaPaymentError) as exc:
        await payments.quote(ServiceRef("teleportation"))
    assert exc.value.code == "UNKNOWN_SERVICE"
