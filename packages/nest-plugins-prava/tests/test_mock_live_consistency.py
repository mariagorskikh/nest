# SPDX-License-Identifier: Apache-2.0
"""Item 10 — MockPravaClient vs HttpPravaClient interface + adapter parity."""

from __future__ import annotations

import inspect

import httpx
import pytest
from nest_plugins_prava import PravaPayments
from nest_plugins_prava.client import HttpPravaClient, MockPravaClient, PravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, PaymentRef, PaymentStatus, ServiceRef


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


REQUIRED_METHODS = (
    "create_session",
    "get_payment_result",
    "report_status",
    "revoke_session",
)


def test_both_clients_satisfy_protocol() -> None:
    mock = MockPravaClient()
    http = HttpPravaClient(
        api_key="sk_test_dummy", transport=httpx.MockTransport(lambda r: httpx.Response(500))
    )
    assert isinstance(mock, PravaClient)
    assert isinstance(http, PravaClient)
    for name in REQUIRED_METHODS:
        assert callable(getattr(mock, name))
        assert callable(getattr(http, name))
        m_sig = inspect.signature(getattr(mock, name))
        h_sig = inspect.signature(getattr(http, name))
        assert list(m_sig.parameters) == list(h_sig.parameters), (name, m_sig, h_sig)
    print(f"interface_match methods={REQUIRED_METHODS}")


@pytest.mark.asyncio
async def test_adapter_same_logic_with_mock_and_http_transport() -> None:
    """Same PravaPayments path must work when client is mock OR http(mock transport)."""

    # Mock client path
    mock = MockPravaClient()
    pay_mock = PravaPayments(AgentId("alice"), initial_balance=500, client=mock, default_fee=20)
    q1 = await pay_mock.quote(ServiceRef("item"))
    r1 = await pay_mock.pay(AgentId("bob"), q1.price, PaymentRef("parity-1"))
    assert await pay_mock.verify_payment(PaymentRef("parity-1")) is PaymentStatus.CONFIRMED

    # Http client with deterministic success transport (same response shape as sandbox)
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/sessions") and request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "session_id": "sess_liveish_001",
                    "order_id": "ord_liveish_001",
                    "session_token": "tok_SHOULD_NOT_LEAK",
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            )
        if path.endswith("/payment-result"):
            return httpx.Response(
                200,
                json={
                    "session_id": "sess_liveish_001",
                    "order_id": "ord_liveish_001",
                    "status": "completed",
                    "transactions": [{"txn_ref_id": "tli_1", "token": "4111111111111111"}],
                },
            )
        if path.endswith("/report-status"):
            return httpx.Response(
                200,
                json={"status": "confirmed", "txn_ref_id": "tli_1", "txn_status": "APPROVED"},
            )
        if path.endswith("/revoke"):
            return httpx.Response(200, json={"success": True})
        return httpx.Response(404, json={"error": {"code": "NOT_FOUND", "message": path}})

    http = HttpPravaClient(api_key="sk_test_dummy", transport=httpx.MockTransport(handler))
    pay_http = PravaPayments(AgentId("alice"), initial_balance=500, client=http, default_fee=20)
    q2 = await pay_http.quote(ServiceRef("item"))
    r2 = await pay_http.pay(AgentId("bob"), q2.price, PaymentRef("parity-2"))
    assert await pay_http.verify_payment(PaymentRef("parity-2")) is PaymentStatus.CONFIRMED

    assert r1.amount.amount == r2.amount.amount == 20
    rec = pay_http.payment_record(PaymentRef("parity-2"))
    assert rec is not None
    assert rec.session_id == "sess_liveish_001"
    assert "tok_SHOULD_NOT_LEAK" not in str(rec.public_view())
    print(
        f"parity: mock_status=confirmed http_session={rec.session_id} "
        f"amounts={r1.amount.amount}/{r2.amount.amount}"
    )
