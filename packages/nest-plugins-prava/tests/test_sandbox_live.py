# SPDX-License-Identifier: Apache-2.0
"""Optional live sandbox checks (skipped unless -m live + PRAVA_API_KEY)."""

from __future__ import annotations

import os

import pytest
from nest_plugins_prava import PravaPayments
from nest_plugins_prava.client import HttpPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


@pytest.fixture(autouse=True)
def _clean_sidecars() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


pytestmark = pytest.mark.live


def _api_key() -> str:
    return os.environ.get("PRAVA_API_KEY", "").strip()


@pytest.mark.asyncio
async def test_live_create_session() -> None:
    key = _api_key()
    if not key:
        pytest.skip("PRAVA_API_KEY not set")
    client = HttpPravaClient(api_key=key)
    body = {
        "user_id": "nanda-live-probe",
        "user_email": "nanda-live-probe@agents.nandatown.local",
        "total_amount": "0.50",
        "currency": "USD",
        "purchase_context": [
            {
                "merchant_details": {
                    "name": "NANDA Town Marketplace",
                    "url": "https://nandatown.projectnanda.org",
                    "country_code_iso2": "US",
                },
                "product_details": [
                    {
                        "description": "Live probe",
                        "unit_price": "0.50",
                        "quantity": 1,
                    }
                ],
            }
        ],
        "integration_type": "full_checkout",
        "callback_url": "https://nandatown.projectnanda.org/prava/callback",
    }
    session = await client.create_session(body)
    assert session.session_id.startswith(("ses_", "sess_"))
    assert session.session_id


@pytest.mark.asyncio
async def test_hybrid_pay_uses_live_session_id() -> None:
    key = _api_key()
    if not key:
        pytest.skip("PRAVA_API_KEY not set")
    pay = PravaPayments(
        AgentId("alice"),
        initial_balance=1000,
        mode="hybrid",
        api_key=key,
    )
    receipt = await pay.pay(AgentId("bob"), Money(amount=50), PaymentRef("hybrid-1"))
    record = pay.payment_record(PaymentRef("hybrid-1"))
    assert record is not None
    assert record.session_id is not None
    assert record.session_id.startswith(("ses_", "sess_"))
    assert "mock" not in record.session_id
    assert await pay.verify_payment(PaymentRef("hybrid-1")) is PaymentStatus.CONFIRMED
    assert receipt.amount.amount == 50
