# SPDX-License-Identifier: Apache-2.0
"""Item 7 — real Prava sandbox proof (FAIL if no key / network)."""

from __future__ import annotations

import json
import os

import pytest
from nest_plugins_prava import PravaPayments
from nest_plugins_prava.client import HttpPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_plugins_prava.secrets import redact
from nest_sdk import AgentId, PaymentRef, PaymentStatus, ServiceRef


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


pytestmark = pytest.mark.live


def _key() -> str:
    return os.environ.get("PRAVA_API_KEY", "").strip()


@pytest.mark.asyncio
async def test_sandbox_create_session_real_response_shape() -> None:
    key = _key()
    if not key:
        pytest.fail(
            "PRAVA_API_KEY not set — cannot prove sandbox integration. "
            "Export a sk_test_ key and re-run: pytest -m live ..."
        )
    client = HttpPravaClient(api_key=key)
    body = {
        "user_id": "nanda-audit-probe",
        "user_email": "nanda-audit-probe@agents.nandatown.local",
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
                        "description": "Hostile audit probe",
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
    public = session.public_view()
    print("SANDBOX_SESSION_PUBLIC=" + json.dumps(redact(public), indent=2))
    # Sandbox returns ULID-style ids: ses_01... / ord_01...
    assert session.session_id.startswith(("ses_", "sess_"))
    assert public.get("session_token") in {None, "***REDACTED***"}


@pytest.mark.asyncio
async def test_sandbox_hybrid_quote_pay_verify_receipt() -> None:
    key = _key()
    if not key:
        pytest.fail("PRAVA_API_KEY not set — hybrid sandbox proof blocked")
    pay = PravaPayments(
        AgentId("alice"),
        initial_balance=1000,
        mode="hybrid",
        api_key=key,
        default_fee=50,
    )
    quote = await pay.quote(ServiceRef("audit-sku"))
    receipt = await pay.pay(AgentId("bob"), quote.price, PaymentRef("sandbox-audit-1"))
    status = await pay.verify_payment(PaymentRef("sandbox-audit-1"))
    record = pay.payment_record(PaymentRef("sandbox-audit-1"))
    assert record is not None
    evidence = {
        "quote_amount": quote.price.amount,
        "prava_amount": quote.metadata.get("prava_amount"),
        "receipt_ref": str(receipt.ref),
        "session_id": record.session_id,
        "order_id": record.order_id,
        "status": status.value,
        "phase": record.phase.value,
    }
    print("SANDBOX_FLOW_EVIDENCE=" + json.dumps(evidence, indent=2))
    assert status is PaymentStatus.CONFIRMED
    assert record.session_id and record.session_id.startswith(("ses_", "sess_"))
    assert "mock" not in record.session_id
