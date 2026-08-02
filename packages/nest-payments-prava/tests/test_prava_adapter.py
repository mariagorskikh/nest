# SPDX-License-Identifier: Apache-2.0
"""Pytest suite for PravaPaymentLayer.

All HTTP calls to the Prava sandbox are intercepted by ``respx`` so the
suite runs fully offline — no real network traffic is generated.

Test cases
----------
1. test_successful_transaction
   Valid token + amount ≤ 150 → sandbox called once, Receipt returned,
   ``verify_payment`` → CONFIRMED.

2. test_decline_over_limit
   Amount > 150 → ``PaymentDeclined`` raised *without* calling the sandbox
   (client-side guard); ``verify_payment`` → FAILED.

3. test_decline_cvv_000
   CVV ``"000"`` → ``PaymentDeclined`` raised *without* calling the sandbox,
   matching the Prava test-harness forced-decline convention.

4. test_duplicate_ref
   Reusing a confirmed ref → ``ValueError``.

5. test_quote
   ``quote()`` returns a Quote with a non-negative price.

6. test_refund
   ``refund()`` reverses soft balances; ``verify_payment`` returns FAILED
   afterwards (receipt removed).

7. test_refund_unknown_ref
   Refunding a non-existent ref → ``ValueError``.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef

from nest_payments_prava.prava_plugin import (
    PRAVA_SANDBOX_CHARGE_URL,
    PaymentDeclined,
    PravaPaymentLayer,
    PravaTokenDetails,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

VALID_TOKEN = PravaTokenDetails(pan="4111111111111111", cvv="123", expiry="12/27", limit=150)
DECLINED_CVV_TOKEN = PravaTokenDetails(pan="4111111111111111", cvv="000", expiry="12/27", limit=150)

BUYER = AgentId("procurement_buyer")
SELLER = AgentId("software_seller")


def _sandbox_ok(ref: str, amount: int) -> dict:
    """Plausible Prava sandbox 200 JSON body."""
    return {
        "charge_id": f"ch_{ref[:8]}",
        "status": "confirmed",
        "amount": amount,
        "reference_id": ref,
    }


@pytest.fixture
def plugin() -> PravaPaymentLayer:
    """PravaPaymentLayer with a valid token and $500 soft balance."""
    return PravaPaymentLayer(BUYER, token=VALID_TOKEN, initial_balance=500)


@pytest.fixture
def declined_cvv_plugin() -> PravaPaymentLayer:
    """PravaPaymentLayer with a forced-decline CVV token."""
    return PravaPaymentLayer(BUYER, token=DECLINED_CVV_TOKEN, initial_balance=500)


# ---------------------------------------------------------------------------
# Test 1 — Successful transaction (amount under token limit)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_successful_transaction(plugin: PravaPaymentLayer) -> None:
    """Valid token + amount ≤ 150 → sandbox charged, Receipt returned."""
    ref = PaymentRef("pay-success-01")
    amount = Money(amount=99, currency="USD")

    respx.post(PRAVA_SANDBOX_CHARGE_URL).mock(
        return_value=httpx.Response(200, json=_sandbox_ok(ref, amount.amount))
    )

    receipt = await plugin.pay(SELLER, amount, ref)

    # Receipt correctness
    assert receipt.ref == ref
    assert receipt.payer == BUYER
    assert receipt.payee == SELLER
    assert receipt.amount.amount == 99

    # Sandbox called exactly once with correct payload
    assert respx.calls.call_count == 1
    body = json.loads(respx.calls.last.request.content)
    assert body["amount"] == 99
    assert body["token"]["cvv"] == "123"
    assert body["reference_id"] == ref

    # Soft balances updated
    assert plugin.balance(BUYER) == 401
    assert plugin.balance(SELLER) == 99

    # verify_payment confirms the charge
    assert await plugin.verify_payment(ref) == PaymentStatus.CONFIRMED


# ---------------------------------------------------------------------------
# Test 2 — Decline: amount exceeds token limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_decline_over_limit(plugin: PravaPaymentLayer) -> None:
    """Amount > 150 → PaymentDeclined raised; sandbox NOT called."""
    ref = PaymentRef("pay-over-limit-01")
    amount = Money(amount=200, currency="USD")  # exceeds $150 limit

    with pytest.raises(PaymentDeclined) as exc_info:
        await plugin.pay(SELLER, amount, ref)

    err = exc_info.value
    assert err.ref == ref
    assert "150" in err.reason   # limit mentioned
    assert "200" in err.reason   # actual amount mentioned

    # Client-side guard fired — sandbox never reached
    assert respx.calls.call_count == 0

    # Soft balance untouched
    assert plugin.balance(BUYER) == 500

    # verify_payment returns FAILED for a declined ref
    assert await plugin.verify_payment(ref) == PaymentStatus.FAILED


# ---------------------------------------------------------------------------
# Test 3 — Decline: CVV 000 (Prava forced-decline convention)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_decline_cvv_000(declined_cvv_plugin: PravaPaymentLayer) -> None:
    """CVV '000' → PaymentDeclined raised; sandbox NOT called."""
    ref = PaymentRef("pay-cvv-decline-01")
    amount = Money(amount=50, currency="USD")

    with pytest.raises(PaymentDeclined) as exc_info:
        await declined_cvv_plugin.pay(SELLER, amount, ref)

    err = exc_info.value
    assert err.ref == ref
    assert "000" in err.reason

    # No network call
    assert respx.calls.call_count == 0

    # Balance unchanged
    assert declined_cvv_plugin.balance(BUYER) == 500

    # verify_payment returns FAILED
    assert await declined_cvv_plugin.verify_payment(ref) == PaymentStatus.FAILED


# ---------------------------------------------------------------------------
# Test 4 — Duplicate reference guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_duplicate_ref(plugin: PravaPaymentLayer) -> None:
    """Reusing a confirmed payment reference raises ValueError."""
    ref = PaymentRef("pay-dup-01")
    amount = Money(amount=10, currency="USD")

    respx.post(PRAVA_SANDBOX_CHARGE_URL).mock(
        return_value=httpx.Response(200, json=_sandbox_ok(ref, amount.amount))
    )

    await plugin.pay(SELLER, amount, ref)

    with pytest.raises(ValueError, match="Duplicate"):
        await plugin.pay(SELLER, amount, ref)


# ---------------------------------------------------------------------------
# Test 5 — Quote
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quote(plugin: PravaPaymentLayer) -> None:
    """quote() returns a Quote with a non-negative price."""
    q = await plugin.quote(ServiceRef("software-license"))
    assert q.service == ServiceRef("software-license")
    assert q.price.amount >= 0


# ---------------------------------------------------------------------------
# Test 6 — Refund
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_refund(plugin: PravaPaymentLayer) -> None:
    """refund() reverses soft balances; verify_payment returns FAILED afterwards."""
    ref = PaymentRef("pay-refund-01")
    amount = Money(amount=75, currency="USD")

    respx.post(PRAVA_SANDBOX_CHARGE_URL).mock(
        return_value=httpx.Response(200, json=_sandbox_ok(ref, amount.amount))
    )

    await plugin.pay(SELLER, amount, ref)
    assert plugin.balance(BUYER) == 425
    assert plugin.balance(SELLER) == 75

    await plugin.refund(ref)

    # Balances restored
    assert plugin.balance(BUYER) == 500
    assert plugin.balance(SELLER) == 0

    # Receipt removed → verify returns FAILED
    assert await plugin.verify_payment(ref) == PaymentStatus.FAILED


# ---------------------------------------------------------------------------
# Test 7 — Refund on unknown reference
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refund_unknown_ref(plugin: PravaPaymentLayer) -> None:
    """refund() on a non-existent reference raises ValueError."""
    with pytest.raises(ValueError, match="not found"):
        await plugin.refund(PaymentRef("ghost-ref-99"))
