# SPDX-License-Identifier: Apache-2.0
"""Payments Protocol conformance tests for PravaPayments."""

from __future__ import annotations

import pytest
from nest_plugins_prava import PravaPayments
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef


@pytest.fixture(autouse=True)
def _clean_sidecars() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


@pytest.fixture
def payments() -> PravaPayments:
    return PravaPayments(
        AgentId("alice"),
        initial_balance=1000,
        client=MockPravaClient(),
        default_fee=42,
    )


@pytest.mark.asyncio
async def test_quote_uses_configured_fee(payments: PravaPayments) -> None:
    quote = await payments.quote(ServiceRef("svc"))
    assert quote.price.amount == 42
    assert quote.metadata["rail"] == "prava"
    assert quote.metadata["prava_amount"] == "0.42"


@pytest.mark.asyncio
async def test_pay_then_verify_confirmed(payments: PravaPayments) -> None:
    ref = PaymentRef("r1")
    receipt = await payments.pay(AgentId("bob"), Money(amount=50), ref)
    assert receipt.payer == AgentId("alice")
    assert receipt.payee == AgentId("bob")
    assert receipt.amount.amount == 50
    assert await payments.verify_payment(ref) is PaymentStatus.CONFIRMED
    assert payments.balance(AgentId("alice")) == 950
    assert payments.balance(AgentId("bob")) == 50


@pytest.mark.asyncio
async def test_verify_unknown_ref_failed(payments: PravaPayments) -> None:
    assert await payments.verify_payment(PaymentRef("missing")) is PaymentStatus.FAILED


@pytest.mark.asyncio
async def test_refund_happy_path(payments: PravaPayments) -> None:
    ref = PaymentRef("r-refund")
    await payments.pay(AgentId("bob"), Money(amount=40), ref)
    await payments.refund(ref)
    assert await payments.verify_payment(ref) is PaymentStatus.REFUNDED
    assert payments.balance(AgentId("alice")) == 1000
    assert payments.balance(AgentId("bob")) == 0
    # Idempotent refund
    await payments.refund(ref)


@pytest.mark.asyncio
async def test_shared_ledger_like_marketplace() -> None:
    balances: dict[AgentId, int] = {}
    payment_records: dict[PaymentRef, object] = {}
    client = MockPravaClient()
    buyer = PravaPayments(
        AgentId("buyer"),
        initial_balance=1000,
        balances=balances,
        payments=payment_records,
        client=client,
    )
    seller = PravaPayments(
        AgentId("seller"),
        initial_balance=0,
        balances=balances,
        payments=payment_records,
        client=client,
    )
    await buyer.pay(AgentId("seller"), Money(amount=25), PaymentRef("m1"))
    assert buyer.balance(AgentId("buyer")) == 975
    assert seller.balance(AgentId("seller")) == 25
    assert await seller.verify_payment(PaymentRef("m1")) is PaymentStatus.CONFIRMED
