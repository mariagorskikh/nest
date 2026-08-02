# SPDX-License-Identifier: Apache-2.0
"""Failure-path coverage for the Prava adapter."""

from __future__ import annotations

import time

import pytest
from nest_plugins_prava import (
    DuplicatePaymentRefError,
    InsufficientFundsError,
    PaymentNotFoundError,
    PravaDeclinedError,
    PravaPayments,
    PravaTimeoutError,
    QuoteExpiredError,
)
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.errors import PravaApiError, PravaAuthError
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef


@pytest.fixture(autouse=True)
def _clean_sidecars() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


@pytest.mark.asyncio
async def test_insufficient_funds_never_hits_client() -> None:
    client = MockPravaClient()
    pay = PravaPayments(AgentId("alice"), initial_balance=5, client=client)
    with pytest.raises(InsufficientFundsError):
        await pay.pay(AgentId("bob"), Money(amount=50), PaymentRef("buy-1"))
    assert client.call_count == 0
    assert pay.balance(AgentId("alice")) == 5


@pytest.mark.asyncio
async def test_duplicate_ref_idempotent_success() -> None:
    client = MockPravaClient()
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=client)
    ref = PaymentRef("same")
    r1 = await pay.pay(AgentId("bob"), Money(amount=10), ref)
    calls_after_first = client.call_count
    r2 = await pay.pay(AgentId("bob"), Money(amount=10), ref)
    assert r1.ref == r2.ref
    assert client.call_count == calls_after_first  # no second rail trip
    assert pay.balance(AgentId("alice")) == 990


@pytest.mark.asyncio
async def test_duplicate_ref_conflict_raises() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    ref = PaymentRef("same")
    await pay.pay(AgentId("bob"), Money(amount=10), ref)
    with pytest.raises(DuplicatePaymentRefError):
        await pay.pay(AgentId("carol"), Money(amount=10), ref)


@pytest.mark.asyncio
async def test_create_timeout_releases_budget() -> None:
    client = MockPravaClient(timeout_on="create_session")
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaTimeoutError):
        await pay.pay(AgentId("bob"), Money(amount=40), PaymentRef("t1"))
    assert pay.balance(AgentId("alice")) == 100
    assert await pay.verify_payment(PaymentRef("t1")) is PaymentStatus.FAILED


@pytest.mark.asyncio
async def test_auth_error_releases_budget() -> None:
    client = MockPravaClient(create_error=PravaAuthError("bad key", code="AUTH_1001"))
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaAuthError):
        await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("a1"))
    assert pay.balance(AgentId("alice")) == 100


@pytest.mark.asyncio
async def test_declined_report_status() -> None:
    client = MockPravaClient(decline_report=True)
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaDeclinedError):
        await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("d1"))
    assert pay.balance(AgentId("alice")) == 100
    assert await pay.verify_payment(PaymentRef("d1")) is PaymentStatus.FAILED


@pytest.mark.asyncio
async def test_failed_payment_result() -> None:
    client = MockPravaClient(poll_statuses=["failed"])
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaDeclinedError):
        await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("f1"))
    assert pay.balance(AgentId("alice")) == 100


@pytest.mark.asyncio
async def test_retry_after_failure_same_ref() -> None:
    client = MockPravaClient(fail_on_create=True)
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaApiError):
        await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("retry-1"))
    # Swap in a healthy client on the same ledger.
    healthy = MockPravaClient()
    pay._client = healthy  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    receipt = await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("retry-1"))
    assert receipt.amount.amount == 20
    assert pay.balance(AgentId("alice")) == 80


@pytest.mark.asyncio
async def test_quote_expired() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    quote = await pay.quote(ServiceRef("svc"))
    # Expire the cached quote manually.
    cached = pay._quotes[str(ServiceRef("svc"))]  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    cached.expires_at = time.time() - 1
    with pytest.raises(QuoteExpiredError):
        await pay.pay(AgentId("bob"), quote.price, PaymentRef("q1"))


@pytest.mark.asyncio
async def test_refund_unknown_ref() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=MockPravaClient())
    with pytest.raises(PaymentNotFoundError):
        await pay.refund(PaymentRef("nope"))


@pytest.mark.asyncio
async def test_reject_non_positive_amount() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=MockPravaClient())
    with pytest.raises(ValueError):
        await pay.pay(AgentId("bob"), Money(amount=0), PaymentRef("z"))
