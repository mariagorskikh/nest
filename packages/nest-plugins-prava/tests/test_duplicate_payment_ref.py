# SPDX-License-Identifier: Apache-2.0
"""Item 1 — hostile idempotency verification for PaymentRef."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from nest_plugins_prava import DuplicatePaymentRefError, PravaPayments
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


@pytest.mark.asyncio
async def test_duplicate_ref_returns_same_receipt_no_second_api_call() -> None:
    client = MockPravaClient()
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=client)
    ref = PaymentRef("abc123")

    r1 = await pay.pay(AgentId("bob"), Money(amount=50), ref)
    calls_after_first = client.call_count
    assert calls_after_first > 0
    assert ref in pay._records  # stored  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    r2 = await pay.pay(AgentId("bob"), Money(amount=50), ref)
    assert r2.ref == r1.ref
    assert r2.payer == r1.payer
    assert r2.payee == r1.payee
    assert r2.amount.amount == r1.amount.amount
    assert client.call_count == calls_after_first  # NO second Prava trip
    assert pay.balance(AgentId("alice")) == 950  # no double spend
    assert pay.balance(AgentId("bob")) == 50


@pytest.mark.asyncio
async def test_lookup_atomic_under_concurrent_duplicate_requests() -> None:
    client = MockPravaClient(latency_s=0.02)
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=client)
    ref = PaymentRef("abc123")

    results = await asyncio.gather(
        *[pay.pay(AgentId("bob"), Money(amount=50), ref) for _ in range(20)]
    )
    assert len({(r.ref, r.amount.amount, r.payee) for r in results}) == 1
    # Exactly one create+poll+report lane (3 calls), not 20×
    assert client.call_count == 3
    assert pay.balance(AgentId("alice")) == 950
    assert pay.balance(AgentId("bob")) == 50


@pytest.mark.asyncio
async def test_process_restart_without_journal_loses_idempotency() -> None:
    """Prove the gap: in-memory only → restart creates a NEW rail call."""
    client1 = MockPravaClient()
    pay1 = PravaPayments(AgentId("alice"), initial_balance=1000, client=client1)
    await pay1.pay(AgentId("bob"), Money(amount=50), PaymentRef("abc123"))
    assert client1.call_count == 3

    reset_ledger_sidecars()  # simulate process death
    client2 = MockPravaClient()
    pay2 = PravaPayments(AgentId("alice"), initial_balance=1000, client=client2)
    await pay2.pay(AgentId("bob"), Money(amount=50), PaymentRef("abc123"))
    assert client2.call_count == 3  # second process charged again — RISK without journal


@pytest.mark.asyncio
async def test_process_restart_with_journal_preserves_idempotency() -> None:
    journal: dict[str, dict[str, Any]] = {}
    client1 = MockPravaClient()
    pay1 = PravaPayments(AgentId("alice"), initial_balance=1000, client=client1, journal=journal)
    r1 = await pay1.pay(AgentId("bob"), Money(amount=50), PaymentRef("abc123"))
    assert "abc123" in journal

    reset_ledger_sidecars()  # simulate process death
    client2 = MockPravaClient()
    # Fresh balances dict but shared durable journal.
    pay2 = PravaPayments(
        AgentId("alice"),
        initial_balance=1000,
        client=client2,
        journal=journal,
    )
    r2 = await pay2.pay(AgentId("bob"), Money(amount=50), PaymentRef("abc123"))
    assert r2.ref == r1.ref
    assert client2.call_count == 0  # no second Prava call after restart
    assert await pay2.verify_payment(PaymentRef("abc123")) is PaymentStatus.CONFIRMED


@pytest.mark.asyncio
async def test_conflicting_duplicate_ref_rejected() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    await pay.pay(AgentId("bob"), Money(amount=50), PaymentRef("abc123"))
    with pytest.raises(DuplicatePaymentRefError):
        await pay.pay(AgentId("carol"), Money(amount=50), PaymentRef("abc123"))
