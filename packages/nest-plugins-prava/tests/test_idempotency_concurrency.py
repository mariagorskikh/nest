# SPDX-License-Identifier: Apache-2.0
"""Idempotency and concurrency invariants."""

from __future__ import annotations

import asyncio

import pytest
from nest_plugins_prava import PravaPayments
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


@pytest.fixture(autouse=True)
def _clean_sidecars() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


@pytest.mark.asyncio
async def test_concurrent_pays_preserve_balance_invariant() -> None:
    balances: dict[AgentId, int] = {AgentId("alice"): 100}
    payments: dict[PaymentRef, object] = {}
    client = MockPravaClient(latency_s=0.005)
    alice = PravaPayments(
        AgentId("alice"),
        initial_balance=0,
        balances=balances,
        payments=payments,
        client=client,
    )

    async def _one(i: int) -> None:
        await alice.pay(AgentId("bob"), Money(amount=10), PaymentRef(f"c-{i}"))

    results = await asyncio.gather(
        *[_one(i) for i in range(20)],
        return_exceptions=True,
    )
    successes = [r for r in results if not isinstance(r, BaseException)]
    failures = [r for r in results if isinstance(r, BaseException)]

    # 100 credits / 10 = 10 successes max
    assert len(successes) == 10
    assert len(failures) == 10
    assert alice.balance(AgentId("alice")) == 0
    assert alice.balance(AgentId("bob")) == 100


@pytest.mark.asyncio
async def test_poll_pending_then_completed() -> None:
    client = MockPravaClient(poll_statuses=["pending", "processing", "awaiting_result"])
    pay = PravaPayments(
        AgentId("alice"),
        initial_balance=100,
        client=client,
        poll_attempts=5,
        poll_interval_s=0.001,
    )
    receipt = await pay.pay(AgentId("bob"), Money(amount=15), PaymentRef("poll-1"))
    assert receipt.amount.amount == 15
    assert await pay.verify_payment(PaymentRef("poll-1")) is PaymentStatus.CONFIRMED
