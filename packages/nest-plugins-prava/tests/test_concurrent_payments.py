# SPDX-License-Identifier: Apache-2.0
"""Item 2 — concurrent payment race conditions (100 agents)."""

from __future__ import annotations

import asyncio

import pytest
from nest_plugins_prava import InsufficientFundsError, PravaPayments
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


@pytest.mark.asyncio
async def test_100_concurrent_same_ref_no_double_spend() -> None:
    balances: dict[AgentId, int] = {AgentId("treasury"): 10_000}
    payments: dict[PaymentRef, object] = {}
    client = MockPravaClient(latency_s=0.001)
    pay = PravaPayments(
        AgentId("treasury"),
        initial_balance=0,
        balances=balances,
        payments=payments,
        client=client,
    )
    ref = PaymentRef("shared-ref")

    results = await asyncio.gather(
        *[pay.pay(AgentId("sink"), Money(amount=25), ref) for _ in range(100)],
        return_exceptions=True,
    )
    ok = [r for r in results if not isinstance(r, BaseException)]
    err = [r for r in results if isinstance(r, BaseException)]
    print(
        f"same_ref: ok={len(ok)} err={len(err)} calls={client.call_count} "
        f"treasury={pay.balance(AgentId('treasury'))} sink={pay.balance(AgentId('sink'))}"
    )
    assert len(ok) == 100  # all return same receipt
    assert len(err) == 0
    assert client.call_count == 3  # one rail transaction only
    assert pay.balance(AgentId("treasury")) == 10_000 - 25
    assert pay.balance(AgentId("sink")) == 25
    assert await pay.verify_payment(ref) is PaymentStatus.CONFIRMED


@pytest.mark.asyncio
async def test_100_concurrent_different_refs_balance_invariant() -> None:
    balances: dict[AgentId, int] = {AgentId("treasury"): 1000}
    payments: dict[PaymentRef, object] = {}
    client = MockPravaClient(latency_s=0.001)
    pay = PravaPayments(
        AgentId("treasury"),
        initial_balance=0,
        balances=balances,
        payments=payments,
        client=client,
    )

    async def one(i: int) -> None:
        await pay.pay(AgentId(f"agent-{i % 10}"), Money(amount=10), PaymentRef(f"ref-{i}"))

    results = await asyncio.gather(*[one(i) for i in range(100)], return_exceptions=True)
    ok = [r for r in results if not isinstance(r, BaseException)]
    fail = [r for r in results if isinstance(r, BaseException)]
    print(
        f"diff_refs: ok={len(ok)} fail={len(fail)} calls={client.call_count} "
        f"treasury={pay.balance(AgentId('treasury'))}"
    )
    # 1000 / 10 = 100 successes exactly
    assert len(ok) == 100
    assert len(fail) == 0
    assert pay.balance(AgentId("treasury")) == 0
    # sum of sink balances
    sinks = sum(pay.balance(AgentId(f"agent-{i}")) for i in range(10))
    assert sinks == 1000
    assert all(isinstance(e, InsufficientFundsError) for e in fail) or fail == []


@pytest.mark.asyncio
async def test_100_concurrent_oversubscribe_no_corruption() -> None:
    balances: dict[AgentId, int] = {AgentId("treasury"): 250}
    payments: dict[PaymentRef, object] = {}
    client = MockPravaClient(latency_s=0.001)
    pay = PravaPayments(
        AgentId("treasury"),
        initial_balance=0,
        balances=balances,
        payments=payments,
        client=client,
    )

    results = await asyncio.gather(
        *[pay.pay(AgentId("sink"), Money(amount=10), PaymentRef(f"over-{i}")) for i in range(100)],
        return_exceptions=True,
    )
    ok = [r for r in results if not isinstance(r, BaseException)]
    fail = [r for r in results if isinstance(r, InsufficientFundsError)]
    other = [
        r
        for r in results
        if isinstance(r, BaseException) and not isinstance(r, InsufficientFundsError)
    ]
    print(
        f"oversubscribe: ok={len(ok)} insuff={len(fail)} other={len(other)} "
        f"treasury={pay.balance(AgentId('treasury'))} sink={pay.balance(AgentId('sink'))} "
        f"calls={client.call_count}"
    )
    assert len(ok) == 25
    assert len(fail) == 75
    assert other == []
    assert pay.balance(AgentId("treasury")) == 0
    assert pay.balance(AgentId("sink")) == 250
    # No partial/corrupt negatives
    assert pay.balance(AgentId("treasury")) >= 0
