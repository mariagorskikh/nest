# SPDX-License-Identifier: Apache-2.0
"""Item 5 — refund safety matrix."""

from __future__ import annotations

import pytest
from nest_plugins_prava import (
    InvalidPaymentStateError,
    PaymentNotFoundError,
    PravaPayments,
)
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_plugins_prava.state import PaymentPhase, PaymentRecord
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


@pytest.mark.asyncio
async def test_refund_confirmed_success() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=MockPravaClient())
    await pay.pay(AgentId("bob"), Money(amount=40), PaymentRef("rf-1"))
    await pay.refund(PaymentRef("rf-1"))
    assert pay.balance(AgentId("alice")) == 100
    assert pay.balance(AgentId("bob")) == 0
    assert await pay.verify_payment(PaymentRef("rf-1")) is PaymentStatus.REFUNDED
    print("refund confirmed: SUCCESS")


@pytest.mark.asyncio
async def test_refund_pending_rejected() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=MockPravaClient())
    ref = PaymentRef("rf-pend")
    pay._records[ref] = PaymentRecord(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        ref=ref,
        payer=AgentId("alice"),
        payee=AgentId("bob"),
        amount=Money(amount=10),
        status=PaymentStatus.PENDING,
        phase=PaymentPhase.BUDGET_LOCKED,
    )
    with pytest.raises(InvalidPaymentStateError) as ei:
        await pay.refund(ref)
    print(f"refund pending: REJECTED {type(ei.value).__name__}")


@pytest.mark.asyncio
async def test_refund_twice_idempotent() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=MockPravaClient())
    await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("rf-2"))
    await pay.refund(PaymentRef("rf-2"))
    bal = pay.balance(AgentId("alice"))
    await pay.refund(PaymentRef("rf-2"))
    assert pay.balance(AgentId("alice")) == bal == 100
    print("refund twice: IDEMPOTENT")


@pytest.mark.asyncio
async def test_refund_unknown_not_found() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=MockPravaClient())
    with pytest.raises(PaymentNotFoundError) as ei:
        await pay.refund(PaymentRef("does-not-exist"))
    assert ei.value.code == "NOT_FOUND"
    print(f"refund unknown: {type(ei.value).__name__} code={ei.value.code}")
