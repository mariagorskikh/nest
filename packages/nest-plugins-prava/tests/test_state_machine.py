# SPDX-License-Identifier: Apache-2.0
"""Item 4 — payment state machine audit."""

from __future__ import annotations

import pytest
from nest_plugins_prava import (
    DuplicatePaymentRefError,
    InvalidPaymentStateError,
    PravaPayments,
)
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.errors import PravaApiError
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_plugins_prava.state import PaymentPhase, PaymentRecord
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


STATE_TABLE = """
Current state | Action              | Expected next state
--------------|---------------------|--------------------
(none)        | quote               | quote cached (TTL)
(none)        | pay                 | PENDING → … → CONFIRMED
PENDING       | verify              | PENDING (or FAILED if rail failed)
CONFIRMED     | pay same ref/params | CONFIRMED (idempotent, same receipt)
CONFIRMED     | pay conflict params | DuplicatePaymentRefError
CONFIRMED     | refund              | REFUNDED
FAILED        | refund              | InvalidPaymentStateError
FAILED        | pay same ref        | retry allowed → CONFIRMED
REFUNDED      | refund again        | REFUNDED (idempotent no-op)
REFUNDED      | pay same ref        | DuplicatePaymentRefError
PENDING       | refund              | InvalidPaymentStateError
"""


@pytest.mark.asyncio
async def test_happy_path_quote_pay_pending_confirmed() -> None:
    print(STATE_TABLE)
    client = MockPravaClient(poll_statuses=["pending", "awaiting_result"])
    pay = PravaPayments(
        AgentId("alice"),
        initial_balance=1000,
        client=client,
        poll_attempts=5,
        poll_interval_s=0.001,
        default_fee=50,
    )
    q = await pay.quote(ServiceRef("sku"))
    assert q.price.amount == 50

    # Drive pay; during flow record transitions PENDING→CONFIRMED
    receipt = await pay.pay(AgentId("bob"), q.price, PaymentRef("sm-1"))
    rec = pay.payment_record(PaymentRef("sm-1"))
    assert rec is not None
    assert rec.status is PaymentStatus.CONFIRMED
    assert rec.phase is PaymentPhase.CONFIRMED
    assert receipt.ref == PaymentRef("sm-1")
    assert await pay.verify_payment(PaymentRef("sm-1")) is PaymentStatus.CONFIRMED
    print(f"happy: phase={rec.phase.value} status={rec.status.value} session={rec.session_id}")


@pytest.mark.asyncio
async def test_confirmed_pay_again_idempotent_not_new_charge() -> None:
    client = MockPravaClient()
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=client)
    await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("sm-2"))
    n = client.call_count
    r2 = await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("sm-2"))
    assert client.call_count == n
    assert r2.amount.amount == 10


@pytest.mark.asyncio
async def test_confirmed_pay_conflict_rejected() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("sm-3"))
    with pytest.raises(DuplicatePaymentRefError):
        await pay.pay(AgentId("carol"), Money(amount=10), PaymentRef("sm-3"))


@pytest.mark.asyncio
async def test_failed_refund_rejected() -> None:
    pay = PravaPayments(
        AgentId("alice"),
        initial_balance=1000,
        client=MockPravaClient(fail_on_create=True),
    )
    with pytest.raises(PravaApiError):
        await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("sm-4"))
    assert await pay.verify_payment(PaymentRef("sm-4")) is PaymentStatus.FAILED
    with pytest.raises(InvalidPaymentStateError):
        await pay.refund(PaymentRef("sm-4"))


@pytest.mark.asyncio
async def test_pending_refund_rejected() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    # Inject a stuck PENDING record (illegal to refund).
    ref = PaymentRef("sm-pending")
    rec = PaymentRecord(
        ref=ref,
        payer=AgentId("alice"),
        payee=AgentId("bob"),
        amount=Money(amount=10),
        phase=PaymentPhase.SESSION_CREATED,
        status=PaymentStatus.PENDING,
        session_id="sess_x",
        locked_credits=0,
    )
    pay._records[ref] = rec  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(InvalidPaymentStateError):
        await pay.refund(ref)


@pytest.mark.asyncio
async def test_refunded_refund_again_idempotent() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("sm-5"))
    await pay.refund(PaymentRef("sm-5"))
    await pay.refund(PaymentRef("sm-5"))  # no error
    assert await pay.verify_payment(PaymentRef("sm-5")) is PaymentStatus.REFUNDED


@pytest.mark.asyncio
async def test_refunded_pay_again_rejected() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("sm-6"))
    await pay.refund(PaymentRef("sm-6"))
    with pytest.raises(DuplicatePaymentRefError):
        await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("sm-6"))
