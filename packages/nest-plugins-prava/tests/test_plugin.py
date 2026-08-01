# SPDX-License-Identifier: Apache-2.0
"""Tests for the NANDA Prava payments adapter."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from nest_core.layers.payments import Payments
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus, Receipt, ServiceRef

from nanda_prava_adapter.plugin import (
    MerchantOutcome,
    PayeeProfile,
    PravaPayments,
    PravaSession,
)


@dataclass
class FakeTransport:
    results: list[dict[str, object]]
    create_calls: int = 0
    reports: list[tuple[str, str, bool]] = field(default_factory=lambda: [])
    revoked: list[str] = field(default_factory=lambda: [])

    def create_session(
        self, *, profile: PayeeProfile, amount: Money, payment_ref: PaymentRef
    ) -> PravaSession:
        del profile, amount, payment_ref
        self.create_calls += 1
        return PravaSession("ses_1", "https://pay.prava.space/s/ses_1")

    def payment_result(self, session_id: str) -> dict[str, object]:
        assert session_id == "ses_1"
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]

    def report_status(
        self,
        *,
        session_id: str,
        transaction_ref: str,
        approved: bool,
        outcome: MerchantOutcome,
    ) -> None:
        del outcome
        self.reports.append((session_id, transaction_ref, approved))

    def revoke_session(self, session_id: str) -> None:
        self.revoked.append(session_id)


@dataclass
class FakeExecutor:
    approved: bool = True
    seen_credentials: dict[str, str] | None = None
    saw_complete_credentials: bool = False

    async def execute(
        self, credentials: dict[str, str], amount: Money, payment_ref: PaymentRef
    ) -> MerchantOutcome:
        del amount, payment_ref
        self.saw_complete_credentials = set(credentials) == {
            "token",
            "dynamic_cvv",
            "expiry_month",
            "expiry_year",
        }
        self.seen_credentials = credentials
        return MerchantOutcome(self.approved, "sandbox", "00" if self.approved else "05")


@dataclass
class FakeRefundHandler:
    refs: list[PaymentRef] = field(default_factory=lambda: [])

    async def refund(self, receipt: Receipt) -> None:
        self.refs.append(receipt.ref)


def approved_result() -> dict[str, object]:
    return {
        "status": "awaiting_result",
        "transactions": [
            {
                "line_items": [
                    {
                        "txn_ref_id": "txn_ref_1",
                        "token": "token-secret",
                        "dynamic_cvv": "123",
                        "expiry_month": "12",
                        "expiry_year": "2030",
                    }
                ]
            }
        ],
    }


def plugin(
    transport: FakeTransport,
    executor: FakeExecutor | None = None,
    refund_handler: FakeRefundHandler | None = None,
) -> PravaPayments:
    return PravaPayments(
        AgentId("buyer"),
        transport=transport,
        executor=executor or FakeExecutor(),
        refund_handler=refund_handler,
        payees={
            AgentId("seller"): PayeeProfile(
                "NANDA Seller",
                "https://nandatown.projectnanda.org",
                "US",
                "buyer",
                "buyer@example.com",
            )
        },
        services={ServiceRef("service"): Money(amount=125, currency="USD")},
        poll_interval_seconds=0,
        poll_timeout_seconds=1,
    )


@pytest.mark.asyncio
async def test_matches_nanda_payments_protocol_and_quotes() -> None:
    payments = plugin(FakeTransport([approved_result()]))
    assert isinstance(payments, Payments)
    quote = await payments.quote(ServiceRef("service"))
    assert quote.price == Money(amount=125, currency="USD")
    assert quote.metadata == {"provider": "prava", "approval_required": True}


@pytest.mark.asyncio
async def test_success_is_idempotent_and_does_not_store_credentials() -> None:
    transport = FakeTransport([approved_result()])
    executor = FakeExecutor()
    payments = plugin(transport, executor)
    ref = PaymentRef("pay-1")
    amount = Money(amount=125, currency="USD")

    receipt = await payments.pay(AgentId("seller"), amount, ref)
    duplicate = await payments.pay(AgentId("seller"), amount, ref)

    assert duplicate == receipt
    assert transport.create_calls == 1
    assert transport.reports == [("ses_1", "txn_ref_1", True)]
    assert await payments.verify_payment(ref) == PaymentStatus.CONFIRMED
    assert executor.saw_complete_credentials is True
    assert executor.seen_credentials == {}


@pytest.mark.asyncio
async def test_decline_is_reported_and_never_returns_a_receipt() -> None:
    transport = FakeTransport([approved_result()])
    payments = plugin(transport, FakeExecutor(approved=False))
    ref = PaymentRef("declined")

    with pytest.raises(RuntimeError, match="merchant declined"):
        await payments.pay(AgentId("seller"), Money(amount=125, currency="USD"), ref)

    assert transport.reports == [("ses_1", "txn_ref_1", False)]
    assert await payments.verify_payment(ref) == PaymentStatus.FAILED


@pytest.mark.asyncio
async def test_prava_failure_revokes_session_and_is_stable() -> None:
    transport = FakeTransport([{"status": "failed"}])
    payments = plugin(transport)
    ref = PaymentRef("failed")

    with pytest.raises(RuntimeError, match="failed before merchant"):
        await payments.pay(AgentId("seller"), Money(amount=125, currency="USD"), ref)

    assert transport.revoked == []
    assert await payments.verify_payment(ref) == PaymentStatus.FAILED


@pytest.mark.asyncio
async def test_refund_delegates_to_merchant_and_is_idempotent() -> None:
    refund_handler = FakeRefundHandler()
    payments = plugin(FakeTransport([approved_result()]), refund_handler=refund_handler)
    ref = PaymentRef("refund")
    await payments.pay(AgentId("seller"), Money(amount=125, currency="USD"), ref)

    await payments.refund(ref)
    await payments.refund(ref)

    assert refund_handler.refs == [ref]
    assert await payments.verify_payment(ref) == PaymentStatus.REFUNDED


@pytest.mark.asyncio
async def test_refund_fails_closed_without_merchant_handler() -> None:
    payments = plugin(FakeTransport([approved_result()]))
    ref = PaymentRef("refund-unconfigured")
    await payments.pay(AgentId("seller"), Money(amount=125, currency="USD"), ref)

    with pytest.raises(NotImplementedError, match="Prava exposes no separate refund"):
        await payments.refund(ref)


@pytest.mark.asyncio
async def test_unknown_service_payee_and_nonpositive_amount_fail_closed() -> None:
    payments = plugin(FakeTransport([approved_result()]))
    with pytest.raises(ValueError, match="unknown service"):
        await payments.quote(ServiceRef("missing"))
    with pytest.raises(ValueError, match="no Prava merchant profile"):
        await payments.pay(AgentId("missing"), Money(amount=100, currency="USD"), PaymentRef("p1"))
    with pytest.raises(ValueError, match="positive"):
        await payments.pay(AgentId("seller"), Money(amount=0, currency="USD"), PaymentRef("p2"))
