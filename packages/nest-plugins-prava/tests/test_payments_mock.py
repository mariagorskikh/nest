# SPDX-License-Identifier: Apache-2.0
"""Unit tests for PravaPayments in mock mode.

These tests run without API keys and verify the plugin behaves correctly
with deterministic mock mandate behavior.
"""

from __future__ import annotations

import pytest
from typing import Any

from nest_plugins_prava import (
    InvalidAmountError,
    MandateNotActiveError,
    MandateNotFoundError,
    PaymentNotFoundError,
    PravaPayments,
    ThresholdExceededError,
)
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus, Receipt


@pytest.fixture
def buyer_id() -> AgentId:
    """Buyer agent ID."""
    return AgentId("buyer-01")


@pytest.fixture
def seller_id() -> AgentId:
    """Seller agent ID."""
    return AgentId("seller-01")


@pytest.fixture
def mandate_id() -> str:
    """Test mandate ID."""
    return "mdt_test_001"


@pytest.fixture
def payments(buyer_id: AgentId, mandate_id: str) -> PravaPayments:
    """Create a PravaPayments instance in mock mode."""
    return PravaPayments(
        agent_id=buyer_id,
        mandate_map={buyer_id: mandate_id},
        approved_amount=10000,  # $100.00
    )


class TestMockModeBasics:
    """Basic mock mode functionality tests."""

    @pytest.mark.asyncio
    async def test_is_mock_mode(self, payments: PravaPayments) -> None:
        """Plugin should report mock mode when no secret key provided."""
        assert not payments.is_live_mode

    @pytest.mark.asyncio
    async def test_get_mandate_id(
        self, payments: PravaPayments, buyer_id: AgentId, mandate_id: str
    ) -> None:
        """Should return configured mandate ID."""
        assert payments.get_mandate_id(buyer_id) == mandate_id

    @pytest.mark.asyncio
    async def test_mandate_remaining_initial(self, payments: PravaPayments) -> None:
        """Initial mandate should have full balance."""
        assert payments.mandate_remaining() == 10000
        assert payments.mandate_spent() == 0


class TestPayments:
    """Payment execution tests."""

    @pytest.mark.asyncio
    async def test_single_payment(
        self, payments: PravaPayments, seller_id: AgentId, buyer_id: AgentId
    ) -> None:
        """Should execute a single payment successfully."""
        receipt = await payments.pay(
            to=seller_id,
            amount=Money(amount=1000, currency="USD"),
            ref=PaymentRef("pay-001"),
        )

        assert receipt.ref == PaymentRef("pay-001")
        assert receipt.payer == buyer_id
        assert receipt.payee == seller_id
        assert receipt.amount.amount == 1000
        assert receipt.timestamp is not None

    @pytest.mark.asyncio
    async def test_payment_updates_spent(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Payment should update mandate spent amount."""
        await payments.pay(
            to=seller_id,
            amount=Money(amount=2500),
            ref=PaymentRef("pay-002"),
        )

        assert payments.mandate_spent() == 2500
        assert payments.mandate_remaining() == 7500

    @pytest.mark.asyncio
    async def test_multiple_payments(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Should handle multiple sequential payments."""
        await payments.pay(seller_id, Money(amount=1000), PaymentRef("p1"))
        await payments.pay(seller_id, Money(amount=2000), PaymentRef("p2"))
        await payments.pay(seller_id, Money(amount=3000), PaymentRef("p3"))

        assert payments.mandate_spent() == 6000
        assert payments.mandate_remaining() == 4000


class TestThresholdEnforcement:
    """Threshold/cap enforcement tests."""

    @pytest.mark.asyncio
    async def test_exact_cap_succeeds(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Charge exactly at cap should succeed."""
        receipt = await payments.pay(
            to=seller_id,
            amount=Money(amount=10000),  # Exactly $100
            ref=PaymentRef("exact-cap"),
        )
        assert receipt.amount.amount == 10000
        assert payments.mandate_remaining() == 0

    @pytest.mark.asyncio
    async def test_over_cap_rejected(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Charge over cap should raise ThresholdExceededError."""
        with pytest.raises(ThresholdExceededError) as exc_info:
            await payments.pay(
                to=seller_id,
                amount=Money(amount=10001),  # $100.01 - over cap
                ref=PaymentRef("over-cap"),
            )

        assert exc_info.value.approved_amount == 10000
        assert exc_info.value.requested_amount == 10001
        assert exc_info.value.spent_amount == 0
        assert "THRESHOLD_EXCEEDED" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_cumulative_over_cap(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Cumulative charges exceeding cap should fail."""
        # First charge: $60
        await payments.pay(seller_id, Money(amount=6000), PaymentRef("c1"))

        # Second charge: $50 (would total $110 > $100)
        with pytest.raises(ThresholdExceededError) as exc_info:
            await payments.pay(seller_id, Money(amount=5000), PaymentRef("c2"))

        assert exc_info.value.spent_amount == 6000
        assert exc_info.value.requested_amount == 5000


class TestIdempotency:
    """Idempotency / duplicate reference tests."""

    @pytest.mark.asyncio
    async def test_duplicate_ref_returns_same_receipt(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Duplicate reference should return original receipt."""
        ref = PaymentRef("dup-test")

        receipt1 = await payments.pay(seller_id, Money(amount=1000), ref)
        receipt2 = await payments.pay(seller_id, Money(amount=1000), ref)

        assert receipt1.ref == receipt2.ref
        assert receipt1.timestamp == receipt2.timestamp

    @pytest.mark.asyncio
    async def test_duplicate_ref_no_double_charge(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Duplicate reference should not double-charge."""
        ref = PaymentRef("dup-charge")

        await payments.pay(seller_id, Money(amount=1000), ref)
        await payments.pay(seller_id, Money(amount=1000), ref)

        # Should only charge once
        assert payments.mandate_spent() == 1000


class TestMandateStates:
    """Mandate state management tests."""

    @pytest.mark.asyncio
    async def test_cancelled_mandate_rejected(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Charges to cancelled mandate should fail."""
        payments.cancel_mandate()

        with pytest.raises(MandateNotActiveError) as exc_info:
            await payments.pay(seller_id, Money(amount=100), PaymentRef("after-cancel"))

        assert exc_info.value.status == "cancelled"

    @pytest.mark.asyncio
    async def test_paused_mandate_rejected(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Charges to paused mandate should fail."""
        payments.pause_mandate()

        with pytest.raises(MandateNotActiveError) as exc_info:
            await payments.pay(seller_id, Money(amount=100), PaymentRef("while-paused"))

        assert exc_info.value.status == "paused"

    @pytest.mark.asyncio
    async def test_resumed_mandate_works(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Resumed mandate should accept charges again."""
        payments.pause_mandate()
        payments.resume_mandate()

        receipt = await payments.pay(
            seller_id, Money(amount=100), PaymentRef("after-resume")
        )
        assert receipt.amount.amount == 100


class TestInvalidInput:
    """Invalid input handling tests."""

    @pytest.mark.asyncio
    async def test_zero_amount_rejected(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Zero amount should raise InvalidAmountError."""
        with pytest.raises(InvalidAmountError):
            await payments.pay(seller_id, Money(amount=0), PaymentRef("zero"))

    @pytest.mark.asyncio
    async def test_negative_amount_rejected(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Negative amount should raise InvalidAmountError."""
        with pytest.raises(InvalidAmountError):
            await payments.pay(seller_id, Money(amount=-100), PaymentRef("neg"))

    @pytest.mark.asyncio
    async def test_unknown_payer_rejected(self, seller_id: AgentId) -> None:
        """Payer without mandate should fail."""
        payments = PravaPayments(
            agent_id=AgentId("unknown-buyer"),
            mandate_map={},  # No mandates configured
        )

        with pytest.raises(MandateNotFoundError):
            await payments.pay(seller_id, Money(amount=100), PaymentRef("no-mandate"))


class TestVerifyPayment:
    """Payment verification tests."""

    @pytest.mark.asyncio
    async def test_verify_confirmed_payment(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Completed payment should verify as CONFIRMED."""
        ref = PaymentRef("verify-test")
        await payments.pay(seller_id, Money(amount=100), ref)

        status = await payments.verify_payment(ref)
        assert status == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_verify_unknown_payment(self, payments: PravaPayments) -> None:
        """Unknown payment reference should return FAILED."""
        status = await payments.verify_payment(PaymentRef("nonexistent"))
        assert status == PaymentStatus.FAILED


class TestRefund:
    """Refund operation tests."""

    @pytest.mark.asyncio
    async def test_refund_reverses_charge(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Refund should reverse the charge in mock mode."""
        ref = PaymentRef("refund-test")
        await payments.pay(seller_id, Money(amount=1000), ref)
        assert payments.mandate_spent() == 1000

        await payments.refund(ref)
        assert payments.mandate_spent() == 0

    @pytest.mark.asyncio
    async def test_refund_removes_receipt(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Refund should remove the receipt."""
        ref = PaymentRef("refund-receipt")
        await payments.pay(seller_id, Money(amount=100), ref)

        await payments.refund(ref)

        status = await payments.verify_payment(ref)
        # After refund, payment should show as REFUNDED or FAILED (receipt removed)
        assert status in (PaymentStatus.REFUNDED, PaymentStatus.FAILED)

    @pytest.mark.asyncio
    async def test_refund_nonexistent_fails(self, payments: PravaPayments) -> None:
        """Refunding nonexistent payment should fail."""
        with pytest.raises(PaymentNotFoundError):
            await payments.refund(PaymentRef("nonexistent"))


class TestQuote:
    """Quote method tests."""

    @pytest.mark.asyncio
    async def test_quote_returns_fixed_price(self, payments: PravaPayments) -> None:
        """Quote should return fixed price."""
        from nest_sdk import ServiceRef

        quote = await payments.quote(ServiceRef("test-service"))
        assert quote.service == ServiceRef("test-service")
        assert quote.price.amount == 10  # $0.10 fixed
        assert quote.ttl_seconds == 300


class TestSharedState:
    """Shared state between plugin instances tests."""

    @pytest.mark.asyncio
    async def test_shared_mandate_state(self) -> None:
        """Multiple instances should share mandate state."""
        shared_mandates: dict[str, Any] = {}
        shared_receipts: dict[PaymentRef, Receipt] = {}

        buyer1 = PravaPayments(
            agent_id=AgentId("b1"),
            mandate_map={AgentId("b1"): "shared-mdt", AgentId("b2"): "shared-mdt"},
            mandates=shared_mandates,
            receipts=shared_receipts,
            approved_amount=5000,
        )

        buyer2 = PravaPayments(
            agent_id=AgentId("b2"),
            mandate_map={AgentId("b1"): "shared-mdt", AgentId("b2"): "shared-mdt"},
            mandates=shared_mandates,
            receipts=shared_receipts,
        )

        seller = AgentId("seller")

        # Buyer 1 charges $30
        await buyer1.pay(seller, Money(amount=3000), PaymentRef("b1-p1"))

        # Buyer 2 sees the spent amount via shared state
        assert buyer2.mandate_spent(AgentId("b1")) == 3000

    @pytest.mark.asyncio
    async def test_shared_receipt_lookup(self) -> None:
        """Receipts should be visible across instances."""
        shared_mandates: dict[str, Any] = {}
        shared_receipts: dict[PaymentRef, Receipt] = {}

        buyer = PravaPayments(
            agent_id=AgentId("b1"),
            mandate_map={AgentId("b1"): "mdt1"},
            mandates=shared_mandates,
            receipts=shared_receipts,
        )

        observer = PravaPayments(
            agent_id=AgentId("observer"),
            mandate_map={AgentId("b1"): "mdt1"},
            mandates=shared_mandates,
            receipts=shared_receipts,
        )

        ref = PaymentRef("shared-receipt")
        await buyer.pay(AgentId("seller"), Money(amount=100), ref)

        # Observer can verify the payment via shared receipts
        status = await observer.verify_payment(ref)
        assert status == PaymentStatus.CONFIRMED


class TestConservationInvariant:
    """Conservation invariant tests."""

    @pytest.mark.asyncio
    async def test_charges_equal_spent(
        self, payments: PravaPayments, seller_id: AgentId
    ) -> None:
        """Sum of charges should equal mandate spent."""
        await payments.pay(seller_id, Money(amount=1000), PaymentRef("c1"))
        await payments.pay(seller_id, Money(amount=2000), PaymentRef("c2"))
        await payments.pay(seller_id, Money(amount=500), PaymentRef("c3"))

        # Get mandate and sum charges
        mandate_id = payments.get_mandate_id()
        assert mandate_id is not None
        mandate = payments._mandates[mandate_id]

        total_charges = sum(c.amount for c in mandate.charges.values())
        assert total_charges == mandate.spent
        assert total_charges == 3500
