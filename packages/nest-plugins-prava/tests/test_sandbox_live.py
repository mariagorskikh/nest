# SPDX-License-Identifier: Apache-2.0
"""Live sandbox tests for PravaPayments.

These tests hit the real Prava sandbox API and require credentials.
They are skipped unless PRAVA_SECRET_KEY and PRAVA_MANDATE_ID are set.

Usage:
    export PRAVA_SECRET_KEY=sk_test_...
    export PRAVA_MANDATE_ID=mdt_01...  # Pre-provisioned test mandate
    pytest packages/nest-plugins-prava/tests/test_sandbox_live.py -v -m live
"""

from __future__ import annotations

import os
import uuid

import pytest
from nest_plugins_prava import (
    PravaClient,
    PravaPayments,
    ThresholdExceededError,
)
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus

# Skip all tests in this module if credentials not set
pytestmark = pytest.mark.live

PRAVA_SECRET_KEY = os.environ.get("PRAVA_SECRET_KEY")
PRAVA_MANDATE_ID = os.environ.get("PRAVA_MANDATE_ID")
PRAVA_BASE_URL = os.environ.get("PRAVA_BASE_URL", "https://sandbox.api.prava.space")

skip_if_no_credentials = pytest.mark.skipif(
    not PRAVA_SECRET_KEY or not PRAVA_MANDATE_ID,
    reason="PRAVA_SECRET_KEY and PRAVA_MANDATE_ID required for live tests",
)


def unique_ref() -> PaymentRef:
    """Generate a unique payment reference."""
    return PaymentRef(f"live-test-{uuid.uuid4().hex[:12]}")


@skip_if_no_credentials
class TestLiveClient:
    """Live tests for the PravaClient."""

    @pytest.fixture
    async def client(self) -> PravaClient:
        """Create a live client."""
        assert PRAVA_SECRET_KEY is not None
        client = PravaClient(
            secret_key=PRAVA_SECRET_KEY,
            base_url=PRAVA_BASE_URL,
        )
        yield client
        await client.close()

    @pytest.mark.asyncio
    async def test_get_mandate(self, client: PravaClient) -> None:
        """Should retrieve mandate info from live API."""
        assert PRAVA_MANDATE_ID is not None
        mandate = await client.get_mandate(PRAVA_MANDATE_ID)

        assert mandate.mandate_id is not None
        assert mandate.approved_amount > 0
        assert mandate.status in ("active", "paused", "cancelled", "expired")

    @pytest.mark.asyncio
    async def test_charge_small_amount(self, client: PravaClient) -> None:
        """Should charge a small amount successfully."""
        assert PRAVA_MANDATE_ID is not None
        ref = f"client-test-{uuid.uuid4().hex[:8]}"

        result = await client.charge(
            mandate_id=PRAVA_MANDATE_ID,
            amount=100,  # $1.00
            reference=ref,
        )

        assert result.transaction_id is not None
        assert result.reference == ref
        assert result.amount == 100
        assert result.status in ("awaiting_result", "completed")

        # Report the charge
        if result.status != "failed":
            await client.report_charge(
                mandate_id=PRAVA_MANDATE_ID,
                transaction_id=result.transaction_id,
                outcome="APPROVED",
            )

    @pytest.mark.asyncio
    async def test_find_charge_by_reference(self, client: PravaClient) -> None:
        """Should find a charge by reference."""
        assert PRAVA_MANDATE_ID is not None
        ref = f"find-test-{uuid.uuid4().hex[:8]}"

        # Create a charge
        result = await client.charge(
            mandate_id=PRAVA_MANDATE_ID,
            amount=50,  # $0.50
            reference=ref,
        )

        # Report it
        if result.transaction_id:
            await client.report_charge(
                mandate_id=PRAVA_MANDATE_ID,
                transaction_id=result.transaction_id,
                outcome="APPROVED",
            )

        # Find it
        charge = await client.find_charge_by_reference(PRAVA_MANDATE_ID, ref)
        assert charge is not None
        assert charge.get("reference") == ref or charge.get("ref") == ref


@skip_if_no_credentials
class TestLivePayments:
    """Live tests for the PravaPayments plugin."""

    @pytest.fixture
    def buyer_id(self) -> AgentId:
        return AgentId("live-buyer")

    @pytest.fixture
    def seller_id(self) -> AgentId:
        return AgentId("live-seller")

    @pytest.fixture
    async def payments(self, buyer_id: AgentId) -> PravaPayments:
        """Create a live payments instance."""
        assert PRAVA_SECRET_KEY is not None
        assert PRAVA_MANDATE_ID is not None

        payments = PravaPayments(
            agent_id=buyer_id,
            mandate_map={buyer_id: PRAVA_MANDATE_ID},
            prava_secret_key=PRAVA_SECRET_KEY,
            prava_base_url=PRAVA_BASE_URL,
        )
        yield payments
        await payments.close()

    @pytest.mark.asyncio
    async def test_is_live_mode(self, payments: PravaPayments) -> None:
        """Should report live mode."""
        assert payments.is_live_mode

    @pytest.mark.asyncio
    async def test_pay_small_amount(
        self,
        payments: PravaPayments,
        seller_id: AgentId,
        buyer_id: AgentId,
    ) -> None:
        """Should execute a small payment successfully."""
        ref = unique_ref()

        receipt = await payments.pay(
            to=seller_id,
            amount=Money(amount=100, currency="USD"),  # $1.00
            ref=ref,
        )

        assert receipt.ref == ref
        assert receipt.payer == buyer_id
        assert receipt.payee == seller_id
        assert receipt.amount.amount == 100

    @pytest.mark.asyncio
    async def test_verify_payment(
        self,
        payments: PravaPayments,
        seller_id: AgentId,
    ) -> None:
        """Should verify a completed payment."""
        ref = unique_ref()

        await payments.pay(
            to=seller_id,
            amount=Money(amount=75),  # $0.75
            ref=ref,
        )

        status = await payments.verify_payment(ref)
        assert status == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_idempotent_duplicate(
        self,
        payments: PravaPayments,
        seller_id: AgentId,
    ) -> None:
        """Duplicate reference should return same receipt."""
        ref = unique_ref()

        receipt1 = await payments.pay(seller_id, Money(amount=50), ref)
        receipt2 = await payments.pay(seller_id, Money(amount=50), ref)

        assert receipt1.ref == receipt2.ref
        # Should be the same receipt (same timestamp)
        assert receipt1.timestamp == receipt2.timestamp


@skip_if_no_credentials
class TestLiveFailures:
    """Live failure case tests.

    These tests intentionally trigger errors to verify error handling.
    """

    @pytest.fixture
    def buyer_id(self) -> AgentId:
        return AgentId("fail-buyer")

    @pytest.fixture
    async def payments(self, buyer_id: AgentId) -> PravaPayments:
        """Create a live payments instance."""
        assert PRAVA_SECRET_KEY is not None
        assert PRAVA_MANDATE_ID is not None

        payments = PravaPayments(
            agent_id=buyer_id,
            mandate_map={buyer_id: PRAVA_MANDATE_ID},
            prava_secret_key=PRAVA_SECRET_KEY,
            prava_base_url=PRAVA_BASE_URL,
        )
        yield payments
        await payments.close()

    @pytest.mark.asyncio
    async def test_over_cap_rejected(
        self,
        payments: PravaPayments,
    ) -> None:
        """Charge over mandate cap should raise ThresholdExceededError.

        Note: This test may fail if the test mandate has a very high cap.
        It attempts to charge $999,999 which should exceed most test mandates.
        """
        seller = AgentId("seller")
        ref = unique_ref()

        # Try to charge way over any reasonable cap
        try:
            await payments.pay(
                to=seller,
                amount=Money(amount=99999900),  # $999,999
                ref=ref,
            )
            # If we get here, the mandate has a very high cap (unexpected)
            pytest.skip("Mandate cap too high for over-cap test")
        except ThresholdExceededError as e:
            # The error was raised correctly - that's what matters
            assert e.code == "THRESHOLD_EXCEEDED"
            # Note: approved_amount may be 0 if API doesn't include it in error response
            assert e.requested_amount == 99999900


@skip_if_no_credentials
class TestLiveRedaction:
    """Verify sensitive data redaction in live responses."""

    @pytest.fixture
    async def client(self) -> PravaClient:
        """Create a live client."""
        assert PRAVA_SECRET_KEY is not None
        client = PravaClient(
            secret_key=PRAVA_SECRET_KEY,
            base_url=PRAVA_BASE_URL,
        )
        yield client
        await client.close()

    @pytest.mark.asyncio
    async def test_charge_response_redacted(self, client: PravaClient) -> None:
        """Charge response should have sensitive data redacted."""
        assert PRAVA_MANDATE_ID is not None
        ref = f"redact-test-{uuid.uuid4().hex[:8]}"

        result = await client.charge(
            mandate_id=PRAVA_MANDATE_ID,
            amount=25,  # $0.25
            reference=ref,
        )

        # Check raw response for sensitive fields
        raw = result.raw_response

        # These fields should NOT contain actual values
        sensitive_keys = ["cardNumber", "card_number", "pan", "cvv", "cvc", "expiry"]
        for key in sensitive_keys:
            if key in raw:
                assert raw[key] == "[REDACTED]", f"Field {key} was not redacted"

        # Report to clean up
        if result.transaction_id:
            await client.report_charge(
                mandate_id=PRAVA_MANDATE_ID,
                transaction_id=result.transaction_id,
                outcome="APPROVED",
            )
