# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the Prava payments plugin.

These tests verify the plugin integrates correctly with the nest runtime
and can be used in scenarios.
"""

from __future__ import annotations

import pytest
from nest_core.plugins import PluginRegistry
from nest_plugins_prava import PravaPayments
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


class TestPluginRegistration:
    """Verify plugin registration via entry points."""

    def test_plugin_discoverable(self) -> None:
        """Plugin should be discoverable via PluginRegistry."""
        registry = PluginRegistry()

        # The plugin should be resolvable by name "prava"
        cls = registry.resolve("payments", "prava")
        assert cls is PravaPayments

    def test_plugin_class_matches(self) -> None:
        """Resolved class should be our PravaPayments."""
        registry = PluginRegistry()
        cls = registry.resolve("payments", "prava")

        # Should be the same class
        assert cls.__name__ == "PravaPayments"
        assert hasattr(cls, "pay")
        assert hasattr(cls, "verify_payment")
        assert hasattr(cls, "refund")
        assert hasattr(cls, "quote")


class TestPluginInstantiation:
    """Verify plugin can be instantiated correctly."""

    def test_mock_mode_instantiation(self) -> None:
        """Plugin should instantiate in mock mode without credentials."""
        buyer = AgentId("buyer-01")
        payments = PravaPayments(
            agent_id=buyer,
            mandate_map={buyer: "mdt_test_001"},
        )

        assert payments.agent_id == buyer
        assert not payments.is_live_mode
        assert payments.get_mandate_id() == "mdt_test_001"

    def test_multi_agent_instantiation(self) -> None:
        """Should handle multiple agents with different mandates."""
        buyers = [AgentId(f"buyer-{i}") for i in range(5)]
        mandate_map = {b: f"mdt_mock_{i}" for i, b in enumerate(buyers)}

        # Create plugin for first buyer
        payments = PravaPayments(
            agent_id=buyers[0],
            mandate_map=mandate_map,
        )

        # Should be able to look up any agent's mandate
        for i, buyer in enumerate(buyers):
            assert payments.get_mandate_id(buyer) == f"mdt_mock_{i}"


class TestPaymentsProtocolCompliance:
    """Verify the plugin satisfies the Payments protocol."""

    @pytest.fixture
    def payments(self) -> PravaPayments:
        """Create a mock payments instance."""
        buyer = AgentId("test-buyer")
        return PravaPayments(
            agent_id=buyer,
            mandate_map={buyer: "mdt_test"},
            approved_amount=10000,
        )

    @pytest.mark.asyncio
    async def test_quote_method(self, payments: PravaPayments) -> None:
        """quote() should return a Quote object."""
        from nest_sdk import ServiceRef

        quote = await payments.quote(ServiceRef("test-service"))

        assert quote.service == ServiceRef("test-service")
        assert quote.price.amount >= 0
        assert quote.ttl_seconds > 0

    @pytest.mark.asyncio
    async def test_pay_method(self, payments: PravaPayments) -> None:
        """pay() should return a Receipt."""
        seller = AgentId("test-seller")
        receipt = await payments.pay(
            to=seller,
            amount=Money(amount=500),
            ref=PaymentRef("test-pay-001"),
        )

        assert receipt.ref == PaymentRef("test-pay-001")
        assert receipt.payer == payments.agent_id
        assert receipt.payee == seller
        assert receipt.amount.amount == 500

    @pytest.mark.asyncio
    async def test_verify_payment_method(self, payments: PravaPayments) -> None:
        """verify_payment() should return PaymentStatus."""
        seller = AgentId("test-seller")
        ref = PaymentRef("test-verify-001")

        await payments.pay(to=seller, amount=Money(amount=100), ref=ref)
        status = await payments.verify_payment(ref)

        assert status == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_refund_method(self, payments: PravaPayments) -> None:
        """refund() should complete without error."""
        seller = AgentId("test-seller")
        ref = PaymentRef("test-refund-001")

        await payments.pay(to=seller, amount=Money(amount=100), ref=ref)

        # Should not raise
        await payments.refund(ref)

        # After refund, verify should show REFUNDED or FAILED
        status = await payments.verify_payment(ref)
        assert status in (PaymentStatus.REFUNDED, PaymentStatus.FAILED)


class TestScenarioCompatibility:
    """Test plugin compatibility with scenario agent configurations."""

    @pytest.mark.asyncio
    async def test_buyer_seller_flow(self) -> None:
        """Simulate a buyer-seller transaction flow."""
        # Setup: 5 buyers, 5 sellers (like prava_mandates.yaml)
        buyers = [AgentId(f"buyer-{i}") for i in range(5)]
        sellers = [AgentId(f"seller-{i}") for i in range(5)]

        # Each buyer has a mandate with $100 cap
        mandate_map = {b: f"mdt_mock_buyer_{i}" for i, b in enumerate(buyers)}

        # Shared state for multi-agent scenario
        shared_mandates: dict[str, object] = {}
        shared_receipts: dict[PaymentRef, object] = {}

        # Create payment instances for each buyer
        buyer_payments = [
            PravaPayments(
                agent_id=buyer,
                mandate_map=mandate_map,
                approved_amount=10000,  # $100
                mandates=shared_mandates,  # type: ignore[arg-type]
                receipts=shared_receipts,  # type: ignore[arg-type]
            )
            for buyer in buyers
        ]

        # Simulate transactions
        for i, (buyer_pay, seller) in enumerate(zip(buyer_payments, sellers, strict=True)):
            receipt = await buyer_pay.pay(
                to=seller,
                amount=Money(amount=1000 + i * 100),  # $10-$14
                ref=PaymentRef(f"order-{i}"),
            )
            assert receipt.payee == seller

        # Verify all buyers' spending is tracked
        total_spent = sum(p.mandate_spent() for p in buyer_payments)
        expected = sum(1000 + i * 100 for i in range(5))  # 1000+1100+1200+1300+1400
        assert total_spent == expected

    @pytest.mark.asyncio
    async def test_cap_enforcement_in_scenario(self) -> None:
        """Verify cap enforcement works in multi-transaction scenarios."""
        from nest_plugins_prava import ThresholdExceededError

        buyer = AgentId("buyer-capped")
        seller = AgentId("seller")

        payments = PravaPayments(
            agent_id=buyer,
            mandate_map={buyer: "mdt_capped"},
            approved_amount=5000,  # $50 cap
        )

        # First transaction: $30
        await payments.pay(seller, Money(amount=3000), PaymentRef("t1"))

        # Second transaction: $15
        await payments.pay(seller, Money(amount=1500), PaymentRef("t2"))

        # Third transaction: $10 - should fail (would exceed $50)
        with pytest.raises(ThresholdExceededError):
            await payments.pay(seller, Money(amount=1000), PaymentRef("t3"))

        # Verify total spent is $45
        assert payments.mandate_spent() == 4500
