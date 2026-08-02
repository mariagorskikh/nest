# SPDX-License-Identifier: Apache-2.0
"""Prava mandate-backed payments plugin for nest.

This module implements the Payments protocol using Prava's Agentic Payments API.
It supports both live mode (with real API calls) and mock mode (for deterministic
CI testing without API credentials).

Example::

    from nest_plugins_prava import PravaPayments
    from nest_sdk import AgentId, Money, PaymentRef

    # Live mode with real API
    payments = PravaPayments(
        agent_id=AgentId("buyer-01"),
        mandate_map={AgentId("buyer-01"): "mdt_real_mandate_id"},
        prava_secret_key="sk_test_...",
    )

    # Mock mode for testing
    payments = PravaPayments(
        agent_id=AgentId("buyer-01"),
        mandate_map={AgentId("buyer-01"): "mdt_mock_001"},
        # No secret key = mock mode
    )

    # Execute a payment
    receipt = await payments.pay(
        to=AgentId("seller-01"),
        amount=Money(amount=1250, currency="USD"),
        ref=PaymentRef("order-123"),
    )
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from nest_sdk import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)

from .client import PravaClient
from .errors import (
    DuplicateReferenceError,
    InvalidAmountError,
    MandateNotActiveError,
    MandateNotFoundError,
    PaymentNotFoundError,
    PravaError,
    ThresholdExceededError,
)

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_PRAVA_BASE_URL = "https://sandbox.api.prava.space"
DEFAULT_APPROVED_AMOUNT_CENTS = 100_00  # $100.00


@dataclass
class MockCharge:
    """Record of a charge against a mock mandate.

    Attributes:
        transaction_id: Unique transaction identifier.
        reference: Idempotency reference.
        amount: Charge amount in cents.
        status: Charge status (awaiting_result, completed, failed, refunded).
        payee: Agent receiving the payment.
        reported: Whether charge outcome was reported.
    """

    transaction_id: str
    reference: str
    amount: int
    status: str
    payee: AgentId
    reported: bool = False


@dataclass
class MockMandate:
    """Mock mandate state for deterministic testing.

    Provides identical error semantics to the live Prava API without
    making actual network calls.

    Attributes:
        mandate_id: The mandate identifier.
        approved_amount: Maximum approved amount in cents.
        spent: Total amount charged so far.
        status: Mandate status (active, paused, cancelled).
        charges: Charges keyed by transaction ID.
        references: Set of used references for idempotency.
    """

    mandate_id: str
    approved_amount: int
    spent: int = 0
    status: str = "active"
    charges: dict[str, MockCharge] = field(default_factory=lambda: {})
    references: dict[str, str] = field(default_factory=lambda: {})  # ref -> txn_id


class PravaPayments:
    """Prava mandate-backed payments implementing the nest Payments protocol.

    This plugin maps AgentId -> mandate_id for payment processing. Each buyer
    agent should have a pre-provisioned mandate (created via Prava session +
    passkey approval) before the scenario runs.

    Supports two modes:
    - **Live mode**: When `prava_secret_key` is provided, makes real API calls.
    - **Mock mode**: When no secret key, uses deterministic mock behavior.

    Example::

        # Configure with mandate mapping
        payments = PravaPayments(
            agent_id=AgentId("buyer-01"),
            mandate_map={
                AgentId("buyer-01"): "mdt_01ABCD...",
                AgentId("buyer-02"): "mdt_02EFGH...",
            },
            prava_secret_key=os.environ.get("PRAVA_SECRET_KEY"),
        )

        # Pay a seller
        receipt = await payments.pay(
            to=AgentId("seller-01"),
            amount=Money(amount=1000, currency="USD"),
            ref=PaymentRef("order-xyz"),
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        mandate_map: dict[AgentId, str] | None = None,
        prava_secret_key: str | None = None,
        prava_base_url: str = DEFAULT_PRAVA_BASE_URL,
        approved_amount: int = DEFAULT_APPROVED_AMOUNT_CENTS,
        # Shared state for multi-agent scenarios
        mandates: dict[str, MockMandate] | None = None,
        receipts: dict[PaymentRef, Receipt] | None = None,
        # Marketplace factory compatibility
        initial_balance: int | None = None,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Any] | None = None,  # noqa: ARG002
    ) -> None:
        """Initialize the Prava payments plugin.

        Args:
            agent_id: The agent this plugin instance serves.
            mandate_map: Mapping of AgentId -> mandate_id for all buyers.
                If None, auto-generates mandate IDs based on agent_id.
            prava_secret_key: API secret key. If None, uses mock mode.
            prava_base_url: Prava API base URL.
            approved_amount: Default approved amount for mock mandates (cents).
            mandates: Shared mock mandate state (for multi-agent scenarios).
            receipts: Shared receipt storage (for multi-agent scenarios).
            initial_balance: Default balance for marketplace agents.
            balances: Shared balance dict for marketplace compatibility.
            payments: (Ignored) For marketplace factory compatibility.
        """
        self._agent_id = agent_id
        self._approved_amount = approved_amount
        self._prava_base_url = prava_base_url

        # If no mandate_map provided, auto-generate from agent_id
        if mandate_map is None:
            mandate_map = {agent_id: f"mdt_auto_{agent_id}"}
        self._mandate_map = mandate_map

        # Shared state (allows multiple plugin instances to share ledger)
        self._mandates = mandates if mandates is not None else {}
        self._receipts = receipts if receipts is not None else {}

        # Marketplace compatibility: balance tracking
        self._balances = balances if balances is not None else {}
        self._initial_balance = initial_balance if initial_balance is not None else 1000
        if agent_id not in self._balances:
            self._balances[agent_id] = self._initial_balance

        # Client for live mode
        self._client: PravaClient | None = None
        if prava_secret_key:
            self._client = PravaClient(
                secret_key=prava_secret_key,
                base_url=prava_base_url,
            )

        # Initialize mock mandates for configured agents
        if not self._client:
            for mid in mandate_map.values():
                if mid not in self._mandates:
                    self._mandates[mid] = MockMandate(
                        mandate_id=mid,
                        approved_amount=approved_amount,
                    )

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def agent_id(self) -> AgentId:
        """The agent ID this plugin serves."""
        return self._agent_id

    @property
    def is_live_mode(self) -> bool:
        """True if using real Prava API, False if mock mode."""
        return self._client is not None

    def get_mandate_id(self, agent_id: AgentId | None = None) -> str | None:
        """Get the mandate ID for an agent.

        Args:
            agent_id: Agent to look up. Defaults to self._agent_id.

        Returns:
            Mandate ID or None if not configured.
        """
        aid = agent_id or self._agent_id
        return self._mandate_map.get(aid)

    def mandate_spent(self, agent_id: AgentId | None = None) -> int:
        """Get total amount spent against an agent's mandate.

        Args:
            agent_id: Agent to look up. Defaults to self._agent_id.

        Returns:
            Amount spent in cents.
        """
        mandate_id = self.get_mandate_id(agent_id)
        if not mandate_id:
            return 0

        mandate = self._mandates.get(mandate_id)
        if mandate:
            return mandate.spent
        return 0

    def mandate_remaining(self, agent_id: AgentId | None = None) -> int:
        """Get remaining balance on an agent's mandate.

        Args:
            agent_id: Agent to look up. Defaults to self._agent_id.

        Returns:
            Remaining amount in cents.
        """
        mandate_id = self.get_mandate_id(agent_id)
        if not mandate_id:
            return 0

        mandate = self._mandates.get(mandate_id)
        if mandate:
            return mandate.approved_amount - mandate.spent
        return self._approved_amount

    def balance(self, agent: AgentId) -> int:
        """Get an agent's balance.

        This method provides compatibility with marketplace scenarios which
        track per-agent balances. For Prava, this returns the balance from the
        shared balances dict if available.

        Args:
            agent: Agent to look up balance for.

        Returns:
            Balance in cents.

        Example::

            bal = payments.balance(AgentId("buyer-01"))
        """
        return self._balances.get(agent, 0)

    # -------------------------------------------------------------------------
    # Payments Protocol Implementation
    # -------------------------------------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Get a price quote for a service.

        This is a simplified implementation that returns a fixed quote.
        Real implementations would query service pricing catalogs.

        Args:
            service: Reference to the service being quoted.

        Returns:
            Quote with price information.

        Example::

            quote = await payments.quote(ServiceRef("data-cleaning"))
            print(f"Price: {quote.price.amount} {quote.price.currency}")
        """
        return Quote(
            service=service,
            price=Money(amount=10, currency="USD"),  # $0.10 fixed quote
            ttl_seconds=300,
            metadata={"source": "prava_payments", "live_mode": self.is_live_mode},
        )

    async def pay(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
    ) -> Receipt:
        """Execute a payment to another agent.

        Charges the sender's mandate and records a receipt. The reference
        parameter provides idempotency - duplicate references return the
        original receipt without double-charging.

        Args:
            to: Agent receiving the payment.
            amount: Payment amount.
            ref: Unique payment reference for idempotency.

        Returns:
            Receipt proving the payment was made.

        Raises:
            ThresholdExceededError: If amount exceeds mandate cap.
            MandateNotFoundError: If payer has no mandate configured.
            MandateNotActiveError: If mandate is cancelled/paused.
            InvalidAmountError: If amount is zero or negative.

        Example::

            receipt = await payments.pay(
                to=AgentId("seller-01"),
                amount=Money(amount=1250, currency="USD"),
                ref=PaymentRef("order-123"),
            )
        """
        # Validate amount
        if amount.amount <= 0:
            raise InvalidAmountError(amount.amount)

        # Get mandate for the paying agent
        mandate_id = self.get_mandate_id(self._agent_id)
        if not mandate_id:
            raise MandateNotFoundError(f"agent:{self._agent_id}")

        # Check for duplicate (idempotent return)
        if ref in self._receipts:
            logger.debug(f"Returning cached receipt for duplicate ref: {ref}")
            return self._receipts[ref]

        if self._client:
            # Live mode: make real API call
            return await self._pay_live(to, amount, ref, mandate_id)
        else:
            # Mock mode: simulate payment
            return await self._pay_mock(to, amount, ref, mandate_id)

    async def _pay_live(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
        mandate_id: str,
    ) -> Receipt:
        """Execute payment via live Prava API."""
        assert self._client is not None

        try:
            # Charge the mandate
            charge_result = await self._client.charge(
                mandate_id=mandate_id,
                amount=amount.amount,
                reference=str(ref),
            )

            # Report the charge outcome immediately
            if charge_result.status != "failed":
                try:
                    await self._client.report_charge(
                        mandate_id=mandate_id,
                        transaction_id=charge_result.transaction_id,
                        outcome="APPROVED",
                    )
                except PravaError as e:
                    # Log but don't fail - charge was successful
                    logger.warning(f"Failed to report charge: {e}")

            # Update marketplace balances
            if self._balances:
                self._balances[self._agent_id] = (
                    self._balances.get(self._agent_id, 0) - amount.amount
                )
                self._balances[to] = self._balances.get(to, 0) + amount.amount

            # Create and store receipt
            receipt = Receipt(
                ref=ref,
                payer=self._agent_id,
                payee=to,
                amount=amount,
                timestamp=time.time(),
            )
            self._receipts[ref] = receipt

            return receipt

        except DuplicateReferenceError:
            # Idempotent: check if we have the receipt cached
            if ref in self._receipts:
                return self._receipts[ref]
            # Otherwise re-raise (shouldn't happen)
            raise

    async def _pay_mock(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
        mandate_id: str,
    ) -> Receipt:
        """Execute payment in mock mode."""
        mandate = self._mandates.get(mandate_id)
        if not mandate:
            raise MandateNotFoundError(mandate_id)

        # Check mandate status
        if mandate.status != "active":
            raise MandateNotActiveError(mandate_id, status=mandate.status)

        # Check idempotency
        if str(ref) in mandate.references:
            existing_txn_id = mandate.references[str(ref)]
            if ref in self._receipts:
                return self._receipts[ref]
            # Reference used but no receipt - shouldn't happen
            raise DuplicateReferenceError(str(ref), existing_txn_id)

        # Check threshold
        remaining = mandate.approved_amount - mandate.spent
        if amount.amount > remaining:
            raise ThresholdExceededError(
                approved_amount=mandate.approved_amount,
                requested_amount=amount.amount,
                spent_amount=mandate.spent,
            )

        # Create charge record
        txn_id = f"txn_mock_{uuid.uuid4().hex[:12]}"
        charge = MockCharge(
            transaction_id=txn_id,
            reference=str(ref),
            amount=amount.amount,
            status="completed",
            payee=to,
            reported=True,
        )

        # Update mandate state
        mandate.charges[txn_id] = charge
        mandate.references[str(ref)] = txn_id
        mandate.spent += amount.amount

        # Update marketplace balances
        if self._balances:
            self._balances[self._agent_id] = (
                self._balances.get(self._agent_id, 0) - amount.amount
            )
            self._balances[to] = self._balances.get(to, 0) + amount.amount

        # Create and store receipt
        receipt = Receipt(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=amount,
            timestamp=time.time(),
        )
        self._receipts[ref] = receipt

        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify the status of a payment.

        Args:
            ref: Payment reference to verify.

        Returns:
            PaymentStatus indicating current state.

        Example::

            status = await payments.verify_payment(PaymentRef("order-123"))
            if status == PaymentStatus.CONFIRMED:
                print("Payment confirmed!")
        """
        # Check local cache first
        if ref in self._receipts:
            return PaymentStatus.CONFIRMED

        if self._client:
            # Live mode: search mandate for the charge
            return await self._verify_live(ref)
        else:
            # Mock mode: search mock mandates
            return await self._verify_mock(ref)

    async def _verify_live(self, ref: PaymentRef) -> PaymentStatus:
        """Verify payment via live API."""
        assert self._client is not None

        mandate_id = self.get_mandate_id(self._agent_id)
        if not mandate_id:
            return PaymentStatus.FAILED

        try:
            charge = await self._client.find_charge_by_reference(mandate_id, str(ref))
            if not charge:
                return PaymentStatus.FAILED

            status = charge.get("status", "unknown")
            if status in ("completed", "approved", "settled"):
                return PaymentStatus.CONFIRMED
            elif status == "awaiting_result":
                return PaymentStatus.PENDING
            elif status == "refunded":
                return PaymentStatus.REFUNDED
            else:
                return PaymentStatus.FAILED

        except PravaError:
            return PaymentStatus.FAILED

    async def _verify_mock(self, ref: PaymentRef) -> PaymentStatus:
        """Verify payment in mock mode."""
        # Search all mandates for the charge
        for mandate in self._mandates.values():
            if str(ref) in mandate.references:
                txn_id = mandate.references[str(ref)]
                charge = mandate.charges.get(txn_id)
                if charge:
                    if charge.status == "completed":
                        return PaymentStatus.CONFIRMED
                    elif charge.status == "refunded":
                        return PaymentStatus.REFUNDED
                    elif charge.status == "failed":
                        return PaymentStatus.FAILED
                    else:
                        return PaymentStatus.PENDING

        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a payment.

        **IMPORTANT**: Prava does not provide a direct refund API endpoint.
        This method implements a ledger-based reversal for game purposes.

        In mock mode, it reverses the charge in the local ledger.
        In live mode, it reports the charge as DECLINED (best-effort network
        reversal) and updates local state.

        This is documented as **game-only behavior** - real refunds would
        require merchant-side processing.

        Args:
            ref: Payment reference to refund.

        Raises:
            PaymentNotFoundError: If payment doesn't exist.

        Example::

            await payments.refund(PaymentRef("order-123"))
        """
        # Find the receipt
        if ref not in self._receipts:
            raise PaymentNotFoundError(str(ref))

        if self._client:
            await self._refund_live(ref)
        else:
            await self._refund_mock(ref)

    async def _refund_live(self, ref: PaymentRef) -> None:
        """Refund via live API (best-effort network reversal)."""
        assert self._client is not None

        mandate_id = self.get_mandate_id(self._agent_id)
        if not mandate_id:
            raise PaymentNotFoundError(str(ref))

        try:
            charge = await self._client.find_charge_by_reference(mandate_id, str(ref))
            if charge:
                txn_id = charge.get("transactionId") or charge.get("transaction_id")
                if txn_id:
                    # Report as DECLINED to attempt network reversal
                    try:
                        await self._client.report_charge(
                            mandate_id=mandate_id,
                            transaction_id=txn_id,
                            outcome="DECLINED",
                        )
                    except PravaError as e:
                        logger.warning(f"Failed to report DECLINED for refund: {e}")

        except PravaError as e:
            logger.warning(f"Error during refund: {e}")

        # Remove from local receipts regardless
        if ref in self._receipts:
            del self._receipts[ref]

    async def _refund_mock(self, ref: PaymentRef) -> None:
        """Refund in mock mode (ledger reversal)."""
        # Find the charge in mandates
        for mandate in self._mandates.values():
            if str(ref) in mandate.references:
                txn_id = mandate.references[str(ref)]
                charge = mandate.charges.get(txn_id)
                if charge and charge.status != "refunded":
                    # Reverse the charge
                    mandate.spent -= charge.amount
                    charge.status = "refunded"
                    break

        # Remove from receipts
        if ref in self._receipts:
            del self._receipts[ref]

    # -------------------------------------------------------------------------
    # Mock Mode Utilities (for testing)
    # -------------------------------------------------------------------------

    def cancel_mandate(self, agent_id: AgentId | None = None) -> None:
        """Cancel a mandate (mock mode only).

        Args:
            agent_id: Agent whose mandate to cancel. Defaults to self.
        """
        mandate_id = self.get_mandate_id(agent_id)
        if mandate_id and mandate_id in self._mandates:
            self._mandates[mandate_id].status = "cancelled"

    def pause_mandate(self, agent_id: AgentId | None = None) -> None:
        """Pause a mandate (mock mode only).

        Args:
            agent_id: Agent whose mandate to pause. Defaults to self.
        """
        mandate_id = self.get_mandate_id(agent_id)
        if mandate_id and mandate_id in self._mandates:
            self._mandates[mandate_id].status = "paused"

    def resume_mandate(self, agent_id: AgentId | None = None) -> None:
        """Resume a paused mandate (mock mode only).

        Args:
            agent_id: Agent whose mandate to resume. Defaults to self.
        """
        mandate_id = self.get_mandate_id(agent_id)
        if (
            mandate_id
            and mandate_id in self._mandates
            and self._mandates[mandate_id].status == "paused"
        ):
            self._mandates[mandate_id].status = "active"

    async def close(self) -> None:
        """Close the HTTP client (live mode only)."""
        if self._client:
            await self._client.close()

    async def __aenter__(self) -> PravaPayments:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
