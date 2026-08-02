# SPDX-License-Identifier: Apache-2.0
"""Prava Agentic Payments adapter — NANDA Town payments-layer plugin.

Implements the standard nest-core payments interface (quote, pay,
verify_payment, refund) backed by Prava's Agentic Payments Sandbox
(https://sandbox.api.prava.space).

Prava Visa Network Token details (PAN, CVV, expiry) are accepted by
``pay()`` and forwarded to the sandbox charge endpoint.  The plugin
enforces two client-side guard rules before ever hitting the network:

- **CVV 000 → decline**: Prava test harness treats 000 as a forced
  decline trigger.  We catch it early and raise :exc:`PaymentDeclined`
  with a descriptive reason.
- **amount > token.limit → decline**: The default sandbox token limit is
  $150.  Charges over that ceiling are declined; we raise
  :exc:`PaymentDeclined` rather than swallowing a 402 silently.

Both cases satisfy the NANDA Prava track's mandatory failure-handling
requirement.

Example::

    from nest_payments_prava import PravaPaymentLayer, PravaTokenDetails
    from nest_core.types import AgentId, Money, PaymentRef, ServiceRef

    token = PravaTokenDetails(pan="4111111111111111", cvv="123", expiry="12/27")
    plugin = PravaPaymentLayer(AgentId("buyer-01"), token=token, initial_balance=500)

    # Inside an async context:
    receipt = await plugin.pay(AgentId("seller-01"), Money(amount=99), PaymentRef("p1"))
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx
from pydantic import BaseModel

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prava sandbox constants
# ---------------------------------------------------------------------------

PRAVA_SANDBOX_CHARGE_URL = "https://sandbox.api.prava.space/v1/charge"

# Default per-token spend ceiling for the Prava sandbox.
PRAVA_DEFAULT_TOKEN_LIMIT: int = 150

# CVV value that Prava's test harness treats as a forced decline.
PRAVA_DECLINED_CVV: str = "000"

# Default quote price (USD cents) when no catalogue is configured.
DEFAULT_QUOTE_AMOUNT: int = 10


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class PravaTokenDetails(BaseModel):
    """Prava Visa Network Token details forwarded to the charge endpoint.

    Example::

        token = PravaTokenDetails(pan="4111111111111111", cvv="123", expiry="12/27")
    """

    pan: str
    """Primary Account Number (16-digit card number)."""

    cvv: str
    """Card Verification Value (3 or 4 digits)."""

    expiry: str
    """Expiry date in MM/YY format, e.g. ``"12/27"``."""

    limit: int = PRAVA_DEFAULT_TOKEN_LIMIT
    """Per-token spend ceiling enforced client-side (default $150)."""


class PaymentDeclined(Exception):
    """Raised when the Prava sandbox (or client-side guard) declines a charge.

    Attributes:
        reason: Human-readable decline reason.
        ref:    The :class:`~nest_core.types.PaymentRef` that was declined.

    Example::

        try:
            receipt = await plugin.pay(seller, Money(amount=200), ref)
        except PaymentDeclined as exc:
            print(f"Declined: {exc.reason}")
    """

    def __init__(self, reason: str, ref: PaymentRef) -> None:
        super().__init__(reason)
        self.reason = reason
        self.ref = ref

    def __repr__(self) -> str:
        return f"PaymentDeclined(reason={self.reason!r}, ref={self.ref!r})"


# ---------------------------------------------------------------------------
# Plugin implementation
# ---------------------------------------------------------------------------


class PravaPaymentLayer:
    """NANDA Town payments-layer plugin backed by Prava's Agentic Payments Sandbox.

    Implements the standard interface expected by nest-core:
    ``quote``, ``pay``, ``verify_payment``, and ``refund``.

    The ``pay`` method accepts Prava Visa Network Token details and POSTs to
    ``https://sandbox.api.prava.space/v1/charge``.

    **Mandatory failure handling**

    - If ``token.cvv == "000"`` → raises :exc:`PaymentDeclined` immediately
      (Prava test-harness forced-decline marker; no network call is made).
    - If ``amount.amount > token.limit`` (default 150) → raises
      :exc:`PaymentDeclined` (sandbox token spend ceiling exceeded; no
      network call is made).

    Args:
        agent_id:        The agent that owns this payment handle.
        token:           Prava Visa Network Token details.
        initial_balance: Soft credit balance for bookkeeping and ``quote``
                         guards.
        http_client:     Optional pre-configured :class:`httpx.AsyncClient`.
                         Inject a mock client in tests to avoid real HTTP.

    Example::

        token = PravaTokenDetails(pan="4111111111111111", cvv="123", expiry="12/27")
        plugin = PravaPaymentLayer(AgentId("buyer"), token=token)
        receipt = await plugin.pay(AgentId("seller"), Money(amount=50), PaymentRef("p1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        token: PravaTokenDetails | None = None,
        initial_balance: int = 1000,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._token = token or PravaTokenDetails(
            pan="4111111111111111",
            cvv="123",
            expiry="12/27",
        )
        self._balances: dict[AgentId, int] = {agent_id: initial_balance}
        self._payments: dict[PaymentRef, Receipt] = {}
        self._declined: set[PaymentRef] = set()
        self._http_client = http_client  # None → created lazily per request

    # ------------------------------------------------------------------
    # Balance helper (useful for tests and scenario introspection)
    # ------------------------------------------------------------------

    def balance(self, agent: AgentId) -> int:
        """Return the current soft balance for *agent*.

        Example::

            bal = plugin.balance(AgentId("buyer"))
        """
        return self._balances.get(agent, 0)

    # ------------------------------------------------------------------
    # Standard nest-core payments interface
    # ------------------------------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a price quote for *service*.

        Returns a fixed sandbox quote of :data:`DEFAULT_QUOTE_AMOUNT` USD for
        any service.  A production integration would call the Prava pricing API.

        Example::

            q = await plugin.quote(ServiceRef("software-license"))
            print(q.price.amount)   # 10
        """
        return Quote(
            service=service,
            price=Money(amount=DEFAULT_QUOTE_AMOUNT, currency="USD"),
            ttl_seconds=300,
            metadata={"adapter": "prava_adapter", "sandbox": True},
        )

    async def pay(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
        *,
        token: PravaTokenDetails | None = None,
    ) -> Receipt:
        """Charge the Prava Visa Network Token and record the receipt.

        Args:
            to:     Payee agent.
            amount: Charge amount; ``amount.amount`` is treated as USD cents
                    when forwarded to the sandbox.
            ref:    Unique payment reference — raises :exc:`ValueError` on
                    duplicate use.
            token:  Override the instance-level token for this single charge.

        Raises:
            ValueError:       On duplicate *ref* or non-positive *amount*.
            PaymentDeclined:  When CVV is ``"000"`` or amount exceeds the
                              token's spend limit, or the sandbox returns 4xx.
            httpx.HTTPError:  On unrecoverable network errors (5xx, timeout).

        Example::

            receipt = await plugin.pay(
                AgentId("seller"), Money(amount=50), PaymentRef("p1")
            )
        """
        effective_token = token or self._token

        # --- basic validation --------------------------------------------
        if amount.amount <= 0:
            msg = f"Payment amount must be positive, got {amount.amount}"
            raise ValueError(msg)

        if ref in self._payments:
            msg = f"Duplicate payment reference: {ref!r}"
            raise ValueError(msg)

        # --- Prava-specific client-side decline rules (mandatory) --------

        if effective_token.cvv == PRAVA_DECLINED_CVV:
            self._declined.add(ref)
            logger.warning(
                "PravaAdapter: charge declined — CVV 000 is a forced test decline "
                "(ref=%s, amount=%s)",
                ref,
                amount.amount,
            )
            raise PaymentDeclined(
                reason="Card declined: CVV '000' is a Prava test-harness forced decline.",
                ref=ref,
            )

        if amount.amount > effective_token.limit:
            self._declined.add(ref)
            logger.warning(
                "PravaAdapter: charge declined — amount %s exceeds token limit %s "
                "(ref=%s)",
                amount.amount,
                effective_token.limit,
                ref,
            )
            raise PaymentDeclined(
                reason=(
                    f"Card declined: charge amount {amount.amount} exceeds the "
                    f"Prava sandbox token limit of {effective_token.limit}."
                ),
                ref=ref,
            )

        # --- call Prava sandbox ------------------------------------------
        charge_payload: dict[str, Any] = {
            "reference_id": str(ref),
            "amount": amount.amount,
            "currency": amount.currency,
            "token": {
                "pan": effective_token.pan,
                "cvv": effective_token.cvv,
                "expiry": effective_token.expiry,
            },
            "payer_agent": str(self._agent_id),
            "payee_agent": str(to),
        }

        try:
            response_data = await self._post_charge(charge_payload)
        except httpx.HTTPStatusError as exc:
            # 4xx → declined; 5xx → re-raise for the caller to handle
            if exc.response.status_code < 500:
                self._declined.add(ref)
                detail = exc.response.text[:200]
                logger.error(
                    "PravaAdapter: sandbox declined charge (status=%s, ref=%s): %s",
                    exc.response.status_code,
                    ref,
                    detail,
                )
                raise PaymentDeclined(
                    reason=f"Prava sandbox declined: HTTP {exc.response.status_code} — {detail}",
                    ref=ref,
                ) from exc
            raise

        logger.info(
            "PravaAdapter: charge confirmed (ref=%s, amount=%s %s, sandbox_id=%s)",
            ref,
            amount.amount,
            amount.currency,
            response_data.get("charge_id", "unknown"),
        )

        # Update soft balances and store receipt
        self._balances[self._agent_id] = self._balances.get(self._agent_id, 0) - amount.amount
        self._balances[to] = self._balances.get(to, 0) + amount.amount

        receipt = Receipt(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=amount,
            timestamp=time.time(),
        )
        self._payments[ref] = receipt
        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Return the current status of a payment by reference.

        Returns:
            ``CONFIRMED`` if the charge succeeded and a receipt is recorded.
            ``FAILED``    if the charge was declined or never attempted.

        Example::

            status = await plugin.verify_payment(PaymentRef("p1"))
            assert status == PaymentStatus.CONFIRMED
        """
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Reverse a confirmed charge by restoring soft balances.

        The Prava sandbox does not yet expose a live refund endpoint; this
        method performs the bookkeeping reversal locally so the balance
        ledger stays consistent.

        Raises:
            ValueError: If *ref* was never confirmed (already declined or
                        unknown).

        Example::

            await plugin.refund(PaymentRef("p1"))
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            msg = f"Cannot refund: payment reference {ref!r} not found or already declined."
            raise ValueError(msg)

        self._balances[receipt.payee] = (
            self._balances.get(receipt.payee, 0) - receipt.amount.amount
        )
        self._balances[receipt.payer] = (
            self._balances.get(receipt.payer, 0) + receipt.amount.amount
        )
        del self._payments[ref]

        logger.info(
            "PravaAdapter: refund applied (ref=%s, amount=%s)",
            ref,
            receipt.amount.amount,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _post_charge(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST *payload* to the Prava sandbox charge endpoint.

        Uses the injected ``http_client`` if provided (test seam), otherwise
        opens a one-shot :class:`httpx.AsyncClient`.

        Returns the parsed JSON response body.
        """
        if self._http_client is not None:
            resp = await self._http_client.post(PRAVA_SANDBOX_CHARGE_URL, json=payload)
            resp.raise_for_status()
            return dict(resp.json())

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(PRAVA_SANDBOX_CHARGE_URL, json=payload)
            resp.raise_for_status()
            return dict(resp.json())

    def _make_ref(self) -> PaymentRef:
        """Generate a unique :class:`~nest_core.types.PaymentRef`."""
        return PaymentRef(str(uuid.uuid4()))
