# SPDX-License-Identifier: Apache-2.0
"""Explicitly requested interactive Prava sandbox proof."""

from __future__ import annotations

import os

import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus

from nanda_prava_adapter import MerchantOutcome, PayeeProfile, PravaPayments


class SandboxOutcomeExecutor:
    """Report a disclosed sandbox merchant outcome after real Prava approval.

    Example::

        executor = SandboxOutcomeExecutor()
    """

    async def execute(
        self,
        credentials: dict[str, str],
        amount: Money,
        payment_ref: PaymentRef,
    ) -> MerchantOutcome:
        """Validate ephemeral credentials and return a sandbox approval.

        Example::

            outcome = await executor.execute(credentials, amount, ref)
        """
        del amount, payment_ref
        assert all(credentials.get(field) for field in ("token", "dynamic_cvv"))
        return MerchantOutcome(True, "NANDA-SANDBOX", "00")


@pytest.mark.live
@pytest.mark.asyncio
async def test_real_prava_sandbox_transaction() -> None:
    """Complete one real Prava sandbox session and disclosed merchant outcome.

    Example::

        NANDA_PRAVA_INTERACTIVE=1 uv run pytest -m live -s
    """
    if os.environ.get("NANDA_PRAVA_INTERACTIVE") != "1":
        pytest.skip("set NANDA_PRAVA_INTERACTIVE=1 for the card and passkey handoff")
    if not os.environ.get("PRAVA_API_KEY", "").startswith("sk_test_"):
        pytest.skip("the live proof requires a Prava sandbox key")

    seller = AgentId("nanda-seller")
    payments = PravaPayments(
        AgentId("nanda-buyer"),
        executor=SandboxOutcomeExecutor(),
        payees={
            seller: PayeeProfile(
                "NANDA Town Sandbox Seller",
                "https://nandatown.projectnanda.org",
                "US",
                "nanda-buyer",
                os.environ.get("NANDA_PRAVA_USER_EMAIL", "buyer@example.com"),
                "Restock trigger evaluation",
            )
        },
        approval_notifier=lambda session_id, url: print(
            f"PRAVA_SESSION={session_id}\nPRAVA_APPROVAL_URL={url}", flush=True
        ),
    )
    ref = PaymentRef("restock-nanda-live-sandbox")
    receipt = await payments.pay(seller, Money(amount=100, currency="USD"), ref)

    assert receipt.ref == ref
    assert await payments.verify_payment(ref) == PaymentStatus.CONFIRMED
