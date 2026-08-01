# SPDX-License-Identifier: Apache-2.0
"""Run one interactive NANDA-to-Prava sandbox payment.

Example::

    uv run python examples/one_payment.py
"""

from __future__ import annotations

import asyncio
import os

from nest_core.types import AgentId, Money, PaymentRef, ServiceRef

from nanda_prava_adapter import MerchantOutcome, PayeeProfile, PravaPayments


class DisclosedSandboxExecutor:
    """Confirm a sandbox outcome without claiming a real merchant charge.

    Example::

        executor = DisclosedSandboxExecutor()
    """

    async def execute(
        self,
        credentials: dict[str, str],
        amount: Money,
        payment_ref: PaymentRef,
    ) -> MerchantOutcome:
        """Return the disclosed sandbox processor outcome.

        Example::

            outcome = await executor.execute(credentials, amount, ref)
        """
        del amount, payment_ref
        if not all(credentials.values()):
            raise RuntimeError("Prava omitted required one-time credentials")
        if os.environ.get("PRAVA_ALLOW_DISCLOSED_SANDBOX_EXECUTION") != "1":
            raise RuntimeError(
                "set PRAVA_ALLOW_DISCLOSED_SANDBOX_EXECUTION=1 to explicitly acknowledge "
                "that this reports a sandbox merchant outcome, not a real merchant charge"
            )
        return MerchantOutcome(True, authorization_code="NANDA-SANDBOX", response_code="00")


def show_approval(session_id: str, approval_url: str) -> None:
    """Print the short-lived passkey URL for the human operator.

    Example::

        show_approval("ses_1", "https://pay.prava.space/s/ses_1")
    """
    print(f"Session: {session_id}")
    print(f"Open for card + passkey approval: {approval_url}")


async def main() -> None:
    """Run one quote, approved sandbox payment, and verification.

    Example::

        asyncio.run(main())
    """
    seller = AgentId("nanda-seller")
    service = ServiceRef("restock-trigger-evaluation")
    amount = Money(amount=100, currency="USD")
    payments = PravaPayments(
        AgentId("nanda-buyer"),
        executor=DisclosedSandboxExecutor(),
        payees={
            seller: PayeeProfile(
                merchant_name="NANDA Town Sandbox Seller",
                merchant_url="https://nandatown.projectnanda.org",
                merchant_country="US",
                user_id=os.environ.get("NANDA_PRAVA_USER_ID", "nanda-buyer"),
                user_email=os.environ.get("NANDA_PRAVA_USER_EMAIL", "buyer@example.com"),
                product_description="Restock trigger evaluation",
            )
        },
        services={service: amount},
        approval_notifier=show_approval,
    )
    quote = await payments.quote(service)
    print(f"Quote: {quote.price.amount} {quote.price.currency} minor units")
    ref = PaymentRef("restock-nanda-sandbox-001")
    receipt = await payments.pay(seller, quote.price, ref)
    status = await payments.verify_payment(ref)
    print(f"Receipt: {receipt.ref}; status={status.value}")


if __name__ == "__main__":
    asyncio.run(main())
