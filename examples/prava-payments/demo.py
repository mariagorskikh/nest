# SPDX-License-Identifier: Apache-2.0
"""Demo: drive a real Prava settlement through the Nanda Town plugin registry.

Resolves the ``prava`` payments plugin exactly as the simulator does
(``PluginRegistry.resolve("payments", "prava")``), then runs:

  1. a successful buyer -> PrintSmith payment (the Dark Knight A3 print),
  2. a refused payment to an unverified seller (Senso trust gate),
  3. a refund of the successful order.

Run:  python demo.py
"""

from __future__ import annotations

import asyncio

from nest_core.plugins import PluginRegistry
from nest_sdk import AgentId, Money, PaymentRef
from prava_payments.trust import TrustGate, TrustRefusedError

BUYER = AgentId("did:buyer:alice")
MERCHANT = AgentId("did:printsmith:store")
SCAMMER = AgentId("did:unknown:scammer")


async def main() -> None:
    """Run the settle / refuse / refund flow and print the outcomes."""
    reg = PluginRegistry()
    prava_cls = reg.resolve("payments", "prava")  # discovered via entry point
    print(f"resolved payments plugin -> {prava_cls.__module__}.{prava_cls.__name__}\n")

    # Senso allowlists the verified store only; shared ledger so both agents settle.
    gate = TrustGate(verified={str(MERCHANT)})
    pay = prava_cls(BUYER, initial_balance=1000, trust=gate, balances={})

    # 1) SUCCESS -- buyer pays PrintSmith for the Dark Knight A3 print.
    ref = PaymentRef("order-dark-knight-a3")
    receipt = await pay.pay(MERCHANT, Money(amount=399, currency="INR"), ref)
    status = await pay.verify_payment(ref)
    print(f"[OK]      {receipt.payer} -> {receipt.payee}")
    print(f"          {receipt.amount.amount} {receipt.amount.currency}  status={status.name}")
    print(f"          balances: buyer={pay.balance(BUYER)}  merchant={pay.balance(MERCHANT)}\n")

    # 2) FAILURE -- buyer refuses to pay an unverified seller (Senso trust gate).
    try:
        await pay.pay(SCAMMER, Money(amount=250, currency="INR"), PaymentRef("order-scam"))
        print("[ERR]     scammer payment should have been refused")
    except TrustRefusedError as exc:
        print(f"[BLOCKED] {exc}\n")

    # 3) REFUND the successful order.
    await pay.refund(ref)
    refunded = await pay.verify_payment(ref)
    print(f"[REFUND]  status={refunded.name}")
    print(f"          balances: buyer={pay.balance(BUYER)}  merchant={pay.balance(MERCHANT)}")


if __name__ == "__main__":
    asyncio.run(main())
