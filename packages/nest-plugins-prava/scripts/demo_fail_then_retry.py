#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Visual demo: insufficient funds → clean error → top-up → successful Prava pay."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow running without install: repo root / package on path.
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "nest-plugins-prava"))
sys.path.insert(0, str(ROOT / "packages" / "nest-sdk"))
sys.path.insert(0, str(ROOT / "packages" / "nest-core"))

from nest_plugins_prava import InsufficientFundsError, PravaPayments  # noqa: E402
from nest_plugins_prava.client import MockPravaClient  # noqa: E402
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef  # noqa: E402


async def main() -> None:
    alice = AgentId("alice")
    bob = AgentId("bob")
    client = MockPravaClient()
    pay = PravaPayments(alice, initial_balance=5, client=client, default_fee=50)

    print("=== Prava adapter demo: fail → retry ===\n")
    quote = await pay.quote(ServiceRef("compute-slot"))
    print(
        f"[1/4] quote(compute-slot) → {quote.price.amount} credits "
        f"(${quote.metadata.get('prava_amount')})"
    )

    try:
        await pay.pay(bob, Money(amount=50), PaymentRef("buy-1"))
        print("[2/4] unexpected success")
        sys.exit(1)
    except InsufficientFundsError as exc:
        print(f"[2/4] pay ref=buy-1 → FAIL {type(exc).__name__}: {exc}")
        print(f"       prava_calls={client.call_count} (must be 0)")

    new_bal = pay.top_up(alice, 100)
    print(f"[3/4] top_up(alice, +100) → balance={new_bal}")

    receipt = await pay.pay(bob, Money(amount=50), PaymentRef("buy-2"))
    status = await pay.verify_payment(PaymentRef("buy-2"))
    record = pay.payment_record(PaymentRef("buy-2"))
    print(f"[4/4] pay ref=buy-2 → OK Receipt payer={receipt.payer} payee={receipt.payee}")
    print(f"       verify={status.value} session={record.session_id if record else None}")
    print(
        f"       alice={pay.balance(alice)} bob={pay.balance(bob)} prava_calls={client.call_count}"
    )

    assert status is PaymentStatus.CONFIRMED
    assert client.call_count > 0
    print("\nDemo passed.")


if __name__ == "__main__":
    asyncio.run(main())
