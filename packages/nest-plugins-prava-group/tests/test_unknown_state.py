# SPDX-License-Identifier: Apache-2.0
"""`CONFIRMED` is a claim about money. It is never made on a guess.

Every path here ends somewhere other than `CONFIRMED`, and unknown ends at
`PENDING` rather than `FAILED` — GMP/1 §4.2: an unresolved charge may well
have landed, and calling it failed is how a retry becomes a double charge.
"""

from __future__ import annotations

from nanda_town_prava import PravaMandates
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus

from .conftest import (
    HostileEngine,
    NoReceiptEngine,
    RailOverrideEngine,
    StatusOverrideEngine,
    UnreachableEngine,
)


async def _pay(engine: object, **kwargs: object) -> PravaMandates:
    payments = PravaMandates(
        AgentId("buyer-0"),
        initial_balance=1000,
        engine=engine,  # type: ignore[arg-type]
        await_seconds=0.0,
        **kwargs,  # type: ignore[arg-type]
    )
    await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    return payments


async def test_unrecognised_group_status_is_pending_and_recorded() -> None:
    payments = await _pay(StatusOverrideEngine(status="quantum_superposition"))

    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING
    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert "quantum_superposition" in auth.unknown_states


async def test_unrecognised_member_status_is_recorded() -> None:
    payments = await _pay(StatusOverrideEngine(status="collecting", member_status="levitating"))

    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING
    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert "member:levitating" in auth.unknown_states


async def test_terminal_without_a_signed_receipt_is_not_confirmed() -> None:
    """Terminal but unprovable. Trust the artifact, not the UI."""
    payments = await _pay(NoReceiptEngine())

    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert auth.group_status == "committed", "the group really did commit"
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING
    assert auth.rail is None, "no receipt means no provable rail"


async def test_an_at_venue_receipt_is_never_reported_as_a_charge() -> None:
    """That receipt describes an agreement. No card was charged through the engine."""
    payments = await _pay(RailOverrideEngine(rail="at_venue"))

    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING
    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert auth.rail == "at_venue"
    assert auth.captured == 0
    assert payments.conservation_report()["merchant_credited"] == 0


async def test_unreachable_engine_is_pending_never_failed() -> None:
    engine = UnreachableEngine()
    payments = await _pay(engine)
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED

    engine.go_dark()
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING


async def test_a_reference_never_authorized_here_is_failed() -> None:
    payments = PravaMandates(AgentId("buyer-0"), initial_balance=1000)
    assert await payments.verify_payment(PaymentRef("never-seen")) is PaymentStatus.FAILED


async def test_confirmed_requires_the_receipt_to_back_it() -> None:
    payments = await _pay(HostileEngine())

    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert auth.rail == "prava_mandates"
    assert auth.transaction_ids, "a confirmed charge has a real transaction id"


async def test_verify_is_idempotent_under_repeated_polling() -> None:
    payments = await _pay(NoReceiptEngine())
    for _ in range(5):
        await payments.verify_payment(PaymentRef("p1"))

    report = payments.conservation_report()
    assert report["authorization_conserved"]
    assert report["headroom_consistent"]
    assert report["captured"] == 50, "polling must not re-capture"
