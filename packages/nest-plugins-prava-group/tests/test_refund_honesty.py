# SPDX-License-Identifier: Apache-2.0
"""Refunds: a void before capture, and an honest refusal after it.

The dishonest implementation of `refund()` is four lines shorter than ours
and would pass a naive test suite, because deleting a dict entry always
succeeds. What it would be advertising is a settlement guarantee the card
rail does not offer.
"""

from __future__ import annotations

import pytest
from nanda_town_prava import PravaMandates, Principal, RefundNotSupportedError
from nanda_town_prava._simulator import SimulatedEngine
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


async def test_pre_capture_refund_is_a_void_and_charges_nobody() -> None:
    engine = SimulatedEngine()
    payments = PravaMandates(
        AgentId("Soham"),
        initial_balance=1000,
        engine=engine,
        auto_approve=False,  # nobody has tapped a passkey yet
        await_seconds=0.0,
    )
    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=400),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh")],
    )

    possible, reason = payments.can_refund(PaymentRef("g1"))
    assert possible
    assert "charges nobody" in reason

    await payments.refund(PaymentRef("g1"))

    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None
    assert auth.voided
    assert auth.captured == 0, "nothing was ever captured, so nothing came back"
    assert auth.mandate_ids == {}, "every mandate was cancelled"
    assert payments.balance(AgentId("Soham")) == 1000, "the hold was released"
    assert await payments.verify_payment(PaymentRef("g1")) is PaymentStatus.REFUNDED
    assert payments.conservation_report()["merchant_credited"] == 0


async def test_post_capture_refund_refuses_instead_of_pretending() -> None:
    payments = PravaMandates(AgentId("buyer-0"), initial_balance=1000)
    await payments.pay(AgentId("seller-0"), Money(amount=450), PaymentRef("p1"))

    possible, reason = payments.can_refund(PaymentRef("p1"))
    assert not possible
    assert "does not roll back" in reason

    with pytest.raises(RefundNotSupportedError) as excinfo:
        await payments.refund(PaymentRef("p1"))

    error = excinfo.value
    assert error.captured == 450
    assert error.ref == "p1"
    assert "merchant-initiated refund" in error.remedy
    # NotImplementedError, so `except ValueError` around a naive refund does
    # not silently swallow it.
    assert isinstance(error, NotImplementedError)

    # And the refusal changed nothing: the money is still at the merchant.
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
    assert payments.conservation_report()["merchant_credited"] == 450


async def test_refunding_an_unknown_reference_raises() -> None:
    payments = PravaMandates(AgentId("buyer-0"), initial_balance=1000)
    with pytest.raises(ValueError, match="Payment not found"):
        await payments.refund(PaymentRef("never-seen"))


async def test_voiding_twice_is_idempotent() -> None:
    engine = SimulatedEngine()
    payments = PravaMandates(
        AgentId("Soham"),
        initial_balance=1000,
        engine=engine,
        auto_approve=False,
        await_seconds=0.0,
    )
    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=400),
        PaymentRef("g1"),
        principals=[Principal(name="Soham")],
    )

    await payments.refund(PaymentRef("g1"))
    await payments.refund(PaymentRef("g1"))  # must not double-release

    assert payments.balance(AgentId("Soham")) == 1000
    assert payments.conservation_report()["headroom_consistent"]


async def test_refund_of_a_settled_group_names_the_transaction_to_reverse() -> None:
    """The refusal is actionable: it carries the id a human needs."""
    payments = PravaMandates(AgentId("organizer"), initial_balance=1000)
    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=18600),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh")],
    )

    with pytest.raises(RefundNotSupportedError):
        await payments.refund(PaymentRef("g1"))

    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None
    assert set(auth.transaction_ids) == {"Soham", "Arsh"}
    assert set(auth.mandate_ids) == {"Soham", "Arsh"}
