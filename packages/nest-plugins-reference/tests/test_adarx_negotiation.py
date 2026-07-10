# SPDX-License-Identifier: Apache-2.0
"""Unit and property tests for the ADARXNegotiation plugin.

ADARXNegotiation ports real, independently-tested procurement logic (tiered
volume discounts, strategy-adjusted terms, a hard compliance gate) rather
than implementing a generic bargaining model from scratch. These tests
verify two things: that the ported business rules behave exactly as
specified, and that the plugin satisfies the same general properties the
other negotiation plugins in this repo are held to.

Two property families (Hypothesis):

* **Determinism**, identical construction + identical offer sequence yields
  an identical run (no wall-clock, no RNG -- the plugin has none).
* **Monotonic discount in quantity**, the volume discount never decreases
  as requested quantity increases, for any quantity.
* **Bounded price**, the negotiated price is never negative and never
  exceeds the base price, for any quantity/strategy combination.
* **Compliance gate is absolute**, for any non-"APPROVED" compliance
  status, the session is rejected at open() and stays rejected through
  respond() and close(), regardless of any offers made afterward.
"""

from __future__ import annotations

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Money, NegotiationStatus, Terms
from nest_plugins_reference.negotiation.adarx import (
    ADARXNegotiation,
    apply_strategy,
    volume_discount_percent,
)

_EPS = 1e-9


def _terms(
    price: int,
    quantity: int = 100,
    strategy: str = "balanced",
    compliance_status: str = "APPROVED",
    lead_time_days: int = 10,
) -> Terms:
    return Terms(
        price=Money(amount=price),
        metadata={
            "quantity": quantity,
            "strategy": strategy,
            "compliance_status": compliance_status,
            "lead_time_days": lead_time_days,
        },
    )


# Unit tests


def test_volume_discount_tiers() -> None:
    """Discount tiers match ADAR-X production thresholds exactly."""
    assert volume_discount_percent(0) == 0
    assert volume_discount_percent(499) == 0
    assert volume_discount_percent(500) == 5
    assert volume_discount_percent(999) == 5
    assert volume_discount_percent(1000) == 8
    assert volume_discount_percent(4999) == 8
    assert volume_discount_percent(5000) == 12
    assert volume_discount_percent(50000) == 12


def test_strategy_aggressive_widens_discount_and_terms() -> None:
    """Aggressive: bigger discount, slower delivery, slower payment to supplier."""
    adjusted = apply_strategy(discount=8, lead_time_days=10, strategy="aggressive")
    assert adjusted["discount"] == 11
    assert adjusted["lead_time_days"] == 12
    assert adjusted["payment_terms"] == "Net 60"
    assert adjusted["sla_tier"] == "COST_OPTIMIZED"


def test_strategy_defensive_trades_discount_for_speed() -> None:
    """Defensive: gives up some discount for faster delivery and longer warranty."""
    adjusted = apply_strategy(discount=8, lead_time_days=10, strategy="defensive")
    assert adjusted["discount"] == 6
    assert adjusted["lead_time_days"] == 7
    assert adjusted["payment_terms"] == "Net 15"
    assert adjusted["warranty_months"] == 24
    assert adjusted["sla_tier"] == "EXPEDITED"


def test_strategy_defensive_lead_time_floor() -> None:
    """Defensive lead-time reduction never goes below the 2-day floor."""
    adjusted = apply_strategy(discount=0, lead_time_days=3, strategy="defensive")
    assert adjusted["lead_time_days"] == 2


def test_strategy_defensive_discount_floor() -> None:
    """Defensive discount reduction never goes negative."""
    adjusted = apply_strategy(discount=1, lead_time_days=10, strategy="defensive")
    assert adjusted["discount"] == 0


def test_strategy_balanced_is_default_terms() -> None:
    """Balanced: no discount adjustment, standard commercial terms."""
    adjusted = apply_strategy(discount=8, lead_time_days=10, strategy="balanced")
    assert adjusted["discount"] == 8
    assert adjusted["lead_time_days"] == 10
    assert adjusted["payment_terms"] == "Net 30"
    assert adjusted["warranty_months"] == 18
    assert adjusted["sla_tier"] == "BALANCED"


def test_compliance_gate_rejects_at_open() -> None:
    """A non-APPROVED counterparty is rejected immediately, no bargaining round spent."""
    neg = ADARXNegotiation(AgentId("buyer"))

    async def go() -> NegotiationStatus:
        session = await neg.open(
            AgentId("seller"), _terms(1000, compliance_status="PENDING_REVIEW")
        )
        return session.status

    assert asyncio.run(go()) == NegotiationStatus.REJECTED


def test_compliance_gate_stays_rejected_through_respond_and_close() -> None:
    """Once rejected at open(), respond() and close() both honor the rejection."""
    neg = ADARXNegotiation(AgentId("buyer"))

    async def go() -> tuple[bool, object]:
        session = await neg.open(
            AgentId("seller"), _terms(1000, compliance_status="PENDING_REVIEW")
        )
        resp = await neg.respond(session)
        agreement = await neg.close(session)
        return resp.accepted, agreement

    accepted, agreement = asyncio.run(go())
    assert accepted is False
    assert agreement is None


def test_respond_accepts_when_offer_already_at_or_below_negotiated_price() -> None:
    """If the offer on the table reaches our fixed negotiated target, accept."""
    neg = ADARXNegotiation(AgentId("buyer"))

    async def go() -> bool:
        # quantity=1500 -> 8% discount, balanced -> no further adjustment.
        # base_price=1250 -> negotiated target = round(1250 * 0.92) = 1150.
        session = await neg.open(AgentId("seller"), _terms(1250, quantity=1500))
        # Counterparty offers down to exactly our target.
        await neg.offer(session, _terms(1150, quantity=1500))
        return (await neg.respond(session)).accepted

    assert asyncio.run(go()) is True


def test_respond_counters_with_correctly_computed_negotiated_price() -> None:
    """A high initial offer is countered with the real negotiated price, not accepted."""
    neg = ADARXNegotiation(AgentId("buyer"))

    async def go() -> int | None:
        session = await neg.open(AgentId("seller"), _terms(1250, quantity=1500))
        resp = await neg.respond(session)
        if resp.counter_terms is None or resp.counter_terms.price is None:
            return None
        return resp.counter_terms.price.amount

    # 1250 * (1 - 8/100) = 1150
    assert asyncio.run(go()) == 1150


def test_round_cap_forces_acceptance() -> None:
    """After 10 rounds of history, respond() accepts regardless of price gap."""
    neg = ADARXNegotiation(AgentId("buyer"))

    async def go() -> bool:
        session = await neg.open(AgentId("seller"), _terms(9999, quantity=100))
        # Pad history to >=10 rounds using fresh Terms objects (not
        # session.current_terms, which is typed Terms | None).
        padding_terms = _terms(9999, quantity=100)
        session.history.extend([padding_terms for _ in range(10)])
        return (await neg.respond(session)).accepted

    assert asyncio.run(go()) is True


def test_close_returns_agreement_with_negotiated_terms() -> None:
    """close() on an approved, settled session returns an Agreement carrying the terms."""
    neg = ADARXNegotiation(AgentId("buyer"))

    async def go() -> bool:
        session = await neg.open(AgentId("seller"), _terms(1250, quantity=1500))
        await neg.offer(session, _terms(1150, quantity=1500))
        await neg.respond(session)
        agreement = await neg.close(session)
        return agreement is not None and agreement.terms.price is not None

    assert asyncio.run(go()) is True


# Property tests (Hypothesis)


@given(
    q1=st.integers(min_value=0, max_value=20000),
    q2=st.integers(min_value=0, max_value=20000),
)
@settings(max_examples=200)
def test_discount_monotonic_in_quantity(q1: int, q2: int) -> None:
    """The volume discount never decreases as requested quantity increases."""
    lo, hi = (q1, q2) if q1 <= q2 else (q2, q1)
    assert volume_discount_percent(lo) <= volume_discount_percent(hi)


@given(
    base_price=st.integers(min_value=1, max_value=100_000),
    quantity=st.integers(min_value=0, max_value=20_000),
    strategy=st.sampled_from(["aggressive", "balanced", "defensive"]),
)
@settings(max_examples=200)
def test_negotiated_price_never_negative_or_above_base(
    base_price: int, quantity: int, strategy: str
) -> None:
    """For any quantity/strategy combination, the negotiated price stays in [0, base_price]."""
    discount = volume_discount_percent(quantity)
    adjusted = apply_strategy(discount, lead_time_days=10, strategy=strategy)
    discount_value = adjusted["discount"]
    assert isinstance(discount_value, int)
    negotiated_price = round(base_price * (1 - discount_value / 100))
    assert 0 <= negotiated_price <= base_price


@given(
    base_price=st.integers(min_value=100, max_value=50_000),
    quantity=st.integers(min_value=1, max_value=10_000),
    strategy=st.sampled_from(["aggressive", "balanced", "defensive"]),
)
@settings(max_examples=100, deadline=None)
def test_determinism(base_price: int, quantity: int, strategy: str) -> None:
    """Two identically-built plugin instances, fed the same offer, respond identically."""

    async def drive() -> tuple[bool, int | None]:
        neg = ADARXNegotiation(AgentId("buyer"))
        session = await neg.open(
            AgentId("seller"), _terms(base_price, quantity=quantity, strategy=strategy)
        )
        resp = await neg.respond(session)
        price = (
            resp.counter_terms.price.amount
            if resp.counter_terms is not None and resp.counter_terms.price is not None
            else None
        )
        return resp.accepted, price

    assert asyncio.run(drive()) == asyncio.run(drive())


@given(compliance_status=st.sampled_from(["PENDING_REVIEW", "REJECTED", "SUSPENDED", "UNKNOWN"]))
@settings(max_examples=50)
def test_compliance_gate_absolute_for_any_non_approved_status(compliance_status: str) -> None:
    """For any non-'APPROVED' status, the session is rejected and stays rejected."""
    neg = ADARXNegotiation(AgentId("buyer"))

    async def go() -> tuple[NegotiationStatus, bool, object]:
        session = await neg.open(
            AgentId("seller"), _terms(1000, compliance_status=compliance_status)
        )
        resp = await neg.respond(session)
        agreement = await neg.close(session)
        return session.status, resp.accepted, agreement

    status, accepted, agreement = asyncio.run(go())
    assert status == NegotiationStatus.REJECTED
    assert accepted is False
    assert agreement is None
