from __future__ import annotations

import pytest

from nest_core.types import AgentId, Money, Terms
from nest_plugins_reference.negotiation.directional_integer_raw_weights import (
    DirectionalIntegerRawWeightsNegotiation,
)


def terms(price: int, deadline: int) -> Terms:
    return Terms(
        price=Money(amount=price),
        conditions={"deadline_days": deadline},
    )


def test_preferences_are_preserved_not_normalized() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("seller"),
        a=2,
        b=6,
        side="seller",
    )

    assert neg.price_preference == pytest.approx(2.0)
    assert neg.deadline_preference == pytest.approx(6.0)
    assert neg.maximum_score == pytest.approx(8.0)


def test_seller_normalizes_attributes_but_not_weights() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("seller"),
        a=2,
        b=6,
        side="seller",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )

    # Minimum normalized price and delay are both zero.
    assert neg.weighted_sum((50, 1)) == pytest.approx(0.0)

    # Maximum normalized price and delay are both one:
    # 2*1 + 6*1 = 8.
    assert neg.weighted_sum((150, 30)) == pytest.approx(8.0)
    assert neg.utility((50, 1)) == pytest.approx(0.0)
    assert neg.utility((150, 30)) == pytest.approx(8.0)


def test_buyer_uses_same_score_with_reversed_utility_direction() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("buyer"),
        a=2,
        b=6,
        side="buyer",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )

    assert neg.weighted_sum((50, 1)) == pytest.approx(0.0)
    assert neg.weighted_sum((150, 30)) == pytest.approx(8.0)

    # Buyer prefers the low-score offer.
    assert neg.utility((50, 1)) == pytest.approx(8.0)
    assert neg.utility((150, 30)) == pytest.approx(0.0)


def test_arbitrary_offer_uses_normalized_attributes() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("seller"),
        a=2,
        b=6,
        side="seller",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )

    # Price 100 has normalized value 0.5.
    # Deadline 15 has normalized value 14/29.
    expected = 2 * 0.5 + 6 * (14 / 29)
    assert neg.weighted_sum((100, 15)) == pytest.approx(expected)


@pytest.mark.asyncio
async def test_seller_accepts_at_raw_weight_threshold() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("seller"),
        a=2,
        b=6,
        initial_utility=8.0,
        side="seller",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )
    session = await neg.open(AgentId("buyer"), terms(150, 30))
    await neg.offer(session, terms(150, 30))

    assert (await neg.respond(session)).accepted


@pytest.mark.asyncio
async def test_buyer_accepts_at_raw_weight_threshold() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("buyer"),
        a=2,
        b=6,
        initial_utility=0.0,
        side="buyer",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )
    session = await neg.open(AgentId("seller"), terms(50, 1))
    await neg.offer(session, terms(50, 1))

    assert (await neg.respond(session)).accepted


@pytest.mark.asyncio
async def test_seller_counteroffer_satisfies_threshold() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("seller"),
        a=2,
        b=6,
        initial_utility=6.4,
        side="seller",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )
    session = await neg.open(AgentId("buyer"), terms(50, 1))
    await neg.offer(session, terms(50, 1))

    response = await neg.respond(session)

    assert not response.accepted
    assert response.counter_terms is not None
    assert neg.weighted_sum(response.counter_terms) >= 6.4 - 1e-12


@pytest.mark.asyncio
async def test_buyer_counteroffer_satisfies_threshold() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("buyer"),
        a=2,
        b=6,
        initial_utility=1.6,
        side="buyer",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )
    session = await neg.open(AgentId("seller"), terms(150, 30))
    await neg.offer(session, terms(150, 30))

    response = await neg.respond(session)

    assert not response.accepted
    assert response.counter_terms is not None
    assert neg.weighted_sum(response.counter_terms) <= 1.6 + 1e-12


def test_u_decreases_on_raw_weight_score_scale() -> None:
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("seller"),
        a=2,
        b=6,
        initial_utility=8.0,
        patience=0.9,
        reservation=3.2,
        max_rounds=3,
        side="seller",
    )

    assert neg.aspiration(0) == pytest.approx(8.0)
    assert neg.aspiration(1) == pytest.approx(7.52)
    assert neg.aspiration(2) == pytest.approx(7.088)
    assert neg.aspiration(3) == pytest.approx(6.6992)
    assert neg.aspiration(100) == pytest.approx(6.6992)


def test_rejects_u_above_a_plus_b() -> None:
    with pytest.raises(ValueError, match=r"\[0, a \+ b\]"):
        DirectionalIntegerRawWeightsNegotiation(
            AgentId("seller"),
            a=2,
            b=6,
            initial_utility=9,
            side="seller",
        )


def test_market_weights_still_have_unit_scale() -> None:
    # The current market scenario already supplies weights summing to one.
    neg = DirectionalIntegerRawWeightsNegotiation(
        AgentId("seller"),
        weights={"price": 0.1, "deadline": 0.9},
        side="seller",
        price_range=(50, 150),
        deadline_range=(1, 30),
    )

    assert neg.maximum_score == pytest.approx(1.0)
    assert neg.weighted_sum((150, 30)) == pytest.approx(1.0)
