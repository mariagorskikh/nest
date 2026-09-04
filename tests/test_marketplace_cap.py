"""Marketplace buyer-cap contract from legacy PR #77 (@Skyrider3)."""

from types import MethodType

import pytest

from nandatown.sim.runner import build_engine
from nandatown.sim.scenario import load_bundled
from nandatown.sim.validators import Trace, marketplace


def _with_buyer_cap(spec, cap_cents):
    index, buyer = next(
        (index, agent) for index, agent in enumerate(spec.agents)
        if agent.role == "buyer"
    )
    spec.agents[index] = buyer.model_copy(update={
        "config": {**buyer.config, "cap_cents": cap_cents},
    })
    return spec


def _stages(spec, events):
    return {stage.name: stage for stage in marketplace(spec, Trace(events))}


def test_initial_marketplace_offer_never_exceeds_buyer_cap():
    spec = _with_buyer_cap(load_bundled("marketplace"), 1500)
    engine = build_engine(spec)

    engine.run()

    offers = [event for event in engine.events if event.kind == "offer_made"]
    assert offers
    assert all(event.detail["cents"] <= 1500 for event in offers)


def test_over_cap_seller_acceptance_cannot_create_escrow_or_order():
    spec = load_bundled("marketplace")
    engine = build_engine(spec)
    buyer = next(agent for agent in engine.agents.values()
                 if agent.role == "buyer")
    over_cap = buyer.config["cap_cents"] + 1

    def accept_above_cap(seller, message):
        seller.api.reply(message, "nego_accepted", {
            "nid": message["body"]["nid"], "cents": over_cap,
        })

    for seller in (agent for agent in engine.agents.values()
                   if agent.role == "seller"):
        seller.handle_nego_offer = MethodType(accept_above_cap, seller)

    engine.run()

    assert not [event for event in engine.events
                if event.kind == "escrow_held"]
    assert not [event for event in engine.events
                if event.kind == "message_sent"
                and event.detail.get("kind") == "purchase_order"]
    abandoned = [event for event in engine.events
                 if event.kind == "negotiation_abandoned"]
    assert abandoned
    assert abandoned[0].detail["reason"] == "price_above_cap"


@pytest.mark.parametrize(("mutation", "failed_stage"), [
    ("accepted", "negotiation"),
    ("ordered", "settlement"),
    ("settled", "settlement"),
])
def test_trace_rejects_accepted_or_purchased_price_above_cap(
        mutation, failed_stage):
    spec = load_bundled("marketplace")
    engine = build_engine(spec)
    engine.run()
    buyer = next(agent for agent in spec.agents if agent.role == "buyer")
    cap = buyer.config["cap_cents"]
    quantity = buyer.config["quantity"]

    if mutation == "accepted":
        event = next(event for event in engine.events
                     if event.kind == "offer_accepted")
        event.detail["cents"] = cap + 1
    elif mutation == "ordered":
        event = next(event for event in engine.events
                     if event.kind == "message_sent"
                     and event.detail.get("kind") == "purchase_order")
        event.detail["body"]["unit_cents"] = cap + 1
    else:
        event = next(event for event in engine.events
                     if event.kind == "payment_settled")
        event.detail["cents"] = (cap + 1) * quantity

    assert _stages(spec, engine.events)[failed_stage].status == "failed"
