"""Marketplace buyer-cap contract from legacy PR #77 (@Skyrider3)."""

from copy import deepcopy
from types import MethodType

import pytest

from nandatown.sim.runner import build_engine
from nandatown.sim.scenario import load_bundled
from nandatown.sim.validators import Trace, evaluate_scenario, marketplace


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


def _run_marketplace():
    spec = load_bundled("marketplace")
    engine = build_engine(spec)
    engine.run()
    return spec, engine


def _result(spec, engine):
    return evaluate_scenario(spec, engine.run_id, engine.events)


def _stage(result, name):
    return next(stage for stage in result.stages if stage.name == name)


def _chain_event(events, name, nth=0):
    if name == "start":
        matches = [event for event in events
                   if event.kind == "negotiation_started"]
    elif name == "accepted":
        matches = [event for event in events
                   if event.kind == "offer_accepted"]
    elif name == "order":
        matches = [event for event in events
                   if event.kind == "message_sent"
                   and isinstance(event.detail, dict)
                   and event.detail.get("kind") == "purchase_order"]
    elif name == "held":
        matches = [event for event in events if event.kind == "escrow_held"]
    elif name == "released":
        matches = [event for event in events
                   if event.kind == "escrow_released"]
    elif name == "settled":
        matches = [event for event in events
                   if event.kind == "payment_settled"
                   and isinstance(event.detail, dict)
                   and event.detail.get("via") == "escrow"]
    else:  # pragma: no cover - test helper misuse
        raise AssertionError(f"unknown chain event {name}")
    return matches[nth]


def _set_field(event, path, value):
    if "." not in path:
        setattr(event, path, value)
        return
    target = event.detail
    parts = path.split(".")[1:]
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value


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


def test_trace_rejects_over_cap_unit_result_hidden_by_order_quantity():
    """Settlement total divided by its order quantity cannot exceed the cap."""
    spec, engine = _run_marketplace()
    order = _chain_event(engine.events, "order")
    order.detail["body"]["quantity"] = 1
    settlement = _chain_event(engine.events, "settled")
    settlement.detail["cents"] = 3800

    result = _result(spec, engine)

    assert _stage(result, "settlement").status == "failed"
    assert result.verdict == "failed"


def test_purchase_orders_carry_their_negotiation_ids():
    _, engine = _run_marketplace()
    starts = [_chain_event(engine.events, "start", index).subject
              for index in range(2)]
    orders = [_chain_event(engine.events, "order", index).detail["body"].get("nid")
              for index in range(2)]

    assert orders == starts


def test_correctly_ordered_purchase_order_cannot_name_other_negotiation():
    spec, engine = _run_marketplace()
    other_nid = _chain_event(engine.events, "start", 1).subject
    _chain_event(engine.events, "order").detail["body"]["nid"] = other_nid

    assert _stage(_result(spec, engine), "settlement").status == "failed"


def test_correctly_ordered_acceptance_cannot_name_other_negotiation():
    spec, engine = _run_marketplace()
    other_nid = _chain_event(engine.events, "start", 1).subject
    _chain_event(engine.events, "accepted").subject = other_nid

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


def test_purchase_order_requires_an_explicit_negotiation_id():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "order").detail["body"].pop("nid", None)

    assert _stage(_result(spec, engine), "settlement").status == "failed"


@pytest.mark.parametrize(("field", "value"), [
    ("observer", "unrelated-observer"),
    ("observer", "seller-a"),
    ("observer", "seller-b"),
    ("subject", "unrelated-negotiation"),
])
def test_trace_binds_acceptance_to_its_negotiation(field, value):
    spec, engine = _run_marketplace()
    _set_field(_chain_event(engine.events, "accepted"), field, value)

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


def test_seller_may_accept_the_buyers_immediately_preceding_offer():
    spec = load_bundled("marketplace")
    seller_index, seller = next(
        (index, agent) for index, agent in enumerate(spec.agents)
        if agent.name == "seller-b"
    )
    spec.agents[seller_index] = seller.model_copy(update={
        "config": {**seller.config, "floor_cents": 1500},
    })
    engine = build_engine(spec)

    engine.run()

    accepted = [event for event in engine.events
                if event.kind == "offer_accepted"]
    assert len(accepted) == 2
    assert all(event.observer == "seller-b" for event in accepted)
    assert _result(spec, engine).verdict == "passed"


@pytest.mark.parametrize(("field", "value"), [
    ("observer", "unrelated-observer"),
    ("detail.to", "seller-a"),
    ("detail.body.order_id", "unrelated-order"),
    ("detail.body.sku", "unrelated-sku"),
    ("detail.body.quantity", 1),
    ("detail.body.unit_cents", 1794),
])
def test_trace_binds_purchase_order_to_buyer_negotiation_and_terms(field, value):
    spec, engine = _run_marketplace()
    _set_field(_chain_event(engine.events, "order"), field, value)

    assert _stage(_result(spec, engine), "settlement").status == "failed"


@pytest.mark.parametrize(("name", "field", "value"), [
    ("held", "observer", "buyer-1"),
    ("held", "subject", "unrelated-order"),
    ("held", "detail.from", "seller-b"),
    ("held", "detail.cents", 3591),
    ("released", "observer", "buyer-1"),
    ("released", "subject", "unrelated-order"),
    ("released", "detail.to", "seller-a"),
    ("released", "detail.cents", 3591),
    ("settled", "observer", "buyer-1"),
    ("settled", "subject", "unrelated-order"),
    ("settled", "detail.from", "seller-b"),
    ("settled", "detail.to", "seller-a"),
    ("settled", "detail.via", "direct"),
    ("settled", "detail.cents", 3591),
])
def test_trace_binds_each_ledger_record_to_order_and_parties(
        name, field, value):
    spec, engine = _run_marketplace()
    _set_field(_chain_event(engine.events, name), field, value)

    assert _stage(_result(spec, engine), "settlement").status == "failed"


def test_trace_binds_accepted_unit_price_to_purchase_order():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "accepted").detail["cents"] = 1794

    assert _stage(_result(spec, engine), "settlement").status == "failed"


def test_trace_uses_the_negotiated_seller_specific_floor():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "start").detail["seller"] = "seller-a"
    _chain_event(engine.events, "order").detail["to"] = "seller-a"
    _chain_event(engine.events, "released").detail["to"] = "seller-a"
    _chain_event(engine.events, "settled").detail["to"] = "seller-a"

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


def test_malformed_negotiated_seller_fails_without_throwing():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "start").detail["seller"] = []

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


def test_trace_binds_negotiated_subject_to_configured_and_ordered_sku():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "start").detail["subject"] = "other-sku"
    _chain_event(engine.events, "order").detail["body"]["sku"] = "other-sku"

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


def test_trace_binds_negotiated_subject_to_seller_inventory():
    spec, engine = _run_marketplace()
    index, seller = next(
        (index, agent) for index, agent in enumerate(spec.agents)
        if agent.name == "seller-b"
    )
    spec.agents[index] = seller.model_copy(update={
        "config": {**seller.config, "sku": "other-sku"},
    })

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


@pytest.mark.parametrize("name", [
    "start", "accepted", "held", "order", "released", "settled",
])
def test_trace_binds_every_transaction_record_to_one_run(name):
    spec, engine = _run_marketplace()
    _chain_event(engine.events, name).run_id = "unrelated-run"

    failed_stage = "negotiation" if name in {"start", "accepted"} else "settlement"
    assert _stage(_result(spec, engine), failed_stage).status == "failed"


def test_transaction_chain_run_must_match_the_recorded_run():
    spec, engine = _run_marketplace()
    created = next(event for event in engine.events
                   if event.kind == "run_created")
    created.run_id = "other-run"
    created.subject = "other-run"
    for name in ("start", "accepted", "held", "order", "released", "settled"):
        for index in range(2):
            _chain_event(engine.events, name, index).run_id = "other-run"

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


@pytest.mark.parametrize(("earlier", "later"), [
    ("start", "accepted"),
    ("accepted", "held"),
    ("held", "order"),
    ("order", "released"),
    ("released", "settled"),
])
@pytest.mark.parametrize("reverse_time", [False, True])
def test_trace_requires_each_transaction_to_be_causally_ordered(
        earlier, later, reverse_time):
    spec, engine = _run_marketplace()
    first = _chain_event(engine.events, earlier)
    second = _chain_event(engine.events, later)
    if reverse_time:
        second.at = first.at - 1
    else:
        engine.events.remove(second)
        engine.events.insert(engine.events.index(first), second)

    assert _stage(_result(spec, engine), "settlement").status == "failed"


def test_trace_requires_distinct_evidence_ids_across_transactions():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "settled").event_id = _chain_event(
        engine.events, "released").event_id

    assert _stage(_result(spec, engine), "settlement").status == "failed"


def test_trace_rejects_empty_transaction_event_id():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "held").event_id = ""

    assert _stage(_result(spec, engine), "settlement").status == "failed"


def test_trace_requires_distinct_order_ids_even_if_every_reference_matches():
    spec, engine = _run_marketplace()
    first_order_id = _chain_event(engine.events, "order").detail["body"]["order_id"]
    _chain_event(engine.events, "order", 1).detail["body"]["order_id"] = first_order_id
    for name in ("held", "released", "settled"):
        _chain_event(engine.events, name, 1).subject = first_order_id

    assert _stage(_result(spec, engine), "settlement").status == "failed"


def test_trace_requires_distinct_negotiation_ids_even_if_acceptance_matches():
    spec, engine = _run_marketplace()
    first_nid = _chain_event(engine.events, "start").subject
    _chain_event(engine.events, "start", 1).subject = first_nid
    _chain_event(engine.events, "accepted", 1).subject = first_nid

    result = _result(spec, engine)

    assert _stage(result, "negotiation").status == "failed"
    assert _stage(result, "settlement").status == "failed"


@pytest.mark.parametrize("name", [
    "start", "accepted", "held", "order", "released", "settled",
])
def test_trace_reports_missing_transaction_records_as_insufficient(name):
    spec, engine = _run_marketplace()
    engine.events.remove(_chain_event(engine.events, name))

    failed_stage = "negotiation" if name in {"start", "accepted"} else "settlement"
    assert _stage(_result(spec, engine), failed_stage).status == "not_enough_evidence"


@pytest.mark.parametrize("name", [
    "start", "accepted", "held", "order", "released", "settled",
])
def test_trace_rejects_extra_transaction_records(name):
    spec, engine = _run_marketplace()
    duplicate = deepcopy(_chain_event(engine.events, name))
    duplicate.event_id = f"extra-{name}"
    engine.events.append(duplicate)

    failed_stage = "negotiation" if name in {"start", "accepted"} else "settlement"
    assert _stage(_result(spec, engine), failed_stage).status == "failed"


@pytest.mark.parametrize(("name", "field", "value"), [
    ("start", "detail", []),
    ("accepted", "detail", {}),
    ("accepted", "detail.cents", 1795.0),
    ("order", "detail.body", []),
    ("order", "detail.body.order_id", 1),
    ("order", "detail.body.quantity", 2.0),
    ("order", "detail.body.unit_cents", True),
    ("held", "detail", {}),
    ("held", "detail.cents", "3590"),
    ("released", "detail", {}),
    ("released", "detail.cents", 3590.0),
    ("settled", "detail", {}),
    ("settled", "detail.from", 1),
    ("settled", "detail.cents", True),
])
def test_malformed_transaction_evidence_fails_without_throwing(
        name, field, value):
    spec, engine = _run_marketplace()
    _set_field(_chain_event(engine.events, name), field, value)

    result = _result(spec, engine)

    failed_stage = "negotiation" if name in {"start", "accepted"} else "settlement"
    assert _stage(result, failed_stage).status == "failed"


def test_unidentifiable_malformed_order_is_insufficient_without_throwing():
    spec, engine = _run_marketplace()
    _chain_event(engine.events, "order").detail = []

    result = _result(spec, engine)

    assert _stage(result, "settlement").status == "not_enough_evidence"


@pytest.mark.parametrize("kind", ["receipt_attested", "reputation_updated"])
def test_malformed_marketplace_reputation_evidence_fails_without_throwing(kind):
    spec, engine = _run_marketplace()
    event = next(event for event in engine.events if event.kind == kind)
    event.detail = []

    result = _result(spec, engine)

    assert _stage(result, "reputation").status == "failed"


@pytest.mark.parametrize(("kind", "field", "value"), [
    ("receipt_attested", "at", "not-a-time"),
    ("reputation_updated", "at", "not-a-time"),
    ("reputation_updated", "subject", []),
])
def test_type_invalid_reputation_metadata_fails_without_throwing(
        kind, field, value):
    spec, engine = _run_marketplace()
    event = next(event for event in engine.events if event.kind == kind)
    setattr(event, field, value)

    result = _result(spec, engine)

    assert _stage(result, "reputation").status == "failed"


@pytest.mark.parametrize("name", [
    "start", "accepted", "held", "order", "released", "settled",
])
def test_type_invalid_transaction_event_id_does_not_throw_or_pass(name):
    spec, engine = _run_marketplace()
    _chain_event(engine.events, name).event_id = []

    result = _result(spec, engine)

    stage = "negotiation" if name in {"start", "accepted"} else "settlement"
    assert _stage(result, stage).status == "failed"
    assert result.verdict != "passed"


@pytest.mark.parametrize("kind", ["receipt_attested", "reputation_updated"])
def test_type_invalid_reputation_event_id_does_not_throw_or_pass(kind):
    spec, engine = _run_marketplace()
    event = next(event for event in engine.events if event.kind == kind)
    event.event_id = []

    result = _result(spec, engine)

    assert _stage(result, "reputation").status == "failed"
    assert result.verdict != "passed"
