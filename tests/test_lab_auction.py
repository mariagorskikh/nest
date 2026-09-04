"""Conserving a total does not prove the intended payee received it.

Retains the correct-recipient distinction from legacy PR #136
(KaranSinghBisht); does not implement its weighted fan-out protocol.
"""

import pytest

from nandatown.bundle import load_bundle, verify_bundle
from nandatown.records import TownEvent
from nandatown.sim.runner import build_engine, run_lab
from nandatown.sim.scenario import load_bundled
from nandatown.sim.validators import Trace, auction, evaluate_scenario


def settlement(spec, events):
    return next(s for s in auction(spec, Trace(events))
                if s.name == "settlement")


def literal_payment_chain():
    """Hand-written bindings, independent of the simulator and evaluator."""
    rows = [
        ("town", "run_created", "run-a", {"scenario": "auction"}),
        ("auctioneer", "task_announced", "auction-print-001",
         {"rule": "highest", "spec": {"item": "print-001"}}),
        ("auctioneer", "task_awarded", "auction-print-001",
         {"winner": "bidder-y", "cents": 900, "rule": "highest"}),
        ("town", "payment_settled", "auction-print-001",
         {"from": "bidder-y", "to": "auctioneer", "cents": 900}),
    ]
    return [TownEvent(event_id=f"event-{i}", run_id="run-a", at=i,
                      observer=who, kind=kind, subject=subject, detail=detail)
            for i, (who, kind, subject, detail) in enumerate(rows)]


@pytest.mark.parametrize("target,field,value", [
    (3, "to", "bidder-x"),
    (3, "from", "bidder-x"),
    (3, "cents", 899),
    (3, "cents", 900.0),
    (2, "winner", "not-a-bidder"),
    (2, "cents", 900.0),
    (2, "rule", "lowest"),
    (1, "rule", "lowest"),
    (1, "spec", {"item": "different-item"}),
])
def test_settlement_rejects_conflicting_terms(target, field, value):
    """Dropping the individual binding must make its case pass incorrectly."""
    events = literal_payment_chain()
    events[target].detail[field] = value
    assert settlement(load_bundled("auction"), events).status == "failed"


@pytest.mark.parametrize("target", [1, 2, 3])
@pytest.mark.parametrize("field,value", [
    ("subject", "unrelated-task"),
    ("observer", "unrelated-observer"),
    ("run_id", "unrelated-run"),
])
def test_settlement_binds_each_record_to_the_task_and_run(target, field, value):
    events = literal_payment_chain()
    setattr(events[target], field, value)
    assert settlement(load_bundled("auction"), events).status == "failed"


@pytest.mark.parametrize("target", [0, 1, 2, 3])
def test_settlement_requires_each_record(target):
    events = literal_payment_chain()
    del events[target]
    assert settlement(load_bundled("auction"), events).status == "not_enough_evidence"


@pytest.mark.parametrize("target", [0, 1, 2, 3])
def test_settlement_rejects_duplicate_records(target):
    events = literal_payment_chain()
    repeated = events[target].model_copy(deep=True)
    repeated.event_id = "duplicate-record"
    events.insert(target + 1, repeated)
    assert settlement(load_bundled("auction"), events).status == "failed"


@pytest.mark.parametrize("target", [1, 2, 3])
@pytest.mark.parametrize("reverse_time", [False, True])
def test_settlement_requires_prior_evidence(target, reverse_time):
    events = literal_payment_chain()
    if reverse_time:
        events[target].at = events[target - 1].at - 1
    else:
        events[target], events[target - 1] = events[target - 1], events[target]
    assert settlement(load_bundled("auction"), events).status == "failed"


def test_wrong_payee_is_not_hidden_by_missing_award():
    events = literal_payment_chain()
    events[3].detail["to"] = "bidder-x"
    del events[2]
    assert settlement(load_bundled("auction"), events).status == "failed"


def test_matching_payment_and_award_do_not_admit_an_unconfigured_bidder():
    events = literal_payment_chain()
    events[2].detail["winner"] = events[3].detail["from"] = "outsider"
    assert settlement(load_bundled("auction"), events).status == "failed"


def test_distinct_records_cannot_share_an_evidence_id():
    events = literal_payment_chain()
    events[3].event_id = events[2].event_id
    assert settlement(load_bundled("auction"), events).status == "failed"


@pytest.mark.parametrize("field,value", [
    ("observer", "not-town"), ("subject", "wrong-run")])
def test_run_creation_record_must_identify_the_run(field, value):
    events = literal_payment_chain()
    setattr(events[0], field, value)
    assert settlement(load_bundled("auction"), events).status == "failed"


def test_equal_logical_timestamps_keep_recorded_order():
    events = literal_payment_chain()
    for event in events:
        event.at = 0
    assert settlement(load_bundled("auction"), events).status == "passed"


def test_literal_settlement_cites_its_evidence():
    events = literal_payment_chain()
    result = settlement(load_bundled("auction"), events)
    assert result.status == "passed"
    assert set(result.evidence) == {"event-0", "event-1", "event-2", "event-3"}


def test_configured_seller_and_item_are_not_hardcoded():
    spec = load_bundled("auction")
    spec.agents[0] = spec.agents[0].model_copy(update={
        "name": "another-seller", "config": {"item": "another-item"}})
    events = literal_payment_chain()
    for e in events[1:]:
        e.subject = "auction-another-item"
    events[1].observer = events[2].observer = "another-seller"
    events[1].detail["spec"] = {"item": "another-item"}
    events[3].detail["to"] = "another-seller"
    assert settlement(spec, events).status == "passed"


def test_real_wrong_recipient_transfer_fails_even_when_money_is_conserved():
    spec = load_bundled("auction")
    engine = build_engine(spec)
    ledger = engine.layers["payments"]
    original = ledger.transfer

    def wrong_recipient(frm, to, cents, memo):
        original(frm, "bidder-x", cents, memo)

    ledger.transfer = wrong_recipient
    engine.run()
    assert ledger.balances == {"auctioneer": 0, "bidder-x": 2900,
                               "bidder-y": 1100, "bidder-late": 2000}
    result = evaluate_scenario(spec, engine.run_id, engine.events)
    stages = {s.name: s.status for s in result.stages}
    assert stages["ledger_conserved"] == "passed"
    assert stages["settlement"] == "failed"
    assert result.verdict == "failed"


def test_healthy_auction_runs_and_replays(tmp_path):
    directory, result = run_lab("auction", str(tmp_path))
    assert result.verdict == "passed"
    assert verify_bundle(directory) == []
    bundle = load_bundle(directory)
    payment = next(e for e in bundle["events"] if e.kind == "payment_settled")
    assert payment.detail == {"from": "bidder-y", "to": "auctioneer", "cents": 900}
    stage = next(s for s in result.stages if s.name == "settlement")
    assert {e.kind for e in bundle["events"] if e.event_id in stage.evidence} == {
        "run_created", "task_announced", "task_awarded", "payment_settled"}
