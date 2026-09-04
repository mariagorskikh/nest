"""Quorum evidence must count voters, not transport events.

Retains the distinct-voter/evidence requirement from legacy #171
(saurabhvmagdum), without importing its BFT protocol or fault model.
"""

import pytest

from nandatown.bundle import verify_bundle
from nandatown.records import TownEvent
from nandatown.sim.runner import build_engine, run_lab
from nandatown.sim.scenario import load_bundled
from nandatown.sim.validators import Trace, consensus


def fixture():
    """Literal trace, independent of the simulator and evaluator algorithms."""
    rows = [
        ("proposer", "message_sent", "p1", {"to": "acceptor-1", "kind": "prepare", "conversation": "c1", "body": {"value": "v42"}}),
        ("town", "message_delivered", "p1", {"to": "acceptor-1", "kind": "prepare"}),
        ("acceptor-1", "message_sent", "a1", {"to": "proposer", "kind": "prepare_ack", "conversation": "c1", "body": {"value": "v42"}}),
        ("town", "message_delivered", "a1", {"to": "proposer", "kind": "prepare_ack"}),
        ("proposer", "message_sent", "p2", {"to": "acceptor-2", "kind": "prepare", "conversation": "c2", "body": {"value": "v42"}}),
        ("town", "message_delivered", "p2", {"to": "acceptor-2", "kind": "prepare"}),
        ("acceptor-2", "message_sent", "a2", {"to": "proposer", "kind": "prepare_ack", "conversation": "c2", "body": {"value": "v42"}}),
        ("town", "message_delivered", "a2", {"to": "proposer", "kind": "prepare_ack"}),
        ("proposer", "consensus_committed", "v42", {"acks": ["acceptor-1", "acceptor-2"], "quorum": 2}),
        ("acceptor-1", "value_committed", "acceptor-1", {"value": "v42"}),
        ("acceptor-2", "value_committed", "acceptor-2", {"value": "v42"}),
        ("acceptor-3", "value_committed", "acceptor-3", {"value": "v42"}),
    ]
    return load_bundled("consensus"), [
        TownEvent(event_id=f"e{i}", run_id="literal", at=i,
                  observer=o, kind=k, subject=s, detail=d)
        for i, (o, k, s, d) in enumerate(rows)
    ]


def stage(spec, events, name="quorum_commit"):
    return next(s for s in consensus(spec, Trace(events)) if s.name == name)


@pytest.mark.parametrize("case,want", [
    ("duplicate_claim", "failed"),
    ("repeated_voter", "failed"),
    ("unknown_voter", "failed"),
    ("wrong_ack_value", "failed"),
    ("wrong_ack_recipient", "failed"),
    ("wrong_delivery_recipient", "failed"),
    ("wrong_delivery_kind", "failed"),
    ("wrong_delivery_observer", "failed"),
    ("wrong_proposal_value", "failed"),
    ("wrong_proposal_sender", "failed"),
    ("wrong_conversation", "failed"),
    ("late_ack", "failed"),
    ("late_prepare_delivery", "failed"),
    ("future_timestamp", "failed"),
    ("different_run", "failed"),
    ("duplicate_send_id", "failed"),
    ("failed_delivery", "failed"),
    ("wrong_committer", "failed"),
    ("wrong_commit_value", "failed"),
    ("wrong_quorum", "failed"),
    ("malformed_claim", "failed"),
    ("malformed_body", "failed"),
    ("missing_ack_send", "not_enough_evidence"),
    ("missing_ack_delivery", "not_enough_evidence"),
    ("missing_prepare_send", "not_enough_evidence"),
    ("missing_prepare_delivery", "not_enough_evidence"),
])
def test_quorum_requires_correlated_distinct_eligible_voters(case, want):
    spec, events = fixture()
    prepare, delivered_prepare, ack, delivery, commit = (
        events[4], events[5], events[6], events[7], events[8])
    if case == "duplicate_claim":
        commit.detail["acks"] = ["acceptor-1", "acceptor-1"]
    elif case == "repeated_voter":
        ack.observer = "acceptor-1"
    elif case == "unknown_voter":
        ack.observer = "outsider"
        commit.detail["acks"][1] = "outsider"
    elif case == "wrong_ack_value":
        ack.detail["body"]["value"] = "other"
    elif case == "wrong_ack_recipient":
        ack.detail["to"] = "another-proposer"
    elif case == "wrong_delivery_recipient":
        delivery.detail["to"] = "another-proposer"
    elif case == "wrong_delivery_kind":
        delivery.detail["kind"] = "not-an-ack"
    elif case == "wrong_delivery_observer":
        delivery.observer = "acceptor-2"
    elif case == "wrong_proposal_value":
        prepare.detail["body"]["value"] = "other"
    elif case == "wrong_proposal_sender":
        prepare.observer = "another-proposer"
    elif case == "wrong_conversation":
        ack.detail["conversation"] = "c1"
    elif case == "late_ack":
        events.remove(delivery)
        events.append(delivery)
    elif case == "late_prepare_delivery":
        events.remove(delivered_prepare)
        events.insert(7, delivered_prepare)
    elif case == "future_timestamp":
        ack.at = commit.at + 1
    elif case == "different_run":
        ack.run_id = "other-run"
    elif case == "duplicate_send_id":
        duplicate = ack.model_copy(deep=True)
        duplicate.event_id = "ambiguous-send"
        events.insert(6, duplicate)
    elif case == "failed_delivery":
        rejection = delivery.model_copy(deep=True)
        rejection.event_id = "rejected"
        rejection.kind = "delivery_failed"
        events.insert(8, rejection)
    elif case == "wrong_committer":
        commit.observer = "another-proposer"
    elif case == "wrong_commit_value":
        commit.subject = "other"
    elif case == "wrong_quorum":
        commit.detail["quorum"] = 1
    elif case == "malformed_claim":
        commit.detail["acks"] = {"acceptor-1": 1, "acceptor-2": 1}
    elif case == "malformed_body":
        ack.detail["body"] = []
    elif case == "missing_ack_send":
        events.remove(ack)
    elif case == "missing_ack_delivery":
        events.remove(delivery)
    elif case == "missing_prepare_send":
        events.remove(prepare)
    elif case == "missing_prepare_delivery":
        events.remove(delivered_prepare)
    assert stage(spec, events).status == want


def test_healthy_literal_and_repeated_delivery_with_real_quorum():
    spec, events = fixture()
    assert stage(spec, events).status == "passed"
    duplicate = events[3].model_copy(deep=True)
    duplicate.event_id = "redelivered"
    events.insert(4, duplicate)
    assert stage(spec, events).status == "passed"


def test_known_invalid_claim_is_not_hidden_by_missing_evidence():
    spec, events = fixture()
    events[8].detail["acks"] = ["acceptor-1", "outsider"]
    events.pop(2)
    assert stage(spec, events).status == "failed"


def test_later_invalid_commit_cannot_hide_behind_first_valid_commit():
    spec, events = fixture()
    invalid = events[8].model_copy(deep=True)
    invalid.event_id = "later-commit"
    invalid.detail["acks"] = ["acceptor-1", "acceptor-1"]
    events.append(invalid)
    assert stage(spec, events).status == "failed"


def test_agreement_must_be_for_the_proposed_value():
    spec, events = fixture()
    for event in events[9:]:
        event.detail["value"] = "unproposed"
    assert stage(spec, events, "agreement").status == "failed"


def test_empty_trace_does_not_certify_consensus():
    spec, _ = fixture()
    assert stage(spec, []).status == "not_enough_evidence"


def test_unrelated_retry_does_not_fill_a_missing_prepare_record():
    spec, events = fixture()
    events[4].detail["conversation"] = "another-attempt"
    assert stage(spec, events).status == "not_enough_evidence"


def test_unclaimed_outsider_ack_does_not_invalidate_a_real_quorum():
    spec, events = fixture()
    sent = events[2].model_copy(deep=True)
    sent.event_id, sent.subject, sent.observer = "noise-sent", "noise", "outsider"
    delivered = events[3].model_copy(deep=True)
    delivered.event_id, delivered.subject = "noise-delivered", "noise"
    events[8:8] = [sent, delivered]
    assert stage(spec, events).status == "passed"


def test_actual_consensus_and_exported_bundle_replay(tmp_path):
    spec = load_bundled("consensus")
    engine = build_engine(spec)
    engine.run()
    assert all(s.status == "passed" for s in consensus(spec, Trace(engine.events)))
    bundle, result = run_lab("consensus", str(tmp_path))
    assert result.verdict == "passed"
    assert verify_bundle(bundle) == []
