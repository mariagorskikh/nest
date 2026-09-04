"""A final score alone must not stand in for attributable score changes.

Retains the report/outcome and per-update (not lifetime-negative) distinction
raised by legacy PRs #129 (Anurag17-2005) and #178 (RoarHX).
"""

import pytest

from nandatown.sim.runner import build_engine, run_lab
from nandatown.sim.scenario import load_bundled
from nandatown.sim.api import TownAPI
from nandatown.sim.engine import Engine
from nandatown.sim.validators import (
    Trace, evaluate_scenario, marketplace, reputation_consistent,
)
from nandatown.bundle import verify_bundle


def marketplace_trace():
    spec = load_bundled("marketplace")
    engine = build_engine(spec)
    engine.run()
    return spec, [event.model_copy(deep=True) for event in engine.events]


def reputation_stage(spec, events):
    return next(stage for stage in marketplace(spec, Trace(events))
                if stage.name == "reputation")


@pytest.mark.parametrize("case,want", [
    ("missing_receipts", "not_enough_evidence"),
    ("missing_one_receipt", "not_enough_evidence"),
    ("wrong_subject", "failed"),
    ("wrong_observer", "failed"),
    ("self_report", "failed"),
    ("wrong_claim", "failed"),
    ("wrong_outcome", "failed"),
    ("future_receipt", "failed"),
    ("future_timestamp", "failed"),
    ("different_run", "failed"),
    ("duplicate_receipt_id", "failed"),
    ("reused_receipt", "failed"),
    ("wrong_intermediate_score", "failed"),
    ("wrong_delta", "failed"),
    ("unknown_outcome", "failed"),
    ("bool_delta", "failed"),
    ("bool_score", "failed"),
    ("missing_score", "failed"),
    ("malformed_receipt_ref", "failed"),
])
def test_marketplace_reputation_requires_receipt_backed_arithmetic(case, want):
    """Removing attribution/arithmetic checks must break these regressions."""
    spec, events = marketplace_trace()
    receipts = [e for e in events if e.kind == "receipt_attested"]
    updates = [e for e in events if e.kind == "reputation_updated"]
    assert len(receipts) == len(updates) == 2
    if case == "missing_receipts":
        events = [e for e in events if e.kind != "receipt_attested"]
    elif case == "missing_one_receipt":
        events.remove(receipts[0])
    elif case == "wrong_subject":
        receipts[0].subject = "unrelated-seller"
    elif case == "wrong_observer":
        receipts[0].observer = "unrelated-buyer"
    elif case == "self_report":
        receipts[0].observer = updates[0].observer = updates[0].subject
    elif case == "wrong_claim":
        receipts[0].detail["claim"] = "endpoint.live"
    elif case == "wrong_outcome":
        receipts[0].detail["value"] = "bad"
    elif case == "future_receipt":
        events.remove(receipts[0])
        events.append(receipts[0])
    elif case == "future_timestamp":
        receipts[0].at = updates[0].at + 1
    elif case == "different_run":
        receipts[0].run_id = "different-run"
    elif case == "duplicate_receipt_id":
        receipts[1].detail["record_id"] = receipts[0].detail["record_id"]
    elif case == "reused_receipt":
        updates[1].detail["receipt"] = updates[0].detail["receipt"]
    elif case == "wrong_intermediate_score":
        updates[0].detail["score"] = 999
    elif case == "wrong_delta":
        updates[0].detail["delta"] = -1
    elif case == "unknown_outcome":
        updates[0].detail["outcome"] = "uncertain"
    elif case == "bool_delta":
        updates[0].detail["delta"] = True
    elif case == "bool_score":
        updates[0].detail["score"] = True
    elif case == "missing_score":
        del updates[0].detail["score"]
    elif case == "malformed_receipt_ref":
        updates[0].detail["receipt"] = []
    result = evaluate_scenario(spec, events[0].run_id, events)
    stage = next(s for s in result.stages if s.name == "reputation")
    assert stage.status == want
    assert result.verdict != "passed"


def test_healthy_marketplace_cites_receipts_and_replays(tmp_path):
    spec, events = marketplace_trace()
    stage = reputation_stage(spec, events)
    assert stage.status == "passed"
    cited_kinds = {e.kind for e in events if e.event_id in stage.evidence}
    assert cited_kinds == {"receipt_attested", "reputation_updated"}
    bundle_dir, result = run_lab("marketplace", str(tmp_path))
    assert result.verdict == "passed"
    assert verify_bundle(bundle_dir) == []


def test_empty_reputation_is_missing_not_success():
    spec = load_bundled("marketplace")
    assert reputation_stage(spec, []).status == "not_enough_evidence"


@pytest.mark.parametrize("case,want", [
    ("recorded_bad", "passed"),
    ("bad_raises_score", "failed"),
    ("bad_missing_receipt", "not_enough_evidence"),
])
def test_real_bad_report_decrements_without_requiring_negative_total(case, want):
    """Do not confuse a negative delta with a negative lifetime reputation."""
    engine = Engine(load_bundled("marketplace"))
    engine.layers["identity"].create("buyer")
    api = TownAPI(engine, "buyer")
    for outcome in ("good", "good", "good", "bad"):
        api.rate("seller", outcome)
    assert api.reputation("seller") == 2
    updates = [e for e in engine.events if e.kind == "reputation_updated"]
    assert [e.detail["score"] for e in updates] == [1, 2, 3, 2]
    assert [e.detail["delta"] for e in updates] == [1, 1, 1, -1]
    if case == "bad_raises_score":
        updates[-1].detail.update(delta=1, score=4)
    elif case == "bad_missing_receipt":
        engine.events = [e for e in engine.events
                         if not (e.kind == "receipt_attested"
                                 and e.detail["value"] == "bad")]
    stage = reputation_consistent(Trace(engine.events))
    assert stage.status == want
    # These are attributed reports, not an independently observed cheating test.
    assert not any(e.kind == "cheat" for e in engine.events)


def test_known_arithmetic_failure_is_not_hidden_by_another_missing_receipt():
    _, events = marketplace_trace()
    receipts = [e for e in events if e.kind == "receipt_attested"]
    updates = [e for e in events if e.kind == "reputation_updated"]
    events.remove(receipts[0])
    updates[1].detail["score"] = 999
    assert reputation_consistent(Trace(events)).status == "failed"


def test_missing_receipt_does_not_hide_wrong_marketplace_update_count():
    spec, events = marketplace_trace()
    events = [e for e in events if e.kind != "receipt_attested"]
    last = [e for e in events if e.kind == "reputation_updated"][-1]
    extra = last.model_copy(deep=True, update={"event_id": "extra-update"})
    extra.detail.update(score=3, receipt="absent-third-receipt")
    events.append(extra)
    assert reputation_stage(spec, events).status == "failed"
