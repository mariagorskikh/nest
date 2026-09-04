"""Regression coverage for Lab scenario evaluation boundaries."""

import hashlib
import json
import os

import pytest

from nandatown.bundle import verify_bundle
from nandatown.records import StageResult, TownEvent, fingerprint
from nandatown.sim.runner import build_engine, run_lab
from nandatown.sim.scenario import load_bundled, load_scenario_file
from nandatown.sim.validators import (
    LAB_EVALUATOR_VERSION,
    VALIDATORS,
    Trace,
    evaluate_scenario,
    ledger_conserved,
    privacy_clean,
)


NATIVE_SCENARIO_STAGES = {
    "marketplace": {
        "discovery", "negotiation", "settlement", "duplicate_recognized",
        "reputation", "memory_reuse",
    },
    "auction": {"announced", "bidding", "award", "settlement", "delivery"},
    "voting": {"ballots", "one_agent_one_vote", "tally", "result_broadcast"},
    "consensus": {"quorum_commit", "agreement", "fault_recovered"},
    "supply_chain": {
        "procurement", "milestones", "assembly_order", "customer_settled",
    },
    "capability_spoofing": {
        "spoof_detected", "honest_verified", "containment",
        "honest_trade_completed",
    },
}
ADAPTED_STAGES = {
    "population_active", "discovery", "messages_flowed", "task_completed",
    "original_scenario",
}
GENERIC_STAGES = {"ledger_conserved", "privacy"}
UPSTREAM_FIXTURES = os.path.join(
    os.path.dirname(__file__), "fixtures", "upstream", "voting.yaml",
)


def stage(result, name):
    return next(item for item in result.stages if item.name == name)


def complete_run_event():
    return TownEvent(
        event_id="finished", run_id="run", at=1.0, observer="town",
        kind="run_finished", subject="run", detail={},
    )


def test_empty_selected_validator_is_a_town_error(monkeypatch):
    """Removing a selected scenario's checks cannot inherit generic PASS."""
    spec = load_bundled("marketplace")
    engine = build_engine(spec)
    engine.run()
    monkeypatch.setitem(VALIDATORS, "marketplace", lambda spec, trace: [])

    for events in ([], engine.events):
        result = evaluate_scenario(spec, "coverage-check", events)
        assert result.verdict == "error"
        coverage = stage(result, "scenario_coverage")
        assert coverage.status == "error"
        assert coverage.note == (
            "selected validator 'marketplace' produced no scenario checks"
        )


def test_unknown_and_untested_selected_validators_remain_incomplete(monkeypatch):
    """Missing coverage is not a subject failure or a generic-pass shortcut."""
    spec = load_bundled("marketplace")
    spec.validator = "not-registered"
    unknown = evaluate_scenario(spec, "unknown", [])
    assert unknown.verdict == "incomplete"
    assert stage(unknown, "validator").status == "not_enough_evidence"

    monkeypatch.setitem(
        VALIDATORS, "marketplace",
        lambda spec, trace: [StageResult(name="source", status="not_tested")],
    )
    spec.validator = "marketplace"
    untested = evaluate_scenario(spec, "untested", [complete_run_event()])
    assert untested.verdict == "incomplete"
    coverage = stage(untested, "scenario_coverage")
    assert coverage.status == "not_enough_evidence"
    assert coverage.note == (
        "selected validator 'marketplace' produced only not_tested checks"
    )


def test_empty_generic_claims_are_missing_but_complete_no_money_is_valid():
    """An empty trace cannot prove ledger or declared-privacy claims."""
    empty = Trace([])
    assert ledger_conserved(empty).status == "not_enough_evidence"
    assert privacy_clean(empty, ["secret"]).status == "not_enough_evidence"
    assert privacy_clean(empty, []).status == "not_tested"

    complete = Trace([complete_run_event()])
    assert ledger_conserved(complete).status == "passed"


def test_declared_privacy_rejects_an_unredacted_event():
    """A declared field with its literal value is a privacy failure."""
    leaked = TownEvent(
        event_id="leak", run_id="run", at=1.0, observer="town",
        kind="note", subject="run", detail={"nested": {"secret": "raw"}},
    )
    result = privacy_clean(Trace([leaked]), ["secret"])
    assert result.status == "failed"
    assert result.evidence == ["leak"]


@pytest.mark.parametrize("name, expected", [
    ("marketplace", NATIVE_SCENARIO_STAGES["marketplace"]),
    ("auction", NATIVE_SCENARIO_STAGES["auction"]),
    ("voting", NATIVE_SCENARIO_STAGES["voting"]),
    ("consensus", NATIVE_SCENARIO_STAGES["consensus"]),
    ("supply_chain", NATIVE_SCENARIO_STAGES["supply_chain"]),
    ("capability_spoofing", NATIVE_SCENARIO_STAGES["capability_spoofing"]),
])
def test_healthy_native_scenarios_emit_their_literal_stage_set(name, expected):
    """Deleting a required native check must fail against this fixed matrix."""
    spec = load_bundled(name)
    engine = build_engine(spec)
    engine.run()
    result = evaluate_scenario(spec, engine.run_id, engine.events)
    assert {item.name for item in result.stages} == expected | GENERIC_STAGES
    assert {item.name for item in result.stages} - GENERIC_STAGES == expected
    assert result.verdict == "passed"


def test_adapted_reference_run_emits_its_literal_stage_set():
    """Adapted coverage is explicit and remains separate from native checks."""
    spec = load_scenario_file(UPSTREAM_FIXTURES)
    engine = build_engine(spec)
    engine.run()
    result = evaluate_scenario(spec, engine.run_id, engine.events)
    assert {item.name for item in result.stages} == ADAPTED_STAGES | GENERIC_STAGES
    assert result.verdict == "passed"


def test_bundled_empty_and_irrelevant_traces_remain_incomplete():
    """Scenario checks need evidence; this does not claim arbitrary truncation detection."""
    irrelevant = TownEvent(
        event_id="irrelevant", run_id="run", at=1.0, observer="town",
        kind="irrelevant", subject="run", detail={},
    )
    for name in NATIVE_SCENARIO_STAGES:
        spec = load_bundled(name)
        assert evaluate_scenario(spec, "empty", []).verdict == "incomplete"
        assert evaluate_scenario(spec, "irrelevant", [irrelevant]).verdict == "incomplete"


def test_weak_auth_remains_a_deliberately_failing_native_control():
    spec = load_bundled("capability_spoofing_weak_auth")
    engine = build_engine(spec)
    engine.run()
    result = evaluate_scenario(spec, engine.run_id, engine.events)
    assert {item.name for item in result.stages} == (
        NATIVE_SCENARIO_STAGES["capability_spoofing"] | GENERIC_STAGES
    )
    assert result.verdict == "failed"
    assert stage(result, "containment").status == "failed"


@pytest.mark.parametrize("old_version", ["lab-0.2.0", "lab-0.2.1", "lab-0.2.2"])
def test_new_lab_bundles_replay_and_old_lab_versions_do_not(tmp_path, old_version):
    """The evaluator bump makes old Lab bundles explicitly non-reproducible."""
    bundle_dir, result = run_lab("marketplace", str(tmp_path))
    assert result.evaluator_version == LAB_EVALUATOR_VERSION
    assert verify_bundle(bundle_dir) == []

    result_path = os.path.join(bundle_dir, "result.json")
    recorded = json.loads(open(result_path).read())
    recorded["evaluator_version"] = old_version
    with open(result_path, "w") as handle:
        json.dump(recorded, handle)
    manifest_path = os.path.join(bundle_dir, "manifest.json")
    manifest = json.loads(open(manifest_path).read())
    manifest["files"]["result.json"] = "sha256:" + hashlib.sha256(
        open(result_path, "rb").read()
    ).hexdigest()
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle)

    assert verify_bundle(bundle_dir) == [
        f"evaluator version differs: bundle {old_version}, local "
        "lab-0.2.3; reproducibility not checked",
    ]
