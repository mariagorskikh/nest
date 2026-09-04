import os
from pathlib import Path

import pytest
import yaml

from nandatown.bundle import load_bundle, verify_bundle
from nandatown.sim.runner import run_lab
from nandatown.sim.scenario import load_scenario_file
from nandatown.sim.upstream import adapt_upstream
from nandatown.sim.validators import evaluate_scenario

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "upstream")


def fixture(name):
    return os.path.join(FIXTURES, name)


def stage(result, name):
    return next(s for s in result.stages if s.name == name)


def test_upstream_format_is_detected_and_adapted():
    spec = load_scenario_file(fixture("voting.yaml"))
    assert spec.name == "upstream-voting"
    assert spec.validator == "adapted"
    roles = [a.role for a in spec.agents]
    assert roles.count("ballot_box") == 1
    assert roles.count("voter") == 19
    assert any("coordinator adapted as ballot_box" in a
               for a in spec.adaptations)


def test_pr220_capability_fulfillment_runs_end_to_end(tmp_path):
    bundle_dir, result = run_lab(fixture("capability_fulfillment.yaml"),
                                 str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail
    for name in ["population_active", "discovery", "messages_flowed",
                 "task_completed"]:
        assert stage(result, name).status == "passed", detail
    assert verify_bundle(bundle_dir) == []
    bundle = load_bundle(bundle_dir)
    assert any("requester adapted as buyer" in a
               for a in bundle["profile"].adaptations)


def test_upstream_voting_runs_end_to_end(tmp_path):
    bundle_dir, result = run_lab(fixture("voting.yaml"), str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail
    assert verify_bundle(bundle_dir) == []


def test_upstream_marketplace_scales_population(tmp_path):
    spec = load_scenario_file(fixture("marketplace.yaml"))
    assert len(spec.agents) <= 32
    buyers = sum(1 for a in spec.agents if a.role == "buyer")
    sellers = sum(1 for a in spec.agents if a.role == "seller")
    assert buyers >= 10 and sellers >= 10
    assert any("scaled" in a for a in spec.adaptations)
    bundle_dir, result = run_lab(fixture("marketplace.yaml"),
                                 str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail


def test_drop_rate_failures_translate():
    spec = adapt_upstream({
        "name": "lossy", "seed": 1,
        "agents": {"roles": [{"name": "requester", "count": 1},
                             {"name": "provider", "count": 1}]},
        "task": {"type": "capability_fulfillment"},
        "failures": {"message_drop": 0.5, "byzantine_agents": 0.1},
        "duration": "ticks: 10000",
    })
    assert spec.faults[0].action == "drop_rate"
    assert spec.faults[0].rate == 0.2
    assert spec.max_time == 300.0
    assert any("byzantine" in a for a in spec.adaptations)


def test_unknown_task_falls_back_to_exchange():
    spec = adapt_upstream({
        "name": "mystery", "seed": 3,
        "agents": {"roles": [{"name": "alpha", "count": 1},
                             {"name": "beta", "count": 1}]},
        "task": {"type": "quantum_bartering"},
    })
    assert {a.role for a in spec.agents} == {"buyer", "seller"}
    assert any("alpha adapted as buyer" in a for a in spec.adaptations)


@pytest.mark.parametrize("key, value", [
    ("network_partition", {"groups": [["private-peer-marker"]]}),
    ("network_partition", False),
    ("reasoning_timeout", 0),
    ("byzantine_agents", 0),
    ("byzantine_agents", 0.1),
])
def test_unsupported_failure_declarations_never_disappear(key, value):
    """Even a disabled unknown condition is not silently treated as supported."""
    spec = adapt_upstream({"failures": {key: value}})
    disclosure = "\n".join(spec.adaptations)
    assert f"failures.{key}" in disclosure
    assert "not modeled" in disclosure
    assert "private-peer-marker" not in disclosure
    assert spec.faults == []


@pytest.mark.parametrize("task_type, failure", [
    ("streaming_payments", {"network_partition": {"groups": [["payer"], ["payee"]]}}),
    ("gossip_registry", {"network_partition": {"groups": [["peer_a"], ["peer_b"]]}}),
])
def test_adapted_run_exports_original_scope_as_untested(tmp_path, task_type, failure):
    """A passing reference exchange cannot certify streaming or partition semantics."""
    source = tmp_path / "legacy.yaml"
    source.write_text(yaml.safe_dump({
        "name": task_type,
        "task": {"type": task_type},
        "agents": {"roles": [{"name": "buyer"}, {"name": "seller"}]},
        "failures": failure,
        # The importer must not execute upstream plugin code.
        "plugin_files": [str(tmp_path / "not-a-local-plugin.py")],
    }))
    directory, result = run_lab(str(source), str(tmp_path / "runs"))
    assert result.verdict == "passed"
    assert stage(result, "task_completed").status == "passed"
    original = stage(result, "original_scenario")
    assert original.status == "not_tested"
    assert original.evidence == []
    assert "original" in original.note.lower()
    bundle = load_bundle(directory)
    assert bundle["profile"].plugin_files == []
    assert any("failures.network_partition" in note
               for note in bundle["profile"].adaptations)
    assert verify_bundle(directory) == []
    report = (Path(directory) / "report.md").read_text()
    assert "failures.network_partition" in report
    assert "original_scenario" in report
    source_line = next(line for line in report.splitlines()
                       if "original_scenario" in line)
    assert "not tested" in source_line.lower()
    assert "adapted reference flow only" in report


def test_empty_adapted_trace_still_cannot_pass():
    """An explicit untested-source marker cannot hide missing local evidence."""
    result = evaluate_scenario(adapt_upstream({}), "empty-adaptation", [])
    assert result.verdict == "incomplete"
    assert stage(result, "original_scenario").status == "not_tested"
    assert stage(result, "task_completed").status == "not_enough_evidence"


@pytest.mark.parametrize("requested, effective", [(0, 0), (0.1, 0.1), (0.5, 0.2)])
def test_supported_drop_translation_is_unchanged(requested, effective):
    """Disclosing unsupported conditions must not change supported drop policy."""
    spec = adapt_upstream({"failures": {"message_drop": requested}})
    assert [(fault.action, fault.rate) for fault in spec.faults] == (
        [("drop_rate", effective)] if effective else []
    )
    assert not any("not modeled" in note for note in spec.adaptations)
    if requested > effective:
        assert any("0.5 capped at 0.2" in note for note in spec.adaptations)
