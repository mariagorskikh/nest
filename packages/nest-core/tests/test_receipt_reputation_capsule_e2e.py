# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the ``receipt_reputation_capsule`` scenario pipeline.

These run the real scenario (runner → auditor → trace → validators) with the
``capsule_emit`` trust plugin and grade it exactly as the rig does — through
the validator registry, i.e. against the PINNED production service identity.
The committed Azure Confidential Ledger write-receipt fixtures are replayed
onto the trace and verified offline; the graded path performs no network,
filesystem, environment, or clock access in the verdict.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

_SCENARIO_YAML = (
    Path(__file__).parent.parent.parent.parent / "scenarios" / "receipt_reputation_capsule.yaml"
)


def _config(trace: Path, seed: int | None = None) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
    config.output.trace = str(trace)
    if seed is not None:
        config.seed = seed
    return config


@pytest.mark.asyncio
async def test_capsule_scenario_passes_through_registry_with_committed_fixtures(
    tmp_path: Path,
) -> None:
    """Honest run + committed ledger fixtures -> all three validators PASS.

    This is the graded path end to end: the plugin loads the committed write
    receipts, the auditor broadcasts them, and the registry validator verifies
    each offline against the pinned production service identity.
    """
    trace = tmp_path / "capsule.jsonl"
    await ScenarioRunner(_config(trace)).run()

    results = {r.name: r for r in validate_trace(trace, "receipt_reputation_capsule")}
    assert results["receipt_reputation_ring_severed"].passed
    assert results["receipt_reputation_honest_confidence"].passed
    anchored = results["receipt_reputation_anchored"]
    assert anchored.passed, f"anchored must PASS with committed fixtures: {anchored.detail}"
    assert "verified" in anchored.detail and "offline" in anchored.detail

    # The trace carries both the seal trip-wire and the ledger evidence.
    msgs = [json.loads(line).get("msg", "") for line in trace.read_text().splitlines()]
    assert any(str(m).startswith("seal:") for m in msgs)
    assert any(str(m).startswith("ccfreceipt:") for m in msgs)


@pytest.mark.asyncio
async def test_non_anchoring_baseline_fails_through_registry(tmp_path: Path) -> None:
    """The same scenario under ``agent_receipts`` FAILS the anchored check.

    The discrimination the gate exists for: a trust layer that anchors nothing
    emits no ledger evidence and cannot pass, fixtures or not.
    """
    trace = tmp_path / "baseline.jsonl"
    config = _config(trace)
    config.layers.trust = "agent_receipts"
    await ScenarioRunner(config).run()

    results = {r.name: r for r in validate_trace(trace, "receipt_reputation_capsule")}
    anchored = results["receipt_reputation_anchored"]
    assert not anchored.passed
    assert "does not anchor" in anchored.detail


@pytest.mark.asyncio
async def test_capsule_scenario_trace_is_deterministic(tmp_path: Path) -> None:
    """Same seed -> byte-identical trace (the pre-anchored fixtures rely on this)."""
    t1, t2 = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    await ScenarioRunner(_config(t1, seed=42)).run()
    await ScenarioRunner(_config(t2, seed=42)).run()
    d1 = hashlib.sha256(t1.read_bytes()).hexdigest()
    d2 = hashlib.sha256(t2.read_bytes()).hexdigest()
    assert d1 == d2
