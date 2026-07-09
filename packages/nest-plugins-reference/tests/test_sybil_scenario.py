# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the Sybil-resistant trust plugin.

Runs the ``sybil_reputation`` scenario:
- With ``trust: sybil_resistant``: all validators PASS.
- With ``trust: score_average``: flood and collusion validators FAIL.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "sybil_reputation.yaml"


def _swap_trust(config: ScenarioConfig, plugin_name: str) -> ScenarioConfig:
    """Return ``config`` with the trust layer pointing at ``plugin_name``."""
    new_layers = config.layers.model_copy(update={"trust": plugin_name})
    return config.model_copy(update={"layers": new_layers})


def _run(plugin_name: str, seed: int = 42) -> Path:
    """Run the scenario with the chosen trust plugin; return the trace path."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_trust(config, plugin_name)
    config = config.model_copy(update={"seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / f"sybil_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_sybil_plugin_passes_validators() -> None:
    """The sybil_resistant plugin satisfies flood and collusion validators."""
    trace_path = _run("sybil_resistant")
    results = validate_trace(trace_path, "sybil_reputation")
    for r in results:
        assert r.passed, f"expected {r.name} to pass under sybil_resistant, but failed: {r.detail}"


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_score_average_fails_validators() -> None:
    """The naive ``score_average`` plugin fails under coordinated Sybil attacks."""
    trace_path = _run("score_average")
    results = validate_trace(trace_path, "sybil_reputation")
    by_name = {r.name: r for r in results}

    # Under score_average, cheaters are never refused (no refusals)
    # and they cheat many times because honest traders keep trading with them.
    assert not by_name["sybil_flood_resistance"].passed, (
        "expected flood validator to fail under score_average"
    )
    assert not by_name["sybil_collusion_ring"].passed, (
        "expected collusion validator to fail under score_average"
    )


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_sybil_scenario_deterministic_under_replay() -> None:
    """Replays are byte-identical."""
    a = _run("sybil_resistant", seed=42).read_bytes()
    b = _run("sybil_resistant", seed=42).read_bytes()
    assert a == b
