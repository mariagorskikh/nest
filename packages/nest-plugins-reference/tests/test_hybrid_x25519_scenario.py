# SPDX-License-Identifier: Apache-2.0
"""Full-simulator integration for the ``hybrid_x25519`` privacy layer.

Boots ``scenarios/sealed_bid_with_privacy.yaml`` through the real
:class:`~nest_core.runner.ScenarioRunner` to prove the plugin integrates into an
end-to-end run without breaking the simulator, and that the run stays
deterministic under replay (Tier-1). The sealed-bid *mechanics* are exercised
directly in ``test_hybrid_x25519.py::TestSealedBidWithPrivacy``; here we verify
the plugin is discoverable and simulator-safe.

Example::

    pytest packages/nest-plugins-reference/tests/test_hybrid_x25519_scenario.py
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_plugins_reference.privacy.hybrid_x25519 import HybridX25519Privacy

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "sealed_bid_with_privacy.yaml"


def test_privacy_layer_resolves_to_hybrid_plugin() -> None:
    """The registry discovers ``hybrid_x25519`` via the built-in map / entry point."""
    cls = PluginRegistry().resolve("privacy", "hybrid_x25519")
    assert cls is HybridX25519Privacy


@pytest.mark.parametrize("seed", [42, 7])
def test_scenario_boots_and_runs(seed: int) -> None:
    """The scenario wiring the hybrid privacy layer runs to completion."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    assert config.layers.privacy == "hybrid_x25519"
    config = config.model_copy(update={"seed": seed})
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"sealed_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        result = asyncio.run(runner.run())
        assert result.exists()
        assert result.stat().st_size > 0


def test_scenario_is_deterministic_under_replay() -> None:
    """Two seed-42 runs produce byte-identical traces (Tier-1 reproducibility)."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    def run_once() -> bytes:
        config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": 42})
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "sealed_replay.jsonl"
            config = config.model_copy(
                update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
            )
            runner = ScenarioRunner(config, registry=PluginRegistry())
            result = asyncio.run(runner.run())
            return result.read_bytes()

    assert run_once() == run_once()
