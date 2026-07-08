# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the budget_enforcement scenario.

Boots the ``budget_enforcement`` scenario through the real ``Simulator`` twice
-- once with ``payments: budget_limited`` and once with
``payments: prepaid_credits`` -- and proves the two validators discriminate:
BOTH PASS under the budget plugin (the over-cap attempt is refused), BOTH FAIL
under the default plugin (which has no budget, so the overspend goes through).

Also pins determinism: same seed -> byte-identical trace.
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

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "budget_enforcement.yaml"


def _swap_payments(config: ScenarioConfig, plugin_name: str) -> ScenarioConfig:
    """Return ``config`` with the payments layer pointing at ``plugin_name``."""
    new_layers = config.layers.model_copy(update={"payments": plugin_name})
    return config.model_copy(update={"layers": new_layers})


def _run(plugin_name: str, seed: int = 42) -> Path:
    """Run the scenario with the chosen payments plugin; return the trace path."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_payments(config, plugin_name)
    config = config.model_copy(update={"seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / f"budget_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_budget_plugin_passes_both_validators() -> None:
    """The budget plugin keeps spend within cap and refuses the over-cap attempt."""
    trace_path = _run("budget_limited")
    results = validate_trace(trace_path, "budget_enforcement")
    summary = [f"{'PASS' if r.passed else 'FAIL'} {r.name}: {r.detail}" for r in results]
    assert all(r.passed for r in results), (
        "expected all validators to pass under budget_limited:\n" + "\n".join(summary)
    )


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_prepaid_credits_fails_both_validators() -> None:
    """The default ``prepaid_credits`` plugin has no budget, so the overspend lands.

    Every attempt succeeds (balance is ample), so cumulative spend exceeds the
    cap and no refusal is ever emitted -- both budget validators must flag it.
    """
    trace_path = _run("prepaid_credits")
    results = validate_trace(trace_path, "budget_enforcement")
    by_name = {r.name: r for r in results}
    assert not by_name["budget_never_exceeds_cap"].passed
    assert not by_name["budget_refuses_overspend"].passed


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_budget_scenario_deterministic_under_replay() -> None:
    """Two runs with seed 42 produce identical trace bytes."""
    a = _run("budget_limited", seed=42).read_bytes()
    b = _run("budget_limited", seed=42).read_bytes()
    assert a == b


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_budget_scenario_passes_across_seeds(seed: int) -> None:
    """Validator discrimination holds across multiple seeds."""
    trace_path = _run("budget_limited", seed=seed)
    results = validate_trace(trace_path, "budget_enforcement")
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]
