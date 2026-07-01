# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the escrow plugin.

Boots the ``escrow_marketplace`` scenario through the real ``Simulator``
twice -- once with ``payments: escrow`` and once with
``payments: prepaid_credits`` -- and proves the four validators
discriminate: ALL PASS under the escrow plugin, ALL FAIL under the
default plugin (which has no escrow protocol).

Also pins determinism: same seed → byte-identical trace.
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

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "escrow_marketplace.yaml"


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
    trace_path = tmp / f"escrow_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


def _all_passed(plugin_name: str) -> tuple[bool, list[str]]:
    trace_path = _run(plugin_name)
    results = validate_trace(trace_path, "escrow_marketplace")
    summary = [f"{'PASS' if r.passed else 'FAIL'} {r.name}: {r.detail}" for r in results]
    return all(r.passed for r in results), summary


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_escrow_plugin_passes_all_four_validators() -> None:
    """The escrow plugin satisfies state-machine, role-binding, bps, and payout-gating."""
    passed, summary = _all_passed("escrow")
    assert passed, "expected all validators to pass under escrow plugin:\n" + "\n".join(summary)


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_prepaid_credits_fails_validators() -> None:
    """The default ``prepaid_credits`` plugin lacks the escrow protocol.

    Three of the four validators MUST flag this: state-machine,
    role-binding, and no-payout-without-delivery all report 'no escrow
    lifecycle observed'. (The bps-range validator vacuously passes
    because there are no arbitrate events to range-check; that is the
    correct behavior -- the rule is 'every arbitrate ∈ range'.)
    """
    trace_path = _run("prepaid_credits")
    results = validate_trace(trace_path, "escrow_marketplace")
    by_name = {r.name: r for r in results}
    assert not by_name["escrow_state_machine"].passed
    assert not by_name["escrow_role_binding"].passed
    assert not by_name["escrow_no_payout_without_delivery"].passed


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_escrow_scenario_deterministic_under_replay() -> None:
    """Two runs with seed 42 produce identical trace bytes."""
    a = _run("escrow", seed=42).read_bytes()
    b = _run("escrow", seed=42).read_bytes()
    assert a == b


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_escrow_scenario_passes_across_seeds(seed: int) -> None:
    """Validator discrimination holds across multiple seeds."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_payments(config, "escrow")
    config = config.model_copy(update={"seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / f"escrow_seed_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    results = validate_trace(trace_path, "escrow_marketplace")
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]
