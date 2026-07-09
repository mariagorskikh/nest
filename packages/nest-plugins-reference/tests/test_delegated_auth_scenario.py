# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the delegatable auth plugin.

Boots the ``delegated_auth`` scenario through the real ``Simulator`` twice --
once with ``auth: delegatable`` and once with ``auth: jwt`` -- and proves the
three validators discriminate: ALL PASS under the delegatable plugin, ALL FAIL
under the default plugin (which has no delegate surface).

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

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "delegated_auth.yaml"


def _swap_auth(config: ScenarioConfig, plugin_name: str) -> ScenarioConfig:
    new_layers = config.layers.model_copy(update={"auth": plugin_name})
    return config.model_copy(update={"layers": new_layers})


def _run(plugin_name: str, seed: int = 42) -> Path:
    """Run the scenario with the chosen auth plugin; return the trace path."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_auth(config, plugin_name)
    config = config.model_copy(update={"seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / f"delegated_auth_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_delegatable_passes_all_three_validators() -> None:
    """The delegatable plugin satisfies attenuation, cascading revocation, audience binding."""
    results = validate_trace(_run("delegatable"), "delegated_auth")
    summary = [f"{'PASS' if r.passed else 'FAIL'} {r.name}: {r.detail}" for r in results]
    assert results and all(r.passed for r in results), (
        "expected all validators to pass under delegatable:\n" + "\n".join(summary)
    )


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_jwt_fails_all_three_validators() -> None:
    """The default ``jwt`` plugin has no delegate surface, so the tree never forms."""
    results = validate_trace(_run("jwt"), "delegated_auth")
    assert results and not any(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if r.passed
    ]


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_scenario_deterministic_under_replay() -> None:
    """Two runs with the same seed produce byte-identical traces."""
    assert _run("delegatable", seed=42).read_bytes() == _run("delegatable", seed=42).read_bytes()


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_validator_discrimination_holds_across_seeds(seed: int) -> None:
    """Validator discrimination is seed-independent (message ordering aside)."""
    results = validate_trace(_run("delegatable", seed=seed), "delegated_auth")
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_scenario_exercises_every_attack_class() -> None:
    """The trace must contain each denied-attack class plus a cascading revoke."""
    trace = _run("delegatable")
    text = trace.read_text()
    for marker in (
        "attack=scope_escalation",
        "attack=audience_confusion",
        "attack=revoked_parent",
        "attack=expired_parent",
        "authz:revoked",
    ):
        assert marker in text, f"missing {marker!r} in trace"
