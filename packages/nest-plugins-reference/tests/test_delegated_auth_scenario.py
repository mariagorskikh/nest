# SPDX-License-Identifier: Apache-2.0
"""Full-simulator test for the delegated_auth scenario.

Runs the delegation-tree scenario under the charter's seed bank (42, 7, 1337),
asserts the delegation outcomes (honest leaves authorized, Byzantine leaves
rejected, cascading revocation), checks that a given seed replays to a
byte-identical trace, and confirms the delegation validators pass against the
scenario's live auth plugin.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_plugins_reference.validators.delegation_validators import run_all_delegation_checks

_SCENARIO = Path(__file__).resolve().parents[3] / "scenarios" / "delegated_auth.yaml"
_SEEDS = [42, 7, 1337]


def _run(seed: int, trace_path: Path) -> ScenarioRunner:
    config = ScenarioConfig.from_yaml(str(_SCENARIO))
    config = config.model_copy(update={"seed": seed})
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return runner


@pytest.mark.parametrize("seed", _SEEDS)
def test_delegation_outcomes(seed: int, tmp_path: Path) -> None:
    runner = _run(seed, tmp_path / f"trace-{seed}.jsonl")
    results = runner.resolved_plugins["_delegation_results"]

    honest = [f"leaf-{i}" for i in range(12) if i not in (5, 10)]
    assert sorted(results["authorized"]) == sorted(honest)
    assert results["blocked"] == {
        "leaf-5": "InvalidTokenError",
        "leaf-10": "AudienceMismatchError",
    }
    assert sorted(results["cascade_revoked"]) == ["leaf-0", "leaf-1", "leaf-2", "leaf-3"]


def test_trace_is_reproducible(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    _run(42, a)
    _run(42, b)
    assert a.read_bytes() == b.read_bytes()


def test_validators_pass_on_scenario_auth(tmp_path: Path) -> None:
    runner = _run(42, tmp_path / "trace.jsonl")
    auth = runner.resolved_plugins["_delegation_auth"]
    report = asyncio.run(run_all_delegation_checks(auth))
    assert report.passed
