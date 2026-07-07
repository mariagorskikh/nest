# SPDX-License-Identifier: Apache-2.0
"""Full-simulator test for the discovery_resolver scenario.

Runs the discovery scenario under the charter seed bank (42, 7, 1337): the eight
stable providers stay resolvable and the four crashed ones self-evict. Also checks
that a given seed replays to a byte-identical trace, and that the resolver validators
pass against the scenario's live registry.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_plugins_reference.validators.resolver_validators import run_all_resolver_checks

_SCENARIO = Path(__file__).resolve().parents[3] / "scenarios" / "discovery_resolver.yaml"
_SEEDS = [42, 7, 1337]
_EVICTED = ["provider-11", "provider-2", "provider-5", "provider-8"]
_RESOLVABLE = sorted(f"provider-{i}" for i in range(12) if i not in (2, 5, 8, 11))


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
def test_crashed_providers_self_evict(seed: int, tmp_path: Path) -> None:
    runner = _run(seed, tmp_path / f"trace-{seed}.jsonl")
    results = runner.resolved_plugins["_discovery_results"]
    assert results["resolvable"] == _RESOLVABLE
    assert results["evicted"] == _EVICTED


def test_trace_is_reproducible(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    _run(42, a)
    _run(42, b)
    assert a.read_bytes() == b.read_bytes()


def test_validators_pass_on_scenario_registry(tmp_path: Path) -> None:
    runner = _run(42, tmp_path / "trace.jsonl")
    registry = runner.resolved_plugins["_discovery_registry"]
    report = asyncio.run(run_all_resolver_checks(registry))
    assert report.passed
