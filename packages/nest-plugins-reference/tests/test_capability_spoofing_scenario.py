# SPDX-License-Identifier: Apache-2.0
"""End-to-end FAIL/PASS gate: capability_spoofing scenario vs the reference registry.

Runs the same ``scenarios/capability_spoofing.yaml`` under
``registry: in_memory`` and ``registry: verified_capabilities`` -- same
seed, only ``layers.registry`` differs -- and proves
``check_capability_conformance`` FAILs against ``in_memory`` (spoofers stay
discoverable forever; ``in_memory`` has no concept of a defection) and
PASSes against ``verified_capabilities`` (every spoofer excluded, every
honest seller still discoverable), deterministically across seeds 42, 7,
1337.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId
from nest_plugins_reference.validators.capability_validators import (
    check_capability_conformance,
)

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "capability_spoofing.yaml"

_SEEDS = [42, 7, 1337]

_SPOOFER_IDS = {AgentId("spoofer-0"), AgentId("spoofer-1"), AgentId("baitswitch-0")}
_HONEST_IDS = {AgentId("honest-0"), AgentId("honest-1"), AgentId("honest-2")}


def _run(registry_plugin: str, seed: int, trace_path: Path) -> dict[str, object]:
    """Run the scenario under *registry_plugin* at *seed*; return resolved plugins.

    Example::

        plugins = _run("in_memory", 42, trace_path)
    """
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = config.model_copy(
        update={
            "seed": seed,
            "layers": config.layers.model_copy(update={"registry": registry_plugin}),
            "output": config.output.model_copy(update={"trace": str(trace_path)}),
        }
    )
    runner = ScenarioRunner(config)
    asyncio.run(runner.run())
    return runner.resolved_plugins


def _run_bytes(registry_plugin: str, seed: int, trace_path: Path) -> bytes:
    """Run the scenario and return the raw trace bytes.

    Example::

        data = _run_bytes("verified_capabilities", 42, trace_path)
    """
    _run(registry_plugin, seed, trace_path)
    return trace_path.read_bytes()


@pytest.mark.parametrize("seed", _SEEDS)
def test_in_memory_registry_fails_conformance(seed: int) -> None:
    """The reference in_memory registry has no defection concept -- spoofers stay visible."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"in_memory_{seed}.jsonl"
        plugins = _run("in_memory", seed, trace_path)
        report = asyncio.run(
            check_capability_conformance(
                plugins["registry"], spoofer_ids=_SPOOFER_IDS, honest_ids=_HONEST_IDS
            )
        )
    assert not report.passed, (
        f"expected in_memory to fail conformance (spoofers should still be "
        f"discoverable); got passed=True: {report.detail}"
    )


@pytest.mark.parametrize("seed", _SEEDS)
def test_verified_capabilities_passes_conformance(seed: int) -> None:
    """verified_capabilities excludes every spoofer while keeping honest sellers discoverable."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"verified_{seed}.jsonl"
        plugins = _run("verified_capabilities", seed, trace_path)
        report = asyncio.run(
            check_capability_conformance(
                plugins["registry"], spoofer_ids=_SPOOFER_IDS, honest_ids=_HONEST_IDS
            )
        )
    assert report.passed, report.detail


def test_scenario_is_byte_for_byte_deterministic() -> None:
    """Two runs at the same seed under verified_capabilities yield identical trace bytes."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    with tempfile.TemporaryDirectory() as tmp:
        trace_a = Path(tmp) / "a.jsonl"
        trace_b = Path(tmp) / "b.jsonl"
        first = _run_bytes("verified_capabilities", 42, trace_a)
        second = _run_bytes("verified_capabilities", 42, trace_b)
    assert first == second
