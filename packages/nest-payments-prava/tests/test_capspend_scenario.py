# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the Prava payments adapter.

Boots the ``capspend_marketplace.yaml`` scenario through ``ScenarioRunner``
with ``layers.payments: prava_adapter`` to confirm that:
1. The plugin resolves properly via PluginRegistry.
2. The scenario executes cleanly and produces a valid trace file.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

SCENARIO_PATH = (
    Path(__file__).resolve().parents[1] / "scenarios" / "capspend_marketplace.yaml"
)


@pytest.mark.asyncio
async def test_capspend_marketplace_scenario_executes() -> None:
    """Scenario executes with prava_adapter payment layer."""
    assert SCENARIO_PATH.exists(), f"Scenario YAML not found at {SCENARIO_PATH}"

    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / "capspend_trace.jsonl"

    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )

    registry = PluginRegistry()
    runner = ScenarioRunner(config, registry=registry)
    result_path = await runner.run()

    assert Path(result_path).exists()
