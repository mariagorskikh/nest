# SPDX-License-Identifier: Apache-2.0
"""Standalone smoke tests for the deterministic capability workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from nest_core.builtin_scenarios import builtin_path
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import StateMachineAgent
from nest_core.types import AgentId
from nest_plugins_reference.registry.in_memory import InMemoryRegistry


def _config(tmp_path: Path) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(builtin_path("capability_fulfillment"))
    config.output.trace = str(tmp_path / "capability.jsonl")
    return config


def test_factory_has_exact_participants_and_run_local_registry(tmp_path: Path) -> None:
    from nest_core.scenarios_builtin.capability_fulfillment import (
        capability_fulfillment_factory,
    )

    config = _config(tmp_path)
    plugins: dict[str, object] = {"registry": InMemoryRegistry}

    agents = capability_fulfillment_factory(config, plugins)

    assert list(agents) == [AgentId("requester-0"), AgentId("provider-0")]
    assert all(isinstance(agent, StateMachineAgent) for agent in agents.values())
    assert type(plugins["registry"]) is InMemoryRegistry


def test_capability_evaluator_emits_generation_one_revision() -> None:
    from nest_core.scenarios_builtin.capability_fulfillment import CapabilityRequesterAgent

    class RecordingContext:
        def __init__(self) -> None:
            self.events: list[dict[str, object]] = []

        def record_scenario_event(self, **event: object) -> None:
            self.events.append(event)

    context = RecordingContext()
    response_digest = "sha256:4929db8434bf7537e497ad88677dcdaf1e8509b6fbf74b69d7a8bb54805cee2a"

    CapabilityRequesterAgent()._evaluate_response(context, b"sold:widget:2")  # type: ignore[arg-type]

    assert context.events[0]["data"] == {
        "evaluator_id": "nanda.agent.capability-fulfillment",
        "evaluator_version": "1",
        "verdict": "pass",
        "expected_response_digest": response_digest,
        "actual_response_digest": response_digest,
    }


@pytest.mark.asyncio
async def test_ordinary_scenario_discovers_and_routes_exact_fixture(tmp_path: Path) -> None:
    config = _config(tmp_path)
    runner = ScenarioRunner(config)

    await runner.run()

    assert type(runner.resolved_plugins["registry"]) is InMemoryRegistry
    records = [json.loads(line) for line in Path(config.output.trace).read_text().splitlines()]
    assert [record["msg"] for record in records if record["kind"] == "send"] == [
        "buy:widget:2",
        "sold:widget:2",
    ]
    assert not any(record["kind"].startswith("test.") for record in records)
