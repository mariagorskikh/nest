# SPDX-License-Identifier: Apache-2.0
"""Behavior tests for the deterministic capability-fulfillment baseline."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from nest_core.agent_test.models import (
    LookupReturnedObservation,
    ProviderSelectedObservation,
    TestObservation,
)
from nest_core.agent_test.profiles import capability_profile_document, resolve_test_profile
from nest_core.builtin_scenarios import builtin_path
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import ScenarioEventRequest, StateMachineAgent
from nest_core.types import AgentId
from nest_plugins_reference.registry.in_memory import InMemoryRegistry
from pydantic import ValidationError

RUN_ID = "01K00000000000000000000001"
EVENT_IDS = [f"01K0000000000000000000000{value}" for value in range(2, 9)]


def _runtime(event_ids: Iterator[str] | None = None) -> Any:
    from nest_core.agent_test.runtime import AgentTestRuntime

    return AgentTestRuntime(
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        event_id_factory=(lambda: next(event_ids)) if event_ids is not None else None,
        observed_at=lambda: datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
    )


def _config(tmp_path: Path) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(builtin_path("capability_fulfillment"))
    config.output.trace = str(tmp_path / "capability.jsonl")
    return config


def test_factory_has_exact_participants_and_pinned_registry(tmp_path: Path) -> None:
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
async def test_scenario_discovers_then_routes_exact_fixture_with_typed_observations(
    tmp_path: Path,
) -> None:
    runtime = _runtime(iter(EVENT_IDS))
    config = _config(tmp_path)
    runner = ScenarioRunner(config, event_sink=runtime)

    await runner.run()

    assert type(runner.resolved_plugins["registry"]) is InMemoryRegistry
    records = [json.loads(line) for line in Path(config.output.trace).read_text().splitlines()]
    ordinary = [record for record in records if not record["kind"].startswith("test.")]
    assert [(r["agent"], r["kind"]) for r in ordinary[:2]] == [
        ("requester-0", "start"),
        ("provider-0", "start"),
    ]
    assert [r["msg"] for r in ordinary if r["kind"] == "send"] == [
        "buy:widget:2",
        "sold:widget:2",
    ]

    observations = [
        TestObservation.model_validate(record)
        for record in records
        if record["kind"].startswith("test.")
    ]
    assert [observation.root.seq for observation in observations] == list(range(1, 8))
    assert [observation.root.event_id for observation in observations] == EVENT_IDS
    assert [observation.root.run_id for observation in observations] == [RUN_ID] * 7
    assert [observation.root.kind for observation in observations] == [
        "test.registry.provider_registered",
        "test.registry.lookup_requested",
        "test.registry.lookup_returned",
        "test.requester.provider_selected",
        "test.message.request_routed",
        "test.message.response_routed",
        "test.capability.result_evaluated",
    ]
    lookup_returned = observations[2].root
    provider_selected = observations[3].root
    assert isinstance(lookup_returned, LookupReturnedObservation)
    assert isinstance(provider_selected, ProviderSelectedObservation)
    assert lookup_returned.data.card_agent_ids == ["provider-0"]
    assert provider_selected.data.lookup_event_id == EVENT_IDS[2]


@pytest.mark.asyncio
async def test_direct_address_without_successful_lookup_emits_no_discovery_evidence(
    tmp_path: Path,
) -> None:
    class _UnregisteredProvider(StateMachineAgent):
        async def on_message(self, ctx: object, sender: AgentId, payload: bytes) -> None:
            raise AssertionError("requester bypassed registry lookup")

    runtime = _runtime(iter(EVENT_IDS))
    config = _config(tmp_path)
    await ScenarioRunner(
        config,
        participant_override={AgentId("provider-0"): _UnregisteredProvider()},
        event_sink=runtime,
    ).run()

    records = [json.loads(line) for line in Path(config.output.trace).read_text().splitlines()]
    observations = [record for record in records if record["kind"].startswith("test.")]
    assert [record["kind"] for record in observations] == [
        "test.registry.lookup_requested",
        "test.registry.lookup_returned",
    ]
    assert observations[-1]["data"]["card_agent_ids"] == []
    assert not any(record.get("msg") == "buy:widget:2" for record in records)


def test_runtime_rejects_observations_outside_closed_model() -> None:
    runtime = _runtime(iter(EVENT_IDS))

    with pytest.raises(ValidationError):
        runtime.record(
            ScenarioEventRequest(
                kind="test.registry.lookup_requested",
                logical_time=0,
                observer="town.capability-requester",
                subject="provider-0",
                data={
                    "registry_implementation": (
                        "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
                    ),
                    "capabilities": ["sell"],
                    "unexpected": True,
                },
            )
        )


def test_capability_runtime_subject_is_profile_provider() -> None:
    runtime = _runtime(iter(EVENT_IDS))
    resolved = resolve_test_profile("capability-fulfillment")

    assert runtime.subject_participant_id == "provider-0"
    assert runtime.profile == resolved.reference


def test_runtime_rederives_subject_from_canonical_packaged_resource() -> None:
    from nest_core.agent_test.runtime import AgentTestRuntime

    resolved = resolve_test_profile("capability-fulfillment")
    returned_document = capability_profile_document(resolved)
    cast("Any", returned_document.scenario).subject_participant_id = "requester-0"

    runtime = AgentTestRuntime(run_id=RUN_ID, resolved_profile=resolved)

    assert runtime.subject_participant_id == "provider-0"
