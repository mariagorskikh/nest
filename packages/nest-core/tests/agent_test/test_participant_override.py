# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the generic participant-replacement runner seam."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.scenarios import register_scenario
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.simulator import Simulator
from nest_core.sim.trace import TraceWriter
from nest_core.types import AgentId


class _ReplacementAgent(StateMachineAgent):
    def __init__(self, *, fail_on_message: bool = False) -> None:
        self.started_as: AgentId | None = None
        self.plugin_marker: object | None = None
        self.messages: list[bytes] = []
        self._fail_on_message = fail_on_message

    async def on_start(self, ctx: AgentContext) -> None:
        self.started_as = ctx.agent_id
        self.plugin_marker = ctx.plugins["marker"]

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self.messages.append(payload)
        if self._fail_on_message:
            raise RuntimeError("replacement failed")


class _ReferenceProvider(StateMachineAgent):
    def __init__(self) -> None:
        self.message_calls = 0

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self.message_calls += 1
        await ctx.send(sender, b"reference-fallback")


class _Requester(StateMachineAgent):
    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.send(AgentId("provider-0"), b"request")


def _config(tmp_path: Path, task_type: str) -> ScenarioConfig:
    return ScenarioConfig.from_dict(
        {
            "name": task_type,
            "task": {"type": task_type},
            "duration": "ticks: 10",
            "output": {"trace": str(tmp_path / f"{task_type}.jsonl")},
        }
    )


@pytest.mark.asyncio
async def test_override_replaces_exact_participant_and_preserves_its_plugins(
    tmp_path: Path,
) -> None:
    marker = object()
    original = _ReferenceProvider()

    def factory(
        config: ScenarioConfig, plugins: dict[str, Any]
    ) -> dict[AgentId, StateMachineAgent]:
        plugins["_agent_plugins"] = {AgentId("provider-0"): {"marker": marker}}
        return {
            AgentId("requester-0"): _Requester(),
            AgentId("provider-0"): original,
        }

    register_scenario("participant_override_exact", factory)
    replacement = _ReplacementAgent()

    await ScenarioRunner(
        _config(tmp_path, "participant_override_exact"),
        participant_override={AgentId("provider-0"): replacement},
    ).run()

    assert replacement.started_as == AgentId("provider-0")
    assert replacement.plugin_marker is marker
    assert replacement.messages == [b"request"]
    assert original.message_calls == 0


@pytest.mark.asyncio
async def test_override_accepts_multiple_existing_targets_without_event_sink(
    tmp_path: Path,
) -> None:
    requester = _ReplacementAgent()
    provider = _ReplacementAgent()

    def factory(
        config: ScenarioConfig, plugins: dict[str, Any]
    ) -> dict[AgentId, StateMachineAgent]:
        marker = object()
        plugins["_agent_plugins"] = {
            AgentId("requester-0"): {"marker": marker},
            AgentId("provider-0"): {"marker": marker},
        }
        return {
            AgentId("requester-0"): _Requester(),
            AgentId("provider-0"): _ReferenceProvider(),
        }

    register_scenario("participant_override_multiple", factory)

    await ScenarioRunner(
        _config(tmp_path, "participant_override_multiple"),
        participant_override={
            AgentId("requester-0"): requester,
            AgentId("provider-0"): provider,
        },
    ).run()

    assert requester.started_as == AgentId("requester-0")
    assert provider.started_as == AgentId("provider-0")


@pytest.mark.asyncio
async def test_override_rejects_only_absent_targets(tmp_path: Path) -> None:
    def factory(
        config: ScenarioConfig, plugins: dict[str, Any]
    ) -> dict[AgentId, StateMachineAgent]:
        return {AgentId("provider-0"): _ReferenceProvider()}

    register_scenario("participant_override_absent", factory)

    with pytest.raises(KeyError, match="absent-0"):
        await ScenarioRunner(
            _config(tmp_path, "participant_override_absent"),
            participant_override={AgentId("absent-0"): _ReferenceProvider()},
        ).run()


@pytest.mark.asyncio
async def test_generic_runner_allows_requester_replacement(tmp_path: Path) -> None:
    replacement = _ReplacementAgent()

    def factory(
        config: ScenarioConfig, plugins: dict[str, Any]
    ) -> dict[AgentId, StateMachineAgent]:
        plugins["_agent_plugins"] = {AgentId("requester-0"): {"marker": object()}}
        return {
            AgentId("requester-0"): _Requester(),
            AgentId("provider-0"): _ReferenceProvider(),
        }

    register_scenario("participant_override_requester", factory)

    await ScenarioRunner(
        _config(tmp_path, "participant_override_requester"),
        participant_override={AgentId("requester-0"): replacement},
    ).run()

    assert replacement.started_as == AgentId("requester-0")


@pytest.mark.asyncio
async def test_failed_replacement_never_falls_back_to_reference_provider(tmp_path: Path) -> None:
    original = _ReferenceProvider()

    def factory(
        config: ScenarioConfig, plugins: dict[str, Any]
    ) -> dict[AgentId, StateMachineAgent]:
        plugins["_agent_plugins"] = {AgentId("provider-0"): {"marker": object()}}
        return {
            AgentId("requester-0"): _Requester(),
            AgentId("provider-0"): original,
        }

    register_scenario("participant_override_failure", factory)
    config = _config(tmp_path, "participant_override_failure")

    with pytest.raises(RuntimeError, match="replacement failed"):
        await ScenarioRunner(
            config,
            participant_override={AgentId("provider-0"): _ReplacementAgent(fail_on_message=True)},
        ).run()

    assert original.message_calls == 0
    records = [json.loads(line) for line in Path(config.output.trace).read_text().splitlines()]
    assert all(record.get("msg") != "reference-fallback" for record in records)


@pytest.mark.asyncio
async def test_ordinary_calls_are_identical_when_optional_seams_are_absent(tmp_path: Path) -> None:
    def factory(
        config: ScenarioConfig, plugins: dict[str, Any]
    ) -> dict[AgentId, StateMachineAgent]:
        return {
            AgentId("requester-0"): _Requester(),
            AgentId("provider-0"): _ReferenceProvider(),
        }

    register_scenario("ordinary_runner_compatibility", factory)
    first = _config(tmp_path, "ordinary_runner_compatibility")
    first.output.trace = str(tmp_path / "first.jsonl")
    second = _config(tmp_path, "ordinary_runner_compatibility")
    second.output.trace = str(tmp_path / "second.jsonl")

    await ScenarioRunner(first).run()
    await ScenarioRunner(second, participant_override=None).run()

    assert Path(first.output.trace).read_bytes() == Path(second.output.trace).read_bytes()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ["add_agent", "set_agent_plugins"])
async def test_runner_closes_trace_when_agent_setup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    primary = RuntimeError(f"{failure_stage} failed")
    close_calls = 0
    original_close = TraceWriter.close

    def factory(
        config: ScenarioConfig, plugins: dict[str, Any]
    ) -> dict[AgentId, StateMachineAgent]:
        plugins["_agent_plugins"] = {AgentId("provider-0"): {"marker": object()}}
        return {AgentId("provider-0"): _ReferenceProvider()}

    def fail_add_agent(simulator: Simulator, agent_id: AgentId, agent: StateMachineAgent) -> None:
        raise primary

    def fail_set_agent_plugins(
        simulator: Simulator, agent_id: AgentId, overrides: dict[str, Any]
    ) -> None:
        raise primary

    def record_close(writer: TraceWriter) -> None:
        nonlocal close_calls
        close_calls += 1
        original_close(writer)

    register_scenario("participant_setup_failure", factory)
    if failure_stage == "add_agent":
        monkeypatch.setattr(Simulator, "add_agent", fail_add_agent)
    else:
        monkeypatch.setattr(Simulator, "set_agent_plugins", fail_set_agent_plugins)
    monkeypatch.setattr(TraceWriter, "close", record_close)
    runner = ScenarioRunner(_config(tmp_path, "participant_setup_failure"))

    with pytest.raises(RuntimeError) as caught:
        await runner.run()

    assert caught.value is primary
    assert close_calls == 1
    assert runner.trace_finalized is True
