# SPDX-License-Identifier: Apache-2.0
"""Outer orchestration tests over the real ScenarioRunner/Registry/simulator path."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
from collections.abc import Callable
from pathlib import Path

import nest_core.agent_test.runner as agent_test_runner_module
import pytest
from nest_core.agent_test.artifacts import ArtifactDirectory, ArtifactStaging
from nest_core.agent_test.driver import (
    DriverCompatibilityError,
    DriverConfigurationError,
    DriverIncompleteError,
    TownDriverError,
)
from nest_core.agent_test.models import (
    ULID,
    DeclareCapabilityIntent,
    DriverReadiness,
    DriverReady,
    DriverRequest,
    DriverResponse,
    EffectiveDriverLimits,
    NoneIntent,
    ReadyLimits,
    ResultDriver,
    SendToSenderIntent,
    StopDriverObservation,
    TestResult,
)
from nest_core.agent_test.profile_codecs import BoundProfileCodec
from nest_core.agent_test.profiles import ResolvedTestProfile, resolve_test_profile
from nest_core.agent_test.runner import (
    AgentTestPreAdmissionError,
    AgentTestTownError,
    run_agent_test,
)
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import OutputConfig, ScenarioConfig
from nest_core.sim.simulator import Simulator
from nest_core.sim.trace import TraceWriter

RUN_ID = "01K00000000000000000000001"
type DriverIntent = DeclareCapabilityIntent | SendToSenderIntent | NoneIntent
_FROZEN_LAYER_NAMES = {
    "transport": "in_memory",
    "comms": "nest_native",
    "identity": "did_key",
    "registry": "in_memory",
    "auth": "jwt",
    "trust": "score_average",
    "payments": "prepaid_credits",
    "coordination": "contract_net",
    "negotiation": "alternating_offers",
    "memory": "blackboard",
    "privacy": "noop",
    "datafacts": "datafacts_v1",
}


class _CollidingRegistry:
    pass


class _RegistryEntryPoint:
    name = "in_memory"

    def load(self) -> type[_CollidingRegistry]:
        return _CollidingRegistry


class _ForeignPlugin:
    pass


class _ForeignEntryPoint:
    def __init__(self, *, layer: str, name: str, loads: list[tuple[str, str]]) -> None:
        self.name = name
        self._layer = layer
        self._loads = loads

    def load(self) -> type[_ForeignPlugin]:
        self._loads.append((self._layer, self.name))
        return _ForeignPlugin


def _digest_request(request: DriverRequest) -> str:
    return "sha256:" + hashlib.sha256(request.model_dump_json().encode()).hexdigest()


def _readiness() -> DriverReadiness:
    return DriverReadiness(
        ready=DriverReady(
            schema_version="town-agent-driver-ready/1",
            adapter_instance_id="adapter:dev",
            contracts=["town-agent-driver/1"],
            profiles=[resolve_test_profile("capability-fulfillment").reference],
            accepting_runs=True,
            limits=ReadyLimits(
                max_active_runs=1,
                max_request_bytes=65536,
                max_response_bytes=65536,
            ),
        ),
        effective_limits=EffectiveDriverLimits(
            max_request_bytes=65536,
            max_response_bytes=65536,
        ),
    )


class _Driver:
    def __init__(self, intent_for: Callable[[DriverRequest], DriverIntent]) -> None:
        self.intent_for = intent_for
        self.requests: list[DriverRequest] = []
        self.lifecycle: list[str] = []
        self.ready_calls = 0
        self.close_calls = 0

    async def ready(self, profile: ResolvedTestProfile) -> DriverReadiness:
        self.ready_calls += 1
        self.lifecycle.append("ready")
        return _readiness()

    async def decide(self, request: DriverRequest) -> DriverResponse:
        self.requests.append(request)
        self.lifecycle.append(request.observation.kind)
        return DriverResponse(
            schema_version="town-agent-driver/1",
            run_id=request.run_id,
            event_id=request.event_id,
            sequence=request.sequence,
            adapter_instance_id="adapter:dev",
            request_digest=_digest_request(request),
            intent=self.intent_for(request),
        )

    async def close(self) -> None:
        self.close_calls += 1
        self.lifecycle.append("close")


class _FailingDriver(_Driver):
    def __init__(self, failure: BaseException) -> None:
        super().__init__(
            lambda request: (
                DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
                if request.observation.kind == "start"
                else NoneIntent(kind="none")
            )
        )
        self.failure = failure

    async def decide(self, request: DriverRequest) -> DriverResponse:
        if request.observation.kind == "message":
            self.requests.append(request)
            self.lifecycle.append(request.observation.kind)
            raise self.failure
        return await super().decide(request)


class _CleanupFailingDriver(_Driver):
    async def decide(self, request: DriverRequest) -> DriverResponse:
        if request.observation.kind == "stop":
            self.requests.append(request)
            self.lifecycle.append(request.observation.kind)
            raise RuntimeError("Bearer secret-cleanup-canary")
        return await super().decide(request)

    async def close(self) -> None:
        self.close_calls += 1
        self.lifecycle.append("close")
        raise RuntimeError("Bearer secret-close-canary")


class _StartContractFailingDriver(_Driver):
    async def decide(self, request: DriverRequest) -> DriverResponse:
        response = await super().decide(request)
        return response.model_copy(update={"sequence": request.sequence + 1})


class _StartPreAdmissionFailingDriver(_Driver):
    def __init__(self, failure: DriverConfigurationError | DriverCompatibilityError) -> None:
        super().__init__(lambda request: NoneIntent(kind="none"))
        self.failure = failure

    async def decide(self, request: DriverRequest) -> DriverResponse:
        self.requests.append(request)
        self.lifecycle.append(request.observation.kind)
        raise self.failure


class _StartAttemptFailingDriver(_Driver):
    def __init__(self, failure: DriverIncompleteError | TownDriverError) -> None:
        super().__init__(lambda request: NoneIntent(kind="none"))
        self.failure = failure

    async def decide(self, request: DriverRequest) -> DriverResponse:
        self.requests.append(request)
        self.lifecycle.append(request.observation.kind)
        raise self.failure


def _metadata() -> ResultDriver:
    return ResultDriver(
        contract="town-agent-driver/1",
        kind="loopback-http",
        adapter_instance_id=None,
        endpoint_origin="http://127.0.0.1:8787",
    )


@pytest.mark.asyncio
async def test_pass_runs_real_registry_discovery_and_simulator_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing Registry lookup or current simulator routing prevents the terminal PASS."""
    validated_results: list[object] = []
    validate_result = BoundProfileCodec.validate_result

    def track_result_validation(self: BoundProfileCodec, value: object) -> object:
        validated_results.append(value)
        return validate_result(self, value)

    monkeypatch.setattr(BoundProfileCodec, "validate_result", track_result_validation)

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        if request.observation.kind == "message":
            return SendToSenderIntent(
                kind="send_to_sender",
                media_type="text/plain; charset=utf-8",
                text="sold:widget:2",
            )
        return NoneIntent(kind="none")

    driver = _Driver(intent_for)
    output = tmp_path / "run"

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        output_dir=output,
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == 0
    assert outcome.result.run_id == RUN_ID
    assert outcome.result.execution.status == "completed"
    assert outcome.result.evaluation.verdict == "pass"
    assert len(validated_results) == 1
    assert [check.status for check in outcome.result.evaluation.checks] == ["pass"] * 5
    assert [request.observation.kind for request in driver.requests] == [
        "start",
        "message",
        "stop",
    ]
    assert [request.sequence for request in driver.requests] == [0, 1, 2]
    stop = driver.requests[-1].observation
    assert isinstance(stop, StopDriverObservation)
    assert stop.reason == "run_complete"
    assert driver.ready_calls == 1
    assert driver.close_calls == 1

    records = [json.loads(line) for line in (output / "trace.jsonl").read_text().splitlines()]
    assert [record["msg"] for record in records if record["kind"] == "send"] == [
        "buy:widget:2",
        "sold:widget:2",
    ]
    observations = [record for record in records if record["kind"].startswith("test.")]
    assert [record["kind"] for record in observations] == [
        "test.driver.run_admitted",
        "test.registry.provider_registered",
        "test.registry.lookup_requested",
        "test.registry.lookup_returned",
        "test.requester.provider_selected",
        "test.message.request_routed",
        "test.driver.intent_returned",
        "test.message.response_routed",
        "test.capability.result_evaluated",
    ]
    assert observations[1]["data"]["registry_implementation"] == (
        "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
    )
    assert observations[3]["data"]["card_agent_ids"] == ["provider-0"]
    assert (output / "result.json").read_bytes() == outcome.result_bytes
    assert [item.status for item in outcome.result.coverage[:4]] == ["exercised"] * 4
    assert all(
        item.status == "not_tested" and item.reason_code == "OUT_OF_PROFILE"
        for item in outcome.result.coverage[4:]
    )


@pytest.mark.asyncio
async def test_agent_test_injects_reference_registry_under_entry_point_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The profile path, rather than generic runner policy, pins the bundled Registry."""

    def entry_points(*, group: str) -> list[_RegistryEntryPoint]:
        if group == "nest.plugins.registry":
            return [_RegistryEntryPoint()]
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", entry_points)
    driver = _Driver(lambda request: NoneIntent(kind="none"))

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        base_dir=tmp_path,
        plugin_registry=PluginRegistry(),
        run_id_factory=lambda: RUN_ID,
    )

    records = [
        json.loads(line)
        for line in (outcome.output_directory / "trace.jsonl").read_text().splitlines()
    ]
    registry_records = [record for record in records if record["kind"].startswith("test.registry.")]
    assert registry_records
    assert all(
        record["data"]["registry_implementation"]
        == "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
        for record in registry_records
    )


@pytest.mark.asyncio
async def test_agent_test_never_loads_colliding_entry_points_for_any_profile_layer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolving any frozen layer through entry-point precedence executes foreign code."""
    loads: list[tuple[str, str]] = []

    def entry_points(*, group: str) -> list[_ForeignEntryPoint]:
        prefix = "nest.plugins."
        if not group.startswith(prefix):
            return []
        layer = group.removeprefix(prefix)
        name = _FROZEN_LAYER_NAMES.get(layer)
        if name is None:
            return []
        return [_ForeignEntryPoint(layer=layer, name=name, loads=loads)]

    monkeypatch.setattr(importlib.metadata, "entry_points", entry_points)

    outcome = await run_agent_test(
        driver=_Driver(lambda request: NoneIntent(kind="none")),
        driver_metadata=_metadata(),
        base_dir=tmp_path,
        plugin_registry=PluginRegistry(),
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == 1
    assert loads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("layer_name", list(_FROZEN_LAYER_NAMES))
async def test_mutated_profile_scenario_config_is_rejected_before_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layer_name: str
) -> None:
    """A packaged scenario that drifts from its profile cannot reach driver readiness."""
    config = ScenarioConfig.from_yaml(
        agent_test_runner_module.builtin_path("capability_fulfillment")
    )
    setattr(config.layers, layer_name, "foreign")

    def return_mutated_config(_path: str | Path) -> ScenarioConfig:
        return config

    monkeypatch.setattr(ScenarioConfig, "from_yaml", return_mutated_config)
    driver = _Driver(lambda request: NoneIntent(kind="none"))

    with pytest.raises(AgentTestTownError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value.code == "PROFILE_SCENARIO_INVALID"
    assert driver.ready_calls == 0
    assert driver.requests == []
    assert driver.close_calls == 1
    assert not (tmp_path / ".town" / "runs" / RUN_ID).exists()


@pytest.mark.asyncio
async def test_start_none_writes_terminal_semantic_failure(tmp_path: Path) -> None:
    """A valid start refusal fails registration without direct-address fallback."""
    driver = _Driver(lambda request: NoneIntent(kind="none"))
    output = tmp_path / "run"

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        output_dir=output,
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == 1
    assert outcome.result.execution.status == "completed"
    assert outcome.result.evaluation.verdict == "fail"
    assert [check.status for check in outcome.result.evaluation.checks] == [
        "pass",
        "fail",
        "not_tested",
        "not_tested",
        "not_tested",
    ]
    assert [request.observation.kind for request in driver.requests] == ["start", "stop"]
    stop = driver.requests[-1].observation
    assert isinstance(stop, StopDriverObservation)
    assert stop.reason == "run_failed"
    assert driver.close_calls == 1
    records = [json.loads(line) for line in (output / "trace.jsonl").read_text().splitlines()]
    assert not any(record.get("msg") == "buy:widget:2" for record in records)
    assert (output / "result.json").is_file()


@pytest.mark.asyncio
async def test_start_contract_failure_writes_failure_without_stop_before_admission(
    tmp_path: Path,
) -> None:
    """Malformed start output fails the driver while dependent checks remain untested."""
    driver = _StartContractFailingDriver(
        lambda request: DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
    )
    output = tmp_path / "run"

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        output_dir=output,
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == 1
    assert outcome.result.execution.status == "completed"
    assert outcome.result.evaluation.verdict == "fail"
    assert [check.status for check in outcome.result.evaluation.checks] == [
        "fail",
        "not_tested",
        "not_tested",
        "not_tested",
        "not_tested",
    ]
    assert [request.observation.kind for request in driver.requests] == ["start"]
    assert driver.close_calls == 1
    assert (output / "result.json").read_bytes() == outcome.result_bytes


@pytest.mark.asyncio
@pytest.mark.parametrize("preexisting_explicit", [False, True])
async def test_pre_trace_town_failure_raises_safe_typed_error_without_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    preexisting_explicit: bool,
) -> None:
    """A Town setup failure cannot be converted into a missing-trace artifact failure."""

    async def fail_before_trace(_runner: ScenarioRunner) -> Path:
        raise RuntimeError("remote Town exception text must not escape")

    monkeypatch.setattr(ScenarioRunner, "run", fail_before_trace)
    driver = _Driver(lambda request: NoneIntent(kind="none"))
    output = tmp_path / "explicit" if preexisting_explicit else None
    before_identity: tuple[int, int] | None = None
    if output is not None:
        output.mkdir()
        before = output.stat()
        before_identity = (before.st_ino, before.st_mode)
    with pytest.raises(AgentTestTownError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert str(caught.value) == "TOWN_EXECUTION_ERROR"
    assert caught.value.code == "TOWN_EXECUTION_ERROR"
    assert caught.value.exit_code == 3
    assert caught.value.__context__ is None
    assert driver.ready_calls == 1
    assert driver.requests == []
    assert driver.close_calls == 1
    if output is None:
        assert not (tmp_path / ".town" / "runs" / RUN_ID).exists()
    else:
        assert output.is_dir()
        assert list(output.iterdir()) == []
        after = output.stat()
        assert (after.st_ino, after.st_mode) == before_identity
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_stage",
    [
        "runtime_construction",
        "driven_agent_construction",
        "scenario_config_loading",
        "scenario_config_mutation",
        "scenario_runner_construction",
    ],
)
async def test_every_town_setup_failure_uses_safe_town_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    """No internal setup exception may escape after Town has created staging."""

    def fail_setup(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("remote post-staging setup text must not escape")

    if failure_stage == "runtime_construction":
        monkeypatch.setattr(agent_test_runner_module, "AgentTestRuntime", fail_setup)
    elif failure_stage == "driven_agent_construction":
        monkeypatch.setattr(agent_test_runner_module, "DrivenAgent", fail_setup)
    elif failure_stage == "scenario_config_loading":
        monkeypatch.setattr(ScenarioConfig, "from_yaml", fail_setup)
    elif failure_stage == "scenario_config_mutation":
        original_setattr = OutputConfig.__setattr__

        def fail_trace_assignment(output: OutputConfig, name: str, value: object) -> None:
            if name == "trace":
                fail_setup()
            original_setattr(output, name, value)

        monkeypatch.setattr(OutputConfig, "__setattr__", fail_trace_assignment)
    else:
        monkeypatch.setattr(agent_test_runner_module, "ScenarioRunner", fail_setup)

    driver = _Driver(lambda request: NoneIntent(kind="none"))
    output = tmp_path / "explicit"
    output.mkdir()
    before = output.stat()

    with pytest.raises(AgentTestTownError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    after = output.stat()
    assert caught.value.code == "TOWN_EXECUTION_ERROR"
    assert str(caught.value) == "TOWN_EXECUTION_ERROR"
    assert caught.value.__context__ is None
    assert "remote post-staging" not in repr(caught.value)
    assert (after.st_ino, after.st_mode) == (before.st_ino, before.st_mode)
    assert list(output.iterdir()) == []
    assert driver.ready_calls == (0 if failure_stage == "scenario_config_loading" else 1)
    assert driver.requests == []
    assert driver.close_calls == 1
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
async def test_post_staging_setup_cancellation_remains_native_without_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Moving setup under Town classification cannot consume native cancellation."""

    def cancel_setup(*_args: object, **_kwargs: object) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(agent_test_runner_module, "DrivenAgent", cancel_setup)
    driver = _Driver(lambda request: NoneIntent(kind="none"))
    output = tmp_path / "explicit"
    output.mkdir()

    with pytest.raises(asyncio.CancelledError):
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert list(output.iterdir()) == []
    assert driver.ready_calls == 1
    assert driver.requests == []
    assert driver.close_calls == 1
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
async def test_pre_observation_cancellation_propagates_without_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancellation remains native until a meaningful test observation exists."""

    async def cancel_before_trace(_runner: ScenarioRunner) -> Path:
        raise asyncio.CancelledError

    monkeypatch.setattr(ScenarioRunner, "run", cancel_before_trace)
    driver = _Driver(lambda request: NoneIntent(kind="none"))
    output = tmp_path / "explicit"
    output.mkdir()
    before = output.stat()

    with pytest.raises(asyncio.CancelledError):
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    after = output.stat()
    assert (after.st_ino, after.st_mode) == (before.st_ino, before.st_mode)
    assert list(output.iterdir()) == []
    assert driver.ready_calls == 1
    assert driver.requests == []
    assert driver.close_calls == 1
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
async def test_unexpected_town_failure_after_observation_writes_terminal_exit_three_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once test evidence exists, an unexpected Town failure remains an honest outcome."""
    original_run = ScenarioRunner.run

    async def fail_after_scenario(runner: ScenarioRunner) -> Path:
        await original_run(runner)
        raise RuntimeError("remote Town exception text must not escape")

    monkeypatch.setattr(ScenarioRunner, "run", fail_after_scenario)

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        if request.observation.kind == "message":
            return SendToSenderIntent(
                kind="send_to_sender",
                media_type="text/plain; charset=utf-8",
                text="sold:widget:2",
            )
        return NoneIntent(kind="none")

    driver = _Driver(intent_for)
    output = tmp_path / "run"

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        output_dir=output,
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == 3
    assert outcome.result.execution.status == "error"
    assert outcome.result.evaluation.verdict == "not_evaluated"
    assert outcome.result.evaluation.checks == []
    assert [item.code for item in outcome.result.diagnostics] == ["TOWN_EXECUTION_ERROR"]
    assert (output / "trace.jsonl").read_bytes().endswith(b"\n")
    assert (output / "result.json").read_bytes() == outcome.result_bytes
    assert driver.close_calls == 1


@pytest.mark.asyncio
async def test_failed_trace_close_after_observation_discards_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A present trace file is not publishable unless its close returned successfully."""
    original_close = TraceWriter.close
    trace_close_calls = 0

    def fail_after_trace_close(writer: TraceWriter) -> None:
        nonlocal trace_close_calls
        original_close(writer)
        trace_close_calls += 1
        raise RuntimeError("remote trace-close text must not escape")

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        if request.observation.kind == "message":
            return SendToSenderIntent(
                kind="send_to_sender",
                media_type="text/plain; charset=utf-8",
                text="sold:widget:2",
            )
        return NoneIntent(kind="none")

    monkeypatch.setattr(TraceWriter, "close", fail_after_trace_close)
    driver = _Driver(intent_for)
    output = tmp_path / "explicit"
    output.mkdir()

    with pytest.raises(AgentTestTownError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value.code == "TOWN_EXECUTION_ERROR"
    assert caught.value.__context__ is None
    assert "remote trace-close" not in repr(caught.value)
    assert trace_close_calls == 1
    assert list(output.iterdir()) == []
    assert [request.observation.kind for request in driver.requests] == [
        "start",
        "message",
        "stop",
    ]
    stop = driver.requests[-1].observation
    assert isinstance(stop, StopDriverObservation)
    assert stop.reason == "run_failed"
    assert driver.lifecycle[-2:] == ["stop", "close"]
    assert driver.close_calls == 1
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
async def test_artifact_promotion_failure_stops_before_close_without_masking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Post-admission publication failure still sends one safe terminal stop."""
    primary = RuntimeError("artifact promotion failed")

    def fail_promotion(staging: ArtifactStaging, *, run_id: ULID) -> ArtifactDirectory:
        raise primary

    monkeypatch.setattr(ArtifactStaging, "promote", fail_promotion)
    driver = _CleanupFailingDriver(lambda request: NoneIntent(kind="none"))

    with pytest.raises(RuntimeError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value is primary
    assert [request.observation.kind for request in driver.requests] == ["start", "stop"]
    stop = driver.requests[-1].observation
    assert isinstance(stop, StopDriverObservation)
    assert stop.reason == "run_failed"
    assert driver.lifecycle == ["ready", "start", "stop", "close"]
    assert driver.close_calls == 1
    assert not (tmp_path / ".town" / "runs" / RUN_ID).exists()
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
async def test_simulator_setup_failure_closes_trace_and_leaves_no_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-writer Simulator setup failure closes before staging is discarded."""
    trace_close_calls = 0
    original_close = TraceWriter.close

    def fail_initialization(_simulator: Simulator) -> None:
        raise RuntimeError("remote Simulator setup text must not escape")

    def record_trace_close(writer: TraceWriter) -> None:
        nonlocal trace_close_calls
        original_close(writer)
        trace_close_calls += 1

    monkeypatch.setattr(Simulator, "_init_failures", fail_initialization)
    monkeypatch.setattr(TraceWriter, "close", record_trace_close)
    driver = _Driver(lambda request: NoneIntent(kind="none"))

    with pytest.raises(AgentTestTownError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value.code == "TOWN_EXECUTION_ERROR"
    assert caught.value.__context__ is None
    assert trace_close_calls == 1
    assert driver.ready_calls == 1
    assert driver.requests == []
    assert driver.close_calls == 1
    assert not (tmp_path / ".town" / "runs" / RUN_ID).exists()
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error_type", "code"),
    [
        (DriverConfigurationError, "AUTHENTICATION_FAILED"),
        (DriverCompatibilityError, "UNSUPPORTED_PROFILE"),
    ],
)
@pytest.mark.parametrize("preexisting_explicit", [False, True])
async def test_start_configuration_or_compatibility_failure_leaves_no_run_bundle(
    tmp_path: Path,
    error_type: type[DriverConfigurationError] | type[DriverCompatibilityError],
    code: str,
    preexisting_explicit: bool,
) -> None:
    """Pre-admission start failures preserve their type without claiming output."""
    failure = error_type(code)
    driver = _StartPreAdmissionFailingDriver(failure)
    output = tmp_path / "explicit" if preexisting_explicit else None
    before_identity: tuple[int, int] | None = None
    if output is not None:
        output.mkdir()
        before = output.stat()
        before_identity = (before.st_ino, before.st_mode)

    with pytest.raises(error_type) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value is failure
    assert caught.value.code == code
    assert driver.ready_calls == 1
    assert [request.observation.kind for request in driver.requests] == ["start"]
    assert driver.close_calls == 1
    if output is None:
        assert not (tmp_path / ".town" / "runs" / RUN_ID).exists()
    else:
        assert output.is_dir()
        assert list(output.iterdir()) == []
        after = output.stat()
        assert (after.st_ino, after.st_mode) == before_identity
    assert not any("staging" in path.name for path in tmp_path.rglob("*"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "execution", "verdict", "exit_code", "disposition"),
    [
        (
            DriverIncompleteError("TIMEOUT"),
            "incomplete",
            "inconclusive",
            4,
            "incomplete",
        ),
        (TownDriverError("TOWN_BROKEN"), "error", "not_evaluated", 3, "town"),
    ],
)
async def test_start_attempt_failures_keep_evidence_and_terminal_bundle(
    tmp_path: Path,
    failure: DriverIncompleteError | TownDriverError,
    execution: str,
    verdict: str,
    exit_code: int,
    disposition: str,
) -> None:
    """Incomplete and Town start failures remain evidenced attempted-run outcomes."""
    driver = _StartAttemptFailingDriver(failure)

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == exit_code
    assert outcome.result.execution.status == execution
    assert outcome.result.evaluation.verdict == verdict
    assert [request.observation.kind for request in driver.requests] == ["start"]
    assert driver.close_calls == 1
    records = [
        json.loads(line)
        for line in (outcome.output_directory / "trace.jsonl").read_text().splitlines()
    ]
    failed = [record for record in records if record["kind"] == "test.driver.exchange_failed"]
    assert len(failed) == 1
    assert failed[0]["data"]["disposition"] == disposition
    assert (outcome.output_directory / "result.json").is_file()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "execution", "verdict", "exit_code", "stop_reason"),
    [
        (DriverIncompleteError("TIMEOUT"), "incomplete", "inconclusive", 4, "run_incomplete"),
        (TownDriverError("TOWN_BROKEN"), "error", "not_evaluated", 3, "run_failed"),
        (asyncio.CancelledError(), "incomplete", "inconclusive", 130, "user_interrupted"),
    ],
)
async def test_post_admission_attempts_always_write_terminal_result_and_close_once(
    tmp_path: Path,
    failure: BaseException,
    execution: str,
    verdict: str,
    exit_code: int,
    stop_reason: str,
) -> None:
    """Incomplete, Town-error, and interrupted attempts retain honest terminal artifacts."""
    driver = _FailingDriver(failure)
    output = tmp_path / "run"

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        output_dir=output,
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == exit_code
    assert outcome.result.execution.status == execution
    assert outcome.result.evaluation.verdict == verdict
    if verdict == "not_evaluated":
        assert outcome.result.evaluation.checks == []
    else:
        assert len(outcome.result.evaluation.checks) == 5
    assert [request.observation.kind for request in driver.requests] == [
        "start",
        "message",
        "stop",
    ]
    stop = driver.requests[-1].observation
    assert isinstance(stop, StopDriverObservation)
    assert stop.reason == stop_reason
    assert driver.close_calls == 1
    assert (output / "trace.jsonl").read_bytes().endswith(b"\n")
    assert (output / "result.json").read_bytes() == outcome.result_bytes


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["file", "symlink", "nonempty_directory"])
async def test_output_configuration_is_rejected_before_readiness_without_mutation(
    tmp_path: Path, kind: str
) -> None:
    """A caller-owned unsafe target cannot trigger driver I/O or a misleading bundle."""
    output = tmp_path / "owned"
    if kind == "file":
        output.write_bytes(b"caller bytes")
    elif kind == "symlink":
        destination = tmp_path / "destination"
        destination.mkdir()
        (destination / "marker.txt").write_bytes(b"caller bytes")
        output.symlink_to(destination, target_is_directory=True)
    else:
        output.mkdir()
        (output / "marker.txt").write_bytes(b"caller bytes")
    before = sorted(
        (path.relative_to(tmp_path), path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    driver = _Driver(lambda request: NoneIntent(kind="none"))

    with pytest.raises(AgentTestPreAdmissionError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value.code == "OUTPUT_DIR_INVALID"
    after = sorted(
        (path.relative_to(tmp_path), path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert after == before
    if kind == "symlink":
        assert output.is_symlink()
    assert driver.ready_calls == 0
    assert driver.requests == []
    assert driver.close_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("target_label", ["", " untrimmed", "bad\nlabel", "é" * 129])
async def test_invalid_target_label_is_rejected_before_admission_or_artifacts(
    tmp_path: Path, target_label: str
) -> None:
    """Unsafe public result labels cannot reach the adapter or mutate caller output."""
    output = tmp_path / "owned"
    output.mkdir()
    marker = output / "marker.txt"
    marker.write_bytes(b"caller bytes")
    driver = _Driver(lambda request: NoneIntent(kind="none"))

    with pytest.raises(AgentTestPreAdmissionError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            target_label=target_label,
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value.code == "TARGET_LABEL_INVALID"
    assert str(caught.value) == "TARGET_LABEL_INVALID"
    assert marker.read_bytes() == b"caller bytes"
    assert list(output.iterdir()) == [marker]
    assert driver.ready_calls == 0
    assert driver.requests == []
    assert driver.close_calls == 1


@pytest.mark.asyncio
async def test_terminal_publication_follows_trace_writer_close_and_writes_result_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ordinary ScenarioRunner closure precedes trace promotion and result publication."""
    trace_closed = False
    original_close = TraceWriter.close
    original_promote = ArtifactStaging.promote
    original_write_result = ArtifactDirectory.write_result

    def record_trace_close(writer: TraceWriter) -> None:
        nonlocal trace_closed
        original_close(writer)
        trace_closed = True

    def assert_closed_before_promotion(
        staging: ArtifactStaging, *, run_id: ULID
    ) -> ArtifactDirectory:
        assert trace_closed
        return original_promote(staging, run_id=run_id)

    def assert_result_is_last(artifacts: ArtifactDirectory, result: TestResult) -> bytes:
        assert artifacts.trace_path.is_file()
        assert artifacts.trace_path.read_bytes().endswith(b"\n")
        assert not artifacts.result_path.exists()
        assert sorted(path.name for path in artifacts.path.iterdir()) == ["trace.jsonl"]
        return original_write_result(artifacts, result)

    monkeypatch.setattr(TraceWriter, "close", record_trace_close)
    monkeypatch.setattr(ArtifactStaging, "promote", assert_closed_before_promotion)
    monkeypatch.setattr(ArtifactDirectory, "write_result", assert_result_is_last)
    output = tmp_path / "run"

    outcome = await run_agent_test(
        driver=_Driver(lambda request: NoneIntent(kind="none")),
        driver_metadata=_metadata(),
        output_dir=output,
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == 1
    assert trace_closed
    assert sorted(path.name for path in output.iterdir()) == ["result.json", "trace.jsonl"]


class _MissingRegistry:
    def resolve_reference(self, layer: str, name: str):
        raise ModuleNotFoundError("remote package text must not surface")


@pytest.mark.asyncio
async def test_missing_pinned_registry_has_exact_guidance_before_admission(tmp_path: Path) -> None:
    """A core-only install fails closed with the one supported optional-extra remediation."""
    driver = _Driver(lambda request: NoneIntent(kind="none"))
    output = tmp_path / "run"

    with pytest.raises(AgentTestPreAdmissionError) as caught:
        await run_agent_test(
            driver=driver,
            driver_metadata=_metadata(),
            output_dir=output,
            base_dir=tmp_path,
            plugin_registry=_MissingRegistry(),  # type: ignore[arg-type]
            run_id_factory=lambda: RUN_ID,
        )

    assert caught.value.code == "REFERENCE_REGISTRY_MISSING"
    assert caught.value.next == "pip install 'nest-core[plugins]'"
    assert str(caught.value) == "REFERENCE_REGISTRY_MISSING"
    assert not output.exists()
    assert driver.ready_calls == 0
    assert driver.requests == []
    assert driver.close_calls == 1


@pytest.mark.asyncio
async def test_default_output_path_is_exact_run_id_directory(tmp_path: Path) -> None:
    """Generated output uses exactly .town/runs/<result run ID> and remains unique."""
    driver = _Driver(lambda request: NoneIntent(kind="none"))

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.output_directory == tmp_path / ".town" / "runs" / RUN_ID
    assert outcome.output_directory.name == outcome.result.run_id
    assert (outcome.output_directory / "result.json").is_file()


@pytest.mark.asyncio
async def test_cleanup_failures_do_not_change_pass_or_leak_secrets(tmp_path: Path) -> None:
    """Best-effort stop and close failures preserve verdict while emitting only local codes."""

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        if request.observation.kind == "message":
            return SendToSenderIntent(
                kind="send_to_sender",
                media_type="text/plain; charset=utf-8",
                text="sold:widget:2",
            )
        return NoneIntent(kind="none")

    driver = _CleanupFailingDriver(intent_for)
    output = tmp_path / "run"

    outcome = await run_agent_test(
        driver=driver,
        driver_metadata=_metadata(),
        output_dir=output,
        base_dir=tmp_path,
        run_id_factory=lambda: RUN_ID,
    )

    assert outcome.exit_code == 0
    assert outcome.result.evaluation.verdict == "pass"
    assert [request.observation.kind for request in driver.requests] == [
        "start",
        "message",
        "stop",
    ]
    assert driver.close_calls == 1
    assert [diagnostic.code for diagnostic in outcome.result.diagnostics] == ["DRIVER_CLOSE_FAILED"]
    artifact_bytes = (output / "trace.jsonl").read_bytes() + (output / "result.json").read_bytes()
    assert b"secret-cleanup-canary" not in artifact_bytes
    assert b"secret-close-canary" not in artifact_bytes
