# SPDX-License-Identifier: Apache-2.0
"""Outer transport-neutral orchestration for one admitted external participant."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast

from pydantic import TypeAdapter, ValidationError

from nest_core.builtin_scenarios import builtin_path
from nest_core.plugins import PluginRegistry
from nest_core.runner import PluginResolver, ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import ScenarioEventSink, StateMachineAgent
from nest_core.types import AgentId

from .aggregation import AggregationCondition, aggregate
from .artifacts import (
    ArtifactDirectory,
    ArtifactDirectoryError,
    ArtifactStaging,
    prepare_artifact_staging,
    validate_artifact_target,
)
from .driven_agent import DrivenAgent
from .driver import (
    AgentDriver,
    AgentDriverError,
    DriverCompatibilityError,
    DriverConfigurationError,
    DriverFailureDisposition,
)
from .evaluator import evaluate_capability_fulfillment
from .ids import new_ulid
from .models import (
    ULID,
    CheckResult,
    CoverageResult,
    Diagnostic,
    Evaluation,
    Execution,
    ResultDriver,
    ResultTarget,
    SafeText128,
    TestResult,
    ToolMetadata,
)
from .profiles import (
    ResolvedTestProfile,
    capability_profile_document,
    resolve_test_profile,
)
from .runtime import AgentTestRuntime

_REGISTRY_IMPLEMENTATION = "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
_ULID_ADAPTER: TypeAdapter[str] = TypeAdapter(ULID)
_TARGET_LABEL_ADAPTER: TypeAdapter[str] = TypeAdapter(SafeText128)
_CAPABILITY_PROFILE_LAYERS = MappingProxyType(
    {
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
)
type StopReason = Literal["run_complete", "run_failed", "run_incomplete", "user_interrupted"]
_STOP_REASON_BY_EXIT: dict[int, StopReason] = {
    0: "run_complete",
    1: "run_failed",
    3: "run_failed",
    4: "run_incomplete",
    130: "user_interrupted",
}


class AgentTestPreAdmissionError(RuntimeError):
    """Safe configuration failure raised before a run bundle can be authoritative."""

    exit_code: Literal[2] = 2

    def __init__(self, code: str, *, next: str | None = None) -> None:
        self.code = code
        self.next = next
        super().__init__(code)


class AgentTestTownError(RuntimeError):
    """Safe Town failure raised before an evidence bundle can be authoritative."""

    exit_code: Literal[3] = 3

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AgentTestOutcome:
    """Terminal machine-readable result plus process and artifact metadata."""

    result: TestResult
    exit_code: int
    output_directory: Path
    result_bytes: bytes


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("agent-test timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _tool_version() -> str:
    try:
        return metadata.version("nest-core")
    except metadata.PackageNotFoundError:
        return "0.1.4"


def _preflight_registry(registry: PluginRegistry) -> None:
    try:
        implementation = registry.resolve_reference("registry", "in_memory")
    except (ImportError, KeyError):
        raise AgentTestPreAdmissionError(
            "REFERENCE_REGISTRY_MISSING", next="pip install 'nest-core[plugins]'"
        ) from None
    identity = f"{implementation.__module__}.{implementation.__qualname__}"
    if identity != _REGISTRY_IMPLEMENTATION:
        raise AgentTestPreAdmissionError(
            "REFERENCE_REGISTRY_MISSING", next="pip install 'nest-core[plugins]'"
        )


@dataclass(frozen=True, slots=True)
class _ProfilePluginResolver(PluginResolver):
    registry: PluginRegistry

    def resolve(self, layer: str, name: str) -> Any:
        expected_name = _CAPABILITY_PROFILE_LAYERS.get(layer)
        if expected_name is None or name != expected_name:
            raise AgentTestTownError("PROFILE_SCENARIO_INVALID")
        return self.registry.resolve_reference(layer, expected_name)


def _validate_profile_scenario(
    config: ScenarioConfig, resolved_profile: ResolvedTestProfile
) -> None:
    scenario = capability_profile_document(resolved_profile).scenario
    if (
        config.task.type != scenario.id
        or config.seed != scenario.seed
        or config.layers.model_dump() != dict(_CAPABILITY_PROFILE_LAYERS)
        or config.layers.registry != scenario.registry_plugin
        or config.task.config.get("lookup_delay_ticks") != scenario.lookup_delay_ticks
    ):
        raise AgentTestTownError("PROFILE_SCENARIO_INVALID")


def _build_profile_scenario_runner(
    *,
    config: ScenarioConfig,
    resolved_profile: ResolvedTestProfile,
    registry: PluginRegistry,
    participant_override: Mapping[AgentId, StateMachineAgent],
    event_sink: ScenarioEventSink,
) -> ScenarioRunner:
    """Apply exact profile policy before entering the generic runner."""
    _validate_profile_scenario(config, resolved_profile)
    subject_id = AgentId(
        capability_profile_document(resolved_profile).scenario.subject_participant_id
    )
    if len(participant_override) != 1 or set(participant_override) != {subject_id}:
        raise AgentTestTownError("PROFILE_SCENARIO_INVALID")
    return ScenarioRunner(
        config,
        participant_override=participant_override,
        plugin_resolver=_ProfilePluginResolver(registry=registry),
        event_sink=event_sink,
    )


def _coverage(
    checks: list[CheckResult], resolved_profile: ResolvedTestProfile
) -> list[CoverageResult]:
    profile = capability_profile_document(resolved_profile)
    by_id = {check.id: check for check in checks}
    check_for_claim = {
        "town.agent-driver.loopback": "driver.contract",
        "nanda.registry.run-local-discovery": "registry.provider-discovered",
        "town.simulator.in-memory-routing": "delivery.request-routed",
        "nanda.agent.synthetic-capability-fulfillment": ("capability.synthetic-request-fulfilled"),
    }
    results: list[CoverageResult] = []
    for claim in profile.coverage.exercised:
        check = by_id.get(check_for_claim[claim])
        conclusive = check is not None and check.status in {"pass", "fail"}
        results.append(
            CoverageResult(
                claim=claim,
                status="exercised" if conclusive else "unknown",
                reason_code=None if conclusive else "NOT_OBSERVED",
                evidence_refs=check.evidence_refs if check is not None and conclusive else [],
            )
        )
    results.extend(
        CoverageResult(
            claim=claim,
            status="not_tested",
            reason_code="OUT_OF_PROFILE",
            evidence_refs=[],
        )
        for claim in profile.coverage.not_tested
    )
    return results


async def run_agent_test(
    *,
    driver: AgentDriver,
    driver_metadata: ResultDriver,
    output_dir: Path | None = None,
    base_dir: Path | None = None,
    target_label: str = "local-agent",
    plugin_registry: PluginRegistry | None = None,
    run_id_factory: Callable[[], str] = new_ulid,
) -> AgentTestOutcome:
    """Run the frozen scenario with one driver-backed provider and write terminal artifacts."""
    artifacts: ArtifactDirectory | None = None
    staging: ArtifactStaging | None = None
    runtime: AgentTestRuntime | None = None
    driven: DrivenAgent | None = None
    scenario_runner: ScenarioRunner | None = None
    driver_closed = False
    stop_attempted = False
    stop_reason: StopReason = "run_failed"

    async def close_driver_once() -> str | None:
        nonlocal driver_closed
        if driver_closed:
            return None
        driver_closed = True
        try:
            await driver.close()
        except BaseException:
            return "DRIVER_CLOSE_FAILED"
        return None

    async def stop_driven_once() -> None:
        nonlocal stop_attempted
        if stop_attempted or driven is None:
            return
        stop_attempted = True
        try:
            await driven.best_effort_stop(stop_reason)
        except BaseException:
            return

    try:
        try:
            target_label = _TARGET_LABEL_ADAPTER.validate_python(target_label, strict=True)
        except ValidationError:
            raise AgentTestPreAdmissionError("TARGET_LABEL_INVALID") from None
        try:
            run_id = _ULID_ADAPTER.validate_python(run_id_factory(), strict=True)
        except ValidationError:
            raise AgentTestPreAdmissionError("RUN_ID_INVALID") from None
        resolved_profile = resolve_test_profile("capability-fulfillment")
        profile_document = capability_profile_document(resolved_profile)
        try:
            validate_artifact_target(run_id=run_id, output_dir=output_dir, base_dir=base_dir)
        except ArtifactDirectoryError:
            raise AgentTestPreAdmissionError("OUTPUT_DIR_INVALID") from None
        registry = plugin_registry or PluginRegistry()
        _preflight_registry(registry)
        config: ScenarioConfig | None = None
        try:
            config = ScenarioConfig.from_yaml(builtin_path("capability_fulfillment"))
            _validate_profile_scenario(config, resolved_profile)
        except AgentTestTownError:
            raise
        except asyncio.CancelledError:
            raise
        except BaseException:
            config = None
        if config is None:
            raise AgentTestTownError("TOWN_EXECUTION_ERROR") from None
        started_wall = _utc_now()
        started_ns = time.monotonic_ns()
        readiness = await driver.ready(resolved_profile)
        try:
            staging = prepare_artifact_staging(
                run_id=run_id, output_dir=output_dir, base_dir=base_dir
            )
        except ArtifactDirectoryError:
            raise AgentTestPreAdmissionError("OUTPUT_DIR_INVALID") from None
        condition: AggregationCondition | None = None
        diagnostics: list[Diagnostic] = []
        try:
            runtime = AgentTestRuntime(run_id=run_id, resolved_profile=resolved_profile)
            driven = DrivenAgent(
                driver=driver,
                run_id=run_id,
                resolved_profile=resolved_profile,
                readiness=readiness,
            )
            config.output.trace = str(staging.trace_path)
            scenario_runner = _build_profile_scenario_runner(
                config=config,
                resolved_profile=resolved_profile,
                registry=registry,
                participant_override={AgentId(runtime.subject_participant_id): driven},
                event_sink=runtime,
            )
            await scenario_runner.run()
        except AgentTestTownError:
            raise
        except (DriverConfigurationError, DriverCompatibilityError) as error:
            if driven is None or not driven.admitted:
                raise
            diagnostics.append(
                Diagnostic(
                    code=error.code,
                    stage="driver",
                    severity="error",
                    summary="The driver exchange ended with a closed local failure",
                    next=None,
                )
            )
        except asyncio.CancelledError:
            if runtime is None or not runtime.observations:
                raise
            condition = "user_interrupted"
            stop_reason = "user_interrupted"
            diagnostics.append(
                Diagnostic(
                    code="USER_INTERRUPTED",
                    stage="driver",
                    severity="warning",
                    summary="The agent-test run was interrupted by the user",
                    next=None,
                )
            )
        except AgentDriverError as error:
            if error.disposition == DriverFailureDisposition.TOWN:
                condition = "town_defect"
            elif error.disposition == DriverFailureDisposition.INCOMPLETE:
                stop_reason = "run_incomplete"
            diagnostics.append(
                Diagnostic(
                    code=error.code,
                    stage="town" if condition == "town_defect" else "driver",
                    severity=(
                        "warning"
                        if error.disposition == DriverFailureDisposition.INCOMPLETE
                        else "error"
                    ),
                    summary="The driver exchange ended with a closed local failure",
                    next=None,
                )
            )
        except BaseException:
            if runtime is not None and runtime.observations:
                condition = "town_defect"
                diagnostics.append(
                    Diagnostic(
                        code="TOWN_EXECUTION_ERROR",
                        stage="town",
                        severity="error",
                        summary="Town could not complete the dedicated scenario",
                        next=None,
                    )
                )

        if (
            runtime is None
            or driven is None
            or scenario_runner is None
            or not runtime.observations
            or not scenario_runner.trace_finalized
        ):
            raise AgentTestTownError("TOWN_EXECUTION_ERROR") from None

        artifacts = staging.promote(run_id=run_id)

        checks: list[CheckResult]
        if condition == "town_defect":
            checks = []
        else:
            try:
                checks = evaluate_capability_fulfillment(
                    runtime.observations,
                    run_id=run_id,
                    resolved_profile=resolved_profile,
                )
            except BaseException:
                condition = "town_defect"
                checks = []
                diagnostics.append(
                    Diagnostic(
                        code="EVALUATOR_ERROR",
                        stage="evaluation",
                        severity="error",
                        summary="Town could not evaluate the closed observation trace",
                        next=None,
                    )
                )
        aggregated = aggregate(
            checks,
            observations=runtime.observations,
            run_id=run_id,
            condition=condition,
        )

        trace_artifact = None
        try:
            trace_artifact = artifacts.finalize_trace(runtime.observations)
        except ArtifactDirectoryError:
            condition = "town_defect"
            checks = []
            aggregated = aggregate(
                checks,
                observations=runtime.observations,
                run_id=run_id,
                condition=condition,
            )
            diagnostics.append(
                Diagnostic(
                    code="TRACE_FINALIZATION_FAILED",
                    stage="artifacts",
                    severity="error",
                    summary="Town could not verify the terminal trace artifact",
                    next=None,
                )
            )

        stop_reason = _STOP_REASON_BY_EXIT.get(aggregated.exit_code, "run_failed")
        await stop_driven_once()
        close_error = await close_driver_once()
        if close_error is not None:
            diagnostics.append(
                Diagnostic(
                    code=close_error,
                    stage="cleanup",
                    severity="warning",
                    summary="The driver transport did not close cleanly",
                    next=None,
                )
            )
        finished_wall = _utc_now()
        duration_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
        result = TestResult(
            schema_version="town.test-result/1",
            run_id=run_id,
            tool=ToolMetadata(name="nest-core", version=_tool_version(), commit=None),
            target=ResultTarget(
                kind="agent",
                label=target_label,
                attribution="self_asserted_loopback_adapter_instance",
            ),
            driver=ResultDriver.model_validate(
                {
                    **driver_metadata.model_dump(mode="json"),
                    "adapter_instance_id": readiness.ready.adapter_instance_id,
                }
            ),
            profile=resolved_profile.reference,
            execution=Execution(
                status=aggregated.execution_status,
                started_at=_timestamp(started_wall),
                finished_at=_timestamp(finished_wall),
                duration_ms=duration_ms,
                scenario="capability_fulfillment",
                seed=profile_document.scenario.seed,
                logical_time_end=driven.logical_time_end,
                decision_timeout_ms=profile_document.driver.decision_timeout_ms,
            ),
            evaluation=Evaluation(verdict=aggregated.verdict, checks=checks),
            coverage=_coverage(checks, resolved_profile),
            artifacts=[] if trace_artifact is None else [trace_artifact],
            diagnostics=diagnostics,
        )
        result = cast("TestResult", resolved_profile.codec.validate_result(result))
        result_bytes = artifacts.write_result(result)
        return AgentTestOutcome(
            result=result,
            exit_code=aggregated.exit_code,
            output_directory=artifacts.path,
            result_bytes=result_bytes,
        )
    finally:
        if staging is not None:
            staging.discard()
        try:
            await stop_driven_once()
        finally:
            await close_driver_once()
