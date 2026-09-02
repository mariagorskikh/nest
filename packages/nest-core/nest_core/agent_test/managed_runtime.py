# SPDX-License-Identifier: Apache-2.0
"""Managed-runtime orchestration through Town's local Generation 1 driver."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, cast

from pydantic import TypeAdapter, ValidationError

from .driver import AgentDriver
from .http_driver import LoopbackHttpAgentDriver
from .local_adapter_server import AdapterDecisionContext, create_local_adapter_server
from .models import (
    DriverIntent,
    DriverReadiness,
    DriverRequest,
    DriverResponse,
    ResultDriver,
    SafeText128,
)
from .profiles import ResolvedTestProfile, resolve_test_profile
from .runner import AgentTestOutcome, run_agent_test
from .runtime_connectors import (
    PreparedRuntime,
    RuntimeConfigurationError,
    RuntimeDisplay,
    RuntimeExecutionError,
    RuntimeIncompleteError,
    RuntimeIssuePolicy,
    RuntimeRun,
)

_INTENT_ADAPTER: TypeAdapter[DriverIntent] = TypeAdapter(DriverIntent)
_SAFE_METADATA_ADAPTER: TypeAdapter[str] = TypeAdapter(SafeText128)


def _event_set() -> set[tuple[str, str]]:
    return set()


@dataclass(frozen=True, slots=True)
class ManagedAgentTestOutcome:
    outcome: AgentTestOutcome
    runtime_id: str
    runtime_version: str
    runtime_display: RuntimeDisplay
    target_id: str
    issue_code: str | None


@dataclass(slots=True)
class _RuntimeState:
    issue_policy: RuntimeIssuePolicy
    run: RuntimeRun | None = None
    issue_code: str | None = None
    failed_events: set[tuple[str, str]] = field(default_factory=_event_set, repr=False)

    def record_owned_issue(self, code: str) -> None:
        if self.issue_code is None:
            self.issue_code = code

    def record_runtime_error(
        self,
        error: RuntimeConfigurationError | RuntimeExecutionError | RuntimeIncompleteError,
    ) -> None:
        self.record_owned_issue(self.issue_policy.code_for(error))


class _ManagedDecisionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _CloseOnceDriver:
    """Make the runner and outer managed scope share one driver close."""

    def __init__(self, driver: LoopbackHttpAgentDriver) -> None:
        self._driver = driver
        self._closed = False
        self.issue_code: str | None = None

    async def ready(self, profile: ResolvedTestProfile) -> DriverReadiness:
        return await self._driver.ready(profile)

    async def decide(self, request: DriverRequest) -> DriverResponse:
        return await self._driver.decide(request)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._driver.close()
        except BaseException:
            self.issue_code = "DRIVER_CLOSE_FAILED"
            raise


def _safe_metadata(value: object, *, code: str) -> str:
    try:
        return _SAFE_METADATA_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        raise RuntimeConfigurationError(code) from None


def _managed_metadata(
    prepared_runtime: PreparedRuntime,
) -> tuple[str, str, RuntimeDisplay, str, str, RuntimeIssuePolicy]:
    runtime_id = _safe_metadata(
        getattr(prepared_runtime, "runtime_id", None),
        code="RUNTIME_METADATA_INVALID",
    )
    runtime_version = _safe_metadata(
        getattr(prepared_runtime, "runtime_version", None),
        code="RUNTIME_METADATA_INVALID",
    )
    display = getattr(prepared_runtime, "display", None)
    if type(display) is not RuntimeDisplay:
        raise RuntimeConfigurationError("RUNTIME_METADATA_INVALID")
    target_id = _safe_metadata(
        getattr(getattr(prepared_runtime, "target", None), "id", None),
        code="TARGET_ID_INVALID",
    )
    target_label = _safe_metadata(
        getattr(prepared_runtime, "target_label", None),
        code="TARGET_LABEL_INVALID",
    )
    issue_policy = getattr(prepared_runtime, "issue_policy", None)
    if type(issue_policy) is not RuntimeIssuePolicy:
        raise RuntimeConfigurationError("RUNTIME_POLICY_INVALID")
    return runtime_id, runtime_version, display, target_id, target_label, issue_policy


def _ignore_request_error(_request: object, _client_address: object) -> None:
    """Keep disconnected managed clients from emitting worker tracebacks."""


def _validated_intent(
    turn_intent: Mapping[str, object], observation: Mapping[str, object]
) -> dict[str, object]:
    try:
        intent = _INTENT_ADAPTER.validate_python(dict(turn_intent), strict=True)
        allowed = observation.get("allowed_intents")
        if type(allowed) is not list or intent.kind not in cast("list[object]", allowed):
            raise ValueError
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise _ManagedDecisionError("RUNTIME_INTENT_INVALID") from None
    return cast("dict[str, object]", intent.model_dump(mode="json"))


def _decision_hook(
    prepared_runtime: PreparedRuntime,
    state: _RuntimeState,
    context: AdapterDecisionContext,
    observation: Mapping[str, object],
) -> Mapping[str, object]:
    event_key = (context.run_id, context.event_id)
    if event_key in state.failed_events:
        raise RuntimeError("RUNTIME_DECISION_FAILED")
    try:
        validated_observation = dict(observation)
        if validated_observation.get("kind") == "start":
            if state.run is not None:
                raise RuntimeExecutionError("RUNTIME_RUN_ALREADY_OPEN")
            state.run = prepared_runtime.open_run(context.run_id)
        runtime_run = state.run
        if runtime_run is None:
            raise RuntimeExecutionError("RUNTIME_RUN_NOT_OPEN")
        turn = runtime_run.turn(validated_observation)
        if turn.activity == "reported":
            raise _ManagedDecisionError("RUNTIME_ACTIVITY_REPORTED")
        return _validated_intent(turn.intent, validated_observation)
    except _ManagedDecisionError as error:
        state.record_owned_issue(error.code)
    except (RuntimeConfigurationError, RuntimeExecutionError, RuntimeIncompleteError) as error:
        state.record_runtime_error(error)
    except BaseException:
        state.record_owned_issue("RUNTIME_EXECUTION_FAILED")
    state.failed_events.add(event_key)
    raise RuntimeError("RUNTIME_DECISION_FAILED") from None


async def run_managed_agent_test(
    *,
    prepared_runtime: PreparedRuntime,
    profile: str,
    output_dir: Path | None,
    base_dir: Path,
) -> ManagedAgentTestOutcome:
    """Run one prepared runtime through the reusable authenticated local adapter."""
    resolve_test_profile(profile)
    runtime_id, runtime_version, runtime_display, target_id, target_label, issue_policy = (
        _managed_metadata(prepared_runtime)
    )
    state = _RuntimeState(issue_policy)
    server: ThreadingHTTPServer | None = None
    thread: Thread | None = None
    thread_started = False
    driver: _CloseOnceDriver | None = None
    outcome: AgentTestOutcome | None = None

    try:
        bearer = ""
        try:
            bearer = secrets.token_hex(32)
            server = create_local_adapter_server(
                token=bearer,
                adapter_instance_id=prepared_runtime.adapter_instance_id,
                decide_intent=lambda context, observation: _decision_hook(
                    prepared_runtime, state, context, observation
                ),
                port=0,
            )
            server.daemon_threads = False
            server.handle_error = cast("Any", _ignore_request_error)
            endpoint_origin = f"http://127.0.0.1:{server.server_port}"
            driver = _CloseOnceDriver(LoopbackHttpAgentDriver(endpoint_origin, bearer))
        finally:
            del bearer

        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        thread_started = True
        driver_metadata = ResultDriver(
            contract="town-agent-driver/1",
            kind="loopback-http",
            adapter_instance_id=None,
            endpoint_origin=endpoint_origin,
        )
        outcome = await run_agent_test(
            driver=cast("AgentDriver", driver),
            driver_metadata=driver_metadata,
            output_dir=output_dir,
            base_dir=base_dir,
            target_label=target_label,
        )
    finally:
        if server is not None:
            if thread_started:
                try:
                    server.shutdown()
                except BaseException:
                    state.record_owned_issue("SERVER_SHUTDOWN_FAILED")
            else:
                try:
                    server.server_close()
                except BaseException:
                    state.record_owned_issue("SERVER_SHUTDOWN_FAILED")
        if thread is not None and thread_started:
            try:
                thread.join(timeout=5)
                if thread.is_alive():
                    state.record_owned_issue("SERVER_THREAD_JOIN_FAILED")
            except BaseException:
                state.record_owned_issue("SERVER_THREAD_JOIN_FAILED")
        if state.run is not None:
            try:
                state.run.close()
            except BaseException:
                state.record_owned_issue("RUNTIME_CLOSE_FAILED")
        if driver is not None:
            with suppress(BaseException):
                await driver.close()
            if driver.issue_code is not None:
                state.record_owned_issue(driver.issue_code)

    assert outcome is not None
    return ManagedAgentTestOutcome(
        outcome=outcome,
        runtime_id=runtime_id,
        runtime_version=runtime_version,
        runtime_display=runtime_display,
        target_id=target_id,
        issue_code=state.issue_code,
    )
