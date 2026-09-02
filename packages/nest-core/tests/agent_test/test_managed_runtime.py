# SPDX-License-Identifier: Apache-2.0
"""Lifecycle tests for managed runtimes behind Town's loopback driver."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import time
from collections.abc import Mapping
from http.client import HTTPConnection
from pathlib import Path
from threading import Event, Thread
from typing import Any, cast

import nest_core.agent_test.managed_runtime as managed_runtime
import pytest
from nest_core.agent_test.artifacts import ArtifactDirectory
from nest_core.agent_test.driver import AgentDriver
from nest_core.agent_test.http_driver import LoopbackHttpAgentDriver
from nest_core.agent_test.local_adapter_server import create_local_adapter_server
from nest_core.agent_test.models import DriverRequest, TestResult
from nest_core.agent_test.profiles import resolve_test_profile
from nest_core.agent_test.runner import (
    AgentTestOutcome,
    AgentTestPreAdmissionError,
)
from nest_core.agent_test.runtime_connectors import (
    RuntimeConfigurationError,
    RuntimeDisplay,
    RuntimeExecutionError,
    RuntimeIncompleteError,
    RuntimeIssuePolicy,
    RuntimeTarget,
    RuntimeTurn,
)

TOKEN = "ab" * 32
RUN_ID = "01K00000000000000000000001"
OPENCLAW_DISPLAY = RuntimeDisplay("OpenClaw", "openclaw gateway status")
OPENCLAW_TEST_POLICY = RuntimeIssuePolicy(
    configuration=frozenset({"OPENCLAW_RUN_DUPLICATE"}),
    incomplete=frozenset(
        {
            "OPENCLAW_FALLBACK_REPORTED",
            "OPENCLAW_TRANSPORT_AMBIGUOUS",
        }
    ),
    execution=frozenset(
        {
            "OPENCLAW_ENVELOPE_INVALID",
            "OPENCLAW_INTENT_INVALID",
            "OPENCLAW_TIMEOUT",
            "OPENCLAW_TRANSPORT_LOSS",
        }
    ),
)


def _turn(intent: Mapping[str, object], *, activity: str = "unknown") -> RuntimeTurn:
    return RuntimeTurn(
        intent=intent,
        provider="provider",
        model="model",
        session_ref_digest="sha256:" + "1" * 64,
        activity=cast("Any", activity),
    )


class FakeRuntimeRun:
    def __init__(
        self,
        decisions: list[RuntimeTurn | BaseException] | None = None,
        *,
        close_error: BaseException | None = None,
    ) -> None:
        self.decisions = decisions or [
            _turn({"kind": "declare_capability", "capabilities": ["sell"]}),
            _turn(
                {
                    "kind": "send_to_sender",
                    "media_type": "text/plain; charset=utf-8",
                    "text": "sold:widget:2",
                }
            ),
        ]
        self.observations: list[dict[str, object]] = []
        self.close_calls = 0
        self.close_error = close_error

    def turn(self, observation: Mapping[str, object]) -> RuntimeTurn:
        self.observations.append(dict(observation))
        decision = self.decisions[len(self.observations) - 1]
        if isinstance(decision, BaseException):
            raise decision
        return decision

    def close(self) -> None:
        self.close_calls += 1
        error = self.close_error
        if error is not None:
            raise error


class FakePreparedRuntime:
    runtime_id = "openclaw"
    runtime_version = "2026.7.1-2"
    display = OPENCLAW_DISPLAY
    issue_policy = OPENCLAW_TEST_POLICY
    adapter_instance_id = "openclaw-managed-test"

    def __init__(
        self,
        run: FakeRuntimeRun | None = None,
        *,
        open_error: BaseException | None = None,
    ) -> None:
        self.target = RuntimeTarget("buyer", "provider/model")
        self.target_label = "openclaw:buyer"
        self.run = run or FakeRuntimeRun()
        self.open_error = open_error
        self.open_calls: list[str] = []

    def open_run(self, town_run_id: str) -> FakeRuntimeRun:
        self.open_calls.append(town_run_id)
        if self.open_error is not None:
            raise self.open_error
        return self.run


class BlockingRuntimeRun(FakeRuntimeRun):
    def __init__(self) -> None:
        super().__init__()
        self.entered = Event()
        self.release = Event()
        self.active = False
        self.close_raced_turn = False

    def turn(self, observation: Mapping[str, object]) -> RuntimeTurn:
        self.observations.append(dict(observation))
        self.active = True
        self.entered.set()
        if not self.release.wait(timeout=3):
            raise RuntimeError("blocked-turn-test-timeout")
        self.active = False
        return _turn({"kind": "declare_capability", "capabilities": ["sell"]})

    def close(self) -> None:
        self.close_raced_turn = self.active
        super().close()


class TrackingDriver(LoopbackHttpAgentDriver):
    instances: list[TrackingDriver] = []
    close_error: BaseException | None = None

    def __init__(self, endpoint_origin: str, token: str, *, timeout_seconds: float = 60.0) -> None:
        super().__init__(endpoint_origin, token, timeout_seconds=timeout_seconds)
        self.close_calls = 0
        type(self).instances.append(self)

    async def close(self) -> None:
        self.close_calls += 1
        await super().close()
        error = type(self).close_error
        if error is not None:
            raise error


def _start_request() -> DriverRequest:
    return DriverRequest.model_validate(
        {
            "schema_version": "town-agent-driver/1",
            "run_id": RUN_ID,
            "event_id": "01K00000000000000000000002",
            "sequence": 0,
            "participant": {"id": "provider-0", "role": "provider"},
            "profile": {
                "id": "nanda/agent/capability-fulfillment",
                "version": "1",
                "digest": (
                    "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"
                ),
            },
            "observation": {
                "kind": "start",
                "logical_time": 0,
                "allowed_intents": ["declare_capability", "none"],
            },
        }
    )


async def _admit(driver: AgentDriver) -> None:
    await driver.ready(resolve_test_profile("capability-fulfillment"))
    await driver.decide(_start_request())


def _assert_port_released(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
    finally:
        probe.close()


def _artifact_bytes(path: Path) -> bytes:
    return b"".join(item.read_bytes() for item in path.rglob("*") if item.is_file())


def _assert_bearer_absent_from_public_error(error: BaseException) -> None:
    pending = [error]
    seen: set[int] = set()
    values: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.append(repr(current))
        traceback = current.__traceback__
        while traceback is not None:
            if "/tests/" not in traceback.tb_frame.f_code.co_filename:
                values.append(repr(traceback.tb_frame.f_locals))
            traceback = traceback.tb_next
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    assert TOKEN not in " ".join(values)


@pytest.fixture(autouse=True)
def _track_driver(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    TrackingDriver.instances = []
    TrackingDriver.close_error = None
    monkeypatch.setattr(managed_runtime, "LoopbackHttpAgentDriver", TrackingDriver)


@pytest.mark.asyncio
async def test_managed_success_uses_ephemeral_loopback_and_preserves_generation_one_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing the existing driver metadata/result path or leaking the bearer breaks the seam."""
    prepared = FakePreparedRuntime()
    captured_servers: list[Any] = []
    captured_threads: list[Any] = []
    token_requests: list[int] = []
    real_factory = create_local_adapter_server
    real_thread = managed_runtime.Thread

    def token_hex(length: int) -> str:
        token_requests.append(length)
        return TOKEN

    def server_factory(**kwargs: Any) -> Any:
        assert kwargs["token"] == TOKEN
        assert kwargs["port"] == 0
        server = real_factory(**kwargs)
        captured_servers.append(server)
        return server

    def thread_factory(*args: Any, **kwargs: Any) -> Any:
        thread = real_thread(*args, **kwargs)
        captured_threads.append(thread)
        return thread

    monkeypatch.setattr(managed_runtime.secrets, "token_hex", token_hex)
    monkeypatch.setattr(managed_runtime, "create_local_adapter_server", server_factory)
    monkeypatch.setattr(managed_runtime, "Thread", thread_factory)

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert token_requests == [32]
    assert prepared.open_calls == [result.outcome.result.run_id]
    assert prepared.run.observations == [
        {
            "kind": "start",
            "logical_time": 0,
            "allowed_intents": ["declare_capability", "none"],
        },
        {
            "kind": "message",
            "logical_time": 0,
            "allowed_intents": ["send_to_sender", "none"],
            "message": {
                "id": "message-001",
                "sender_id": "requester-0",
                "media_type": "text/plain; charset=utf-8",
                "text": "buy:widget:2",
            },
        },
    ]
    assert all(type(observation) is dict for observation in prepared.run.observations)
    assert prepared.run.close_calls == 1
    assert result.runtime_id == "openclaw"
    assert result.runtime_version == "2026.7.1-2"
    assert result.runtime_display == OPENCLAW_DISPLAY
    assert result.target_id == "buyer"
    assert result.issue_code is None
    assert result.outcome.exit_code == 0
    assert result.outcome.result.execution.status == "completed"
    assert result.outcome.result.evaluation.verdict == "pass"
    assert len(result.outcome.result.evaluation.checks) == 5
    assert {check.status for check in result.outcome.result.evaluation.checks} == {"pass"}
    assert result.outcome.result.target.label == "openclaw:buyer"
    assert result.outcome.result.driver.model_dump(mode="json") == {
        "contract": "town-agent-driver/1",
        "kind": "loopback-http",
        "adapter_instance_id": "openclaw-managed-test",
        "endpoint_origin": f"http://127.0.0.1:{captured_servers[0].server_port}",
    }
    assert captured_servers[0].server_address[0] == "127.0.0.1"
    assert captured_threads and not captured_threads[0].is_alive()
    _assert_port_released(captured_servers[0].server_port)
    assert len(TrackingDriver.instances) == 1
    assert TrackingDriver.instances[0].close_calls == 1
    assert TOKEN not in repr(result)
    assert TOKEN not in repr(captured_servers[0].__dict__)
    assert TOKEN not in repr(TrackingDriver.instances[0])
    assert TOKEN.encode() not in result.outcome.result_bytes
    assert TOKEN.encode() not in _artifact_bytes(result.outcome.output_directory)
    assert not any(TOKEN in value for value in os.environ.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "issue_code"),
    [
        (RuntimeExecutionError("OPENCLAW_TIMEOUT"), "OPENCLAW_TIMEOUT"),
        (
            RuntimeIncompleteError("OPENCLAW_FALLBACK_REPORTED"),
            "OPENCLAW_FALLBACK_REPORTED",
        ),
        (RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID"), "OPENCLAW_ENVELOPE_INVALID"),
        (RuntimeExecutionError("OPENCLAW_TRANSPORT_LOSS"), "OPENCLAW_TRANSPORT_LOSS"),
        (RuntimeExecutionError(TOKEN), "RUNTIME_EXECUTION_FAILED"),
    ],
)
async def test_failed_start_is_one_turn_and_becomes_incomplete_not_target_failure(
    tmp_path: Path,
    failure: BaseException,
    issue_code: str,
) -> None:
    """Retrying runtime uncertainty or scoring it as target failure would overclaim evidence."""
    run = FakeRuntimeRun([failure])
    prepared = FakePreparedRuntime(run)

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert len(run.observations) == 1
    assert run.observations[0]["kind"] == "start"
    assert prepared.open_calls == [result.outcome.result.run_id]
    assert run.close_calls == 1
    assert result.issue_code == issue_code
    assert result.outcome.exit_code == 4
    assert result.outcome.result.execution.status == "incomplete"
    assert result.outcome.result.evaluation.verdict == "inconclusive"
    assert not any(check.status == "fail" for check in result.outcome.result.evaluation.checks)
    assert [item.code for item in result.outcome.result.diagnostics] == ["ADAPTER_INTERNAL"]
    assert issue_code.encode() not in result.outcome.result_bytes
    assert TrackingDriver.instances[0].close_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        RuntimeExecutionError("OPENCLAW_TIMEOUT"),
        RuntimeExecutionError("OPENCLAW_INTENT_INVALID"),
    ],
)
async def test_message_uncertainty_has_no_retry_and_remains_incomplete(
    tmp_path: Path,
    failure: BaseException,
) -> None:
    """A timeout or invalid second envelope must not replay the managed session turn."""
    run = FakeRuntimeRun(
        [
            _turn({"kind": "declare_capability", "capabilities": ["sell"]}),
            failure,
        ]
    )

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=FakePreparedRuntime(run),
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert [item["kind"] for item in run.observations] == ["start", "message"]
    assert run.close_calls == 1
    assert result.issue_code == cast("Any", failure).code
    assert result.outcome.exit_code == 4
    assert result.outcome.result.evaluation.verdict == "inconclusive"
    assert [item.code for item in result.outcome.result.diagnostics] == ["ADAPTER_INTERNAL"]


@pytest.mark.asyncio
async def test_reported_activity_is_sanitized_incomplete(tmp_path: Path) -> None:
    """Treating reported external activity as a valid intent would widen the managed boundary."""
    run = FakeRuntimeRun(
        [_turn({"kind": "declare_capability", "capabilities": ["sell"]}, activity="reported")]
    )

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=FakePreparedRuntime(run),
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert len(run.observations) == 1
    assert result.issue_code == "RUNTIME_ACTIVITY_REPORTED"
    assert result.outcome.exit_code == 4
    assert [item.code for item in result.outcome.result.diagnostics] == ["ADAPTER_INTERNAL"]


@pytest.mark.asyncio
async def test_open_failure_is_sanitized_and_never_creates_a_runtime_handle(
    tmp_path: Path,
) -> None:
    """An open failure must be incomplete without fabricating a closeable session."""
    prepared = FakePreparedRuntime(open_error=RuntimeConfigurationError("OPENCLAW_RUN_DUPLICATE"))

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert len(prepared.open_calls) == 1
    assert prepared.run.observations == []
    assert prepared.run.close_calls == 0
    assert result.issue_code == "OPENCLAW_RUN_DUPLICATE"
    assert result.outcome.exit_code == 4
    assert [item.code for item in result.outcome.result.diagnostics] == ["ADAPTER_INTERNAL"]


def _request_data() -> dict[str, object]:
    return _start_request().model_dump(mode="json")


def _message_request_data() -> dict[str, object]:
    return DriverRequest.model_validate(
        {
            "schema_version": "town-agent-driver/1",
            "run_id": RUN_ID,
            "event_id": "01K00000000000000000000003",
            "sequence": 1,
            "participant": {"id": "provider-0", "role": "provider"},
            "profile": {
                "id": "nanda/agent/capability-fulfillment",
                "version": "1",
                "digest": (
                    "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"
                ),
            },
            "observation": {
                "kind": "message",
                "logical_time": 0,
                "allowed_intents": ["send_to_sender", "none"],
                "message": {
                    "id": "message-001",
                    "sender_id": "requester-0",
                    "media_type": "text/plain; charset=utf-8",
                    "text": "buy:widget:2",
                },
            },
        }
    ).model_dump(mode="json")


def _post(port: int, token: str, request: dict[str, object]) -> tuple[int, bytes]:
    body = json.dumps(request, separators=(",", ":")).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Town-Driver-Contract": "town-agent-driver/1",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
        "Town-Request-Digest": "sha256:" + hashlib.sha256(body).hexdigest(),
    }
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request("POST", "/town-driver/1/decide", body=body, headers=headers)
    response = connection.getresponse()
    response_body = response.read()
    connection.close()
    return response.status, response_body


@pytest.mark.asyncio
async def test_exact_http_replay_is_byte_cached_and_changed_body_conflicts_without_turn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing server replay binding would execute one Town event more than once."""
    run = FakeRuntimeRun([_turn({"kind": "declare_capability", "capabilities": ["sell"]})])
    prepared = FakePreparedRuntime(run)

    def token_hex(_length: int) -> str:
        return TOKEN

    monkeypatch.setattr(managed_runtime.secrets, "token_hex", token_hex)

    async def replay_runner(**kwargs: Any) -> AgentTestOutcome:
        metadata = kwargs["driver_metadata"]
        port = int(str(metadata.endpoint_origin).rsplit(":", 1)[1])
        request = _request_data()
        first_status, first_body = await asyncio.to_thread(_post, port, TOKEN, request)
        replay_status, replay_body = await asyncio.to_thread(_post, port, TOKEN, request)
        changed = json.loads(json.dumps(request))
        changed["observation"]["logical_time"] = 1
        conflict_status, _ = await asyncio.to_thread(_post, port, TOKEN, changed)
        assert first_status == replay_status == 200
        assert replay_body == first_body
        assert conflict_status == 409
        return AgentTestOutcome(
            result=cast("TestResult", object()),
            exit_code=0,
            output_directory=tmp_path,
            result_bytes=b"sentinel",
        )

    monkeypatch.setattr(managed_runtime, "run_agent_test", replay_runner)

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=None,
        base_dir=tmp_path,
    )

    assert result.outcome.result_bytes == b"sentinel"
    assert len(run.observations) == 1
    assert prepared.open_calls == [RUN_ID]
    assert run.close_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_kind", ["start", "message"])
async def test_failed_http_event_replay_is_cached_without_another_runtime_turn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_kind: str,
) -> None:
    """A byte-identical retry after ADAPTER_INTERNAL must not repeat a runtime turn."""
    failure = RuntimeExecutionError("OPENCLAW_TIMEOUT")
    decisions: list[RuntimeTurn | BaseException] = (
        [failure]
        if failed_kind == "start"
        else [
            _turn({"kind": "declare_capability", "capabilities": ["sell"]}),
            failure,
        ]
    )
    run = FakeRuntimeRun(decisions)
    prepared = FakePreparedRuntime(run)

    def token_hex(_length: int) -> str:
        return TOKEN

    monkeypatch.setattr(managed_runtime.secrets, "token_hex", token_hex)

    async def replay_runner(**kwargs: Any) -> AgentTestOutcome:
        metadata = kwargs["driver_metadata"]
        port = int(str(metadata.endpoint_origin).rsplit(":", 1)[1])
        if failed_kind == "message":
            start_status, _ = await asyncio.to_thread(_post, port, TOKEN, _request_data())
            assert start_status == 200
            request = _message_request_data()
        else:
            request = _request_data()
        first_status, first_body = await asyncio.to_thread(_post, port, TOKEN, request)
        replay_status, replay_body = await asyncio.to_thread(_post, port, TOKEN, request)
        changed = json.loads(json.dumps(request))
        changed["observation"]["logical_time"] = 7
        conflict_status, _ = await asyncio.to_thread(_post, port, TOKEN, changed)
        assert first_status == replay_status == 500
        assert replay_body == first_body
        assert conflict_status == 409
        return AgentTestOutcome(
            result=cast("TestResult", object()),
            exit_code=4,
            output_directory=tmp_path,
            result_bytes=b"sentinel",
        )

    monkeypatch.setattr(managed_runtime, "run_agent_test", replay_runner)

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=None,
        base_dir=tmp_path,
    )

    assert result.issue_code == "OPENCLAW_TIMEOUT"
    assert [item["kind"] for item in run.observations] == (
        ["start"] if failed_kind == "start" else ["start", "message"]
    )
    assert prepared.open_calls == [RUN_ID]
    assert run.close_calls == 1


@pytest.mark.asyncio
async def test_cancellation_waits_for_inflight_runtime_worker_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancelled Town task must not close a runtime while its synchronous turn is active."""
    run = BlockingRuntimeRun()
    prepared = FakePreparedRuntime(run)
    cancellation_sent = Event()
    close_before_release: list[int] = []
    captured_servers: list[Any] = []
    real_factory = create_local_adapter_server

    def server_factory(**kwargs: Any) -> Any:
        server = real_factory(**kwargs)
        captured_servers.append(server)
        return server

    async def blocked_runner(**kwargs: Any) -> AgentTestOutcome:
        await _admit(kwargs["driver"])
        raise AssertionError("cancelled admission unexpectedly returned")

    def release_worker() -> None:
        assert run.entered.wait(timeout=2)
        assert cancellation_sent.wait(timeout=2)
        # BaseServer.shutdown can return after its 0.5 s serve-loop poll even
        # while the daemon request worker is still inside RuntimeRun.turn.
        time.sleep(0.75)
        close_before_release.append(run.close_calls)
        run.release.set()

    releaser = Thread(target=release_worker)
    releaser.start()
    monkeypatch.setattr(managed_runtime, "create_local_adapter_server", server_factory)
    monkeypatch.setattr(managed_runtime, "run_agent_test", blocked_runner)

    task = asyncio.create_task(
        managed_runtime.run_managed_agent_test(
            prepared_runtime=prepared,
            profile="capability-fulfillment",
            output_dir=None,
            base_dir=tmp_path,
        )
    )
    assert await asyncio.to_thread(run.entered.wait, 2)
    task.cancel()
    cancellation_sent.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    releaser.join(timeout=2)

    assert close_before_release == [0]
    assert not releaser.is_alive()
    assert run.close_calls == 1
    assert not run.close_raced_turn
    assert list(getattr(captured_servers[0], "_threads", ())) == []
    assert TrackingDriver.instances[0].close_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["open", "turn"])
async def test_runtime_baseexception_is_sanitized_incomplete_without_thread_leak(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    stage: str,
) -> None:
    """Runtime-side BaseException is worker uncertainty, not outer Town cancellation."""
    private = "runtime-baseexception-private-canary"
    if stage == "open":
        prepared = FakePreparedRuntime(open_error=KeyboardInterrupt(private))
        run = prepared.run
    else:
        run = FakeRuntimeRun([SystemExit(private)])
        prepared = FakePreparedRuntime(run)

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    captured = capsys.readouterr()
    assert result.issue_code == "RUNTIME_EXECUTION_FAILED"
    assert result.outcome.exit_code == 4
    assert [item.code for item in result.outcome.result.diagnostics] == ["ADAPTER_INTERNAL"]
    assert private not in captured.out + captured.err + repr(result)
    assert run.close_calls == (0 if stage == "open" else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("runner_fails", [False, True])
async def test_server_listener_is_closed_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner_fails: bool,
) -> None:
    """The reusable shutdown owns listener close after serve_forever starts."""
    close_calls: list[int] = []
    real_factory = create_local_adapter_server

    def server_factory(**kwargs: Any) -> Any:
        server = real_factory(**kwargs)
        real_close = server.server_close

        def tracked_close() -> None:
            close_calls.append(1)
            real_close()

        server.server_close = tracked_close
        return server

    monkeypatch.setattr(managed_runtime, "create_local_adapter_server", server_factory)

    if runner_fails:

        async def fail_runner(**_kwargs: Any) -> AgentTestOutcome:
            raise AgentTestPreAdmissionError("OUTPUT_DIR_INVALID")

        monkeypatch.setattr(managed_runtime, "run_agent_test", fail_runner)
        with pytest.raises(AgentTestPreAdmissionError, match="OUTPUT_DIR_INVALID"):
            await managed_runtime.run_managed_agent_test(
                prepared_runtime=FakePreparedRuntime(),
                profile="capability-fulfillment",
                output_dir=None,
                base_dir=tmp_path,
            )
    else:
        await managed_runtime.run_managed_agent_test(
            prepared_runtime=FakePreparedRuntime(),
            profile="capability-fulfillment",
            output_dir=tmp_path / "result",
            base_dir=tmp_path,
        )

    assert close_calls == [1]


@pytest.mark.asyncio
async def test_long_valid_openclaw_target_gets_deterministic_safe_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid 128-byte OpenClaw ID must not overflow Generation 1 SafeText128."""
    target_id = "a" * 128
    prepared = FakePreparedRuntime()
    prepared.target = RuntimeTarget(target_id, None)
    prepared.target_label = (
        "openclaw:" + "a" * 102 + ":" + hashlib.sha256(target_id.encode()).hexdigest()[:16]
    )
    labels: list[str] = []

    async def capture_runner(**kwargs: Any) -> AgentTestOutcome:
        labels.append(kwargs["target_label"])
        return AgentTestOutcome(
            result=cast("TestResult", object()),
            exit_code=0,
            output_directory=tmp_path,
            result_bytes=b"sentinel",
        )

    monkeypatch.setattr(managed_runtime, "run_agent_test", capture_runner)

    await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=None,
        base_dir=tmp_path,
    )

    expected = prepared.target_label
    assert labels == [expected]
    assert len(labels[0]) == 128


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attribute", "value", "code"),
    [
        ("runtime_id", "openclaw\nspoof", "RUNTIME_METADATA_INVALID"),
        ("runtime_version", " version ", "RUNTIME_METADATA_INVALID"),
        ("target_label", "buyer\nspoof", "TARGET_LABEL_INVALID"),
    ],
)
async def test_invalid_prepared_identity_is_rejected_before_server_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
    value: str,
    code: str,
) -> None:
    """Unchecked runtime identity must not reach listener or result construction."""
    prepared = FakePreparedRuntime()
    setattr(prepared, attribute, value)
    token_calls: list[int] = []

    def token_hex(length: int) -> str:
        token_calls.append(length)
        return TOKEN

    monkeypatch.setattr(managed_runtime.secrets, "token_hex", token_hex)

    with pytest.raises(RuntimeConfigurationError, match=code):
        await managed_runtime.run_managed_agent_test(
            prepared_runtime=prepared,
            profile="capability-fulfillment",
            output_dir=None,
            base_dir=tmp_path,
        )

    assert token_calls == []
    assert TrackingDriver.instances == []


@pytest.mark.asyncio
async def test_synthetic_hermes_runtime_uses_the_generic_managed_path_without_core_edits(
    tmp_path: Path,
) -> None:
    prepared = FakePreparedRuntime()
    prepared.runtime_id = "hermes"
    prepared.runtime_version = "9.4.1"
    prepared.display = RuntimeDisplay("Hermes", "hermes doctor")
    prepared.issue_policy = RuntimeIssuePolicy(execution=frozenset({"HERMES_TIMEOUT"}))
    prepared.adapter_instance_id = "hermes-managed-test"
    prepared.target = RuntimeTarget("merchant", "provider/model")
    prepared.target_label = "hermes:merchant"

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert result.runtime_id == "hermes"
    assert result.runtime_version == "9.4.1"
    assert result.runtime_display == RuntimeDisplay("Hermes", "hermes doctor")
    assert result.target_id == "merchant"
    assert result.outcome.result.target.label == "hermes:merchant"
    assert result.outcome.exit_code == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (RuntimeExecutionError("HERMES_TIMEOUT"), "HERMES_TIMEOUT"),
        (RuntimeExecutionError("HERMES_UNKNOWN"), "RUNTIME_EXECUTION_FAILED"),
        (RuntimeIncompleteError("HERMES_TIMEOUT"), "RUNTIME_INCOMPLETE"),
    ],
)
async def test_synthetic_connector_policy_owns_runtime_issue_codes(
    tmp_path: Path,
    failure: BaseException,
    expected: str,
) -> None:
    prepared = FakePreparedRuntime(FakeRuntimeRun([failure]))
    prepared.runtime_id = "hermes"
    prepared.runtime_version = "9.4.1"
    prepared.display = RuntimeDisplay("Hermes", "hermes doctor")
    prepared.issue_policy = RuntimeIssuePolicy(execution=frozenset({"HERMES_TIMEOUT"}))
    prepared.target = RuntimeTarget("merchant", None)
    prepared.target_label = "hermes:merchant"

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=tmp_path / expected,
        base_dir=tmp_path,
    )

    assert result.issue_code == expected
    assert result.outcome.exit_code == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (RuntimeExecutionError("OPENCLAW_TIMEOUT"), "OPENCLAW_TIMEOUT"),
        (RuntimeIncompleteError("OPENCLAW_TIMEOUT"), "RUNTIME_INCOMPLETE"),
        (RuntimeExecutionError("DRIVER_CLOSE_FAILED"), "RUNTIME_EXECUTION_FAILED"),
        (RuntimeIncompleteError("TARGET_FAILED"), "RUNTIME_INCOMPLETE"),
        (RuntimeExecutionError("SYNTACTICALLY_VALID"), "RUNTIME_EXECUTION_FAILED"),
        (RuntimeIncompleteError("RUNTIME_ACTIVITY_REPORTED"), "RUNTIME_INCOMPLETE"),
        (RuntimeExecutionError("RUNTIME_INTENT_INVALID"), "RUNTIME_EXECUTION_FAILED"),
    ],
)
async def test_runtime_issue_codes_are_owned_and_class_aware(
    tmp_path: Path,
    failure: BaseException,
    expected: str,
) -> None:
    """Runtime data cannot impersonate cleanup stages or target verdicts."""
    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=FakePreparedRuntime(FakeRuntimeRun([failure])),
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert result.issue_code == expected
    assert result.outcome.exit_code == 4


Failure = tuple[type[BaseException], str]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_type", "message"),
    [
        (asyncio.CancelledError, ""),
        (KeyboardInterrupt, "interrupt-private-canary"),
        (RuntimeError, "publication-private-canary"),
    ],
)
async def test_runner_failure_always_closes_port_thread_runtime_and_driver_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
    message: str,
) -> None:
    """Cancellation, SIGINT, or publication failure must not orphan managed resources."""
    run = FakeRuntimeRun()
    prepared = FakePreparedRuntime(run)
    captured_servers: list[Any] = []
    captured_threads: list[Any] = []
    real_factory = create_local_adapter_server
    real_thread = managed_runtime.Thread

    def server_factory(**kwargs: Any) -> Any:
        server = real_factory(**kwargs)
        captured_servers.append(server)
        return server

    def thread_factory(*args: Any, **kwargs: Any) -> Any:
        thread = real_thread(*args, **kwargs)
        captured_threads.append(thread)
        return thread

    async def failing_runner(**kwargs: Any) -> AgentTestOutcome:
        await _admit(kwargs["driver"])
        raise failure_type(message)

    def token_hex(_length: int) -> str:
        return TOKEN

    monkeypatch.setattr(managed_runtime, "create_local_adapter_server", server_factory)
    monkeypatch.setattr(managed_runtime, "Thread", thread_factory)
    monkeypatch.setattr(managed_runtime, "run_agent_test", failing_runner)
    monkeypatch.setattr(managed_runtime.secrets, "token_hex", token_hex)

    with pytest.raises(failure_type) as caught:
        await managed_runtime.run_managed_agent_test(
            prepared_runtime=prepared,
            profile="capability-fulfillment",
            output_dir=None,
            base_dir=tmp_path,
        )

    assert run.close_calls == 1
    assert TrackingDriver.instances[0].close_calls == 1
    assert captured_threads and not captured_threads[0].is_alive()
    _assert_port_released(captured_servers[0].server_port)
    _assert_bearer_absent_from_public_error(caught.value)


@pytest.mark.asyncio
async def test_preflight_failure_still_closes_server_thread_and_driver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure before admission must close resources without opening a runtime run."""
    prepared = FakePreparedRuntime()
    captured_servers: list[Any] = []
    captured_threads: list[Any] = []
    real_factory = create_local_adapter_server
    real_thread = managed_runtime.Thread

    def server_factory(**kwargs: Any) -> Any:
        server = real_factory(**kwargs)
        captured_servers.append(server)
        return server

    def thread_factory(*args: Any, **kwargs: Any) -> Any:
        thread = real_thread(*args, **kwargs)
        captured_threads.append(thread)
        return thread

    async def preflight_failure(**_kwargs: Any) -> AgentTestOutcome:
        raise AgentTestPreAdmissionError("OUTPUT_DIR_INVALID")

    monkeypatch.setattr(managed_runtime, "create_local_adapter_server", server_factory)
    monkeypatch.setattr(managed_runtime, "Thread", thread_factory)
    monkeypatch.setattr(managed_runtime, "run_agent_test", preflight_failure)

    with pytest.raises(AgentTestPreAdmissionError, match="OUTPUT_DIR_INVALID"):
        await managed_runtime.run_managed_agent_test(
            prepared_runtime=prepared,
            profile="capability-fulfillment",
            output_dir=None,
            base_dir=tmp_path,
        )

    assert prepared.open_calls == []
    assert prepared.run.close_calls == 0
    assert TrackingDriver.instances[0].close_calls == 1
    assert captured_threads and not captured_threads[0].is_alive()
    _assert_port_released(captured_servers[0].server_port)


@pytest.mark.asyncio
async def test_real_result_publication_failure_closes_runtime_and_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A terminal artifact write failure must not bypass managed cleanup."""
    run = FakeRuntimeRun()
    prepared = FakePreparedRuntime(run)
    captured_servers: list[Any] = []
    real_factory = create_local_adapter_server

    def server_factory(**kwargs: Any) -> Any:
        server = real_factory(**kwargs)
        captured_servers.append(server)
        return server

    def fail_publication(_self: ArtifactDirectory, _result: TestResult) -> bytes:
        raise OSError("publication-private-canary")

    monkeypatch.setattr(managed_runtime, "create_local_adapter_server", server_factory)
    monkeypatch.setattr(ArtifactDirectory, "write_result", fail_publication)

    with pytest.raises(OSError, match="publication-private-canary"):
        await managed_runtime.run_managed_agent_test(
            prepared_runtime=prepared,
            profile="capability-fulfillment",
            output_dir=tmp_path / "result",
            base_dir=tmp_path,
        )

    assert [item["kind"] for item in run.observations] == ["start", "message"]
    assert run.close_calls == 1
    assert TrackingDriver.instances[0].close_calls == 1
    _assert_port_released(captured_servers[0].server_port)


@pytest.mark.asyncio
async def test_cleanup_failures_are_safe_issue_codes_without_mutating_the_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleanup uncertainty belongs in wrapper diagnostics, not Generation 1 evidence."""
    run = FakeRuntimeRun(close_error=RuntimeError("runtime-close-private-canary"))
    prepared = FakePreparedRuntime(run)
    real_factory = create_local_adapter_server
    captured_servers: list[Any] = []

    def server_factory(**kwargs: Any) -> Any:
        server = real_factory(**kwargs)
        real_shutdown = server.shutdown

        def failing_shutdown() -> None:
            real_shutdown()
            raise RuntimeError("server-shutdown-private-canary")

        server.shutdown = failing_shutdown
        captured_servers.append(server)
        return server

    monkeypatch.setattr(managed_runtime, "create_local_adapter_server", server_factory)

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=prepared,
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert result.outcome.exit_code == 0
    assert result.outcome.result.evaluation.verdict == "pass"
    assert result.issue_code == "SERVER_SHUTDOWN_FAILED"
    assert run.close_calls == 1
    assert TrackingDriver.instances[0].close_calls == 1
    _assert_port_released(captured_servers[0].server_port)
    serialized = repr(result) + result.outcome.result_bytes.decode()
    assert "server-shutdown-private-canary" not in serialized
    assert "runtime-close-private-canary" not in serialized


@pytest.mark.asyncio
async def test_driver_close_failure_is_called_once_and_reported_safely(
    tmp_path: Path,
) -> None:
    """Retrying a failed driver close could duplicate transport cleanup side effects."""
    TrackingDriver.close_error = RuntimeError("driver-close-private-canary")

    result = await managed_runtime.run_managed_agent_test(
        prepared_runtime=FakePreparedRuntime(),
        profile="capability-fulfillment",
        output_dir=tmp_path / "result",
        base_dir=tmp_path,
    )

    assert TrackingDriver.instances[0].close_calls == 1
    assert result.issue_code == "DRIVER_CLOSE_FAILED"
    assert result.outcome.exit_code == 0
    assert [item.code for item in result.outcome.result.diagnostics] == ["DRIVER_CLOSE_FAILED"]
    assert "driver-close-private-canary" not in repr(result)
