# SPDX-License-Identifier: Apache-2.0
"""CLI contract tests for the frozen local agent-test journey."""

from __future__ import annotations

import builtins
import io
import json
import os
import re
import signal
import subprocess
import sys
import threading
from collections.abc import Generator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, NoReturn, cast

import pytest
from nest_core.agent_test.driver import (
    DriverCompatibilityError,
    DriverConfigurationError,
    DriverContractError,
    DriverIncompleteError,
    TownDriverError,
)
from nest_core.agent_test.models import TestResult
from nest_core.agent_test.profiles import resolve_test_profile
from nest_core.agent_test.runner import (
    AgentTestOutcome,
    AgentTestPreAdmissionError,
    AgentTestTownError,
)
from nest_core.agent_test.runtime_connectors import (
    RuntimeConfigurationError,
    RuntimeDisplay,
    RuntimeExecutionError,
    RuntimeIncompleteError,
    RuntimeIssuePolicy,
    RuntimeProbe,
    RuntimeTarget,
)
from nest_core.cli import app
from typer.testing import CliRunner

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
TOKEN = "0123456789abcdef" * 4
PROFILE_ALIAS = "capability-fulfillment"
PROFILE_EXACT = "nanda/agent/capability-fulfillment@1"
ENDPOINT = "http://127.0.0.1:8787"
PLAIN_HELP_ENV: dict[str, str | None] = {
    "FORCE_COLOR": None,
    "GITHUB_ACTIONS": None,
    "TERM": "dumb",
}
OPENCLAW_VERSION = "2026.7.1-2"
OPENCLAW_TEST_POLICY = RuntimeIssuePolicy(
    configuration=frozenset(
        {
            "OPENCLAW_MODEL_INVALID",
            "OPENCLAW_PLATFORM_UNSUPPORTED",
            "OPENCLAW_REMOTE_DISPATCH",
        }
    ),
    incomplete=frozenset({"OPENCLAW_GATEWAY_UNAVAILABLE"}),
    execution=frozenset({"OPENCLAW_GATEWAY_INVALID"}),
)


class _FakePreparedRuntime:
    def __init__(
        self,
        runtime_id: str,
        runtime_version: str,
        display: RuntimeDisplay,
        target: RuntimeTarget,
        issue_policy: RuntimeIssuePolicy,
    ) -> None:
        self.runtime_id = runtime_id
        self.runtime_version = runtime_version
        self.display = display
        self.target = target
        self.issue_policy = issue_policy
        self.target_label = f"{runtime_id}:{target.id}"
        self.adapter_instance_id = f"{runtime_id}:cli-test"


class _FakeConnector:
    def __init__(
        self,
        runtime_id: str,
        targets: tuple[RuntimeTarget, ...],
        *,
        probe: RuntimeProbe | None | bool = True,
        probe_error: BaseException | None = None,
        list_error: BaseException | None = None,
        prepare_error: BaseException | None = None,
        issue_policy: RuntimeIssuePolicy | None = None,
        prepared_issue_policy: RuntimeIssuePolicy | None = None,
    ) -> None:
        self.runtime_id = runtime_id
        self.issue_policy = (
            issue_policy
            if issue_policy is not None
            else OPENCLAW_TEST_POLICY
            if runtime_id == "openclaw"
            else RuntimeIssuePolicy()
        )
        self.prepared_issue_policy = prepared_issue_policy
        self.display = RuntimeDisplay(
            "OpenClaw" if runtime_id == "openclaw" else runtime_id.title(),
            ("openclaw gateway status" if runtime_id == "openclaw" else f"{runtime_id} doctor"),
        )
        self.targets = targets
        self.probe_value = (
            RuntimeProbe(
                runtime_id,
                Path(f"/opt/{runtime_id}"),
                OPENCLAW_VERSION,
                self.display,
            )
            if probe is True
            else probe
        )
        self.probe_error = probe_error
        self.list_error = list_error
        self.prepare_error = prepare_error
        self.probe_calls = 0
        self.list_targets_calls = 0
        self.prepare_calls: list[tuple[RuntimeProbe, RuntimeTarget, str | None]] = []

    def probe(self) -> RuntimeProbe | None:
        self.probe_calls += 1
        if self.probe_error is not None:
            raise self.probe_error
        assert self.probe_value is None or isinstance(self.probe_value, RuntimeProbe)
        return self.probe_value

    def list_targets(self, probe: RuntimeProbe) -> tuple[RuntimeTarget, ...]:
        self.list_targets_calls += 1
        if self.list_error is not None:
            raise self.list_error
        assert probe is self.probe_value
        return self.targets

    def prepare(
        self,
        probe: RuntimeProbe,
        target: RuntimeTarget,
        model_override: str | None,
    ) -> _FakePreparedRuntime:
        self.prepare_calls.append((probe, target, model_override))
        if self.prepare_error is not None:
            raise self.prepare_error
        return _FakePreparedRuntime(
            self.runtime_id,
            probe.version,
            probe.display,
            target,
            self.prepared_issue_policy or self.issue_policy,
        )


class _InterruptServer(ThreadingHTTPServer):
    daemon_threads = True
    message_seen: threading.Event
    release_message: threading.Event
    observations: list[dict[str, Any]]


class _InterruptHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        profile = resolve_test_profile(PROFILE_ALIAS)
        self._send_json(
            {
                "schema_version": "town-agent-driver-ready/1",
                "adapter_instance_id": "adapter:interrupt-test",
                "contracts": ["town-agent-driver/1"],
                "profiles": [profile.reference.model_dump(mode="json")],
                "accepting_runs": True,
                "limits": {
                    "max_active_runs": 1,
                    "max_request_bytes": 65536,
                    "max_response_bytes": 65536,
                },
            }
        )

    def do_POST(self) -> None:  # noqa: N802
        import hashlib

        server = cast("_InterruptServer", self.server)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        request: dict[str, Any] = json.loads(body)
        observation: dict[str, Any] = request["observation"]
        server.observations.append(observation)
        kind = observation["kind"]
        if kind == "message":
            server.message_seen.set()
            server.release_message.wait(timeout=20)
        if kind == "start":
            intent: dict[str, object] = {
                "kind": "declare_capability",
                "capabilities": ["sell"],
            }
        elif kind == "message":
            intent = {
                "kind": "send_to_sender",
                "media_type": "text/plain; charset=utf-8",
                "text": "sold:widget:2",
            }
        else:
            intent = {"kind": "none"}
        self._send_json(
            {
                "schema_version": "town-agent-driver/1",
                "run_id": request["run_id"],
                "event_id": request["event_id"],
                "sequence": request["sequence"],
                "adapter_instance_id": "adapter:interrupt-test",
                "request_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                "intent": intent,
            }
        )

    def _send_json(self, value: object) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Town-Driver-Contract", "town-agent-driver/1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass


@contextmanager
def _serve_interrupt_adapter() -> Generator[_InterruptServer]:
    server = _InterruptServer(("127.0.0.1", 0), _InterruptHandler)
    server.message_seen = threading.Event()
    server.release_message = threading.Event()
    server.observations = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release_message.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _result_data(exit_code: int) -> dict[str, Any]:
    fixture = "result-incomplete.json" if exit_code in {4, 130} else "result-pass.json"
    data: dict[str, Any] = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
    check_ids = (
        "driver.contract",
        "registry.provider-registered",
        "registry.provider-discovered",
        "delivery.request-routed",
        "capability.synthetic-request-fulfilled",
    )
    not_tested_claims = (
        "nanda.index.persistent-discovery",
        "nanda.comms.real-network-delivery",
        "nanda.identity",
        "nanda.authorization",
        "nanda.trust",
        "nanda.payments",
        "nanda.negotiation",
        "agent.safety",
        "agent.long-term-reliability",
    )
    data["coverage"] = [item for item in data["coverage"] if item["status"] != "not_tested"] + [
        {
            "claim": claim,
            "status": "not_tested",
            "reason_code": "OUT_OF_PROFILE",
            "evidence_refs": [],
        }
        for claim in not_tested_claims
    ]
    if exit_code in {4, 130}:
        data["evaluation"]["checks"] = [
            data["evaluation"]["checks"][0],
            *(
                {
                    "id": check_id,
                    "required": True,
                    "status": "not_tested",
                    "summary": "This stage was not reached",
                    "evidence_refs": [],
                }
                for check_id in check_ids[1:]
            ),
        ]
    else:
        data["evaluation"]["checks"] = [
            {
                "id": check_id,
                "required": True,
                "status": "pass",
                "summary": "The expected local evidence was observed",
                "evidence_refs": ["trace.jsonl#seq=1"],
            }
            for check_id in check_ids
        ]
    if exit_code == 1:
        data["evaluation"]["verdict"] = "fail"
        data["evaluation"]["checks"][-1].update(
            status="fail", summary="The adapter returned the wrong synthetic response"
        )
    elif exit_code == 3:
        data["execution"]["status"] = "error"
        data["evaluation"] = {"verdict": "not_evaluated", "checks": []}
        data["coverage"] = [
            {
                "claim": "town.agent-driver.loopback",
                "status": "unknown",
                "reason_code": "TOWN_EXECUTION_ERROR",
                "evidence_refs": [],
            }
        ]
        data["diagnostics"] = [
            {
                "code": "TOWN_EXECUTION_ERROR",
                "stage": "town",
                "severity": "error",
                "summary": "Town could not complete the dedicated scenario",
                "next": None,
            }
        ]
    elif exit_code == 130:
        data["diagnostics"] = [
            {
                "code": "USER_INTERRUPTED",
                "stage": "driver",
                "severity": "warning",
                "summary": "The agent-test run was interrupted by the user",
                "next": None,
            }
        ]
    return data


def _outcome(tmp_path: Path, exit_code: int) -> AgentTestOutcome:
    result = TestResult.model_validate(_result_data(exit_code))
    output_directory = tmp_path / f"out-{exit_code}"
    output_directory.mkdir(exist_ok=True)
    result_bytes = (
        json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    (output_directory / "result.json").write_bytes(result_bytes)
    for artifact in result.artifacts:
        if artifact.kind == "trace":
            (output_directory / artifact.path).write_text(
                '{"ts":0.0,"agent":"provider-0","kind":"test.driver.run_admitted"}\n',
                encoding="utf-8",
            )
    return AgentTestOutcome(
        result=result,
        exit_code=exit_code,
        output_directory=output_directory,
        result_bytes=result_bytes,
    )


def _invoke(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    outcome_exit: int = 0,
    profile: str = PROFILE_ALIAS,
    extra: list[str] | None = None,
) -> tuple[Any, list[dict[str, object]], AgentTestOutcome]:
    import nest_core.agent_test.cli as agent_cli

    outcome = _outcome(tmp_path, outcome_exit)
    calls: list[dict[str, object]] = []

    async def fake_execute(**kwargs: object) -> AgentTestOutcome:
        calls.append(kwargs)
        return outcome

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fake_execute)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    args = ["test", "agent", "--endpoint", ENDPOINT]
    if profile != PROFILE_ALIAS:
        args.extend(["--profile", profile])
    if extra:
        args.extend(extra)
    return runner.invoke(app, args, color=False), calls, outcome


def _invoke_managed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    target: str = "everett",
    outcome_exit: int = 0,
    issue_code: str | None = None,
    connectors: tuple[_FakeConnector, ...] | None = None,
    extra: list[str] | None = None,
) -> tuple[Any, list[dict[str, object]], AgentTestOutcome, tuple[_FakeConnector, ...]]:
    import nest_core.agent_test.cli as agent_cli
    import nest_core.agent_test.managed_runtime as managed_runtime
    from nest_core.agent_test.managed_runtime import ManagedAgentTestOutcome

    outcome = _outcome(tmp_path, outcome_exit)
    selected_connectors = connectors or (
        _FakeConnector("openclaw", (RuntimeTarget(target, "provider/configured"),)),
    )
    calls: list[dict[str, object]] = []

    async def fake_managed(**kwargs: object) -> ManagedAgentTestOutcome:
        calls.append(kwargs)
        prepared = cast("_FakePreparedRuntime", kwargs["prepared_runtime"])
        return ManagedAgentTestOutcome(
            outcome=outcome,
            runtime_id=prepared.runtime_id,
            runtime_version=prepared.runtime_version,
            runtime_display=prepared.display,
            target_id=target,
            issue_code=issue_code,
        )

    monkeypatch.setattr(
        agent_cli,
        "_available_runtime_connectors",
        lambda: selected_connectors,
        raising=False,
    )
    monkeypatch.setattr(managed_runtime, "run_managed_agent_test", fake_managed)
    args = ["test", "agent", target]
    if extra:
        args.extend(extra)
    return runner.invoke(app, args, color=False), calls, outcome, selected_connectors


def test_test_and_agent_help_freeze_the_additive_command_tree() -> None:
    test_help = runner.invoke(app, ["test", "--help"], color=False, env=PLAIN_HELP_ENV)
    agent_help = runner.invoke(app, ["test", "agent", "--help"], color=False, env=PLAIN_HELP_ENV)

    assert test_help.exit_code == 0
    assert "Test an existing agent with Town." in test_help.stdout
    assert "agent" in test_help.stdout
    assert agent_help.exit_code == 0
    normalized = " ".join(agent_help.stdout.replace("│", "").split())
    assert "Usage: nest test agent [OPTIONS] [TARGET]" in normalized
    assert "Run a basic local agent test with a supported managed runtime or adapter." in (
        normalized
    )
    for expected in (
        "TARGET",
        "Agent name in the selected runtime.",
        "--runtime",
        "Auto-detected when omitted; currently OpenClaw on macOS or Linux.",
        "--model",
        "Optional model override for this run.",
        "--profile",
        "--endpoint",
        "--target-label",
        "--token-env",
        "--format",
        "[human|json]",
        "--output-dir",
        ".town/runs/<run-id>",
        "--no-color",
        "--verbose",
    ):
        assert expected in normalized
    advanced_panel = normalized.index("Advanced adapter options")
    for advanced in ("--profile", "--endpoint", "--target-label", "--token-env"):
        assert normalized.index(advanced) > advanced_panel
    for forbidden in (
        "capability-fulfillment",
        PROFILE_EXACT,
        "sha256:",
        "bearer",
        "127.0.0.1",
        "[::1]",
        "adapter instance",
    ):
        assert forbidden.lower() not in normalized.lower()


def test_agent_help_is_plain_when_color_is_disabled() -> None:
    result = runner.invoke(app, ["test", "agent", "--help"], color=False, env=PLAIN_HELP_ENV)

    assert result.exit_code == 0
    assert "\x1b[" not in result.stdout


def test_cli_import_keeps_endpoint_and_managed_runtime_implementation_lazy() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import nest_core.cli; "
                "assert 'nest_core.agent_test.http_driver' not in sys.modules; "
                "assert 'nest_core.agent_test.runner' not in sys.modules; "
                "assert 'nest_core.agent_test.openclaw_runtime' not in sys.modules; "
                "assert 'nest_core.agent_test.managed_runtime' not in sys.modules"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_interrupt_during_lazy_import_is_safe_exit_130_without_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original_import = builtins.__import__

    def interrupt_driver_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if (
            level == 1
            and name == "driver"
            and globals is not None
            and globals.get("__name__") == "nest_core.agent_test.cli"
        ):
            raise KeyboardInterrupt("interrupt-import-canary")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    monkeypatch.setattr(builtins, "__import__", interrupt_driver_import)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 130
    assert result.stdout_bytes == b""
    assert "RESULT: INTERRUPTED" in result.stderr
    assert "interrupt-import-canary" not in result.stderr
    assert "TOWN_AGENT_TOKEN" not in os.environ
    assert not (tmp_path / ".town").exists()


def test_interrupt_during_profile_resolution_is_safe_exit_130_without_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.profiles as profiles

    def interrupt_profile(_reference: str) -> NoReturn:
        raise KeyboardInterrupt("interrupt-profile-canary")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    monkeypatch.setattr(profiles, "resolve_test_profile", interrupt_profile)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 130
    assert result.stdout_bytes == b""
    assert "RESULT: INTERRUPTED" in result.stderr
    assert "interrupt-profile-canary" not in result.stderr
    assert "TOWN_AGENT_TOKEN" not in os.environ
    assert not (tmp_path / ".town").exists()


def test_interrupt_during_output_directory_validation_is_safe_exit_130_without_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli

    def interrupt_validation(_output_dir: Path | None) -> NoReturn:
        raise KeyboardInterrupt("interrupt-validation-canary")

    target = tmp_path / "bundle"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    monkeypatch.setattr(agent_cli, "_validate_output_directory", interrupt_validation)
    result = runner.invoke(
        app,
        [
            "test",
            "agent",
            "--endpoint",
            ENDPOINT,
            "--output-dir",
            str(target),
            "--format",
            "json",
        ],
        color=False,
    )

    assert result.exit_code == 130
    assert result.stdout_bytes == b""
    assert "RESULT: INTERRUPTED" in result.stderr
    assert "interrupt-validation-canary" not in result.stderr
    assert "TOWN_AGENT_TOKEN" not in os.environ
    assert not target.exists()
    assert not (tmp_path / ".town").exists()


@pytest.mark.parametrize(
    ("mode_args", "progress_name"),
    [
        (["--endpoint", ENDPOINT], "_write_endpoint_progress"),
        (["everett"], "_write_managed_progress"),
    ],
)
def test_interrupt_during_progress_is_safe_exit_130_without_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode_args: list[str],
    progress_name: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    def interrupt_progress(**_kwargs: object) -> NoReturn:
        raise KeyboardInterrupt("interrupt-progress-canary")

    connector = _FakeConnector("openclaw", (RuntimeTarget("everett", None),))
    monkeypatch.setattr(
        agent_cli,
        "_available_runtime_connectors",
        lambda: (connector,),
        raising=False,
    )
    monkeypatch.setattr(agent_cli, progress_name, interrupt_progress)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", *mode_args, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 130
    assert result.stdout_bytes == b""
    assert "RESULT: INTERRUPTED" in result.stderr
    assert "interrupt-progress-canary" not in result.stderr
    assert not (tmp_path / ".town").exists()


def test_alias_and_exact_profile_reference_reach_the_same_frozen_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    default, default_calls, _ = _invoke(monkeypatch, tmp_path)
    exact, exact_calls, _ = _invoke(
        monkeypatch,
        tmp_path,
        extra=["--profile", PROFILE_EXACT],
    )

    assert default.exit_code == exact.exit_code == 0
    assert default.stdout == exact.stdout
    assert default_calls[0]["profile"] == PROFILE_ALIAS
    assert exact_calls[0]["profile"] == PROFILE_EXACT


def test_managed_default_and_exact_profile_reach_the_same_frozen_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    default, default_calls, _, _ = _invoke_managed(monkeypatch, tmp_path)
    exact, exact_calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        extra=["--profile", PROFILE_EXACT],
    )

    assert default.exit_code == exact.exit_code == 0
    assert default.stdout == exact.stdout
    assert default_calls[0]["profile"] == PROFILE_ALIAS
    assert exact_calls[0]["profile"] == PROFILE_EXACT


def test_managed_target_detects_exactly_one_connector_and_forwards_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = RuntimeTarget("everett", "provider/configured")
    connector = _FakeConnector("openclaw", (RuntimeTarget("other", None), target))

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
        extra=["--model", "provider/override"],
    )

    assert result.exit_code == 0
    assert connector.probe_calls == 1
    assert connector.list_targets_calls == 1
    assert connector.prepare_calls == [(connector.probe_value, target, "provider/override")]
    assert calls[0]["prepared_runtime"] is not None
    assert calls[0]["base_dir"] == Path.cwd()


def test_explicit_runtime_probes_no_other_connector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    requested = _FakeConnector("openclaw", (RuntimeTarget("everett", None),))
    unrelated = _FakeConnector("other", (RuntimeTarget("everett", None),))

    result, _, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(requested, unrelated),
        extra=["--runtime", "openclaw"],
    )

    assert result.exit_code == 0
    assert requested.probe_calls == requested.list_targets_calls == 1
    assert unrelated.probe_calls == unrelated.list_targets_calls == 0


def test_missing_runtime_explains_install_version_and_path_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    connector = _FakeConnector("openclaw", (), probe=None)

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
        extra=["--format", "json"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert calls == []
    assert "Configuration error: RUNTIME_NOT_FOUND" in result.stderr
    assert "Install a supported managed runtime version" in result.stderr
    assert "PATH" in result.stderr
    assert "--runtime openclaw" not in result.stderr
    assert not (tmp_path / ".town").exists()


def test_unsupported_openclaw_platform_exits_2_before_inference_with_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    connector = _FakeConnector(
        "openclaw",
        (),
        probe_error=RuntimeConfigurationError("OPENCLAW_PLATFORM_UNSUPPORTED"),
    )

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
        extra=["--format", "json"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert calls == []
    assert "Configuration error: OPENCLAW_PLATFORM_UNSUPPORTED" in result.stderr
    assert "macOS or Linux" in result.stderr
    assert "Native Windows is not supported" in result.stderr
    assert "No agent/model turn was started" in result.stderr
    assert not (tmp_path / ".town").exists()


def test_remote_openclaw_route_exits_2_with_local_mode_recovery_before_inference(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    connector = _FakeConnector(
        "openclaw",
        (),
        probe_error=RuntimeConfigurationError("OPENCLAW_REMOTE_DISPATCH"),
    )

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
        extra=["--format", "json"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert calls == []
    assert "Configuration error: OPENCLAW_REMOTE_DISPATCH" in result.stderr
    assert "openclaw config get gateway.mode --json" in result.stderr
    assert 'must be exactly `"local"`' in result.stderr
    assert "OPENCLAW_GATEWAY_URL" in result.stderr
    assert "No agent/model turn was started" in result.stderr
    assert not (tmp_path / ".town").exists()


def test_missing_target_points_to_openclaw_agent_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    connector = _FakeConnector("openclaw", (RuntimeTarget("other", None),))

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
        extra=["--format", "json"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert calls == []
    assert "Configuration error: TARGET_NOT_FOUND" in result.stderr
    assert "openclaw agents list" in result.stderr
    assert "--runtime openclaw" not in result.stderr
    assert not (tmp_path / ".town").exists()


def test_ambiguous_runtime_offers_copy_ready_explicit_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    connectors = (
        _FakeConnector("openclaw", (RuntimeTarget("everett", None),)),
        _FakeConnector("other", (RuntimeTarget("everett", None),)),
    )

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=connectors,
        extra=["--format", "json"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert calls == []
    assert "Configuration error: RUNTIME_AMBIGUOUS" in result.stderr
    assert "Next: Choose one runtime explicitly:" in result.stderr
    assert "nest test agent everett --runtime openclaw" in result.stderr
    assert "nest test agent everett --runtime other" in result.stderr
    assert not (tmp_path / ".town").exists()


def test_ambiguous_target_does_not_claim_an_explicit_runtime_will_fix_duplicates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    connector = _FakeConnector(
        "openclaw",
        (RuntimeTarget("everett", None), RuntimeTarget("everett", None)),
    )

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
        extra=["--format", "json"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert calls == []
    assert "Configuration error: TARGET_AMBIGUOUS" in result.stderr
    assert "duplicate" in result.stderr.lower()
    assert "openclaw agents list" in result.stderr
    assert "--runtime openclaw" not in result.stderr
    assert not (tmp_path / ".town").exists()


def test_endpoint_mode_bypasses_all_runtime_probes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector("openclaw", (RuntimeTarget("everett", None),))
    monkeypatch.setattr(
        agent_cli,
        "_available_runtime_connectors",
        lambda: (connector,),
        raising=False,
    )

    result, calls, _ = _invoke(monkeypatch, tmp_path)

    assert result.exit_code == 0
    assert len(calls) == 1
    assert connector.probe_calls == connector.list_targets_calls == 0


@pytest.mark.parametrize("output_format", ["human", "json"])
def test_managed_mode_never_prompts_for_runtime_or_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    output_format: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    def reject_prompt(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("the CLI must not prompt")

    monkeypatch.setattr(agent_cli.typer, "prompt", reject_prompt)
    result, _, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        extra=["--format", output_format],
    )

    assert result.exit_code == 0


def test_no_target_without_endpoint_exits_2_before_probe_or_token_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector("openclaw", (RuntimeTarget("everett", None),))
    monkeypatch.setattr(
        agent_cli,
        "_available_runtime_connectors",
        lambda: (connector,),
        raising=False,
    )
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["test", "agent", "--format", "json"], color=False)

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert "nest test agent TARGET" in result.stderr
    assert os.environ["TOWN_AGENT_TOKEN"] == TOKEN
    assert connector.probe_calls == connector.list_targets_calls == 0
    assert not (tmp_path / ".town").exists()


@pytest.mark.parametrize(
    "conflict",
    [
        ["everett"],
        ["--runtime", "openclaw"],
        ["--model", "provider/model"],
    ],
)
def test_endpoint_conflicts_exit_2_before_probe_or_token_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    conflict: list[str],
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector("openclaw", (RuntimeTarget("everett", None),))
    monkeypatch.setattr(
        agent_cli,
        "_available_runtime_connectors",
        lambda: (connector,),
        raising=False,
    )
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", *conflict, "--endpoint", ENDPOINT, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert "--endpoint cannot be combined" in result.stderr
    assert os.environ["TOWN_AGENT_TOKEN"] == TOKEN
    assert connector.probe_calls == connector.list_targets_calls == 0
    assert not (tmp_path / ".town").exists()


@pytest.mark.parametrize(
    "adapter_option",
    [["--token-env", "PRIVATE_TOKEN"], ["--target-label", "private-label"]],
)
def test_managed_adapter_options_exit_2_without_consuming_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    adapter_option: list[str],
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector("openclaw", (RuntimeTarget("everett", None),))
    monkeypatch.setattr(
        agent_cli,
        "_available_runtime_connectors",
        lambda: (connector,),
        raising=False,
    )
    monkeypatch.setenv("PRIVATE_TOKEN", TOKEN)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", "everett", *adapter_option, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert "only valid with --endpoint" in result.stderr
    assert os.environ["PRIVATE_TOKEN"] == TOKEN
    assert connector.probe_calls == connector.list_targets_calls == 0
    assert not (tmp_path / ".town").exists()


@pytest.mark.parametrize(
    ("error", "exit_code", "expected"),
    [
        (RuntimeConfigurationError("OPENCLAW_MODEL_INVALID"), 2, "Configuration error"),
        (RuntimeIncompleteError("OPENCLAW_GATEWAY_UNAVAILABLE"), 4, "RESULT: INCOMPLETE"),
        (RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID"), 3, "RESULT: ERROR"),
    ],
)
def test_managed_pre_admission_error_mapping_has_empty_stdout_and_no_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: RuntimeError,
    exit_code: int,
    expected: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector(
        "openclaw",
        (RuntimeTarget("everett", None),),
        prepare_error=error,
    )
    monkeypatch.setattr(
        agent_cli,
        "_available_runtime_connectors",
        lambda: (connector,),
        raising=False,
    )
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", "everett", "--format", "json"],
        color=False,
    )

    assert result.exit_code == exit_code
    assert result.stdout_bytes == b""
    assert expected in result.stderr
    assert str(error) in result.stderr
    assert "Next:" in result.stderr
    if str(error) == "OPENCLAW_GATEWAY_UNAVAILABLE":
        assert "openclaw gateway" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_synthetic_managed_connector_controls_display_and_recovery_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    connector = _FakeConnector("hermes", (RuntimeTarget("everett", None),))

    result, _, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
        issue_code="HERMES_TIMEOUT",
    )

    assert result.exit_code == 0
    assert f"Hermes {OPENCLAW_VERSION}" in result.stderr
    assert "hermes doctor" in result.stderr
    assert "--runtime hermes" in result.stderr
    assert "OpenClaw" not in result.stderr


@pytest.mark.parametrize(
    ("error", "exit_code", "headline", "safe_code"),
    [
        (
            RuntimeConfigurationError("PRIVATE\nCONFIG"),
            2,
            "Configuration error",
            "RUNTIME_CONFIGURATION_FAILED",
        ),
        (
            RuntimeIncompleteError("PRIVATE\nINCOMPLETE"),
            4,
            "RESULT: INCOMPLETE",
            "RUNTIME_INCOMPLETE",
        ),
        (
            RuntimeExecutionError("PRIVATE\nEXECUTION"),
            3,
            "RESULT: ERROR",
            "RUNTIME_EXECUTION_FAILED",
        ),
    ],
)
def test_managed_exception_class_controls_exit_and_unsafe_codes_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: RuntimeError,
    exit_code: int,
    headline: str,
    safe_code: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector(
        "hermes",
        (RuntimeTarget("everett", None),),
        probe_error=error,
    )
    monkeypatch.setattr(agent_cli, "_available_runtime_connectors", lambda: (connector,))

    result = runner.invoke(app, ["test", "agent", "everett"], color=False)

    assert result.exit_code == exit_code
    assert headline in result.stderr
    assert safe_code in result.stderr
    assert "PRIVATE" not in result.stderr


@pytest.mark.parametrize(
    ("stage", "error", "exit_code", "fallback"),
    [
        (
            "probe",
            RuntimeConfigurationError("PRIVATE_TOKEN_ABC123"),
            2,
            "RUNTIME_CONFIGURATION_FAILED",
        ),
        (
            "list",
            RuntimeIncompleteError("PRIVATE_TOKEN_ABC123"),
            4,
            "RUNTIME_INCOMPLETE",
        ),
        (
            "prepare",
            RuntimeExecutionError("PRIVATE_TOKEN_ABC123"),
            3,
            "RUNTIME_EXECUTION_FAILED",
        ),
    ],
)
def test_unowned_syntactically_valid_connector_codes_never_reach_stderr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stage: str,
    error: RuntimeError,
    exit_code: int,
    fallback: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector(
        "hermes",
        (RuntimeTarget("everett", None),),
        probe_error=error if stage == "probe" else None,
        list_error=error if stage == "list" else None,
        prepare_error=error if stage == "prepare" else None,
    )
    monkeypatch.setattr(agent_cli, "_available_runtime_connectors", lambda: (connector,))
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", "everett", "--format", "json"],
        color=False,
    )

    assert result.exit_code == exit_code
    assert result.stdout_bytes == b""
    assert fallback in result.stderr
    assert "PRIVATE_TOKEN_ABC123" not in result.stderr
    assert "runtime runtime" not in result.stderr
    assert not (tmp_path / ".town").exists()


def test_prepared_runtime_policy_mismatch_fails_before_progress_or_inference(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    connector = _FakeConnector(
        "hermes",
        (RuntimeTarget("everett", None),),
        issue_policy=RuntimeIssuePolicy(execution=frozenset({"HERMES_TIMEOUT"})),
        prepared_issue_policy=RuntimeIssuePolicy(execution=frozenset({"HERMES_OTHER_FAILURE"})),
    )
    monkeypatch.setattr(agent_cli, "_available_runtime_connectors", lambda: (connector,))
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", "everett", "--format", "json"],
        color=False,
    )

    assert result.exit_code == 3
    assert result.stdout_bytes == b""
    assert "RUNTIME_POLICY_MISMATCH" in result.stderr
    assert "Running a basic local agent test" not in result.stderr
    assert not (tmp_path / ".town").exists()


def test_equal_frozen_prepared_policy_preserves_continuity_without_identity_coupling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    connector_policy = RuntimeIssuePolicy(execution=frozenset({"HERMES_TIMEOUT"}))
    prepared_policy = RuntimeIssuePolicy(execution=frozenset({"HERMES_TIMEOUT"}))
    connector = _FakeConnector(
        "hermes",
        (RuntimeTarget("everett", None),),
        issue_policy=connector_policy,
        prepared_issue_policy=prepared_policy,
    )

    result, calls, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        connectors=(connector,),
    )

    prepared = cast("_FakePreparedRuntime", calls[0]["prepared_runtime"])
    assert result.exit_code == 0
    assert prepared.issue_policy == connector.issue_policy
    assert prepared.issue_policy is not connector.issue_policy


@pytest.mark.parametrize("stage", ["probe", "list", "prepare"])
def test_unexpected_connector_value_error_is_safe_exit_3_before_admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stage: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    private_detail = f"private-connector-{stage}-{TOKEN}"
    failure = ValueError(private_detail)
    connector = _FakeConnector(
        "openclaw",
        (RuntimeTarget("everett", None),),
        probe_error=failure if stage == "probe" else None,
        list_error=failure if stage == "list" else None,
        prepare_error=failure if stage == "prepare" else None,
    )
    monkeypatch.setattr(agent_cli, "_available_runtime_connectors", lambda: (connector,))
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", "everett", "--format", "json"],
        color=False,
    )

    assert result.exit_code == 3
    assert result.stdout_bytes == b""
    assert "RESULT: ERROR" in result.stderr
    assert "managed runtime connector failed unexpectedly" in result.stderr
    assert private_detail not in result.stderr
    assert TOKEN not in result.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("managed_args", "expected"),
    [
        ([" bad-target "], "TARGET must be"),
        (["everett", "--runtime", " bad-runtime "], "--runtime must be"),
        (["everett", "--model", "provider"], "--model must be provider/model"),
    ],
)
def test_invalid_managed_user_values_exit_2_before_connector_loading(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    managed_args: list[str],
    expected: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    loaded = False

    def must_not_load_connectors() -> NoReturn:
        nonlocal loaded
        loaded = True
        raise AssertionError("connector loading crossed the user-validation boundary")

    monkeypatch.setattr(agent_cli, "_available_runtime_connectors", must_not_load_connectors)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["test", "agent", *managed_args, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert expected in result.stderr
    assert loaded is False
    assert os.environ["TOWN_AGENT_TOKEN"] == TOKEN
    assert TOKEN not in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_managed_output_directory_admission_race_keeps_actionable_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli
    import nest_core.agent_test.managed_runtime as managed_runtime

    async def fail_admission(**_kwargs: object) -> NoReturn:
        raise AgentTestPreAdmissionError("OUTPUT_DIR_INVALID")

    connector = _FakeConnector("openclaw", (RuntimeTarget("everett", None),))
    monkeypatch.setattr(agent_cli, "_available_runtime_connectors", lambda: (connector,))
    monkeypatch.setattr(managed_runtime, "run_managed_agent_test", fail_admission)
    output_directory = tmp_path / "result"

    result = runner.invoke(
        app,
        [
            "test",
            "agent",
            "everett",
            "--output-dir",
            str(output_directory),
            "--format",
            "json",
        ],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert "output directory must be new or empty and must not be a file or symlink" in (
        result.stderr
    )
    assert not output_directory.exists()


@pytest.mark.parametrize("exit_code", [0, 1, 3, 4, 130])
def test_managed_admitted_exit_codes_preserve_result_json_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exit_code: int,
) -> None:
    issue_code = "OPENCLAW_TIMEOUT" if exit_code == 4 else None

    result, _, outcome, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        outcome_exit=exit_code,
        issue_code=issue_code,
        extra=["--format", "json"],
    )

    assert result.exit_code == exit_code
    assert result.stdout_bytes == outcome.result_bytes
    assert result.stdout_bytes == (outcome.output_directory / "result.json").read_bytes()
    machine_result = json.loads(result.stdout_bytes)
    assert machine_result["profile"] == {
        "id": "nanda/agent/capability-fulfillment",
        "version": "1",
        "digest": "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58",
    }
    assert machine_result["driver"]["endpoint_origin"] == ENDPOINT
    assert "adapter_instance_id" in machine_result["driver"]
    assert f"OpenClaw {OPENCLAW_VERSION}" in result.stderr
    assert "everett" in result.stderr
    if issue_code is not None:
        assert f"Runtime issue: {issue_code}" in result.stderr
        assert "Next:" in result.stderr


def test_managed_verbose_diagnostics_retain_runtime_model_and_result_identifiers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _, _, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        extra=["--model", "provider/override", "--verbose"],
    )

    assert result.exit_code == 0
    for technical_identifier in (
        f"OpenClaw {OPENCLAW_VERSION}",
        "everett",
        "Model: provider/override",
        PROFILE_EXACT,
        "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58",
        ENDPOINT,
        "01K00000000000000000000000",
    ):
        assert technical_identifier in result.stderr


@pytest.mark.parametrize(
    ("profile", "endpoint", "token_env", "token", "output_format", "expected"),
    [
        ("unknown", ENDPOINT, "TOWN_AGENT_TOKEN", TOKEN, "human", "unknown Test Profile"),
        (
            PROFILE_ALIAS,
            "http://localhost:8787",
            "TOWN_AGENT_TOKEN",
            TOKEN,
            "human",
            "endpoint must be http://127.0.0.1:<port> or http://[::1]:<port>",
        ),
        (PROFILE_ALIAS, ENDPOINT, "TOWN_AGENT_TOKEN", None, "human", "is not set"),
        (
            PROFILE_ALIAS,
            ENDPOINT,
            "TOWN_AGENT_TOKEN",
            "A" * 64,
            "human",
            "exactly 64 lowercase hexadecimal characters",
        ),
        (
            PROFILE_ALIAS,
            ENDPOINT,
            "BAD-NAME",
            TOKEN,
            "human",
            "--token-env must name a valid environment variable",
        ),
        (
            PROFILE_ALIAS,
            ENDPOINT,
            "TOWN_AGENT_TOKEN",
            TOKEN,
            "xml",
            "one of 'human', 'json'",
        ),
    ],
)
def test_invalid_invocation_is_exit_2_before_execution_with_empty_stdout(
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    endpoint: str,
    token_env: str,
    token: str | None,
    output_format: str,
    expected: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    called = False

    async def must_not_execute(**_kwargs: object) -> AgentTestOutcome:
        nonlocal called
        called = True
        raise AssertionError("execution crossed the configuration boundary")

    monkeypatch.setattr(agent_cli, "_execute_agent_test", must_not_execute)
    if token is None:
        monkeypatch.delenv(token_env, raising=False)
    else:
        monkeypatch.setenv(token_env, token)
    args = [
        "test",
        "agent",
        "--endpoint",
        endpoint,
        "--token-env",
        token_env,
        "--format",
        output_format,
    ]
    if profile != PROFILE_ALIAS:
        args.extend(["--profile", profile])
    result = runner.invoke(app, args, color=False)

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert expected in result.stderr
    assert not called
    if token is not None:
        assert token not in result.stderr


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("A" * 64, "exactly 64 lowercase hexadecimal characters"),
        (None, "TOWN_AGENT_TOKEN is not set"),
    ],
)
def test_invalid_or_missing_caller_credential_is_absent_after_validation(
    monkeypatch: pytest.MonkeyPatch,
    token: str | None,
    expected: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    called = False

    async def must_not_execute(**_kwargs: object) -> AgentTestOutcome:
        nonlocal called
        called = True
        raise AssertionError("execution crossed the credential boundary")

    monkeypatch.setattr(agent_cli, "_execute_agent_test", must_not_execute)
    if token is None:
        monkeypatch.delenv("TOWN_AGENT_TOKEN", raising=False)
    else:
        monkeypatch.setenv("TOWN_AGENT_TOKEN", token)

    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert expected in result.stderr
    assert "TOWN_AGENT_TOKEN" not in os.environ
    assert not called
    if token is not None:
        assert token not in result.stderr


@pytest.mark.parametrize("kind", ["file", "symlink", "nonempty"])
def test_unsafe_explicit_output_is_refused_unchanged_before_execution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str
) -> None:
    import nest_core.agent_test.cli as agent_cli

    target = tmp_path / "bundle"
    if kind == "file":
        target.write_text("caller-data", encoding="utf-8")
    elif kind == "symlink":
        source = tmp_path / "source"
        source.mkdir()
        target.symlink_to(source, target_is_directory=True)
    else:
        target.mkdir()
        (target / "caller.txt").write_text("caller-data", encoding="utf-8")
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    called = False

    async def must_not_execute(**_kwargs: object) -> AgentTestOutcome:
        nonlocal called
        called = True
        raise AssertionError("execution crossed the output boundary")

    monkeypatch.setattr(agent_cli, "_execute_agent_test", must_not_execute)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        [
            "test",
            "agent",
            "--endpoint",
            ENDPOINT,
            "--output-dir",
            str(target),
            "--format",
            "json",
        ],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert "output directory must be new or empty" in result.stderr
    assert not called
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == before
    if kind == "file":
        assert target.read_text(encoding="utf-8") == "caller-data"


def test_default_and_explicit_output_arguments_are_forwarded_without_reinterpretation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    default, default_calls, _ = _invoke(monkeypatch, tmp_path)
    explicit_path = tmp_path / "explicit"
    explicit, explicit_calls, _ = _invoke(
        monkeypatch,
        tmp_path,
        extra=["--output-dir", str(explicit_path)],
    )

    assert default.exit_code == explicit.exit_code == 0
    assert default_calls[0]["output_dir"] is None
    assert explicit_calls[0]["output_dir"] == explicit_path


def test_target_label_default_and_override_are_forwarded_to_the_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    default, default_calls, _ = _invoke(monkeypatch, tmp_path)
    named, named_calls, _ = _invoke(
        monkeypatch,
        tmp_path,
        extra=["--target-label", "checkout-agent"],
    )

    assert default.exit_code == named.exit_code == 0
    assert default_calls[0]["target_label"] == "local-agent"
    assert named_calls[0]["target_label"] == "checkout-agent"


def test_unsafe_target_label_is_rejected_before_admission_without_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        [
            "test",
            "agent",
            "--endpoint",
            ENDPOINT,
            "--target-label",
            "bad\nlabel",
            "--format",
            "json",
        ],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert "Configuration error: --target-label must be nonempty, trimmed, control-free" in (
        result.stderr
    )
    assert not (tmp_path / ".town").exists()
    assert TOKEN not in result.stderr


def test_default_human_output_is_a_plain_fixed_basic_local_agent_test(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result, _, outcome = _invoke(monkeypatch, tmp_path)

    expected = f"""RESULT: PASS
Target: local-agent
This was a basic local agent test.

Stages
  PASS        Connected to the agent
  PASS        Offered the test capability
  PASS        Found through local discovery
  PASS        Received the test request
  PASS        Returned the expected response

Not tested
  Persistent discovery, real network delivery, identity, authorization, trust,
  payments, negotiation, safety, and long-term reliability.

Next
  Review the result and trace evidence.

Artifacts
  Directory: {outcome.output_directory}
"""
    assert result.exit_code == 0
    assert result.stdout == expected
    for forbidden in (
        "capability-fulfillment",
        PROFILE_EXACT,
        "sha256:",
        "bearer",
        ENDPOINT,
        "loopback",
        "adapter instance",
        "01K00000000000000000000000",
    ):
        assert forbidden.lower() not in result.stdout.lower()


@pytest.mark.parametrize(
    ("exit_code", "headline"),
    [
        (0, "RESULT: PASS"),
        (1, "RESULT: FAIL"),
        (3, "RESULT: ERROR"),
        (4, "RESULT: INCOMPLETE"),
        (130, "RESULT: INTERRUPTED"),
    ],
)
def test_human_terminal_outcomes_keep_five_plain_stages_and_next_action(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exit_code: int,
    headline: str,
) -> None:
    result, _, _ = _invoke(monkeypatch, tmp_path, outcome_exit=exit_code)

    assert result.exit_code == exit_code
    assert result.stdout.startswith(headline + "\n")
    assert result.stdout.count("Connected to the agent") == 1
    assert result.stdout.count("Offered the test capability") == 1
    assert result.stdout.count("Found through local discovery") == 1
    assert result.stdout.count("Received the test request") == 1
    assert result.stdout.count("Returned the expected response") == 1
    positions = [
        result.stdout.index(section) for section in ("Stages", "Not tested", "Next", "Artifacts")
    ]
    assert positions == sorted(positions)
    lowered = result.stdout.lower()
    for forbidden in (
        "capability-fulfillment",
        PROFILE_EXACT,
        "sha256:",
        "bearer",
        ENDPOINT,
        "loopback",
        "adapter instance",
        "compatible",
        "certified",
        "trusted",
        "llm",
    ):
        assert re.search(rf"\b{forbidden}\b", lowered) is None


def test_no_color_explicitly_disables_color_for_human_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli

    outcome = _outcome(tmp_path, 0)

    async def fake_execute(**_kwargs: object) -> AgentTestOutcome:
        return outcome

    original_echo = agent_cli.typer.echo
    final_color_values: list[object] = []

    def recording_echo(message: Any = None, *args: Any, **kwargs: Any) -> None:
        if isinstance(message, str) and message.startswith("RESULT: PASS"):
            final_color_values.append(kwargs.get("color"))
        original_echo(message, *args, **kwargs)

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fake_execute)
    monkeypatch.setattr(agent_cli.typer, "echo", recording_echo)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--no-color"],
        color=True,
    )

    assert result.exit_code == 0
    assert final_color_values == [False]
    assert "\x1b[" not in result.stdout


def test_json_stdout_is_exact_result_bytes_and_progress_is_only_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _, outcome = _invoke(monkeypatch, tmp_path, extra=["--format", "json"])

    assert result.exit_code == 0
    assert result.stdout_bytes == outcome.result_bytes
    assert result.stdout_bytes == (outcome.output_directory / "result.json").read_bytes()
    assert str(tmp_path).encode() not in result.stdout_bytes
    assert b"Running a basic local agent test" not in result.stdout_bytes
    assert "Running a basic local agent test" in result.stderr


def test_human_next_offers_a_working_portable_trace_inspect_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    result, _, outcome = _invoke(monkeypatch, tmp_path, extra=["--verbose"])

    trace = outcome.output_directory / "trace.jsonl"
    relative_trace = trace.relative_to(tmp_path)
    command = f"nest inspect {relative_trace}"
    assert result.exit_code == 0
    assert f"Inspect the trace: {command}" in result.stderr
    assert str(tmp_path) not in next(
        line for line in result.stderr.splitlines() if "nest inspect" in line
    )
    inspected = runner.invoke(app, ["inspect", str(relative_trace)], color=False)
    assert inspected.exit_code == 0
    assert "Total events:" in inspected.stdout


def test_binary_stdout_writer_preserves_exact_bytes_and_flushes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    class _Buffer(io.BytesIO):
        flushed = False

        def flush(self) -> None:
            self.flushed = True
            super().flush()

    class _Stdout:
        def __init__(self) -> None:
            self.buffer = _Buffer()

    stdout = _Stdout()
    monkeypatch.setattr(agent_cli.sys, "stdout", stdout)
    payload = b'{"unicode":"\\u2603"}\n'

    agent_cli._write_stdout_bytes(payload)  # pyright: ignore[reportPrivateUsage]

    assert stdout.buffer.getvalue() == payload
    assert stdout.buffer.flushed is True


def test_causally_unobserved_check_is_not_merged_with_out_of_profile_coverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli

    data = _result_data(4)
    data["evaluation"]["checks"][0].update(
        status="not_tested", summary="The driver exchange did not reach this check"
    )
    data["coverage"].append(
        {
            "claim": "agent.safety",
            "status": "not_tested",
            "reason_code": "OUT_OF_PROFILE",
            "evidence_refs": [],
        }
    )
    result_model = TestResult.model_validate(data)
    output_directory = tmp_path / "causal-sections"
    output_directory.mkdir()
    result_bytes = (
        json.dumps(result_model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    (output_directory / "result.json").write_bytes(result_bytes)
    outcome = AgentTestOutcome(
        result=result_model,
        exit_code=4,
        output_directory=output_directory,
        result_bytes=result_bytes,
    )

    async def fake_execute(**_kwargs: object) -> AgentTestOutcome:
        return outcome

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fake_execute)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    rendered = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT],
        color=False,
    )

    assert rendered.exit_code == 4
    causal_check = rendered.stdout.index("Connected to the agent")
    not_tested = rendered.stdout.index("Not tested\n")
    out_of_profile = rendered.stdout.index("safety")
    assert causal_check < not_tested < out_of_profile


def test_verbose_changes_stderr_only_and_never_prints_the_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    normal, _, _ = _invoke(monkeypatch, tmp_path)
    verbose, _, _ = _invoke(monkeypatch, tmp_path, extra=["--verbose"])

    assert normal.exit_code == verbose.exit_code == 0
    assert normal.stdout == verbose.stdout
    assert normal.stderr != verbose.stderr
    assert PROFILE_EXACT in verbose.stderr
    assert "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58" in (
        verbose.stderr
    )
    assert ENDPOINT in verbose.stderr
    assert "01K00000000000000000000000" in verbose.stderr
    assert TOKEN not in normal.stdout + normal.stderr + verbose.stdout + verbose.stderr


def test_valid_caller_credential_is_removed_from_environment_before_execution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli

    token_env = "TOWN_TEST_CALLER_CREDENTIAL"
    outcome = _outcome(tmp_path, 0)
    observations: list[tuple[str | None, object]] = []

    async def observe_environment(**kwargs: object) -> AgentTestOutcome:
        observations.append((os.environ.get(token_env), kwargs["token"]))
        return outcome

    monkeypatch.setattr(agent_cli, "_execute_agent_test", observe_environment)
    monkeypatch.setenv(token_env, TOKEN)

    result = runner.invoke(
        app,
        [
            "test",
            "agent",
            "--endpoint",
            ENDPOINT,
            "--token-env",
            token_env,
            "--format",
            "json",
        ],
        color=False,
    )

    assert result.exit_code == 0
    assert observations == [(None, TOKEN)]
    assert token_env not in os.environ
    assert result.stdout_bytes == outcome.result_bytes
    assert TOKEN not in result.stderr


@pytest.mark.parametrize(
    ("outcome_exit", "final_status"),
    [(0, "PASS"), (1, "FAIL"), (3, "ERROR"), (4, "INCOMPLETE"), (130, "INTERRUPTED")],
)
def test_interrupt_during_terminal_diagnostics_distinguishes_finalized_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    outcome_exit: int,
    final_status: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    def interrupt_diagnostics(_outcome: AgentTestOutcome) -> NoReturn:
        raise KeyboardInterrupt("interrupt-diagnostics-canary")

    monkeypatch.setattr(agent_cli, "_write_diagnostics", interrupt_diagnostics)
    result, _, outcome = _invoke(
        monkeypatch,
        tmp_path,
        outcome_exit=outcome_exit,
        extra=["--format", "json"],
    )

    assert result.exit_code == 130
    assert result.stdout_bytes == b""
    assert "RESULT: OUTPUT INTERRUPTED" in result.stderr
    assert f"test finalized as {final_status}; result.json remains authoritative" in result.stderr
    assert "The local adapter test was interrupted." not in result.stderr
    assert "interrupt-diagnostics-canary" not in result.stderr
    assert (outcome.output_directory / "result.json").read_bytes() == outcome.result_bytes
    assert outcome.exit_code == outcome_exit
    assert TOKEN not in result.stderr


def test_interrupt_during_managed_issue_diagnostics_preserves_finalized_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    def interrupt_issue(_outcome: object) -> NoReturn:
        raise KeyboardInterrupt("interrupt-runtime-issue-canary")

    monkeypatch.setattr(agent_cli, "_write_managed_issue", interrupt_issue)
    result, _, outcome, _ = _invoke_managed(
        monkeypatch,
        tmp_path,
        outcome_exit=4,
        issue_code="OPENCLAW_TIMEOUT",
        extra=["--format", "json"],
    )

    assert result.exit_code == 130
    assert result.stdout_bytes == b""
    assert "RESULT: OUTPUT INTERRUPTED" in result.stderr
    assert "test finalized as INCOMPLETE; result.json remains authoritative" in result.stderr
    assert "interrupt-runtime-issue-canary" not in result.stderr
    assert (outcome.output_directory / "result.json").read_bytes() == outcome.result_bytes


@pytest.mark.parametrize(
    ("failure", "exit_code", "terminal"),
    [
        (
            AgentTestPreAdmissionError(
                "REFERENCE_REGISTRY_MISSING", next="pip install 'nest-core[plugins]'"
            ),
            2,
            "Configuration error: pinned reference Registry is unavailable.",
        ),
        (
            DriverConfigurationError("AUTHENTICATION_FAILED"),
            2,
            "Configuration error: local adapter configuration was rejected before admission.",
        ),
        (
            DriverCompatibilityError("UNSUPPORTED_PROFILE"),
            2,
            "Configuration error: local adapter does not support the frozen profile or driver "
            "contract.",
        ),
        (
            DriverContractError("MALFORMED_RESPONSE"),
            1,
            "The local agent returned an invalid response to Town's test request.",
        ),
        (
            DriverIncompleteError("TRANSPORT_LOSS"),
            4,
            "Reason: TRANSPORT_LOSS",
        ),
        (
            TownDriverError("PROFILE_MISMATCH"),
            3,
            "Town could not complete the basic local agent test.",
        ),
        (
            AgentTestTownError("TOWN_EXECUTION_ERROR"),
            3,
            "Town could not complete the basic local agent test.",
        ),
        (TimeoutError("secret-timeout-detail"), 4, "RESULT: INCOMPLETE"),
        (RuntimeError("secret-runtime-detail"), 3, "RESULT: ERROR"),
        (KeyboardInterrupt(), 130, "RESULT: INTERRUPTED"),
    ],
)
def test_safe_exception_to_exit_mapping_has_no_stdout_or_underlying_text(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    exit_code: int,
    terminal: str,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    async def fail(**_kwargs: object) -> AgentTestOutcome:
        raise failure

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fail)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--format", "json"],
        color=False,
    )

    assert result.exit_code == exit_code
    assert result.stdout_bytes == b""
    assert terminal in result.stderr
    if str(failure) and not isinstance(failure, DriverIncompleteError):
        assert str(failure) not in result.stderr
    assert TOKEN not in result.stderr
    assert "TOWN_AGENT_TOKEN" not in os.environ


@pytest.mark.parametrize("reason", ["TRANSPORT_LOSS", "TIMEOUT", "RUN_BUSY"])
def test_pre_admission_incomplete_names_safe_reason_and_actionable_adapter_next_step(
    monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    import nest_core.agent_test.cli as agent_cli

    async def fail(**_kwargs: object) -> AgentTestOutcome:
        raise DriverIncompleteError(reason)

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fail)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 4
    assert result.stdout_bytes == b""
    assert f"Reason: {reason}" in result.stderr
    assert f"Next: Start or check the local adapter at {ENDPOINT}, then rerun." in result.stderr
    assert TOKEN not in result.stderr


def test_pre_admission_incomplete_does_not_render_unrecognized_error_text_or_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    unsafe = f"private-{TOKEN}"

    async def fail(**_kwargs: object) -> AgentTestOutcome:
        raise DriverIncompleteError(unsafe)

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fail)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--format", "json"],
        color=False,
    )

    assert result.exit_code == 4
    assert result.stdout_bytes == b""
    assert "Reason: ADAPTER_UNAVAILABLE" in result.stderr
    assert unsafe not in result.stderr
    assert TOKEN not in result.stderr


def test_missing_reference_plugin_prints_exact_remediation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nest_core.agent_test.cli as agent_cli

    async def fail(**_kwargs: object) -> AgentTestOutcome:
        raise AgentTestPreAdmissionError(
            "REFERENCE_REGISTRY_MISSING", next="pip install 'nest-core[plugins]'"
        )

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fail)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT],
        color=False,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert "Next: pip install 'nest-core[plugins]'" in result.stderr


def test_recursive_token_canary_is_absent_from_output_and_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nest_core.agent_test.cli as agent_cli

    async def fail(**_kwargs: object) -> AgentTestOutcome:
        raise RuntimeError(TOKEN)

    monkeypatch.setattr(agent_cli, "_execute_agent_test", fail)
    monkeypatch.setenv("TOWN_AGENT_TOKEN", TOKEN)
    result = runner.invoke(
        app,
        ["test", "agent", "--endpoint", ENDPOINT, "--verbose"],
        color=False,
    )

    corpus = result.stdout_bytes + result.stderr_bytes
    for path in tmp_path.rglob("*"):
        if path.is_file():
            corpus += path.read_bytes()
    assert TOKEN.encode() not in corpus


def test_real_subprocess_sigint_after_admission_writes_terminal_interrupted_bundle(
    tmp_path: Path,
) -> None:
    with _serve_interrupt_adapter() as server:
        endpoint = f"http://127.0.0.1:{server.server_port}"
        environment = os.environ.copy()
        environment["TOWN_AGENT_TOKEN"] = TOKEN
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "nest_core.cli",
                "test",
                "agent",
                "--endpoint",
                endpoint,
                "--format",
                "json",
            ],
            cwd=tmp_path,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert server.message_seen.wait(timeout=10), "run never reached post-admission message"
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=15)
        finally:
            server.release_message.set()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    assert process.returncode == 130
    bundles = list((tmp_path / ".town" / "runs").iterdir())
    assert len(bundles) == 1
    result_path = bundles[0] / "result.json"
    trace_path = bundles[0] / "trace.jsonl"
    assert stdout == result_path.read_bytes()
    result = TestResult.model_validate_json(stdout)
    assert result.execution.status == "incomplete"
    assert result.evaluation.verdict == "inconclusive"
    assert trace_path.read_bytes().endswith(b"\n")
    stop_observations = [item for item in server.observations if item["kind"] == "stop"]
    assert len(stop_observations) == 1
    assert stop_observations[0]["reason"] == "user_interrupted"
    corpus = stdout + stderr
    for path in bundles[0].rglob("*"):
        if path.is_file():
            corpus += path.read_bytes()
    assert TOKEN.encode() not in corpus
