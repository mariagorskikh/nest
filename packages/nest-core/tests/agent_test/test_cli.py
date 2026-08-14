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
from nest_core.cli import app
from typer.testing import CliRunner

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
TOKEN = "0123456789abcdef" * 4
PROFILE_ALIAS = "capability-fulfillment"
PROFILE_EXACT = "nanda/agent/capability-fulfillment@1"
ENDPOINT = "http://127.0.0.1:8787"


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
    if exit_code == 1:
        data["evaluation"]["verdict"] = "fail"
        data["evaluation"]["checks"][0].update(
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


def test_test_and_agent_help_freeze_the_additive_command_tree() -> None:
    test_help = runner.invoke(app, ["test", "--help"], color=False)
    agent_help = runner.invoke(app, ["test", "agent", "--help"], color=False)

    assert test_help.exit_code == 0
    assert "Run local NANDA Town adapter tests." in test_help.stdout
    assert "agent" in test_help.stdout
    assert agent_help.exit_code == 0
    normalized = " ".join(agent_help.stdout.replace("│", "").split())
    assert (
        "Test one local agent adapter with bearer-authenticated requests using the "
        "Generation 1 capability-fulfillment profile." in normalized
    )
    assert (
        "Generation 1 is the first frozen agent-test contract/profile generation, not a Town "
        "or nest-core 1.0 release." in normalized
    )
    for expected in (
        "--profile",
        "Advanced: built-in profile alias or exact versioned reference.",
        "--endpoint",
        "Adapter origin: http://127.0.0.1:<port> or http://[::1]:<port>.",
        "--target-label",
        "Local evidence label for this target; not a verified identity.",
        "local-agent",
        "--token-env",
        "TOWN_AGENT_TOKEN",
        "Environment variable containing the bearer caller credential",
        "--format",
        "[human|json]",
        "--output-dir",
        ".town/runs/<run-id>",
        "--no-color",
        "--verbose",
    ):
        assert expected in normalized
    assert "agent [OPTIONS] PROFILE" not in normalized


def test_agent_help_is_plain_when_color_is_disabled() -> None:
    result = runner.invoke(app, ["test", "agent", "--help"], color=False)

    assert result.exit_code == 0
    assert "\x1b[" not in result.stdout


def test_cli_import_keeps_http_driver_and_runner_lazy() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import nest_core.cli; "
                "assert 'nest_core.agent_test.http_driver' not in sys.modules; "
                "assert 'nest_core.agent_test.runner' not in sys.modules"
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
def test_human_terminal_outcomes_have_honest_ordered_sections(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exit_code: int,
    headline: str,
) -> None:
    result, _, outcome = _invoke(monkeypatch, tmp_path, outcome_exit=exit_code)

    assert result.exit_code == exit_code
    assert result.stdout.startswith(headline + "\n")
    assert "Run: 01K00000000000000000000001" in result.stdout
    assert f"Profile: {PROFILE_EXACT}" in result.stdout
    assert (
        "Target label: local-agent (local evidence label; not verified identity)" in result.stdout
    )
    expected_instance = outcome.result.driver.adapter_instance_id or "not observed"
    assert (
        "Request authentication: Town sent bearer-authenticated requests using the caller "
        "credential" in result.stdout
    )
    assert f"Adapter instance (self-asserted): {expected_instance}" in result.stdout
    assert "Next\n" in result.stdout
    assert "Artifacts\n" in result.stdout
    expected_sections = {
        0: ["Passed", "Not tested", "Next", "Artifacts"],
        1: ["Failed", "Not tested", "Next", "Artifacts"],
        3: ["Not evaluated", "Next", "Artifacts"],
        4: ["Incomplete", "Next", "Artifacts"],
        130: ["Incomplete", "Next", "Artifacts"],
    }[exit_code]
    positions = [result.stdout.index(section + "\n") for section in expected_sections]
    assert positions == sorted(positions)
    lowered = result.stdout.lower()
    for forbidden in ("compatible", "certified", "safe", "trusted", "reliable", "llm"):
        assert re.search(rf"\b{forbidden}\b", lowered) is None
    if exit_code == 4:
        assert "TRANSPORT_LOSS" in result.stdout
        assert f"Start or check the local adapter at {ENDPOINT}, then rerun" in result.stdout


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
    assert b"Running local adapter test" not in result.stdout_bytes
    assert "Running local adapter test" in result.stderr


def test_human_next_offers_a_working_portable_trace_inspect_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    result, _, outcome = _invoke(monkeypatch, tmp_path)

    trace = outcome.output_directory / "trace.jsonl"
    relative_trace = trace.relative_to(tmp_path)
    command = f"nest inspect {relative_trace}"
    assert result.exit_code == 0
    assert f"Inspect the trace: {command}" in result.stdout
    assert str(tmp_path) not in next(
        line for line in result.stdout.splitlines() if "nest inspect" in line
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
    not_evaluated = rendered.stdout.index("Not evaluated\n")
    causal_check = rendered.stdout.index("driver.contract:")
    not_tested = rendered.stdout.index("Not tested\n")
    out_of_profile = rendered.stdout.index("agent.safety:")
    assert not_evaluated < causal_check < not_tested < out_of_profile


def test_verbose_changes_stderr_only_and_never_prints_the_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    normal, _, _ = _invoke(monkeypatch, tmp_path)
    verbose, _, _ = _invoke(monkeypatch, tmp_path, extra=["--verbose"])

    assert normal.exit_code == verbose.exit_code == 0
    assert normal.stdout == verbose.stdout
    assert normal.stderr != verbose.stderr
    assert PROFILE_EXACT in verbose.stderr
    assert ENDPOINT in verbose.stderr
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
            "Driver contract: the local adapter returned an invalid response to Town's "
            "bearer-authenticated request.",
        ),
        (
            DriverIncompleteError("TRANSPORT_LOSS"),
            4,
            "Reason: TRANSPORT_LOSS",
        ),
        (
            TownDriverError("PROFILE_MISMATCH"),
            3,
            "Town could not complete the local adapter test.",
        ),
        (
            AgentTestTownError("TOWN_EXECUTION_ERROR"),
            3,
            "Town could not complete the local adapter test.",
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
