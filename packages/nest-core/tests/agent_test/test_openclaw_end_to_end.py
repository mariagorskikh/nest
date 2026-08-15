# SPDX-License-Identifier: Apache-2.0
"""Installed-process proof for Town's exact OpenClaw quickstart boundary."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

BEARER_CANARY = "town-managed-bearer-must-not-cross-the-openclaw-boundary"
PASS_CHECKS = [
    "driver.contract",
    "registry.provider-registered",
    "registry.provider-discovered",
    "delivery.request-routed",
    "capability.synthetic-request-fulfilled",
]
START_PROMPT = (
    b"You are completing one basic local NANDA Town agent test.\n"
    b"Return exactly one minified JSON object and no other characters.\n"
    b"Do not return prose, Markdown, or code fences.\n"
    b"Do not invoke tools, access files, memory, messages, channels, or perform any "
    b"other action.\n"
    b"This is the start event. Declare the sell capability by returning exactly "
    b'{"capabilities":["sell"],"kind":"declare_capability"}.\n'
    b'If you cannot do that, return exactly {"kind":"none"}.\n'
)
MESSAGE_PROMPT = (
    b"You are completing one basic local NANDA Town agent test.\n"
    b"Return exactly one minified JSON object and no other characters.\n"
    b"Do not return prose, Markdown, or code fences.\n"
    b"Do not invoke tools, access files, memory, messages, channels, or perform any "
    b"other action.\n"
    b"This is the message event.\n"
    b'Input text: "buy:widget:2"\n'
    b"If the text matches buy:<item>:<quantity>, return one canonical object shaped as "
    b'{"kind":"send_to_sender","media_type":"text/plain; charset=utf-8",'
    b'"text":"sold:<item>:<quantity>"}, replacing <item> and <quantity> with the '
    b"input values.\n"
    b'If you cannot do that, return exactly {"kind":"none"}.\n'
)


def _installed_nest() -> Path:
    for name in ("nest", "nest.exe"):
        command = Path(sys.executable).with_name(name)
        if command.is_file():
            return command
    raise AssertionError("the installed test environment must expose the nest console script")


def _environment(fake_bin: Path, prompt_directory: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join((str(fake_bin), environment.get("PATH", "")))
    environment["TMPDIR"] = str(prompt_directory)
    environment["TOWN_FAKE_BEARER"] = BEARER_CANARY
    environment["PYTHONNOUSERSITE"] = "1"
    environment.pop("PYTHONPATH", None)
    return environment


def _install_fake_openclaw(
    fake_bin: Path,
    *,
    variant: str = "success",
    version: str = "2026.7.1-2",
    linger_port: int | None = None,
) -> Path:
    """Install a four-command fake with private, test-only prompt capture."""
    state_path = fake_bin / "fake-openclaw-state.json"
    log_path = fake_bin / "fake-openclaw-log.jsonl"
    ready_path = fake_bin / "fake-openclaw-child-ready"
    capture_directory = fake_bin / "private-prompt-captures"
    capture_directory.mkdir(mode=0o700)
    state_path.write_text('{"turns":{}}', encoding="utf-8")
    executable = fake_bin / ("openclaw.exe" if os.name == "nt" else "openclaw")
    script = textwrap.dedent(
        """\
        #!__PYTHON__
        import hashlib
        import json
        import os
        import pathlib
        import socket
        import stat
        import subprocess
        import sys
        import time

        state_path = pathlib.Path(__STATE__)
        log_path = pathlib.Path(__LOG__)
        ready_path = pathlib.Path(__READY__)
        capture_directory = pathlib.Path(__CAPTURES__)
        variant = __VARIANT__
        version = __VERSION__
        linger_port = __PORT__
        start_prompt = __START_PROMPT__
        message_prompt = __MESSAGE_PROMPT__
        args = sys.argv[1:]

        def append_log(argument_names, **fields):
            record = {
                "argument_names": argument_names,
                "town_environment_names": sorted(
                    name for name in os.environ if name.startswith("TOWN_")
                ),
                **fields,
            }
            with log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\\n")

        def emit(value):
            if isinstance(value, str):
                print(value)
            else:
                print(json.dumps(value, sort_keys=True, separators=(",", ":")))

        if args == ["--version"]:
            append_log(["--version"])
            emit("OpenClaw " + version + " (0790d9f)")
            raise SystemExit(0)

        if args == ["config", "get", "gateway.mode", "--json"]:
            append_log(["config", "get", "gateway.mode", "--json"])
            emit(json.dumps("local"))
            raise SystemExit(0)

        if args == ["config", "get", "env", "--json"]:
            append_log(["config", "get", "env", "--json"])
            raise SystemExit(1)

        if args == ["agents", "list", "--json"]:
            append_log(["agents", "list", "--json"])
            emit([
                {
                    "id": "fixture-agent",
                    "name": "Fixture Agent",
                    "workspace": "/synthetic/workspace",
                    "agentDir": "/synthetic/agent",
                    "model": "fixture/model",
                    "isDefault": True,
                    "bindings": 0,
                }
            ])
            raise SystemExit(0)

        if args == ["gateway", "status", "--json", "--require-rpc"]:
            append_log(["gateway", "status", "--json", "--require-rpc"])
            emit({
                "cli": {"entrypoint": "/synthetic/openclaw.mjs", "version": version},
                "config": {
                    "cli": {
                        "controlUi": {},
                        "exists": True,
                        "path": "/synthetic/openclaw.json",
                        "valid": True,
                    },
                    "daemon": {
                        "controlUi": {},
                        "exists": True,
                        "path": "/synthetic/openclaw.json",
                        "valid": True,
                    },
                },
                "extraServices": [{"label": "user-managed-service"}],
                "gateway": {
                    "bindMode": "lan",
                    "bindHost": "0.0.0.0",
                    "probeUrl": "ws://127.0.0.1:18789",
                    "version": version,
                },
                "port": {
                    "hints": [],
                    "listeners": [{"address": "TCP *:18789 (LISTEN)"}],
                    "port": 18789,
                    "status": "busy",
                },
                "rpc": {
                    "capability": "operator",
                    "kind": "read",
                    "ok": True,
                    "version": version,
                    "url": "ws://127.0.0.1:18789",
                },
            })
            raise SystemExit(0)

        expected_flags = [
            "agent",
            "--agent",
            "--session-key",
            "--timeout",
            "--message-file",
            "--json",
        ]
        argument_names = (
            [args[0], *[argument for argument in args[1:] if argument.startswith("--")]]
            if args
            else []
        )
        if not args or argument_names != expected_flags:
            append_log(argument_names)
            raise SystemExit(17)
        if args[args.index("--agent") + 1] != "fixture-agent":
            append_log(argument_names)
            raise SystemExit(18)
        if args[args.index("--timeout") + 1] != "0":
            append_log(argument_names)
            raise SystemExit(19)

        session_key = args[args.index("--session-key") + 1]
        message_path = pathlib.Path(args[args.index("--message-file") + 1])
        message = message_path.read_bytes()
        message_digest = "sha256:" + hashlib.sha256(message).hexdigest()
        message_mode = stat.S_IMODE(message_path.stat().st_mode)
        capture_path = capture_directory / (message_digest.removeprefix("sha256:") + ".json")
        capture_descriptor = os.open(
            capture_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            offset = 0
            while offset < len(message):
                written = os.write(capture_descriptor, message[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.fsync(capture_descriptor)
        finally:
            os.close(capture_descriptor)
        append_log(
            argument_names,
            message_digest=message_digest,
            message_mode=message_mode,
            session_key=session_key,
        )
        if message == start_prompt:
            expected_turn = 0
            intent = {"capabilities": ["sell"], "kind": "declare_capability"}
        elif message == message_prompt:
            expected_turn = 1
            intent = {
                "kind": "send_to_sender",
                "media_type": "text/plain; charset=utf-8",
                "text": "sold:widget:2",
            }
        else:
            raise SystemExit(23)
        del message

        state = json.loads(state_path.read_text(encoding="utf-8"))
        turn = int(state["turns"].get(session_key, 0))
        if turn != expected_turn:
            raise SystemExit(24)
        state["turns"][session_key] = turn + 1
        state_path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

        if variant == "timeout":
            if not isinstance(linger_port, int):
                raise SystemExit(20)
            child_code = (
                "import pathlib,socket,sys,time;"
                "s=socket.socket();"
                "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                "s.bind(('127.0.0.1',int(sys.argv[1])));"
                "s.listen();"
                "pathlib.Path(sys.argv[2]).write_text('ready');"
                "time.sleep(60)"
            )
            child = subprocess.Popen(
                [sys.executable, "-c", child_code, str(linger_port), str(ready_path)]
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not ready_path.exists():
                if child.poll() is not None:
                    raise SystemExit(21)
                time.sleep(0.01)
            child.wait()
            raise SystemExit(22)

        text = json.dumps(intent, sort_keys=True, separators=(",", ":"))
        session_digest = hashlib.sha256(session_key.encode("utf-8")).hexdigest()
        envelope = {
            "runId": "run-" + session_digest[:16],
            "status": "ok",
            "summary": "completed",
            "result": {
                "payloads": [{"text": text, "mediaUrl": None}],
                "meta": {
                    "durationMs": 1,
                    "agentMeta": {
                        "sessionId": "session-" + session_digest[:16],
                        "provider": "fixture",
                        "model": "model",
                        "agentHarnessId": "fixture-agent",
                    },
                    "aborted": False,
                    "finalAssistantVisibleText": text,
                    "finalAssistantRawText": text,
                    "replayInvalid": False,
                    "livenessState": "working",
                    "stopReason": "stop",
                    "executionTrace": {
                        "winnerProvider": "fixture",
                        "winnerModel": "model",
                        "attempts": [{
                            "provider": "fixture",
                            "model": "model",
                            "result": "success",
                            "stage": "assistant",
                        }],
                        "fallbackUsed": False,
                        "runner": "embedded",
                    },
                    "completion": {"stopReason": "stop", "finishReason": "stop"},
                },
            },
        }
        if variant == "fallback":
            envelope["fallback"] = True
        elif variant == "activity":
            envelope["toolCalls"] = []
        emit(envelope)
        """
    )
    script = (
        script.replace("__PYTHON__", os.fspath(Path(sys.executable)))
        .replace("__STATE__", repr(str(state_path)))
        .replace("__LOG__", repr(str(log_path)))
        .replace("__READY__", repr(str(ready_path)))
        .replace("__CAPTURES__", repr(str(capture_directory)))
        .replace("__VARIANT__", repr(variant))
        .replace("__VERSION__", repr(version))
        .replace("__PORT__", repr(linger_port))
        .replace("__START_PROMPT__", repr(START_PROMPT))
        .replace("__MESSAGE_PROMPT__", repr(MESSAGE_PROMPT))
    )
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o700)
    return log_path


def _run(
    cwd: Path,
    environment: dict[str, str],
    *arguments: str,
    timeout: int = 20,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(_installed_nest()), "test", "agent", *arguments],
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _logs(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _result_bundle(
    cwd: Path, completed: subprocess.CompletedProcess[bytes]
) -> tuple[dict[str, Any], Path]:
    result = json.loads(completed.stdout)
    bundle = cwd / ".town" / "runs" / result["run_id"]
    assert completed.stdout == (bundle / "result.json").read_bytes()
    return result, bundle


def _assert_five_passes(result: dict[str, Any]) -> None:
    assert result["execution"]["status"] == "completed"
    assert result["evaluation"]["verdict"] == "pass"
    assert [(check["id"], check["status"]) for check in result["evaluation"]["checks"]] == [
        (check_id, "pass") for check_id in PASS_CHECKS
    ]


def _assert_no_sensitive_bytes(
    *roots: Path,
    streams: tuple[bytes, ...] = (),
    raw_prompts: tuple[bytes, ...] = (),
) -> None:
    values = list(streams)
    for root in roots:
        values.extend(path.read_bytes() for path in root.rglob("*") if path.is_file())
    assert all(BEARER_CANARY.encode("ascii") not in value for value in values)
    assert all(b'"observation":' not in value for value in values if b'"argument_names"' in value)
    assert all(prompt and prompt not in value for prompt in raw_prompts for value in values)


def _read_and_remove_private_prompt_captures(fake_bin: Path) -> tuple[bytes, ...]:
    capture_directory = fake_bin / "private-prompt-captures"
    assert capture_directory.stat().st_mode & 0o777 == 0o700
    captures = sorted(capture_directory.iterdir())
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in captures)
    values = tuple(path.read_bytes() for path in captures)
    for path in captures:
        path.unlink()
    assert list(capture_directory.iterdir()) == []
    return values


def _assert_port_released(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))


def test_sensitive_scan_rejects_an_artifact_that_embeds_the_raw_prompt(tmp_path: Path) -> None:
    """A wrapper around a prompt must not evade a whole-file digest comparison."""
    prompt = b'{"private":"raw-prompt-canary"}'
    artifact = tmp_path / "trace.jsonl"
    artifact.write_bytes(b"prefix\n" + prompt + b"\nsuffix")

    with pytest.raises(AssertionError):
        _assert_no_sensitive_bytes(
            tmp_path,
            raw_prompts=(prompt,),
        )


def test_headline_command_autodetects_one_exact_target_and_reuses_one_session(
    tmp_path: Path,
) -> None:
    """Extra probes, prompt retention, or session reuse across Town runs must fail."""
    fake_bin = tmp_path / "bin"
    prompts = tmp_path / "prompts"
    first = tmp_path / "first"
    second = tmp_path / "second"
    for directory in (fake_bin, prompts, first, second):
        directory.mkdir()
    log_path = _install_fake_openclaw(fake_bin)
    environment = _environment(fake_bin, prompts)

    first_completed = _run(first, environment, "fixture-agent", "--format", "json")
    assert first_completed.returncode == 0, first_completed.stderr.decode(errors="replace")
    first_result, first_bundle = _result_bundle(first, first_completed)
    _assert_five_passes(first_result)
    first_logs = _logs(log_path)
    first_prompts = _read_and_remove_private_prompt_captures(fake_bin)

    assert [entry["argument_names"] for entry in first_logs] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
        ["gateway", "status", "--json", "--require-rpc"],
        ["agent", "--agent", "--session-key", "--timeout", "--message-file", "--json"],
        ["agent", "--agent", "--session-key", "--timeout", "--message-file", "--json"],
    ]
    first_turns = [entry for entry in first_logs if entry["argument_names"][0] == "agent"]
    assert len({entry["session_key"] for entry in first_turns}) == 1
    assert len({entry["message_digest"] for entry in first_turns}) == 2
    assert len(first_prompts) == 2
    assert all(entry["message_mode"] == 0o600 for entry in first_turns)
    assert all(entry["town_environment_names"] == [] for entry in first_logs)
    assert all("--deliver" not in entry["argument_names"] for entry in first_logs)
    assert all("--local" not in entry["argument_names"] for entry in first_logs)
    assert list(prompts.iterdir()) == []

    second_completed = _run(second, environment, "fixture-agent", "--format", "json")
    assert second_completed.returncode == 0, second_completed.stderr.decode(errors="replace")
    second_result, second_bundle = _result_bundle(second, second_completed)
    _assert_five_passes(second_result)
    second_prompts = _read_and_remove_private_prompt_captures(fake_bin)
    all_turns = [entry for entry in _logs(log_path) if entry["argument_names"][0] == "agent"]
    sessions = [entry["session_key"] for entry in all_turns]
    assert len(all_turns) == 4
    assert sessions[0] == sessions[1]
    assert sessions[2] == sessions[3]
    assert sessions[0] != sessions[2]
    assert len(second_prompts) == 2
    assert list(prompts.iterdir()) == []

    _assert_no_sensitive_bytes(
        first_bundle,
        second_bundle,
        streams=(
            first_completed.stdout,
            first_completed.stderr,
            second_completed.stdout,
            second_completed.stderr,
            log_path.read_bytes(),
        ),
        raw_prompts=first_prompts + second_prompts,
    )


def test_public_command_accepts_and_records_a_coherent_alternate_openclaw_version(
    tmp_path: Path,
) -> None:
    """A stale release allowlist or unrecorded probe version must fail this boundary."""
    fake_bin = tmp_path / "bin"
    prompts = tmp_path / "prompts"
    runtime = tmp_path / "runtime"
    for directory in (fake_bin, prompts, runtime):
        directory.mkdir()
    _install_fake_openclaw(fake_bin, version="2027.1.0-preview.3+compat")

    completed = _run(
        runtime,
        _environment(fake_bin, prompts),
        "fixture-agent",
        "--format",
        "json",
    )

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    result, _ = _result_bundle(runtime, completed)
    _assert_five_passes(result)
    assert b"OpenClaw 2027.1.0-preview.3+compat" in completed.stderr
    assert len(_read_and_remove_private_prompt_captures(fake_bin)) == 2


def test_explicit_runtime_uses_only_the_openclaw_connector(tmp_path: Path) -> None:
    """An explicit OpenClaw selection must not widen connector discovery."""
    fake_bin = tmp_path / "bin"
    prompts = tmp_path / "prompts"
    runtime = tmp_path / "runtime"
    for directory in (fake_bin, prompts, runtime):
        directory.mkdir()
    log_path = _install_fake_openclaw(fake_bin)

    completed = _run(
        runtime,
        _environment(fake_bin, prompts),
        "fixture-agent",
        "--runtime",
        "openclaw",
        "--format",
        "json",
    )

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    result, _ = _result_bundle(runtime, completed)
    _assert_five_passes(result)
    assert len(_read_and_remove_private_prompt_captures(fake_bin)) == 2
    assert [entry["argument_names"] for entry in _logs(log_path)[:5]] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
        ["gateway", "status", "--json", "--require-rpc"],
    ]


@pytest.mark.parametrize(
    "unknown_target",
    ["unknown", "fixture", "FIXTURE-AGENT", "Fixture Agent"],
)
def test_unknown_target_stops_after_read_only_inventory_without_artifacts(
    tmp_path: Path,
    unknown_target: str,
) -> None:
    """An absent exact target must never reach gateway preparation or run admission."""
    fake_bin = tmp_path / "bin"
    prompts = tmp_path / "prompts"
    runtime = tmp_path / "runtime"
    for directory in (fake_bin, prompts, runtime):
        directory.mkdir()
    log_path = _install_fake_openclaw(fake_bin)

    completed = _run(
        runtime,
        _environment(fake_bin, prompts),
        unknown_target,
        "--format",
        "json",
    )

    assert completed.returncode == 2
    assert completed.stdout == b""
    assert b"TARGET_NOT_FOUND" in completed.stderr
    assert [entry["argument_names"] for entry in _logs(log_path)] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
    ]
    assert not (runtime / ".town").exists()
    assert list(prompts.iterdir()) == []
    assert _read_and_remove_private_prompt_captures(fake_bin) == ()


@pytest.mark.parametrize(
    ("variant", "issue_code"),
    [
        ("fallback", "OPENCLAW_FALLBACK_REPORTED"),
        ("activity", "OPENCLAW_ACTIVITY_REPORTED"),
    ],
)
def test_reported_fallback_or_activity_is_incomplete(
    tmp_path: Path,
    variant: str,
    issue_code: str,
) -> None:
    """OpenClaw fallback or tool activity must not be scored as agent behavior."""
    fake_bin = tmp_path / "bin"
    prompts = tmp_path / "prompts"
    runtime = tmp_path / "runtime"
    for directory in (fake_bin, prompts, runtime):
        directory.mkdir()
    log_path = _install_fake_openclaw(fake_bin, variant=variant)

    completed = _run(
        runtime,
        _environment(fake_bin, prompts),
        "fixture-agent",
        "--format",
        "json",
    )

    assert completed.returncode == 4
    assert issue_code.encode("ascii") in completed.stderr
    result, bundle = _result_bundle(runtime, completed)
    assert result["execution"]["status"] == "incomplete"
    assert result["evaluation"]["verdict"] == "inconclusive"
    raw_prompts = _read_and_remove_private_prompt_captures(fake_bin)
    assert len(raw_prompts) == 1
    assert list(prompts.iterdir()) == []
    _assert_no_sensitive_bytes(
        bundle,
        streams=(completed.stdout, completed.stderr, log_path.read_bytes()),
        raw_prompts=raw_prompts,
    )


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup assertion requires POSIX")
def test_timeout_reaps_fake_openclaw_child_and_releases_its_port(tmp_path: Path) -> None:
    """A timed-out OpenClaw turn must not leave its process group or listener behind."""
    fake_bin = tmp_path / "bin"
    prompts = tmp_path / "prompts"
    runtime = tmp_path / "runtime"
    for directory in (fake_bin, prompts, runtime):
        directory.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = int(reserved.getsockname()[1])
    log_path = _install_fake_openclaw(fake_bin, variant="timeout", linger_port=port)

    completed = _run(
        runtime,
        _environment(fake_bin, prompts),
        "fixture-agent",
        "--format",
        "json",
        timeout=58,
    )

    assert completed.returncode == 4
    assert b"OPENCLAW_TIMEOUT" in completed.stderr
    result, bundle = _result_bundle(runtime, completed)
    assert result["execution"]["status"] == "incomplete"
    assert result["evaluation"]["verdict"] == "inconclusive"
    raw_prompts = _read_and_remove_private_prompt_captures(fake_bin)
    assert len(raw_prompts) == 1
    _assert_port_released(port)
    assert list(prompts.iterdir()) == []
    _assert_no_sensitive_bytes(
        bundle,
        streams=(completed.stdout, completed.stderr, log_path.read_bytes()),
        raw_prompts=raw_prompts,
    )
