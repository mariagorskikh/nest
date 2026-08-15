#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the documented agent-test journey from clean source and installed wheels."""

from __future__ import annotations

import io
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
from http.client import HTTPConnection
from pathlib import Path

_CONTRACT = "town-agent-driver/1"
_PROFILE_DIGEST = "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"
_OPENCLAW_SECRET = "clean-wheel-managed-bearer-must-not-cross-runtime-boundary"
_OPENCLAW_START_PROMPT = (
    b"You are completing one basic local NANDA Town agent test.\n"
    b"Return exactly one minified JSON object and no other characters.\n"
    b"Do not return prose, Markdown, or code fences.\n"
    b"Do not invoke tools, access files, memory, messages, channels, or perform any "
    b"other action.\n"
    b"This is the start event. Declare the sell capability by returning exactly "
    b'{"capabilities":["sell"],"kind":"declare_capability"}.\n'
    b'If you cannot do that, return exactly {"kind":"none"}.\n'
)
_OPENCLAW_MESSAGE_PROMPT = (
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
_PASS_CHECKS = [
    "driver.contract",
    "registry.provider-registered",
    "registry.provider-discovered",
    "delivery.request-routed",
    "capability.synthetic-request-fulfilled",
]


class _CheckFailureError(RuntimeError):
    pass


def _safe_environment() -> dict[str, str]:
    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "PATHEXT",
        "PATH",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMPDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _run(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    label: str,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise _CheckFailureError(f"{label} exited {completed.returncode}")
    return completed


def _copy_committed_source(source: Path, destination: Path, environment: dict[str, str]) -> None:
    status = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        environment=environment,
        label="clean source check",
    )
    if status.stdout:
        raise _CheckFailureError("source tree must be clean before checking committed HEAD")
    archived = _run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=source,
        environment=environment,
        label="committed source archive",
    )
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as archive:
        archive.extractall(destination, filter="data")


def _venv_executable(virtual_environment: Path, name: str) -> Path:
    candidates = (
        virtual_environment / "bin" / name,
        virtual_environment / "Scripts" / f"{name}.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise _CheckFailureError(f"virtual environment does not contain {name}")


def _artifact_files(output: Path) -> list[Path]:
    return sorted(path for path in output.rglob("*") if path.is_file())


def _assert_no_raw_prompts(values: list[bytes], raw_prompts: list[bytes]) -> None:
    if any(not prompt or prompt in value for prompt in raw_prompts for value in values):
        raise _CheckFailureError("raw OpenClaw prompt appeared in installed artifacts")


def _read_private_prompt_captures(directory: Path) -> list[bytes]:
    if directory.stat().st_mode & 0o777 != 0o700:
        raise _CheckFailureError("fake OpenClaw prompt capture directory was not private")
    captures = sorted(directory.iterdir())
    if any(path.stat().st_mode & 0o777 != 0o600 for path in captures):
        raise _CheckFailureError("fake OpenClaw prompt capture was not private")
    values = [path.read_bytes() for path in captures]
    for path in captures:
        path.unlink()
    if list(directory.iterdir()):
        raise _CheckFailureError("fake OpenClaw prompt capture cleanup failed")
    return values


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_ready(process: subprocess.Popen[bytes], port: int, token: str) -> None:
    deadline = time.monotonic() + 5
    headers = {
        "Authorization": f"Bearer {token}",
        "Town-Driver-Contract": _CONTRACT,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise _CheckFailureError("reference adapter exited before readiness")
        try:
            connection = HTTPConnection("127.0.0.1", port, timeout=0.2)
            connection.request("GET", "/town-driver/1/ready", headers=headers)
            response = connection.getresponse()
            body = response.read()
            connection.close()
            if response.status == 200 and json.loads(body)["accepting_runs"] is True:
                return
        except (ConnectionError, OSError, TimeoutError):
            pass
        time.sleep(0.02)
    raise _CheckFailureError("reference adapter did not become ready")


def _wheel(distribution: Path, normalized_name: str) -> Path:
    wheels = list(distribution.glob(f"{normalized_name}-*.whl"))
    if len(wheels) != 1:
        raise _CheckFailureError(f"expected one {normalized_name} wheel")
    return wheels[0]


def _verify_installed_resources(
    python: Path, environment: dict[str, str], runtime: Path, virtual_environment: Path
) -> None:
    probe = r"""
import json
import sys
from importlib import resources
from pathlib import Path

venv = Path(sys.argv[1]).resolve()
import nest_core
from nest_core.agent_test.profiles import profile_digest, resolve_profile

module_path = Path(nest_core.__file__).resolve()
profile_path = Path(str(resources.files("nest_core.agent_test.resources.profiles"))).resolve()
schema_path = Path(str(resources.files("nest_core.agent_test.resources.schemas"))).resolve()
assert module_path.is_relative_to(venv)
assert profile_path.is_relative_to(venv)
assert schema_path.is_relative_to(venv)
assert json.loads(resolve_profile("capability-fulfillment"))["version"] == "1"
assert profile_digest("capability-fulfillment") == sys.argv[2]
for name in (
    "driver-error-1.schema.json",
    "driver-ready-1.schema.json",
    "driver-request-1.schema.json",
    "driver-response-1.schema.json",
    "test-observation-1.schema.json",
    "test-profile-1.schema.json",
    "test-result-1.schema.json",
):
    json.loads(resources.files("nest_core.agent_test.resources.schemas").joinpath(name).read_bytes())
"""
    _run(
        [str(python), "-I", "-c", probe, str(virtual_environment), _PROFILE_DIGEST],
        cwd=runtime,
        environment=environment,
        label="installed resource probe",
    )


def _write_fake_openclaw(directory: Path) -> tuple[Path, Path]:
    directory.mkdir()
    state_path = directory / "state.json"
    log_path = directory / "log.jsonl"
    capture_directory = directory / "private-prompt-captures"
    capture_directory.mkdir(mode=0o700)
    state_path.write_text('{"turns":{}}', encoding="utf-8")
    executable = directory / ("openclaw.exe" if os.name == "nt" else "openclaw")
    script = textwrap.dedent(
        """\
        #!__PYTHON__
        import hashlib
        import json
        import os
        import pathlib
        import stat
        import sys

        state_path = pathlib.Path(__STATE__)
        log_path = pathlib.Path(__LOG__)
        capture_directory = pathlib.Path(__CAPTURES__)
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
            print(
                value
                if isinstance(value, str)
                else json.dumps(value, sort_keys=True, separators=(",", ":"))
            )

        if args == ["--version"]:
            append_log(["--version"])
            emit("OpenClaw 2026.7.1-2 (0790d9f)")
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
                "cli": {"entrypoint": "/synthetic/openclaw.mjs", "version": "2026.7.1-2"},
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
                    "version": "2026.7.1-2",
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
                    "version": "2026.7.1-2",
                    "url": "ws://127.0.0.1:18789",
                },
            })
            raise SystemExit(0)

        argument_names = (
            [args[0], *[argument for argument in args[1:] if argument.startswith("--")]]
            if args
            else []
        )
        expected = [
            "agent",
            "--agent",
            "--session-key",
            "--timeout",
            "--message-file",
            "--json",
        ]
        if not args or argument_names != expected:
            append_log(argument_names)
            raise SystemExit(17)
        if args[args.index("--agent") + 1] != "fixture-agent":
            append_log(argument_names)
            raise SystemExit(18)
        session_key = args[args.index("--session-key") + 1]
        message_path = pathlib.Path(args[args.index("--message-file") + 1])
        message = message_path.read_bytes()
        message_digest = "sha256:" + hashlib.sha256(message).hexdigest()
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
            message_mode=stat.S_IMODE(message_path.stat().st_mode),
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
            raise SystemExit(19)
        del message

        state = json.loads(state_path.read_text(encoding="utf-8"))
        turn = int(state["turns"].get(session_key, 0))
        if turn != expected_turn:
            raise SystemExit(20)
        state["turns"][session_key] = turn + 1
        state_path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        text = json.dumps(intent, sort_keys=True, separators=(",", ":"))
        session_digest = hashlib.sha256(session_key.encode("utf-8")).hexdigest()
        emit({
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
        })
        """
    )
    script = (
        script.replace("__PYTHON__", os.fspath(Path(sys.executable)))
        .replace("__STATE__", repr(str(state_path)))
        .replace("__LOG__", repr(str(log_path)))
        .replace("__CAPTURES__", repr(str(capture_directory)))
        .replace("__START_PROMPT__", repr(_OPENCLAW_START_PROMPT))
        .replace("__MESSAGE_PROMPT__", repr(_OPENCLAW_MESSAGE_PROMPT))
    )
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o700)
    return executable, log_path


def _invoke_installed(
    nest: Path,
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(nest), *arguments],
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _managed_result(
    completed: subprocess.CompletedProcess[bytes], cwd: Path
) -> tuple[dict[str, object], Path]:
    if completed.returncode != 0:
        raise _CheckFailureError("installed OpenClaw command did not pass")
    try:
        result = json.loads(completed.stdout)
        bundle = cwd / ".town" / "runs" / result["run_id"]
        result_bytes = (bundle / "result.json").read_bytes()
        checks = result["evaluation"]["checks"]
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise _CheckFailureError("installed OpenClaw result was invalid") from error
    if completed.stdout != result_bytes:
        raise _CheckFailureError("installed OpenClaw JSON did not match result.json")
    if (
        result["execution"]["status"] != "completed"
        or result["evaluation"]["verdict"] != "pass"
        or [(check["id"], check["status"]) for check in checks]
        != [(check_id, "pass") for check_id in _PASS_CHECKS]
    ):
        raise _CheckFailureError("installed OpenClaw checks were not all passing")
    return result, bundle


def _verify_installed_openclaw(
    *,
    nest: Path,
    runtime: Path,
    environment: dict[str, str],
) -> None:
    fake_bin = runtime / "fake-bin"
    prompts = runtime / "prompts"
    auto = runtime / "auto"
    explicit = runtime / "explicit"
    unknown_targets = ("unknown", "fixture", "FIXTURE-AGENT", "Fixture Agent")
    unknown_directories = [
        (target, runtime / f"unknown-{index}")
        for index, target in enumerate(unknown_targets, start=1)
    ]
    for directory in (prompts, auto, explicit, *(path for _, path in unknown_directories)):
        directory.mkdir()
    _, log_path = _write_fake_openclaw(fake_bin)
    managed_environment = environment.copy()
    managed_environment["PATH"] = os.pathsep.join(
        (str(fake_bin), managed_environment.get("PATH", ""))
    )
    managed_environment["TMPDIR"] = str(prompts)
    managed_environment["TOWN_FAKE_BEARER"] = _OPENCLAW_SECRET

    auto_completed = _invoke_installed(
        nest,
        ["test", "agent", "fixture-agent", "--format", "json"],
        cwd=auto,
        environment=managed_environment,
    )
    _, auto_bundle = _managed_result(auto_completed, auto)
    capture_directory = fake_bin / "private-prompt-captures"
    raw_prompts = _read_private_prompt_captures(capture_directory)
    if len(raw_prompts) != 2:
        raise _CheckFailureError("auto-detected OpenClaw prompt count changed")
    first_logs = [json.loads(line) for line in log_path.read_text().splitlines()]
    expected_inventory = [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
        ["gateway", "status", "--json", "--require-rpc"],
    ]
    if [record["argument_names"] for record in first_logs[:5]] != expected_inventory:
        raise _CheckFailureError("auto-detected OpenClaw inventory path changed")
    if len(first_logs) != 7 or any(record["town_environment_names"] for record in first_logs):
        raise _CheckFailureError("auto-detected OpenClaw process boundary changed")
    turn_logs = first_logs[5:]
    if any(
        record["message_mode"] != 0o600
        or "--deliver" in record["argument_names"]
        or "--local" in record["argument_names"]
        for record in turn_logs
    ):
        raise _CheckFailureError("installed OpenClaw prompt containment changed")

    explicit_completed = _invoke_installed(
        nest,
        [
            "test",
            "agent",
            "fixture-agent",
            "--runtime",
            "openclaw",
            "--format",
            "json",
        ],
        cwd=explicit,
        environment=managed_environment,
    )
    _, explicit_bundle = _managed_result(explicit_completed, explicit)
    explicit_prompts = _read_private_prompt_captures(capture_directory)
    if len(explicit_prompts) != 2:
        raise _CheckFailureError("explicit OpenClaw prompt count changed")
    raw_prompts.extend(explicit_prompts)
    all_logs = [json.loads(line) for line in log_path.read_text().splitlines()]
    if [record["argument_names"] for record in all_logs[7:12]] != expected_inventory:
        raise _CheckFailureError("explicit OpenClaw connector path changed")
    if len(all_logs) != 14:
        raise _CheckFailureError("explicit OpenClaw invoked an unexpected process")
    auto_sessions = [record["session_key"] for record in all_logs[5:7]]
    explicit_sessions = [record["session_key"] for record in all_logs[12:14]]
    if (
        len(set(auto_sessions)) != 1
        or len(set(explicit_sessions)) != 1
        or auto_sessions[0] == explicit_sessions[0]
    ):
        raise _CheckFailureError("installed OpenClaw session isolation changed")

    unknown_results: list[subprocess.CompletedProcess[bytes]] = []
    for target, directory in unknown_directories:
        unknown_completed = _invoke_installed(
            nest,
            ["test", "agent", target, "--format", "json"],
            cwd=directory,
            environment=managed_environment,
        )
        unknown_results.append(unknown_completed)
        if (
            unknown_completed.returncode != 2
            or unknown_completed.stdout
            or (directory / ".town").exists()
        ):
            raise _CheckFailureError("unknown OpenClaw target crossed the preflight boundary")
    all_logs = [json.loads(line) for line in log_path.read_text().splitlines()]
    expected_near_match_logs = [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
    ] * len(unknown_targets)
    if [record["argument_names"] for record in all_logs[14:]] != expected_near_match_logs:
        raise _CheckFailureError("OpenClaw near-match target reached inference")
    if list(prompts.iterdir()):
        raise _CheckFailureError("installed OpenClaw prompt file remained after execution")

    log_bytes = log_path.read_bytes()
    secret = _OPENCLAW_SECRET.encode("ascii")
    scanned = [
        auto_completed.stdout,
        auto_completed.stderr,
        explicit_completed.stdout,
        explicit_completed.stderr,
        *(value for result in unknown_results for value in (result.stdout, result.stderr)),
        log_bytes,
        *(path.read_bytes() for path in _artifact_files(auto_bundle)),
        *(path.read_bytes() for path in _artifact_files(explicit_bundle)),
    ]
    if any(secret in value for value in scanned):
        raise _CheckFailureError("managed runtime secret appeared in installed output")
    if b'"observation":' in log_bytes or b"allowed_intents" in log_bytes:
        raise _CheckFailureError("raw OpenClaw prompt appeared in fixture logs")
    _assert_no_raw_prompts(scanned, raw_prompts)


def _check() -> None:
    source = Path(__file__).resolve().parents[1]
    uv = shutil.which("uv")
    if uv is None:
        raise _CheckFailureError("uv is not installed")
    base_environment = _safe_environment()
    with tempfile.TemporaryDirectory(prefix="town-agent-quickstart-") as temporary:
        temporary_root = Path(temporary)
        archive = temporary_root / "source"
        _copy_committed_source(source, archive, base_environment)

        _run(
            [uv, "--no-config", "sync", "--frozen"],
            cwd=archive,
            environment=base_environment,
            label="locked source install",
        )
        distribution = temporary_root / "distribution"
        distribution.mkdir()
        for package in ("nest-core", "nest-sdk", "nest-plugins-reference"):
            _run(
                [
                    uv,
                    "--no-config",
                    "build",
                    "--wheel",
                    "--package",
                    package,
                    "--out-dir",
                    str(distribution),
                    "--no-create-gitignore",
                ],
                cwd=archive,
                environment=base_environment,
                label=f"{package} wheel build",
            )
        core_wheel = _wheel(distribution, "nest_core")
        sdk_wheel = _wheel(distribution, "nest_sdk")
        plugin_wheel = _wheel(distribution, "nest_plugins_reference")
        virtual_environment = archive / ".venv"
        python = _venv_executable(virtual_environment, "python")
        _run(
            [
                uv,
                "--no-config",
                "pip",
                "install",
                "--python",
                str(python),
                "--reinstall",
                "--no-deps",
                str(core_wheel),
                str(sdk_wheel),
                str(plugin_wheel),
            ],
            cwd=archive,
            environment=base_environment,
            label="wheel replacement install",
        )

        runtime = temporary_root / "runtime"
        runtime.mkdir()
        adapter_path = runtime / "reference_adapter.py"
        shutil.copy2(archive / "examples" / "agent-test" / "reference_adapter.py", adapter_path)
        (archive / "packages").rename(archive / "source-packages-disabled")
        _verify_installed_resources(python, base_environment, runtime, virtual_environment)
        nest = _venv_executable(virtual_environment, "nest")

        token = secrets.token_hex(32)
        runtime_environment = base_environment.copy()
        runtime_environment["TOWN_AGENT_TOKEN"] = token
        port = _reserve_port()
        adapter = subprocess.Popen(
            [str(python), str(adapter_path), "--port", str(port)],
            cwd=runtime,
            env=runtime_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        adapter_stdout = b""
        adapter_stderr = b""
        try:
            _wait_ready(adapter, port, token)
            output = runtime / "evidence"
            completed = _run(
                [
                    str(nest),
                    "test",
                    "agent",
                    "--endpoint",
                    f"http://127.0.0.1:{port}",
                    "--format",
                    "json",
                    "--output-dir",
                    str(output),
                    "--no-color",
                ],
                cwd=runtime,
                environment=runtime_environment,
                label="installed quickstart command",
            )
        finally:
            adapter.terminate()
            try:
                adapter_stdout, adapter_stderr = adapter.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                adapter.kill()
                adapter_stdout, adapter_stderr = adapter.communicate(timeout=2)

        result_bytes = (output / "result.json").read_bytes()
        if completed.stdout != result_bytes:
            raise _CheckFailureError("JSON stdout did not equal result.json")
        result = json.loads(result_bytes)
        if (
            result["execution"]["status"] != "completed"
            or result["evaluation"]["verdict"] != "pass"
        ):
            raise _CheckFailureError("installed quickstart did not pass")
        if [check["status"] for check in result["evaluation"]["checks"]] != ["pass"] * 5:
            raise _CheckFailureError("installed quickstart checks were not all passing")
        secret = token.encode("ascii")
        scanned = [
            completed.stdout,
            completed.stderr,
            adapter_stdout,
            adapter_stderr,
            *(path.read_bytes() for path in _artifact_files(output)),
        ]
        if any(secret in value for value in scanned):
            raise _CheckFailureError("runtime secret appeared in quickstart output")
        _verify_installed_openclaw(
            nest=nest,
            runtime=runtime,
            environment=base_environment,
        )


def main() -> int:
    try:
        _check()
    except (OSError, subprocess.SubprocessError, _CheckFailureError) as error:
        print(f"clean archive/wheel quickstart: FAIL ({error})", file=sys.stderr)
        return 1
    print("clean archive/wheel quickstart: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
