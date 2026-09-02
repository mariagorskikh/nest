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
import time
from http.client import HTTPConnection
from pathlib import Path

_CONTRACT = "town-agent-driver/1"
_PROFILE_DIGEST = "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"


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
                    str(_venv_executable(virtual_environment, "nest")),
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
