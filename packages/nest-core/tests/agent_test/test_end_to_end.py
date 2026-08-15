# SPDX-License-Identifier: Apache-2.0
"""Installed-command proof for the local bring-your-agent journey."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from http.client import HTTPConnection
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any

import jsonschema
import pytest
from nest_core.agent_test.models import TestObservation, TestResult

REPOSITORY_ROOT = Path(__file__).parents[4]
ADAPTER_PATH = REPOSITORY_ROOT / "examples" / "agent-test" / "reference_adapter.py"
CHECKER_PATH = REPOSITORY_ROOT / "scripts" / "check_agent_test_quickstart.py"
ROOT_README = REPOSITORY_ROOT / "README.md"
DOCS_INDEX = REPOSITORY_ROOT / "docs" / "README.md"
DOCS_QUICKSTART = REPOSITORY_ROOT / "docs" / "quickstart.md"
BEGINNER_GUIDE = REPOSITORY_ROOT / "docs" / "bring-your-agent.md"
ADAPTER_REFERENCE = REPOSITORY_ROOT / "docs" / "agent-test-adapter-reference.md"
EXAMPLE_README = REPOSITORY_ROOT / "examples" / "agent-test" / "README.md"
TOKEN = "9" * 64
CONTRACT = "town-agent-driver/1"


def _reserve_ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_until_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 5
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Town-Driver-Contract": CONTRACT,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"reference adapter exited before readiness: {process.returncode}")
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
    raise AssertionError("reference adapter did not become ready")


def _installed_nest() -> Path:
    for name in ("nest", "nest.exe"):
        command = Path(sys.executable).with_name(name)
        if command.is_file():
            return command
    raise AssertionError("the installed test environment must expose the nest console script")


def _schema(name: str) -> dict[str, Any]:
    package = resources.files("nest_core.agent_test.resources.schemas")
    return json.loads(package.joinpath(name).read_bytes())


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("town_quickstart_checker", CHECKER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git(repository: Path, *arguments: str) -> None:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_installed_command_runs_reference_adapter_and_emits_verified_evidence(
    tmp_path: Path,
) -> None:
    """Any source shortcut, fake runner, or incomplete evidence chain must fail end to end."""
    port = _reserve_ephemeral_port()
    environment = os.environ.copy()
    environment["TOWN_AGENT_TOKEN"] = TOKEN
    environment["PYTHONNOUSERSITE"] = "1"
    environment.pop("PYTHONPATH", None)
    adapter = subprocess.Popen(
        [sys.executable, str(ADAPTER_PATH), "--port", str(port)],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    adapter_stdout = b""
    adapter_stderr = b""
    try:
        _wait_until_ready(adapter, port)
        output = tmp_path / "evidence"
        completed = subprocess.run(
            [
                str(_installed_nest()),
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
            cwd=tmp_path,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=20,
        )
    finally:
        adapter.terminate()
        try:
            adapter_stdout, adapter_stderr = adapter.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            adapter.kill()
            adapter_stdout, adapter_stderr = adapter.communicate(timeout=2)

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    result_bytes = (output / "result.json").read_bytes()
    assert completed.stdout == result_bytes
    result_data = json.loads(result_bytes)
    jsonschema.validate(result_data, _schema("test-result-1.schema.json"))
    result = TestResult.model_validate(result_data)
    assert result.execution.status == "completed"
    assert result.evaluation.verdict == "pass"
    assert [(check.id, check.status) for check in result.evaluation.checks] == [
        ("driver.contract", "pass"),
        ("registry.provider-registered", "pass"),
        ("registry.provider-discovered", "pass"),
        ("delivery.request-routed", "pass"),
        ("capability.synthetic-request-fulfilled", "pass"),
    ]

    trace_bytes = (output / "trace.jsonl").read_bytes()
    trace_artifact = next(artifact for artifact in result.artifacts if artifact.kind == "trace")
    assert trace_artifact.path == "trace.jsonl"
    assert trace_artifact.digest == "sha256:" + hashlib.sha256(trace_bytes).hexdigest()
    records = [json.loads(line) for line in trace_bytes.splitlines()]
    test_records = [record for record in records if str(record.get("kind", "")).startswith("test.")]
    observations: list[TestObservation] = []
    observation_schema = _schema("test-observation-1.schema.json")
    for record in test_records:
        jsonschema.validate(record, observation_schema)
        observations.append(TestObservation.model_validate(record))

    roots = [observation.root for observation in observations]
    assert [root.seq for root in roots] == list(range(1, len(roots) + 1))
    assert len({root.event_id for root in roots}) == len(roots)
    assert all(root.run_id == result.run_id for root in roots)
    assert all(root.subject_participant_id == "provider-0" for root in roots)
    admitted = next(root for root in roots if root.kind == "test.driver.run_admitted")
    assert admitted.data.profile_digest == result.profile.digest
    registered = next(root for root in roots if root.kind == "test.registry.provider_registered")
    assert registered.data.registry_implementation == (
        "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
    )
    discovered = next(root for root in roots if root.kind == "test.registry.lookup_returned")
    assert discovered.data.card_agent_ids == ["provider-0"]
    assert any(root.kind == "test.message.request_routed" for root in roots)
    assert any(root.kind == "test.message.response_routed" for root in roots)
    referenced_sequences = {
        int(match.group(1))
        for check in result.evaluation.checks
        for reference in check.evidence_refs
        if (match := re.fullmatch(r"trace\.jsonl#seq=([1-9][0-9]*)", reference))
    }
    assert referenced_sequences
    assert referenced_sequences <= {root.seq for root in roots}

    secret = TOKEN.encode("ascii")
    scanned = [
        completed.stdout,
        completed.stderr,
        adapter_stdout,
        adapter_stderr,
        *(path.read_bytes() for path in output.rglob("*") if path.is_file()),
    ]
    assert all(secret not in content for content in scanned)


def test_profile_and_public_schemas_resolve_from_installed_wheel(tmp_path: Path) -> None:
    """Omitting package data or falling back to the checkout must fail this wheel probe."""
    uv = shutil.which("uv")
    assert uv is not None
    distribution = tmp_path / "distribution"
    environment = os.environ.copy()
    build = subprocess.run(
        [
            uv,
            "build",
            "--wheel",
            "--package",
            "nest-core",
            "--out-dir",
            str(distribution),
            "--no-create-gitignore",
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert build.returncode == 0, build.stderr
    wheels = list(distribution.glob("nest_core-*.whl"))
    assert len(wheels) == 1
    installed = tmp_path / "installed"
    install = subprocess.run(
        [uv, "pip", "install", "--target", str(installed), "--no-deps", str(wheels[0])],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert install.returncode == 0, install.stderr
    probe = r"""
import json
import sys
from importlib import resources
from pathlib import Path

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
import nest_core
from nest_core.agent_test.profiles import profile_digest, resolve_profile

profile_package = resources.files("nest_core.agent_test.resources.profiles")
schema_package = resources.files("nest_core.agent_test.resources.schemas")
schema_names = [
    "driver-error-1.schema.json",
    "driver-ready-1.schema.json",
    "driver-request-1.schema.json",
    "driver-response-1.schema.json",
    "test-observation-1.schema.json",
    "test-profile-1.schema.json",
    "test-result-1.schema.json",
]
for name in schema_names:
    json.loads(schema_package.joinpath(name).read_bytes())
profile = json.loads(resolve_profile("capability-fulfillment"))
assert profile["id"] == "nanda/agent/capability-fulfillment"
assert profile_digest("capability-fulfillment") == (
    "sha256:436622e70cd84690e39c24f93236c7639adefea2fe9ea72a1dddb25e65609c58"
)
module_path = Path(nest_core.__file__).resolve()
profile_path = Path(str(profile_package)).resolve()
schema_path = Path(str(schema_package)).resolve()
assert module_path.is_relative_to(site)
assert profile_path.is_relative_to(site)
assert schema_path.is_relative_to(site)
print(json.dumps({
    "module": str(module_path),
    "profile": str(profile_path),
    "schema": str(schema_path),
}))
"""
    probe_environment = environment.copy()
    probe_environment["PYTHONNOUSERSITE"] = "1"
    probe_environment.pop("PYTHONPATH", None)
    checked = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(installed)],
        cwd=tmp_path,
        env=probe_environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert checked.returncode == 0, checked.stderr
    paths = json.loads(checked.stdout)
    assert all(str(installed) in path for path in paths.values())


def test_checker_archives_committed_head_and_refuses_dirty_or_untracked_inputs(
    tmp_path: Path,
) -> None:
    """Copying working-tree bytes could let uncommitted release files mask a broken HEAD."""
    checker = _load_checker()
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Town Test")
    _git(repository, "config", "user.email", "town-test@example.invalid")
    (repository / "required.txt").write_text("committed\n", encoding="utf-8")
    _git(repository, "add", "required.txt")
    _git(repository, "commit", "-q", "-m", "fixture")
    environment = os.environ.copy()

    committed = tmp_path / "committed"
    checker._copy_committed_source(repository, committed, environment)
    assert (committed / "required.txt").read_text(encoding="utf-8") == "committed\n"
    assert not (committed / ".git").exists()

    (repository / "required.txt").write_text("dirty\n", encoding="utf-8")
    (repository / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    with pytest.raises(checker._CheckFailureError, match="clean"):
        checker._copy_committed_source(repository, tmp_path / "rejected", environment)


def test_checker_resolves_posix_or_windows_virtual_environment_commands(tmp_path: Path) -> None:
    """Hard-coding `.venv/bin` would make the clean-package proof fail on Windows."""
    checker = _load_checker()
    virtual_environment = tmp_path / "venv"
    scripts = virtual_environment / "Scripts"
    scripts.mkdir(parents=True)
    python = scripts / "python.exe"
    nest = scripts / "nest.exe"
    python.touch()
    nest.touch()

    assert checker._venv_executable(virtual_environment, "python") == python
    assert checker._venv_executable(virtual_environment, "nest") == nest


def test_checker_recursively_enumerates_every_artifact_file(tmp_path: Path) -> None:
    """A secret in a nested future artifact must remain inside the release scan frontier."""
    checker = _load_checker()
    output = tmp_path / "evidence"
    nested = output / "nested" / "future.bin"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"future artifact")
    (output / "result.json").write_bytes(b"{}")

    assert checker._artifact_files(output) == [nested, output / "result.json"]


def test_checker_exercises_installed_openclaw_auto_explicit_and_preflight_paths(
    tmp_path: Path,
) -> None:
    """Dropping the installed managed-runtime journey from the release check must fail."""
    checker = _load_checker()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    environment = checker._safe_environment()

    checker._verify_installed_openclaw(
        nest=_installed_nest(),
        runtime=runtime,
        environment=environment,
    )
    logs = [
        json.loads(line) for line in (runtime / "fake-bin" / "log.jsonl").read_text().splitlines()
    ]
    assert len(logs) == 30
    assert [record["argument_names"] for record in logs[14:]] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
    ] * 4


def test_checker_raw_prompt_scan_rejects_an_embedded_prompt() -> None:
    """The release scan must inspect prompt bytes, not only whole-file digests."""
    checker = _load_checker()
    prompt = b'{"private":"clean-wheel-raw-prompt"}'
    retained = b"prefix\n" + prompt + b"\nsuffix"

    with pytest.raises(checker._CheckFailureError, match="raw OpenClaw prompt"):
        checker._assert_no_raw_prompts([retained], [prompt])


def test_public_docs_route_beginner_and_advanced_readers_without_duplication() -> None:
    """Public indexes must route to both guides while the example stays implementation-only."""
    assert "docs/bring-your-agent.md" in ROOT_README.read_text()
    assert "docs/agent-test-adapter-reference.md" in ROOT_README.read_text()
    assert "bring-your-agent.md" in DOCS_INDEX.read_text()
    assert "agent-test-adapter-reference.md" in DOCS_INDEX.read_text()
    assert "bring-your-agent.md" in DOCS_QUICKSTART.read_text()
    assert "agent-test-adapter-reference.md" in DOCS_QUICKSTART.read_text()

    example = EXAMPLE_README.read_text()
    assert "../../docs/agent-test-adapter-reference.md" in example
    for duplicated_detail in (
        "TOWN_AGENT_TOKEN",
        "two terminals",
        "127.0.0.1",
        "digest binding",
        "replay",
        "--endpoint",
    ):
        assert duplicated_detail not in example

    beginner = BEGINNER_GUIDE.read_text()
    assert "agent-test-adapter-reference.md" in beginner
    reference = ADAPTER_REFERENCE.read_text()
    assert "run state is released after stop" in reference
    assert "adapter process continues serving until you press Ctrl-C" in reference


def test_public_beginner_readme_hides_the_internal_profile_name() -> None:
    assert "capability-fulfillment" not in ROOT_README.read_text()


def test_beginner_guide_discloses_openclaw_session_retention() -> None:
    beginner = " ".join(BEGINNER_GUIDE.read_text().split())
    assert (
        "Each Town run uses a fresh OpenClaw session, but OpenClaw may retain that session "
        "and its normal transcript; Town does not delete them."
    ) in beginner


def test_beginner_guide_explains_how_to_test_an_agent_on_another_computer() -> None:
    beginner = " ".join(BEGINNER_GUIDE.read_text().split())
    assert "If OpenClaw runs on another computer" in beginner
    assert "SSH into that computer and run Town there" in beginner
    assert "does not connect directly to a remote OpenClaw Gateway" in beginner
    assert "Gateway must be healthy and bound to loopback" not in beginner


@pytest.mark.skipif(
    os.environ.get("TOWN_RUN_PACKAGE_QUICKSTART") != "1",
    reason="explicit clean-package journey; run before release handoff",
)
def test_clean_archive_wheel_quickstart_checker() -> None:
    """Any source fallback or unlocked/source install must fail the release checker."""
    checker = CHECKER_PATH
    environment = os.environ.copy()
    environment["PYTHONNOUSERSITE"] = "1"
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(checker)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "clean archive/wheel quickstart: PASS\n"
