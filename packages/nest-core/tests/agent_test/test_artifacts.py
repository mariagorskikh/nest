# SPDX-License-Identifier: Apache-2.0
"""Ownership, closure, and exact-byte tests for agent-test run artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from nest_core.agent_test import artifacts as artifact_module
from nest_core.agent_test.artifacts import (
    ArtifactDirectoryError,
    prepare_artifact_directory,
    prepare_artifact_staging,
)
from nest_core.agent_test.models import TestResult
from nest_core.agent_test.profiles import resolve_test_profile
from nest_core.agent_test.runtime import AgentTestRuntime
from nest_core.sim.agent import ScenarioEventRequest
from nest_core.sim.trace import TraceWriter

RUN_ID = "01K00000000000000000000001"


def test_local_artifact_boundary_is_explicit_and_complete() -> None:
    """The API must carry the exact local-storage trust boundary for later surfaces."""
    assert artifact_module.LOCAL_ARTIFACT_BOUNDARY == (
        "Artifact output must be on a local filesystem in a directory controlled by the "
        "invoking user. Town is not a privilege boundary and does not defend against another "
        "process running as the same OS user, hostile filesystem behavior, or path replacement "
        "during a run. It refuses files, direct symlinks, non-empty directories, and existing "
        "artifact names, and never intentionally overwrites caller data. On POSIX, Town-created "
        "run directories and artifact files use modes 0700 and 0600. Existing caller-owned "
        "directories keep their modes; Town does not recursively chmod them. Do not run Town "
        "elevated. Local artifacts are mutable diagnostic files, not attestations. If "
        "adapter/model is untrusted, sandbox without artifact output mount."
    )


@contextmanager
def _umask(mask: int) -> Generator[None]:
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


def _write_artifacts(*, tmp_path: Path, output_dir: Path | None) -> tuple[Path, Path, Path]:
    staging = prepare_artifact_staging(
        run_id=RUN_ID,
        output_dir=output_dir,
        base_dir=tmp_path,
    )
    writer = TraceWriter(staging.trace_path)
    writer.record({"kind": "test.permissions"})
    writer.close()
    artifacts = staging.promote(run_id=RUN_ID)
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "result-pass.json").read_text(encoding="utf-8")
    )
    artifacts.write_result(TestResult.model_validate(fixture))
    return artifacts.path, artifacts.trace_path, artifacts.result_path


@pytest.mark.parametrize("process_umask", [0o022, 0o000])
@pytest.mark.parametrize("explicit", [False, True])
def test_town_created_artifact_directories_and_files_are_private(
    tmp_path: Path,
    process_umask: int,
    explicit: bool,
) -> None:
    """Default and absent explicit targets must not inherit permissive process modes."""
    output_dir = tmp_path / "new-explicit-output" if explicit else None

    with _umask(process_umask):
        directory, trace_path, result_path = _write_artifacts(
            tmp_path=tmp_path,
            output_dir=output_dir,
        )

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(trace_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(result_path.stat().st_mode) == 0o600


@pytest.mark.parametrize("process_umask", [0o022, 0o000])
def test_missing_generated_hierarchy_parents_are_private(
    tmp_path: Path,
    process_umask: int,
) -> None:
    """Every generated hierarchy component created by Town must exclude group and other."""
    with _umask(process_umask):
        directory, _, _ = _write_artifacts(tmp_path=tmp_path, output_dir=None)

    assert stat.S_IMODE((tmp_path / ".town").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / ".town" / "runs").stat().st_mode) == 0o700
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


@pytest.mark.parametrize("preexisting_runs", [False, True])
def test_generated_hierarchy_preserves_preexisting_parent_mode(
    tmp_path: Path,
    preexisting_runs: bool,
) -> None:
    """Securing missing descendants must not chmod a caller-owned hierarchy component."""
    town = tmp_path / ".town"
    town.mkdir()
    town.chmod(0o751)
    runs = town / "runs"
    if preexisting_runs:
        runs.mkdir()
        runs.chmod(0o753)

    with _umask(0o000):
        directory, _, _ = _write_artifacts(tmp_path=tmp_path, output_dir=None)

    assert stat.S_IMODE(town.stat().st_mode) == 0o751
    assert stat.S_IMODE(runs.stat().st_mode) == (0o753 if preexisting_runs else 0o700)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


@pytest.mark.parametrize("process_umask", [0o022, 0o000])
def test_existing_explicit_directory_keeps_its_mode_while_new_files_are_private(
    tmp_path: Path,
    process_umask: int,
) -> None:
    """Town secures its files without recursively chmodding a caller-owned directory."""
    output_dir = tmp_path / "existing-explicit-output"
    output_dir.mkdir(mode=0o751)
    output_dir.chmod(0o751)

    with _umask(process_umask):
        directory, trace_path, result_path = _write_artifacts(
            tmp_path=tmp_path,
            output_dir=output_dir,
        )

    assert directory == output_dir
    assert stat.S_IMODE(directory.stat().st_mode) == 0o751
    assert stat.S_IMODE(trace_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(result_path.stat().st_mode) == 0o600


def test_staging_is_unique_same_parent_and_discard_removes_only_its_own_entries(
    tmp_path: Path,
) -> None:
    """Separate invocations stage beside the target and clean up only their own directory."""
    target = tmp_path / "explicit-absent"
    unrelated = tmp_path / "caller-marker.txt"
    unrelated.write_bytes(b"caller bytes")
    first = prepare_artifact_staging(run_id=RUN_ID, output_dir=target, base_dir=tmp_path)
    second = prepare_artifact_staging(run_id=RUN_ID, output_dir=target, base_dir=tmp_path)

    assert first.path.parent == target.parent
    assert second.path.parent == target.parent
    assert first.path != second.path
    first.trace_path.write_bytes(b"first trace\n")
    second.trace_path.write_bytes(b"second trace\n")

    first.discard()

    assert not first.path.exists()
    assert second.trace_path.read_bytes() == b"second trace\n"
    assert unrelated.read_bytes() == b"caller bytes"
    assert not target.exists()
    second.discard()
    assert unrelated.read_bytes() == b"caller bytes"


def test_absent_explicit_target_is_published_without_run_id_child(tmp_path: Path) -> None:
    """An absent explicit target is claimed directly only after its trace is complete."""
    target = tmp_path / "explicit-absent"
    staging = prepare_artifact_staging(run_id=RUN_ID, output_dir=target, base_dir=tmp_path)
    staging.trace_path.write_bytes(b"closed trace\n")

    artifacts = staging.promote(run_id=RUN_ID)

    assert artifacts.path == target
    assert artifacts.trace_path.read_bytes() == b"closed trace\n"
    assert not (target / RUN_ID).exists()
    assert not any("staging" in path.name for path in tmp_path.iterdir())


def test_trace_publication_collision_preserves_caller_entry_and_staging(tmp_path: Path) -> None:
    """A late artifact-name collision fails closed without overwriting either copy."""
    target = tmp_path / "explicit-empty"
    target.mkdir()
    staging = prepare_artifact_staging(run_id=RUN_ID, output_dir=target, base_dir=tmp_path)
    staging.trace_path.write_bytes(b"invocation trace\n")
    caller_trace = target / "trace.jsonl"
    caller_trace.write_bytes(b"caller trace\n")

    with pytest.raises(ArtifactDirectoryError):
        staging.promote(run_id=RUN_ID)

    assert caller_trace.read_bytes() == b"caller trace\n"
    assert staging.trace_path.read_bytes() == b"invocation trace\n"
    staging.discard()
    assert caller_trace.read_bytes() == b"caller trace\n"


@pytest.mark.parametrize("kind", ["file", "symlink", "nonempty_directory"])
def test_explicit_unsafe_output_is_refused_without_mutation(tmp_path: Path, kind: str) -> None:
    """Validation must fail before opening writers or changing caller-owned output."""
    target = tmp_path / "owned-output"
    if kind == "file":
        target.write_bytes(b"caller bytes")
    elif kind == "symlink":
        destination = tmp_path / "destination"
        destination.mkdir()
        target.symlink_to(destination, target_is_directory=True)
    else:
        target.mkdir()
        (target / "caller.txt").write_bytes(b"caller bytes")
    before = sorted(
        (path.name, path.read_bytes()) for path in tmp_path.rglob("*") if path.is_file()
    )

    with pytest.raises(ArtifactDirectoryError):
        prepare_artifact_directory(run_id=RUN_ID, output_dir=target, base_dir=tmp_path)

    after = sorted((path.name, path.read_bytes()) for path in tmp_path.rglob("*") if path.is_file())
    assert after == before
    assert not (target / "trace.jsonl").exists()
    assert not (target / "result.json").exists()


def test_generated_and_explicit_directories_have_exact_distinct_shapes(tmp_path: Path) -> None:
    """Generated output owns the run-ID child; an explicit directory never gains one."""
    generated = prepare_artifact_directory(run_id=RUN_ID, output_dir=None, base_dir=tmp_path)
    assert generated.path == tmp_path / ".town" / "runs" / RUN_ID
    assert generated.path.is_dir()

    explicit_path = tmp_path / "explicit"
    explicit_path.mkdir()
    explicit = prepare_artifact_directory(
        run_id=RUN_ID, output_dir=explicit_path, base_dir=tmp_path
    )
    assert explicit.path == explicit_path
    assert not (explicit_path / RUN_ID).exists()

    with pytest.raises(ArtifactDirectoryError):
        prepare_artifact_directory(run_id=RUN_ID, output_dir=None, base_dir=tmp_path)


def _runtime() -> AgentTestRuntime:
    event_ids = iter(["01K00000000000000000000002"])
    return AgentTestRuntime(
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        event_id_factory=lambda: next(event_ids),
        observed_at=lambda: datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
    )


def test_trace_finalization_requires_closed_exact_runtime_parity(tmp_path: Path) -> None:
    """Digesting a buffered/open or runtime-divergent trace must fail before result writing."""
    artifacts = prepare_artifact_directory(
        run_id=RUN_ID, output_dir=tmp_path / "run", base_dir=tmp_path
    )
    runtime = _runtime()
    runtime.record(
        ScenarioEventRequest(
            kind="test.driver.run_admitted",
            logical_time=0,
            observer="town.driven-agent",
            subject="provider-0",
            data={
                "adapter_instance_id": "adapter:dev",
                "profile_digest": resolve_test_profile("capability-fulfillment").reference.digest,
                "driver_sequence": 0,
                "intent_kind": "declare_capability",
            },
        )
    )
    writer = TraceWriter(artifacts.trace_path)
    writer.record(runtime.observations[-1].model_dump(mode="json"))

    with pytest.raises(ArtifactDirectoryError):
        artifacts.finalize_trace(runtime.observations)

    writer.close()
    trace_artifact = artifacts.finalize_trace(runtime.observations)
    exact_bytes = artifacts.trace_path.read_bytes()
    assert exact_bytes.endswith(b"\n")
    assert trace_artifact.model_dump(mode="json") == {
        "kind": "trace",
        "path": "trace.jsonl",
        "media_type": "application/x-ndjson",
        "digest": "sha256:" + hashlib.sha256(exact_bytes).hexdigest(),
    }


def test_result_is_deterministic_final_lf_and_atomic_last(tmp_path: Path) -> None:
    """A terminal result is closed, stable, and cannot be silently overwritten."""
    artifacts = prepare_artifact_directory(
        run_id=RUN_ID, output_dir=tmp_path / "run", base_dir=tmp_path
    )
    fixture = (Path(__file__).parent / "fixtures" / "result-pass.json").read_text(encoding="utf-8")
    result = TestResult.model_validate_json(fixture)

    written = artifacts.write_result(result)

    exact_bytes = artifacts.result_path.read_bytes()
    assert written == exact_bytes
    assert exact_bytes.endswith(b"\n")
    assert json.loads(exact_bytes) == result.model_dump(mode="json")
    assert sorted(path.name for path in artifacts.path.iterdir()) == ["result.json"]
    with pytest.raises(ArtifactDirectoryError):
        artifacts.write_result(result)
