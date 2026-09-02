# SPDX-License-Identifier: Apache-2.0
"""Exclusive artifact-directory ownership and deterministic terminal writers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from .models import ULID, ResultArtifact, TestObservation, TestResult

LOCAL_ARTIFACT_BOUNDARY = (
    "Artifact output must be on a local filesystem in a directory controlled by the invoking "
    "user. Town is not a privilege boundary and does not defend against another process running "
    "as the same OS user, hostile filesystem behavior, or path replacement during a run. It "
    "refuses files, direct symlinks, non-empty directories, and existing artifact names, and "
    "never intentionally overwrites caller data. On POSIX, Town-created run directories and "
    "artifact files use modes 0700 and 0600. Existing caller-owned directories keep their "
    "modes; Town does not recursively chmod them. Do not run Town elevated. Local artifacts "
    "are mutable diagnostic files, not attestations. If adapter/model is untrusted, sandbox "
    "without artifact output mount."
)

_TRACE_LINE_ADAPTER = TypeAdapter(dict[str, object])


def _private_file_opener(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


def _create_missing_private_directories(path: Path) -> None:
    """Create only missing POSIX hierarchy components with mode 0700."""
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)


class ArtifactDirectoryError(ValueError):
    """The requested output target is not safe for exclusive run ownership."""


@dataclass(frozen=True, slots=True)
class ArtifactStaging:
    """Invocation-owned trace staging that leaves the requested target untouched."""

    path: Path
    target: Path
    generated: bool
    target_identity: tuple[int, int] | None

    @property
    def trace_path(self) -> Path:
        return self.path / "trace.jsonl"

    def promote(self, *, run_id: ULID) -> ArtifactDirectory:
        """Publish the closed trace into the validated final directory."""
        validate_artifact_target(
            run_id=run_id,
            output_dir=None if self.generated else self.target,
            base_dir=self.target.parents[2] if self.generated else None,
        )
        target_created = False
        if self.target_identity is not None:
            current = self.target.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != self.target_identity:
                raise ArtifactDirectoryError("output target identity changed before admission")
        else:
            try:
                self.target.mkdir(mode=0o700, exist_ok=False)
                target_created = True
            except OSError as exc:
                raise ArtifactDirectoryError("output target could not be claimed") from exc
        try:
            os.link(self.trace_path, self.target / "trace.jsonl")
        except OSError as exc:
            if target_created:
                with suppress(OSError):
                    self.target.rmdir()
            raise ArtifactDirectoryError("closed trace could not be published") from exc
        self.trace_path.unlink()
        self.path.rmdir()
        return ArtifactDirectory(path=self.target, generated=self.generated)

    def discard(self) -> None:
        """Best-effort removal of only this invocation's private staged bytes."""
        with suppress(OSError):
            self.trace_path.unlink()
        with suppress(OSError):
            self.path.rmdir()


@dataclass(frozen=True, slots=True)
class ArtifactDirectory:
    """A validated directory owned exclusively by one admitted agent-test run."""

    path: Path
    generated: bool

    @property
    def trace_path(self) -> Path:
        return self.path / "trace.jsonl"

    @property
    def result_path(self) -> Path:
        return self.path / "result.json"

    def finalize_trace(self, observations: Sequence[TestObservation]) -> ResultArtifact:
        """Verify closed exact trace/runtime parity, then digest the terminal bytes."""
        try:
            content = self.trace_path.read_bytes()
        except OSError as exc:
            raise ArtifactDirectoryError("trace is not available for finalization") from exc
        if not content.endswith(b"\n"):
            raise ArtifactDirectoryError("trace must be terminally flushed with a final LF")
        parsed_observations: list[TestObservation] = []
        try:
            for line in content.splitlines():
                value = _TRACE_LINE_ADAPTER.validate_json(line)
                if str(value.get("kind", "")).startswith("test."):
                    parsed_observations.append(TestObservation.model_validate(value))
        except (UnicodeDecodeError, ValidationError) as exc:
            raise ArtifactDirectoryError("trace contains invalid test observation bytes") from exc
        actual = [item.model_dump(mode="json") for item in parsed_observations]
        expected = [item.model_dump(mode="json") for item in observations]
        if actual != expected:
            raise ArtifactDirectoryError("trace and runtime observations must match exactly")
        return ResultArtifact(
            kind="trace",
            path="trace.jsonl",
            media_type="application/x-ndjson",
            digest="sha256:" + hashlib.sha256(content).hexdigest(),
        )

    def write_result(self, result: TestResult) -> bytes:
        """Atomically publish deterministic result bytes once, after all other artifacts."""
        if self.generated and self.path.name != result.run_id:
            raise ArtifactDirectoryError("generated output directory must match the result run ID")
        if self.result_path.exists() or self.result_path.is_symlink():
            raise ArtifactDirectoryError("result.json is already present")
        content = (
            json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        temporary = self.path / f".result-{result.run_id}.tmp"
        try:
            with open(temporary, "xb", opener=_private_file_opener) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, self.result_path)
        except FileExistsError as exc:
            raise ArtifactDirectoryError("result.json is already present") from exc
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()
        return content


def prepare_artifact_directory(
    *,
    run_id: ULID,
    output_dir: Path | None,
    base_dir: Path | None = None,
) -> ArtifactDirectory:
    """Validate the complete target first, then claim it without opening writers."""
    generated = output_dir is None
    target = validate_artifact_target(run_id=run_id, output_dir=output_dir, base_dir=base_dir)
    if not target.exists():
        try:
            if generated:
                _create_missing_private_directories(target.parent)
                target.mkdir(mode=0o700, exist_ok=False)
            else:
                target.mkdir(mode=0o700, parents=True, exist_ok=False)
        except OSError as exc:
            raise ArtifactDirectoryError("output target could not be claimed") from exc
    return ArtifactDirectory(path=target, generated=generated)


def prepare_artifact_staging(
    *,
    run_id: ULID,
    output_dir: Path | None,
    base_dir: Path | None = None,
) -> ArtifactStaging:
    """Create private same-filesystem trace staging without claiming the final target."""
    generated = output_dir is None
    target = validate_artifact_target(run_id=run_id, output_dir=output_dir, base_dir=base_dir)
    target_identity: tuple[int, int] | None = None
    if target.exists():
        current = target.stat(follow_symlinks=False)
        target_identity = (current.st_dev, current.st_ino)
    try:
        if generated:
            _create_missing_private_directories(target.parent)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=target.parent))
    except OSError as exc:
        raise ArtifactDirectoryError("artifact staging could not be created") from exc
    return ArtifactStaging(
        path=staging,
        target=target,
        generated=generated,
        target_identity=target_identity,
    )


def validate_artifact_target(
    *,
    run_id: ULID,
    output_dir: Path | None,
    base_dir: Path | None = None,
) -> Path:
    """Validate an output target without creating, opening, or mutating it."""
    generated = output_dir is None
    root = Path.cwd() if base_dir is None else base_dir
    target = root / ".town" / "runs" / run_id if output_dir is None else output_dir
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ArtifactDirectoryError("output target must be a non-symlink directory")
    if target.exists() and (generated or any(target.iterdir())):
        raise ArtifactDirectoryError("output target must not already contain entries")
    return target
