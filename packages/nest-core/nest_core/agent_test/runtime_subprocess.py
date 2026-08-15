# SPDX-License-Identifier: Apache-2.0
"""Bounded, code-only subprocess execution for managed runtime connectors."""

from __future__ import annotations

import math
import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import IO

PROBE_DEADLINE_SECONDS = 5
TURN_DEADLINE_SECONDS = 45
TERMINATE_GRACE_SECONDS = 5
KILL_REAP_SECONDS = 5
DEFAULT_OUTPUT_LIMIT_BYTES = 256 * 1024

_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "SHELL",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USER",
        "WINDIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    }
)
_ENVIRONMENT_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


class ProcessError(RuntimeError):
    """A subprocess failure whose public representation is a stable code only."""

    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _SharedOutputBudget:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.used = 0
        self.overflow = threading.Event()
        self.lock = threading.Lock()

    def retain(self, chunk: bytes) -> bytes:
        with self.lock:
            remaining = self.maximum - self.used
            if remaining <= 0:
                self.overflow.set()
                return b""
            retained = chunk[:remaining]
            self.used += len(retained)
            if len(retained) != len(chunk):
                self.overflow.set()
            return retained


def _filtered_environment(
    extra: Mapping[str, str] | None,
    allowed_environment_keys: frozenset[str],
) -> dict[str, str]:
    if type(allowed_environment_keys) is not frozenset or any(
        type(key) is not str or _ENVIRONMENT_KEY_RE.fullmatch(key) is None
        for key in allowed_environment_keys
    ):
        raise ProcessError("PROCESS_INVALID_ENVIRONMENT_POLICY")
    allowed = _ENVIRONMENT_ALLOWLIST | allowed_environment_keys
    source = dict(os.environ)
    if extra is not None:
        source.update(extra)
    return {
        key: value
        for key, value in source.items()
        if key in allowed and not key.startswith("TOWN_")
    }


def _validated_argv(argv: list[str]) -> list[str]:
    if type(argv) is not list or not argv:
        raise ProcessError("PROCESS_INVALID_ARGV")
    if any(type(argument) is not str or not argument or "\x00" in argument for argument in argv):
        raise ProcessError("PROCESS_INVALID_ARGV")
    return list(argv)


def _drain(pipe: IO[bytes], budget: _SharedOutputBudget, retained: bytearray) -> None:
    try:
        while chunk := pipe.read(8192):
            retained.extend(budget.retain(chunk))
    finally:
        pipe.close()


def _process_group_exists(process_id: int) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(process_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_group(process: subprocess.Popen[bytes], *, force: bool) -> None:
    if os.name != "posix" and process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        elif force:
            process.kill()
        else:
            process.terminate()
    except ProcessLookupError:
        return
    except OSError as error:
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.02)
        if os.name == "posix":
            if not _process_group_exists(process.pid):
                return
        elif process.poll() is not None:
            return
        raise ProcessError("PROCESS_CLEANUP_FAILED") from error


def _reap(
    process: subprocess.Popen[bytes],
    *,
    terminate_grace_seconds: float,
    kill_reap_seconds: float,
) -> float:
    _signal_group(process, force=False)
    grace_deadline = time.monotonic() + terminate_grace_seconds
    while True:
        leader_exited = process.poll() is not None
        if leader_exited and (os.name != "posix" or not _process_group_exists(process.pid)):
            return time.monotonic() + kill_reap_seconds
        remaining = grace_deadline - time.monotonic()
        if remaining <= 0:
            break
        if leader_exited:
            time.sleep(min(remaining, 0.02))
            continue
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=min(remaining, 0.02))
    cleanup_deadline = time.monotonic() + kill_reap_seconds
    _signal_group(process, force=True)
    if process.poll() is None:
        try:
            process.wait(timeout=max(0.0, cleanup_deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise ProcessError("PROCESS_REAP_FAILED") from error
    return cleanup_deadline


def _run_bounded(
    argv: list[str],
    *,
    deadline_seconds: float,
    max_output_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES,
    environment: Mapping[str, str] | None = None,
    allowed_environment_keys: frozenset[str] = frozenset(),
    accept_empty_exit_one: bool = False,
    terminate_grace_seconds: float = TERMINATE_GRACE_SECONDS,
    kill_reap_seconds: float = KILL_REAP_SECONDS,
) -> ProcessResult:
    """Run literal argv with fixed output, environment, time, and cleanup bounds."""
    arguments = _validated_argv(argv)
    time_limits = (deadline_seconds, terminate_grace_seconds, kill_reap_seconds)
    if (
        type(deadline_seconds) not in (int, float)
        or deadline_seconds <= 0
        or type(max_output_bytes) is not int
        or max_output_bytes <= 0
        or type(terminate_grace_seconds) not in (int, float)
        or terminate_grace_seconds < 0
        or type(kill_reap_seconds) not in (int, float)
        or kill_reap_seconds <= 0
        or any(type(limit) is float and not math.isfinite(limit) for limit in time_limits)
        or sum(time_limits) >= 60
    ):
        raise ProcessError("PROCESS_INVALID_LIMIT")
    if type(accept_empty_exit_one) is not bool:
        raise ProcessError("PROCESS_INVALID_RETURNCODE_POLICY")

    stdout_pipe: IO[bytes] | None = None
    stderr_pipe: IO[bytes] | None = None
    pipes: list[IO[bytes]] = []
    budget: _SharedOutputBudget | None = None
    stdout: bytearray | None = None
    stderr: bytearray | None = None
    readers: list[threading.Thread] = []
    started_readers: list[threading.Thread] = []
    failure_code: str | None = None
    cleanup_started = False
    drain_deadline: float | None = None
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_filtered_environment(environment, allowed_environment_keys),
            shell=False,
            start_new_session=True,
            creationflags=0,
        )
    except (OSError, ValueError) as error:
        raise ProcessError("PROCESS_START_FAILED") from error

    try:
        stdout_pipe = process.stdout
        stderr_pipe = process.stderr
        pipes.extend(pipe for pipe in (stdout_pipe, stderr_pipe) if pipe is not None)
        if stdout_pipe is None or stderr_pipe is None:
            failure_code = "PROCESS_PIPE_FAILED"
        else:
            try:
                budget = _SharedOutputBudget(max_output_bytes)
                stdout = bytearray()
                stderr = bytearray()
                readers.append(
                    threading.Thread(
                        target=_drain,
                        args=(stdout_pipe, budget, stdout),
                        daemon=True,
                    )
                )
                readers.append(
                    threading.Thread(
                        target=_drain,
                        args=(stderr_pipe, budget, stderr),
                        daemon=True,
                    )
                )
                for reader in readers:
                    reader.start()
                    started_readers.append(reader)
            except Exception:
                failure_code = "PROCESS_READER_SETUP_FAILED"

        if failure_code is None:
            assert budget is not None
            deadline = time.monotonic() + deadline_seconds
            while process.poll() is None:
                if budget.overflow.is_set():
                    failure_code = "PROCESS_OUTPUT_LIMIT"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure_code = "PROCESS_TIMEOUT"
                    break
                try:
                    process.wait(timeout=min(remaining, 0.02))
                except subprocess.TimeoutExpired:
                    continue
        if failure_code is not None:
            cleanup_started = True
            drain_deadline = _reap(
                process,
                terminate_grace_seconds=terminate_grace_seconds,
                kill_reap_seconds=kill_reap_seconds,
            )
        elif os.name == "posix" and _process_group_exists(process.pid):
            failure_code = "PROCESS_DRAIN_FAILED"
            cleanup_started = True
            drain_deadline = _reap(
                process,
                terminate_grace_seconds=terminate_grace_seconds,
                kill_reap_seconds=kill_reap_seconds,
            )
    except BaseException:
        if cleanup_started:
            if drain_deadline is None:
                drain_deadline = time.monotonic()
        else:
            cleanup_started = True
            try:
                drain_deadline = _reap(
                    process,
                    terminate_grace_seconds=terminate_grace_seconds,
                    kill_reap_seconds=kill_reap_seconds,
                )
            except BaseException:
                drain_deadline = time.monotonic()
                raise
        raise
    finally:
        if drain_deadline is None:
            drain_deadline = time.monotonic() + kill_reap_seconds
        for index, pipe in enumerate(pipes):
            if index >= len(started_readers):
                with suppress(OSError, ValueError):
                    pipe.close()
        for reader in started_readers:
            reader.join(timeout=max(0.0, drain_deadline - time.monotonic()))
        for index, reader in enumerate(readers):
            if index < len(pipes) and not reader.is_alive():
                with suppress(OSError, ValueError):
                    pipes[index].close()

    if any(reader.is_alive() for reader in started_readers):
        raise ProcessError("PROCESS_DRAIN_FAILED")
    if failure_code is not None:
        raise ProcessError(failure_code)
    if budget is not None and budget.overflow.is_set():
        raise ProcessError("PROCESS_OUTPUT_LIMIT")
    if process.returncode != 0 and not (accept_empty_exit_one and process.returncode == 1):
        raise ProcessError("PROCESS_EXIT_NONZERO")
    assert stdout is not None and stderr is not None
    if process.returncode == 1:
        stdout.clear()
        stderr.clear()
        return ProcessResult(1, b"", b"")
    return ProcessResult(process.returncode, bytes(stdout), bytes(stderr))


def run_bounded(
    argv: list[str],
    *,
    deadline_seconds: float,
    max_output_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES,
    environment: Mapping[str, str] | None = None,
    allowed_environment_keys: frozenset[str] = frozenset(),
    terminate_grace_seconds: float = TERMINATE_GRACE_SECONDS,
    kill_reap_seconds: float = KILL_REAP_SECONDS,
    accept_empty_exit_one: bool = False,
) -> ProcessResult:
    """Run a contained POSIX child without retaining output from failed children.

    A caller may treat exit 1 as an absent optional value; both output streams
    are erased before that result is returned.
    """
    if os.name != "posix":
        raise ProcessError("PROCESS_UNSUPPORTED_PLATFORM")
    result: ProcessResult | None = None
    failure_code: str | None = None
    unexpected: BaseException | None = None
    try:
        result = _run_bounded(
            argv,
            deadline_seconds=deadline_seconds,
            max_output_bytes=max_output_bytes,
            environment=environment,
            allowed_environment_keys=allowed_environment_keys,
            accept_empty_exit_one=accept_empty_exit_one,
            terminate_grace_seconds=terminate_grace_seconds,
            kill_reap_seconds=kill_reap_seconds,
        )
    except ProcessError as error:
        failure_code = error.code
    except BaseException as error:
        unexpected = error.with_traceback(None)
        unexpected.__cause__ = None
        unexpected.__context__ = None
    del argv, environment, allowed_environment_keys
    if failure_code is not None:
        raise ProcessError(failure_code)
    if unexpected is not None:
        error = unexpected
        del unexpected
        raise error
    assert result is not None
    return result
