# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the bounded runtime subprocess boundary."""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
from nest_core.agent_test.runtime_subprocess import (
    KILL_REAP_SECONDS,
    PROBE_DEADLINE_SECONDS,
    TERMINATE_GRACE_SECONDS,
    TURN_DEADLINE_SECONDS,
    ProcessError,
    run_bounded,
)


def _python(source: str, *arguments: str) -> list[str]:
    return [sys.executable, "-c", source, *arguments]


def _wait_for_file(path: Path) -> None:
    deadline = time.monotonic() + 2
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError("child did not create synchronization file")
        time.sleep(0.01)


def _wait_for_pid_exit(pid: int) -> None:
    deadline = time.monotonic() + 2
    while True:
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            return
        if time.monotonic() >= deadline:
            raise AssertionError("descendant process was not killed")
        time.sleep(0.01)


def _traceback_locals(error: BaseException) -> str:
    values: list[str] = []
    traceback = error.__traceback__
    while traceback is not None:
        filename = traceback.tb_frame.f_code.co_filename
        if "/tests/" not in filename:
            values.extend(repr(value) for value in traceback.tb_frame.f_locals.values())
        traceback = traceback.tb_next
    return " ".join(values)


def test_frozen_deadlines_fit_inside_town_callback() -> None:
    assert PROBE_DEADLINE_SECONDS < TURN_DEADLINE_SECONDS
    assert TURN_DEADLINE_SECONDS == 45
    assert TERMINATE_GRACE_SECONDS == 5
    assert KILL_REAP_SECONDS == 5
    assert TURN_DEADLINE_SECONDS + TERMINATE_GRACE_SECONDS + KILL_REAP_SECONDS < 60


def test_stdout_and_stderr_are_continuously_drained_but_strictly_bounded() -> None:
    source = (
        "import sys; sys.stdout.write('private-out' * 10000); "
        "sys.stderr.write('private-err' * 10000)"
    )

    with pytest.raises(ProcessError) as caught:
        run_bounded(_python(source), deadline_seconds=2, max_output_bytes=128)

    assert caught.value.code == "PROCESS_OUTPUT_LIMIT"
    assert str(caught.value) == "PROCESS_OUTPUT_LIMIT"
    assert "private" not in repr(caught.value)


@pytest.mark.parametrize("deadline", [0.03, 0.08])
def test_probe_and_turn_deadlines_raise_only_a_stable_code(deadline: float) -> None:
    with pytest.raises(ProcessError) as caught:
        run_bounded(
            _python("import time; time.sleep(30)"),
            deadline_seconds=deadline,
            terminate_grace_seconds=0.05,
            kill_reap_seconds=0.2,
        )

    assert caught.value.code == "PROCESS_TIMEOUT"
    assert str(caught.value) == "PROCESS_TIMEOUT"


@pytest.mark.parametrize(
    "limits",
    [
        {"deadline_seconds": float("nan")},
        {"deadline_seconds": float("inf")},
        {"deadline_seconds": float("-inf")},
        {"deadline_seconds": 1, "terminate_grace_seconds": float("nan")},
        {"deadline_seconds": 1, "terminate_grace_seconds": float("inf")},
        {"deadline_seconds": 1, "kill_reap_seconds": float("inf")},
    ],
)
def test_non_finite_time_limits_are_rejected_before_spawn(limits: dict[str, Any]) -> None:
    with pytest.raises(ProcessError, match="^PROCESS_INVALID_LIMIT$"):
        run_bounded(_python("raise SystemExit(93)"), **limits)


def test_child_stdin_is_closed() -> None:
    result = run_bounded(
        _python("import sys; print('closed' if sys.stdin.buffer.read() == b'' else 'open')"),
        deadline_seconds=2,
    )

    assert result.stdout == b"closed\n"
    assert result.stderr == b""


def test_optional_exit_one_discards_both_output_streams() -> None:
    result = run_bounded(
        _python(
            "import sys; print('absent'); sys.stderr.write('not-found\\n'); raise SystemExit(1)"
        ),
        deadline_seconds=2,
        accept_empty_exit_one=True,
    )

    assert result.returncode == 1
    assert result.stdout == result.stderr == b""


def test_optional_exit_other_than_one_remains_a_code_only_failure() -> None:
    with pytest.raises(ProcessError) as caught:
        run_bounded(
            _python(
                "import sys; value = 'pri' + 'vate'; print(value + '-stdout'); "
                "sys.stderr.write(value + '-stderr'); "
                "raise SystemExit(2)"
            ),
            deadline_seconds=2,
            accept_empty_exit_one=True,
        )

    assert caught.value.code == "PROCESS_EXIT_NONZERO"
    assert "private" not in repr(caught.value)
    assert "private" not in _traceback_locals(caught.value)


def test_second_reader_start_failure_cleans_child_pipes_and_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nest_core.agent_test.runtime_subprocess as subprocess_module

    processes: list[Any] = []
    real_popen = subprocess_module.subprocess.Popen
    real_start = subprocess_module.threading.Thread.start
    starts = 0

    def tracked_popen(*args: Any, **kwargs: Any) -> Any:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    def fail_second_start(thread: Any) -> None:
        nonlocal starts
        starts += 1
        if starts == 2:
            raise RuntimeError("reader-start-canary")
        real_start(thread)

    monkeypatch.setattr(subprocess_module.subprocess, "Popen", tracked_popen)
    monkeypatch.setattr(subprocess_module.threading.Thread, "start", fail_second_start)

    with pytest.raises(ProcessError) as caught:
        run_bounded(
            _python("import time; time.sleep(30)"),
            deadline_seconds=1,
            terminate_grace_seconds=0.05,
            kill_reap_seconds=0.3,
        )

    assert caught.value.code == "PROCESS_READER_SETUP_FAILED"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "reader-start-canary" not in _traceback_locals(caught.value)
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert processes[0].stdout is not None and processes[0].stdout.closed
    assert processes[0].stderr is not None and processes[0].stderr.closed


def test_argv_is_a_literal_list_and_shell_metacharacters_are_not_executed(tmp_path: Path) -> None:
    canary = tmp_path / "shell-expanded"
    literal = f"; touch {canary}"
    result = run_bounded(
        _python("import sys; print(sys.argv[1])", literal),
        deadline_seconds=2,
    )

    assert result.stdout.decode().strip() == literal
    assert not canary.exists()
    with pytest.raises(ProcessError, match="^PROCESS_INVALID_ARGV$"):
        run_bounded("echo unsafe", deadline_seconds=2)  # type: ignore[arg-type]


def test_platform_without_process_tree_containment_fails_closed_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nest_core.agent_test.runtime_subprocess as subprocess_module

    started = False

    def forbidden_spawn(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal started
        started = True
        raise AssertionError

    monkeypatch.setattr(subprocess_module.os, "name", "nt")
    monkeypatch.setattr(subprocess_module.subprocess, "Popen", forbidden_spawn)

    with pytest.raises(ProcessError, match="^PROCESS_UNSUPPORTED_PLATFORM$"):
        run_bounded(_python("pass"), deadline_seconds=1)

    assert started is False


def test_child_environment_filters_all_town_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOWN_BEARER", "bearer-canary-private")
    monkeypatch.setenv("TOWN_PROMPT", "prompt-canary-private")
    result = run_bounded(
        _python(
            "import json, os; print(json.dumps("
            "{k: v for k, v in os.environ.items() if k.startswith('TOWN_')}))"
        ),
        deadline_seconds=2,
    )

    assert json.loads(result.stdout) == {}
    assert b"canary" not in result.stdout + result.stderr


def test_connector_environment_keys_require_an_explicit_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENCLAW_CONFIG_PATH", "/private/openclaw-config")
    monkeypatch.setenv("OPENCLAW_STATE_DIR", "/private/openclaw-state")
    source = (
        "import json, os; print(json.dumps({k: os.environ.get(k) for k in "
        "['OPENCLAW_CONFIG_PATH', 'OPENCLAW_STATE_DIR']}))"
    )

    without_policy = run_bounded(_python(source), deadline_seconds=2)
    with_policy = run_bounded(
        _python(source),
        deadline_seconds=2,
        allowed_environment_keys=frozenset({"OPENCLAW_CONFIG_PATH", "OPENCLAW_STATE_DIR"}),
    )

    assert json.loads(without_policy.stdout) == {
        "OPENCLAW_CONFIG_PATH": None,
        "OPENCLAW_STATE_DIR": None,
    }
    assert json.loads(with_policy.stdout) == {
        "OPENCLAW_CONFIG_PATH": "/private/openclaw-config",
        "OPENCLAW_STATE_DIR": "/private/openclaw-state",
    }


def test_connector_policy_cannot_allow_town_or_invalid_environment_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TOWN_BEARER", "private-bearer")
    result = run_bounded(
        _python("import os; print(os.environ.get('TOWN_BEARER', 'absent'))"),
        deadline_seconds=2,
        allowed_environment_keys=frozenset({"TOWN_BEARER"}),
    )

    assert result.stdout == b"absent\n"
    with pytest.raises(ProcessError, match="^PROCESS_INVALID_ENVIRONMENT_POLICY$"):
        run_bounded(
            _python("raise SystemExit(93)"),
            deadline_seconds=2,
            allowed_environment_keys=frozenset({"INVALID-KEY"}),
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group signal semantics")
def test_timeout_gracefully_terminates_the_managed_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "terminated"
    source = (
        "import pathlib, signal, sys, time; "
        "marker=pathlib.Path(sys.argv[1]); "
        "signal.signal(signal.SIGTERM, lambda *_: (marker.write_text('term'), sys.exit(0))); "
        "print('ready', flush=True); time.sleep(30)"
    )

    with pytest.raises(ProcessError, match="^PROCESS_TIMEOUT$"):
        run_bounded(
            _python(source, str(marker)),
            deadline_seconds=0.1,
            terminate_grace_seconds=0.5,
            kill_reap_seconds=0.2,
        )

    _wait_for_file(marker)
    assert marker.read_text() == "term"


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group signal semantics")
def test_child_ignoring_termination_is_force_killed_and_reaped(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid"
    source = (
        "import os, pathlib, signal, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    )

    with pytest.raises(ProcessError, match="^PROCESS_TIMEOUT$"):
        run_bounded(
            _python(source, str(pid_file)),
            deadline_seconds=0.1,
            terminate_grace_seconds=0.05,
            kill_reap_seconds=0.5,
        )

    _wait_for_file(pid_file)
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, signal.SIGCONT)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group signal semantics")
def test_leader_exit_does_not_leave_term_ignoring_group_descendant(tmp_path: Path) -> None:
    pid_file = tmp_path / "descendant-pid"
    descendant = (
        "import os, pathlib, signal, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    )
    source = (
        "import pathlib, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}, sys.argv[1]])\n"
        "path = pathlib.Path(sys.argv[1])\n"
        "deadline = time.monotonic() + 2\n"
        "while not path.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.01)\n"
        "time.sleep(30)\n"
    )
    pid: int | None = None
    try:
        with pytest.raises(ProcessError, match="^PROCESS_TIMEOUT$"):
            run_bounded(
                _python(source, str(pid_file)),
                deadline_seconds=0.1,
                terminate_grace_seconds=0.1,
                kill_reap_seconds=0.4,
            )
        _wait_for_file(pid_file)
        pid = int(pid_file.read_text())
        _wait_for_pid_exit(pid)
    finally:
        if pid is None and pid_file.exists():
            pid = int(pid_file.read_text())
        if pid is not None:
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


@pytest.mark.skipif(os.name != "posix", reason="POSIX inherited-pipe semantics")
def test_normally_exiting_leader_does_not_leave_same_group_descendant(tmp_path: Path) -> None:
    pid_file = tmp_path / "normal-descendant-pid"
    descendant = (
        "import os, pathlib, signal, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    )
    source = (
        "import pathlib, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}, sys.argv[1]])\n"
        "path = pathlib.Path(sys.argv[1])\n"
        "deadline = time.monotonic() + 2\n"
        "while not path.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.01)\n"
    )
    pid: int | None = None
    try:
        with pytest.raises(ProcessError, match="^PROCESS_DRAIN_FAILED$"):
            run_bounded(
                _python(source, str(pid_file)),
                deadline_seconds=1,
                terminate_grace_seconds=0.05,
                kill_reap_seconds=0.3,
            )
        _wait_for_file(pid_file)
        pid = int(pid_file.read_text())
        _wait_for_pid_exit(pid)
    finally:
        if pid is None and pid_file.exists():
            pid = int(pid_file.read_text())
        if pid is not None:
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


@pytest.mark.skipif(os.name != "posix", reason="POSIX inherited-pipe semantics")
def test_forced_reap_and_both_output_drains_share_one_cleanup_budget() -> None:
    source = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1)'], "
        "start_new_session=True); time.sleep(30)"
    )
    started = time.monotonic()

    with pytest.raises(ProcessError, match="^PROCESS_DRAIN_FAILED$"):
        run_bounded(
            _python(source),
            deadline_seconds=0.05,
            terminate_grace_seconds=0.05,
            kill_reap_seconds=0.15,
        )

    assert time.monotonic() - started < 0.33


def test_nonzero_exit_never_exposes_child_output() -> None:
    with pytest.raises(ProcessError) as caught:
        run_bounded(
            _python(
                "import sys; print('stdout-secret'); "
                "print('stderr-secret', file=sys.stderr); raise SystemExit(7)"
            ),
            deadline_seconds=2,
        )

    assert caught.value.code == "PROCESS_EXIT_NONZERO"
    assert str(caught.value) == "PROCESS_EXIT_NONZERO"
    assert "secret" not in repr(caught.value)
    assert "stdout-secret" not in _traceback_locals(caught.value)
    assert "stderr-secret" not in _traceback_locals(caught.value)
