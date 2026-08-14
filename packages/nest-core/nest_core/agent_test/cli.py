# SPDX-License-Identifier: Apache-2.0
"""Focused Typer surface for the Generation 1 frozen local agent Test Profile."""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import sys
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import typer

if TYPE_CHECKING:
    from .runner import AgentTestOutcome

_PROFILE_ALIAS = "capability-fulfillment"
_PROFILE_EXACT = "nanda/agent/capability-fulfillment@1"
_PROFILE_REFERENCES = frozenset({_PROFILE_ALIAS, _PROFILE_EXACT})
_TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z")
_ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_INCOMPLETE_REASON_CODES = frozenset(
    {
        "ADAPTER_INSTANCE_CHANGED",
        "ADAPTER_INTERNAL",
        "ADAPTER_UNAVAILABLE",
        "AUTHENTICATION_FAILED",
        "RUN_BUSY",
        "TIMEOUT",
        "TRANSPORT_LOSS",
    }
)


class _OutputFormat(StrEnum):
    HUMAN = "human"
    JSON = "json"


def _typer_option(*args: Any, **kwargs: Any) -> Any:
    return typer.Option(*args, **kwargs)  # pyright: ignore[reportUnknownMemberType]


test_app = typer.Typer(
    help="Run local NANDA Town adapter tests.",
    no_args_is_help=True,
)


def _configuration_error(message: str) -> NoReturn:
    typer.echo(f"Configuration error: {message}", err=True)
    raise typer.Exit(2)


def _terminal_error(headline: str, detail: str, exit_code: int) -> NoReturn:
    typer.echo(headline, err=True)
    typer.echo(detail, err=True)
    raise typer.Exit(exit_code)


def _interrupted_error() -> NoReturn:
    _terminal_error(
        "RESULT: INTERRUPTED",
        "The local adapter test was interrupted.",
        130,
    )


def _output_interrupted_error(outcome: AgentTestOutcome) -> NoReturn:
    final_status = {
        0: "PASS",
        1: "FAIL",
        3: "ERROR",
        4: "INCOMPLETE",
        130: "INTERRUPTED",
    }.get(outcome.exit_code, "UNKNOWN")
    _terminal_error(
        "RESULT: OUTPUT INTERRUPTED",
        (
            f"Terminal output was interrupted after the test finalized as {final_status}; "
            "result.json remains authoritative."
        ),
        130,
    )


def _pre_admission_incomplete_error(*, code: str, endpoint: str) -> NoReturn:
    reason = code if code in _INCOMPLETE_REASON_CODES else "ADAPTER_UNAVAILABLE"
    typer.echo("RESULT: INCOMPLETE", err=True)
    typer.echo(f"Reason: {reason}", err=True)
    typer.echo(
        "Adapter: the local adapter did not complete the requested exchange.",
        err=True,
    )
    typer.echo(
        f"Next: Start or check the local adapter at {endpoint}, then rerun.",
        err=True,
    )
    raise typer.Exit(4)


def _write_stdout_bytes(content: bytes) -> None:
    """Write the machine result without text transcoding or an implicit newline."""
    sys.stdout.buffer.write(content)
    sys.stdout.buffer.flush()


def _validate_output_directory(output_dir: Path | None) -> None:
    if output_dir is None:
        return
    try:
        invalid = output_dir.is_symlink() or (
            output_dir.exists()
            and (not output_dir.is_dir() or next(output_dir.iterdir(), None) is not None)
        )
    except OSError:
        invalid = True
    if invalid:
        _configuration_error(
            "output directory must be new or empty and must not be a file or symlink."
        )


async def _execute_agent_test(
    *,
    profile: str,
    endpoint: str,
    token: str,
    output_dir: Path | None,
    target_label: str,
) -> AgentTestOutcome:
    """Resolve the pinned profile, then construct the one supported driver lazily."""
    from .http_driver import LoopbackHttpAgentDriver, parse_loopback_origin
    from .models import ResultDriver
    from .profiles import resolve_test_profile
    from .runner import run_agent_test

    resolve_test_profile(profile)
    endpoint = parse_loopback_origin(endpoint)
    driver = LoopbackHttpAgentDriver(endpoint, token)
    driver_metadata = ResultDriver(
        contract="town-agent-driver/1",
        kind="loopback-http",
        adapter_instance_id=None,
        endpoint_origin=endpoint,
    )
    return await run_agent_test(
        driver=driver,
        driver_metadata=driver_metadata,
        output_dir=output_dir,
        base_dir=Path.cwd(),
        target_label=target_label,
    )


def _render_human(outcome: AgentTestOutcome) -> str:
    result = outcome.result
    headline = {
        0: "RESULT: PASS",
        1: "RESULT: FAIL",
        3: "RESULT: ERROR",
        4: "RESULT: INCOMPLETE",
        130: "RESULT: INTERRUPTED",
    }.get(outcome.exit_code, "RESULT: ERROR")
    lines = [
        headline,
        f"Run: {result.run_id}",
        f"Profile: {result.profile.id}@{result.profile.version}",
        f"Profile digest: {result.profile.digest}",
        f"Target label: {result.target.label} (local evidence label; not verified identity)",
        (
            "Request authentication: Town sent bearer-authenticated requests using the "
            "caller credential"
        ),
        (
            "Adapter instance (self-asserted): "
            f"{result.driver.adapter_instance_id or 'not observed'}"
        ),
    ]

    checks_by_status = {
        status: [check for check in result.evaluation.checks if check.status == status]
        for status in ("pass", "fail", "not_tested", "inconclusive", "error")
    }

    def add_section(title: str, entries: list[str]) -> None:
        if entries:
            lines.extend([title, *(f"  - {entry}" for entry in entries)])

    add_section(
        "Passed",
        [f"{check.id}: {check.summary}" for check in checks_by_status["pass"]],
    )
    add_section(
        "Failed",
        [f"{check.id}: {check.summary}" for check in checks_by_status["fail"]],
    )
    incomplete_checks = [
        check for status in ("inconclusive", "error") for check in checks_by_status[status]
    ]
    incomplete_coverage = [item for item in result.coverage if item.status == "unknown"]
    add_section(
        "Incomplete",
        [f"{check.id}: {check.summary}" for check in incomplete_checks]
        + [
            f"Coverage {item.claim}: {item.reason_code or 'NOT_OBSERVED'}"
            for item in incomplete_coverage
        ],
    )
    not_evaluated_entries = [
        f"{check.id}: {check.summary}" for check in checks_by_status["not_tested"]
    ]
    if result.evaluation.verdict == "not_evaluated":
        not_evaluated_entries.insert(0, "Town did not evaluate this profile.")
    add_section("Not evaluated", not_evaluated_entries)
    add_section(
        "Not tested",
        [
            f"{item.claim}: {item.reason_code or 'OUT_OF_PROFILE'}"
            for item in result.coverage
            if item.status == "not_tested"
        ],
    )

    next_step = {
        0: "Review the scoped result and trace evidence.",
        1: "Update the failed adapter behavior, then rerun this profile.",
        3: "Review Town diagnostics, then rerun this profile.",
        4: (
            f"Start or check the local adapter at {result.driver.endpoint_origin}, "
            "then rerun this profile."
        ),
        130: "Rerun this profile when ready.",
    }.get(outcome.exit_code, "Review Town diagnostics, then rerun this profile.")
    next_steps = [next_step]
    trace_artifact = next(
        (artifact for artifact in result.artifacts if artifact.kind == "trace"),
        None,
    )
    if trace_artifact is not None:
        trace_path = outcome.output_directory / trace_artifact.path
        relative_trace = os.path.relpath(trace_path, start=Path.cwd())
        next_steps.append(f"Inspect the trace: nest inspect {shlex.quote(relative_trace)}")
    add_section("Next", next_steps)
    artifacts = [f"result: {outcome.output_directory / 'result.json'}"]
    artifacts.extend(
        f"{artifact.kind}: {outcome.output_directory / artifact.path}"
        for artifact in result.artifacts
    )
    add_section("Artifacts", artifacts)
    return "\n".join(lines) + "\n"


def _write_progress(
    *, profile_reference: str, endpoint: str, output_dir: Path | None, verbose: bool
) -> None:
    typer.echo("Running local adapter test...", err=True)
    if not verbose:
        return
    typer.echo(f"Profile: {profile_reference}", err=True)
    typer.echo(f"Endpoint: {endpoint}", err=True)
    typer.echo(
        f"Output: {output_dir if output_dir is not None else '.town/runs/<run-id>'}",
        err=True,
    )


def _write_diagnostics(outcome: AgentTestOutcome) -> None:
    for diagnostic in outcome.result.diagnostics:
        typer.echo(f"Diagnostic {diagnostic.code}: {diagnostic.summary}", err=True)
        if diagnostic.next is not None:
            typer.echo(f"Next: {diagnostic.next}", err=True)


_OUTPUT_FORMAT_OPTION = _typer_option(
    _OutputFormat.HUMAN,
    "--format",
    help="Final output format.",
)


@test_app.command(
    "agent",
    help=(
        "Test one local agent adapter with bearer-authenticated requests using the "
        "Generation 1 capability-fulfillment profile. Generation 1 is the first frozen "
        "agent-test contract/profile generation, not a Town or nest-core 1.0 release."
    ),
)
def agent(
    profile: str = _typer_option(
        _PROFILE_ALIAS,
        "--profile",
        help="Advanced: built-in profile alias or exact versioned reference.",
        rich_help_panel="Advanced adapter options",
    ),
    endpoint: str = _typer_option(
        ...,
        "--endpoint",
        help="Adapter origin: http://127.0.0.1:<port> or http://[::1]:<port>.",
    ),
    target_label: str = _typer_option(
        "local-agent",
        "--target-label",
        help="Local evidence label for this target; not a verified identity.",
    ),
    token_env: str = _typer_option(
        "TOWN_AGENT_TOKEN",
        "--token-env",
        help=(
            "Environment variable containing the bearer caller credential: a 64-character "
            "lowercase hexadecimal token."
        ),
    ),
    output_format: _OutputFormat = _OUTPUT_FORMAT_OPTION,
    output_dir: str | None = _typer_option(
        None,
        "--output-dir",
        help="Exact empty or new run-artifact directory. Default: .town/runs/<run-id>.",
    ),
    no_color: bool = _typer_option(
        False,
        "--no-color",
        help="Disable ANSI color in human output.",
    ),
    verbose: bool = _typer_option(
        False,
        "--verbose",
        help="Write additional safe progress details to stderr.",
    ),
) -> None:
    """Run the frozen local adapter profile."""
    try:
        output_path = None if output_dir is None else Path(output_dir)
        if profile not in _PROFILE_REFERENCES:
            _configuration_error(f"unknown Test Profile; use {_PROFILE_ALIAS} or {_PROFILE_EXACT}.")
        if _ENVIRONMENT_NAME_RE.fullmatch(token_env) is None:
            _configuration_error("--token-env must name a valid environment variable.")
        token = os.environ.pop(token_env, None)
        if token is None or not token:
            _configuration_error(f"{token_env} is not set.")
        if _TOKEN_RE.fullmatch(token) is None:
            _configuration_error(
                f"{token_env} must contain exactly 64 lowercase hexadecimal characters."
            )
        _validate_output_directory(output_path)
    except (KeyboardInterrupt, asyncio.CancelledError):
        _interrupted_error()

    try:
        from .driver import (
            AgentDriverError,
            DriverCompatibilityError,
            DriverConfigurationError,
            DriverContractError,
            DriverIncompleteError,
            TownDriverError,
        )
        from .http_driver import parse_loopback_origin
        from .profiles import resolve_test_profile
        from .runner import AgentTestPreAdmissionError, AgentTestTownError
    except (KeyboardInterrupt, asyncio.CancelledError):
        _interrupted_error()
    except Exception:
        _terminal_error(
            "RESULT: ERROR",
            "Town could not prepare the local adapter test.",
            3,
        )

    try:
        endpoint = parse_loopback_origin(endpoint)
    except (KeyboardInterrupt, asyncio.CancelledError):
        _interrupted_error()
    except ValueError:
        _configuration_error("endpoint must be http://127.0.0.1:<port> or http://[::1]:<port>.")
    try:
        resolved_profile = resolve_test_profile(profile)
        profile_reference = f"{resolved_profile.reference.id}@{resolved_profile.reference.version}"
        _write_progress(
            profile_reference=profile_reference,
            endpoint=endpoint,
            output_dir=output_path,
            verbose=verbose,
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        _interrupted_error()
    except KeyError:
        _configuration_error(f"unknown Test Profile; use {_PROFILE_ALIAS} or {_PROFILE_EXACT}.")
    except Exception:
        _terminal_error(
            "RESULT: ERROR",
            "Town could not load the frozen Test Profile.",
            3,
        )

    try:
        outcome = asyncio.run(
            _execute_agent_test(
                profile=profile,
                endpoint=endpoint,
                token=token,
                output_dir=output_path,
                target_label=target_label,
            )
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        _interrupted_error()
    except AgentTestPreAdmissionError as error:
        if error.code == "REFERENCE_REGISTRY_MISSING":
            typer.echo(
                "Configuration error: pinned reference Registry is unavailable.",
                err=True,
            )
            typer.echo("Next: pip install 'nest-core[plugins]'", err=True)
        elif error.code == "OUTPUT_DIR_INVALID":
            typer.echo(
                "Configuration error: output directory must be new or empty and must not be a "
                "file or symlink.",
                err=True,
            )
        elif error.code == "TARGET_LABEL_INVALID":
            typer.echo(
                "Configuration error: --target-label must be nonempty, trimmed, control-free, "
                "and at most 128 UTF-8 bytes.",
                err=True,
            )
        else:
            typer.echo("Configuration error: Town could not admit this invocation.", err=True)
        raise typer.Exit(2) from None
    except (DriverConfigurationError, DriverCompatibilityError) as error:
        if isinstance(error, DriverCompatibilityError):
            detail = (
                "Configuration error: local adapter does not support the frozen profile or "
                "driver contract."
            )
        else:
            detail = (
                "Configuration error: local adapter configuration was rejected before admission."
            )
        typer.echo(detail, err=True)
        raise typer.Exit(2) from None
    except DriverContractError:
        _terminal_error(
            "RESULT: FAIL",
            (
                "Driver contract: the local adapter returned an invalid response to Town's "
                "bearer-authenticated request."
            ),
            1,
        )
    except DriverIncompleteError as error:
        _pre_admission_incomplete_error(
            code=error.code,
            endpoint=endpoint,
        )
    except (TownDriverError, AgentTestTownError):
        _terminal_error(
            "RESULT: ERROR",
            "Town could not complete the local adapter test.",
            3,
        )
    except TimeoutError:
        _pre_admission_incomplete_error(
            code="TIMEOUT",
            endpoint=endpoint,
        )
    except AgentDriverError:
        _terminal_error(
            "RESULT: ERROR",
            "Town could not classify a local adapter failure.",
            3,
        )
    except Exception:
        _terminal_error(
            "RESULT: ERROR",
            "Town could not complete the local adapter test.",
            3,
        )

    try:
        _write_diagnostics(outcome)
        if output_format == _OutputFormat.JSON:
            _write_stdout_bytes(outcome.result_bytes)
        else:
            typer.echo(
                _render_human(outcome),
                nl=False,
                color=False if no_color else None,
            )
    except (KeyboardInterrupt, asyncio.CancelledError):
        _output_interrupted_error(outcome)
    raise typer.Exit(outcome.exit_code)
