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
    from .managed_runtime import ManagedAgentTestOutcome
    from .runner import AgentTestOutcome
    from .runtime_connectors import RuntimeConnector, RuntimeDisplay

_PROFILE_ALIAS = "capability-fulfillment"
_PROFILE_EXACT = "nanda/agent/capability-fulfillment@1"
_PROFILE_REFERENCES = frozenset({_PROFILE_ALIAS, _PROFILE_EXACT})
_TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z")
_ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_MANAGED_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
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


def _typer_argument(*args: Any, **kwargs: Any) -> Any:
    return typer.Argument(*args, **kwargs)  # pyright: ignore[reportUnknownMemberType]


test_app = typer.Typer(
    help="Test an existing agent with Town.",
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


def _agent_pre_admission_error(code: str) -> NoReturn:
    if code == "REFERENCE_REGISTRY_MISSING":
        typer.echo(
            "Configuration error: pinned reference Registry is unavailable.",
            err=True,
        )
        typer.echo("Next: pip install 'nest-core[plugins]'", err=True)
    elif code == "OUTPUT_DIR_INVALID":
        typer.echo(
            "Configuration error: output directory must be new or empty and must not "
            "be a file or symlink.",
            err=True,
        )
    elif code == "TARGET_LABEL_INVALID":
        typer.echo(
            "Configuration error: --target-label must be nonempty, trimmed, "
            "control-free, and at most 128 UTF-8 bytes.",
            err=True,
        )
    else:
        typer.echo("Configuration error: Town could not admit this invocation.", err=True)
    raise typer.Exit(2)


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


def _valid_runtime_metadata(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and len(value) <= 128
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _validate_managed_user_values(*, target: str, runtime: str | None, model: str | None) -> None:
    if not _valid_runtime_metadata(target):
        _configuration_error(
            "TARGET must be nonempty, trimmed, control-free, and at most 128 characters."
        )
    if runtime is not None and not _valid_runtime_metadata(runtime):
        _configuration_error(
            "--runtime must be nonempty, trimmed, control-free, and at most 128 characters."
        )
    if model is not None:
        parts = model.split("/")
        if len(parts) != 2 or any(_MANAGED_ID_RE.fullmatch(part) is None for part in parts):
            _configuration_error(
                "--model must be provider/model using letters, digits, dots, underscores, "
                "colons, or hyphens."
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


_STAGES = (
    ("driver.contract", "Connected to the agent"),
    ("registry.provider-registered", "Offered the test capability"),
    ("registry.provider-discovered", "Found through local discovery"),
    ("delivery.request-routed", "Received the test request"),
    ("capability.synthetic-request-fulfilled", "Returned the expected response"),
)
_STAGE_STATUS = {
    "pass": "PASS",
    "fail": "FAIL",
    "not_tested": "NOT RUN",
    "inconclusive": "INCOMPLETE",
    "error": "ERROR",
}
_NOT_TESTED_BOUNDARY = (
    "  Persistent discovery, real network delivery, identity, authorization, trust,\n"
    "  payments, negotiation, safety, and long-term reliability."
)
_SAFE_RUNTIME_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def _render_human(outcome: AgentTestOutcome, *, target: str) -> str:
    checks = {check.id: check.status for check in outcome.result.evaluation.checks}
    headline = {
        0: "RESULT: PASS",
        1: "RESULT: FAIL",
        3: "RESULT: ERROR",
        4: "RESULT: INCOMPLETE",
        130: "RESULT: INTERRUPTED",
    }.get(outcome.exit_code, "RESULT: ERROR")
    stage_lines = [
        f"  {_STAGE_STATUS.get(checks.get(check_id, 'not_tested'), 'ERROR'):<12}{label}"
        for check_id, label in _STAGES
    ]
    next_step = {
        0: "Review the result and trace evidence.",
        1: "Update the agent's failed behavior, then rerun the test.",
        3: "Review Town's diagnostics, then rerun the test.",
        4: "Check the local agent and runtime, then rerun the test.",
        130: "Rerun the test when ready.",
    }.get(outcome.exit_code, "Review Town's diagnostics, then rerun the test.")
    return "\n".join(
        [
            headline,
            f"Target: {target}",
            "This was a basic local agent test.",
            "",
            "Stages",
            *stage_lines,
            "",
            "Not tested",
            _NOT_TESTED_BOUNDARY,
            "",
            "Next",
            f"  {next_step}",
            "",
            "Artifacts",
            f"  Directory: {outcome.output_directory}",
            "",
        ]
    )


def _write_endpoint_progress(
    *, profile_reference: str, endpoint: str, output_dir: Path | None, verbose: bool
) -> None:
    typer.echo("Running a basic local agent test...", err=True)
    if verbose:
        typer.echo(f"Profile: {profile_reference}", err=True)
        typer.echo(f"Endpoint: {endpoint}", err=True)
        typer.echo(
            f"Output: {output_dir if output_dir is not None else '.town/runs/<run-id>'}",
            err=True,
        )


def _write_managed_progress(
    *,
    runtime_display: RuntimeDisplay,
    runtime_version: str,
    target: str,
    profile_reference: str,
    model: str | None,
    output_dir: Path | None,
    verbose: bool,
) -> None:
    typer.echo(
        f"Running a basic local agent test for {target} with "
        f"{runtime_display.name} {runtime_version}...",
        err=True,
    )
    if verbose:
        typer.echo(f"Profile: {profile_reference}", err=True)
        typer.echo(f"Model: {model or 'configured target model'}", err=True)
        typer.echo(
            f"Output: {output_dir if output_dir is not None else '.town/runs/<run-id>'}",
            err=True,
        )


def _write_verbose_result(outcome: AgentTestOutcome) -> None:
    result = outcome.result
    typer.echo(f"Run: {result.run_id}", err=True)
    typer.echo(f"Profile: {result.profile.id}@{result.profile.version}", err=True)
    typer.echo(f"Profile digest: {result.profile.digest}", err=True)
    typer.echo(f"Endpoint: {result.driver.endpoint_origin}", err=True)
    typer.echo(
        f"Adapter instance: {result.driver.adapter_instance_id or 'not observed'}",
        err=True,
    )
    trace_artifact = next(
        (artifact for artifact in result.artifacts if artifact.kind == "trace"),
        None,
    )
    if trace_artifact is not None:
        trace_path = outcome.output_directory / trace_artifact.path
        relative_trace = os.path.relpath(trace_path, start=Path.cwd())
        typer.echo(
            f"Inspect the trace: nest inspect {shlex.quote(relative_trace)}",
            err=True,
        )


def _available_runtime_connectors() -> tuple[RuntimeConnector, ...]:
    from .openclaw_runtime import OpenClawConnector

    return (OpenClawConnector(),)


def _runtime_commands(target: str, connectors: tuple[RuntimeConnector, ...]) -> list[str]:
    quoted_target = shlex.quote(target)
    return [
        f"nest test agent {quoted_target} --runtime {shlex.quote(connector.runtime_id)}"
        for connector in connectors
    ]


def _target_inventory_commands(connectors: tuple[RuntimeConnector, ...]) -> list[str]:
    commands = {
        connector.runtime_id: "openclaw agents list"
        for connector in connectors
        if connector.runtime_id == "openclaw"
    }
    return list(commands.values())


def _managed_pre_admission_error(
    *,
    kind: str,
    code: str,
    target: str,
    connectors: tuple[RuntimeConnector, ...],
    runtime_display: RuntimeDisplay | None,
) -> NoReturn:
    fallback = {
        "configuration": "RUNTIME_CONFIGURATION_FAILED",
        "incomplete": "RUNTIME_INCOMPLETE",
        "execution": "RUNTIME_EXECUTION_FAILED",
    }.get(kind, "RUNTIME_EXECUTION_FAILED")
    safe_code = code if _SAFE_RUNTIME_CODE_RE.fullmatch(code) is not None else fallback
    commands = _runtime_commands(target, connectors)
    runtime_name = runtime_display.name if runtime_display is not None else "managed"
    check_command = runtime_display.check_command if runtime_display is not None else None
    if kind == "configuration":
        typer.echo(f"Configuration error: {safe_code}", err=True)
        if safe_code == "RUNTIME_NOT_FOUND":
            typer.echo(
                "Next: Install a supported managed runtime version and ensure its "
                "executable is on PATH, then rerun.",
                err=True,
            )
        elif safe_code == "TARGET_NOT_FOUND":
            typer.echo("Next: List configured agents and copy the exact target ID:", err=True)
            for command in _target_inventory_commands(connectors):
                typer.echo(f"  {command}", err=True)
        elif safe_code == "RUNTIME_AMBIGUOUS":
            typer.echo("Next: Choose one runtime explicitly:", err=True)
            for command in commands:
                typer.echo(f"  {command}", err=True)
        elif safe_code == "TARGET_AMBIGUOUS":
            typer.echo(
                "Next: Resolve duplicate exact target IDs, then verify the inventory:", err=True
            )
            for command in _target_inventory_commands(connectors):
                typer.echo(f"  {command}", err=True)
        elif safe_code == "OPENCLAW_PLATFORM_UNSUPPORTED":
            typer.echo(
                "Next: Run Town and OpenClaw together on macOS or Linux. Native Windows "
                "is not supported in this preview. No agent/model turn was started.",
                err=True,
            )
        elif safe_code == "OPENCLAW_REMOTE_DISPATCH":
            typer.echo(
                "Next: Run Town on the OpenClaw computer and check "
                "`openclaw config get gateway.mode --json`; it must be exactly "
                '`"local"`. Remove any configured `OPENCLAW_GATEWAY_URL` override, '
                "then retry. No agent/model turn was started.",
                err=True,
            )
        else:
            check = f" with `{check_command}`" if check_command is not None else ""
            typer.echo(
                f"Next: Check the {runtime_name} runtime{check} and target configuration, "
                "then retry.",
                err=True,
            )
        raise typer.Exit(2)
    if kind == "incomplete":
        typer.echo("RESULT: INCOMPLETE", err=True)
        typer.echo(f"Reason: {safe_code}", err=True)
        check = f" with `{check_command}`" if check_command is not None else ""
        rerun = f", then rerun `{commands[0]}`" if commands else ""
        typer.echo(f"Next: Start or check the {runtime_name} runtime{check}{rerun}.", err=True)
        raise typer.Exit(4)
    typer.echo("RESULT: ERROR", err=True)
    typer.echo(f"Runtime issue: {safe_code}", err=True)
    check = f" with `{check_command}`" if check_command is not None else ""
    typer.echo(f"Next: Check the {runtime_name} runtime{check}, then retry.", err=True)
    raise typer.Exit(3)


def _write_managed_issue(outcome: ManagedAgentTestOutcome) -> None:
    if outcome.issue_code is None:
        return
    code = (
        outcome.issue_code
        if _SAFE_RUNTIME_CODE_RE.fullmatch(outcome.issue_code) is not None
        else "RUNTIME_EXECUTION_FAILED"
    )
    typer.echo(f"Runtime issue: {code}", err=True)
    check_command = outcome.runtime_display.check_command
    check = f" with `{check_command}`" if check_command is not None else ""
    typer.echo(
        f"Next: Check the {outcome.runtime_display.name} runtime{check} and target "
        "configuration, then rerun "
        f"`nest test agent {shlex.quote(outcome.target_id)} --runtime "
        f"{shlex.quote(outcome.runtime_id)}`.",
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
        "Run a basic local agent test with a supported managed runtime or adapter. "
        "Town currently supports existing agents in OpenClaw."
    ),
)
def agent(
    target: str | None = _typer_argument(
        None,
        help="Agent name in the selected runtime.",
    ),
    runtime: str | None = _typer_option(
        None,
        "--runtime",
        help="Auto-detected when omitted; currently OpenClaw on macOS or Linux.",
    ),
    model: str | None = _typer_option(
        None,
        "--model",
        help="Optional model override for this run.",
    ),
    profile: str = _typer_option(
        _PROFILE_ALIAS,
        "--profile",
        help="Built-in test profile.",
        rich_help_panel="Advanced adapter options",
        show_default=False,
    ),
    endpoint: str | None = _typer_option(
        None,
        "--endpoint",
        help="Advanced local adapter origin.",
        rich_help_panel="Advanced adapter options",
    ),
    target_label: str | None = _typer_option(
        None,
        "--target-label",
        help="Adapter-mode evidence label.",
        rich_help_panel="Advanced adapter options",
    ),
    token_env: str | None = _typer_option(
        None,
        "--token-env",
        help="Adapter-mode token variable.",
        rich_help_panel="Advanced adapter options",
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
    """Test one existing managed agent or one advanced local adapter."""
    endpoint_mode = endpoint is not None
    try:
        output_path = None if output_dir is None else Path(output_dir)
        if endpoint_mode:
            conflicts = [
                flag
                for flag, value in (
                    ("TARGET", target),
                    ("--runtime", runtime),
                    ("--model", model),
                )
                if value is not None
            ]
            if conflicts:
                _configuration_error(
                    "--endpoint cannot be combined with " + ", ".join(conflicts) + "."
                )
        else:
            if target is None:
                _configuration_error(
                    "choose a target with `nest test agent TARGET`, or use --endpoint ORIGIN."
                )
            if target_label is not None or token_env is not None:
                _configuration_error(
                    "--target-label and --token-env are only valid with --endpoint."
                )
            _validate_managed_user_values(target=target, runtime=runtime, model=model)
        if profile not in _PROFILE_REFERENCES:
            _configuration_error(f"unknown Test Profile; use {_PROFILE_ALIAS} or {_PROFILE_EXACT}.")
        token = ""
        resolved_token_env = token_env or "TOWN_AGENT_TOKEN"
        resolved_target_label = target_label or "local-agent"
        if endpoint_mode:
            if _ENVIRONMENT_NAME_RE.fullmatch(resolved_token_env) is None:
                _configuration_error("--token-env must name a valid environment variable.")
            token = os.environ.pop(resolved_token_env, None) or ""
            if not token:
                _configuration_error(f"{resolved_token_env} is not set.")
            if _TOKEN_RE.fullmatch(token) is None:
                _configuration_error(
                    f"{resolved_token_env} must contain exactly 64 lowercase hexadecimal "
                    "characters."
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
        resolved_profile = resolve_test_profile(profile)
        profile_reference = f"{resolved_profile.reference.id}@{resolved_profile.reference.version}"
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

    managed_diagnostics: ManagedAgentTestOutcome | None = None
    if endpoint_mode:
        assert endpoint is not None
        try:
            from .http_driver import parse_loopback_origin
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        except Exception:
            _terminal_error(
                "RESULT: ERROR",
                "Town could not prepare the basic local agent test.",
                3,
            )
        try:
            parsed_endpoint = parse_loopback_origin(endpoint)
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        except ValueError:
            _configuration_error("endpoint must be http://127.0.0.1:<port> or http://[::1]:<port>.")
        try:
            _write_endpoint_progress(
                profile_reference=profile_reference,
                endpoint=parsed_endpoint,
                output_dir=output_path,
                verbose=verbose,
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        try:
            outcome = asyncio.run(
                _execute_agent_test(
                    profile=profile,
                    endpoint=parsed_endpoint,
                    token=token,
                    output_dir=output_path,
                    target_label=resolved_target_label,
                )
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        except AgentTestPreAdmissionError as error:
            _agent_pre_admission_error(error.code)
        except (DriverConfigurationError, DriverCompatibilityError) as error:
            if isinstance(error, DriverCompatibilityError):
                detail = (
                    "Configuration error: local adapter does not support the frozen profile or "
                    "driver contract."
                )
            else:
                detail = (
                    "Configuration error: local adapter configuration was rejected before "
                    "admission."
                )
            typer.echo(detail, err=True)
            raise typer.Exit(2) from None
        except DriverContractError:
            _terminal_error(
                "RESULT: FAIL",
                "The local agent returned an invalid response to Town's test request.",
                1,
            )
        except DriverIncompleteError as error:
            _pre_admission_incomplete_error(
                code=error.code,
                endpoint=parsed_endpoint,
            )
        except (TownDriverError, AgentTestTownError):
            _terminal_error(
                "RESULT: ERROR",
                "Town could not complete the basic local agent test.",
                3,
            )
        except TimeoutError:
            _pre_admission_incomplete_error(
                code="TIMEOUT",
                endpoint=parsed_endpoint,
            )
        except AgentDriverError:
            _terminal_error(
                "RESULT: ERROR",
                "Town could not classify a local agent failure.",
                3,
            )
        except Exception:
            _terminal_error(
                "RESULT: ERROR",
                "Town could not complete the basic local agent test.",
                3,
            )
        display_target = resolved_target_label
    else:
        assert target is not None
        try:
            from .managed_runtime import run_managed_agent_test
            from .runtime_connectors import (
                RuntimeConfigurationError,
                RuntimeExecutionError,
                RuntimeIncompleteError,
                prepare_runtime,
                select_runtime,
            )

            connectors = _available_runtime_connectors()
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        except Exception:
            _terminal_error(
                "RESULT: ERROR",
                "Town could not load the managed runtime connector.",
                3,
            )

        selected_runtime_display: RuntimeDisplay | None = None
        try:
            connector, probe, selected_target = select_runtime(
                target_id=target,
                requested_runtime=runtime,
                connectors=connectors,
            )
            selected_runtime_display = probe.display
            prepared_runtime = prepare_runtime(
                connector=connector,
                probe=probe,
                target=selected_target,
                model_override=model,
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        except RuntimeConfigurationError as error:
            _managed_pre_admission_error(
                kind="configuration",
                code=error.code,
                target=target,
                connectors=connectors,
                runtime_display=selected_runtime_display,
            )
        except RuntimeIncompleteError as error:
            _managed_pre_admission_error(
                kind="incomplete",
                code=error.code,
                target=target,
                connectors=connectors,
                runtime_display=selected_runtime_display,
            )
        except RuntimeExecutionError as error:
            _managed_pre_admission_error(
                kind="execution",
                code=error.code,
                target=target,
                connectors=connectors,
                runtime_display=selected_runtime_display,
            )
        except Exception:
            _terminal_error(
                "RESULT: ERROR",
                "Town's managed runtime connector failed unexpectedly.",
                3,
            )

        try:
            _write_managed_progress(
                runtime_display=probe.display,
                runtime_version=probe.version,
                target=target,
                profile_reference=profile_reference,
                model=model or selected_target.configured_model,
                output_dir=output_path,
                verbose=verbose,
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        try:
            managed_outcome = asyncio.run(
                run_managed_agent_test(
                    prepared_runtime=prepared_runtime,
                    profile=profile,
                    output_dir=output_path,
                    base_dir=Path.cwd(),
                )
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            _interrupted_error()
        except AgentTestPreAdmissionError as error:
            _agent_pre_admission_error(error.code)
        except RuntimeConfigurationError as error:
            _managed_pre_admission_error(
                kind="configuration",
                code=error.code,
                target=target,
                connectors=connectors,
                runtime_display=prepared_runtime.display,
            )
        except RuntimeIncompleteError as error:
            _managed_pre_admission_error(
                kind="incomplete",
                code=error.code,
                target=target,
                connectors=connectors,
                runtime_display=prepared_runtime.display,
            )
        except RuntimeExecutionError as error:
            _managed_pre_admission_error(
                kind="execution",
                code=error.code,
                target=target,
                connectors=connectors,
                runtime_display=prepared_runtime.display,
            )
        except (TownDriverError, AgentTestTownError):
            _terminal_error(
                "RESULT: ERROR",
                "Town could not complete the managed agent test.",
                3,
            )
        except Exception:
            _terminal_error(
                "RESULT: ERROR",
                "Town could not complete the managed agent test.",
                3,
            )
        managed_diagnostics = managed_outcome
        outcome = managed_outcome.outcome
        display_target = target

    try:
        if managed_diagnostics is not None:
            _write_managed_issue(managed_diagnostics)
        _write_diagnostics(outcome)
        if verbose:
            _write_verbose_result(outcome)
        if output_format == _OutputFormat.JSON:
            _write_stdout_bytes(outcome.result_bytes)
        else:
            typer.echo(
                _render_human(outcome, target=display_target),
                nl=False,
                color=False if no_color else None,
            )
    except (KeyboardInterrupt, asyncio.CancelledError):
        _output_interrupted_error(outcome)
    raise typer.Exit(outcome.exit_code)
