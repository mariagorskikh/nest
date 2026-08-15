# SPDX-License-Identifier: Apache-2.0
"""Static contracts for managed, session-oriented runtime connectors."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

_MAX_METADATA_LENGTH = 128
_ACTIVITIES = frozenset({"none_reported", "reported", "unknown"})
_ISSUE_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def _metadata(value: str, *, maximum: int = _MAX_METADATA_LENGTH) -> str:
    """Validate bounded metadata without retaining or exposing unsafe text."""
    if type(value) is not str or not value or value != value.strip():
        raise ValueError("INVALID_RUNTIME_METADATA")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("INVALID_RUNTIME_METADATA")
    return value


def _optional_metadata(value: str | None) -> str | None:
    if value is None:
        return None
    return _metadata(value)


@dataclass(frozen=True, slots=True)
class RuntimeDisplay:
    """Bounded connector-owned text that Town may safely render."""

    name: str
    check_command: str | None

    def __post_init__(self) -> None:
        _metadata(self.name)
        if self.check_command is not None:
            _metadata(self.check_command, maximum=256)


@dataclass(frozen=True, slots=True)
class RuntimeProbe:
    runtime_id: str
    executable: Path
    version: str
    display: RuntimeDisplay

    def __post_init__(self) -> None:
        _metadata(self.runtime_id)
        _metadata(self.version)
        if type(self.display) is not RuntimeDisplay:
            raise ValueError("INVALID_RUNTIME_METADATA")


@dataclass(frozen=True, slots=True)
class RuntimeTarget:
    id: str
    configured_model: str | None

    def __post_init__(self) -> None:
        _metadata(self.id)
        _optional_metadata(self.configured_model)


@dataclass(frozen=True, slots=True)
class RuntimeTurn:
    intent: Mapping[str, object]
    provider: str | None
    model: str | None
    session_ref_digest: str
    activity: Literal["none_reported", "reported", "unknown"]

    def __post_init__(self) -> None:
        _optional_metadata(self.provider)
        _optional_metadata(self.model)
        _metadata(self.session_ref_digest)
        if self.activity not in _ACTIVITIES:
            raise ValueError("INVALID_RUNTIME_ACTIVITY")


class RuntimeRun(Protocol):
    def turn(self, observation: Mapping[str, object]) -> RuntimeTurn: ...

    def close(self) -> None: ...


class PreparedRuntime(Protocol):
    runtime_id: str
    runtime_version: str
    display: RuntimeDisplay
    target: RuntimeTarget
    target_label: str
    issue_policy: RuntimeIssuePolicy
    adapter_instance_id: str

    def open_run(self, town_run_id: str) -> RuntimeRun: ...


class RuntimeConnector(Protocol):
    runtime_id: str
    issue_policy: RuntimeIssuePolicy

    def probe(self) -> RuntimeProbe | None: ...

    def list_targets(self, probe: RuntimeProbe) -> tuple[RuntimeTarget, ...]: ...

    def prepare(
        self,
        probe: RuntimeProbe,
        target: RuntimeTarget,
        model_override: str | None,
    ) -> PreparedRuntime: ...


class _RuntimeError(RuntimeError):
    """Base for errors whose public text is a stable code only."""

    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RuntimeConfigurationError(_RuntimeError):
    """The configured runtime or target set cannot be selected safely."""


class RuntimeIncompleteError(_RuntimeError):
    """The selected runtime cannot provide the required managed seam."""


class RuntimeExecutionError(_RuntimeError):
    """A managed runtime operation failed without exposing runtime details."""


@dataclass(frozen=True, slots=True)
class RuntimeIssuePolicy:
    """Connector-owned, class-aware allowlist for post-admission issue codes."""

    configuration: frozenset[str] = frozenset()
    incomplete: frozenset[str] = frozenset()
    execution: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        groups = (self.configuration, self.incomplete, self.execution)
        if any(type(group) is not frozenset for group in groups):
            raise ValueError("INVALID_RUNTIME_ISSUE_POLICY")
        codes = tuple(code for group in groups for code in group)
        if any(type(code) is not str or _ISSUE_CODE_RE.fullmatch(code) is None for code in codes):
            raise ValueError("INVALID_RUNTIME_ISSUE_POLICY")
        if len(codes) != len(set(codes)):
            raise ValueError("INVALID_RUNTIME_ISSUE_POLICY")

    def code_for(
        self,
        error: RuntimeConfigurationError | RuntimeIncompleteError | RuntimeExecutionError,
    ) -> str:
        if isinstance(error, RuntimeConfigurationError):
            allowed = self.configuration
            fallback = "RUNTIME_CONFIGURATION_FAILED"
        elif isinstance(error, RuntimeIncompleteError):
            allowed = self.incomplete
            fallback = "RUNTIME_INCOMPLETE"
        else:
            allowed = self.execution
            fallback = "RUNTIME_EXECUTION_FAILED"
        return error.code if error.code in allowed else fallback


def _safe_error_details(
    policy: RuntimeIssuePolicy,
    error: RuntimeConfigurationError | RuntimeIncompleteError | RuntimeExecutionError,
) -> tuple[
    type[RuntimeConfigurationError] | type[RuntimeIncompleteError] | type[RuntimeExecutionError],
    str,
]:
    if isinstance(error, RuntimeConfigurationError):
        error_type = RuntimeConfigurationError
    elif isinstance(error, RuntimeIncompleteError):
        error_type = RuntimeIncompleteError
    else:
        error_type = RuntimeExecutionError
    return error_type, policy.code_for(error)


def _connector_issue_policy(connector: RuntimeConnector) -> RuntimeIssuePolicy:
    invalid = False
    policy: object = None
    try:
        policy = connector.issue_policy
    except Exception:
        invalid = True
    if invalid:
        raise RuntimeExecutionError("RUNTIME_POLICY_INVALID")
    if type(policy) is not RuntimeIssuePolicy:
        raise RuntimeExecutionError("RUNTIME_POLICY_INVALID")
    return policy


def _probe_connector(connector: RuntimeConnector) -> RuntimeProbe | None:
    policy = _connector_issue_policy(connector)
    probe: RuntimeProbe | None = None
    failure_type: (
        type[RuntimeConfigurationError]
        | type[RuntimeIncompleteError]
        | type[RuntimeExecutionError]
        | None
    ) = None
    failure_code: str | None = None
    try:
        probe = connector.probe()
    except (RuntimeConfigurationError, RuntimeIncompleteError, RuntimeExecutionError) as error:
        failure_type, failure_code = _safe_error_details(policy, error)
    if failure_type is not None:
        assert failure_code is not None
        raise failure_type(failure_code)
    return probe


def _list_connector_targets(
    connector: RuntimeConnector,
    probe: RuntimeProbe,
) -> tuple[RuntimeTarget, ...]:
    policy = _connector_issue_policy(connector)
    targets: tuple[RuntimeTarget, ...] | None = None
    failure_type: (
        type[RuntimeConfigurationError]
        | type[RuntimeIncompleteError]
        | type[RuntimeExecutionError]
        | None
    ) = None
    failure_code: str | None = None
    try:
        targets = connector.list_targets(probe)
    except (RuntimeConfigurationError, RuntimeIncompleteError, RuntimeExecutionError) as error:
        failure_type, failure_code = _safe_error_details(policy, error)
    if failure_type is not None:
        assert failure_code is not None
        raise failure_type(failure_code)
    assert targets is not None
    return targets


def prepare_runtime(
    *,
    connector: RuntimeConnector,
    probe: RuntimeProbe,
    target: RuntimeTarget,
    model_override: str | None,
) -> PreparedRuntime:
    """Prepare through the connector's validated policy and bind policy continuity."""
    policy = _connector_issue_policy(connector)
    prepared: PreparedRuntime | None = None
    failure_type: (
        type[RuntimeConfigurationError]
        | type[RuntimeIncompleteError]
        | type[RuntimeExecutionError]
        | None
    ) = None
    failure_code: str | None = None
    try:
        prepared = connector.prepare(probe, target, model_override)
    except (RuntimeConfigurationError, RuntimeIncompleteError, RuntimeExecutionError) as error:
        failure_type, failure_code = _safe_error_details(policy, error)
    if failure_type is not None:
        assert failure_code is not None
        raise failure_type(failure_code)
    assert prepared is not None
    policy_unavailable = False
    prepared_policy: object = None
    try:
        prepared_policy = prepared.issue_policy
    except Exception:
        policy_unavailable = True
    if (
        policy_unavailable
        or type(prepared_policy) is not RuntimeIssuePolicy
        or prepared_policy != policy
    ):
        raise RuntimeExecutionError("RUNTIME_POLICY_MISMATCH")
    return prepared


def _connector_for_runtime(
    requested_runtime: str,
    connectors: tuple[RuntimeConnector, ...],
) -> RuntimeConnector:
    matches = tuple(
        connector for connector in connectors if connector.runtime_id == requested_runtime
    )
    if not matches:
        raise RuntimeConfigurationError("RUNTIME_NOT_FOUND")
    if len(matches) != 1:
        raise RuntimeConfigurationError("RUNTIME_AMBIGUOUS")
    return matches[0]


def _matching_target(
    connector: RuntimeConnector,
    probe: RuntimeProbe,
    target_id: str,
) -> tuple[RuntimeConnector, RuntimeProbe, RuntimeTarget]:
    matches = tuple(
        target for target in _list_connector_targets(connector, probe) if target.id == target_id
    )
    if not matches:
        raise RuntimeConfigurationError("TARGET_NOT_FOUND")
    if len(matches) != 1:
        raise RuntimeConfigurationError("TARGET_AMBIGUOUS")
    return connector, probe, matches[0]


def _require_probe_identity(connector: RuntimeConnector, probe: RuntimeProbe) -> None:
    if probe.runtime_id != connector.runtime_id:
        raise RuntimeConfigurationError("RUNTIME_ID_MISMATCH")


def select_runtime(
    *,
    target_id: str,
    requested_runtime: str | None,
    connectors: tuple[RuntimeConnector, ...],
) -> tuple[RuntimeConnector, RuntimeProbe, RuntimeTarget]:
    """Select exactly one probed connector and exact target.

    An omitted runtime is not a default: absent connectors are skipped, while an
    inspection failure remains fatal. Selection is made only from exact target
    matches. An explicit runtime limits probing to that connector first.
    """
    _metadata(target_id)
    if requested_runtime is not None:
        _metadata(requested_runtime)

    if requested_runtime is not None:
        connector = _connector_for_runtime(requested_runtime, connectors)
        probe = _probe_connector(connector)
        if probe is None:
            raise RuntimeConfigurationError("RUNTIME_NOT_FOUND")
        _require_probe_identity(connector, probe)
        return _matching_target(connector, probe, target_id)

    probed: list[tuple[RuntimeConnector, RuntimeProbe]] = []
    for connector in connectors:
        probe = _probe_connector(connector)
        if probe is None:
            continue
        _require_probe_identity(connector, probe)
        probed.append((connector, probe))

    if not probed:
        raise RuntimeConfigurationError("RUNTIME_NOT_FOUND")

    candidates: list[tuple[RuntimeConnector, RuntimeProbe, RuntimeTarget]] = []
    for connector, probe in probed:
        matches = tuple(
            target for target in _list_connector_targets(connector, probe) if target.id == target_id
        )
        if len(matches) > 1:
            raise RuntimeConfigurationError("TARGET_AMBIGUOUS")
        if matches:
            candidates.append((connector, probe, matches[0]))

    if not candidates:
        raise RuntimeConfigurationError("TARGET_NOT_FOUND")
    if len(candidates) != 1:
        raise RuntimeConfigurationError("RUNTIME_AMBIGUOUS")
    return candidates[0]
