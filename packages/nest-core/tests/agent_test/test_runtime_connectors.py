# SPDX-License-Identifier: Apache-2.0
"""Tests for the generic managed-runtime connector seam."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast, get_type_hints

import pytest
from nest_core.agent_test.runtime_connectors import (
    PreparedRuntime,
    RuntimeConfigurationError,
    RuntimeConnector,
    RuntimeDisplay,
    RuntimeExecutionError,
    RuntimeIncompleteError,
    RuntimeIssuePolicy,
    RuntimeProbe,
    RuntimeRun,
    RuntimeTarget,
    RuntimeTurn,
    prepare_runtime,
    select_runtime,
)


class FakeConnector:
    def __init__(
        self,
        runtime_id: str,
        probe: RuntimeProbe | None,
        targets: tuple[RuntimeTarget, ...] = (),
        *,
        probe_error: RuntimeError | None = None,
        list_error: RuntimeError | None = None,
        prepare_error: RuntimeError | None = None,
        issue_policy: RuntimeIssuePolicy | None = None,
    ) -> None:
        self.runtime_id = runtime_id
        self.issue_policy = issue_policy or RuntimeIssuePolicy()
        self.probe_value = probe
        self.target_values = targets
        self.probe_error = probe_error
        self.list_error = list_error
        self.prepare_error = prepare_error
        self.probe_calls = 0
        self.list_targets_calls = 0

    def probe(self) -> RuntimeProbe | None:
        self.probe_calls += 1
        if self.probe_error is not None:
            raise self.probe_error
        return self.probe_value

    def list_targets(self, probe: RuntimeProbe) -> tuple[RuntimeTarget, ...]:
        self.list_targets_calls += 1
        if self.list_error is not None:
            raise self.list_error
        assert probe is self.probe_value
        return self.target_values

    def prepare(
        self,
        probe: RuntimeProbe,
        target: RuntimeTarget,
        model_override: str | None,
    ) -> PreparedRuntime:
        if self.prepare_error is not None:
            raise self.prepare_error
        raise NotImplementedError


def _probe(runtime_id: str) -> RuntimeProbe:
    return RuntimeProbe(
        runtime_id,
        Path(f"/opt/{runtime_id}"),
        "1.2.3",
        RuntimeDisplay(runtime_id.title(), f"{runtime_id} doctor"),
    )


def _target(target_id: str) -> RuntimeTarget:
    return RuntimeTarget(target_id, None)


def test_explicit_runtime_probes_only_the_requested_connector() -> None:
    requested = FakeConnector("requested", _probe("requested"), (_target("agent"),))
    unrelated = FakeConnector("unrelated", _probe("unrelated"), (_target("agent"),))

    result = select_runtime(
        target_id="agent",
        requested_runtime="requested",
        connectors=(requested, unrelated),
    )

    assert result == (requested, requested.probe_value, requested.target_values[0])
    assert requested.probe_calls == 1
    assert requested.list_targets_calls == 1
    assert unrelated.probe_calls == 0
    assert unrelated.list_targets_calls == 0


def test_selection_requires_an_exact_target_match() -> None:
    connector = FakeConnector("runtime", _probe("runtime"), (_target("agent-prod"),))

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(connector,))

    assert caught.value.code == "TARGET_NOT_FOUND"
    assert str(caught.value) == "TARGET_NOT_FOUND"


def test_one_unambiguous_target_selects() -> None:
    connector = FakeConnector(
        "runtime", _probe("runtime"), (_target("other"), _target("agent"), _target("third"))
    )

    selected_connector, probe, target = select_runtime(
        target_id="agent", requested_runtime=None, connectors=(connector,)
    )

    assert selected_connector is connector
    assert probe is connector.probe_value
    assert target is connector.target_values[1]


def test_multiple_matching_targets_are_a_configuration_error() -> None:
    connector = FakeConnector("runtime", _probe("runtime"), (_target("agent"), _target("agent")))

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(connector,))

    assert caught.value.code == "TARGET_AMBIGUOUS"
    assert str(caught.value) == "TARGET_AMBIGUOUS"


def test_multiple_connectors_matching_target_are_ambiguous() -> None:
    first = FakeConnector("first", _probe("first"), (_target("agent"),))
    second = FakeConnector("second", _probe("second"), (_target("agent"),))

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(first, second))

    assert caught.value.code == "RUNTIME_AMBIGUOUS"


def test_auto_selection_skips_a_connector_that_is_definitely_absent() -> None:
    inspectable = FakeConnector("inspectable", _probe("inspectable"), (_target("agent"),))
    absent = FakeConnector("hermes", None)

    selected = select_runtime(
        target_id="agent",
        requested_runtime=None,
        connectors=(absent, inspectable),
    )

    assert selected == (inspectable, inspectable.probe_value, inspectable.target_values[0])
    assert absent.probe_calls == 1
    assert absent.list_targets_calls == 0
    assert inspectable.list_targets_calls == 1


def test_all_absent_connectors_fail_without_target_inspection() -> None:
    openclaw = FakeConnector("openclaw", None)
    hermes = FakeConnector("hermes", None)

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(openclaw, hermes))

    assert caught.value.code == "RUNTIME_NOT_FOUND"
    assert openclaw.list_targets_calls == hermes.list_targets_calls == 0


def test_explicit_absent_connector_fails_before_target_inspection() -> None:
    connector = FakeConnector("hermes", None)

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime="hermes", connectors=(connector,))

    assert caught.value.code == "RUNTIME_NOT_FOUND"
    assert connector.probe_calls == 1
    assert connector.list_targets_calls == 0


def test_typed_probe_inspection_failure_fails_closed_in_auto_mode() -> None:
    openclaw = FakeConnector("openclaw", _probe("openclaw"), (_target("agent"),))
    hermes = FakeConnector(
        "hermes",
        None,
        probe_error=RuntimeExecutionError("HERMES_PROBE_FAILED"),
        issue_policy=RuntimeIssuePolicy(execution=frozenset({"HERMES_PROBE_FAILED"})),
    )

    with pytest.raises(RuntimeExecutionError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(openclaw, hermes))

    assert caught.value.code == "HERMES_PROBE_FAILED"
    assert openclaw.list_targets_calls == 0
    assert hermes.list_targets_calls == 0


def test_invalid_connector_policy_fails_before_probe() -> None:
    connector = FakeConnector("hermes", _probe("hermes"), (_target("agent"),))
    connector.issue_policy = cast("Any", object())

    with pytest.raises(RuntimeExecutionError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(connector,))

    assert caught.value.code == "RUNTIME_POLICY_INVALID"
    assert connector.probe_calls == 0
    assert connector.list_targets_calls == 0


def test_sanitized_connector_error_drops_private_exception_context() -> None:
    connector = FakeConnector(
        "hermes",
        None,
        probe_error=RuntimeExecutionError("PRIVATE_TOKEN_ABC123"),
    )

    with pytest.raises(RuntimeExecutionError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(connector,))

    assert caught.value.code == "RUNTIME_EXECUTION_FAILED"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "PRIVATE_TOKEN_ABC123" not in repr(caught.value)


@pytest.mark.parametrize(
    ("stage", "failure", "error_type", "fallback"),
    [
        (
            "probe",
            RuntimeConfigurationError("PRIVATE_TOKEN_ABC123"),
            RuntimeConfigurationError,
            "RUNTIME_CONFIGURATION_FAILED",
        ),
        (
            "list",
            RuntimeIncompleteError("PRIVATE_TOKEN_ABC123"),
            RuntimeIncompleteError,
            "RUNTIME_INCOMPLETE",
        ),
        (
            "prepare",
            RuntimeExecutionError("PRIVATE_TOKEN_ABC123"),
            RuntimeExecutionError,
            "RUNTIME_EXECUTION_FAILED",
        ),
    ],
)
def test_probe_list_and_prepare_drop_private_error_context_and_traceback_locals(
    stage: str,
    failure: RuntimeError,
    error_type: type[RuntimeError],
    fallback: str,
) -> None:
    probe = _probe("hermes")
    target = _target("agent")
    connector = FakeConnector(
        "hermes",
        probe,
        (target,),
        probe_error=failure if stage == "probe" else None,
        list_error=failure if stage == "list" else None,
        prepare_error=failure if stage == "prepare" else None,
    )

    with pytest.raises(error_type) as caught:
        if stage == "prepare":
            prepare_runtime(
                connector=connector,
                probe=probe,
                target=target,
                model_override=None,
            )
        else:
            select_runtime(
                target_id="agent",
                requested_runtime=None,
                connectors=(connector,),
            )

    assert str(caught.value) == fallback
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    traceback = caught.value.__traceback__
    retained: list[str] = []
    while traceback is not None:
        if "/tests/" not in traceback.tb_frame.f_code.co_filename:
            retained.append(repr(traceback.tb_frame.f_locals))
        traceback = traceback.tb_next
    assert "PRIVATE_TOKEN_ABC123" not in " ".join(retained)


def test_policy_access_failure_drops_private_error_before_probe() -> None:
    class BrokenPolicyConnector:
        runtime_id = "hermes"

        @property
        def issue_policy(self) -> RuntimeIssuePolicy:
            raise RuntimeExecutionError("PRIVATE_TOKEN_ABC123")

        def probe(self) -> RuntimeProbe | None:
            raise AssertionError("probe must not run")

        def list_targets(self, probe: RuntimeProbe) -> tuple[RuntimeTarget, ...]:
            raise AssertionError(probe)

        def prepare(
            self,
            probe: RuntimeProbe,
            target: RuntimeTarget,
            model_override: str | None,
        ) -> PreparedRuntime:
            raise AssertionError((probe, target, model_override))

    with pytest.raises(RuntimeExecutionError) as caught:
        select_runtime(
            target_id="agent",
            requested_runtime=None,
            connectors=(cast("RuntimeConnector", BrokenPolicyConnector()),),
        )

    assert caught.value.code == "RUNTIME_POLICY_INVALID"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_unknown_explicit_runtime_does_not_probe_path_order_candidates() -> None:
    first = FakeConnector("first", _probe("first"), (_target("agent"),))
    second = FakeConnector("second", _probe("second"), (_target("agent"),))

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime="missing", connectors=(first, second))

    assert caught.value.code == "RUNTIME_NOT_FOUND"
    assert first.probe_calls == 0
    assert second.probe_calls == 0


def test_explicit_runtime_rejects_a_probe_with_a_different_runtime_id() -> None:
    connector = FakeConnector("openclaw", _probe("hermes"), (_target("agent"),))

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime="openclaw", connectors=(connector,))

    assert caught.value.code == "RUNTIME_ID_MISMATCH"
    assert connector.list_targets_calls == 0


def test_implicit_runtime_rejects_a_probe_with_a_different_runtime_id() -> None:
    connector = FakeConnector("openclaw", _probe("hermes"), (_target("agent"),))

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(connector,))

    assert caught.value.code == "RUNTIME_ID_MISMATCH"
    assert connector.list_targets_calls == 0


def test_missing_runtime_without_default_is_not_selected_by_order() -> None:
    first = FakeConnector("first", _probe("first"), ())
    second = FakeConnector("second", _probe("second"), ())

    with pytest.raises(RuntimeConfigurationError) as caught:
        select_runtime(target_id="agent", requested_runtime=None, connectors=(first, second))

    assert caught.value.code == "TARGET_NOT_FOUND"


def test_contract_dataclasses_are_frozen_and_preserve_unknown_activity() -> None:
    display = RuntimeDisplay("Runtime", "runtime doctor")
    probe = RuntimeProbe("runtime", Path("/opt/runtime"), "1.2.3", display)
    target = RuntimeTarget("agent", None)
    turn = RuntimeTurn(
        intent={"kind": "none"},
        provider=None,
        model=None,
        session_ref_digest="sha256:unknown",
        activity="unknown",
    )

    with pytest.raises(FrozenInstanceError):
        probe.runtime_id = "other"  # type: ignore[misc]
    assert target.configured_model is None
    assert turn.activity == "unknown"


def test_runtime_issue_policy_is_frozen_class_aware_and_fail_closed() -> None:
    policy = RuntimeIssuePolicy(
        configuration=frozenset({"HERMES_CONFIG_INVALID"}),
        incomplete=frozenset({"HERMES_UNAVAILABLE"}),
        execution=frozenset({"HERMES_TIMEOUT"}),
    )

    assert policy.code_for(RuntimeConfigurationError("HERMES_CONFIG_INVALID")) == (
        "HERMES_CONFIG_INVALID"
    )
    assert policy.code_for(RuntimeIncompleteError("HERMES_UNAVAILABLE")) == ("HERMES_UNAVAILABLE")
    assert policy.code_for(RuntimeExecutionError("HERMES_TIMEOUT")) == "HERMES_TIMEOUT"
    assert policy.code_for(RuntimeIncompleteError("HERMES_TIMEOUT")) == "RUNTIME_INCOMPLETE"
    assert policy.code_for(RuntimeExecutionError("SYNTACTICALLY_VALID")) == (
        "RUNTIME_EXECUTION_FAILED"
    )
    with pytest.raises(FrozenInstanceError):
        policy.execution = frozenset()  # type: ignore[misc]


@pytest.mark.parametrize(
    "metadata",
    [
        RuntimeDisplay("Hermes", "hermes doctor"),
        RuntimeDisplay("Hermes Runtime", None),
    ],
)
def test_runtime_display_is_bounded_safe_metadata(metadata: RuntimeDisplay) -> None:
    assert metadata.name.startswith("Hermes")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: RuntimeDisplay("Hermes\nspoof", None),
        lambda: RuntimeDisplay("Hermes", "hermes doctor\x1b[31m"),
        lambda: RuntimeIssuePolicy(execution=frozenset({"private-code"})),
        lambda: RuntimeIssuePolicy(
            configuration=frozenset({"HERMES_DUPLICATE"}),
            execution=frozenset({"HERMES_DUPLICATE"}),
        ),
    ],
)
def test_runtime_display_and_issue_policy_reject_unsafe_or_ambiguous_metadata(
    factory: object,
) -> None:
    with pytest.raises(ValueError):
        cast("Any", factory)()


def test_protocols_are_static_only_and_exceptions_are_code_only() -> None:
    assert "turn" in RuntimeRun.__dict__
    assert get_type_hints(PreparedRuntime)["runtime_id"] is str
    assert get_type_hints(PreparedRuntime)["display"] is RuntimeDisplay
    assert get_type_hints(PreparedRuntime)["issue_policy"] is RuntimeIssuePolicy
    assert get_type_hints(RuntimeConnector)["runtime_id"] is str
    assert get_type_hints(RuntimeConnector)["issue_policy"] is RuntimeIssuePolicy
    assert str(RuntimeIncompleteError("INCOMPLETE")) == "INCOMPLETE"
    assert str(RuntimeExecutionError("EXECUTION_FAILED")) == "EXECUTION_FAILED"
    assert isinstance(RuntimeRun, type)
    assert isinstance(PreparedRuntime, type)
    assert isinstance(RuntimeConnector, type)
