# SPDX-License-Identifier: Apache-2.0
"""Dependency-boundary regressions for the generic simulator and runner."""

from __future__ import annotations

import ast
import importlib.util
import inspect
from dataclasses import fields
from pathlib import Path

import nest_core.agent_test as agent_test
import nest_core.sim.agent as sim_agent

_CORE_PACKAGE = Path(__file__).parents[2] / "nest_core"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


def test_simulator_package_does_not_depend_on_agent_test() -> None:
    """Adding evidence-model imports below sim would restore the reverse dependency."""
    offenders = {
        path.relative_to(_CORE_PACKAGE): sorted(
            name for name in _imports(path) if name.startswith("nest_core.agent_test")
        )
        for path in (_CORE_PACKAGE / "sim").rglob("*.py")
        if any(name.startswith("nest_core.agent_test") for name in _imports(path))
    }

    assert offenders == {}


def test_scenario_event_boundary_is_generic_and_trace_writer_free() -> None:
    """Feature fields or a writer argument would couple core sim back to evidence."""
    agent_path = _CORE_PACKAGE / "sim" / "agent.py"
    request_type = getattr(sim_agent, "ScenarioEventRequest", None)

    assert request_type is not None
    assert [field.name for field in fields(request_type)] == [
        "kind",
        "logical_time",
        "observer",
        "subject",
        "data",
        "attributes",
    ]
    assert [field.name for field in fields(sim_agent.ScenarioEventReceipt)] == [
        "event_id",
        "trace_record",
    ]
    assert list(inspect.signature(sim_agent.ScenarioEventSink.record).parameters) == [
        "self",
        "request",
    ]
    assert list(inspect.signature(sim_agent.ScenarioAgentContext.record_scenario_event).parameters)[
        1:
    ] == ["kind", "observer", "subject", "data", "attributes"]
    assert "nest_core.sim.trace" not in _imports(agent_path)


def test_generic_runner_has_no_profile_specific_authority() -> None:
    """Profile subjects and capability policy belong above the reusable runner."""
    path = _CORE_PACKAGE / "runner.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    argument_names = {
        argument.arg
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for argument in [*node.args.args, *node.args.kwonlyargs]
    }
    string_constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    assert not any(name.startswith("nest_core.agent_test") for name in _imports(path))
    assert "AgentTestRuntime" not in identifiers
    assert "test_runtime" not in argument_names | identifiers
    assert "subject_participant_id" not in identifiers
    assert not any("capability_fulfillment" in value for value in string_constants)


def test_capability_scenario_uses_only_generic_simulator_context() -> None:
    """The deterministic scenario may not recover an agent-test dependency."""
    path = _CORE_PACKAGE / "scenarios_builtin" / "capability_fulfillment.py"

    assert not any(name.startswith("nest_core.agent_test") for name in _imports(path))


def test_contract_models_are_split_by_public_responsibility() -> None:
    """The compatibility module cannot recover the former all-in-one model implementation."""
    expected_modules = {
        "nest_core.agent_test.contracts",
        "nest_core.agent_test.capability_profile",
        "nest_core.agent_test.evidence",
    }

    assert all(importlib.util.find_spec(name) is not None for name in expected_modules)
    tree = ast.parse((_CORE_PACKAGE / "agent_test" / "models.py").read_text(encoding="utf-8"))
    assert not any(isinstance(node, (ast.ClassDef, ast.FunctionDef)) for node in tree.body)


def test_agent_test_facade_does_not_export_internal_runtime() -> None:
    """The run recorder remains an internal implementation detail."""
    assert "AgentTestRuntime" not in agent_test.__all__
    assert not hasattr(agent_test, "AgentTestRuntime")
