# SPDX-License-Identifier: Apache-2.0
"""Guards against drift between the three hand-maintained scenario registries.

Nanda Town keeps three registries in sync by hand, with nothing enforcing that
they agree:

1. ``scenarios/*.yaml``     -- shipped scenario files, each naming a ``task.type``
2. ``nest_core.scenarios``  -- ``_try_load_builtin``, an if/elif chain mapping
                               ``task.type`` -> agent factory
3. ``nest_core.validators`` -- ``VALIDATORS``, mapping ``task.type`` -> property checks

Drift between them is silent today.
``test_validators.py::TestValidatorRegistry::test_all_scenario_types_registered``
asserts only that a *name* is a key in ``VALIDATORS``; it never asks whether a
scenario of that type can be built, run, or validated. A name can therefore
satisfy that test while being unreachable end to end.

Known drift present at the time this module was added is marked ``xfail`` with
the specific reason, so CI stays green while the gap stays visible. The markers
are ``strict``: fixing one turns its case into an ``XPASS`` failure, which is
the signal to delete the marker rather than let it rot.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from nest_core.scenarios import get_scenario_factory
from nest_core.validators import VALIDATORS

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCENARIO_DIR = _REPO_ROOT / "scenarios"

# --- Known drift, as audited at 675a20b ------------------------------------
# Each entry is a finding, not an accepted state. See the reason strings.

_NO_FACTORY = {
    "streaming_payments": (
        "scenarios/streaming_payments.yaml and streaming_payments_partition.yaml "
        "ship but no factory is registered for task.type 'streaming_payments' "
        "(added by PR #21); `nest run` on either raises KeyError"
    ),
}

_UNREACHABLE_VALIDATORS = {
    "streaming_payments": (
        "3 validators registered against a task.type whose scenarios cannot be "
        "instantiated, so they have never run against a real trace"
    ),
    "receipt_reputation_majority": (
        "3 validators registered against a task.type no scenario declares -- "
        "receipt_reputation_majority_ring.yaml declares task.type "
        "'receipt_reputation'"
    ),
}

_MISSING_VALIDATOR_ENTRY = {
    "capability_spoofing",
    "delegated_auth",
    "delegated_auth_partition",
    "gossip_byzantine_forgery",
    "gossip_eclipse",
    "gossip_registry",
    "gossip_signed_equivocation",
}


def _task_type(path: Path) -> str | None:
    """Read the declared ``task.type`` from a scenario YAML.

    Example::

        ttype = _task_type(Path("scenarios/marketplace.yaml"))
    """
    data = cast("dict[str, Any]", yaml.safe_load(path.read_text()) or {})
    task = cast("dict[str, Any]", data.get("task") or {})
    ttype: Any = task.get("type")
    return str(ttype) if ttype else None


def _factory_exists(task_type: str) -> bool:
    """True when ``nest_core`` can build agents for this task type.

    Example::

        assert _factory_exists("marketplace")
    """
    try:
        get_scenario_factory(task_type)
    except KeyError:
        return False
    return True


def _scenario_params() -> list[Any]:
    """Scenario files as pytest params, xfailing those with no factory.

    Example::

        params = _scenario_params()
    """
    params: list[Any] = []
    for path in sorted(_SCENARIO_DIR.glob("*.yaml")):
        ttype = _task_type(path)
        reason = _NO_FACTORY.get(ttype or "")
        marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
        params.append(pytest.param(path, marks=marks, id=path.stem))
    return params


def _validator_key_params() -> list[Any]:
    """VALIDATORS keys as pytest params, xfailing the unreachable ones.

    Example::

        params = _validator_key_params()
    """
    params: list[Any] = []
    for key in sorted(VALIDATORS):
        reason = _UNREACHABLE_VALIDATORS.get(key)
        marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
        params.append(pytest.param(key, marks=marks, id=key))
    return params


def _validator_coverage_params() -> list[Any]:
    """Scenario files as params, xfailing those absent from VALIDATORS.

    Example::

        params = _validator_coverage_params()
    """
    params: list[Any] = []
    for path in sorted(_SCENARIO_DIR.glob("*.yaml")):
        marks = (
            [
                pytest.mark.xfail(
                    reason=(
                        f"task.type {_task_type(path)!r} has no VALIDATORS entry, so "
                        "validate_protocol reports success having executed zero checks"
                    ),
                    strict=True,
                )
            ]
            if path.stem in _MISSING_VALIDATOR_ENTRY
            else []
        )
        params.append(pytest.param(path, marks=marks, id=path.stem))
    return params


@pytest.mark.parametrize("scenario", _scenario_params())
def test_shipped_scenario_can_be_instantiated(scenario: Path) -> None:
    """Every shipped scenario YAML must resolve to an agent factory.

    A scenario that ships without a factory raises ``KeyError`` the moment
    anyone runs ``nest run`` on it. It is dead weight that looks supported.

    Example::

        test_shipped_scenario_can_be_instantiated(Path("scenarios/auction.yaml"))
    """
    ttype = _task_type(scenario)
    assert ttype is not None, f"{scenario.name} declares no task.type"
    assert _factory_exists(ttype), (
        f"{scenario.name} declares task.type={ttype!r} but no factory is registered "
        f"for it in nest_core.scenarios._try_load_builtin, so "
        f"`nest run {scenario.name}` raises KeyError"
    )


@pytest.mark.parametrize("task_type", _validator_key_params())
def test_registered_validators_are_reachable(task_type: str) -> None:
    """Every VALIDATORS entry must belong to a scenario that can actually run.

    Validators registered against a task type that no scenario declares, or
    that has no factory, can never execute against a real trace. They are
    unit-tested against hand-built event fixtures and nothing more, which
    reads as coverage but verifies nothing end to end.

    Example::

        test_registered_validators_are_reachable("marketplace")
    """
    declared = {_task_type(p) for p in sorted(_SCENARIO_DIR.glob("*.yaml"))}
    assert task_type in declared, (
        f"VALIDATORS registers {len(VALIDATORS[task_type])} validator(s) for "
        f"task.type={task_type!r}, but no scenario YAML declares that type, so "
        f"they cannot run against a real trace"
    )
    assert _factory_exists(task_type), (
        f"VALIDATORS registers validators for task.type={task_type!r} but no factory "
        f"exists, so the scenario cannot be instantiated"
    )


@pytest.mark.parametrize("scenario", _validator_coverage_params())
def test_runnable_scenario_has_validator_entry(scenario: Path) -> None:
    """A runnable scenario absent from VALIDATORS yields a vacuous verdict.

    ``validate_events`` does ``VALIDATORS.get(scenario_type, [])``. A scenario
    missing from that registry reaches ``metrics.validate_protocol`` with an
    empty validator list and no checks are executed.

    This does not claim such scenarios are unverified -- several are covered by
    bespoke validators under ``nest_plugins_reference/validators/`` that their
    own tests call directly. It claims they are unreachable through the
    registry-driven path.

    Example::

        test_runnable_scenario_has_validator_entry(Path("scenarios/auction.yaml"))
    """
    ttype = _task_type(scenario)
    assert ttype is not None
    if not _factory_exists(ttype):
        pytest.skip("covered by test_shipped_scenario_can_be_instantiated")
    assert VALIDATORS.get(ttype), (
        f"{scenario.name} (task.type={ttype!r}) runs and emits a trace, but "
        f"nest_core.VALIDATORS has no entry for it"
    )


def test_unknown_scenario_type_is_not_reported_as_passing(tmp_path: Path) -> None:
    """An unrecognised scenario type must not produce a passing verdict.

    ``all([])`` is ``True``, so before the accompanying fix a typo in
    ``task.type`` -- or a scenario never added to the registry -- made
    ``validate_protocol`` return ``all_passed=True`` having checked nothing.

    Example::

        test_unknown_scenario_type_is_not_reported_as_passing(Path("/tmp/x"))
    """
    from nest_core.metrics import validate_protocol

    trace = tmp_path / "trace.jsonl"
    trace.write_text(json.dumps({"agent": "a-0", "kind": "start", "ts": 0.0}) + "\n")

    result = validate_protocol(trace, "definitely_not_a_real_scenario_type")

    assert result["validators_run"] == 0
    assert result["unknown_scenario_type"] is True
    assert result["all_passed"] is False, (
        "validate_protocol reported success with zero validations for an unknown "
        "scenario type; absence of checks must not read as a pass"
    )
