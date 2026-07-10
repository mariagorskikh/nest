# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegated_auth scenario and its adversarial validators.

Proves end-to-end that the four validators PASS against ``auth: delegatable``
and FAIL against ``auth: jwt`` (without crashing), that the run is
deterministic, and — with hand-built synthetic traces — that each validator
fails for the specific violation it is meant to catch.

Example::

    pytest packages/nest-core/tests/test_delegated_auth_scenario.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_convergent_auth_attacks_blocked,
    validate_convergent_auth_cascade,
    validate_convergent_auth_convergence,
    validate_convergent_auth_tree_built,
    validate_trace,
)

type Event = dict[str, Any]

_YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "convergent_auth.yaml"


def _s(msg: str) -> Event:
    """A minimal ``send`` trace event carrying *msg* (what the validators read)."""
    return {"ts": 0.0, "agent": "coordinator", "kind": "send", "to": "x", "msg": msg}


def _config(trace: Path, auth: str) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(_YAML)
    config.layers.auth = auth
    config.output.trace = str(trace)
    return config


# ---------------------------------------------------------------------------
# End-to-end scenario
# ---------------------------------------------------------------------------


class TestScenarioEndToEnd:
    async def test_passes_against_delegatable(self, tmp_path: Path) -> None:
        trace = tmp_path / "deleg.jsonl"
        result = await ScenarioRunner(_config(trace, "delegatable_crdt")).run()
        assert result.exists()
        results = validate_trace(result, "convergent_auth")
        assert results, "no validators ran"
        assert all(r.passed for r in results), [str(r) for r in results]

    async def test_fails_against_jwt_without_crashing(self, tmp_path: Path) -> None:
        trace = tmp_path / "jwt.jsonl"
        # Must NOT raise — jwt has no delegate(); agents capability-gate it.
        result = await ScenarioRunner(_config(trace, "jwt")).run()
        assert result.exists()
        results = validate_trace(result, "convergent_auth")
        assert not any(r.passed for r in results), [str(r) for r in results]

    async def test_deterministic(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for i in range(2):
            trace = tmp_path / f"det-{i}.jsonl"
            await ScenarioRunner(_config(trace, "delegatable_crdt")).run()
            traces.append(trace.read_text())
        assert traces[0] == traces[1]
        assert len(traces[0]) > 0


# ---------------------------------------------------------------------------
# tree_built
# ---------------------------------------------------------------------------


class TestTreeBuilt:
    def _full_tree(self) -> list[Event]:
        events = [_s(f"delegated:coordinator:inter-{i}:s{i}:ok") for i in range(3)]
        events += [_s(f"delegated:inter-{i // 4}:leaf-{i}:l{i}:ok") for i in range(12)]
        return events

    def test_full_tree_passes(self) -> None:
        assert validate_convergent_auth_tree_built(self._full_tree())[0].passed

    def test_unsupported_fails(self) -> None:
        events = [_s(f"delegated:coordinator:inter-{i}:na:unsupported") for i in range(3)]
        assert not validate_convergent_auth_tree_built(events)[0].passed

    def test_partial_tree_fails(self) -> None:
        events = [_s(f"delegated:coordinator:inter-{i}:s{i}:ok") for i in range(3)]
        # Only 3 leaf delegations instead of 12.
        events += [_s(f"delegated:inter-0:leaf-{i}:l{i}:ok") for i in range(3)]
        assert not validate_convergent_auth_tree_built(events)[0].passed


# ---------------------------------------------------------------------------
# cascade
# ---------------------------------------------------------------------------


class TestCascade:
    def _tree(self) -> list[Event]:
        events = [_s(f"delegated:coordinator:inter-{i}:s{i}:ok") for i in range(3)]
        events += [_s(f"delegated:inter-{i // 4}:leaf-{i}:l{i}:ok") for i in range(12)]
        return events

    def test_cascade_passes(self) -> None:
        events = [*self._tree(), _s("revoked:inter-0:s0")]
        # inter-0 owns leaf-0..3; they must fail after revocation, siblings ok.
        events += [_s(f"verify:leaf-{i}:l{i}:revoked") for i in range(4)]
        events += [_s(f"verify:leaf-{i}:l{i}:ok") for i in range(4, 12)]
        assert validate_convergent_auth_cascade(events)[0].passed

    def test_no_revocation_fails(self) -> None:
        assert not validate_convergent_auth_cascade(self._tree())[0].passed

    def test_leaked_descendant_fails(self) -> None:
        events = [*self._tree(), _s("revoked:inter-0:s0")]
        events += [_s("verify:leaf-0:l0:ok")]  # a revoked-subtree leaf still verifies
        events += [_s(f"verify:leaf-{i}:l{i}:revoked") for i in range(1, 4)]
        assert not validate_convergent_auth_cascade(events)[0].passed

    def test_over_revocation_fails(self) -> None:
        events = [*self._tree(), _s("revoked:inter-0:s0")]
        events += [_s(f"verify:leaf-{i}:l{i}:revoked") for i in range(4)]
        events += [_s("verify:leaf-5:l5:revoked")]  # sibling wrongly severed
        assert not validate_convergent_auth_cascade(events)[0].passed


# ---------------------------------------------------------------------------
# attacks_blocked
# ---------------------------------------------------------------------------


class TestAttacksBlocked:
    def _all_blocked(self) -> list[Event]:
        return [
            _s("attack:escalation:s0:blocked"),
            _s("attack:stale_parent:s1:blocked"),
            _s("attack:audience:s2:blocked"),
        ]

    def test_all_blocked_passes(self) -> None:
        assert validate_convergent_auth_attacks_blocked(self._all_blocked())[0].passed

    def test_leaked_attack_fails(self) -> None:
        events = [*self._all_blocked()[:2], _s("attack:audience:s2:LEAKED")]
        assert not validate_convergent_auth_attacks_blocked(events)[0].passed

    def test_missing_attack_kind_fails(self) -> None:
        events = self._all_blocked()[:2]  # no audience attack exercised
        assert not validate_convergent_auth_attacks_blocked(events)[0].passed


# ---------------------------------------------------------------------------
# convergence
# ---------------------------------------------------------------------------


class TestConvergence:
    def _converged(self) -> list[Event]:
        return [
            _s("revoked:inter-0:s0"),
            _s("converge:inter-0:s0:severed"),
            _s("converge:inter-1:s1:valid"),
            _s("converge:inter-2:s2:valid"),
        ]

    def test_convergence_passes(self) -> None:
        assert validate_convergent_auth_convergence(self._converged())[0].passed

    def test_revoked_still_valid_fails(self) -> None:
        events = [
            _s("revoked:inter-0:s0"),
            _s("converge:inter-0:s0:valid"),  # revocation did not converge
            _s("converge:inter-1:s1:valid"),
        ]
        assert not validate_convergent_auth_convergence(events)[0].passed

    def test_over_propagation_fails(self) -> None:
        events = [
            _s("revoked:inter-0:s0"),
            _s("converge:inter-0:s0:severed"),
            _s("converge:inter-1:s1:severed"),  # unrelated intermediary severed
        ]
        assert not validate_convergent_auth_convergence(events)[0].passed

    def test_no_probes_fails(self) -> None:
        assert not validate_convergent_auth_convergence([_s("revoked:inter-0:s0")])[0].passed


@pytest.mark.parametrize(
    "validator",
    [
        validate_convergent_auth_tree_built,
        validate_convergent_auth_cascade,
        validate_convergent_auth_attacks_blocked,
        validate_convergent_auth_convergence,
    ],
)
def test_validators_fail_on_empty_trace(validator: Any) -> None:
    results = validator([])
    assert results and not results[0].passed
