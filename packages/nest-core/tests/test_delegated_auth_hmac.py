# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegated_auth adversarial validators and scenario.

The core claim under test: the validators FAIL against the default ``jwt``
auth layer (which has no delegation concept at all) and PASS against
``delegatable`` -- driven both from synthetic traces and from a real
simulator run.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_auth_audience_confusion_blocked,
    validate_auth_cascading_revocation,
    validate_auth_delegation_occurred,
    validate_auth_scope_escalation_blocked,
    validate_trace,
)

type Event = dict[str, Any]


def _send(agent: str, msg: str, to: str = "auditor-0", ts: float = 0.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


# ---------------------------------------------------------------------------
# Validator unit tests (synthetic traces)
# ---------------------------------------------------------------------------


class TestDelegationOccurred:
    def test_pass_with_full_tree(self) -> None:
        events = [_send("coordinator-0", "issued:root:coordinator-0:read,write,admin")]
        events += [
            _send("coordinator-0", f"delegated:mid-{i}:root:intermediary-{i}:read,write")
            for i in range(3)
        ]
        events += [
            _send(f"intermediary-{i}", f"delegated:leaf-{i}-{j}:mid-{i}:leaf-{i}-{j}:read")
            for i in range(3)
            for j in range(4)
        ]
        results = validate_auth_delegation_occurred(events)
        assert results[0].passed is True

    def test_fail_when_no_root_issued(self) -> None:
        results = validate_auth_delegation_occurred([])
        assert results[0].passed is False

    def test_fail_when_too_few_delegations(self) -> None:
        events = [
            _send("coordinator-0", "issued:root:coordinator-0:read,write,admin"),
            _send("coordinator-0", "delegated:mid-0:root:intermediary-0:read,write"),
        ]
        results = validate_auth_delegation_occurred(events)
        assert results[0].passed is False


class TestScopeEscalationBlocked:
    def test_pass_when_escalation_blocked(self) -> None:
        events = [_send("coordinator-0", "delegate_blocked:scope_escalation:root")]
        results = validate_auth_scope_escalation_blocked(events)
        assert results[0].passed is True

    def test_fail_when_no_attempt_observed(self) -> None:
        results = validate_auth_scope_escalation_blocked([])
        assert results[0].passed is False

    def test_unrelated_attack_kind_does_not_count(self) -> None:
        events = [_send("coordinator-0", "delegate_blocked:excessive_ttl:root")]
        results = validate_auth_scope_escalation_blocked(events)
        assert results[0].passed is False


class TestCascadingRevocation:
    """Tree: root -> mid-0 -> leaf-0 (revoked subtree), root -> mid-1 (sibling)."""

    _TREE = [
        _send("coordinator-0", "delegated:mid-0:root:intermediary-0:read,write"),
        _send("coordinator-0", "delegated:mid-1:root:intermediary-1:read,write"),
        _send("intermediary-0", "delegated:leaf-0:mid-0:leaf-0-0:read"),
    ]

    def test_pass_when_cascade_and_sibling_isolation_both_hold(self) -> None:
        events = [
            *self._TREE,
            # Phase 1 (before revocation): everyone verifies fine.
            _send("auditor-0", "verify_result:mid-0:normal:ok"),
            _send("auditor-0", "verify_result:leaf-0:normal:ok"),
            _send("coordinator-0", "revoked:mid-0"),
            # Phase 2 (after revocation): revoked subtree blocked...
            _send("auditor-0", "verify_result:mid-0:normal:revoked_ancestor"),
            _send("auditor-0", "verify_result:leaf-0:normal:revoked_ancestor"),
            # ...but the untouched sibling subtree is unaffected.
            _send("auditor-0", "verify_result:mid-1:normal:ok"),
        ]
        results = validate_auth_cascading_revocation(events)
        assert results[0].passed is True, results[0].detail

    def test_fail_when_no_revocation_observed(self) -> None:
        events = [*self._TREE, _send("auditor-0", "verify_result:leaf-0:normal:ok")]
        results = validate_auth_cascading_revocation(events)
        assert results[0].passed is False
        assert "no revocation" in results[0].detail

    def test_fail_when_descendant_still_verifies_ok_after_revocation(self) -> None:
        events = [
            *self._TREE,
            _send("coordinator-0", "revoked:mid-0"),
            _send("auditor-0", "verify_result:leaf-0:normal:ok"),  # should have been blocked
        ]
        results = validate_auth_cascading_revocation(events)
        assert results[0].passed is False
        assert "leaf-0" in results[0].detail

    def test_fail_when_mechanism_never_actually_fires(self) -> None:
        """Revocation recorded, but no descendant verify was ever observed after it."""
        events = [*self._TREE, _send("coordinator-0", "revoked:mid-0")]
        results = validate_auth_cascading_revocation(events)
        assert results[0].passed is False
        assert "ever rejected" in results[0].detail

    def test_fail_when_sibling_isolation_never_exercised(self) -> None:
        events = [
            *self._TREE,
            _send("coordinator-0", "revoked:mid-0"),
            _send("auditor-0", "verify_result:leaf-0:normal:revoked_ancestor"),
        ]
        results = validate_auth_cascading_revocation(events)
        assert results[0].passed is False
        assert "sibling" in results[0].detail

    def test_ok_before_revocation_is_not_a_violation(self) -> None:
        """A legitimate pre-revocation 'ok' must not be mistaken for a cascade failure."""
        events = [
            *self._TREE,
            _send("auditor-0", "verify_result:leaf-0:normal:ok"),
            _send("coordinator-0", "revoked:mid-0"),
            _send("auditor-0", "verify_result:leaf-0:normal:revoked_ancestor"),
            _send("auditor-0", "verify_result:mid-1:normal:ok"),
        ]
        results = validate_auth_cascading_revocation(events)
        assert results[0].passed is True, results[0].detail


class TestAudienceConfusionBlocked:
    def test_pass_when_attack_rejected(self) -> None:
        events = [_send("auditor-0", "verify_result:leaf-0:audience_attack:audience_mismatch")]
        results = validate_auth_audience_confusion_blocked(events)
        assert results[0].passed is True

    def test_fail_when_no_attempt_observed(self) -> None:
        results = validate_auth_audience_confusion_blocked([])
        assert results[0].passed is False

    def test_fail_when_attack_incorrectly_accepted(self) -> None:
        events = [_send("auditor-0", "verify_result:leaf-0:audience_attack:ok")]
        results = validate_auth_audience_confusion_blocked(events)
        assert results[0].passed is False


# ---------------------------------------------------------------------------
# End-to-end: real simulator run
# ---------------------------------------------------------------------------


def _run(auth: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/delegated_auth_hmac.yaml")
    cfg.layers.auth = auth
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_delegatable_passes(self, tmp_path: Path) -> None:
        out = tmp_path / "delegatable.jsonl"
        _run("delegatable_hmac", out)
        results = validate_trace(out, "delegated_auth_hmac")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_jwt_fails_all_checks(self, tmp_path: Path) -> None:
        out = tmp_path / "jwt.jsonl"
        _run("jwt", out)
        results = {r.name: r.passed for r in validate_trace(out, "delegated_auth_hmac")}
        assert results["auth_delegation_occurred"] is False
        assert results["auth_scope_escalation_blocked"] is False
        assert results["auth_cascading_revocation"] is False
        assert results["auth_audience_confusion_blocked"] is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("delegatable_hmac", a, seed=seed)
            _run("delegatable_hmac", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "delegated_auth_hmac"))
