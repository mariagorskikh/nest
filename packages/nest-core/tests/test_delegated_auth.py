# SPDX-License-Identifier: Apache-2.0
"""Tests for delegated_auth adversarial validators and end-to-end scenario.

Core claim: the three validators FAIL against ``jwt`` (which has no delegation
model at all) and PASS against ``delegatable`` — verified with both synthetic
traces and a real simulator run.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_auth_audience_confusion_rejected,
    validate_auth_no_scope_escalation,
    validate_auth_stale_parent_rejected,
    validate_trace,
)

type Event = dict[str, Any]


# ---------------------------------------------------------------------------
# Synthetic trace helpers
# ---------------------------------------------------------------------------


def _ev(kind: str, msg: str, agent: str = "coord-0") -> Event:
    return {"ts": 1.0, "agent": agent, "kind": kind, "msg": msg}


def _send(msg: str, agent: str = "coord-0") -> Event:
    return _ev("send", msg, agent)


# ---------------------------------------------------------------------------
# Validator unit tests
# ---------------------------------------------------------------------------


def _audit(data: dict[str, Any]) -> Event:
    import json

    return _send(json.dumps(data))


class TestNoScopeEscalation:
    def test_pass_when_escalation_rejected(self) -> None:
        events = [
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "delegate",
                    "granted": False,
                    "parent_scopes": ["read"],
                    "child_scopes": ["read", "write"],
                }
            )
        ]
        assert validate_auth_no_scope_escalation(events)[0].passed is True

    def test_fail_when_escalation_accepted(self) -> None:
        events = [
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "delegate",
                    "granted": True,
                    "parent_scopes": ["read"],
                    "child_scopes": ["read", "write"],
                }
            )
        ]
        assert validate_auth_no_scope_escalation(events)[0].passed is False

    def test_fail_when_no_event_found(self) -> None:
        results = validate_auth_no_scope_escalation([])
        assert results[0].passed is False

    def test_multiple_rejections_all_pass(self) -> None:
        events = [
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "delegate",
                    "granted": False,
                    "parent_scopes": ["read"],
                    "child_scopes": ["read", "write"],
                }
            ),
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "delegate",
                    "granted": False,
                    "parent_scopes": ["read"],
                    "child_scopes": ["read", "write"],
                }
            ),
        ]
        assert validate_auth_no_scope_escalation(events)[0].passed is True

    def test_one_accepted_among_rejections_fails(self) -> None:
        events = [
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "delegate",
                    "granted": False,
                    "parent_scopes": ["read"],
                    "child_scopes": ["read", "write"],
                }
            ),
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "delegate",
                    "granted": True,
                    "parent_scopes": ["read"],
                    "child_scopes": ["read", "write"],
                }
            ),
        ]
        assert validate_auth_no_scope_escalation(events)[0].passed is False


class TestStaleParentRejected:
    def test_pass_when_post_revoke_rejected(self) -> None:
        events = [
            _audit({"type": "delegation_audit", "op": "revoke", "tid": "parent", "tick": 10}),
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "verify",
                    "chain_tids": ["parent", "child"],
                    "tick": 15,
                    "verified": False,
                }
            ),
        ]
        assert validate_auth_stale_parent_rejected(events)[0].passed is True

    def test_fail_when_post_revoke_accepted(self) -> None:
        events = [
            _audit({"type": "delegation_audit", "op": "revoke", "tid": "parent", "tick": 10}),
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "verify",
                    "chain_tids": ["parent", "child"],
                    "tick": 15,
                    "verified": True,
                }
            ),
        ]
        assert validate_auth_stale_parent_rejected(events)[0].passed is False

    def test_fail_when_no_event(self) -> None:
        results = validate_auth_stale_parent_rejected([])
        assert results[0].passed is False

    def test_all_leaves_rejected_passes(self) -> None:
        events = [_audit({"type": "delegation_audit", "op": "revoke", "tid": "parent", "tick": 10})]
        events.extend(
            [
                _audit(
                    {
                        "type": "delegation_audit",
                        "op": "verify",
                        "chain_tids": ["parent", f"leaf-{i}"],
                        "tick": 15,
                        "verified": False,
                    }
                )
                for i in range(12)
            ]
        )
        assert validate_auth_stale_parent_rejected(events)[0].passed is True


class TestAudienceConfusionRejected:
    def test_pass_when_confusion_rejected(self) -> None:
        events = [
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "verify",
                    "presenter": "attacker",
                    "audience": "victim",
                    "verified": False,
                }
            )
        ]
        assert validate_auth_audience_confusion_rejected(events)[0].passed is True

    def test_fail_when_confusion_accepted(self) -> None:
        events = [
            _audit(
                {
                    "type": "delegation_audit",
                    "op": "verify",
                    "presenter": "attacker",
                    "audience": "victim",
                    "verified": True,
                }
            )
        ]
        assert validate_auth_audience_confusion_rejected(events)[0].passed is False

    def test_fail_when_no_event(self) -> None:
        results = validate_auth_audience_confusion_rejected([])
        assert results[0].passed is False


# ---------------------------------------------------------------------------
# End-to-end: real simulator run
# ---------------------------------------------------------------------------


def _run(auth_plugin: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml")
    cfg.layers.auth = auth_plugin
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_delegatable_passes_all_validators(self, tmp_path: Path) -> None:
        out = tmp_path / "delegatable.jsonl"
        _run("delegatable", out)
        results = validate_trace(out, "delegated_auth")
        assert results, "no validators ran"
        failures = [r for r in results if not r.passed]
        assert not failures, [f"{r.name}: {r.detail}" for r in failures]

    def test_jwt_baseline_fails_all_validators(self, tmp_path: Path) -> None:
        """The jwt plugin has no delegate(); all three adversarial validators must FAIL.

        The scenario degrades gracefully: _delegate() falls back to plain re-issuance
        (a new root token with whatever scopes were requested).  The resulting trace
        carries no real delegation chain so:
          - scope escalation is never rejected  → validator fails
          - stale-parent revocation has no effect on freshly-issued tokens → validator fails
          - audience binding is not enforced    → validator fails
        """
        out = tmp_path / "jwt_baseline.jsonl"
        _run("jwt", out)
        results = validate_trace(out, "delegated_auth")
        assert results, "no validators ran against jwt baseline"
        # Every single validator must report a failure — that's the whole point
        passing = [r for r in results if r.passed]
        assert not passing, (
            "Expected all validators to FAIL on jwt trace, but these passed: "
            + str([r.name for r in passing])
        )

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a = tmp_path / f"{seed}a.jsonl"
            b = tmp_path / f"{seed}b.jsonl"
            _run("delegatable", a, seed=seed)
            _run("delegatable", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "delegated_auth"))
