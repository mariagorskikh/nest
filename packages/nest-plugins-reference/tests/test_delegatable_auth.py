# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable auth plugin and its three adversarial validators.

Three layers:

1. **Plugin unit tests**, drive ``DelegatableAuth`` directly: root issuance,
   subset-enforced delegation, TTL clamping, transitive (cascading) revocation,
   sibling isolation, audience binding, and tamper resistance.
2. **Adversarial-validator discrimination** (the core deliverable), the same
   three checks — scope escalation, stale parent, audience confusion — **FAIL**
   against the reference ``jwt`` plugin and **PASS** against ``DelegatableAuth``.
   Without the delegatable plugin these assertions cannot hold.
3. **End-to-end scenario**, boot the real ``delegated_auth`` scenario through
   ``ScenarioRunner`` and confirm the trace validators pass on the produced
   cascading-revocation trace.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Token
from nest_core.validators import (
    validate_delegated_auth_audience_binding,
    validate_delegated_auth_cascading_revocation,
    validate_delegated_auth_scope_narrowing,
    validate_trace,
)
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    ExpiredTokenError,
    InvalidSignatureError,
    MalformedTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.validators import (
    check_audience_confusion_rejected,
    check_scope_escalation_rejected,
    check_stale_parent_rejected,
)

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "delegated_auth.yaml"


@pytest.fixture
def auth() -> DelegatableAuth:
    """A delegatable auth instance with a frozen clock for determinism."""
    return DelegatableAuth(secret=b"test-secret", clock=0.0)


class TestDelegatableAuthPlugin:
    """Direct unit tests of the plugin surface."""

    async def test_issue_and_verify_root(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        ctx = await auth.verify(root)
        assert ctx.subject == AgentId("coord")
        assert sorted(ctx.scopes) == ["read", "write"]
        assert ctx.expires_at == 3600.0

    async def test_delegate_narrows_scopes(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write", "pay"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600)
        ctx = await auth.verify(child, presenter=AgentId("worker"))
        assert ctx.scopes == ["read"]
        assert ctx.subject == AgentId("worker")

    async def test_delegate_rejects_scope_escalation(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("worker"), ["write"], ttl=600)

    async def test_delegate_clamps_ttl_to_parent(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read"])  # exp = 3600
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=999_999)
        ctx = await auth.verify(child, presenter=AgentId("worker"))
        assert ctx.expires_at == 3600.0

    async def test_cascading_revocation(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600)
        grandchild = await auth.delegate(child, AgentId("sub"), ["read"], ttl=300)
        # All verify before revocation.
        await auth.verify(child)
        await auth.verify(grandchild)
        # Revoking the root sinks the whole subtree.
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(grandchild)

    async def test_revocation_does_not_affect_siblings(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read"])
        child_a = await auth.delegate(root, AgentId("a"), ["read"], ttl=600)
        child_b = await auth.delegate(root, AgentId("b"), ["read"], ttl=600)
        await auth.revoke(child_a)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child_a)
        # Sibling is untouched.
        ctx = await auth.verify(child_b, presenter=AgentId("b"))
        assert ctx.subject == AgentId("b")

    async def test_audience_binding(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read"])
        child = await auth.delegate(root, AgentId("bob"), ["read"], ttl=600)
        # Correct audience is accepted.
        await auth.verify(child, presenter=AgentId("bob"))
        # An impostor is rejected.
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=AgentId("mallory"))
        # Omitting the presenter preserves the base contract (no audience check).
        await auth.verify(child)

    async def test_delegate_from_revoked_parent_fails(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.delegate(child, AgentId("sub"), ["read"], ttl=300)

    async def test_tampered_scope_fails_signature(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600)
        tampered = Token(str(child).replace('"read"', '"read","write"'))
        with pytest.raises(InvalidSignatureError):
            await auth.verify(tampered)

    async def test_expired_token_rejected(self) -> None:
        issuer = DelegatableAuth(secret=b"s", clock=0.0)
        root = await issuer.issue(AgentId("coord"), ["read"])  # exp = 3600
        # A verifier whose clock is past the root's 1-hour lifetime rejects it.
        later = DelegatableAuth(secret=b"s", clock=4000.0)
        with pytest.raises(ExpiredTokenError):
            await later.verify(root)

    async def test_malformed_token_rejected(self, auth: DelegatableAuth) -> None:
        with pytest.raises(MalformedTokenError):
            await auth.verify(Token("not-a-token"))


class TestAdversarialValidators:
    """The three attacks FAIL against jwt and PASS against delegatable."""

    async def test_scope_escalation_discriminates(self) -> None:
        jwt_report = await check_scope_escalation_rejected(
            JwtAuth(clock=0.0), root_scopes=["read"], escalated_scope="write"
        )
        assert not jwt_report.passed, jwt_report.detail
        good_report = await check_scope_escalation_rejected(
            DelegatableAuth(clock=0.0), root_scopes=["read"], escalated_scope="write"
        )
        assert good_report.passed, good_report.detail

    async def test_stale_parent_discriminates(self) -> None:
        jwt_report = await check_stale_parent_rejected(JwtAuth(clock=0.0), scopes=["read"])
        assert not jwt_report.passed, jwt_report.detail
        good_report = await check_stale_parent_rejected(DelegatableAuth(clock=0.0), scopes=["read"])
        assert good_report.passed, good_report.detail

    async def test_audience_confusion_discriminates(self) -> None:
        jwt_report = await check_audience_confusion_rejected(JwtAuth(clock=0.0), scopes=["read"])
        assert not jwt_report.passed, jwt_report.detail
        good_report = await check_audience_confusion_rejected(
            DelegatableAuth(clock=0.0), scopes=["read"]
        )
        assert good_report.passed, good_report.detail


class TestDelegatedAuthScenario:
    """The shipped scenario produces a trace all delegated_auth validators pass."""

    async def test_scenario_trace_validates(self) -> None:
        config = ScenarioConfig.from_yaml(SCENARIO_PATH)
        with tempfile.TemporaryDirectory() as tmp:
            config.output.trace = str(Path(tmp) / "delegated_auth.jsonl")
            runner = ScenarioRunner(config)
            trace_path = await runner.run()
            results = validate_trace(Path(trace_path), "delegated_auth")

        assert results, "no validators ran for delegated_auth"
        for result in results:
            assert result.passed, f"{result.name}: {result.detail}"
        names = {r.name for r in results}
        assert names == {
            "delegated_auth_scope_narrowing",
            "delegated_auth_cascading_revocation",
            "delegated_auth_audience_binding",
        }

    async def test_scenario_is_deterministic(self) -> None:
        traces: list[str] = []
        for _ in range(2):
            config = ScenarioConfig.from_yaml(SCENARIO_PATH)
            with tempfile.TemporaryDirectory() as tmp:
                config.output.trace = str(Path(tmp) / "run.jsonl")
                trace_path = await ScenarioRunner(config).run()
                traces.append(Path(trace_path).read_text())
        assert traces[0] == traces[1]


def _send(msg: str) -> dict[str, object]:
    """A minimal send event carrying a colon-delimited dauth frame."""
    return {"kind": "send", "msg": msg, "agent": "coordinator", "to": "peer"}


class TestDelegatedAuthTraceValidators:
    """Direct-call tests exercising each FAIL branch of the trace validators."""

    def test_scope_narrowing_flags_escalation(self) -> None:
        events = [
            _send("dauth:issue:coord:read"),
            _send("dauth:delegate:coord:child:read|write"),  # widened beyond parent
        ]
        result = validate_delegated_auth_scope_narrowing(events)[0]
        assert not result.passed
        assert "widened" in result.detail

    def test_scope_narrowing_passes_clean_tree(self) -> None:
        events = [
            _send("dauth:issue:coord:read|write"),
            _send("dauth:delegate:coord:child:read"),
        ]
        result = validate_delegated_auth_scope_narrowing(events)[0]
        assert result.passed

    def test_cascading_revocation_flags_surviving_descendant(self) -> None:
        events = [
            _send("dauth:issue:coord:read"),
            _send("dauth:delegate:coord:child:read"),
            _send("dauth:verify:child:child:ok:pre"),
            _send("dauth:revoke:coord"),
            # child is in the revoked subtree but still verified -> stale parent
            _send("dauth:verify:child:child:ok:post"),
        ]
        result = validate_delegated_auth_cascading_revocation(events)[0]
        assert not result.passed
        assert "still verified" in result.detail

    def test_cascading_revocation_passes_when_subtree_dies(self) -> None:
        events = [
            _send("dauth:issue:coord:read"),
            _send("dauth:delegate:coord:child:read"),
            _send("dauth:verify:child:child:ok:pre"),
            _send("dauth:revoke:coord"),
            _send("dauth:verify:child:child:fail:post"),
        ]
        result = validate_delegated_auth_cascading_revocation(events)[0]
        assert result.passed

    def test_audience_binding_flags_accepted_impostor(self) -> None:
        events = [
            _send("dauth:verify:mallory:bob:ok:pre"),  # impostor accepted
        ]
        result = validate_delegated_auth_audience_binding(events)[0]
        assert not result.passed
        assert "impostor" in result.detail

    def test_audience_binding_passes_when_impostor_rejected(self) -> None:
        events = [
            _send("dauth:verify:mallory:bob:fail:pre"),
        ]
        result = validate_delegated_auth_audience_binding(events)[0]
        assert result.passed
