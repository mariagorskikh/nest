# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable auth plugin.

Covers: happy path, scope enforcement, cascading revocation, audience
binding, expiry, HMAC chain integrity, Protocol conformance, and the
three adversarial validators.
"""

from __future__ import annotations

import pytest
from nest_core.layers.auth import Auth
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceConfusionError,
    DelegatableAuth,
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.validators.auth_validators import (
    check_audience_confusion_blocked,
    check_scope_escalation_blocked,
    check_stale_parent_blocked,
)


@pytest.fixture()
def auth() -> DelegatableAuth:
    return DelegatableAuth(secret=b"test-secret", clock=1000.0)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_auth_protocol(self, auth: DelegatableAuth) -> None:
        assert isinstance(auth, Auth)

    async def test_issue_returns_token(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("a1"), ["read"])
        assert isinstance(token, str)

    async def test_verify_returns_auth_context(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("a1"), ["read"])
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("a1")
        assert ctx.scopes == ["read"]

    async def test_revoke_then_verify_raises(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("a1"), ["read"])
        await auth.revoke(token)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(token)


# ---------------------------------------------------------------------------
# Root token basics
# ---------------------------------------------------------------------------


class TestRootToken:
    async def test_scopes_sorted_in_token(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("a1"), ["write", "read"])
        ctx = await auth.verify(token)
        assert ctx.scopes == ["read", "write"]

    async def test_issued_at_and_expires_at(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("a1"), ["read"], ttl=600.0)
        ctx = await auth.verify(token)
        assert ctx.issued_at == 1000.0
        assert ctx.expires_at == 1600.0

    async def test_expired_token_raises(self) -> None:
        auth = DelegatableAuth(secret=b"s", clock=1000.0)
        token = await auth.issue(AgentId("a1"), ["read"], ttl=10.0)
        auth.set_clock(1011.0)  # advance past expiry
        with pytest.raises(ValueError, match="expired"):
            await auth.verify(token)

    async def test_tampered_signature_raises(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("a1"), ["read"])
        raw = str(token)
        bad = Token(raw[:-4] + "0000")
        with pytest.raises(ValueError, match="invalid token signature"):
            await auth.verify(bad)

    async def test_malformed_token_raises(self, auth: DelegatableAuth) -> None:
        with pytest.raises(ValueError, match="malformed"):
            await auth.verify(Token("no-separator-here"))

    async def test_root_has_no_audience_so_caller_ignored(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("a1"), ["read"])
        # No audience on root → caller check is skipped
        ctx = await auth.verify(token, caller=AgentId("anyone"))
        assert ctx.subject == AgentId("a1")


# ---------------------------------------------------------------------------
# Delegation — happy path
# ---------------------------------------------------------------------------


class TestDelegation:
    async def test_delegate_creates_verifiable_child(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
        ctx = await auth.verify(child, caller=AgentId("worker"))
        assert ctx.scopes == ["read"]
        assert ctx.subject == AgentId("coord")

    async def test_delegate_preserves_parent_subject(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write", "exec"])
        mid = await auth.delegate(root, AgentId("mid"), ["read", "exec"], ttl=300.0)
        leaf = await auth.delegate(mid, AgentId("leaf"), ["read"], ttl=60.0)
        ctx = await auth.verify(leaf, caller=AgentId("leaf"))
        # subject traces back to the original issuer
        assert ctx.subject == AgentId("coord")

    async def test_delegate_caps_ttl_at_parent_remaining(self) -> None:
        auth = DelegatableAuth(secret=b"s", clock=1000.0)
        root = await auth.issue(AgentId("a"), ["read"], ttl=100.0)  # expires at 1100
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=9999.0)
        ctx = await auth.verify(child, caller=AgentId("b"))
        # child must expire no later than parent
        assert ctx.expires_at is not None
        assert ctx.expires_at <= 1100.0

    async def test_delegate_same_scopes_allowed(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=60.0)
        ctx = await auth.verify(child, caller=AgentId("b"))
        assert set(ctx.scopes) == {"read", "write"}

    async def test_three_level_chain(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["admin", "read", "write", "exec"])
        mid = await auth.delegate(root, AgentId("b"), ["read", "write", "exec"], ttl=3600.0)
        leaf = await auth.delegate(mid, AgentId("c"), ["read", "exec"], ttl=600.0)
        ctx = await auth.verify(leaf, caller=AgentId("c"))
        assert set(ctx.scopes) == {"read", "exec"}


# ---------------------------------------------------------------------------
# Scope escalation
# ---------------------------------------------------------------------------


class TestScopeEscalation:
    async def test_scope_escalation_raises(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=60.0)

    async def test_scope_not_in_parent_raises(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read", "write"])
        with pytest.raises(ScopeEscalationError, match="admin"):
            await auth.delegate(root, AgentId("b"), ["admin"], ttl=60.0)

    async def test_partial_overlap_with_new_scope_raises(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("b"), ["read", "exec"], ttl=60.0)

    async def test_empty_child_scopes_allowed(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read"])
        child = await auth.delegate(root, AgentId("b"), [], ttl=60.0)
        ctx = await auth.verify(child, caller=AgentId("b"))
        assert ctx.scopes == []


# ---------------------------------------------------------------------------
# Cascading revocation
# ---------------------------------------------------------------------------


class TestCascadingRevocation:
    async def test_revoke_root_blocks_child(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)

    async def test_revoke_root_blocks_grandchild(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read", "write", "exec"])
        mid = await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=3600.0)
        leaf = await auth.delegate(mid, AgentId("c"), ["read"], ttl=600.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf)

    async def test_revoke_middle_blocks_leaf_not_root(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read", "write", "exec"])
        mid = await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=3600.0)
        leaf = await auth.delegate(mid, AgentId("c"), ["read"], ttl=600.0)
        await auth.revoke(mid)
        # root still valid
        ctx = await auth.verify(root)
        assert ctx.subject == AgentId("a")
        # leaf blocked
        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf)

    async def test_revoke_sibling_does_not_affect_other_child(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("a"), ["read", "write"])
        child_x = await auth.delegate(root, AgentId("x"), ["read"], ttl=600.0)
        child_y = await auth.delegate(root, AgentId("y"), ["read"], ttl=600.0)
        await auth.revoke(child_x)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child_x)
        # sibling unaffected
        ctx = await auth.verify(child_y, caller=AgentId("y"))
        assert "read" in ctx.scopes


# ---------------------------------------------------------------------------
# Audience confusion
# ---------------------------------------------------------------------------


class TestAudienceConfusion:
    async def test_correct_caller_passes(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
        ctx = await auth.verify(child, caller=AgentId("worker"))
        assert ctx.scopes == ["read"]

    async def test_wrong_caller_raises(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
        with pytest.raises(AudienceConfusionError):
            await auth.verify(child, caller=AgentId("intruder"))

    async def test_no_caller_skips_audience_check(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
        # Callers that don't pass caller= still work (backward compat)
        ctx = await auth.verify(child)
        assert ctx.scopes == ["read"]


# ---------------------------------------------------------------------------
# Adversarial validators
# ---------------------------------------------------------------------------


class TestAdversarialValidators:
    async def test_scope_escalation_validator_passes_against_delegatable(
        self, auth: DelegatableAuth
    ) -> None:
        root = await auth.issue(AgentId("a"), ["read"])
        report = await check_scope_escalation_blocked(auth, root, ["admin"])
        assert report.passed, report.detail

    async def test_stale_parent_validator_passes_against_delegatable(
        self,
    ) -> None:
        fresh = DelegatableAuth(secret=b"test-secret", clock=1000.0)
        root = await fresh.issue(AgentId("a"), ["read", "write"])
        child = await fresh.delegate(root, AgentId("b"), ["read"], ttl=600.0)
        report = await check_stale_parent_blocked(fresh, root, child)
        assert report.passed, report.detail

    async def test_audience_confusion_validator_passes_against_delegatable(
        self, auth: DelegatableAuth
    ) -> None:
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
        report = await check_audience_confusion_blocked(auth, child, AgentId("intruder"))
        assert report.passed, report.detail

    async def test_scope_escalation_validator_fails_against_jwt(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        jwt = JwtAuth(secret=b"s", clock=1000.0)
        root = await jwt.issue(AgentId("a"), ["read"])
        report = await check_scope_escalation_blocked(jwt, root, ["admin"])
        assert not report.passed, "jwt should fail: no delegation enforcement"

    async def test_stale_parent_validator_fails_against_jwt(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        jwt = JwtAuth(secret=b"s", clock=1000.0)
        parent = await jwt.issue(AgentId("a"), ["read"])
        # jwt has no delegation, so issue a separate child independently
        child = await jwt.issue(AgentId("b"), ["read"])
        report = await check_stale_parent_blocked(jwt, parent, child)
        assert not report.passed, "jwt should fail: no cascading revocation"

    async def test_audience_confusion_validator_fails_against_jwt(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        jwt = JwtAuth(secret=b"s", clock=1000.0)
        child = await jwt.issue(AgentId("worker"), ["read"])
        report = await check_audience_confusion_blocked(jwt, child, AgentId("intruder"))
        assert not report.passed, "jwt should fail: no audience binding"


# ---------------------------------------------------------------------------
# Adversarial: delegation caller bypass
# ---------------------------------------------------------------------------


class TestDelegateCallerBypass:
    async def test_delegate_rejects_wrong_caller(self, auth: DelegatableAuth) -> None:
        """A thief who holds a stolen child token must not be able to mint a valid
        grandchild by calling delegate() as a different caller.

        Failure mode before fix: delegate() called verify() without caller=, so any
        presenter of a valid token could re-delegate it to themselves.
        """
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        alice_token = await auth.delegate(root, AgentId("alice"), ["read"], ttl=600.0)

        # Intruder presents alice's token and tries to delegate to themselves.
        with pytest.raises(AudienceConfusionError):
            await auth.delegate(
                alice_token, AgentId("intruder"), ["read"], ttl=30.0, caller=AgentId("intruder")
            )

    async def test_delegate_accepts_correct_caller(self, auth: DelegatableAuth) -> None:
        """The legitimate holder can still delegate onward after the fix."""
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        alice_token = await auth.delegate(root, AgentId("alice"), ["read", "write"], ttl=600.0)

        # Alice legitimately delegates to carol.
        carol_token = await auth.delegate(
            alice_token, AgentId("carol"), ["read"], ttl=60.0, caller=AgentId("alice")
        )
        ctx = await auth.verify(carol_token, caller=AgentId("carol"))
        assert ctx.scopes == ["read"]
