# SPDX-License-Identifier: Apache-2.0
"""Tests for the DelegatableAuth plugin — Problem 04.

Covers:
- Root token issuance and basic verification
- Delegation (happy path, depth-3 tree)
- Scope escalation is rejected (ScopeEscalationError)
- Stale-parent: expired parent invalidates child (ExpiredAncestorError)
- Stale-parent: revoked parent invalidates child (RevokedAncestorError)
- Audience confusion is rejected (AudienceConfusionError)
- Cascading revocation propagates transitively
- TTL cap: child cannot outlive parent
- Backward-compatibility: plain verify() still works (no presenter)
- Determinism: same inputs → same token IDs
"""

from __future__ import annotations

import pytest

from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceConfusionError,
    DelegatableAuth,
    ExpiredAncestorError,
    RevokedAncestorError,
    ScopeEscalationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_auth(t: float = 0.0) -> DelegatableAuth:
    """Return a fresh DelegatableAuth with deterministic clock starting at t."""
    return DelegatableAuth(secret=b"test-secret", clock=t)


COORD = AgentId("coordinator")
INTERM = AgentId("intermediary-1")
LEAF = AgentId("leaf-1")
EVE = AgentId("eve")


# ---------------------------------------------------------------------------
# Basic issuance and verification
# ---------------------------------------------------------------------------


class TestRootIssueAndVerify:
    """Root token issuance and baseline verification."""

    @pytest.mark.asyncio
    async def test_issue_returns_token(self) -> None:
        auth = make_auth()
        token = await auth.issue(COORD, ["read", "write"])
        assert isinstance(token, str)
        assert "|" in token

    @pytest.mark.asyncio
    async def test_verify_returns_correct_context(self) -> None:
        auth = make_auth()
        token = await auth.issue(COORD, ["read", "write"])
        ctx = await auth.verify(token)
        assert ctx.subject == COORD
        assert set(ctx.scopes) == {"read", "write"}

    @pytest.mark.asyncio
    async def test_verify_scopes_are_sorted(self) -> None:
        auth = make_auth()
        token = await auth.issue(COORD, ["write", "read", "exec"])
        ctx = await auth.verify(token)
        assert ctx.scopes == sorted(ctx.scopes)

    @pytest.mark.asyncio
    async def test_tampered_token_rejected(self) -> None:
        auth = make_auth()
        token = await auth.issue(COORD, ["read"])
        raw = str(token)
        tampered = Token(raw.replace('"read"', '"admin"'))
        with pytest.raises(ValueError, match="Invalid token signature"):
            await auth.verify(tampered)

    @pytest.mark.asyncio
    async def test_revoke_invalidates_token(self) -> None:
        auth = make_auth()
        token = await auth.issue(COORD, ["read"])
        await auth.revoke(token)
        with pytest.raises((ValueError, RevokedAncestorError)):
            await auth.verify(token)

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self) -> None:
        auth = make_auth(t=0.0)
        token = await auth.issue(COORD, ["read"])
        # Advance clock past DEFAULT_TTL
        auth.tick(DelegatableAuth.DEFAULT_TTL + 1.0)
        with pytest.raises(ValueError, match="expired"):
            await auth.verify(token)


# ---------------------------------------------------------------------------
# Delegation — happy path
# ---------------------------------------------------------------------------


class TestDelegationHappyPath:
    """Successful delegation at various depths."""

    @pytest.mark.asyncio
    async def test_single_level_delegation(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write", "exec"])
        child = await auth.delegate(root, INTERM, ["read", "exec"], ttl=300.0)
        ctx = await auth.verify(child, presenter=INTERM)
        assert set(ctx.scopes) == {"read", "exec"}
        assert ctx.subject == INTERM

    @pytest.mark.asyncio
    async def test_depth_3_delegation_tree(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write", "exec"])
        interm = await auth.delegate(root, INTERM, ["read", "exec"], ttl=600.0)
        leaf = await auth.delegate(interm, LEAF, ["read"], ttl=120.0)
        ctx = await auth.verify(leaf, presenter=LEAF)
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_same_scopes_as_parent_allowed(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write"])
        child = await auth.delegate(root, INTERM, ["read", "write"], ttl=60.0)
        ctx = await auth.verify(child, presenter=INTERM)
        assert set(ctx.scopes) == {"read", "write"}

    @pytest.mark.asyncio
    async def test_verify_without_presenter_still_works(self) -> None:
        """Backward-compatible: omitting presenter does not enforce audience."""
        auth = make_auth()
        root = await auth.issue(COORD, ["read"])
        child = await auth.delegate(root, INTERM, ["read"], ttl=60.0)
        ctx = await auth.verify(child)
        assert "read" in ctx.scopes

    @pytest.mark.asyncio
    async def test_ttl_capped_at_parent_remaining(self) -> None:
        auth = make_auth(t=0.0)
        root = await auth.issue(COORD, ["read"])
        # Advance to use up most of root's TTL
        auth.tick(DelegatableAuth.DEFAULT_TTL - 100.0)
        child = await auth.delegate(root, INTERM, ["read"], ttl=9999.0)
        rec = auth.get_record(child)
        assert rec is not None
        # Child must expire at or before root
        root_rec_exp = DelegatableAuth.DEFAULT_TTL  # root expires at 3600
        assert rec.expires_at <= root_rec_exp + 1.0  # +1 for float tolerance


# ---------------------------------------------------------------------------
# Attack 1 — Scope escalation
# ---------------------------------------------------------------------------


class TestScopeEscalation:
    """Scope escalation must always raise ScopeEscalationError."""

    @pytest.mark.asyncio
    async def test_escalation_single_extra_scope(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read"])
        with pytest.raises(ScopeEscalationError, match="write"):
            await auth.delegate(root, INTERM, ["read", "write"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_escalation_completely_disjoint(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, INTERM, ["admin"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_escalation_at_depth_2(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write"])
        interm = await auth.delegate(root, INTERM, ["read"], ttl=600.0)
        with pytest.raises(ScopeEscalationError, match="write"):
            # Leaf tries to claim write which intermediary does not hold
            await auth.delegate(interm, LEAF, ["read", "write"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_no_escalation_with_subset(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write", "exec"])
        # Valid — strict subset
        child = await auth.delegate(root, INTERM, ["exec"], ttl=60.0)
        ctx = await auth.verify(child, presenter=INTERM)
        assert ctx.scopes == ["exec"]


# ---------------------------------------------------------------------------
# Attack 2 — Stale parent (revoked)
# ---------------------------------------------------------------------------


class TestStaleParentRevoked:
    """Revoking a parent must cascade to all descendants."""

    @pytest.mark.asyncio
    async def test_revoke_root_invalidates_child(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write"])
        child = await auth.delegate(root, INTERM, ["read"], ttl=300.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=INTERM)

    @pytest.mark.asyncio
    async def test_revoke_intermediary_invalidates_leaf(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write", "exec"])
        interm = await auth.delegate(root, INTERM, ["read", "exec"], ttl=600.0)
        leaf = await auth.delegate(interm, LEAF, ["read"], ttl=120.0)
        await auth.revoke(interm)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf, presenter=LEAF)

    @pytest.mark.asyncio
    async def test_revoke_root_cascades_depth_3(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write", "exec"])
        interm = await auth.delegate(root, INTERM, ["read", "exec"], ttl=600.0)
        leaf = await auth.delegate(interm, LEAF, ["read"], ttl=120.0)
        await auth.revoke(root)
        # Both interm and leaf should fail
        with pytest.raises(RevokedAncestorError):
            await auth.verify(interm, presenter=INTERM)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf, presenter=LEAF)

    @pytest.mark.asyncio
    async def test_sibling_unaffected_by_revocation(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write"])
        child_a = await auth.delegate(root, INTERM, ["read"], ttl=300.0)
        child_b = await auth.delegate(root, AgentId("other-worker"), ["write"], ttl=300.0)
        await auth.revoke(child_a)
        # child_b shares the same root but is not revoked
        ctx = await auth.verify(child_b, presenter=AgentId("other-worker"))
        assert "write" in ctx.scopes

    @pytest.mark.asyncio
    async def test_delegating_from_revoked_parent_fails(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write"])
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.delegate(root, INTERM, ["read"], ttl=60.0)


# ---------------------------------------------------------------------------
# Attack 2 — Stale parent (expired)
# ---------------------------------------------------------------------------


class TestStaleParentExpired:
    """An expired parent must invalidate its children."""

    @pytest.mark.asyncio
    async def test_expired_parent_invalidates_child(self) -> None:
        auth = make_auth(t=0.0)
        root = await auth.issue(COORD, ["read", "write"])
        child = await auth.delegate(root, INTERM, ["read"], ttl=DelegatableAuth.DEFAULT_TTL)
        # Advance past root TTL
        auth.tick(DelegatableAuth.DEFAULT_TTL + 1.0)
        with pytest.raises((ValueError, ExpiredAncestorError)):
            await auth.verify(child, presenter=INTERM)

    @pytest.mark.asyncio
    async def test_cannot_delegate_from_expired_parent(self) -> None:
        auth = make_auth(t=0.0)
        root = await auth.issue(COORD, ["read"])
        auth.tick(DelegatableAuth.DEFAULT_TTL + 1.0)
        with pytest.raises(ValueError, match="expired"):
            await auth.delegate(root, INTERM, ["read"], ttl=60.0)


# ---------------------------------------------------------------------------
# Attack 3 — Audience confusion
# ---------------------------------------------------------------------------


class TestAudienceConfusion:
    """Token presented by wrong agent must raise AudienceConfusionError."""

    @pytest.mark.asyncio
    async def test_wrong_presenter_rejected(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read", "write"])
        child = await auth.delegate(root, INTERM, ["read"], ttl=300.0)
        with pytest.raises(AudienceConfusionError):
            await auth.verify(child, presenter=EVE)

    @pytest.mark.asyncio
    async def test_correct_presenter_accepted(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read"])
        child = await auth.delegate(root, INTERM, ["read"], ttl=60.0)
        ctx = await auth.verify(child, presenter=INTERM)
        assert ctx.subject == INTERM

    @pytest.mark.asyncio
    async def test_root_presenter_same_as_subject(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read"])
        ctx = await auth.verify(root, presenter=COORD)
        assert ctx.subject == COORD

    @pytest.mark.asyncio
    async def test_root_presenter_wrong_rejected(self) -> None:
        auth = make_auth()
        root = await auth.issue(COORD, ["read"])
        with pytest.raises(AudienceConfusionError):
            await auth.verify(root, presenter=EVE)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Same inputs + same clock must produce byte-identical token IDs."""

    @pytest.mark.asyncio
    async def test_same_seed_same_first_tid(self) -> None:
        auth1 = DelegatableAuth(secret=b"deterministic", clock=42.0)
        auth2 = DelegatableAuth(secret=b"deterministic", clock=42.0)
        t1 = await auth1.issue(COORD, ["read"])
        t2 = await auth2.issue(COORD, ["read"])
        # token IDs (16-char hex embedded in JSON) should match
        import json

        c1 = json.loads(str(t1).rsplit("|", 1)[0])
        c2 = json.loads(str(t2).rsplit("|", 1)[0])
        assert c1["tid"] == c2["tid"]


# ---------------------------------------------------------------------------
# Fails-against-jwt baseline (validator semantics)
# ---------------------------------------------------------------------------


class TestFailsAgainstJwt:
    """The vanilla JwtAuth must fail the delegation tests (no delegate API)."""

    def test_jwt_auth_has_no_delegate_method(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        auth = JwtAuth(secret=b"x")
        assert not hasattr(auth, "delegate"), (
            "JwtAuth should not have a delegate method — that's our novelty"
        )

    def test_jwt_auth_no_cascading_revoke(self) -> None:
        """JwtAuth._revoked is a flat set with no parent tracking."""
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        auth = JwtAuth(secret=b"x")
        assert hasattr(auth, "_revoked")
        assert isinstance(auth._revoked, set)
        # No parent_id tracking in JwtAuth
        assert not hasattr(auth, "_records")
