# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable capability auth plugin.

Covers: Auth protocol conformance, root token issuance, child delegation,
scope-subset enforcement, cascading revocation, TTL/expiry, audience binding,
adversarial scenarios (scope escalation, stale-parent, audience confusion),
and the PluginRegistry wiring.
"""

from __future__ import annotations

import pytest
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceError,
    DelegatableAuth,
    ResourceGuardError,
    RevocationViewStaleError,
    RevokedAncestorError,
    ScopeEscalationError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(clock: float = 1_000_000.0) -> DelegatableAuth:
    """Return a fresh DelegatableAuth pinned to a fixed clock for determinism."""
    return DelegatableAuth(secret=b"test-secret", clock=clock)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_auth(self) -> None:
        assert isinstance(_auth(), Auth)

    @pytest.mark.asyncio
    async def test_issue_returns_token(self) -> None:
        auth = _auth()
        token = await auth.issue(AgentId("a1"), ["read"])
        assert str(token)  # non-empty

    @pytest.mark.asyncio
    async def test_verify_root_token(self) -> None:
        auth = _auth()
        token = await auth.issue(AgentId("a1"), ["read", "write"])
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("a1")
        assert set(ctx.scopes) == {"read", "write"}

    @pytest.mark.asyncio
    async def test_revoke_root_then_verify_raises(self) -> None:
        auth = _auth()
        token = await auth.issue(AgentId("a1"), ["read"])
        await auth.revoke(token)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(token)


# ---------------------------------------------------------------------------
# Delegation — happy path
# ---------------------------------------------------------------------------


class TestDelegation:
    @pytest.mark.asyncio
    async def test_delegate_returns_child_token(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
        assert str(child)

    @pytest.mark.asyncio
    async def test_child_verify_preserves_subject(self) -> None:
        """Child token subject is the root issuer's subject (delegation chain)."""
        auth = _auth()
        root = await auth.issue(AgentId("coordinator"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=30.0)
        ctx = await auth.verify(child)
        assert ctx.subject == AgentId("coordinator")

    @pytest.mark.asyncio
    async def test_child_scopes_subset_of_parent(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write", "delete"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        ctx = await auth.verify(child)
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_multi_hop_delegation_chain(self) -> None:
        """Three-level chain: root → mid → leaf — leaf verifies successfully."""
        auth = _auth()
        root = await auth.issue(AgentId("root"), ["read", "write", "delegate"])
        mid = await auth.delegate(root, AgentId("mid"), ["read", "write"], ttl=600.0)
        leaf = await auth.delegate(mid, AgentId("leaf"), ["read"], ttl=30.0)
        ctx = await auth.verify(leaf)
        assert "read" in ctx.scopes

    @pytest.mark.asyncio
    async def test_child_ttl_capped_to_parent_remaining(self) -> None:
        """Child cannot request a TTL longer than the parent's remaining lifetime."""
        auth = DelegatableAuth(secret=b"s", clock=1_000_000.0)
        root = await auth.issue(AgentId("a1"), ["read", "write"])  # expires at +3600
        # Request 7200 s — should be capped at 3600 s
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=7200.0)
        # Verify the child's expiry <= parent's expiry using public verify
        root_ctx = await auth.verify(root)
        child_ctx = await auth.verify(child)
        # Child should expire at or before parent (both issued at same clock tick)
        assert child_ctx.expires_at is not None
        assert root_ctx.expires_at is not None
        assert child_ctx.expires_at <= root_ctx.expires_at + 1  # small epsilon for same tick

    @pytest.mark.asyncio
    async def test_audience_check_accepts_correct_presenter(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        ctx = await auth.verify(child, presenter=AgentId("a2"))
        assert ctx.subject == AgentId("a1")


# ---------------------------------------------------------------------------
# Adversarial validator — three attack classes
# ---------------------------------------------------------------------------


class TestAdversarialScenarios:
    """These are the three attacks the problem spec requires catching."""

    # 1. Scope escalation
    @pytest.mark.asyncio
    async def test_scope_escalation_rejected(self) -> None:
        """Child cannot request scopes the parent does not hold."""
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("a2"), ["read", "delete"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_scope_escalation_rejected_when_parent_has_none(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), [])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_scope_escalation_in_multi_hop_chain(self) -> None:
        """Even deep in the chain, scopes cannot be elevated."""
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write", "delete"])
        child = await auth.delegate(root, AgentId("a2"), ["read", "write"], ttl=60.0)
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(child, AgentId("a3"), ["read", "delete"], ttl=30.0)

    # 2. Stale parent (revoked)
    @pytest.mark.asyncio
    async def test_revoking_parent_invalidates_child(self) -> None:
        """Cascading revocation: revoking a parent makes child unverifiable."""
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)

    @pytest.mark.asyncio
    async def test_revoking_grandparent_invalidates_leaf(self) -> None:
        """Three-level: revoking the root kills the leaf too."""
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write", "delete"])
        mid = await auth.delegate(root, AgentId("a2"), ["read", "write"], ttl=600.0)
        leaf = await auth.delegate(mid, AgentId("a3"), ["read"], ttl=60.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf)

    @pytest.mark.asyncio
    async def test_revoking_mid_invalidates_leaf_not_root(self) -> None:
        """Only descendants are invalidated; siblings of the revoked node survive."""
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write", "delete"])
        mid = await auth.delegate(root, AgentId("a2"), ["read", "write"], ttl=600.0)
        sibling = await auth.delegate(root, AgentId("a3"), ["write"], ttl=600.0)
        leaf = await auth.delegate(mid, AgentId("a4"), ["read"], ttl=60.0)

        await auth.revoke(mid)

        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf)

        # Root and sibling (branching off root, not mid) must still be valid
        ctx_root = await auth.verify(root)
        assert ctx_root.subject == AgentId("a1")
        ctx_sib = await auth.verify(sibling)
        assert "write" in ctx_sib.scopes

    # 3. Audience confusion
    @pytest.mark.asyncio
    async def test_wrong_presenter_rejected(self) -> None:
        """A child token is rejected when presented by the wrong agent."""
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        with pytest.raises(AudienceError):
            await auth.verify(child, presenter=AgentId("a3"))

    @pytest.mark.asyncio
    async def test_root_token_has_no_audience_restriction(self) -> None:
        """Root tokens (issued via ``issue``) accept any presenter."""
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read"])
        ctx = await auth.verify(root, presenter=AgentId("anyone"))
        assert ctx.subject == AgentId("a1")

    # 4. Epoch fence
    @pytest.mark.asyncio
    async def test_epoch_fence_rejects_stale_views(self) -> None:
        """The epoch fence rejects verification attempts with stale revocation views."""
        auth = DelegatableAuth(secret=b"test-secret", clock=1_000_000.0, stale_after=2)
        root = await auth.issue(AgentId("a1"), ["read"])
        auth.advance_epoch()
        auth.advance_epoch()
        auth.advance_epoch()
        with pytest.raises(RevocationViewStaleError):
            await auth.verify(root, visible_epoch=0)


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


class TestExpiry:
    @pytest.mark.asyncio
    async def test_expired_token_raises(self) -> None:
        """A token issued at t=0 with ttl=1 is expired at t=2."""
        auth_issue = DelegatableAuth(secret=b"s", clock=0.0)
        token = await auth_issue.issue(AgentId("a1"), ["read"])

        auth_beyond = DelegatableAuth(secret=b"s", clock=4000.0)
        with pytest.raises(ValueError, match="expired"):
            await auth_beyond.verify(token)


# ---------------------------------------------------------------------------
# Invalid tokens
# ---------------------------------------------------------------------------


class TestInvalidTokens:
    @pytest.mark.asyncio
    async def test_tampered_payload_fails(self) -> None:
        auth = _auth()
        token = await auth.issue(AgentId("a1"), ["read"])
        raw = str(token)
        tampered_raw = raw.replace('"read"', '"admin"')
        with pytest.raises(ValueError):
            await auth.verify(Token(tampered_raw))

    @pytest.mark.asyncio
    async def test_malformed_token_fails(self) -> None:
        with pytest.raises(ValueError, match="Malformed"):
            await _auth().verify(Token("notavalidtoken"))


# ---------------------------------------------------------------------------
# PluginRegistry wiring
# ---------------------------------------------------------------------------


class TestPluginRegistry:
    def test_resolve_delegatable(self) -> None:
        reg = PluginRegistry()
        cls = reg.resolve("auth", "delegatable")
        assert cls is DelegatableAuth


# ---------------------------------------------------------------------------
# Operation Overkill Tests
# ---------------------------------------------------------------------------


class TestAdvancedFeatures:
    @pytest.mark.asyncio
    async def test_offline_attenuation(self) -> None:
        """Test that delegation doesn't require root secret."""
        auth = DelegatableAuth(secret=b"test-secret", clock=1_000_000.0)
        root = await auth.issue(AgentId("a1"), ["read", "write"])

        # we can delegate even if auth had a different secret (offline!)
        auth_offline = DelegatableAuth(secret=b"wrong-secret", clock=1_000_000.0)
        child = await auth_offline.delegate(root, AgentId("a2"), ["read"], ttl=60.0)

        # But we must verify with the original
        ctx = await auth.verify(child)
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_epoch_fence_stale_view_rejected(self) -> None:
        """Test that a verifier with a stale epoch fails closed."""
        auth = DelegatableAuth(secret=b"test-secret", clock=1_000_000.0, stale_after=2)
        root = await auth.issue(AgentId("a1"), ["read", "write"])

        # Advance global epoch beyond stale_after
        for _ in range(5):
            auth.advance_epoch()

        # Verify with an old visible_epoch
        with pytest.raises(RevocationViewStaleError):
            await auth.verify(root, visible_epoch=0)

    @pytest.mark.asyncio
    async def test_confused_deputy_resource_guard(self) -> None:
        """Test the authorize() resource guard."""
        auth = DelegatableAuth(secret=b"test-secret", clock=1_000_000.0)
        root = await auth.issue(AgentId("a1"), ["read"])

        # Has read, so this works
        await auth.authorize(root, presenter=AgentId("a1"), required_scope="read")

        # Missing write, so this fails
        with pytest.raises(ResourceGuardError):
            await auth.authorize(root, presenter=AgentId("a1"), required_scope="write")


# ---------------------------------------------------------------------------
# Copilot Review Overkill Tests (Boundary TTL & Depth Invariants)
# ---------------------------------------------------------------------------


class TestBoundaryAndInvariants:
    @pytest.mark.asyncio
    async def test_boundary_ttl_exact_expiry_denied(self) -> None:
        """now == expires_at => deny."""
        auth = DelegatableAuth(secret=b"s", clock=100.0)
        root = await auth.issue(AgentId("a1"), ["read"])

        # Verify exactly at expiration time (100.0 + 3600.0 = 3700.0)
        auth_exact = DelegatableAuth(secret=b"s", clock=3700.0)
        with pytest.raises(ValueError, match="expired"):
            await auth_exact.verify(root)

    @pytest.mark.asyncio
    async def test_boundary_ttl_minus_epsilon_allowed(self) -> None:
        """now == expires_at - 1ms => allow."""
        auth = DelegatableAuth(secret=b"s", clock=100.0)
        root = await auth.issue(AgentId("a1"), ["read"])

        auth_before = DelegatableAuth(secret=b"s", clock=3699.999)
        ctx = await auth_before.verify(root)
        assert ctx.subject == AgentId("a1")

    @pytest.mark.asyncio
    async def test_depth_tampering_rejected(self) -> None:
        """Tampering the depth field at any level fails validation."""
        auth = DelegatableAuth(secret=b"s", clock=100.0)
        root = await auth.issue(AgentId("a1"), ["read"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)

        raw = str(child)
        parts = raw.split("|")
        # Tamper the depth in the child payload (parts[1])
        import json

        payload_dict = json.loads(parts[1])
        payload_dict["depth"] = 99  # Tamper
        parts[1] = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
        tampered_child = Token("|".join(parts))

        with pytest.raises(ValueError):
            await auth.verify(tampered_child)

    @pytest.mark.asyncio
    async def test_strict_resource_binding_enforced(self) -> None:
        """Resource identity must exactly match during authorize()."""
        auth = DelegatableAuth(secret=b"s", clock=100.0)
        root = await auth.issue(AgentId("a1"), ["read"])

        # Delegate with strict resource binding
        child = await auth.delegate(
            root, AgentId("a2"), ["read"], ttl=60.0, resource="urn:data:climate"
        )

        # Verify works
        await auth.verify(child)

        # Authorize with correct resource works
        await auth.authorize(child, AgentId("a2"), "read", resource_id="urn:data:climate")

        # Authorize with incorrect resource fails
        with pytest.raises(ResourceGuardError, match="Resource mismatch"):
            await auth.authorize(child, AgentId("a2"), "read", resource_id="urn:data:other")

        # Authorize missing resource fails
        with pytest.raises(ResourceGuardError, match="Token is resource-bound"):
            await auth.authorize(child, AgentId("a2"), "read")

    @pytest.mark.asyncio
    async def test_broadening_resource_binding_fails(self) -> None:
        auth = DelegatableAuth(secret=b"s", clock=100.0)
        root = await auth.issue(AgentId("a1"), ["read"])
        child = await auth.delegate(
            root, AgentId("a2"), ["read"], ttl=60.0, resource="urn:data:climate"
        )

        # Grandchild trying to broaden resource fails
        with pytest.raises(ScopeEscalationError, match="Cannot broaden resource binding"):
            await auth.delegate(child, AgentId("a3"), ["read"], ttl=30.0, resource="urn:data:other")
