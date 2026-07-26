# SPDX-License-Identifier: Apache-2.0
"""Tests for depth-bounded delegation and prunable revocation state.

Three groups:

``TestInheritedBehaviour`` pins that subclassing did not change what the
merged plugins already guarantee -- attenuation, cascading revocation,
audience binding, and G-Set convergence must all still hold.

``TestDepthBound`` and ``TestPruning`` cover the two additions.

``TestGrowthAgainstReference`` demonstrates the failure modes on the
merged plugins directly, so the tests double as evidence that the
problems are real rather than hypothetical.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.auth.bounded_delegation import (
    DEFAULT_MAX_DEPTH,
    BoundedDelegationAuth,
    DelegationDepthExceededError,
)
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegationError,
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.auth.mesh_revocable import MeshRevocableAuth

SECRET = b"bounded-delegation-test-secret"


def make_auth(**kwargs: object) -> BoundedDelegationAuth:
    """Build a fixed-clock replica so every test is deterministic."""
    params: dict[str, object] = {"secret": SECRET, "clock": 0.0}
    params.update(kwargs)
    return BoundedDelegationAuth(**params)  # type: ignore[arg-type]


class TestConstruction:
    def test_default_max_depth(self) -> None:
        assert make_auth().max_depth == DEFAULT_MAX_DEPTH

    def test_explicit_max_depth(self) -> None:
        assert make_auth(max_depth=3).max_depth == 3

    @pytest.mark.parametrize("depth", [0, -1, -100])
    def test_rejects_nonpositive_max_depth(self, depth: int) -> None:
        with pytest.raises(ValueError, match="max_depth must be at least 1"):
            make_auth(max_depth=depth)

    def test_rejects_negative_prune_grace(self) -> None:
        with pytest.raises(ValueError, match="prune_grace must be non-negative"):
            make_auth(prune_grace=-1.0)


class TestInheritedBehaviour:
    """Subclassing must not weaken anything the merged plugins guarantee."""

    @pytest.mark.asyncio
    async def test_root_issue_and_verify(self) -> None:
        auth = make_auth()
        root = await auth.issue(AgentId("coordinator"), ["read", "write"])
        ctx = await auth.verify(root)
        assert ctx.subject == AgentId("coordinator")
        assert sorted(ctx.scopes) == ["read", "write"]

    @pytest.mark.asyncio
    async def test_scope_escalation_still_refused(self) -> None:
        auth = make_auth()
        root = await auth.issue(AgentId("coordinator"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("worker"), ["read", "admin"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_cascading_revocation_still_works(self) -> None:
        auth = make_auth()
        root = await auth.issue(AgentId("coordinator"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)

    @pytest.mark.asyncio
    async def test_audience_binding_still_enforced(self) -> None:
        auth = make_auth()
        root = await auth.issue(AgentId("coordinator"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
        with pytest.raises(AudienceMismatchError):
            await auth.verify_presented(child, AgentId("intruder"))

    @pytest.mark.asyncio
    async def test_expiry_is_clamped_to_parent(self) -> None:
        auth = make_auth()
        root = await auth.issue(AgentId("coordinator"), ["read"])
        root_ctx = await auth.verify(root)
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=999_999.0)
        child_ctx = await auth.verify(child)
        assert root_ctx.expires_at is not None
        assert child_ctx.expires_at is not None
        assert child_ctx.expires_at <= root_ctx.expires_at

    @pytest.mark.asyncio
    async def test_gossip_convergence_still_works(self) -> None:
        issuer = make_auth()
        gateway = make_auth()
        root = await issuer.issue(AgentId("coordinator"), ["read"])
        child = await issuer.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
        await gateway.verify(child)
        await issuer.revoke(root)
        await gateway.verify(child)  # not yet gossiped
        gateway.merge_revocations(issuer.export_revocations())
        with pytest.raises(RevokedAncestorError):
            await gateway.verify(child)


class TestDepthBound:
    @pytest.mark.asyncio
    async def test_delegation_within_bound_succeeds(self) -> None:
        auth = make_auth(max_depth=4)
        token = await auth.issue(AgentId("coordinator"), ["read"])
        for i in range(3):
            token = await auth.delegate(token, AgentId(f"w{i}"), ["read"], ttl=60.0)
        assert auth.chain_summary(token)["depth"] == 4

    @pytest.mark.asyncio
    async def test_delegation_past_bound_raises(self) -> None:
        auth = make_auth(max_depth=2)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
        with pytest.raises(DelegationDepthExceededError, match="exceeding max_depth 2"):
            await auth.delegate(child, AgentId("subworker"), ["read"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_depth_error_is_a_delegation_error(self) -> None:
        """Callers catching DelegationError generically must still work."""
        auth = make_auth(max_depth=1)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        with pytest.raises(DelegationError):
            await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_max_depth_one_permits_only_root(self) -> None:
        auth = make_auth(max_depth=1)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        await auth.verify(root)
        with pytest.raises(DelegationDepthExceededError):
            await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)

    @pytest.mark.asyncio
    async def test_stricter_verifier_rejects_laxer_mint(self) -> None:
        """A chain minted under a loose bound must fail a strict verifier.

        This is why the check is repeated at verify: delegate is not the
        only path by which a deep chain can reach a replica.
        """
        lax = make_auth(max_depth=8)
        strict = make_auth(max_depth=2)
        token = await lax.issue(AgentId("coordinator"), ["read"])
        for i in range(4):
            token = await lax.delegate(token, AgentId(f"w{i}"), ["read"], ttl=60.0)
        await lax.verify(token)
        with pytest.raises(DelegationDepthExceededError, match="chain depth 5"):
            await strict.verify(token)

    @pytest.mark.asyncio
    async def test_depth_refused_before_scope_check(self) -> None:
        """An over-deep request is refused without doing attenuation work."""
        auth = make_auth(max_depth=1)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        # Scopes are also invalid here; depth must be what raises.
        with pytest.raises(DelegationDepthExceededError):
            await auth.delegate(root, AgentId("worker"), ["admin"], ttl=60.0)


class TestPruning:
    @pytest.mark.asyncio
    async def test_expired_revocation_is_pruned(self) -> None:
        auth = make_auth(prune_grace=10.0)
        token = await auth.issue(AgentId("agent"), ["read"])
        await auth.revoke(token)
        assert auth.revocation_stats()["retained"] == 1
        auth.advance_to(100_000.0)
        assert auth.prune_revocations()
        assert auth.revocation_stats()["retained"] == 0

    @pytest.mark.asyncio
    async def test_live_revocation_is_retained(self) -> None:
        auth = make_auth(prune_grace=10.0)
        token = await auth.issue(AgentId("agent"), ["read"])
        await auth.revoke(token)
        auth.advance_to(1.0)
        assert auth.prune_revocations() == set()
        assert auth.revocation_stats()["retained"] == 1

    @pytest.mark.asyncio
    async def test_grace_period_delays_pruning(self) -> None:
        """An entry past expiry but inside the grace window is kept."""
        auth = make_auth(prune_grace=1_000_000.0)
        token = await auth.issue(AgentId("agent"), ["read"])
        await auth.revoke(token)
        auth.advance_to(100_000.0)  # past exp, still inside grace
        assert auth.prune_revocations() == set()

    @pytest.mark.asyncio
    async def test_unknown_expiry_is_never_pruned(self) -> None:
        """Entries merged from a peer carry no expiry and must be retained."""
        issuer = make_auth(prune_grace=0.0)
        peer = make_auth(prune_grace=0.0)
        token = await issuer.issue(AgentId("agent"), ["read"])
        await issuer.revoke(token)
        peer.merge_revocations(issuer.export_revocations())
        peer.advance_to(100_000.0)
        assert peer.revocation_stats()["unknown_expiry"] == 1
        assert peer.prune_revocations() == set()

    @pytest.mark.asyncio
    async def test_pruning_preserves_live_revocation_semantics(self) -> None:
        """Pruning must never resurrect a token that should stay dead."""
        auth = make_auth(prune_grace=10.0)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
        await auth.revoke(root)
        auth.advance_to(100_000.0)
        auth.prune_revocations()
        # The revocation entry is gone, but the chain is long expired, so
        # the token still fails -- on expiry rather than revocation.
        with pytest.raises(DelegationError):
            await auth.verify(child)

    @pytest.mark.asyncio
    async def test_export_prunes_before_serializing(self) -> None:
        auth = make_auth(prune_grace=10.0)
        token = await auth.issue(AgentId("agent"), ["read"])
        await auth.revoke(token)
        auth.advance_to(100_000.0)
        assert b'"revoked": []' in auth.export_revocations()

    @pytest.mark.asyncio
    async def test_stats_report_prunable_before_pruning(self) -> None:
        auth = make_auth(prune_grace=10.0)
        token = await auth.issue(AgentId("agent"), ["read"])
        await auth.revoke(token)
        auth.advance_to(100_000.0)
        assert auth.revocation_stats()["prunable"] == 1


class TestChainSummary:
    @pytest.mark.asyncio
    async def test_reports_depth_and_bound(self) -> None:
        auth = make_auth(max_depth=5)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        summary = auth.chain_summary(root)
        assert summary["depth"] == 1
        assert summary["max_depth"] == 5

    @pytest.mark.asyncio
    async def test_bytes_grow_with_depth(self) -> None:
        auth = make_auth(max_depth=6)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        deep = root
        for i in range(4):
            deep = await auth.delegate(deep, AgentId(f"w{i}"), ["read"], ttl=60.0)
        assert auth.chain_summary(deep)["bytes"] > auth.chain_summary(root)["bytes"]


class TestGrowthAgainstReference:
    """Demonstrate the two failure modes on the merged plugins.

    These are the reason the plugin exists. They assert the *unfixed*
    behaviour, so if a future change bounds either growth upstream, they
    fail and should be deleted along with the corresponding defence.
    """

    @pytest.mark.asyncio
    async def test_merged_plugin_allows_unbounded_depth(self) -> None:
        auth = MeshRevocableAuth(secret=SECRET, clock=0.0)
        token = await auth.issue(AgentId("coordinator"), ["read"])
        for i in range(64):
            token = await auth.delegate(token, AgentId(f"w{i}"), ["read"], ttl=60.0)
        ctx = await auth.verify(token)
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_merged_plugin_token_grows_with_depth(self) -> None:
        auth = MeshRevocableAuth(secret=SECRET, clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read"])
        token = root
        for i in range(64):
            token = await auth.delegate(token, AgentId(f"w{i}"), ["read"], ttl=60.0)
        assert len(str(token)) > 20 * len(str(root))

    @pytest.mark.asyncio
    async def test_merged_plugin_never_prunes(self) -> None:
        """Every revocation survives, however long ago its token expired.

        A replica started far in the future receives the same state a
        replica at t=0 exported, and keeps all of it -- the G-Set has no
        notion that an expired entry can no longer change an outcome.
        """
        issuer = MeshRevocableAuth(secret=SECRET, clock=0.0)
        for i in range(16):
            token = await issuer.issue(AgentId(f"a{i}"), ["read"])
            await issuer.revoke(token)
        state = issuer.export_revocations()

        future = MeshRevocableAuth(secret=SECRET, clock=10_000_000.0)
        future.merge_revocations(state)
        assert future.export_revocations() == state
