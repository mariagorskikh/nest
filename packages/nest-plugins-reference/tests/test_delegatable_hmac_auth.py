# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable auth plugin: delegation and cascading revocation.

Persona note (auth engineer): the invariants under test are the three
attacks the problem brief calls out by name -- scope escalation, a stale
(expired/revoked) parent still verifying, and audience confusion -- plus
the headline feature: revoking a token invalidates everything delegated
from it, transitively, with a single ``revoke`` call.
"""

from __future__ import annotations

import pytest
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable_hmac import (
    AudienceMismatchError,
    DelegatableAuth,
    ExcessiveTtlError,
    RevokedAncestorError,
    ScopeEscalationError,
)

_ROOT = AgentId("coordinator")
_WORKER = AgentId("worker")
_SUBWORKER = AgentId("subworker")
_MALLORY = AgentId("mallory")


def _auth(clock: float = 1000.0) -> DelegatableAuth:
    return DelegatableAuth(secret=b"test-secret", clock=clock)


class TestIssueAndVerify:
    @pytest.mark.asyncio
    async def test_issue_verify_round_trip(self) -> None:
        auth = _auth()
        token = await auth.issue(_ROOT, ["read", "write"])
        ctx = await auth.verify(token)
        assert ctx.subject == _ROOT
        assert ctx.scopes == ["read", "write"]

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self) -> None:
        auth = DelegatableAuth(secret=b"secret1", clock=1000.0)
        token = await auth.issue(_ROOT, ["read"])

        other = DelegatableAuth(secret=b"secret2", clock=1000.0)
        with pytest.raises(ValueError, match="signature"):
            await other.verify(token)


class TestDelegation:
    @pytest.mark.asyncio
    async def test_delegated_token_narrows_scopes(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read", "write", "admin"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60)
        ctx = await auth.verify(child, presented_by=_WORKER)
        assert ctx.subject == _WORKER
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_delegation_chains_transitively(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read", "write"])
        mid = await auth.delegate(root, _WORKER, ["read"], ttl=100)
        leaf = await auth.delegate(mid, _SUBWORKER, ["read"], ttl=50)
        ctx = await auth.verify(leaf, presented_by=_SUBWORKER)
        assert ctx.subject == _SUBWORKER
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_scope_escalation_is_rejected(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, _WORKER, ["read", "admin"], ttl=60)

    @pytest.mark.asyncio
    async def test_ttl_exceeding_parent_is_rejected(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])  # expires at clock + 3600
        with pytest.raises(ExcessiveTtlError):
            await auth.delegate(root, _WORKER, ["read"], ttl=999_999)


class TestCascadingRevocation:
    """The headline feature: one revoke() call kills a whole subtree."""

    @pytest.mark.asyncio
    async def test_revoking_root_invalidates_direct_child(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60)

        await auth.revoke(root)

        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presented_by=_WORKER)

    @pytest.mark.asyncio
    async def test_revoking_root_invalidates_grandchild_without_touching_it(self) -> None:
        """Revoking the root must cascade two levels down with a single call."""
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])
        mid = await auth.delegate(root, _WORKER, ["read"], ttl=100)
        leaf = await auth.delegate(mid, _SUBWORKER, ["read"], ttl=50)

        await auth.revoke(root)  # only the root is ever revoked directly
        assert len(auth._revoked) == 1  # pyright: ignore[reportPrivateUsage]

        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf, presented_by=_SUBWORKER)

    @pytest.mark.asyncio
    async def test_revoking_child_does_not_invalidate_sibling(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])
        worker_token = await auth.delegate(root, _WORKER, ["read"], ttl=60)
        subworker_token = await auth.delegate(root, _SUBWORKER, ["read"], ttl=60)

        await auth.revoke(worker_token)

        with pytest.raises(RevokedAncestorError):
            await auth.verify(worker_token, presented_by=_WORKER)
        # The sibling never had its own or the root's id revoked.
        ctx = await auth.verify(subworker_token, presented_by=_SUBWORKER)
        assert ctx.subject == _SUBWORKER

    @pytest.mark.asyncio
    async def test_expired_parent_child_still_within_ttl_is_rejected(self) -> None:
        """A parent that has since expired must invalidate its child too."""
        auth = DelegatableAuth(secret=b"test-secret", clock=1000.0)
        root = await auth.issue(_ROOT, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60)

        # A verifier running later (child.exp <= root.exp by construction, so
        # this also passes root's natural expiry) must reject the child.
        later = DelegatableAuth(secret=b"test-secret", clock=1000.0 + 61)
        with pytest.raises(ValueError, match="expired"):
            await later.verify(child, presented_by=_WORKER)


class TestAudienceConfusion:
    @pytest.mark.asyncio
    async def test_wrong_presenter_is_rejected(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60)

        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presented_by=_MALLORY)

    @pytest.mark.asyncio
    async def test_correct_presenter_is_accepted(self) -> None:
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60)
        ctx = await auth.verify(child, presented_by=_WORKER)
        assert ctx.subject == _WORKER

    @pytest.mark.asyncio
    async def test_presented_by_is_optional(self) -> None:
        """Omitting presented_by (e.g. the base Auth protocol call site) still works."""
        auth = _auth()
        root = await auth.issue(_ROOT, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60)
        ctx = await auth.verify(child)
        assert ctx.subject == _WORKER


class TestApiFit:
    def test_satisfies_auth_protocol(self) -> None:
        assert isinstance(_auth(), Auth)

    def test_resolvable_from_registry(self) -> None:
        cls = PluginRegistry().resolve("auth", "delegatable_hmac")
        assert cls is DelegatableAuth

    def test_delegation_errors_are_value_errors(self) -> None:
        """Existing ``except ValueError`` guards keep catching delegation failures."""
        assert issubclass(ScopeEscalationError, ValueError)
        assert issubclass(ExcessiveTtlError, ValueError)
        assert issubclass(RevokedAncestorError, ValueError)
        assert issubclass(AudienceMismatchError, ValueError)
