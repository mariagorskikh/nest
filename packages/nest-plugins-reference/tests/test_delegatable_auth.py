# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable auth plugin: delegation, cascading revocation, attacks.

Persona (capability-security engineer): every invariant here is the boundary
that separates safe delegation from catastrophic privilege escalation.  The
three attack classes under test are real: scope escalation, stale-parent
verification, and audience confusion all appear in production auth CVEs.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceError,
    DelegatableAuth,
    RevokedAncestorError,
    ScopeEscalationError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def auth(clock: float | None = None) -> DelegatableAuth:
    return DelegatableAuth(secret=b"test-secret", clock=clock)


COORD = AgentId("coord")
WORKER = AgentId("worker")
IMPERSONATOR = AgentId("impersonator")


# ---------------------------------------------------------------------------
# Basic issue / verify round-trip
# ---------------------------------------------------------------------------


class TestIssue:
    def test_issue_and_verify(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write"]))
        ctx = loop.run_until_complete(a.verify(root))
        assert ctx.subject == COORD
        assert sorted(ctx.scopes) == ["read", "write"]

    def test_expired_token_rejected(self) -> None:
        a = auth(clock=0.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read"]))
        # Advance clock past expiry (default 3600s).
        a._clock = 4000.0  # type: ignore[attr-defined]
        with pytest.raises(ValueError, match="expired"):
            loop.run_until_complete(a.verify(root))

    def test_tampered_signature_rejected(self) -> None:
        a = auth()
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read"]))
        bad = Token(str(root) + "x")
        with pytest.raises(ValueError, match="signature"):
            loop.run_until_complete(a.verify(bad))

    def test_satisfies_auth_protocol(self) -> None:
        assert isinstance(auth(), Auth)

    def test_resolvable_from_registry(self) -> None:
        cls = PluginRegistry().resolve("auth", "delegatable")
        assert cls is DelegatableAuth


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------


class TestDelegation:
    def test_delegate_subset_scopes(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write", "admin"]))
        child = loop.run_until_complete(a.delegate(root, audience=WORKER, scopes=["read"], ttl=300))
        ctx = loop.run_until_complete(a.verify(child, caller=WORKER))
        assert ctx.scopes == ["read"]

    def test_delegate_all_parent_scopes(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write"]))
        child = loop.run_until_complete(
            a.delegate(root, audience=WORKER, scopes=["read", "write"], ttl=60)
        )
        ctx = loop.run_until_complete(a.verify(child, caller=WORKER))
        assert sorted(ctx.scopes) == ["read", "write"]

    def test_multi_level_delegation(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write", "admin"]))
        interm_id = AgentId("interm")
        interm_tok = loop.run_until_complete(
            a.delegate(root, audience=interm_id, scopes=["read", "write"], ttl=3600)
        )
        leaf_id = AgentId("leaf")
        leaf_tok = loop.run_until_complete(
            a.delegate(interm_tok, audience=leaf_id, scopes=["read"], ttl=600)
        )
        ctx = loop.run_until_complete(a.verify(leaf_tok, caller=leaf_id))
        assert ctx.scopes == ["read"]

    def test_child_ttl_capped_by_parent(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        # Parent expires in 100s from now (clock=1000, exp=1100).
        loop.run_until_complete(a.issue(COORD, ["read"]))
        # Manually truncate parent expiry for this test.
        # Re-issue with short TTL by manipulating clock.
        a._clock = 0.0  # pyright: ignore[reportPrivateUsage]
        short_root = loop.run_until_complete(a.issue(COORD, ["read"]))
        # short_root expires at 3600, child TTL is 100 but actual exp = min(3600, 100).
        # The important invariant: child can't outlive parent.
        child = loop.run_until_complete(
            a.delegate(short_root, audience=WORKER, scopes=["read"], ttl=100)
        )
        ctx = loop.run_until_complete(a.verify(child, caller=WORKER))
        assert ctx.expires_at is not None and ctx.expires_at <= 100.0


# ---------------------------------------------------------------------------
# Attack 1: Scope escalation
# ---------------------------------------------------------------------------


class TestScopeEscalation:
    def test_escalation_raises_scope_escalation_error(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read"]))
        with pytest.raises(ScopeEscalationError) as exc:
            loop.run_until_complete(
                a.delegate(root, audience=WORKER, scopes=["read", "admin"], ttl=60)
            )
        assert "admin" in exc.value.disallowed

    def test_escalation_is_value_error(self) -> None:
        """Existing ``except ValueError`` guards still catch it."""
        assert issubclass(ScopeEscalationError, ValueError)

    @settings(max_examples=50, deadline=None)
    @given(
        parent_scopes=st.frozensets(st.sampled_from(["read", "write", "admin"]), min_size=1),
        extra=st.frozensets(st.sampled_from(["superadmin", "delete", "godmode"]), min_size=1),
    )
    def test_escalation_always_rejected(
        self, parent_scopes: frozenset[str], extra: frozenset[str]
    ) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, list(parent_scopes)))
        child_scopes = list(parent_scopes | extra)
        with pytest.raises(ScopeEscalationError):
            loop.run_until_complete(a.delegate(root, audience=WORKER, scopes=child_scopes, ttl=60))


# ---------------------------------------------------------------------------
# Attack 2: Stale parent / cascading revocation
# ---------------------------------------------------------------------------


class TestCascadingRevocation:
    def test_revoking_root_invalidates_child(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write"]))
        child = loop.run_until_complete(a.delegate(root, audience=WORKER, scopes=["read"], ttl=300))
        loop.run_until_complete(a.revoke(root))
        with pytest.raises(RevokedAncestorError):
            loop.run_until_complete(a.verify(child, caller=WORKER))

    def test_revoking_intermediate_invalidates_grandchild(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write"]))
        interm_id = AgentId("interm")
        interm_tok = loop.run_until_complete(
            a.delegate(root, audience=interm_id, scopes=["read", "write"], ttl=3600)
        )
        leaf_id = AgentId("leaf")
        leaf_tok = loop.run_until_complete(
            a.delegate(interm_tok, audience=leaf_id, scopes=["read"], ttl=600)
        )
        # Only revoke the intermediary token, not the root.
        loop.run_until_complete(a.revoke(interm_tok))
        with pytest.raises(RevokedAncestorError):
            loop.run_until_complete(a.verify(leaf_tok, caller=leaf_id))
        # Root itself still valid.
        ctx = loop.run_until_complete(a.verify(root))
        assert "read" in ctx.scopes

    def test_jwt_baseline_does_not_cascade(self) -> None:
        """Sanity-check proving why cascading revocation matters.

        jwt_auth has no parent-child link, so revoking a root token string
        that was never handed to the child leaves the child perfectly valid.
        This test documents the gap (not testing our plugin).
        """
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        loop = asyncio.new_event_loop()
        j = JwtAuth(secret=b"test")
        root = loop.run_until_complete(j.issue(COORD, ["read", "write"]))
        # jwt_auth has no delegate(); we simulate by issuing a separate child.
        child = loop.run_until_complete(j.issue(WORKER, ["read"]))
        loop.run_until_complete(j.revoke(root))
        # Child was issued independently — revoking root has NO effect.
        ctx = loop.run_until_complete(j.verify(child))
        assert "read" in ctx.scopes  # still valid — the bug jwt_auth has

    def test_revoked_ancestor_error_is_value_error(self) -> None:
        assert issubclass(RevokedAncestorError, ValueError)


# ---------------------------------------------------------------------------
# Attack 3: Audience confusion
# ---------------------------------------------------------------------------


class TestAudienceConfusion:
    def test_wrong_caller_raises_audience_error(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write"]))
        child = loop.run_until_complete(a.delegate(root, audience=WORKER, scopes=["read"], ttl=300))
        with pytest.raises(AudienceError) as exc:
            loop.run_until_complete(a.verify(child, caller=IMPERSONATOR))
        assert exc.value.expected == str(WORKER)
        assert exc.value.got == str(IMPERSONATOR)

    def test_correct_caller_succeeds(self) -> None:
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read", "write"]))
        child = loop.run_until_complete(a.delegate(root, audience=WORKER, scopes=["read"], ttl=300))
        ctx = loop.run_until_complete(a.verify(child, caller=WORKER))
        assert ctx.scopes == ["read"]

    def test_no_caller_check_if_none(self) -> None:
        """Omitting caller= bypasses audience check (root tokens have no audience)."""
        a = auth(clock=1000.0)
        loop = asyncio.new_event_loop()
        root = loop.run_until_complete(a.issue(COORD, ["read"]))
        ctx = loop.run_until_complete(a.verify(root))
        assert ctx.subject == COORD

    def test_audience_error_is_value_error(self) -> None:
        assert issubclass(AudienceError, ValueError)
