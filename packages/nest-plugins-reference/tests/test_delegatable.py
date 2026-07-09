# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable capability-token auth plugin.

Persona note (capability-systems engineer): the invariants under test are the
ones a delegation chain lives or dies on -- scopes only narrow, TTLs only
tighten, a token cannot verify without a genuine chain rooted in the issuer's
secret, and revoking one hop kills every descendant without touching them.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    RevokedAncestorError,
    ScopeEscalationError,
    TokenChainMalformedError,
)

_ORCHESTRATOR = AgentId("orchestrator")
_WORKER = AgentId("worker-1")
_SUB_WORKER = AgentId("worker-1-1")
_ATTACKER = AgentId("attacker")


def _auth(clock: float = 0.0) -> DelegatableAuth:
    return DelegatableAuth(secret=b"test-secret", clock=clock)


# ---------------------------------------------------------------------------
# Delegation and scope narrowing
# ---------------------------------------------------------------------------


class TestDelegation:
    async def test_child_scope_strict_subset_of_parent_verifies(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read", "write", "deploy"])
        child = await auth.delegate(root, _WORKER, ["read", "write"], ttl=60.0)
        ctx = await auth.verify(child)
        assert ctx.subject == _WORKER
        assert ctx.scopes == ["read", "write"]

    async def test_child_scope_equal_to_parent_verifies(self) -> None:
        """Boundary: the subset relation is non-strict on scope *content*."""
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        ctx = await auth.verify(child)
        assert ctx.scopes == ["read"]

    async def test_child_scope_superset_of_parent_raises_scope_escalation(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        with pytest.raises(ScopeEscalationError) as exc:
            await auth.delegate(root, _WORKER, ["read", "admin"], ttl=60.0)
        assert "admin" in exc.value.requested_scopes

    async def test_child_scope_disjoint_from_parent_raises_scope_escalation(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, _WORKER, ["write"], ttl=60.0)

    async def test_multi_level_delegation_narrows_further(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read", "write"])
        child = await auth.delegate(root, _WORKER, ["read", "write"], ttl=100.0)
        grandchild = await auth.delegate(child, _SUB_WORKER, ["read"], ttl=50.0)
        ctx = await auth.verify(grandchild)
        assert ctx.subject == _SUB_WORKER
        assert ctx.scopes == ["read"]

    async def test_empty_scopes_subset_is_a_valid_boundary(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, [], ttl=60.0)
        ctx = await auth.verify(child)
        assert ctx.scopes == []


class TestTtlBounds:
    async def test_child_ttl_within_parent_window_verifies(self) -> None:
        auth = _auth(clock=0.0)
        root = await auth.issue(_ORCHESTRATOR, ["read"])  # expires at 3600
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        ctx = await auth.verify(child)
        assert ctx.expires_at == 60.0

    async def test_child_ttl_exceeding_parent_expiry_raises(self) -> None:
        auth = _auth(clock=0.0)
        root = await auth.issue(_ORCHESTRATOR, ["read"])  # expires at 3600
        with pytest.raises(ValueError, match="ttl"):
            await auth.delegate(root, _WORKER, ["read"], ttl=99999.0)


# ---------------------------------------------------------------------------
# Cascading revocation
# ---------------------------------------------------------------------------


class TestCascadingRevocation:
    async def test_verify_succeeds_before_any_revocation(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        await auth.verify(child)  # does not raise

    async def test_revoking_parent_invalidates_child(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)

    async def test_revoking_grandparent_invalidates_grandchild(self) -> None:
        """Cascade must propagate more than one level."""
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=100.0)
        grandchild = await auth.delegate(child, _SUB_WORKER, ["read"], ttl=50.0)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(grandchild)

    async def test_revoking_child_does_not_invalidate_sibling(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child_a = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        child_b = await auth.delegate(root, _SUB_WORKER, ["read"], ttl=60.0)
        await auth.revoke(child_a)
        await auth.verify(child_b)  # does not raise

    async def test_delegating_from_revoked_parent_raises_immediately(self) -> None:
        """Stale-parent attack: minting from a dead parent must fail at mint time."""
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.delegate(root, _WORKER, ["read"], ttl=60.0)

    async def test_delegating_from_expired_parent_raises(self) -> None:
        auth = _auth(clock=0.0)
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        auth.set_clock(999999.0)  # advance past root's 3600s default expiry
        with pytest.raises(ValueError, match="expired"):
            await auth.delegate(root, _WORKER, ["read"], ttl=60.0)


# ---------------------------------------------------------------------------
# Audience binding
# ---------------------------------------------------------------------------


class TestAudienceBinding:
    async def test_verify_with_audience_by_correct_holder_succeeds(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        ctx = await auth.verify_with_audience(child, _WORKER)
        assert ctx.subject == _WORKER

    async def test_verify_with_audience_by_wrong_agent_raises(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        with pytest.raises(AudienceMismatchError) as exc:
            await auth.verify_with_audience(child, _ATTACKER)
        assert exc.value.presented_by == _ATTACKER
        assert exc.value.declared_holder == _WORKER


# ---------------------------------------------------------------------------
# Chain authenticity / tamper resistance
# ---------------------------------------------------------------------------


class TestChainAuthenticity:
    async def test_forged_token_with_fabricated_chain_fails_mac_check(self) -> None:
        """An attacker without the secret cannot mint a valid-looking root."""
        auth = _auth()
        forged = Token(
            json.dumps(
                {
                    "hops": [
                        {
                            "holder": "attacker",
                            "scopes": ["admin"],
                            "issued_at": 0.0,
                            "expires_at": 3600.0,
                        }
                    ],
                    "mac": "0" * 64,
                }
            )
        )
        with pytest.raises(TokenChainMalformedError):
            await auth.verify(forged)

    async def test_tampering_with_hop_payload_breaks_mac(self) -> None:
        auth = _auth()
        root = await auth.issue(_ORCHESTRATOR, ["read"])
        child = await auth.delegate(root, _WORKER, ["read"], ttl=60.0)
        parsed = json.loads(str(child))
        parsed["hops"][-1]["scopes"] = ["read", "admin"]  # tamper after minting
        tampered = Token(json.dumps(parsed))
        with pytest.raises(TokenChainMalformedError):
            await auth.verify(tampered)

    async def test_malformed_json_raises_chain_malformed(self) -> None:
        auth = _auth()
        with pytest.raises(TokenChainMalformedError):
            await auth.verify(Token("not-json"))

    async def test_empty_hops_list_raises_chain_malformed(self) -> None:
        auth = _auth()
        with pytest.raises(TokenChainMalformedError):
            await auth.verify(Token(json.dumps({"hops": [], "mac": "abc"})))

    async def test_different_secret_cannot_verify_each_others_tokens(self) -> None:
        """Two independently-keyed authorities cannot forge for one another."""
        auth_a = DelegatableAuth(secret=b"secret-a", clock=0.0)
        auth_b = DelegatableAuth(secret=b"secret-b", clock=0.0)
        token = await auth_a.issue(_ORCHESTRATOR, ["read"])
        with pytest.raises(TokenChainMalformedError):
            await auth_b.verify(token)


# ---------------------------------------------------------------------------
# API fit
# ---------------------------------------------------------------------------


class TestApiFit:
    async def test_satisfies_auth_protocol(self) -> None:
        assert isinstance(_auth(), Auth)

    def test_resolvable_from_registry(self) -> None:
        cls = PluginRegistry().resolve("auth", "delegatable")
        assert cls is DelegatableAuth

    async def test_issue_matches_base_auth_contract(self) -> None:
        """issue/verify/revoke alone (no delegation) still behave like a normal Auth plugin."""
        auth = _auth()
        token = await auth.issue(_ORCHESTRATOR, ["read", "write"])
        ctx = await auth.verify(token)
        assert ctx.subject == _ORCHESTRATOR
        assert ctx.scopes == ["read", "write"]
        await auth.revoke(token)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(token)


# ---------------------------------------------------------------------------
# Property-based: chain depth and scope narrowing hold across arbitrary chains
# ---------------------------------------------------------------------------


_SCOPE_UNIVERSE = ["read", "write", "deploy", "admin", "billing"]


@st.composite
def _narrowing_chain(draw: st.DrawFn) -> list[list[str]]:
    """Draw a chain of scope-sets, each a subset of the previous."""
    depth = draw(st.integers(min_value=1, max_value=5))
    current = set(draw(st.lists(st.sampled_from(_SCOPE_UNIVERSE), min_size=1, unique=True)))
    chain = [sorted(current)]
    for _ in range(depth - 1):
        if not current:
            break
        current = set(draw(st.lists(st.sampled_from(sorted(current)), unique=True)))
        chain.append(sorted(current))
    return chain


class TestChainProperties:
    @settings(max_examples=100, deadline=None)
    @given(chain=_narrowing_chain())
    async def test_any_valid_narrowing_chain_verifies_end_to_end(
        self, chain: list[list[str]]
    ) -> None:
        auth = _auth(clock=0.0)
        token = await auth.issue(_ORCHESTRATOR, chain[0])
        holder = _ORCHESTRATOR
        for i, scopes in enumerate(chain[1:], start=1):
            holder = AgentId(f"agent-{i}")
            token = await auth.delegate(token, holder, scopes, ttl=3600.0 - i)
        ctx = await auth.verify(token)
        assert ctx.scopes == chain[-1]
        assert ctx.subject == holder

    @settings(max_examples=50, deadline=None)
    @given(chain=_narrowing_chain())
    async def test_revoking_root_kills_every_depth_of_any_chain(
        self, chain: list[list[str]]
    ) -> None:
        auth = _auth(clock=0.0)
        root = await auth.issue(_ORCHESTRATOR, chain[0])
        token = root
        for i, scopes in enumerate(chain[1:], start=1):
            token = await auth.delegate(token, AgentId(f"agent-{i}"), scopes, ttl=3600.0 - i)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(token)
