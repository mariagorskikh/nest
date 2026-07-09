# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Example-based tests for the ``delegatable`` auth plugin.

Covers the ``Auth`` protocol surface, the ``delegate`` extension, and the three
attacks the delegated-auth problem calls out: scope escalation (honest and
MAC-forged), cascading revocation, and audience confusion — plus tampering,
TTL clamping, and expiry.
"""

from __future__ import annotations

import pytest
from nest_core.layers.auth import Auth
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    ExpiredTokenError,
    InvalidTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
)


@pytest.fixture
def auth() -> DelegatableAuth:
    """A fresh plugin pinned to logical tick 0."""
    return DelegatableAuth(secret=b"root-secret", clock=0.0, default_ttl=1000.0)


class TestProtocolConformance:
    """The plugin must be a structural ``Auth`` and keep its base behaviour."""

    def test_is_auth_instance(self, auth: DelegatableAuth) -> None:
        """It satisfies the runtime-checkable ``Auth`` protocol."""
        assert isinstance(auth, Auth)

    async def test_issue_verify_roundtrip(self, auth: DelegatableAuth) -> None:
        """A freshly issued root token verifies with its scopes and subject."""
        root = await auth.issue(AgentId("orch"), ["tool:write", "tool:read"])
        ctx = await auth.verify(root)
        assert ctx.subject == AgentId("orch")
        assert ctx.scopes == ["tool:read", "tool:write"]  # sorted, canonical

    async def test_issue_is_inspectable(self, auth: DelegatableAuth) -> None:
        """The token is human-inspectable JSON (grep-able in a trace)."""
        root = await auth.issue(AgentId("orch"), ["read"])
        assert '"chain"' in str(root)
        assert "|sig:" in str(root)


class TestDelegation:
    """``delegate`` mints strictly-narrowing child tokens without the issuer."""

    async def test_child_narrows_scopes(self, auth: DelegatableAuth) -> None:
        """A child restricted to a subset verifies with exactly that subset."""
        root = await auth.issue(AgentId("orch"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=100.0)
        ctx = await auth.verify(child, presenter=AgentId("worker"))
        assert ctx.subject == AgentId("worker")
        assert ctx.scopes == ["read"]

    async def test_multi_hop_chain(self, auth: DelegatableAuth) -> None:
        """Delegation composes: grandchild off a child still verifies."""
        root = await auth.issue(AgentId("orch"), ["read", "write"])
        child = await auth.delegate(root, AgentId("mid"), ["read", "write"], ttl=500.0)
        grand = await auth.delegate(child, AgentId("leaf"), ["read"], ttl=100.0)
        assert (await auth.verify(grand, presenter=AgentId("leaf"))).scopes == ["read"]

    async def test_ttl_clamped_to_parent(self, auth: DelegatableAuth) -> None:
        """A child TTL request beyond the parent's expiry is clamped down."""
        auth_short = DelegatableAuth(secret=b"s", clock=0.0, default_ttl=100.0)
        root = await auth_short.issue(AgentId("orch"), ["read"])
        child = await auth_short.delegate(root, AgentId("worker"), ["read"], ttl=9999.0)
        assert (await auth_short.verify(child)).expires_at == 100.0


class TestScopeEscalation:
    """Attack 1: a child must never hold scopes the parent lacks."""

    async def test_escalation_rejected_at_delegate(self, auth: DelegatableAuth) -> None:
        """Honest minting of a wider child raises immediately."""
        root = await auth.issue(AgentId("orch"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("worker"), ["read", "write"], ttl=10.0)

    async def test_forged_wide_caveat_rejected_at_verify(self, auth: DelegatableAuth) -> None:
        """A MAC-valid but widened caveat is rejected on verify.

        The holder knows the parent signature (the child's MAC key), so it can
        forge a caveat with a valid chain MAC. Restriction is enforced at verify
        time — this is the macaroon property that actually stops escalation.
        """
        root = await auth.issue(AgentId("orch"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=100.0)
        chain, _ = auth._decode(child)
        forged = {
            "tid": "forged0000000000",
            "parent_tid": chain[-1]["tid"],
            "sub": "evil",
            "aud": "evil",
            "scopes": ["read", "write"],  # parent (child) only holds read
            "iat": 0.0,
            "exp": 50.0,
        }
        forged_token = auth._encode([*chain, forged])  # recomputes a valid MAC
        with pytest.raises(ScopeEscalationError):
            await auth.verify(forged_token)


class TestCascadingRevocation:
    """Attack 2: revoking any ancestor invalidates the whole subtree."""

    async def test_revoke_parent_kills_descendants(self, auth: DelegatableAuth) -> None:
        """Revoking the root fails root, child, and grandchild at verify."""
        root = await auth.issue(AgentId("orch"), ["read", "write"])
        child = await auth.delegate(root, AgentId("mid"), ["read"], ttl=500.0)
        grand = await auth.delegate(child, AgentId("leaf"), ["read"], ttl=100.0)

        await auth.revoke(root)

        for token in (root, child, grand):
            with pytest.raises(RevokedAncestorError):
                await auth.verify(token)

    async def test_revoke_middle_spares_ancestor(self, auth: DelegatableAuth) -> None:
        """Revoking a middle node fails it and its child but not its parent."""
        root = await auth.issue(AgentId("orch"), ["read", "write"])
        child = await auth.delegate(root, AgentId("mid"), ["read"], ttl=500.0)
        grand = await auth.delegate(child, AgentId("leaf"), ["read"], ttl=100.0)

        await auth.revoke(child)

        assert (await auth.verify(root)).subject == AgentId("orch")  # parent survives
        for token in (child, grand):
            with pytest.raises(RevokedAncestorError):
                await auth.verify(token)


class TestAudienceBinding:
    """Attack 3: a token is usable only by its declared audience."""

    async def test_wrong_presenter_rejected(self, auth: DelegatableAuth) -> None:
        """A child bound to `worker` fails when presented by an intruder."""
        root = await auth.issue(AgentId("orch"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=100.0)
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=AgentId("intruder"))

    async def test_right_presenter_accepted(self, auth: DelegatableAuth) -> None:
        """The declared audience verifies fine."""
        root = await auth.issue(AgentId("orch"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=100.0)
        assert (await auth.verify(child, presenter=AgentId("worker"))).subject == AgentId("worker")

    async def test_presenter_optional(self, auth: DelegatableAuth) -> None:
        """Omitting `presenter` keeps protocol compatibility (skips aud check)."""
        root = await auth.issue(AgentId("orch"), ["read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=100.0)
        assert (await auth.verify(child)).subject == AgentId("worker")


class TestIntegrityAndExpiry:
    """MAC tampering and expiry are rejected with typed errors."""

    async def test_tampered_token_rejected(self, auth: DelegatableAuth) -> None:
        """Flipping any byte breaks the chain MAC."""
        root = await auth.issue(AgentId("orch"), ["read"])
        with pytest.raises(InvalidTokenError):
            await auth.verify(Token(str(root) + "x"))

    async def test_malformed_token_rejected(self, auth: DelegatableAuth) -> None:
        """A token without the MAC envelope is rejected."""
        with pytest.raises(InvalidTokenError):
            await auth.verify(Token("garbage"))

    async def test_expired_leaf_rejected(self, auth: DelegatableAuth) -> None:
        """A token past its expiry fails once the clock advances."""
        short = DelegatableAuth(secret=b"s", clock=0.0, default_ttl=10.0)
        root = await short.issue(AgentId("orch"), ["read"])
        short.set_clock(11.0)
        with pytest.raises(ExpiredTokenError):
            await short.verify(root)


class TestDeterminism:
    """Same inputs -> byte-identical tokens (Tier 1 requirement)."""

    async def test_issue_is_deterministic(self) -> None:
        """Two plugins with the same secret/clock issue identical tokens."""
        a = DelegatableAuth(secret=b"k", clock=5.0)
        b = DelegatableAuth(secret=b"k", clock=5.0)
        ta = await a.issue(AgentId("x"), ["read"])
        tb = await b.issue(AgentId("x"), ["read"])
        assert str(ta) == str(tb)

    async def test_delegate_is_deterministic(self) -> None:
        """Identical delegation chains produce identical child tokens."""
        a = DelegatableAuth(secret=b"k", clock=0.0)
        b = DelegatableAuth(secret=b"k", clock=0.0)
        ra = await a.issue(AgentId("x"), ["read", "write"])
        rb = await b.issue(AgentId("x"), ["read", "write"])
        ca = await a.delegate(ra, AgentId("y"), ["read"], ttl=10.0)
        cb = await b.delegate(rb, AgentId("y"), ["read"], ttl=10.0)
        assert str(ca) == str(cb)
