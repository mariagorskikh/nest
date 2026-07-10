# SPDX-License-Identifier: Apache-2.0
"""Tests for DelegatableAuth plugin.

Covers:
- Basic issue/verify/revoke (Auth protocol conformance)
- Delegation with scope subset, TTL bounds
- All three adversarial attacks: scope escalation, stale parent, audience confusion
- Cascading revocation (grandchild after parent revoke)
- Independent subtree isolation (sibling survives after one path revoked)
- Invalid nonce chain detection
"""

from __future__ import annotations

import json

import pytest
from nest_core.types import AgentId, AuthContext, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    InvalidDelegationChainError,
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.validators.auth_validators import (
    check_audience_enforced,
    check_no_scope_escalation,
    check_stale_parent_invalidates_child,
)


class TestDelegatableAuthProtocol:
    """Conformance to the Auth protocol (issue/verify/revoke)."""

    @pytest.fixture
    def auth(self) -> DelegatableAuth:
        return DelegatableAuth(secret=b"test-secret")

    @pytest.mark.asyncio
    async def test_issue_root(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("admin"), ["read", "write"])
        assert isinstance(token, str)
        assert len(token) > 0

    @pytest.mark.asyncio
    async def test_verify_root(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("admin"), ["read", "write"])
        ctx = await auth.verify(token)
        assert isinstance(ctx, AuthContext)
        assert ctx.subject == AgentId("admin")
        assert set(ctx.scopes) == {"read", "write"}

    @pytest.mark.asyncio
    async def test_verify_with_presenter_matches(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            token,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        ctx = await auth.verify(child, presenter=AgentId("worker"))
        assert ctx.subject == AgentId("admin")
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_revoke_root(self, auth: DelegatableAuth) -> None:
        token = await auth.issue(AgentId("admin"), ["read"])
        await auth.revoke(token)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(token)

    @pytest.mark.asyncio
    async def test_issue_multiple_tokens(self, auth: DelegatableAuth) -> None:
        t1 = await auth.issue(AgentId("a1"), ["read"])
        t2 = await auth.issue(AgentId("a1"), ["write"])
        assert t1 != t2
        assert (await auth.verify(t1)).scopes == ["read"]
        assert (await auth.verify(t2)).scopes == ["write"]


class TestDelegation:
    """Delegation semantics."""

    @pytest.fixture
    def auth(self) -> DelegatableAuth:
        return DelegatableAuth(secret=b"test-secret")

    @pytest.mark.asyncio
    async def test_delegate_basic(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read", "write"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        assert isinstance(child, str)
        ctx = await auth.verify(child, presenter=AgentId("worker"))
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_delegate_preserves_subject(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        ctx = await auth.verify(child, presenter=AgentId("worker"))
        assert ctx.subject == AgentId("admin")

    @pytest.mark.asyncio
    async def test_delegate_nested(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read", "write", "delete"])
        child = await auth.delegate(
            root,
            audience=AgentId("manager"),
            scopes=["read", "write"],
            ttl=200,
        )
        grandchild = await auth.delegate(
            child,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=50,
        )
        ctx = await auth.verify(grandchild, presenter=AgentId("worker"))
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_cascading_revocation(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("manager"),
            scopes=["read"],
            ttl=100,
        )
        grandchild = await auth.delegate(
            child,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=50,
        )
        # Revoke the middle — grandchild should also fail
        await auth.revoke(child)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(grandchild, presenter=AgentId("worker"))
        # Child itself should also fail
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=AgentId("manager"))

    @pytest.mark.asyncio
    async def test_sibling_subtree_independent(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read", "write"])
        child_a = await auth.delegate(
            root,
            audience=AgentId("worker-a"),
            scopes=["read"],
            ttl=100,
        )
        child_b = await auth.delegate(
            root,
            audience=AgentId("worker-b"),
            scopes=["write"],
            ttl=100,
        )
        # Revoke child_a's subtree only
        await auth.revoke(child_a)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child_a, presenter=AgentId("worker-a"))
        # child_b must still verify
        ctx = await auth.verify(child_b, presenter=AgentId("worker-b"))
        assert ctx.scopes == ["write"]


class TestAdversarial:
    """Adversarial attacks that delegatable prevents (and jwt_auth does not)."""

    @pytest.fixture
    def auth(self) -> DelegatableAuth:
        return DelegatableAuth(secret=b"test-secret")

    @pytest.mark.asyncio
    async def test_scope_escalation_rejected(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(
                root,
                audience=AgentId("worker"),
                scopes=["read", "write"],
                ttl=100,
            )

    @pytest.mark.asyncio
    async def test_scope_escalation_validator(self, auth: DelegatableAuth) -> None:
        report = await check_no_scope_escalation(auth)
        assert report.passed, report.detail

    @pytest.mark.asyncio
    async def test_stale_parent_rejected(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=AgentId("worker"))

    @pytest.mark.asyncio
    async def test_stale_parent_validator(self, auth: DelegatableAuth) -> None:
        report = await check_stale_parent_invalidates_child(auth)
        assert report.passed, report.detail

    @pytest.mark.asyncio
    async def test_audience_mismatch_rejected(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=AgentId("eve"))

    @pytest.mark.asyncio
    async def test_audience_validator(self, auth: DelegatableAuth) -> None:
        report = await check_audience_enforced(auth)
        assert report.passed, report.detail

    @pytest.mark.asyncio
    async def test_tampered_token_rejected(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        # Tamper with the nonce portion of the token string
        tok_str = str(child)
        last_delim = tok_str.rfind("|")
        tampered = Token(tok_str[:last_delim] + "|deadbeef")
        with pytest.raises((ValueError, InvalidDelegationChainError)):
            await auth.verify(tampered, presenter=AgentId("worker"))

    @pytest.mark.asyncio
    async def test_path_rewrite_rejected(self, auth: DelegatableAuth) -> None:
        """Rewriting the path on a revoked-ancestor child must NOT bypass revocation.

        Before the fix, path was not in the HMAC, so an attacker could:
        1. Obtain a valid child token whose parent was revoked
        2. Rewrite path_hex to a non-revoked prefix
        3. The HMAC still checked out (path wasn't signed)
        4. The revocation check passed (new path doesn't match revoked prefix)
        """
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        # Revoke the root
        await auth.revoke(root)

        # Now try to rewrite the path to bypass revocation
        child_str = str(child)
        parts = child_str.split("|")
        assert len(parts) == 3
        _path_hex, payload_b64, nonce = parts

        # Craft a *different* path (non-revoked) with the same payload and nonce
        forged_path = json.dumps(["fresh-handle"]).encode().hex()
        forged_token = Token(f"{forged_path}|{payload_b64}|{nonce}")

        # Must fail — either the HMAC doesn't match (path is signed now) or
        # the revocation check catches it. Both are acceptable defences.
        with pytest.raises((ValueError, InvalidDelegationChainError, RevokedAncestorError)):
            await auth.verify(forged_token, presenter=AgentId("worker"))

    @pytest.mark.asyncio
    async def test_ttl_enforced(self, auth: DelegatableAuth) -> None:
        past_time = 0.0
        auth._clock = past_time  # type: ignore[reportPrivateUsage]

        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=10,
        )
        # Advance clock past TTL
        auth._clock = 20.0  # type: ignore[reportPrivateUsage]
        with pytest.raises(ValueError, match="expired"):
            await auth.verify(child, presenter=AgentId("worker"))

    @pytest.mark.asyncio
    async def test_child_ttl_exceeds_parent(self, auth: DelegatableAuth) -> None:
        root = await auth.issue(AgentId("admin"), ["read"])
        with pytest.raises(ValueError, match="exceeds parent"):
            await auth.delegate(
                root,
                audience=AgentId("worker"),
                scopes=["read"],
                ttl=10000,
            )


class TestValidatorsFailAgainstJwt:
    """Adversarial validators MUST fail against the reference ``jwt_auth`` plugin.

    Each test demonstrates that the reference plugin cannot prevent the attack
    that ``DelegatableAuth`` prevents.  The same validators pass against
    ``DelegatableAuth`` (tested in :class:`TestAdversarial`).
    """

    @pytest.fixture
    def jwt(self) -> JwtAuth:
        return JwtAuth(secret=b"test-secret")

    @pytest.mark.asyncio
    async def test_scope_escalation_validator_fails_jwt(self, jwt: JwtAuth) -> None:
        """check_no_scope_escalation returns passed=False for jwt_auth."""
        report = await check_no_scope_escalation(jwt)  # type: ignore[arg-type]
        assert not report.passed, report.detail

    @pytest.mark.asyncio
    async def test_stale_parent_validator_fails_jwt(self, jwt: JwtAuth) -> None:
        """check_stale_parent_invalidates_child returns passed=False for jwt_auth."""
        report = await check_stale_parent_invalidates_child(jwt)  # type: ignore[arg-type]
        assert not report.passed, report.detail

    @pytest.mark.asyncio
    async def test_audience_validator_fails_jwt(self, jwt: JwtAuth) -> None:
        """check_audience_enforced returns passed=False for jwt_auth."""
        report = await check_audience_enforced(jwt)  # type: ignore[arg-type]
        assert not report.passed, report.detail

    @pytest.mark.asyncio
    async def test_jwt_no_scope_enforcement(self, jwt: JwtAuth) -> None:
        """jwt_auth has no delegate() — once a token is issued any holder
        can use all its scopes; there is no mechanism to issue a *restricted*
        child token."""
        token = await jwt.issue(AgentId("admin"), ["read", "write"])
        ctx = await jwt.verify(token)
        # Holder can use any scope, no delegation concept exists
        assert set(ctx.scopes) == {"read", "write"}

    @pytest.mark.asyncio
    async def test_jwt_allows_stale_parent(self, jwt: JwtAuth) -> None:
        """jwt_auth: revoking one token does not affect any other token.

        Because there is no parent-child chain, revoking an "issuer" token has
        no effect on tokens issued independently.
        """
        # Use explicit clock so tokens are distinct
        jwt._clock = 0.0  # type: ignore[reportPrivateUsage]
        token_a = await jwt.issue(AgentId("admin"), ["read"])
        jwt._clock = 1.0  # type: ignore[reportPrivateUsage]
        token_b = await jwt.issue(AgentId("admin"), ["read"])
        await jwt.revoke(token_a)
        # token_b still verifies — no parent-child link
        ctx = await jwt.verify(token_b)
        assert ctx.subject == AgentId("admin")

    @pytest.mark.asyncio
    async def test_jwt_no_audience_enforcement(self, jwt: JwtAuth) -> None:
        """jwt_auth: no audience claim — any presenter passes verification."""
        token = await jwt.issue(AgentId("alice"), ["read"])
        # No presenter parameter exists in jwt_auth.verify
        ctx = await jwt.verify(token)
        assert ctx.subject == AgentId("alice")

    @pytest.mark.asyncio
    async def test_delegatable_stale_parent_blocked(self) -> None:
        """DelegatableAuth: revoking parent cascades to child."""
        auth = DelegatableAuth(secret=b"test-secret")
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=AgentId("worker"))

    @pytest.mark.asyncio
    async def test_delegatable_audience_enforced(self) -> None:
        """DelegatableAuth: presenter must match token audience."""
        auth = DelegatableAuth(secret=b"test-secret")
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=AgentId("eve"))


class TestDeterminism:
    """Determinism: same operations produce same results."""

    @pytest.mark.asyncio
    async def test_deterministic_issue(self) -> None:
        a1 = DelegatableAuth(secret=b"fixed-secret")
        a2 = DelegatableAuth(secret=b"fixed-secret")
        t1 = await a1.issue(AgentId("admin"), ["read"])
        t2 = await a2.issue(AgentId("admin"), ["read"])
        # Tokens are deterministic (same secret → same handles)
        assert t1 == t2
        ctx1 = await a1.verify(t1)
        ctx2 = await a2.verify(t2)
        assert ctx1.subject == ctx2.subject
        assert ctx1.scopes == ctx2.scopes

    @pytest.mark.asyncio
    async def test_deterministic_verify(self) -> None:
        auth = DelegatableAuth(secret=b"fixed-secret")
        root = await auth.issue(AgentId("admin"), ["read"])
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
        ctx1 = await auth.verify(child, presenter=AgentId("worker"))
        ctx2 = await auth.verify(child, presenter=AgentId("worker"))
        assert ctx1 == ctx2
