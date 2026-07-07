# SPDX-License-Identifier: Apache-2.0
"""Tests for the macaroons auth plugin: delegation, attenuation, cascading revocation.

The suite mixes spec-example unit tests, Hypothesis property tests for the attenuation
invariant, and the charter's adversarial-discrimination test: the delegation validators
must FAIL against the default ``jwt`` plugin and PASS against ``macaroons``.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given
from hypothesis import strategies as st
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.auth.macaroons import (
    AudienceMismatchError,
    ExpiredTokenError,
    InvalidTokenError,
    MacaroonAuth,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlExtensionError,
)
from nest_plugins_reference.validators.delegation_validators import run_all_delegation_checks

_SCOPES = ["read", "write", "admin", "delete", "list"]


def _auth() -> MacaroonAuth:
    return MacaroonAuth(secret=b"test-secret", clock=0.0)


class TestDelegation:
    @pytest.mark.asyncio
    async def test_issue_and_verify_root(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        ctx = await auth.verify(root)
        assert ctx.subject == AgentId("a1")
        assert set(ctx.scopes) == {"read", "write"}

    @pytest.mark.asyncio
    async def test_delegate_narrows_scope(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write", "admin"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600)
        ctx = await auth.verify(child)
        assert ctx.subject == AgentId("b")
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_scope_escalation_raises(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("b"), ["read", "admin"], ttl=60)

    @pytest.mark.asyncio
    async def test_ttl_extension_raises(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read"])  # default ttl 3600
        with pytest.raises(TtlExtensionError):
            await auth.delegate(root, AgentId("b"), ["read"], ttl=10_000)

    @pytest.mark.asyncio
    async def test_cascading_revocation(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600)
        grandchild = await auth.delegate(child, AgentId("c"), ["read"], ttl=60)
        await auth.verify(grandchild)  # valid before revocation
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(grandchild)

    @pytest.mark.asyncio
    async def test_audience_confusion_raises(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60)
        await auth.verify_for(child, AgentId("b"))  # correct audience is fine
        with pytest.raises(AudienceMismatchError):
            await auth.verify_for(child, AgentId("attacker"))

    @pytest.mark.asyncio
    async def test_tampered_token_rejected(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a1"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60)
        forged = Token(str(child).replace("read", "admin"))
        with pytest.raises(InvalidTokenError):
            await auth.verify(forged)

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self) -> None:
        auth = MacaroonAuth(secret=b"k", clock=0.0)
        root = await auth.issue(AgentId("a1"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=100)
        auth.set_clock(200.0)  # advance past the child's expiry
        with pytest.raises(ExpiredTokenError):
            await auth.verify(child)

    @pytest.mark.asyncio
    async def test_deterministic_issue(self) -> None:
        a = MacaroonAuth(secret=b"k", clock=0.0)
        b = MacaroonAuth(secret=b"k", clock=0.0)
        ta = await a.issue(AgentId("x"), ["read"])
        tb = await b.issue(AgentId("x"), ["read"])
        assert str(ta) == str(tb)

    def test_registry_resolves_macaroons(self) -> None:
        cls = PluginRegistry().resolve("auth", "macaroons")
        assert cls is MacaroonAuth


class TestAdversarialDiscrimination:
    """The charter's bar: the validator fails the reference plugin, passes the new one."""

    @pytest.mark.asyncio
    async def test_jwt_fails_delegation_checks(self) -> None:
        report = await run_all_delegation_checks(JwtAuth(secret=b"k", clock=0.0))
        assert not report.passed

    @pytest.mark.asyncio
    async def test_macaroons_passes_delegation_checks(self) -> None:
        report = await run_all_delegation_checks(MacaroonAuth(secret=b"k", clock=0.0))
        assert report.passed


class TestAttenuationProperties:
    @given(
        scopes=st.lists(st.sampled_from(_SCOPES), unique=True, min_size=1),
        picks=st.lists(st.sampled_from(_SCOPES), unique=True),
    )
    def test_delegation_is_always_a_subset(self, scopes: list[str], picks: list[str]) -> None:
        subset = [s for s in picks if s in scopes]

        async def run() -> None:
            auth = MacaroonAuth(secret=b"k", clock=0.0)
            root = await auth.issue(AgentId("a"), scopes)
            child = await auth.delegate(root, AgentId("b"), subset, ttl=60)
            ctx = await auth.verify(child)
            assert set(ctx.scopes) == set(subset)
            assert set(ctx.scopes).issubset(set(scopes))

        asyncio.run(run())

    @given(scopes=st.lists(st.sampled_from(_SCOPES), unique=True, min_size=1))
    def test_escalation_always_raises(self, scopes: list[str]) -> None:
        missing = [s for s in _SCOPES if s not in scopes]
        if not missing:
            return  # nothing outside the parent's scopes to escalate to

        async def run() -> None:
            auth = MacaroonAuth(secret=b"k", clock=0.0)
            root = await auth.issue(AgentId("a"), scopes)
            with pytest.raises(ScopeEscalationError):
                await auth.delegate(root, AgentId("b"), [*scopes, missing[0]], ttl=60)

        asyncio.run(run())
