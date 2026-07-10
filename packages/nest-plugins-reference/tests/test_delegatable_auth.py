# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable capability-token auth plugin.

Covers issuance, offline delegation, scope attenuation, TTL clamping,
cascading revocation across deep chains, audience binding, the three
adversarial patterns from the problem brief (scope escalation, stale
parent, audience confusion), and base ``Auth`` protocol compatibility.
"""

from __future__ import annotations

import pytest
from nest_core.layers.auth import Auth
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    DelegationError,
    ExpiredAncestorError,
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.auth.jwt_auth import JwtAuth

ROOT = AgentId("coordinator")
MID = AgentId("intermediary")
LEAF = AgentId("leaf")


def _auth(clock: float = 0.0) -> DelegatableAuth:
    return DelegatableAuth(secret=b"test-secret", clock=clock)


@pytest.mark.asyncio
async def test_satisfies_auth_protocol() -> None:
    auth = _auth()
    assert isinstance(auth, Auth)


@pytest.mark.asyncio
async def test_issue_and_verify_root() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read", "write"])
    ctx = await auth.verify(root)
    assert ctx.subject == ROOT
    assert sorted(ctx.scopes) == ["read", "write"]


@pytest.mark.asyncio
async def test_delegate_offline_and_verify_child() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read", "write"])
    child = await auth.delegate(root, MID, ["read"], ttl=60.0)
    ctx = await auth.verify(child)
    assert ctx.subject == MID
    assert ctx.scopes == ["read"]


@pytest.mark.asyncio
async def test_scope_escalation_raises_at_mint() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, MID, ["read", "admin"], ttl=60.0)


@pytest.mark.asyncio
async def test_grandchild_cannot_exceed_grandparent() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read", "write"])
    child = await auth.delegate(root, MID, ["read"], ttl=60.0)
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(child, LEAF, ["write"], ttl=30.0)


@pytest.mark.asyncio
async def test_child_ttl_clamped_to_parent() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read"])
    root_exp = (await auth.verify(root)).expires_at
    child = await auth.delegate(root, MID, ["read"], ttl=10_000_000.0)
    child_exp = (await auth.verify(child)).expires_at
    assert root_exp is not None and child_exp is not None
    assert child_exp <= root_exp


@pytest.mark.asyncio
async def test_cascading_revocation_root_kills_grandchild() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read", "write"])
    child = await auth.delegate(root, MID, ["read"], ttl=60.0)
    grandchild = await auth.delegate(child, LEAF, ["read"], ttl=30.0)
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(grandchild)


@pytest.mark.asyncio
async def test_revoking_middle_spares_sibling_branch() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read", "write"])
    mid_a = await auth.delegate(root, AgentId("mid-a"), ["read"], ttl=60.0)
    mid_b = await auth.delegate(root, AgentId("mid-b"), ["write"], ttl=60.0)
    leaf_a = await auth.delegate(mid_a, LEAF, ["read"], ttl=30.0)
    await auth.revoke(mid_a)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(leaf_a)
    ctx = await auth.verify(mid_b)
    assert ctx.scopes == ["write"]


@pytest.mark.asyncio
async def test_stale_parent_expired_ancestor_fails() -> None:
    auth = _auth(clock=0.0)
    root = await auth.issue(ROOT, ["read"])
    child = await auth.delegate(root, MID, ["read"], ttl=60.0)
    auth.set_clock(10_000_000.0)
    with pytest.raises(ExpiredAncestorError):
        await auth.verify(child)


@pytest.mark.asyncio
async def test_revoked_parent_cannot_mint_children() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read"])
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.delegate(root, MID, ["read"], ttl=60.0)


@pytest.mark.asyncio
async def test_audience_confusion_rejected() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read"])
    child = await auth.delegate(root, MID, ["read"], ttl=60.0)
    with pytest.raises(AudienceMismatchError):
        await auth.verify_presented(child, LEAF)
    ctx = await auth.verify_presented(child, MID)
    assert ctx.subject == MID


@pytest.mark.asyncio
async def test_tampered_chain_rejected() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read"])
    forged = Token(str(root).replace('"read"', '"admin"'))
    with pytest.raises(DelegationError):
        await auth.verify(forged)


@pytest.mark.asyncio
async def test_garbage_token_rejected() -> None:
    auth = _auth()
    for garbage in ("", "not-json", '{"chain": [], "sig": "00"}'):
        with pytest.raises(DelegationError):
            await auth.verify(Token(garbage))


@pytest.mark.asyncio
async def test_delegation_errors_are_value_errors() -> None:
    auth = _auth()
    root = await auth.issue(ROOT, ["read"])
    await auth.revoke(root)
    with pytest.raises(ValueError, match="revoked"):
        await auth.verify(root)


@pytest.mark.asyncio
async def test_default_jwt_plugin_is_vulnerable_baseline() -> None:
    """Document the gap this plugin closes: jwt has no chain semantics.

    Under ``JwtAuth`` a "delegated" token is just a fresh issuance, so
    revoking the parent leaves the child fully valid — the stale-parent
    attack the adversarial validator must catch.
    """
    jwt = JwtAuth(secret=b"test-secret")
    parent = await jwt.issue(ROOT, ["read"])
    child = await jwt.issue(MID, ["read", "admin"])  # escalation unnoticed
    await jwt.revoke(parent)
    ctx = await jwt.verify(child)  # still verifies: no cascade
    assert "admin" in ctx.scopes
