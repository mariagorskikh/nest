# SPDX-License-Identifier: Apache-2.0
"""Tests for DelegatableAuth: happy paths, restrictions, and transitive revocation."""

from __future__ import annotations

import json

import pytest
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import DelegatableAuth, RevokedAncestorError


@pytest.fixture
def auth() -> DelegatableAuth:
    return DelegatableAuth(secret=b"test-secret-key")


@pytest.mark.asyncio
async def test_root_issue_and_verify(auth: DelegatableAuth) -> None:
    subject = AgentId("agent-root")
    scopes = ["read", "write"]
    token = await auth.issue(subject, scopes)

    ctx = await auth.verify(token)
    assert ctx.subject == subject
    assert ctx.scopes == scopes
    assert ctx.expires_at is not None
    assert ctx.issued_at is not None
    assert ctx.expires_at > ctx.issued_at


@pytest.mark.asyncio
async def test_delegation_happy_path(auth: DelegatableAuth) -> None:
    root_subject = AgentId("agent-root")
    root_scopes = ["read", "write", "delete"]
    root_token = await auth.issue(root_subject, root_scopes)

    # Delegate subset of scopes to agent-child
    child_subject = AgentId("agent-child")
    child_scopes = ["read", "write"]
    child_token = await auth.delegate(root_token, child_subject, child_scopes, ttl=100)

    # Verify child token
    ctx = await auth.verify(child_token)
    assert ctx.subject == child_subject
    assert ctx.scopes == child_scopes


@pytest.mark.asyncio
async def test_delegation_scope_escalation(auth: DelegatableAuth) -> None:
    root_token = await auth.issue(AgentId("agent-root"), ["read"])

    # Attempting to delegate "write" which parent doesn't have should raise ValueError
    with pytest.raises(ValueError, match="Escalated scopes"):
        await auth.delegate(root_token, AgentId("agent-child"), ["read", "write"], ttl=100)


@pytest.mark.asyncio
async def test_delegation_time_bounds(auth: DelegatableAuth) -> None:
    # Root expires in 3600 seconds by default
    root_token = await auth.issue(AgentId("agent-root"), ["read"])

    # Attempting to delegate with a TTL of 4000 seconds
    # (exceeding root's remaining lifetime) should raise ValueError
    with pytest.raises(ValueError, match="Child TTL exceeds parent expiration"):
        await auth.delegate(root_token, AgentId("agent-child"), ["read"], ttl=4000)


@pytest.mark.asyncio
async def test_cascading_revocation(auth: DelegatableAuth) -> None:
    root_token = await auth.issue(AgentId("coordinator"), ["read", "write"])
    int_token = await auth.delegate(root_token, AgentId("intermediary"), ["read", "write"], ttl=100)
    leaf_token = await auth.delegate(int_token, AgentId("leaf"), ["read"], ttl=50)

    # Verify both work fine initially
    await auth.verify(int_token)
    await auth.verify(leaf_token)

    # Revoke intermediate token
    await auth.revoke(int_token)

    # Verifying intermediate token itself raises ValueError (direct revocation)
    with pytest.raises(ValueError, match="Token has been revoked"):
        await auth.verify(int_token)

    # Verifying leaf token raises RevokedAncestorError (cascading revocation)
    with pytest.raises(RevokedAncestorError, match="Ancestor token was revoked"):
        await auth.verify(leaf_token)

    # Revoke leaf token directly
    leaf_token2 = await auth.delegate(root_token, AgentId("leaf-2"), ["read"], ttl=50)
    await auth.revoke(leaf_token2)
    with pytest.raises(ValueError, match="Token has been revoked"):
        await auth.verify(leaf_token2)


@pytest.mark.asyncio
async def test_signature_tampering(auth: DelegatableAuth) -> None:
    root_token = await auth.issue(AgentId("agent-root"), ["read"])
    child_token = await auth.delegate(root_token, AgentId("agent-child"), ["read"], ttl=100)

    # Tamper with the child payload part of the token string
    parts = str(child_token).split("|")
    # parts: [root_payload, root_sig, child_payload, child_sig]
    payload = json.loads(parts[2])
    payload["scopes"] = ["read", "write"]  # Escalated via tampering!
    parts[2] = json.dumps(payload, sort_keys=True)
    tampered_token = Token("|".join(parts))

    with pytest.raises(ValueError, match="Invalid token signature|Escalated scopes"):
        await auth.verify(tampered_token)


@pytest.mark.asyncio
async def test_expired_token(auth: DelegatableAuth) -> None:
    # Use custom clock to simulate expiration
    auth_with_clock = DelegatableAuth(secret=b"test-secret-key", clock=1000.0)
    token = await auth_with_clock.issue(AgentId("a"), ["read"])

    # Verify at same clock -> OK
    await auth_with_clock.verify(token)

    # Advance clock beyond expiration (1000 + 3600 = 4600)
    auth_with_clock._clock = 4700.0  # type: ignore
    with pytest.raises(ValueError, match="Token has expired"):
        await auth_with_clock.verify(token)
