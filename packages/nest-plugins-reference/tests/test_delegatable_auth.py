# SPDX-License-Identifier: Apache-2.0
"""Conformance tests for the delegatable capability tokens auth plugin."""

from __future__ import annotations

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import DelegatableAuth, RevokedAncestorError


@pytest.mark.asyncio
async def test_issue_and_verify() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    token = await auth.issue(AgentId("a1"), ["read", "write"])
    ctx = await auth.verify(token, presenter=AgentId("a1"))
    assert ctx.subject == AgentId("a1")
    assert ctx.scopes == ["read", "write"]


@pytest.mark.asyncio
async def test_delegate_subset_scopes() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    token = await auth.issue(AgentId("a1"), ["read", "write"])
    child = await auth.delegate(token, AgentId("b1"), ["read"], ttl=50.0)
    ctx = await auth.verify(child, presenter=AgentId("b1"))
    assert ctx.subject == AgentId("a1")
    assert ctx.scopes == ["read"]


@pytest.mark.asyncio
async def test_delegate_scope_escalation_raises() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    token = await auth.issue(AgentId("a1"), ["read"])
    with pytest.raises(ValueError, match="Scope escalation"):
        await auth.delegate(token, AgentId("b1"), ["read", "write"], ttl=50.0)


@pytest.mark.asyncio
async def test_revoke_parent_invalidates_child() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    parent = await auth.issue(AgentId("a1"), ["read", "write"])
    child = await auth.delegate(parent, AgentId("b1"), ["read"], ttl=50.0)

    # Revoking parent
    await auth.revoke(parent)

    with pytest.raises(RevokedAncestorError, match="revoked"):
        await auth.verify(child, presenter=AgentId("b1"))


@pytest.mark.asyncio
async def test_revoke_grandparent_invalidates_grandchild() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    grandparent = await auth.issue(AgentId("a1"), ["read", "write", "admin"])
    parent = await auth.delegate(grandparent, AgentId("b1"), ["read", "write"], ttl=100.0)
    child = await auth.delegate(parent, AgentId("c1"), ["read"], ttl=50.0)

    # Revoking grandparent
    await auth.revoke(grandparent)

    with pytest.raises(RevokedAncestorError, match="revoked"):
        await auth.verify(child, presenter=AgentId("c1"))


@pytest.mark.asyncio
async def test_audience_confusion_raises() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    token = await auth.issue(AgentId("a1"), ["read"])
    child = await auth.delegate(token, AgentId("b1"), ["read"], ttl=50.0)

    # Presented by wrong agent c1
    with pytest.raises(ValueError, match="Audience confusion"):
        await auth.verify(child, presenter=AgentId("c1"))


@pytest.mark.asyncio
async def test_child_ttl_exceeds_parent_raises() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    # parent expires at 100 + 3600 = 3700.0
    parent = await auth.issue(AgentId("a1"), ["read", "write"])

    # child delegated at 100 with ttl=3601 (expires at 3701.0 > parent's 3700.0)
    with pytest.raises(ValueError, match="Child TTL exceeds"):
        await auth.delegate(parent, AgentId("b1"), ["read"], ttl=3601.0)


@pytest.mark.asyncio
async def test_leaf_scopes_subset_of_root() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    root = await auth.issue(AgentId("a1"), ["read", "write"])

    # intermediary narrows scopes
    parent = await auth.delegate(root, AgentId("b1"), ["read"], ttl=50.0)

    # leaf tries to delegate write (raises ScopeEscalation since parent only has read)
    with pytest.raises(ValueError, match="Scope escalation"):
        await auth.delegate(parent, AgentId("c1"), ["write"], ttl=10.0)
