# SPDX-License-Identifier: Apache-2.0
"""Conformance tests for the delegatable capability tokens auth plugin."""

from __future__ import annotations

import json
from typing import Any

import pytest
from nest_core.types import AgentId, Token
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


@pytest.mark.asyncio
async def test_truncation_attack_fails() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    root = await auth.issue(AgentId("alice"), ["read", "write", "admin"])
    bob = await auth.delegate(root, AgentId("bob"), ["read"], ttl=100.0)

    # Bob tries to strip the delegation frame, leaving only the root
    bob_data = json.loads(str(bob))
    # Create forged token with caveats removed (only root remains) and Bob keeping root signature
    forged_data: dict[str, Any] = {
        "root_id": bob_data["root_id"],
        "subject": bob_data["subject"],
        "audience": bob_data["audience"],
        "scopes": bob_data["scopes"],
        "issued_at": bob_data["issued_at"],
        "expires_at": bob_data["expires_at"],
        "caveats": [],
        "sig": bob_data["sig"],  # The tail signature of the delegated token
    }
    forged = Token(json.dumps(forged_data))

    # Verification must fail because root signature calculated by verify will mismatch the tail sig
    with pytest.raises(ValueError, match="signature"):
        await auth.verify(forged, presenter=AgentId("alice"))


@pytest.mark.asyncio
async def test_middle_frame_re_escalation_fails() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    root = await auth.issue(AgentId("alice"), ["read", "write", "admin"])
    # Delegated: Alice -> Bob [read, write] -> Bob [read]
    bob_mid = await auth.delegate(root, AgentId("bob"), ["read", "write"], ttl=100.0)
    bob_low = await auth.delegate(bob_mid, AgentId("bob"), ["read"], ttl=100.0)

    low_data = json.loads(str(bob_low))
    # Bob tries to strip the final caveat to gain [read, write] using low_data's sig
    forged_mid_data = {
        "root_id": low_data["root_id"],
        "subject": low_data["subject"],
        "audience": low_data["audience"],
        "scopes": low_data["scopes"],
        "issued_at": low_data["issued_at"],
        "expires_at": low_data["expires_at"],
        "caveats": [low_data["caveats"][0]],
        "sig": low_data["sig"],  # Bob attempts to reuse the tail signature
    }
    forged = Token(json.dumps(forged_mid_data))

    with pytest.raises(ValueError, match="signature"):
        await auth.verify(forged, presenter=AgentId("bob"))


@pytest.mark.asyncio
async def test_invalid_json_raises_value_error() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=100.0)
    for bad_input in [
        "[{}",
        "123",
        "[123]",
        '{"token_id": "x"}',
        "[]",
        json.dumps(
            {
                "root_id": "x",
                "subject": "a",
                "audience": "a",
                "scopes": [],
                "issued_at": 100,
                "expires_at": 200,
                "caveats": 123,
                "sig": "abc",
            }
        ),
    ]:
        with pytest.raises(ValueError, match="Invalid token format"):
            await auth.verify(Token(bad_input), presenter=AgentId("alice"))
