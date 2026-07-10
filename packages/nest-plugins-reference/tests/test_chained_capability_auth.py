# SPDX-License-Identifier: Apache-2.0
"""Tests for the chained-capability auth plugin.

Covers the happy path (issue -> delegate -> verify), cascading revocation,
and the three adversarial attacks named in the problem brief: scope
escalation, a stale (expired/revoked) parent still verifying, and audience
confusion. Each adversarial test is paired with a demonstration that the
default ``jwt`` plugin has no defense against the same attack class, since
it has no concept of a delegation chain at all.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.chained_capability import (
    AudienceMismatchError,
    ChainedCapabilityAuth,
    ExpiredAncestorError,
    InvalidTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlExceededError,
)
from nest_plugins_reference.auth.jwt_auth import JwtAuth

ROOT = AgentId("coordinator")
INTERMEDIARY = AgentId("intermediary")
LEAF = AgentId("leaf")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_issue_and_verify_round_trip() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    token = await auth.issue(ROOT, ["read", "write"])
    ctx = await auth.verify(token)
    assert ctx.subject == ROOT
    assert set(ctx.scopes) == {"read", "write"}


async def test_delegate_narrows_scopes() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read", "write", "admin"])
    child = await auth.delegate(root, INTERMEDIARY, ["read"], ttl=100)
    ctx = await auth.verify(child, expected_audience=INTERMEDIARY)
    assert ctx.subject == INTERMEDIARY
    assert ctx.scopes == ["read"]


async def test_delegate_two_levels_deep() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read", "write"])
    mid = await auth.delegate(root, INTERMEDIARY, ["read"], ttl=1000)
    leaf = await auth.delegate(mid, LEAF, ["read"], ttl=100)
    ctx = await auth.verify(leaf, expected_audience=LEAF)
    assert ctx.subject == LEAF
    assert ctx.scopes == ["read"]


async def test_verify_with_matching_audience_succeeds() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read"])
    child = await auth.delegate(root, LEAF, ["read"], ttl=100)
    ctx = await auth.verify(child, expected_audience=LEAF)
    assert ctx.subject == LEAF


# ---------------------------------------------------------------------------
# Cascading revocation
# ---------------------------------------------------------------------------


async def test_revoking_root_invalidates_all_descendants() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read", "write"])
    mid = await auth.delegate(root, INTERMEDIARY, ["read"], ttl=1000)
    leaf = await auth.delegate(mid, LEAF, ["read"], ttl=100)

    await auth.verify(leaf, expected_audience=LEAF)  # still fine before revocation

    await auth.revoke(root)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(mid, expected_audience=INTERMEDIARY)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(leaf, expected_audience=LEAF)


async def test_revoking_intermediary_does_not_affect_root() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read"])
    mid = await auth.delegate(root, INTERMEDIARY, ["read"], ttl=1000)

    await auth.revoke(mid)

    await auth.verify(root)  # unaffected
    with pytest.raises(RevokedAncestorError):
        await auth.verify(mid, expected_audience=INTERMEDIARY)


# ---------------------------------------------------------------------------
# Adversarial attack 1: scope escalation
# ---------------------------------------------------------------------------


async def test_scope_escalation_rejected_at_delegate_time() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, LEAF, ["read", "admin"], ttl=10)


async def test_scope_escalation_rejected_even_if_hand_crafted() -> None:
    """A forged token that skips ``delegate()`` and claims broader scopes
    directly must still be caught at verify time (defense in depth)."""
    auth = ChainedCapabilityAuth(secret=b"s")
    root_token = await auth.issue(ROOT, ["read"])
    root_chain = json.loads(str(root_token))
    forged_child = {
        "jti": "forged",
        "sub": str(LEAF),
        "aud": str(LEAF),
        "scopes": ["read", "admin"],
        "parent_jti": root_chain[0]["jti"],
        "iat": 0,
        "exp": 100,
        "sig": "0" * 64,
    }
    forged = Token(json.dumps([*root_chain, forged_child]))
    with pytest.raises((ScopeEscalationError, InvalidTokenError)):
        await auth.verify(forged, expected_audience=LEAF)


async def test_naive_jwt_has_no_scope_escalation_defense() -> None:
    """The default jwt plugin has no delegation concept, so gluing a
    ``delegated_from`` claim onto an independently-issued token is
    indistinguishable from a legitimately-scoped token -- there is
    nothing to reject."""
    jwt = JwtAuth(secret=b"s")
    fake_child = await jwt.issue(LEAF, ["read", "admin"])  # "admin" never checked against a parent
    ctx = await jwt.verify(fake_child)
    assert "admin" in ctx.scopes  # escalation sails through uncaught


# ---------------------------------------------------------------------------
# Adversarial attack 2: stale parent (expired or revoked) still verifying
# ---------------------------------------------------------------------------


async def test_expired_parent_invalidates_child_even_before_child_expiry() -> None:
    auth = ChainedCapabilityAuth(secret=b"s", clock=0.0)
    root = await auth.issue(ROOT, ["read"])  # expires at 3600
    child = await auth.delegate(root, LEAF, ["read"], ttl=100)  # expires at 100

    auth.set_clock(3601.0)  # root has expired; child's own exp (100) is moot
    with pytest.raises(ExpiredAncestorError):
        await auth.verify(child, expected_audience=LEAF)


async def test_delegate_ttl_cannot_outlive_parent() -> None:
    auth = ChainedCapabilityAuth(secret=b"s", clock=0.0)
    root = await auth.issue(ROOT, ["read"])  # expires at 3600
    with pytest.raises(TtlExceededError):
        await auth.delegate(root, LEAF, ["read"], ttl=10_000)


async def test_revoked_parent_invalidates_child() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read"])
    child = await auth.delegate(root, LEAF, ["read"], ttl=100)
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(child, expected_audience=LEAF)


async def test_naive_jwt_has_no_revocation_propagation() -> None:
    """Revoking a jwt "parent" token has zero effect on an independently
    issued "child" token, because jwt_auth's revocation set is keyed by
    exact token string with no parent/child relationship at all."""
    jwt = JwtAuth(secret=b"s")
    parent = await jwt.issue(ROOT, ["read"])
    child = await jwt.issue(LEAF, ["read"])  # not actually derived from parent
    await jwt.revoke(parent)
    ctx = await jwt.verify(child)  # still verifies: revocation did not propagate
    assert ctx.subject == LEAF


# ---------------------------------------------------------------------------
# Adversarial attack 3: audience confusion
# ---------------------------------------------------------------------------


async def test_audience_mismatch_rejected() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read"])
    child = await auth.delegate(root, LEAF, ["read"], ttl=100)
    with pytest.raises(AudienceMismatchError):
        await auth.verify(child, expected_audience=AgentId("someone-else"))


async def test_omitted_audience_on_delegated_token_is_rejected() -> None:
    """The actual fix for the reviewed gap: presenting a *delegated* token
    with no ``expected_audience`` at all must fail, not silently skip the
    check the way an optional parameter would. This is what closes the
    B-hands-its-token-to-C hole even when the caller forgets to ask."""
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read"])
    child = await auth.delegate(root, LEAF, ["read"], ttl=100)
    with pytest.raises(AudienceMismatchError):
        await auth.verify(child)  # no expected_audience -- must not be allowed to pass


async def test_omitted_audience_on_root_token_is_still_allowed() -> None:
    """A root token has no delegation hop to confuse, so unlike a
    delegated token, omitting ``expected_audience`` on a root stays
    legal -- the mandatory check is scoped to exactly the attack it
    defends against."""
    auth = ChainedCapabilityAuth(secret=b"s")
    root = await auth.issue(ROOT, ["read"])
    ctx = await auth.verify(root)
    assert ctx.subject == ROOT


async def test_naive_jwt_has_no_audience_binding() -> None:
    """jwt_auth's verify() has no audience parameter at all, so any
    holder of a bearer token can present it as anyone."""
    jwt = JwtAuth(secret=b"s")
    token = await jwt.issue(LEAF, ["read"])
    ctx = await jwt.verify(token)  # no way to assert "presented by X"
    assert ctx.subject == LEAF  # succeeds regardless of who actually presented it


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


async def test_tampered_scope_is_rejected() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    token = await auth.issue(ROOT, ["read"])
    chain = json.loads(str(token))
    chain[0]["scopes"] = ["read", "admin"]  # tamper after signing
    tampered = Token(json.dumps(chain))
    with pytest.raises(InvalidTokenError):
        await auth.verify(tampered)


async def test_malformed_token_is_rejected() -> None:
    auth = ChainedCapabilityAuth(secret=b"s")
    with pytest.raises(InvalidTokenError):
        await auth.verify(Token("not-json"))
    with pytest.raises(InvalidTokenError):
        await auth.verify(Token("[]"))


# ---------------------------------------------------------------------------
# Property-based: cascading revocation holds for arbitrary chain depth
# ---------------------------------------------------------------------------


@given(depth=st.integers(min_value=1, max_value=6))
async def test_revoking_root_invalidates_chain_of_any_depth(depth: int) -> None:
    auth = ChainedCapabilityAuth(secret=b"s", clock=0.0)
    root = await auth.issue(ROOT, ["read"])
    leaf = root
    last_agent = ROOT
    for i in range(depth):
        last_agent = AgentId(f"agent-{i}")
        leaf = await auth.delegate(leaf, last_agent, ["read"], ttl=1000)

    await auth.verify(leaf, expected_audience=last_agent)  # sanity: valid before revocation

    await auth.revoke(root)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(leaf, expected_audience=last_agent)
