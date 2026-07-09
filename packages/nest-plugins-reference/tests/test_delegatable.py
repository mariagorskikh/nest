# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the delegatable (macaroon-style) auth plugin.

Cover the core contract: attenuating delegation, cascading revocation, audience
binding, expiry, tamper resistance, caveats, and byte-determinism.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    CaveatUnsatisfiedError,
    DelegatableAuth,
    ExpiredTokenError,
    InvalidTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlExpansionError,
)

_SECRET = b"unit-test-secret"


def _auth(clock: float = 100.0, **kwargs: object) -> DelegatableAuth:
    return DelegatableAuth(secret=_SECRET, clock=clock, **kwargs)  # type: ignore[arg-type]


async def test_issue_and_verify_root() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("coordinator"), ["read", "write", "exec"])
    ctx = await auth.verify(root)
    assert ctx.subject == AgentId("coordinator")
    assert set(ctx.scopes) == {"read", "write", "exec"}


async def test_delegate_narrows_scopes_and_binds_audience() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write", "exec"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600)
    ctx = await auth.verify(child, presenter=AgentId("b"))
    assert ctx.subject == AgentId("b")
    assert ctx.scopes == ["read"]


async def test_delegate_scope_escalation_raises() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=60)


async def test_delegate_ttl_expansion_raises() -> None:
    auth = _auth()
    # Root expiry is clock + default_ttl; a child asking for more must fail.
    root = await auth.issue(AgentId("a"), ["read"])
    with pytest.raises(TtlExpansionError):
        await auth.delegate(root, AgentId("b"), ["read"], ttl=10_000_000)


async def test_cascading_revocation_three_deep() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600)
    grand = await auth.delegate(child, AgentId("c"), ["read"], ttl=300)
    # All verify before revocation.
    await auth.verify(grand, presenter=AgentId("c"))
    await auth.revoke(root)
    for token, holder in ((root, "a"), (child, "b"), (grand, "c")):
        with pytest.raises(RevokedAncestorError):
            await auth.verify(token, presenter=AgentId(holder))


async def test_revoke_middle_spares_root_and_siblings() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write"])
    branch = await auth.delegate(root, AgentId("b"), ["read"], ttl=600)
    sibling = await auth.delegate(root, AgentId("s"), ["read"], ttl=600)
    leaf = await auth.delegate(branch, AgentId("b1"), ["read"], ttl=300)
    await auth.revoke(branch)
    # Revoked branch and its descendant fail.
    with pytest.raises(RevokedAncestorError):
        await auth.verify(branch, presenter=AgentId("b"))
    with pytest.raises(RevokedAncestorError):
        await auth.verify(leaf, presenter=AgentId("b1"))
    # Root and unrelated sibling are untouched.
    assert (await auth.verify(root)).subject == AgentId("a")
    assert (await auth.verify(sibling, presenter=AgentId("s"))).subject == AgentId("s")


async def test_audience_mismatch_raises() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600)
    with pytest.raises(AudienceMismatchError):
        await auth.verify(child, presenter=AgentId("attacker"))
    # No presenter given -> audience is not checked.
    assert (await auth.verify(child)).subject == AgentId("b")


async def test_expiry_raises_under_advanced_clock() -> None:
    shared_revoked: set[str] = set()
    past = DelegatableAuth(secret=_SECRET, clock=100.0, revoked=shared_revoked)
    root = await past.issue(AgentId("a"), ["read"])
    child = await past.delegate(root, AgentId("b"), ["read"], ttl=10)  # exp = 110
    # A verifier whose clock is past the expiry rejects the token.
    future = DelegatableAuth(secret=_SECRET, clock=200.0, revoked=shared_revoked)
    with pytest.raises(ExpiredTokenError):
        await future.verify(child, presenter=AgentId("b"))


async def test_delegate_from_expired_parent_raises() -> None:
    past = DelegatableAuth(secret=_SECRET, clock=100.0, default_ttl=10.0)
    root = await past.issue(AgentId("a"), ["read"])  # exp = 110
    future = DelegatableAuth(secret=_SECRET, clock=200.0)
    with pytest.raises(ExpiredTokenError):
        await future.delegate(root, AgentId("b"), ["read"], ttl=1)


async def test_delegate_from_revoked_parent_raises() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.delegate(root, AgentId("b"), ["read"], ttl=60)


async def test_tampered_token_fails_signature() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    tampered = Token(str(root).replace('"read"', '"admin"'))
    assert tampered != root
    with pytest.raises(InvalidTokenError):
        await auth.verify(tampered)


async def test_malformed_token_raises() -> None:
    auth = _auth()
    for bad in ("not json", "{}", '{"links": [], "sig": "x"}'):
        with pytest.raises(InvalidTokenError):
            await auth.verify(Token(bad))


async def test_determinism_same_inputs_same_bytes() -> None:
    a = await _auth().issue(AgentId("x"), ["read", "write"])
    b = await _auth().issue(AgentId("x"), ["read", "write"])
    assert a == b
    child_a = await _auth().delegate(a, AgentId("y"), ["read"], ttl=60)
    child_b = await _auth().delegate(b, AgentId("y"), ["read"], ttl=60)
    assert child_a == child_b


async def test_caveat_context_enforced() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60, caveats=["resource=jobs"])
    # Satisfied when context matches.
    assert (await auth.verify(child, context={"resource": "jobs"})).subject == AgentId("b")
    # Fails closed when context is missing or mismatched.
    with pytest.raises(CaveatUnsatisfiedError):
        await auth.verify(child, context={"resource": "secrets"})
    with pytest.raises(CaveatUnsatisfiedError):
        await auth.verify(child)


async def test_max_depth_caveat_bounds_chain_length() -> None:
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    # Caveat added at depth 2 permits at most a 2-link chain.
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600, caveats=["max_depth=2"])
    assert (await auth.verify(child, presenter=AgentId("b"))).subject == AgentId("b")
    # Delegating once more makes the chain length 3 -> the caveat now fails.
    grand = await auth.delegate(child, AgentId("c"), ["read"], ttl=300)
    with pytest.raises(CaveatUnsatisfiedError):
        await auth.verify(grand, presenter=AgentId("c"))


async def test_verify_rejects_hand_forged_scope_widening() -> None:
    """A token whose leaf widens scope (bypassing delegate) fails verify."""
    import json

    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60)
    data = json.loads(str(child))
    data["links"][-1]["scopes"] = ["read", "admin"]  # widen without re-signing
    from nest_core.types import Token

    forged = Token(json.dumps(data, sort_keys=True))
    # The chain signature no longer matches the mutated link.
    with pytest.raises(InvalidTokenError):
        await auth.verify(forged)
