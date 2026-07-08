# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the delegatable auth plugin.

Three invariants under Hypothesis:

1. **Scope subset invariant** — any subset of parent scopes succeeds in
   ``delegate()``, any strict superset raises ``ScopeEscalationError``.
2. **HMAC round-trip** — every token issued by ``issue()`` or ``delegate()``
   can be verified and returns the same scopes.
3. **Revocation cascade** — revoking any ancestor in a chain makes every
   descendant unverifiable.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    DelegatableAuth,
    RevokedAncestorError,
    ScopeEscalationError,
)

# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

_scope_name = st.text(
    alphabet=st.characters(whitelist_categories=("Ll",), whitelist_characters="_"),
    min_size=1,
    max_size=8,
)
_scope_list = st.lists(_scope_name, min_size=0, max_size=6, unique=True)


def _run(coro: object) -> None:
    """Run a coroutine in a fresh event loop, closing it afterwards."""
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(coro)  # type: ignore[arg-type]
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# 1. Scope subset invariant
# ---------------------------------------------------------------------------


@given(
    parent_scopes=_scope_list,
    child_scopes=_scope_list,
)
@settings(max_examples=200)
def test_scope_subset_invariant(parent_scopes: list[str], child_scopes: list[str]) -> None:
    """Delegating a subset always succeeds; a superset always raises."""

    async def _inner() -> None:
        auth = DelegatableAuth(secret=b"prop-secret", clock=1000.0)
        root = await auth.issue(AgentId("coord"), parent_scopes, ttl=3600.0)
        parent_set = set(parent_scopes)
        child_set = set(child_scopes)

        if child_set <= parent_set:
            child = await auth.delegate(root, AgentId("worker"), child_scopes, ttl=60.0)
            ctx = await auth.verify(child, caller=AgentId("worker"))
            assert set(ctx.scopes) == child_set
        else:
            with pytest.raises(ScopeEscalationError):
                await auth.delegate(root, AgentId("worker"), child_scopes, ttl=60.0)

    _run(_inner())


# ---------------------------------------------------------------------------
# 2. HMAC round-trip invariant
# ---------------------------------------------------------------------------


@given(
    scopes=_scope_list,
    secret=st.binary(min_size=1, max_size=64),
)
@settings(max_examples=200)
def test_hmac_round_trip(scopes: list[str], secret: bytes) -> None:
    """Every issued token verifies correctly and returns identical scopes."""

    async def _inner() -> None:
        auth = DelegatableAuth(secret=secret, clock=1000.0)
        root = await auth.issue(AgentId("a"), scopes, ttl=3600.0)
        ctx = await auth.verify(root)
        assert set(ctx.scopes) == set(scopes)
        assert ctx.subject == AgentId("a")

    _run(_inner())


@given(
    parent_scopes=st.lists(_scope_name, min_size=1, max_size=6, unique=True),
    child_scopes_draw=st.data(),
)
@settings(max_examples=150)
def test_delegation_round_trip(parent_scopes: list[str], child_scopes_draw: st.DataObject) -> None:
    """Every delegated token verifies correctly and returns correct scopes."""
    child_scopes = child_scopes_draw.draw(
        st.lists(
            st.sampled_from(parent_scopes),
            min_size=0,
            max_size=len(parent_scopes),
            unique=True,
        )
    )

    async def _inner() -> None:
        auth = DelegatableAuth(secret=b"rt-secret", clock=1000.0)
        root = await auth.issue(AgentId("coord"), parent_scopes, ttl=3600.0)
        child = await auth.delegate(root, AgentId("worker"), child_scopes, ttl=600.0)
        ctx = await auth.verify(child, caller=AgentId("worker"))
        assert set(ctx.scopes) == set(child_scopes)

    _run(_inner())


# ---------------------------------------------------------------------------
# 3. Revocation cascade invariant
# ---------------------------------------------------------------------------


@given(chain_depth=st.integers(min_value=1, max_value=4))
@settings(max_examples=100)
def test_revocation_cascade(chain_depth: int) -> None:
    """Revoking any node in a chain invalidates all its descendants."""

    async def _inner() -> None:
        auth = DelegatableAuth(secret=b"rev-secret", clock=1000.0)
        scopes = ["read", "write", "exec"]
        tokens: list[Token] = []

        root = await auth.issue(AgentId("root"), scopes, ttl=3600.0)
        tokens.append(root)

        for i in range(chain_depth):
            prev = tokens[-1]
            tokens.append(await auth.delegate(prev, AgentId(f"a{i}"), ["read"], ttl=3600.0))

        await auth.revoke(tokens[0])
        for t in tokens:
            with pytest.raises(RevokedAncestorError):
                await auth.verify(t)

    _run(_inner())


@given(
    left_depth=st.integers(min_value=0, max_value=3),
    right_depth=st.integers(min_value=0, max_value=3),
)
@settings(max_examples=80)
def test_revoke_one_branch_leaves_sibling_intact(left_depth: int, right_depth: int) -> None:
    """Revoking one branch must not affect a sibling branch."""

    async def _inner() -> None:
        auth = DelegatableAuth(secret=b"branch-secret", clock=1000.0)
        root = await auth.issue(AgentId("root"), ["read", "write"], ttl=3600.0)

        left: list[Token] = [root]
        for i in range(left_depth):
            left.append(await auth.delegate(left[-1], AgentId(f"L{i}"), ["read"], ttl=3600.0))

        right: list[Token] = [root]
        for i in range(right_depth):
            right.append(await auth.delegate(right[-1], AgentId(f"R{i}"), ["read"], ttl=3600.0))

        await auth.revoke(left[-1])

        if left_depth == 0:
            # left[-1] is root → root revoked, right branch also fails
            with pytest.raises(RevokedAncestorError):
                await auth.verify(root)
        else:
            ctx = await auth.verify(root)
            assert "read" in ctx.scopes
            caller = AgentId(f"R{right_depth - 1}") if right_depth > 0 else None
            ctx2 = await auth.verify(right[-1], caller=caller)
            assert "read" in ctx2.scopes

    _run(_inner())
