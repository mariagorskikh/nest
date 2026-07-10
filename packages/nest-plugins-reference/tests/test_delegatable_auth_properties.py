# SPDX-License-Identifier: Apache-2.0
"""Property tests for the delegatable auth plugin.

Two invariants under random delegation chains: (1) *monotone
attenuation* — a verified leaf never holds a scope its root lacked and
never outlives any ancestor; (2) *cascading revocation* — revoking a
random ancestor always invalidates every descendant minted under it.
Token bytes are also deterministic for a fixed clock and secret.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    DelegatableAuth,
    RevokedAncestorError,
)

_SCOPES = st.sets(st.sampled_from(["read", "write", "pay", "admin"]), min_size=1)


def _run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


async def _build_chain(
    auth: DelegatableAuth,
    root_scopes: set[str],
    subset_picks: list[int],
) -> tuple[list[Token], list[set[str]]]:
    effective_root = set(root_scopes) | {"delegate"}
    tokens: list[Token] = [await auth.issue(AgentId("agent-0"), sorted(effective_root))]
    scope_sets: list[set[str]] = [effective_root]
    for depth, pick in enumerate(subset_picks, start=1):
        parent = sorted(scope_sets[-1])
        non_delegate = [s for s in parent if s != "delegate"]
        is_leaf = depth == len(subset_picks)
        if "delegate" not in parent:
            break
        if is_leaf:
            if not non_delegate:
                child_scopes = set()
            else:
                keep = max(1, (pick % len(non_delegate)))
                child_scopes = set(non_delegate[:keep])
        else:
            keep = pick % len(non_delegate) if non_delegate else 0
            child_scopes = set(non_delegate[:keep]) | {"delegate"}
        if not child_scopes or child_scopes == set(parent):
            child_scopes = {non_delegate[0]} if non_delegate else set()
        if not child_scopes:
            break
        token = await auth.delegate(
            tokens[-1],
            AgentId(f"agent-{depth}"),
            sorted(child_scopes),
            ttl=100.0,
        )
        tokens.append(token)
        scope_sets.append(child_scopes)
    return tokens, scope_sets


@settings(max_examples=50, deadline=None)
@given(root_scopes=_SCOPES, picks=st.lists(st.integers(min_value=1), min_size=1, max_size=6))
def test_leaf_scopes_never_exceed_root(root_scopes: set[str], picks: list[int]) -> None:
    async def scenario() -> None:
        auth = DelegatableAuth(secret=b"prop", clock=0.0)
        tokens, _ = await _build_chain(auth, root_scopes, picks)
        leaf_id = AgentId(f"agent-{len(tokens) - 1}")
        ctx = await auth.verify(tokens[-1], presenter=leaf_id)
        assert set(ctx.scopes).issubset(root_scopes | {"delegate"})
        root_ctx = await auth.verify(tokens[0])
        assert root_ctx.expires_at is not None and ctx.expires_at is not None
        assert ctx.expires_at <= root_ctx.expires_at

    _run(scenario())


@settings(max_examples=50, deadline=None)
@given(
    root_scopes=_SCOPES,
    picks=st.lists(st.integers(min_value=1), min_size=1, max_size=6),
    revoke_at=st.integers(min_value=0),
)
def test_revoking_any_ancestor_invalidates_leaf(
    root_scopes: set[str],
    picks: list[int],
    revoke_at: int,
) -> None:
    async def scenario() -> None:
        auth = DelegatableAuth(secret=b"prop", clock=0.0)
        tokens, _ = await _build_chain(auth, root_scopes, picks)
        target = revoke_at % (len(tokens) - 1)  # any strict ancestor of the leaf
        await auth.revoke(tokens[target])
        leaf_id = AgentId(f"agent-{len(tokens) - 1}")
        try:
            await auth.verify(tokens[-1], presenter=leaf_id)
        except RevokedAncestorError:
            return
        raise AssertionError("leaf verified despite revoked ancestor")

    _run(scenario())


@settings(max_examples=25, deadline=None)
@given(root_scopes=_SCOPES)
def test_token_bytes_deterministic(root_scopes: set[str]) -> None:
    async def scenario() -> None:
        first = DelegatableAuth(secret=b"prop", clock=42.0)
        second = DelegatableAuth(secret=b"prop", clock=42.0)
        token_a = await first.issue(AgentId("a1"), sorted(root_scopes))
        token_b = await second.issue(AgentId("a1"), sorted(root_scopes))
        assert str(token_a) == str(token_b)

    _run(scenario())
