# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Hypothesis property-based tests for the ``delegatable`` auth plugin.

Each invariant is checked over generated scope sets, delegation depths, TTLs,
and revocation points so the macaroon guarantees hold for *all* inputs, not
just the hand-picked cases in ``test_delegatable_auth.py``:

1. Scope monotonicity: a verified leaf's scopes are always a subset of the root's.
2. Forged widening is always rejected at verify, at any depth.
3. Cascading revocation: revoking link ``k`` fails every token at depth ``>= k``
   and spares every token at depth ``< k``.
4. Determinism: identical delegation chains yield byte-identical tokens.
5. TTL never extends: each child's expiry is ``<=`` its parent's.

Delegation only ever narrows, so the strategies build a descending chain of
scope subsets and non-increasing TTLs and assert the plugin honours them.

Example::

    pytest packages/nest-plugins-reference/tests/test_delegatable_auth_properties.py
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    DelegatableAuth,
    RevokedAncestorError,
    ScopeEscalationError,
)

_ALL_SCOPES = ["read", "write", "exec", "admin", "list"]

# A descending chain of scope subsets: each element is a subset of the prior.
_scope_chains = st.lists(
    st.sets(st.sampled_from(_ALL_SCOPES), min_size=1), min_size=1, max_size=4
).map(lambda subsets: [set(_ALL_SCOPES)] + subsets)


def _descending(scopes: list[set[str]]) -> list[list[str]]:
    """Coerce a list of scope sets into a strictly-narrowing chain (root first)."""
    chain: list[list[str]] = [sorted(scopes[0])]
    current = set(scopes[0])
    for nxt in scopes[1:]:
        current = current & nxt  # intersection is always a subset
        chain.append(sorted(current))
    return chain


async def _build_chain(auth: DelegatableAuth, scope_levels: list[list[str]]) -> list[Token]:
    """Issue a root and delegate down through ``scope_levels`` (root first)."""
    tokens = [await auth.issue(AgentId("agent-0"), scope_levels[0])]
    for depth, scopes in enumerate(scope_levels[1:], start=1):
        tokens.append(
            await auth.delegate(tokens[-1], AgentId(f"agent-{depth}"), scopes, ttl=1000.0 - depth)
        )
    return tokens


@settings(max_examples=100, deadline=None)
@given(scope_levels=_scope_chains)
async def test_leaf_scopes_subset_of_root(scope_levels: list[set[str]]) -> None:
    """Property 1: every verified leaf's scopes ⊆ the root's scopes."""
    levels = _descending(scope_levels)
    auth = DelegatableAuth(secret=b"k", clock=0.0)
    tokens = await _build_chain(auth, levels)
    leaf_ctx = await auth.verify(tokens[-1])
    root_scopes = set(levels[0])
    assert set(leaf_ctx.scopes).issubset(root_scopes)


@settings(max_examples=100, deadline=None)
@given(scope_levels=_scope_chains)
async def test_ttl_never_extends(scope_levels: list[set[str]]) -> None:
    """Property 5: each child's expiry never exceeds its parent's."""
    levels = _descending(scope_levels)
    auth = DelegatableAuth(secret=b"k", clock=0.0)
    tokens = await _build_chain(auth, levels)
    exps = [(await auth.verify(t)).expires_at for t in tokens]
    for parent_exp, child_exp in zip(exps, exps[1:], strict=False):
        assert child_exp is not None and parent_exp is not None
        assert child_exp <= parent_exp


@settings(max_examples=100, deadline=None)
@given(scope_levels=_scope_chains, extra=st.sampled_from(_ALL_SCOPES))
async def test_forged_widening_rejected(scope_levels: list[set[str]], extra: str) -> None:
    """Property 2: a MAC-valid caveat that adds a scope the parent lacks fails."""
    levels = _descending(scope_levels)
    auth = DelegatableAuth(secret=b"k", clock=0.0)
    tokens = await _build_chain(auth, levels)
    parent = tokens[-1]
    parent_scopes = set(levels[-1])
    if extra in parent_scopes:
        return  # not a widening; nothing to prove
    chain, _ = auth._decode(parent)
    forged = {
        "tid": "forged0000000000",
        "parent_tid": chain[-1]["tid"],
        "sub": "evil",
        "aud": "evil",
        "scopes": sorted(parent_scopes | {extra}),
        "iat": 0.0,
        "exp": 10.0,
    }
    forged_token = auth._encode([*chain, forged])  # recomputes a valid MAC
    try:
        await auth.verify(forged_token)
        raise AssertionError("forged widening was accepted")
    except ScopeEscalationError:
        pass


@settings(max_examples=100, deadline=None)
@given(scope_levels=_scope_chains, revoke_at=st.integers(min_value=0, max_value=4))
async def test_cascading_revocation(scope_levels: list[set[str]], revoke_at: int) -> None:
    """Property 3: revoking depth k fails depths >= k, spares depths < k."""
    levels = _descending(scope_levels)
    auth = DelegatableAuth(secret=b"k", clock=0.0)
    tokens = await _build_chain(auth, levels)
    k = min(revoke_at, len(tokens) - 1)

    await auth.revoke(tokens[k])

    for depth, token in enumerate(tokens):
        if depth < k:
            assert (await auth.verify(token)).subject == AgentId(f"agent-{depth}")
        else:
            try:
                await auth.verify(token)
                raise AssertionError(f"depth {depth} verified after revoking {k}")
            except RevokedAncestorError:
                pass


@settings(max_examples=50, deadline=None)
@given(scope_levels=_scope_chains)
async def test_determinism(scope_levels: list[set[str]]) -> None:
    """Property 4: identical chains produce byte-identical tokens."""
    levels = _descending(scope_levels)
    a = DelegatableAuth(secret=b"k", clock=0.0)
    b = DelegatableAuth(secret=b"k", clock=0.0)
    ta = await _build_chain(a, levels)
    tb = await _build_chain(b, levels)
    assert [str(t) for t in ta] == [str(t) for t in tb]
