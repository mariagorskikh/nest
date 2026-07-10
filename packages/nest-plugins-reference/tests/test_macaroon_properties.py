# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the macaroon auth plugin (Hypothesis).

Invariants asserted across randomly generated delegation chains and scope
sets:

1. **Attenuation only narrows.** Any verifiable token in a chain has scopes
   that are a subset of the root's scopes, at every depth.
2. **Cascading revocation is monotone.** Revoking any ancestor invalidates
   every descendant, and never resurrects a previously valid sibling.
3. **Determinism.** Building the same chain twice yields byte-identical
   tokens (no wall-clock, no unseeded RNG).
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId
from nest_plugins_reference.auth.macaroon import (
    MacaroonAuth,
    RevokedAncestorError,
    ScopeEscalationError,
)

_SCOPES = ["read", "write", "invoke", "admin", "billing"]


def _run[T](coro: Coroutine[Any, Any, T]) -> T:
    # A fresh loop per call: Hypothesis re-invokes the test body many times and
    # pytest-asyncio (auto mode) manages the ambient loop, so a shared
    # get_event_loop() would leak a closed loop across examples. asyncio.run
    # creates and disposes an isolated loop for each scenario.
    return asyncio.run(coro)


@settings(max_examples=100, deadline=None)
@given(
    root_scopes=st.lists(st.sampled_from(_SCOPES), min_size=1, max_size=5, unique=True),
    depth=st.integers(min_value=1, max_value=5),
    data=st.data(),
)
def test_subset_invariant_holds_down_the_chain(
    root_scopes: list[str], depth: int, data: st.DataObject
) -> None:
    """Every verifiable link's scopes are a subset of its parent's."""

    async def scenario() -> None:
        auth = MacaroonAuth(secret=b"prop", clock=0.0)
        token = await auth.issue(AgentId("root"), root_scopes)
        current = set(root_scopes)
        for i in range(depth):
            subset = data.draw(
                st.lists(
                    st.sampled_from(sorted(current)),
                    min_size=1,
                    max_size=len(current),
                    unique=True,
                )
            )
            token = await auth.delegate(token, AgentId(f"a{i}"), subset, ttl=100.0)
            ctx = await auth.verify(token, presenter=AgentId(f"a{i}"))
            assert set(ctx.scopes) <= current
            current = set(subset)

    _run(scenario())


@settings(max_examples=100, deadline=None)
@given(
    scopes=st.lists(st.sampled_from(_SCOPES), min_size=1, max_size=4, unique=True),
    revoke_at=st.integers(min_value=0, max_value=3),
)
def test_revocation_cascades_monotonically(scopes: list[str], revoke_at: int) -> None:
    """Revoking link *k* invalidates every link at depth >= k, none below."""

    async def scenario() -> None:
        auth = MacaroonAuth(secret=b"prop", clock=0.0)
        tokens = [await auth.issue(AgentId("root"), scopes)]
        for i in range(3):
            tokens.append(await auth.delegate(tokens[-1], AgentId(f"a{i}"), scopes, ttl=100.0))
        k = min(revoke_at, len(tokens) - 1)
        await auth.revoke(tokens[k])
        # depths < k stay valid; depths >= k are revoked
        for depth, tok in enumerate(tokens):
            presenter = AgentId("root") if depth == 0 else AgentId(f"a{depth - 1}")
            if depth < k:
                await auth.verify(tok, presenter=presenter)  # must not raise
            else:
                try:
                    await auth.verify(tok, presenter=presenter)
                    raise AssertionError(f"depth {depth} verified after revoking {k}")
                except RevokedAncestorError:
                    pass

    _run(scenario())


@settings(max_examples=50, deadline=None)
@given(scopes=st.lists(st.sampled_from(_SCOPES), min_size=1, max_size=5, unique=True))
def test_token_construction_is_deterministic(scopes: list[str]) -> None:
    """Same inputs → byte-identical tokens (Tier-1 determinism requirement)."""

    async def scenario() -> None:
        a1 = MacaroonAuth(secret=b"det", clock=0.0)
        a2 = MacaroonAuth(secret=b"det", clock=0.0)
        r1 = await a1.issue(AgentId("root"), scopes)
        r2 = await a2.issue(AgentId("root"), scopes)
        assert str(r1) == str(r2)
        c1 = await a1.delegate(r1, AgentId("b"), scopes, ttl=50.0)
        c2 = await a2.delegate(r2, AgentId("b"), scopes, ttl=50.0)
        assert str(c1) == str(c2)

    _run(scenario())


@settings(max_examples=50, deadline=None)
@given(
    root_scopes=st.lists(st.sampled_from(_SCOPES), min_size=1, max_size=3, unique=True),
    extra=st.sampled_from(_SCOPES),
)
def test_escalation_always_rejected(root_scopes: list[str], extra: str) -> None:
    """Delegating a scope outside the parent's set always raises."""

    async def scenario() -> None:
        if extra in root_scopes:
            return
        auth = MacaroonAuth(secret=b"prop", clock=0.0)
        root = await auth.issue(AgentId("root"), root_scopes)
        try:
            await auth.delegate(root, AgentId("b"), [*root_scopes, extra], ttl=50.0)
            raise AssertionError("escalation was not rejected")
        except ScopeEscalationError:
            pass

    _run(scenario())
