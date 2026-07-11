# SPDX-License-Identifier: Apache-2.0
"""Property tests for the mesh-revocable auth plugin.

Two families of invariants: (1) the replication channel is a genuine
semilattice join at the plugin surface -- merge is commutative,
associative, and idempotent over exported bytes for arbitrary
revocation sets; (2) *eventual fatality* -- after one revocation and
any Hypothesis-drawn sequence of pairwise gossips that ends with a full
round-robin pass, every replica denies the revoked lineage.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import RevokedAncestorError
from nest_plugins_reference.auth.mesh_revocable import CRDT_KIND, MeshRevocableAuth

_TIDS = st.sets(st.text(alphabet="0123456789abcdef", min_size=1, max_size=8), max_size=8)


def _run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


def _state(tids: set[str]) -> bytes:
    return json.dumps({"crdt": CRDT_KIND, "revoked": sorted(tids)}).encode()


def _loaded(tids: set[str]) -> MeshRevocableAuth:
    auth = MeshRevocableAuth(secret=b"s", clock=0.0)
    if tids:
        auth.merge_revocations(_state(tids))
    return auth


@given(a=_TIDS, b=_TIDS)
@settings(max_examples=50)
def test_merge_commutative(a: set[str], b: set[str]) -> None:
    left = _loaded(a)
    left.merge_revocations(_state(b))
    right = _loaded(b)
    right.merge_revocations(_state(a))
    assert left.export_revocations() == right.export_revocations()


@given(a=_TIDS, b=_TIDS, c=_TIDS)
@settings(max_examples=50)
def test_merge_associative(a: set[str], b: set[str], c: set[str]) -> None:
    ab_then_c = _loaded(a)
    ab_then_c.merge_revocations(_state(b))
    ab_then_c.merge_revocations(_state(c))

    bc = _loaded(b)
    bc.merge_revocations(_state(c))
    a_then_bc = _loaded(a)
    a_then_bc.merge_revocations(bc.export_revocations())

    assert ab_then_c.export_revocations() == a_then_bc.export_revocations()


@given(a=_TIDS)
@settings(max_examples=50)
def test_merge_idempotent(a: set[str]) -> None:
    auth = _loaded(a)
    once = auth.export_revocations()
    assert auth.merge_revocations(once) is False
    assert auth.export_revocations() == once


@given(
    gossip_pairs=st.lists(
        st.tuples(st.integers(min_value=0, max_value=3), st.integers(min_value=0, max_value=3)),
        max_size=12,
    )
)
@settings(max_examples=30, deadline=None)
def test_revocation_eventually_fatal_under_any_gossip_order(
    gossip_pairs: list[tuple[int, int]],
) -> None:
    async def scenario() -> None:
        replicas = [MeshRevocableAuth(secret=b"s", clock=0.0) for _ in range(4)]
        issuer = replicas[0]
        root = await issuer.issue(AgentId("coordinator"), ["read", "write"])
        child = await issuer.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
        await issuer.revoke(root)

        # Arbitrary partial gossip drawn by Hypothesis...
        for src, dst in gossip_pairs:
            if src != dst:
                replicas[dst].merge_revocations(replicas[src].export_revocations())
        # ...then one full round-robin pass (a heal): 0->1->2->3 then 3->0.
        for i in range(3):
            replicas[i + 1].merge_revocations(replicas[i].export_revocations())
        replicas[0].merge_revocations(replicas[3].export_revocations())

        for replica in replicas:
            with pytest.raises(RevokedAncestorError):
                await replica.verify(child)

    _run(scenario())
