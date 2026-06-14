# SPDX-License-Identifier: Apache-2.0
"""Conformance tests for the gossip registry plugin.

These tests exercise the partition-honest, eventually-consistent properties:

* per-agent local view (no shared dict)
* monotonic LWW conflict resolution via ``(version, publisher_id)``
* tombstone propagation through gossip
* deterministic replay under a seeded RNG
* convergence of N agents within ``K`` rounds via full mesh push-pull
* bridge-mediated convergence when peers are split into partition groups
* property-based merge associativity / commutativity (Hypothesis)

The plugin's own ``gossip_round`` and ``handle_gossip`` need an
``AgentContext``; we stub one with a deterministic queue rather than
spin the full simulator up for unit tests.
"""

from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.registry.gossip import (
    DEFAULT_FANOUT,
    GOSSIP_PREFIX,
    GossipNetwork,
    GossipRegistry,
)

# ---------------------------------------------------------------------------
# Fixtures / fake context
# ---------------------------------------------------------------------------


@dataclass
class _FakeNetwork:
    """In-process router that funnels gossip into the right recipient registry."""

    registries: dict[AgentId, GossipRegistry]
    drop: Callable[[AgentId, AgentId], bool] = field(default=lambda _s, _t: False)
    inbox: dict[AgentId, list[tuple[AgentId, bytes]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    async def deliver(self, sender: AgentId, target: AgentId, payload: bytes) -> None:
        if self.drop(sender, target):
            return
        self.inbox[target].append((sender, payload))


@dataclass
class _FakeContext:
    agent_id: AgentId
    rng: random.Random
    net: _FakeNetwork
    plugins: dict[str, Any] = field(default_factory=dict[str, Any])
    time: float = 0.0

    async def send(self, to: AgentId, payload: bytes) -> None:
        await self.net.deliver(self.agent_id, to, payload)

    async def broadcast(self, payload: bytes) -> None:
        for aid in self.net.registries:
            if aid != self.agent_id:
                await self.net.deliver(self.agent_id, aid, payload)

    async def schedule(self, delay: float, payload: bytes) -> None:
        pass


def _make_card(aid: str, name: str | None = None, caps: list[str] | None = None) -> AgentCard:
    return AgentCard(
        agent_id=AgentId(aid),
        name=name or aid,
        capabilities=caps or [],
    )


def _build(
    n: int,
    *,
    seed: int = 42,
    drop: Callable[[AgentId, AgentId], bool] | None = None,
) -> tuple[
    GossipNetwork,
    dict[AgentId, GossipRegistry],
    dict[AgentId, _FakeContext],
    _FakeNetwork,
]:
    ids = [AgentId(f"a-{i}") for i in range(n)]
    gnet = GossipNetwork(agent_ids=ids)
    regs = {aid: GossipRegistry(aid, gnet) for aid in ids}
    fake_net = _FakeNetwork(registries=regs, drop=drop or (lambda _s, _t: False))
    ctxs = {
        aid: _FakeContext(agent_id=aid, rng=random.Random(seed + i), net=fake_net)
        for i, aid in enumerate(ids)
    }
    return gnet, regs, ctxs, fake_net


async def _drain(
    regs: dict[AgentId, GossipRegistry],
    ctxs: dict[AgentId, _FakeContext],
    fake_net: _FakeNetwork,
) -> None:
    """Deliver every queued gossip message and recurse until the inboxes are empty."""
    while any(fake_net.inbox.values()):
        snapshot = {aid: list(msgs) for aid, msgs in fake_net.inbox.items() if msgs}
        fake_net.inbox.clear()
        for aid, msgs in snapshot.items():
            reg = regs[aid]
            ctx = ctxs[aid]
            for sender, payload in msgs:
                await reg.handle_gossip(sender, payload, ctx)  # type: ignore[arg-type]


async def _round(
    regs: dict[AgentId, GossipRegistry],
    ctxs: dict[AgentId, _FakeContext],
    fake_net: _FakeNetwork,
) -> None:
    for aid, reg in regs.items():
        await reg.gossip_round(ctxs[aid])  # type: ignore[arg-type]
    await _drain(regs, ctxs, fake_net)


def _converged(regs: dict[AgentId, GossipRegistry]) -> bool:
    snapshots = [reg.view_snapshot() for reg in regs.values()]
    return all(s == snapshots[0] for s in snapshots)


# ---------------------------------------------------------------------------
# Single-agent semantics
# ---------------------------------------------------------------------------


def test_register_and_lookup_local_only() -> None:
    """Register one card and look it up — no gossip needed, single-agent path."""
    _, regs, _, _ = _build(1)
    reg = regs[AgentId("a-0")]
    asyncio.run(reg.register(_make_card("a-0", caps=["sell"])))
    results = asyncio.run(reg.lookup(Query()))
    assert len(results) == 1
    assert results[0].agent_id == AgentId("a-0")


def test_lookup_filters_by_capability() -> None:
    _, regs, _, _ = _build(1)
    reg = regs[AgentId("a-0")]
    asyncio.run(reg.register(_make_card("a-0", caps=["sell"])))
    asyncio.run(reg.register(_make_card("b-0", caps=["buy"])))
    assert len(asyncio.run(reg.lookup(Query(capabilities=["sell"])))) == 1
    assert len(asyncio.run(reg.lookup(Query(capabilities=["unknown"])))) == 0


def test_deregister_tombstones_locally() -> None:
    _, regs, _, _ = _build(1)
    reg = regs[AgentId("a-0")]
    asyncio.run(reg.register(_make_card("a-0")))
    assert len(asyncio.run(reg.lookup(Query()))) == 1
    asyncio.run(reg.deregister(AgentId("a-0")))
    assert len(asyncio.run(reg.lookup(Query()))) == 0


# ---------------------------------------------------------------------------
# Two-agent gossip
# ---------------------------------------------------------------------------


def test_gossip_propagates_registration_between_two() -> None:
    """A registers; one round of gossip; B sees A's card."""
    _, regs, ctxs, fake_net = _build(2)
    a, b = AgentId("a-0"), AgentId("a-1")
    asyncio.run(regs[a].register(_make_card("a-0", caps=["sell"])))
    asyncio.run(_round(regs, ctxs, fake_net))
    assert AgentId("a-0") in regs[b].view_snapshot()


def test_handle_gossip_returns_false_for_non_gossip_payload() -> None:
    _, regs, ctxs, _ = _build(1)
    reg = regs[AgentId("a-0")]
    result = asyncio.run(reg.handle_gossip(AgentId("a-0"), b"hello", ctxs[AgentId("a-0")]))  # type: ignore[arg-type]
    assert result is False


def test_handle_gossip_returns_true_for_prefixed_payload() -> None:
    _, regs, ctxs, _ = _build(1)
    reg = regs[AgentId("a-0")]
    result = asyncio.run(reg.handle_gossip(AgentId("a-0"), GOSSIP_PREFIX, ctxs[AgentId("a-0")]))  # type: ignore[arg-type]
    assert result is True


# ---------------------------------------------------------------------------
# Conflict resolution
# ---------------------------------------------------------------------------


def test_lww_higher_version_wins() -> None:
    """Two registers of the same agent — higher version wins, lower is dropped."""
    _, regs, ctxs, fake_net = _build(2)
    a, b = AgentId("a-0"), AgentId("a-1")
    asyncio.run(regs[a].register(_make_card("a-0", name="v1")))
    asyncio.run(regs[a].register(_make_card("a-0", name="v2")))
    asyncio.run(_round(regs, ctxs, fake_net))
    seen = asyncio.run(regs[b].lookup(Query()))
    assert len(seen) == 1
    assert seen[0].name == "v2"


def test_tombstone_propagates_via_gossip() -> None:
    """A registers, gossips, deregisters, gossips again → B's view tombstones it."""
    _, regs, ctxs, fake_net = _build(2)
    a, b = AgentId("a-0"), AgentId("a-1")
    asyncio.run(regs[a].register(_make_card("a-0")))
    asyncio.run(_round(regs, ctxs, fake_net))
    assert len(asyncio.run(regs[b].lookup(Query()))) == 1
    asyncio.run(regs[a].deregister(a))
    asyncio.run(_round(regs, ctxs, fake_net))
    assert asyncio.run(regs[b].lookup(Query())) == []


# ---------------------------------------------------------------------------
# Convergence under N agents
# ---------------------------------------------------------------------------


def test_full_mesh_converges_within_k_rounds() -> None:
    """N=20, F=3, no drop, no partition → convergence well within K=10 rounds."""
    n = 20
    k_bound = 10
    _, regs, ctxs, fake_net = _build(n, seed=42)
    for i, aid in enumerate(regs):
        asyncio.run(regs[aid].register(_make_card(str(aid), caps=[f"cap-{i}"])))
    rounds_used = 0
    for _ in range(k_bound):
        rounds_used += 1
        asyncio.run(_round(regs, ctxs, fake_net))
        if _converged(regs):
            break
    assert _converged(regs), f"did not converge within {k_bound} rounds (used {rounds_used})"
    final_size = len(next(iter(regs.values())).view_snapshot())
    assert final_size == n


def test_partition_blocks_propagation_until_bridge() -> None:
    """Without a bridge, two partition groups never converge.  Add a bridge → they do."""
    n_per_group = 5
    ids_a = [AgentId(f"g0-{i}") for i in range(n_per_group)]
    ids_b = [AgentId(f"g1-{i}") for i in range(n_per_group)]
    bridge = AgentId("bridge")
    group_of: dict[AgentId, str] = {**{aid: "A" for aid in ids_a}, **{aid: "B" for aid in ids_b}}

    def drop(sender: AgentId, target: AgentId) -> bool:
        s_grp = group_of.get(sender)
        t_grp = group_of.get(target)
        if s_grp is None or t_grp is None:
            return False  # bridge → free traffic
        return s_grp != t_grp

    all_ids: list[AgentId] = [*ids_a, *ids_b, bridge]
    gnet = GossipNetwork(agent_ids=all_ids)
    regs = {aid: GossipRegistry(aid, gnet) for aid in all_ids}
    fake_net = _FakeNetwork(registries=regs, drop=drop)
    ctxs = {
        aid: _FakeContext(agent_id=aid, rng=random.Random(7 + i), net=fake_net)
        for i, aid in enumerate(all_ids)
    }
    for aid in all_ids:
        asyncio.run(regs[aid].register(_make_card(str(aid))))
    for _ in range(15):
        asyncio.run(_round(regs, ctxs, fake_net))
        if _converged(regs):
            break
    assert _converged(regs), "bridge-mediated convergence failed within 15 rounds"


def test_partition_without_bridge_does_not_leak() -> None:
    """No cross-group propagation: group A never learns any of group B's cards."""
    n_per_group = 4
    ids_a = [AgentId(f"g0-{i}") for i in range(n_per_group)]
    ids_b = [AgentId(f"g1-{i}") for i in range(n_per_group)]
    group_of: dict[AgentId, str] = {**{aid: "A" for aid in ids_a}, **{aid: "B" for aid in ids_b}}

    def drop(sender: AgentId, target: AgentId) -> bool:
        return group_of[sender] != group_of[target]

    all_ids: list[AgentId] = [*ids_a, *ids_b]
    gnet = GossipNetwork(agent_ids=all_ids)
    regs = {aid: GossipRegistry(aid, gnet) for aid in all_ids}
    fake_net = _FakeNetwork(registries=regs, drop=drop)
    ctxs = {
        aid: _FakeContext(agent_id=aid, rng=random.Random(13 + i), net=fake_net)
        for i, aid in enumerate(all_ids)
    }
    for aid in all_ids:
        asyncio.run(regs[aid].register(_make_card(str(aid))))
    for _ in range(8):
        asyncio.run(_round(regs, ctxs, fake_net))
    a_view = set(regs[ids_a[0]].view_snapshot().keys())
    b_view = set(regs[ids_b[0]].view_snapshot().keys())
    assert a_view.isdisjoint(set(ids_b)), "group A leaked cards from group B"
    assert b_view.isdisjoint(set(ids_a)), "group B leaked cards from group A"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_seed_same_view_trajectory() -> None:
    """Two independent runs with identical seeds produce byte-identical snapshots."""

    def run(seed: int) -> dict[str, dict[AgentId, tuple[int, AgentId, bool]]]:
        _, regs, ctxs, fake_net = _build(8, seed=seed)
        for aid in regs:
            asyncio.run(regs[aid].register(_make_card(str(aid))))
        for _ in range(5):
            asyncio.run(_round(regs, ctxs, fake_net))
        return {str(aid): reg.view_snapshot() for aid, reg in regs.items()}

    assert run(99) == run(99)


# ---------------------------------------------------------------------------
# Property-based: merge is associative + commutative
# ---------------------------------------------------------------------------


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    seed=st.integers(min_value=0, max_value=10_000),
    n_writes=st.integers(min_value=1, max_value=12),
)
def test_property_random_op_sequence_converges(seed: int, n_writes: int) -> None:
    """Any random sequence of registers/deregisters across N agents converges."""
    n = 6
    rng = random.Random(seed)
    _, regs, ctxs, fake_net = _build(n, seed=seed)
    ids = list(regs.keys())
    for _ in range(n_writes):
        writer = rng.choice(ids)
        subject = rng.choice(ids)
        if rng.random() < 0.7:
            card = _make_card(str(subject), name=f"v{rng.randint(0, 100)}")
            asyncio.run(regs[writer].register(card))
        else:
            asyncio.run(regs[writer].deregister(subject))
    for _ in range(12):
        asyncio.run(_round(regs, ctxs, fake_net))
        if _converged(regs):
            break
    assert _converged(regs)


# ---------------------------------------------------------------------------
# Drop-in compat
# ---------------------------------------------------------------------------


def test_implements_registry_protocol() -> None:
    """Runtime check that GossipRegistry implements ``nest_core.layers.registry.Registry``."""
    from nest_core.layers.registry import Registry

    _, regs, _, _ = _build(1)
    reg = regs[AgentId("a-0")]
    assert isinstance(reg, Registry)


def test_default_fanout_is_three() -> None:
    assert DEFAULT_FANOUT == 3


def test_subscribe_yields_current_view_then_ends() -> None:
    """Subscribe is a single-shot generator over the local view at call time."""
    _, regs, _, _ = _build(1)
    reg = regs[AgentId("a-0")]
    asyncio.run(reg.register(_make_card("a-0", caps=["sell"])))
    asyncio.run(reg.register(_make_card("b-0", caps=["buy"])))

    async def drain() -> list[AgentCard]:
        out: list[AgentCard] = []
        async for card in reg.subscribe(Query(capabilities=["sell"])):
            out.append(card)
        return out

    cards = asyncio.run(drain())
    assert len(cards) == 1
    assert cards[0].agent_id == AgentId("a-0")


@pytest.mark.parametrize("fanout", [1, 2, 5])
def test_fanout_obeyed_when_fewer_peers_than_requested(fanout: int) -> None:
    """Fanout clamps to ``len(peers)``; never raises on small networks."""
    ids = [AgentId(f"a-{i}") for i in range(3)]
    gnet = GossipNetwork(agent_ids=ids, fanout=fanout)
    regs = {aid: GossipRegistry(aid, gnet) for aid in ids}
    fake_net = _FakeNetwork(registries=regs)
    ctxs = {
        aid: _FakeContext(agent_id=aid, rng=random.Random(i), net=fake_net)
        for i, aid in enumerate(ids)
    }
    asyncio.run(regs[ids[0]].register(_make_card(str(ids[0]))))
    asyncio.run(regs[ids[0]].gossip_round(ctxs[ids[0]]))  # type: ignore[arg-type]
    sent_count = sum(len(v) for v in fake_net.inbox.values())
    assert sent_count == min(fanout, len(ids) - 1)
