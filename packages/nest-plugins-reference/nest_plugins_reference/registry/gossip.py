# SPDX-License-Identifier: Apache-2.0
"""Gossip registry plugin — eventually-consistent agent discovery under partition.

The default ``in_memory`` registry is one shared ``dict`` per simulation: every
agent's ``register``, ``lookup``, and ``subscribe`` touch the same map.  That
is a useful *test scaffold* but it is operationally a lie: in any real
deployment the registry is distributed, possibly partitioned, and definitely
subject to eventual-consistency races.  In particular, when the simulator
injects a ``failures.network_partition`` (see
``nest_core/sim/simulator.py``), the partition silently does not affect
registry lookups — partitioned agents can still discover each other through
the shared dict.  That is physically impossible in production.

This plugin replaces that scaffold with **per-agent local views** synchronised
by anti-entropy gossip over the existing transport layer.  An on-chain
registry author wrote this plugin to benchmark the eventual-consistency
trade-off against the linearisable, partition-fatal alternative that a
contract-backed registry provides.  Three invariants are enforced and exposed
to validators:

* **Partition honesty.**  Gossip messages ride the agent's own transport,
  so the simulator's ``_should_drop`` partition logic naturally blocks
  cross-partition propagation.  An agent's local view can only grow with
  cards whose publishers it can actually reach.
* **Convergence under heal.**  After the partition heals, push-pull
  anti-entropy with fanout ``F`` converges in ``O(log_F(N))`` rounds in the
  best case.  With a 5% message-drop rate the constant doubles; we pick a
  convergence bound ``K=10`` for ``N=20, F=3`` (theoretical ~3, doubled to
  ~6 under drop, plus safety margin).  Validators assert convergence
  inside ``K``.
* **Conflict resolution.**  Each card is stamped with a monotonic
  ``(version, publisher_id)`` pair.  Merge is last-writer-wins by
  ``version``, tiebroken by ``publisher_id`` lexicographically — same shape
  as a Lamport-style write tag, deterministic across replays.

Wire format (binary-prefixed bytes over transport)::

    GOSSIP_PREFIX || op (1B) || canonical_json(payload)

where ``op`` is ``D`` (digest exchange) or ``P`` (push of cards).  The
canonical JSON encoding matches ``nest_core.sim.trace`` for replay equality.

The plugin is **deterministic**: it uses the agent's seeded ``Random`` (via
``handle_gossip`` callers) for peer selection and never reads wall-clock
time.  Same seed → identical view trajectory.

Example::

    from nest_plugins_reference.registry.gossip import GossipNetwork, GossipRegistry

    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b"), AgentId("c")])
    reg_a = GossipRegistry(AgentId("a"), net)
    await reg_a.register(AgentCard(agent_id=AgentId("a"), name="A"))
    # Later, agent A's driver fires a tick:
    await reg_a.gossip_round(ctx)  # type: ignore[arg-type]
"""

from __future__ import annotations

import json
import random
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from nest_core.types import AgentCard, AgentId, Query

if TYPE_CHECKING:
    from nest_core.sim.agent import AgentContext

GOSSIP_PREFIX = b"GOSSIP|"
"""Wire marker for gossip messages.  Agents forward matching payloads to
``GossipRegistry.handle_gossip``; other payloads are application traffic.

Example::

    if payload.startswith(GOSSIP_PREFIX):
        await registry.handle_gossip(sender, payload)
"""

OP_DIGEST = b"D"
"""Wire op: digest exchange (peer asks: what versions do you hold?)."""

OP_PUSH = b"P"
"""Wire op: push (peer sends cards the digest revealed it was missing)."""

DEFAULT_FANOUT = 3
"""Number of peers each gossip round pushes to.  ``F=3`` is the sweet spot
for ``N`` up to a few hundred — see the SWIM and Plumtree literature.
"""


@dataclass(frozen=True, order=True)
class _WriteTag:
    """Lamport-style write tag: ``(version, publisher_id)``.

    Used to order concurrent writes deterministically.  ``version`` is a
    per-publisher monotonic counter; ties are broken by ``publisher_id``
    so two agents observing the same set of writes always agree on the
    winner.

    Example::

        tag1 = _WriteTag(version=1, publisher_id=AgentId("a"))
        tag2 = _WriteTag(version=1, publisher_id=AgentId("b"))
        assert tag1 < tag2  # 'a' < 'b' lex
    """

    version: int
    publisher_id: AgentId


@dataclass
class _Versioned:
    """A stored card plus its write tag and a tombstone bit.

    Tombstones are kept so deregistration propagates through gossip
    without being overwritten by stale ``register`` re-prints.

    Example::

        v = _Versioned(card=card, tag=_WriteTag(1, AgentId("a")), tombstone=False)
    """

    card: AgentCard
    tag: _WriteTag
    tombstone: bool = False


@dataclass
class GossipNetwork:
    """Shared backplane: peer list + per-publisher version counters.

    The network does **not** route messages — that is the transport's job.
    It only exposes the peer set and hands out fresh ``_WriteTag`` values so
    every per-agent ``GossipRegistry`` instance agrees on monotonic
    versioning even though the writers are independent.

    Example::

        net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
        reg = GossipRegistry(AgentId("a"), net)
    """

    agent_ids: list[AgentId]
    fanout: int = DEFAULT_FANOUT
    _versions: dict[AgentId, int] = field(default_factory=lambda: dict[AgentId, int]())

    def next_version(self, publisher: AgentId) -> int:
        """Return the next monotonic version for ``publisher``.

        Example::

            v = net.next_version(AgentId("a"))
        """
        v = self._versions.get(publisher, 0) + 1
        self._versions[publisher] = v
        return v

    def peers_of(self, agent: AgentId) -> list[AgentId]:
        """Return all peers of ``agent`` (i.e. every other agent in the network).

        Example::

            peers = net.peers_of(AgentId("a"))
        """
        return [a for a in self.agent_ids if a != agent]


class GossipRegistry:
    """Per-agent gossip registry with partition-honest eventual consistency.

    The plugin satisfies ``nest_core.layers.registry.Registry``: ``register``,
    ``lookup``, ``subscribe``, ``deregister``.  Lookups read **only** the
    local view — they are potentially stale, never linearisable.

    Driver agents are responsible for calling ``gossip_round(ctx)`` on a
    schedule (typically ``ctx.schedule(GOSSIP_INTERVAL, ...)``) and for
    forwarding inbound ``GOSSIP_PREFIX``-marked payloads to
    ``handle_gossip(sender, payload)``.  See
    ``nest_core.scenarios_builtin.gossip_registry`` for a complete driver.

    Example::

        net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
        reg = GossipRegistry(AgentId("a"), net)
        await reg.register(AgentCard(agent_id=AgentId("a"), name="A"))
        cards = await reg.lookup(Query())  # returns local view only
    """

    def __init__(self, agent_id: AgentId, network: GossipNetwork) -> None:
        self._agent_id = agent_id
        self._network = network
        self._view: dict[AgentId, _Versioned] = {}
        self._last_pushed: dict[AgentId, dict[AgentId, _WriteTag]] = {}
        self._pending_subscribers: list[tuple[Query, list[AgentCard]]] = []

    # ------------------------------------------------------------------
    # Registry protocol
    # ------------------------------------------------------------------

    async def register(self, card: AgentCard) -> None:
        """Register ``card`` locally; gossip will propagate it on the next round.

        Stamps the card with a fresh write tag from the shared network so
        concurrent re-registrations from the same publisher are ordered
        deterministically.

        Example::

            await reg.register(AgentCard(agent_id=AgentId("a"), name="A"))
        """
        tag = _WriteTag(
            version=self._network.next_version(card.agent_id),
            publisher_id=card.agent_id,
        )
        self._apply(card, tag, tombstone=False)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Return cards matching ``query`` from the **local** view.

        Stale by construction: only reflects what gossip has delivered to
        this agent so far.  During a partition, returns nothing from the
        other side that this agent did not already know about.

        Example::

            cards = await reg.lookup(Query(capabilities=["sell"]))
        """
        return [v.card for v in self._view.values() if not v.tombstone and _matches(v.card, query)]

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Yield cards matching ``query`` from the local view, then end.

        This is a deliberately simple implementation: yield the current
        view once and stop.  A streaming subscription would require a
        long-lived task per subscriber; not justified for the test rig.

        Example::

            async for card in reg.subscribe(query):
                print(card.name)
        """
        for card in await self.lookup(query):
            yield card

    async def deregister(self, agent: AgentId) -> None:
        """Tombstone ``agent`` locally; gossip propagates the tombstone.

        Example::

            await reg.deregister(AgentId("a"))
        """
        existing = self._view.get(agent)
        if existing is None:
            return
        tag = _WriteTag(
            version=self._network.next_version(agent),
            publisher_id=agent,
        )
        self._apply(existing.card, tag, tombstone=True)

    # ------------------------------------------------------------------
    # Gossip mechanics
    # ------------------------------------------------------------------

    async def gossip_round(self, ctx: AgentContext) -> None:
        """Run one round of push-pull anti-entropy.

        Picks ``fanout`` peers uniformly at random (using the agent's
        seeded RNG, so replays are byte-identical) and sends each one a
        digest of locally-known write tags.  The peer replies with cards
        the digest revealed it was missing — that handshake completes
        via ``handle_gossip``.

        Example::

            await reg.gossip_round(ctx)
        """
        peers = self._network.peers_of(self._agent_id)
        if not peers:
            return
        fanout = min(self._network.fanout, len(peers))
        chosen = _sample_without_replacement(ctx.rng, peers, fanout)
        digest = self._digest()
        payload = GOSSIP_PREFIX + OP_DIGEST + _encode(digest)
        for peer in chosen:
            await ctx.send(peer, payload)

    async def handle_gossip(self, sender: AgentId, payload: bytes, ctx: AgentContext) -> bool:
        """Process a gossip message from ``sender``.

        Returns ``True`` if the payload was a gossip message (and was
        consumed), ``False`` otherwise.  Driver agents should call this
        first in ``on_message`` and dispatch normally only when it
        returns ``False``.

        On a ``D`` (digest), replies with a ``P`` (push) of cards the
        sender is missing or stale on.  On a ``P`` (push), merges each card into
        the local view via the same LWW rule used by ``register``.

        Example::

            handled = await reg.handle_gossip(sender, payload, ctx)
        """
        if not payload.startswith(GOSSIP_PREFIX):
            return False
        body = payload[len(GOSSIP_PREFIX) :]
        if not body:
            return True
        op, rest = body[:1], body[1:]
        if op == OP_DIGEST:
            sender_digest = _decode_digest(rest)
            missing = self._compute_missing(sender_digest)
            if missing:
                push_payload = GOSSIP_PREFIX + OP_PUSH + _encode_push(missing)
                await ctx.send(sender, push_payload)
            return True
        if op == OP_PUSH:
            for card, tag, tombstone in _decode_push(rest):
                self._apply(card, tag, tombstone=tombstone)
            return True
        return True  # Unknown op: consume silently so junk doesn't escape.

    # ------------------------------------------------------------------
    # Inspection (used by validators + tests)
    # ------------------------------------------------------------------

    def view_snapshot(self) -> dict[AgentId, tuple[int, AgentId, bool]]:
        """Return a deterministic snapshot of the local view.

        Format: ``{agent_id: (version, publisher_id, tombstone)}``.  Two
        snapshots are equal iff the two views have converged.

        Example::

            snap = reg.view_snapshot()
        """
        return {
            aid: (v.tag.version, v.tag.publisher_id, v.tombstone)
            for aid, v in sorted(self._view.items())
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _apply(self, card: AgentCard, tag: _WriteTag, *, tombstone: bool) -> None:
        existing = self._view.get(card.agent_id)
        if existing is not None and existing.tag >= tag:
            return
        self._view[card.agent_id] = _Versioned(card=card, tag=tag, tombstone=tombstone)

    def _digest(self) -> dict[AgentId, _WriteTag]:
        return {aid: v.tag for aid, v in self._view.items()}

    def _compute_missing(
        self, sender_digest: dict[AgentId, _WriteTag]
    ) -> list[tuple[AgentCard, _WriteTag, bool]]:
        out: list[tuple[AgentCard, _WriteTag, bool]] = []
        for aid, versioned in self._view.items():
            sender_tag = sender_digest.get(aid)
            if sender_tag is None or sender_tag < versioned.tag:
                out.append((versioned.card, versioned.tag, versioned.tombstone))
        return out


# ---------------------------------------------------------------------------
# Helpers (module-private)
# ---------------------------------------------------------------------------


def _matches(card: AgentCard, query: Query) -> bool:
    if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
        return False
    return not (query.name_pattern and query.name_pattern not in card.name)


def _sample_without_replacement(rng: random.Random, peers: list[AgentId], k: int) -> list[AgentId]:
    """Deterministic sample of ``k`` peers from ``peers`` using ``rng``.

    We avoid ``random.sample`` because the agent ``rng`` may be a custom
    ``Random`` subclass; explicit Fisher-Yates over a copy keeps the
    sampling reproducible across Python versions.
    """
    pool = list(peers)
    out: list[AgentId] = []
    for _ in range(k):
        j = rng.randint(0, len(pool) - 1)
        out.append(pool[j])
        pool[j] = pool[-1]
        pool.pop()
    return out


def _encode(digest: dict[AgentId, _WriteTag]) -> bytes:
    obj = {str(aid): [t.version, str(t.publisher_id)] for aid, t in digest.items()}
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _decode_digest(raw: bytes) -> dict[AgentId, _WriteTag]:
    obj = json.loads(raw.decode())
    return {
        AgentId(aid): _WriteTag(version=int(v), publisher_id=AgentId(pid))
        for aid, (v, pid) in obj.items()
    }


def _encode_push(items: list[tuple[AgentCard, _WriteTag, bool]]) -> bytes:
    obj = [
        {
            "card": card.model_dump(mode="json"),
            "version": tag.version,
            "publisher": str(tag.publisher_id),
            "tombstone": tombstone,
        }
        for card, tag, tombstone in items
    ]
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _decode_push(raw: bytes) -> list[tuple[AgentCard, _WriteTag, bool]]:
    obj: list[dict[str, object]] = json.loads(raw.decode())
    out: list[tuple[AgentCard, _WriteTag, bool]] = []
    for entry in obj:
        card = AgentCard.model_validate(entry["card"])
        tag = _WriteTag(
            version=int(entry["version"]),  # type: ignore[arg-type]
            publisher_id=AgentId(str(entry["publisher"])),
        )
        out.append((card, tag, bool(entry["tombstone"])))
    return out
