# SPDX-License-Identifier: Apache-2.0
"""OR-Set claim/release marketplace -- convergence under a Byzantine forger.

A task-claim marketplace: ``claimant-0 .. claimant-{N-1}`` each own a private
OR-Set replica of one shared key (``claims``) and concurrently *claim* (add) and
*release* (remove) slot ids while gossiping their replica to convergence under
10% message loss. Alongside them runs exactly **one** Byzantine replica,
``byzantine-0``, that injects a forged, inflated-counter state throughout the
run -- the OR-Set analogue of the ``lww_register`` clock-forgery attack (a
register forged with ``lamport = 2**60``).

The forgery does two adversarial things at once:

* it adds a Byzantine-owned element (``BYZANTINE-FORGED``) tagged with an
  absurd counter (``2**60``), and
* it fabricates *tombstones* ``(claimant-k, 2**60)`` aimed at every honest node,
  trying to suppress honest claims by pre-emptively removing them.

Both fail against an observed-remove set: the inflated counter only mints a
Byzantine-owned tag, and the fabricated tombstones carry counters no honest add
ever used, so they tombstone nothing real. Every replica -- honest and
Byzantine -- still converges to byte-identical state, and every honest claim
survives. That is what the ``memory_orset_claims`` validators assert.

Determinism is structural: slot ids and the op schedule come from each agent's
index, tags come from ``(node_id, counter)``, and the forged state is a fixed
constant. No wall clock, no ``uuid4``, no unseeded RNG -- the run replays
byte-for-byte under seeds 42, 7, and 1337.

Example::

    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig

    config = ScenarioConfig.from_yaml("scenarios/memory_orset_claims.yaml")
    runner = ScenarioRunner(config)
    await runner.run()
"""

from __future__ import annotations

import json
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

KEY = "claims"
"""The single shared OR-Set key every replica claims and releases slots in."""

_SYNC_PREFIX = "sync:"
"""Marker prefix for an anti-entropy gossip broadcast; the suffix is OR-Set state."""

_FINAL_PREFIX = "final:"
"""Marker prefix for a replica's terminal-state broadcast, read by the validators."""

_ROUND_PREFIX = b"r:"
"""Marker prefix for a self-scheduled round tick; the suffix is the round index."""

BYZANTINE_ELEMENT = "BYZANTINE-FORGED"
"""The element a Byzantine replica injects; the validators check it actually appears."""

FORGED_COUNTER = 2**60
"""The inflated tag counter the Byzantine replica forges -- the OR-Set analogue of
``lww_register``'s forged ``lamport = 2**60``."""

_NUM_CHURN_SLOTS = 5
"""Number of shared ``batch-*`` slots that claimants concurrently claim/release."""

_CLAIM_ROUND = 2
"""Round at which each claimant claims its shared churn slot."""

_RELEASE_ROUND = 5
"""Round at which each claimant releases its shared churn slot again."""


def _add_op(element: str) -> bytes:
    """Return the structured OR-Set write payload that claims (adds) ``element``.

    Example::

        assert _add_op("slot-1") == b'{"element":"slot-1","op":"add"}'
    """
    return json.dumps({"op": "add", "element": element}, sort_keys=True).encode("utf-8")


def _remove_op(element: str) -> bytes:
    """Return the structured OR-Set write payload that releases (removes) ``element``.

    Example::

        assert _remove_op("slot-1") == b'{"element":"slot-1","op":"remove"}'
    """
    return json.dumps({"op": "remove", "element": element}, sort_keys=True).encode("utf-8")


def _forged_state(honest_node_ids: list[str]) -> bytes:
    """Build the constant forged OR-Set export the Byzantine replica injects.

    Adds a Byzantine-owned element with an inflated counter and fabricates
    tombstones against every honest node id -- both with counter ``2**60``, a
    value no honest add ever mints, so the attack cannot suppress real claims.
    The bytes are canonical and deterministic, independent of any clock or RNG.

    Example::

        forged = _forged_state(["claimant-0", "claimant-1"])
    """
    element_key = json.dumps(BYZANTINE_ELEMENT, separators=(",", ":"))
    adds = {element_key: [["byzantine-0", FORGED_COUNTER]]}
    removed = [[node_id, FORGED_COUNTER] for node_id in sorted(honest_node_ids)]
    return json.dumps(
        {"crdt": "or_set", "adds": adds, "removed": removed},
        sort_keys=True,
    ).encode("utf-8")


class ClaimantAgent(StateMachineAgent):
    """Honest replica: permanently claims its own slot, churns a shared slot, gossips.

    On start the claimant claims ``slot-<index>`` and **never** releases it, so
    that claim is guaranteed to survive to convergence -- the honest-liveness
    property the validators check. It also schedules ``rounds`` gossip ticks. At
    :data:`_CLAIM_ROUND` it claims a *shared* churn slot ``batch-<index mod k>``
    (claimed by two claimants at once), and at :data:`_RELEASE_ROUND` it releases
    that shared slot -- genuinely concurrent claim/release traffic on one shared
    OR-Set key. The churn namespace (``batch-*``) is disjoint from the permanent
    ``slot-*`` namespace, so churn never disturbs a surviving claim. Every tick
    it broadcasts its serialized replica; every peer sync it merges.

    Example::

        agent = ClaimantAgent(AgentId("claimant-0"), index=0, num_slots=10, rounds=30)
    """

    def __init__(self, agent_id: AgentId, index: int, num_slots: int, rounds: int) -> None:
        self._id = agent_id
        self._index = index
        self._num_slots = num_slots
        self._rounds = rounds
        self._self_slot = f"slot-{index}"
        self._churn_slot = f"batch-{index % _NUM_CHURN_SLOTS}"

    async def on_start(self, ctx: AgentContext) -> None:
        """Claim this replica's own slot and schedule every gossip round upfront.

        Example::

            await agent.on_start(ctx)
        """
        mem = ctx.plugins["memory"]
        await mem.write(KEY, _add_op(self._self_slot))
        for round_idx in range(self._rounds):
            await ctx.schedule(float(round_idx + 1), _ROUND_PREFIX + str(round_idx).encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Run this round's claim/release op then gossip, or merge a peer sync.

        Example::

            await agent.on_message(ctx, AgentId("claimant-1"), b"r:2")
        """
        mem = ctx.plugins["memory"]
        if payload.startswith(_ROUND_PREFIX):
            round_idx = int(payload[len(_ROUND_PREFIX) :])
            if round_idx == _CLAIM_ROUND:
                await mem.write(KEY, _add_op(self._churn_slot))
            elif round_idx == _RELEASE_ROUND:
                await mem.write(KEY, _remove_op(self._churn_slot))
            state = mem.export(KEY)
            if state is not None:
                await ctx.broadcast(_SYNC_PREFIX.encode() + state)
            return
        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_SYNC_PREFIX):
            state = text[len(_SYNC_PREFIX) :].encode("utf-8")
            try:
                await mem.merge(KEY, state)
            except ValueError:
                # Malformed / Byzantine-garbled state: reject without corruption.
                return

    async def on_stop(self, ctx: AgentContext) -> None:
        """Broadcast this replica's terminal OR-Set state for the validators.

        Example::

            await agent.on_stop(ctx)
        """
        mem = ctx.plugins["memory"]
        state = mem.export(KEY)
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)


class ByzantineForgerAgent(StateMachineAgent):
    """Byzantine replica: injects a forged, inflated-counter state, then gossips.

    On start it merges a fixed forged state (see :func:`_forged_state`) into its
    own replica -- adding a Byzantine element and fabricated honest-node
    tombstones -- and thereafter behaves like an ordinary gossiper: every tick
    it broadcasts its replica (propagating the forgery) and merges peer syncs
    (so it, too, converges). Because an OR-Set merge is a union and the forged
    tombstones match no real add-tag, this cannot suppress an honest claim; it
    only proves the swarm converges *despite* an adversary in the mix.

    Example::

        agent = ByzantineForgerAgent(AgentId("byzantine-0"), honest_ids, rounds=30)
    """

    def __init__(self, agent_id: AgentId, honest_node_ids: list[str], rounds: int) -> None:
        self._id = agent_id
        self._forged = _forged_state(honest_node_ids)
        self._rounds = rounds

    async def on_start(self, ctx: AgentContext) -> None:
        """Inject the forged state into the local replica and schedule gossip.

        Example::

            await agent.on_start(ctx)
        """
        mem = ctx.plugins["memory"]
        await mem.merge(KEY, self._forged)
        for round_idx in range(self._rounds):
            await ctx.schedule(float(round_idx + 1), _ROUND_PREFIX + str(round_idx).encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Gossip the (forged-carrying) replica on a tick, or merge a peer sync.

        Example::

            await agent.on_message(ctx, AgentId("claimant-0"), b"r:0")
        """
        mem = ctx.plugins["memory"]
        if payload.startswith(_ROUND_PREFIX):
            state = mem.export(KEY)
            if state is not None:
                await ctx.broadcast(_SYNC_PREFIX.encode() + state)
            return
        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_SYNC_PREFIX):
            state = text[len(_SYNC_PREFIX) :].encode("utf-8")
            try:
                await mem.merge(KEY, state)
            except ValueError:
                return

    async def on_stop(self, ctx: AgentContext) -> None:
        """Broadcast this replica's terminal state so it joins the convergence check.

        Example::

            await agent.on_stop(ctx)
        """
        mem = ctx.plugins["memory"]
        state = mem.export(KEY)
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)


def memory_orset_claims_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build ``N`` honest claimants plus one Byzantine forger, each with a replica.

    The factory instantiates one replica of the configured memory plugin per
    agent (passing the agent id as the stable node id) and registers them as
    per-agent overrides via the ``_agent_plugins`` channel the runner
    understands. ``claimants`` and ``rounds`` come from the task config; the
    single Byzantine replica is always ``byzantine-0``. Everything derives from
    indices, so the scenario replays byte-identically under a fixed seed.

    Example::

        agents = memory_orset_claims_factory(config, plugins)
    """
    task_config = config.task.config
    claimants = int(task_config.get("claimants", 10))
    rounds = int(task_config.get("rounds", 30))
    num_slots = max(claimants, 1)

    memory_cls = plugins["memory"]
    honest_ids = [f"claimant-{i}" for i in range(claimants)]

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    for i in range(claimants):
        aid = AgentId(honest_ids[i])
        agents[aid] = ClaimantAgent(aid, index=i, num_slots=num_slots, rounds=rounds)
        overrides[aid] = {"memory": memory_cls(str(aid))}

    byz_id = AgentId("byzantine-0")
    agents[byz_id] = ByzantineForgerAgent(byz_id, honest_node_ids=honest_ids, rounds=rounds)
    overrides[byz_id] = {"memory": memory_cls(str(byz_id))}

    plugins["_agent_plugins"] = overrides
    return agents
