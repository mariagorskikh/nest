# SPDX-License-Identifier: Apache-2.0
"""Concurrent-writers scenario -- stress a CRDT memory plugin to convergence.

Every agent owns its **own replica** of the memory plugin (injected as a
per-agent plugin override) and writes a distinct value to the *same* shared
key at start-up. Agents then run a fixed number of anti-entropy gossip
rounds, broadcasting their replica's serialized state; peers merge whatever
they receive. Under a lossy network the redundant rounds still drive every
replica to the same winning value -- if the memory plugin is a real CRDT.

On stop each agent broadcasts a ``final:<state>`` record so the
``memory_concurrent_writers`` trace validator
(:func:`nest_core.validators.validate_memory_convergence`) can confirm the
swarm converged.

Example::

    agents = memory_concurrent_writers_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_TICK = b"tick"
_SYNC_PREFIX = "sync:"
_FINAL_PREFIX = "final:"


class CrdtWriterAgent(StateMachineAgent):
    """Writes one value to a shared key, then gossips its replica to convergence.

    The agent reads its private replica from ``ctx.plugins["memory"]`` (set up
    by the factory as a per-agent override), so each agent merges independently
    and the scenario genuinely exercises conflict resolution rather than a
    single shared dict.

    Example::

        agent = CrdtWriterAgent(AgentId("w0"), key="shared", value=b"v0", rounds=20)
    """

    def __init__(
        self,
        agent_id: AgentId,
        key: str,
        value: bytes,
        rounds: int,
    ) -> None:
        self._id = agent_id
        self._key = key
        self._value = value
        self._rounds = rounds

    async def on_start(self, ctx: AgentContext) -> None:
        """Write this agent's value and schedule all gossip rounds upfront.

        Scheduling every round at start (rather than chaining one tick to the
        next) means a dropped tick cannot halt the gossip loop -- the remaining
        ticks still fire, which is what makes convergence robust to loss.

        Example::

            await agent.on_start(ctx)
        """
        mem = ctx.plugins["memory"]
        await mem.write(self._key, self._value)
        for round_idx in range(self._rounds):
            await ctx.schedule(float(round_idx + 1), _TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle a gossip tick (broadcast state) or an incoming sync (merge it).

        Example::

            await agent.on_message(ctx, AgentId("w1"), b"tick")
        """
        mem = ctx.plugins["memory"]
        if payload == _TICK:
            state = mem.export(self._key)
            if state is not None:
                await ctx.broadcast(_SYNC_PREFIX.encode() + state)
            return
        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_SYNC_PREFIX):
            state = text[len(_SYNC_PREFIX) :].encode("utf-8")
            try:
                await mem.merge(self._key, state)
            except ValueError:
                # Malformed / garbled state (e.g. byzantine corruption): ignore.
                return

    async def on_stop(self, ctx: AgentContext) -> None:
        """Broadcast this replica's terminal state for the convergence validator.

        Example::

            await agent.on_stop(ctx)
        """
        mem = ctx.plugins["memory"]
        state = mem.export(self._key)
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)


def memory_concurrent_writers_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create N writer agents, each with its own memory replica.

    The factory instantiates one replica of the configured memory plugin per
    agent (passing the agent id as the replica's stable node id) and registers
    them as per-agent overrides via the ``_agent_plugins`` channel the runner
    understands. Values are derived deterministically from the agent index so
    the scenario replays byte-identically under a fixed seed.

    Example::

        agents = memory_concurrent_writers_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 20))
    key = str(task_config.get("key", "shared"))
    count = max(config.agents.count, 8)

    memory_cls = plugins["memory"]
    agent_ids = [AgentId(f"writer-{i}") for i in range(count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}
    for aid in agent_ids:
        agents[aid] = CrdtWriterAgent(
            aid,
            key=key,
            value=f"value-from-{aid}".encode(),
            rounds=rounds,
        )
        overrides[aid] = {"memory": memory_cls(str(aid))}

    plugins["_agent_plugins"] = overrides
    return agents
