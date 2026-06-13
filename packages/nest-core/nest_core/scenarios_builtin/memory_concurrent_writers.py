# SPDX-License-Identifier: Apache-2.0
"""Concurrent-writers scenario — agents race to update one shared key.

Every writer owns its own memory replica and writes a distinct value to the same
key, then gossips its serialised state to all peers. Peers merge what they
receive and re-gossip until they go quiet. With a conflict-free (CRDT) memory
layer the replicas converge on one winning value even though writes are
concurrent and messages may be dropped; with a last-writer-by-arrival layer they
do not.

Example::

    agents = memory_concurrent_writers_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_STATE_PREFIX = b"crdt:"


class CRDTWriterAgent(StateMachineAgent):
    """Writes one value to a shared key, then gossips and merges CRDT state."""

    def __init__(self, agent_id: AgentId, key: str, value: bytes, max_rounds: int = 16) -> None:
        self._id = agent_id
        self._key = key
        self._value = value
        self._max_rounds = max_rounds
        self._rounds = 0

    async def on_start(self, ctx: AgentContext) -> None:
        """Write this agent's value, then broadcast the initial state."""
        memory = ctx.plugins.get("memory")
        if memory is None:
            return
        await memory.write(self._key, self._value)
        await self._broadcast_state(ctx, memory)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Merge an incoming state blob and re-broadcast only if it taught us something.

        Re-broadcasting solely on a real state change makes the gossip quiesce once
        a replica has seen everything, so the flood terminates on its own.
        """
        memory = ctx.plugins.get("memory")
        if memory is None or not payload.startswith(_STATE_PREFIX):
            return
        before = memory.export_state()
        memory.merge_state(payload[len(_STATE_PREFIX) :])
        if memory.export_state() != before and self._rounds < self._max_rounds:
            await self._broadcast_state(ctx, memory)

    async def on_stop(self, ctx: AgentContext) -> None:
        """Announce the value this replica converged on, for the validator to compare."""
        memory = ctx.plugins.get("memory")
        if memory is None:
            return
        winner = await memory.read(self._key)
        await ctx.broadcast(b"value:" + self._key.encode() + b":" + (winner or b""))

    async def _broadcast_state(self, ctx: AgentContext, memory: Any) -> None:
        """Broadcast the current serialised CRDT state to all peers."""
        self._rounds += 1
        await ctx.broadcast(_STATE_PREFIX + memory.export_state())


def memory_concurrent_writers_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create writers that each own a replica of the configured memory layer.

    Example::

        agents = memory_concurrent_writers_factory(config, plugins)
    """
    task_config = config.task.config
    key = str(task_config.get("key", "shared"))
    max_rounds = int(task_config.get("rounds", 6))
    n_writers = max(2, config.agents.count)

    memory_cls = plugins["memory"]
    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    for i in range(n_writers):
        agent_id = AgentId(f"writer-{i}")
        # Each agent gets its own replica, tagged with its id for tie-breaking.
        try:
            replica = memory_cls(node_id=str(agent_id))
        except TypeError:
            replica = memory_cls()
        overrides[agent_id] = {"memory": replica}
        agents[agent_id] = CRDTWriterAgent(agent_id, key, f"v-{i}".encode(), max_rounds)

    plugins["_agent_plugins"] = overrides
    return agents
