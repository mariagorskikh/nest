# SPDX-License-Identifier: Apache-2.0
"""Concurrent-writers scenario -- stress a CRDT memory plugin to convergence.

Exercises both write() and remove() for the OR-Set plugin.
"""

from __future__ import annotations

import random
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_TICK = b"tick"
_SYNC_PREFIX = "sync:"
_FINAL_PREFIX = "final:"


class OrSetWriterAgent(StateMachineAgent):
    def __init__(
        self,
        agent_id: AgentId,
        key: str,
        values: list[bytes],
        rounds: int,
        add_fraction: float,
        remove_fraction: float,
        seed: int,
    ) -> None:
        self._id = agent_id
        self._key = key
        self._values = values
        self._rounds = rounds
        self._add_fraction = add_fraction
        self._remove_fraction = remove_fraction
        self._rng = random.Random(seed)

    async def on_start(self, ctx: AgentContext) -> None:

        # Schedule a burst of ops at T=0.1 to T=1.0 to simulate concurrent writes
        for i in range(10):
            if self._rng.random() < self._add_fraction:
                await ctx.schedule(0.1 + (i * 0.05), b"op:write")
            if self._rng.random() < self._remove_fraction:
                await ctx.schedule(0.1 + (i * 0.05) + 0.01, b"op:remove")

        # Schedule all gossip rounds starting from T=2.0
        for round_idx in range(self._rounds):
            await ctx.schedule(2.0 + float(round_idx), _TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        mem = ctx.plugins["memory"]
        if payload == b"op:write":
            await mem.write(self._key, self._rng.choice(self._values))
            return
        if payload == b"op:remove":
            await mem.remove(self._key, self._rng.choice(self._values))
            return

        if payload == _TICK:
            state = mem.export(self._key)
            if state is not None:
                await ctx.broadcast(_SYNC_PREFIX.encode() + state)
            return

        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_SYNC_PREFIX):
            state = text[len(_SYNC_PREFIX) :].encode("utf-8")
            try:
                if hasattr(mem, "merge"):
                    await mem.merge(self._key, state)
            except Exception:
                return

    async def on_stop(self, ctx: AgentContext) -> None:
        mem = ctx.plugins["memory"]
        state = mem.export(self._key)
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)


def memory_or_set_writers_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 20))
    key = str(task_config.get("key", "shared"))

    # Parse values
    values_str = task_config.get("values", ["apple", "banana", "cherry"])
    values = [str(v).encode() for v in values_str]

    add_fraction = float(task_config.get("add_fraction", 0.75))
    remove_fraction = float(task_config.get("remove_fraction", 0.25))

    count = max(config.agents.count, 8)
    base_seed = int(config.seed) if hasattr(config, "seed") else 42

    memory_cls = plugins["memory"]
    agent_ids = [AgentId(f"writer-{i}") for i in range(count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}
    for i, aid in enumerate(agent_ids):
        agents[aid] = OrSetWriterAgent(
            aid,
            key=key,
            values=values,
            rounds=rounds,
            add_fraction=add_fraction,
            remove_fraction=remove_fraction,
            seed=base_seed + i,
        )
        overrides[aid] = {"memory": memory_cls(str(aid))}

    plugins["_agent_plugins"] = overrides
    return agents
