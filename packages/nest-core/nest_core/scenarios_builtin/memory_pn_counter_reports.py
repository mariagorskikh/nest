# SPDX-License-Identifier: Apache-2.0
"""PN-Counter memory scenario -- aggregate signed evidence under noisy writes.

The scenario models a small "calculator project" evidence stream. Honest
agents contribute positive implementation/test evidence, while one noisy agent
contributes a small negative signal representing irrelevant copypasta-like
contamination. Every agent owns a private PN-Counter replica and gossips state
until all replicas converge to the same signed total.

Example::

    agents = memory_pn_counter_reports_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_TICK = b"tick"
_SYNC_PREFIX = "sync:"
_DELTA_PREFIX = "pn_delta|"
_FINAL_PREFIX = "final:"


class PnCounterReportAgent(StateMachineAgent):
    """Apply one signed delta, then gossip the PN-Counter state.

    Example::

        agent = PnCounterReportAgent(AgentId("reporter-0"), "score", 2, 20)
    """

    def __init__(self, agent_id: AgentId, key: str, delta: int, rounds: int) -> None:
        self._id = agent_id
        self._key = key
        self._delta = delta
        self._rounds = rounds

    async def on_start(self, ctx: AgentContext) -> None:
        """Apply the local signed evidence and schedule anti-entropy rounds.

        Example::

            await agent.on_start(ctx)
        """
        mem = ctx.plugins["memory"]
        await mem.write(self._key, str(self._delta).encode("ascii"))
        await ctx.broadcast(f"{_DELTA_PREFIX}{self._key}|{self._delta}".encode())
        for round_idx in range(self._rounds):
            await ctx.schedule(float(round_idx + 1), _TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Broadcast on ticks and merge incoming PN-Counter snapshots.

        Example::

            await agent.on_message(ctx, AgentId("reporter-1"), b"tick")
        """
        mem = ctx.plugins["memory"]
        if payload == _TICK:
            state = mem.export(self._key)
            if state is not None:
                await ctx.broadcast(_SYNC_PREFIX.encode() + state)
            return
        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_SYNC_PREFIX):
            try:
                await mem.merge(self._key, text[len(_SYNC_PREFIX) :].encode("utf-8"))
            except ValueError:
                return

    async def on_stop(self, ctx: AgentContext) -> None:
        """Broadcast this replica's terminal counter state.

        Example::

            await agent.on_stop(ctx)
        """
        mem = ctx.plugins["memory"]
        state = mem.export(self._key)
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)


def memory_pn_counter_reports_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create signed-evidence reporters with per-agent PN-Counter replicas.

    Example::

        agents = memory_pn_counter_reports_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 20))
    key = str(task_config.get("key", "calculator:ready_score"))
    configured = cast("object", task_config.get("deltas"))
    if isinstance(configured, list) and configured:
        deltas: list[int] = []
        for raw_delta in cast("list[object]", configured):
            deltas.append(int(cast("Any", raw_delta)))
    else:
        deltas = [2, 2, 1, -1, 3, -2, 1, 1]
    count = max(config.agents.count, len(deltas))

    memory_cls = plugins["memory"]
    agent_ids = [AgentId(f"reporter-{i}") for i in range(count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}
    for idx, aid in enumerate(agent_ids):
        delta = deltas[idx % len(deltas)]
        agents[aid] = PnCounterReportAgent(aid, key=key, delta=delta, rounds=rounds)
        overrides[aid] = {"memory": memory_cls(str(aid))}

    plugins["_agent_plugins"] = overrides
    return agents
