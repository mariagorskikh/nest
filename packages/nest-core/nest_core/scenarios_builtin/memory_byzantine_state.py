# SPDX-License-Identifier: Apache-2.0
"""Byzantine-state memory scenario -- reject malformed CRDT gossip.

This scenario is a hostile variant of ``memory_concurrent_writers``. Each
honest agent owns a private LWW-register replica, writes a local value, and
gossips normally. One byzantine agent then broadcasts malformed serialized
register state with an artificially high Lamport clock. A hardened CRDT must
raise at the merge boundary and leave the trusted local value unchanged; an
unsafe decoder can accept the poison and spread it by later gossip rounds.

Example::

    agents = memory_byzantine_state_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_TICK = b"tick"
_ATTACK = b"attack"
_SYNC_PREFIX = "sync:"
_ATTACK_PREFIX = "attack:"
_FINAL_PREFIX = "final:"
_REJECTED_PREFIX = "rejected:"
_ACCEPTED_PREFIX = "accepted:"


class ByzantineStateAgent(StateMachineAgent):
    """Write one CRDT value, gossip it, and reject malformed remote state.

    Example::

        agent = ByzantineStateAgent(AgentId("writer-1"), "shared", b"value", 20, False)
    """

    def __init__(
        self,
        agent_id: AgentId,
        key: str,
        value: bytes,
        rounds: int,
        is_attacker: bool,
        malicious_state: bytes,
    ) -> None:
        self._id = agent_id
        self._key = key
        self._value = value
        self._rounds = rounds
        self._is_attacker = is_attacker
        self._malicious_state = malicious_state

    async def on_start(self, ctx: AgentContext) -> None:
        """Write the local value and schedule deterministic gossip rounds.

        Example::

            await agent.on_start(ctx)
        """
        mem = ctx.plugins["memory"]
        await mem.write(self._key, self._value)
        for round_idx in range(self._rounds):
            await ctx.schedule(float(round_idx + 1), _TICK)
        if self._is_attacker:
            await ctx.schedule(2.5, _ATTACK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle gossip ticks, normal sync state, and byzantine attack state.

        Example::

            await agent.on_message(ctx, AgentId("writer-0"), b"tick")
        """
        mem = ctx.plugins["memory"]
        if payload == _TICK:
            state = mem.export(self._key)
            if state is not None:
                await ctx.broadcast(_SYNC_PREFIX.encode() + state)
            return
        if payload == _ATTACK:
            await ctx.broadcast(_ATTACK_PREFIX.encode() + self._malicious_state)
            return

        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_SYNC_PREFIX):
            state = text[len(_SYNC_PREFIX) :].encode("utf-8")
            try:
                await mem.merge(self._key, state)
            except ValueError:
                return
            return
        if text.startswith(_ATTACK_PREFIX):
            if self._is_attacker:
                return
            state = text[len(_ATTACK_PREFIX) :].encode("utf-8")
            before = mem.export(self._key)
            try:
                await mem.merge(self._key, state)
            except ValueError:
                await ctx.broadcast(f"{_REJECTED_PREFIX}{sender}".encode())
                return
            if mem.export(self._key) != before:
                await ctx.broadcast(f"{_ACCEPTED_PREFIX}{sender}".encode())

    async def on_stop(self, ctx: AgentContext) -> None:
        """Broadcast the terminal register state for validators.

        Example::

            await agent.on_stop(ctx)
        """
        mem = ctx.plugins["memory"]
        state = mem.export(self._key)
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)


def memory_byzantine_state_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create writer replicas plus one deterministic malformed-state attacker.

    Example::

        agents = memory_byzantine_state_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 20))
    key = str(task_config.get("key", "shared"))
    count = max(config.agents.count, 8)
    attacker_index = int(task_config.get("attacker_index", 0))
    malicious_state = str(
        task_config.get(
            "malicious_state",
            '{"crdt":"lww_register","payload":"@@@","lamport":999,"node":"evil"}',
        )
    ).encode("utf-8")

    memory_cls = plugins["memory"]
    agent_ids = [AgentId(f"writer-{i}") for i in range(count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}
    for idx, aid in enumerate(agent_ids):
        agents[aid] = ByzantineStateAgent(
            aid,
            key=key,
            value=f"value-from-{aid}".encode(),
            rounds=rounds,
            is_attacker=idx == attacker_index,
            malicious_state=malicious_state,
        )
        overrides[aid] = {"memory": memory_cls(str(aid))}

    plugins["_agent_plugins"] = overrides
    return agents
