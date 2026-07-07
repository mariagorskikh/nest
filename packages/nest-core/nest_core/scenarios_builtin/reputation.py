# SPDX-License-Identifier: Apache-2.0
"""Reputation-based trading scenario.

Honest agents trade reliably while malicious agents sometimes cheat.
An observer tracks reputation scores and broadcasts warnings.

Example::

    agents = reputation_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


class HonestAgent(StateMachineAgent):
    """Always delivers on trades and reports cheaters."""

    def __init__(
        self,
        agent_id: AgentId,
        peers: list[AgentId],
        observer: AgentId,
        rounds: int = 5,
    ) -> None:
        self._id = agent_id
        self._peers = peers
        self._observer = observer
        self._rounds = rounds
        self._round = 0

    async def on_start(self, ctx: AgentContext) -> None:
        self._round = 1
        peer = ctx.rng.choice(self._peers)
        await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("trade:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                await ctx.send(sender, f"deliver:{rnd}:{self._id}".encode())
        elif msg.startswith("deliver:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                await ctx.send(
                    self._observer,
                    f"report:{rnd}:{sender}:good".encode(),
                )
                self._round += 1
                if self._round <= self._rounds:
                    peer = ctx.rng.choice(self._peers)
                    await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())
        elif msg.startswith("cheat:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                await ctx.send(
                    self._observer,
                    f"report:{rnd}:{sender}:bad".encode(),
                )
                self._round += 1
                if self._round <= self._rounds:
                    peer = ctx.rng.choice(self._peers)
                    await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())


class MaliciousAgent(StateMachineAgent):
    """Sometimes cheats on trades to game the system."""

    def __init__(
        self,
        agent_id: AgentId,
        peers: list[AgentId],
        observer: AgentId,
        rounds: int = 5,
    ) -> None:
        self._id = agent_id
        self._peers = peers
        self._observer = observer
        self._rounds = rounds
        self._round = 0

    async def on_start(self, ctx: AgentContext) -> None:
        self._round = 1
        peer = ctx.rng.choice(self._peers)
        await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("trade:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                if ctx.rng.random() > 0.5:
                    await ctx.send(sender, f"cheat:{rnd}:{self._id}".encode())
                else:
                    await ctx.send(sender, f"deliver:{rnd}:{self._id}".encode())
        elif msg.startswith("deliver:") or msg.startswith("cheat:"):
            self._round += 1
            if self._round <= self._rounds:
                peer = ctx.rng.choice(self._peers)
                await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())


class ObserverAgent(StateMachineAgent):
    """Tracks reputation scores and broadcasts warnings about bad actors."""

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._scores: dict[str, int] = {}
        self._warned: set[str] = set()

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("report:"):
            return
        parts = msg.split(":")
        if len(parts) < 4:
            return
        rnd, agent_str, outcome = parts[1], parts[2], parts[3]
        if agent_str not in self._scores:
            self._scores[agent_str] = 0
        self._scores[agent_str] += 1 if outcome == "good" else -2
        if self._scores[agent_str] <= -3 and agent_str not in self._warned:
            self._warned.add(agent_str)
            await ctx.broadcast(f"warning:{rnd}:{agent_str}:untrusted".encode())


def reputation_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create honest, malicious, and observer agents.

    Example::

        agents = reputation_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = task_config.get("rounds", 5)
    malicious_fraction = task_config.get("malicious_fraction", 0.2)

    agents: dict[AgentId, StateMachineAgent] = {}

    trader_count = config.agents.count - 1
    malicious_count = max(1, int(trader_count * malicious_fraction))
    honest_count = trader_count - malicious_count

    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "honest":
                honest_count = role.count
            elif role.name == "malicious":
                malicious_count = role.count

    observer_id = AgentId("observer-0")
    honest_ids = [AgentId(f"honest-{i}") for i in range(honest_count)]
    malicious_ids = [AgentId(f"malicious-{i}") for i in range(malicious_count)]
    all_traders: list[AgentId] = [*honest_ids, *malicious_ids]

    for aid in honest_ids:
        peers = [p for p in all_traders if p != aid]
        agents[aid] = HonestAgent(aid, peers=peers, observer=observer_id, rounds=rounds)

    for aid in malicious_ids:
        # Malicious agents only *initiate* trades with honest peers. A cheat is
        # emitted in reply to a received trade, so restricting who a malicious
        # agent trades with guarantees every cheat is witnessed — and reported —
        # by an honest agent. Without this, a malicious→malicious cheat is never
        # reported (the peer stays silent) and the reputation layer cannot see
        # it, which trips ``validate_reputation_scoring``. Fall back to all
        # traders only in the degenerate all-malicious config (no honest peers).
        peers = honest_ids or [p for p in all_traders if p != aid]
        agents[aid] = MaliciousAgent(aid, peers=peers, observer=observer_id, rounds=rounds)

    agents[observer_id] = ObserverAgent(observer_id)

    return agents
