# SPDX-License-Identifier: Apache-2.0
"""Stale-report trust scenario.

Honest agents trade reliably.  A "reformed" agent behaves well early on,
accumulates many positive reports, then turns malicious for the rest of
the scenario.  An observer files trust reports and tracks scores.

Under ``trust: weighted`` the stale early positives decay, so the
agent's recent malice dominates and its score drops below the warning
threshold.  Under ``trust: score_average`` every positive counts equally
forever, so the old positives overwhelm the recent negatives and the
score stays deceptively high.

Example::

    agents = stale_report_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


class HonestTrader(StateMachineAgent):
    """Always delivers on trades and reports outcomes to the observer."""

    def __init__(
        self,
        agent_id: AgentId,
        peers: list[AgentId],
        observer: AgentId,
        rounds: int = 10,
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
                    f"report:{rnd}:{sender}:good:{ctx.time}".encode(),
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
                    f"report:{rnd}:{sender}:bad:{ctx.time}".encode(),
                )
                self._round += 1
                if self._round <= self._rounds:
                    peer = ctx.rng.choice(self._peers)
                    await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())


class ReformedAttacker(StateMachineAgent):
    """Behaves well for the first ``good_rounds`` then cheats every round.

    Early rounds produce many positive reports that are STALE by the end.
    Under score_average these old positives mask the later malice.
    Under weighted trust they decay and the recent negatives dominate.
    """

    def __init__(
        self,
        agent_id: AgentId,
        peers: list[AgentId],
        observer: AgentId,
        rounds: int = 10,
        good_rounds: int = 6,
    ) -> None:
        self._id = agent_id
        self._peers = peers
        self._observer = observer
        self._rounds = rounds
        self._good_rounds = good_rounds
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
                if self._round <= self._good_rounds:
                    await ctx.send(sender, f"deliver:{rnd}:{self._id}".encode())
                else:
                    await ctx.send(sender, f"cheat:{rnd}:{self._id}".encode())
        elif msg.startswith("deliver:") or msg.startswith("cheat:"):
            self._round += 1
            if self._round <= self._rounds:
                peer = ctx.rng.choice(self._peers)
                await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())


class TrustObserver(StateMachineAgent):
    """Tracks trust reports filed against each agent.

    Emits ``filed:<round>:<agent>:<outcome>:<tick>`` messages so the
    validator can verify report patterns and check whether the reformed
    attacker's late negatives are present.
    """

    def __init__(self, agent_id: AgentId, attacker_id: AgentId, rounds: int = 10) -> None:
        self._id = agent_id
        self._attacker_id = attacker_id
        self._rounds = rounds
        self._reports_filed = 0

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("report:"):
            return
        parts = msg.split(":")
        if len(parts) < 4:
            return
        rnd_str, agent_str, outcome = parts[1], parts[2], parts[3]
        # Determine the tick from the message if present
        tick = float(parts[4]) if len(parts) >= 5 else ctx.time

        # Broadcast the filed report so the validator can inspect the pattern
        await ctx.broadcast(
            f"filed:{rnd_str}:{agent_str}:{outcome}:{tick}".encode(),
        )
        self._reports_filed += 1


def stale_report_factory(
    config: ScenarioConfig,
    plugins: Any,
) -> dict[AgentId, StateMachineAgent]:
    """Create honest traders, a reformed attacker, and an observer.

    Example::

        agents = stale_report_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = task_config.get("rounds", 10)
    good_rounds = task_config.get("good_rounds", 6)

    agents: dict[AgentId, StateMachineAgent] = {}

    trader_count = config.agents.count - 2  # minus attacker and observer
    observer_id = AgentId("observer-0")
    attacker_id = AgentId("attacker-0")

    all_traders: list[AgentId] = []
    for i in range(trader_count):
        all_traders.append(AgentId(f"honest-{i}"))
    all_traders.append(attacker_id)

    for i in range(trader_count):
        aid = AgentId(f"honest-{i}")
        peers = [p for p in all_traders if p != aid]
        agents[aid] = HonestTrader(aid, peers=peers, observer=observer_id, rounds=rounds)

    # The reformed attacker: good first, malicious later
    peers = [p for p in all_traders if p != attacker_id]
    agents[attacker_id] = ReformedAttacker(
        attacker_id,
        peers=peers,
        observer=observer_id,
        rounds=rounds,
        good_rounds=good_rounds,
    )

    agents[observer_id] = TrustObserver(observer_id, attacker_id, rounds=rounds)

    return agents
