# SPDX-License-Identifier: Apache-2.0
"""Sybil reputation scenario — honest traders vs. coordinated Sybil attackers.

Honest agents trade reliably, report cheaters, and earn legitimate reputation.
Sybil attackers run three coordinated attack strategies against a target:

1. **Flood attack**: all Sybil agents send many rapid-fire positive reports for
   the target, attempting ballot-stuffing.
2. **Collusion ring**: Sybil agents mutually boost each other's reputation,
   creating an artificial trust network.
3. **Legitimate cheating**: Sybil agents still cheat in trades (so honest
   agents report them negatively), but flood enough positive reports to try
   to stay above the warning threshold.

Under ``trust: sybil_resistant`` the three attacks are detected and damped.
Under ``trust: score_average`` they succeed trivially.

Example::

    agents = sybil_reputation_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


class HonestTrader(StateMachineAgent):
    """Trades reliably and reports cheaters to the observer.

    Example::

        agent = HonestTrader(AgentId("honest-0"), peers, observer)
    """

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

    async def _select_trusted_peer(self, ctx: AgentContext) -> AgentId:
        """Filter peers by reputation if trust plugin is available."""
        trust = ctx.plugins.get("trust")
        if not trust:
            return ctx.rng.choice(self._peers)

        eligible_peers: list[AgentId] = []
        for peer in self._peers:
            rep = await trust.score(peer)
            if rep.score >= 0.45:
                eligible_peers.append(peer)

        if not eligible_peers:
            return ctx.rng.choice(self._peers)
        return ctx.rng.choice(eligible_peers)

    async def on_start(self, ctx: AgentContext) -> None:
        """Initiate the first trade with a random peer.

        Example::

            await agent.on_start(ctx)
        """
        self._round = 1
        peer = await self._select_trusted_peer(ctx)
        await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle trade, delivery, cheat, and warning messages.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("trade:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                # Check reputation before delivering
                trust = ctx.plugins.get("trust")
                if trust:
                    rep = await trust.score(sender)
                    if rep.score < 0.45:
                        await ctx.send(sender, f"refuse:{rnd}:{self._id}".encode())
                        return
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
                    peer = await self._select_trusted_peer(ctx)
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
                    peer = await self._select_trusted_peer(ctx)
                    await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())
        elif msg.startswith("refuse:"):
            # Refused by peer, try next round with a new trusted peer
            self._round += 1
            if self._round <= self._rounds:
                peer = await self._select_trusted_peer(ctx)
                await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())


class SybilAttacker(StateMachineAgent):
    """Coordinated Sybil attacker: floods, colludes, and cheats.

    Executes three attack patterns:

    - Sends ``sybil_flood_count`` rapid positive reports for the target
    - Mutually boosts every other Sybil attacker (collusion ring)
    - Cheats on trades 50% of the time (like ``MaliciousAgent``)

    Example::

        agent = SybilAttacker(AgentId("sybil-0"), peers, observer, sybil_peers, target)
    """

    def __init__(
        self,
        agent_id: AgentId,
        peers: list[AgentId],
        observer: AgentId,
        sybil_peers: list[AgentId],
        target: AgentId,
        rounds: int = 5,
        flood_count: int = 8,
    ) -> None:
        self._id = agent_id
        self._peers = peers
        self._observer = observer
        self._sybil_peers = sybil_peers
        self._target = target
        self._rounds = rounds
        self._flood_count = flood_count
        self._round = 0
        self._flooded = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Launch flood attack and collusion ring on start.

        Example::

            await agent.on_start(ctx)
        """
        self._round = 1
        # Attack 1: Flood positive reports for the target
        for i in range(self._flood_count):
            await ctx.send(
                self._observer,
                f"report:sybil-{i}:{self._target}:good".encode(),
            )
        self._flooded = True

        # Attack 2: Collusion ring — boost every other Sybil peer
        for peer in self._sybil_peers:
            if peer != self._id:
                await ctx.send(
                    self._observer,
                    f"report:ring:{peer}:good".encode(),
                )

        # Also try to trade normally
        peer = ctx.rng.choice(self._peers)
        await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle trades — cheats 50% of the time.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("trade:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                # Cheat 50% of the time
                if ctx.rng.random() > 0.5:
                    await ctx.send(sender, f"cheat:{rnd}:{self._id}".encode())
                else:
                    await ctx.send(sender, f"deliver:{rnd}:{self._id}".encode())
        elif msg.startswith("deliver:") or msg.startswith("cheat:") or msg.startswith("refuse:"):
            self._round += 1
            if self._round <= self._rounds:
                peer = ctx.rng.choice(self._peers)
                await ctx.send(peer, f"trade:{self._round}:{self._id}".encode())


class SybilObserver(StateMachineAgent):
    """Observer that tracks reports and broadcasts warnings.

    Identical to the standard reputation observer — scores agents and warns
    when they drop below -3.

    Example::

        agent = SybilObserver(AgentId("observer-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._scores: dict[str, int] = {}
        self._warned: set[str] = set()
        # Track reporter -> subject -> count for Sybil detection logging
        self._reporter_counts: dict[str, dict[str, int]] = {}

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Process reports and issue warnings.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("report:"):
            return
        parts = msg.split(":")
        if len(parts) < 4:
            return
        _rnd, agent_str, outcome = parts[1], parts[2], parts[3]

        # Track per-reporter counts
        reporter_str = str(sender)
        if reporter_str not in self._reporter_counts:
            self._reporter_counts[reporter_str] = {}
        self._reporter_counts[reporter_str][agent_str] = (
            self._reporter_counts[reporter_str].get(agent_str, 0) + 1
        )

        if agent_str not in self._scores:
            self._scores[agent_str] = 0
        self._scores[agent_str] += 1 if outcome == "good" else -2

        # Update the trust layer
        trust = ctx.plugins.get("trust")
        if trust:
            from nest_core.types import Evidence

            kind = "positive" if outcome == "good" else "negative"
            await trust.report(
                AgentId(agent_str),
                Evidence(
                    reporter=sender,
                    subject=AgentId(agent_str),
                    kind=kind,
                ),
            )

        if self._scores[agent_str] <= -3 and agent_str not in self._warned:
            self._warned.add(agent_str)
            await ctx.broadcast(f"warning:{_rnd}:{agent_str}:untrusted".encode())

        # Sybil detection: log when a single reporter sends > 5 reports
        # for the same subject (observable in trace for validator)
        count = self._reporter_counts[reporter_str][agent_str]
        if count > 5:
            await ctx.send(
                ctx.agent_id,
                f"sybil_alert:{reporter_str}:{agent_str}:{count}".encode(),
            )


def sybil_reputation_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create honest traders, Sybil attackers, and the observer.

    Example::

        agents = sybil_reputation_factory(config, plugins)
    """
    # Instantiate the trust class if it is not already an instance
    trust_cls = plugins.get("trust")
    if trust_cls and isinstance(trust_cls, type):
        plugins["trust"] = trust_cls()

    task_config = config.task.config
    rounds = task_config.get("rounds", 5)
    sybil_target_str = task_config.get("sybil_target", "honest-0")
    flood_count = task_config.get("sybil_flood_count", 8)

    agents: dict[AgentId, StateMachineAgent] = {}

    # Count agents by role
    honest_count = 16
    sybil_count = 4
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "honest":
                honest_count = role.count
            elif role.name == "sybil":
                sybil_count = role.count

    observer_id = AgentId("observer-0")
    sybil_target = AgentId(sybil_target_str)

    all_traders: list[AgentId] = []
    sybil_ids: list[AgentId] = []

    for i in range(honest_count):
        all_traders.append(AgentId(f"honest-{i}"))
    for i in range(sybil_count):
        aid = AgentId(f"sybil-{i}")
        all_traders.append(aid)
        sybil_ids.append(aid)

    # Create honest agents
    for i in range(honest_count):
        aid = AgentId(f"honest-{i}")
        peers = [p for p in all_traders if p != aid]
        agents[aid] = HonestTrader(aid, peers=peers, observer=observer_id, rounds=rounds)

    # Create Sybil attackers
    for i in range(sybil_count):
        aid = AgentId(f"sybil-{i}")
        peers = [p for p in all_traders if p != aid]
        agents[aid] = SybilAttacker(
            aid,
            peers=peers,
            observer=observer_id,
            sybil_peers=sybil_ids,
            target=sybil_target,
            rounds=rounds,
            flood_count=flood_count,
        )

    # Create observer
    agents[observer_id] = SybilObserver(observer_id)

    return agents
