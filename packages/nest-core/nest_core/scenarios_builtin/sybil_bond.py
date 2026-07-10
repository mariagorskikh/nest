# SPDX-License-Identifier: Apache-2.0
"""Sybil-bond scenario — a free-minted swarm attacks a ledger-backed trust root.

This scenario makes the configured **trust plugin load-bearing** and gives the
Sybils real teeth: they *attempt* to bond, not merely abstain. A shared credit
ledger (the scarcity anchor) endows honest traders but leaves the Sybil swarm
broke.

* **Honest traders** hold credits, bond them, and endorse one another.
* **Sybil attackers** cross-endorse their clique to fake a history **and each
  sends a huge ``bond:`` request** — but they hold zero credits, so a
  credit-backed ledger reserves nothing and their trust root never opens.

The point the earlier version missed: the Sybils here *try* the attack the
security review raised ("just send ``bond:1000000``"). Under ``score_average``
the clique promotes itself to the top (validators FAIL). Under ``bonded_trust``
with a scarce ledger, every unfunded Sybil's bond request is rejected and it
stays pinned at the untrusted floor (validators PASS) — the defense is
*enforced*, not assumed.

Example::

    agents = sybil_bond_factory(config, plugins)
"""

from __future__ import annotations

import inspect
from typing import Any

from nest_plugins_reference.trust.stake_ledgers import CreditBackedLedger

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Evidence

_FINALIZE = b"finalize"
_SYBIL_BID = 1_000_000  # what a Sybil *tries* to bond with an empty wallet


class HonestTrader(StateMachineAgent):
    """Bonds its own credits, then endorses its honest peers.

    Example::

        agent = HonestTrader(AgentId("honest-0"), [AgentId("honest-1")], AgentId("observer-0"), 100)
    """

    def __init__(
        self,
        agent_id: AgentId,
        peers: list[AgentId],
        observer: AgentId,
        bond: int,
    ) -> None:
        self._id = agent_id
        self._peers = peers
        self._observer = observer
        self._bond = bond

    async def on_start(self, ctx: AgentContext) -> None:
        """Bond own credits with the observer, then endorse each honest peer.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.send(self._observer, f"bond:{self._bond}".encode())
        for peer in self._peers:
            await ctx.send(self._observer, f"endorse:{peer}".encode())


class SybilAttacker(StateMachineAgent):
    """Tries to bond big on an empty wallet, and cross-endorses its own clique.

    Example::

        agent = SybilAttacker(AgentId("sybil-0"), [AgentId("sybil-1")], AgentId("observer-0"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        peers: list[AgentId],
        observer: AgentId,
    ) -> None:
        self._id = agent_id
        self._peers = peers
        self._observer = observer

    async def on_start(self, ctx: AgentContext) -> None:
        """Bid a huge bond on an empty wallet, then cross-endorse the clique.

        Example::

            await agent.on_start(ctx)
        """
        # The attack the security review raised: claim a huge bond with no credits.
        await ctx.send(self._observer, f"bond:{_SYBIL_BID}".encode())
        for peer in self._peers:
            await ctx.send(self._observer, f"endorse:{peer}".encode())


class TrustObserver(StateMachineAgent):
    """Drives the injected trust plugin and broadcasts every agent's final score.

    Example::

        observer = TrustObserver(AgentId("observer-0"), trust, [AgentId("honest-0")])
    """

    def __init__(
        self,
        agent_id: AgentId,
        trust: Any,
        subjects: list[AgentId],
    ) -> None:
        self._id = agent_id
        self._trust = trust
        self._subjects = subjects

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the finalize tick that scores and broadcasts every agent.

        Example::

            await observer.on_start(ctx)
        """
        # Finalize after every start-time bond/endorsement has been processed.
        await ctx.schedule(1.0, _FINALIZE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Apply a bond/endorsement to the trust plugin, or finalize and broadcast.

        Example::

            await observer.on_message(ctx, sender, b"bond:100")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg == "finalize":
            for agent in self._subjects:
                rep = await self._trust.score(agent)
                await ctx.broadcast(f"trustscore:{agent}:{rep.score:.4f}".encode())
            return
        if msg.startswith("bond:"):
            await self._trust.stake(sender, int(msg.split(":")[1]))
        elif msg.startswith("endorse:"):
            subject = AgentId(msg.split(":", 1)[1])
            await self._trust.report(
                subject,
                Evidence(reporter=sender, subject=subject, kind="positive"),
            )


def sybil_bond_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create funded honest traders, a broke Sybil swarm, and a trust observer.

    A shared credit ledger endows honest traders with ``honest_bond`` credits and
    leaves Sybils with zero. The observer shares one instance of the configured
    ``trust`` plugin, injected with a :class:`CreditBackedLedger` when the plugin
    accepts one (``bonded_trust``); baselines like ``score_average`` are
    constructed plainly.

    Example::

        agents = sybil_bond_factory(config, plugins)
    """
    task_config = config.task.config
    honest_bond = int(task_config.get("honest_bond", 100))

    honest_count = 5
    sybil_count = 20
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "honest":
                honest_count = role.count
            elif role.name == "sybil":
                sybil_count = role.count

    honest_ids = [AgentId(f"honest-{i}") for i in range(honest_count)]
    sybil_ids = [AgentId(f"sybil-{i}") for i in range(sybil_count)]
    observer_id = AgentId("observer-0")
    subjects = honest_ids + sybil_ids

    # Scarcity anchor: honest agents are funded, the Sybil swarm is broke.
    balances: dict[AgentId, int] = {aid: honest_bond for aid in honest_ids}
    ledger = CreditBackedLedger(balances)

    trust_cls = plugins["trust"]
    # Inject the ledger only if the plugin declares it — checking the signature
    # (rather than catching TypeError) so a real bug inside __init__ isn't masked
    # into a silent unbacked construction.
    if "ledger" in inspect.signature(trust_cls).parameters:
        trust = trust_cls(ledger=ledger)
    else:
        trust = trust_cls()  # baselines (e.g. score_average) take no ledger

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in honest_ids:
        peers = [p for p in honest_ids if p != aid]
        agents[aid] = HonestTrader(aid, peers=peers, observer=observer_id, bond=honest_bond)
    for aid in sybil_ids:
        peers = [p for p in sybil_ids if p != aid]
        agents[aid] = SybilAttacker(aid, peers=peers, observer=observer_id)
    agents[observer_id] = TrustObserver(observer_id, trust=trust, subjects=subjects)

    return agents
