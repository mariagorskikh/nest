# SPDX-License-Identifier: Apache-2.0
"""Gossip registry scenario — exercises the partition-honest registry plugin.

Topology:

* ``peer_a-*`` and ``peer_b-*`` are split into two partition groups (see the
  scenario YAML's ``failures.network_partition.groups``).  Cross-group
  transport traffic is dropped by the simulator's ``_should_drop``.
* ``bridge-0`` is **not** in any partition group, so it can talk to
  agents on both sides — it is the only path for cross-group gossip
  convergence.

Each agent runs a ``GossipDriverAgent`` that:

1. ``on_start`` — publishes its own card and arms a periodic ``GOSSIP_TICK``
   self-message via ``ctx.schedule(gossip_interval, ...)``.
2. ``on_message`` — if the payload is a ``GOSSIP_TICK``, runs a gossip
   round and re-arms; if it is a ``GOSSIP_PREFIX``-marked peer message,
   forwards it to ``GossipRegistry.handle_gossip``; otherwise ignores.

Per-agent ``GossipRegistry`` instances are stitched into the simulator via
the ``_agent_plugins`` override channel (see
``nest_core/runner.py``), so each agent really does have its own view —
``in_memory``-style shared-dict behaviour is impossible by construction.

Example::

    from nest_core.runner import ScenarioRunner
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/gossip_registry.yaml"))
    await runner.run()
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId

GOSSIP_TICK = b"GOSSIP_TICK"
"""Payload tag for the periodic self-message that triggers a gossip round."""

DEFAULT_GOSSIP_INTERVAL = 50.0
"""Default ticks between gossip rounds.  Tunable via ``task.config.gossip_interval``."""

TICK_REDUNDANCY = 5
"""How many redundant future wake-ups to schedule per gossip round.

The simulator applies its ``failures.message_drop`` rate to every
``deliver`` event, including the self-deliveries that ``ctx.schedule``
generates.  A single dropped wake-up would otherwise kill the agent's
tick chain.  Scheduling ``TICK_REDUNDANCY`` independent wake-ups at
slightly different delays drops the chain-death probability per round
to ``drop_rate ** TICK_REDUNDANCY`` (≈3e-7 at 5% drop, 5 redundant).
The cost is at most ``TICK_REDUNDANCY × N`` outstanding events, which
is negligible.  Each fire deduplicates: only the first ``GOSSIP_TICK``
in a single ``gossip_interval`` window runs a round.
"""


class GossipDriverAgent(StateMachineAgent):
    """Minimal agent that drives one ``GossipRegistry`` instance.

    The agent does no application-level work: its sole job is to (a)
    publish its own ``AgentCard`` on start, (b) periodically run a
    gossip round, and (c) forward inbound gossip-marked messages to
    the registry's ``handle_gossip``.  All higher-level scenario tasks
    (marketplace, auction, etc.) would compose on top of this without
    modification.

    Example::

        agent = GossipDriverAgent(AgentId("peer_a-0"), capabilities=["sell"])
    """

    def __init__(
        self,
        agent_id: AgentId,
        capabilities: list[str] | None = None,
        gossip_interval: float = DEFAULT_GOSSIP_INTERVAL,
    ) -> None:
        self._id = agent_id
        self._capabilities = capabilities or []
        self._gossip_interval = gossip_interval
        self._last_round_at: float = -1.0

    async def _arm_next_ticks(self, ctx: AgentContext) -> None:
        for i in range(TICK_REDUNDANCY):
            await ctx.schedule(self._gossip_interval + float(i), GOSSIP_TICK)

    async def on_start(self, ctx: AgentContext) -> None:
        """Publish own card; arm the first redundant gossip ticks.

        Example::

            await agent.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        if registry is not None:
            await registry.register(
                AgentCard(
                    agent_id=self._id,
                    name=str(self._id),
                    capabilities=self._capabilities,
                )
            )
        await self._arm_next_ticks(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Dispatch: self-tick → gossip round; gossip-marked → registry; else drop.

        Self-ticks are deduplicated per ``gossip_interval`` window so the
        ``TICK_REDUNDANCY`` redundant wake-ups don't multiplicatively
        amplify gossip traffic.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        if sender == ctx.agent_id and payload == GOSSIP_TICK:
            if ctx.time - self._last_round_at >= self._gossip_interval:
                self._last_round_at = ctx.time
                registry = ctx.plugins.get("registry")
                if registry is not None and hasattr(registry, "gossip_round"):
                    await registry.gossip_round(ctx)
                await self._arm_next_ticks(ctx)
            return
        registry = ctx.plugins.get("registry")
        if registry is not None and hasattr(registry, "handle_gossip"):
            await registry.handle_gossip(sender, payload, ctx)


def gossip_registry_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build the agent fleet for the gossip-registry scenario.

    Roles are read from ``config.agents.roles``; per-agent
    ``GossipRegistry`` instances are injected via the ``_agent_plugins``
    override channel so each agent's view is genuinely its own.

    Example::

        agents = gossip_registry_factory(config, plugins)
    """
    from nest_plugins_reference.registry.gossip import GossipNetwork, GossipRegistry

    task_cfg = config.task.config or {}
    gossip_interval = float(task_cfg.get("gossip_interval", DEFAULT_GOSSIP_INTERVAL))

    all_ids: list[AgentId] = []
    agent_capabilities: dict[AgentId, list[str]] = {}
    for role in config.agents.roles:
        for i in range(role.count):
            aid = AgentId(f"{role.name}-{i}")
            all_ids.append(aid)
            agent_capabilities[aid] = ["gossip_peer"]

    network = GossipNetwork(agent_ids=all_ids)
    per_agent_registry: dict[AgentId, GossipRegistry] = {
        aid: GossipRegistry(aid, network) for aid in all_ids
    }
    agent_plugin_overrides: dict[AgentId, dict[str, Any]] = {
        aid: {"registry": reg} for aid, reg in per_agent_registry.items()
    }
    plugins["_agent_plugins"] = agent_plugin_overrides
    plugins["_gossip_network"] = network
    plugins["_gossip_registries"] = per_agent_registry

    agents: dict[AgentId, Any] = {}
    for aid in all_ids:
        agents[aid] = GossipDriverAgent(
            agent_id=aid,
            capabilities=agent_capabilities[aid],
            gossip_interval=gossip_interval,
        )
    return agents
