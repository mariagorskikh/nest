# SPDX-License-Identifier: Apache-2.0
"""Discovery scenario — shows the caching resolver self-evicting crashed agents.

Topology (13 agents):

* ``resolver-0`` drives the lookups.
* ``provider-0..11`` register themselves for discovery. Eight are stable (a long
  TTL, as if they keep heartbeating); four are ephemeral (a short TTL and no
  heartbeat, as if they crashed right after registering).

Every provider registers, then the resolver advances the clock past the ephemeral
TTL and does one lookup. The stable providers are still resolvable; the crashed
ones have self-evicted, with no manual deregister. Against the default ``in_memory``
registry all twelve would still resolve — that is the liveness gap this closes.

The scenario is RNG-free, so a given seed replays to a byte-identical trace.

Example::

    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/discovery_resolver.yaml"))
    await runner.run()
    results = runner.resolved_plugins["_discovery_results"]
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Query

RESOLVER = AgentId("resolver-0")
_CAP = "discoverable"
_EPHEMERAL_INDICES = {2, 5, 8, 11}
_STABLE_TTL = 1000.0
_EPHEMERAL_TTL = 10.0
_ADVANCE_TO = 100.0  # past the ephemeral TTL, well before the stable TTL
_REGISTERED = b"REGISTERED"


class ProviderAgent(StateMachineAgent):
    """Registers itself for discovery, then tells the resolver it is up.

    Example::

        provider = ProviderAgent(card)
    """

    def __init__(self, card: AgentCard) -> None:
        self._card = card

    async def on_start(self, ctx: AgentContext) -> None:
        """Register with the shared resolver and ping the resolver agent.

        Example::

            await provider.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        if registry is not None:
            await registry.register(self._card)
        await ctx.send(RESOLVER, _REGISTERED)


class ResolverAgent(StateMachineAgent):
    """After every provider registers, advances time and records who resolves.

    Example::

        resolver = ResolverAgent(registry, provider_ids, 12, results)
    """

    def __init__(
        self,
        registry: Any,
        provider_ids: list[str],
        expected: int,
        results: dict[str, Any],
    ) -> None:
        self._registry = registry
        self._provider_ids = provider_ids
        self._expected = expected
        self._results = results
        self._seen = 0

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Count registrations; on the last, expire ephemerals and record the result.

        Example::

            await resolver.on_message(ctx, AgentId("provider-0"), b"REGISTERED")
        """
        if payload != _REGISTERED:
            return
        self._seen += 1
        if self._seen < self._expected:
            return
        self._registry.set_clock(_ADVANCE_TO)
        live = await self._registry.lookup(Query(capabilities=[_CAP]))
        resolvable = sorted(str(card.agent_id) for card in live)
        evicted = sorted(set(self._provider_ids) - set(resolvable))
        self._results["resolvable"] = resolvable
        self._results["evicted"] = evicted


def discovery_resolver_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build the resolver, providers, and the shared caching-resolver registry.

    Example::

        agents = discovery_resolver_factory(config, plugins)
    """
    from nest_plugins_reference.registry.caching_resolver import CachingResolverRegistry

    counts = {role.name: role.count for role in config.agents.roles}
    n_providers = counts.get("provider", 12)

    registry = CachingResolverRegistry(default_ttl=_STABLE_TTL, clock=0.0)

    provider_ids: list[str] = []
    cards: dict[str, AgentCard] = {}
    for i in range(n_providers):
        aid = f"provider-{i}"
        provider_ids.append(aid)
        ttl = _EPHEMERAL_TTL if i in _EPHEMERAL_INDICES else _STABLE_TTL
        cards[aid] = AgentCard(
            agent_id=AgentId(aid), name=aid, capabilities=[_CAP], metadata={"ttl": ttl}
        )

    results: dict[str, Any] = {"resolvable": [], "evicted": []}
    plugins["_discovery_registry"] = registry
    plugins["_discovery_results"] = results

    # Every agent shares the one resolver instance.
    overrides: dict[AgentId, dict[str, Any]] = {RESOLVER: {"registry": registry}}
    for aid in provider_ids:
        overrides[AgentId(aid)] = {"registry": registry}
    plugins["_agent_plugins"] = overrides

    agents: dict[AgentId, Any] = {
        RESOLVER: ResolverAgent(registry, provider_ids, n_providers, results)
    }
    for aid in provider_ids:
        agents[AgentId(aid)] = ProviderAgent(cards[aid])
    return agents
