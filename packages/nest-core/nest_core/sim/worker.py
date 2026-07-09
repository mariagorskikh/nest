# SPDX-License-Identifier: Apache-2.0
"""Run one worker partition of a distributed scenario."""

from __future__ import annotations
import asyncio
import time
from typing import Any, cast
from nest_core.middleware_registry import MiddlewareRegistry
from nest_core.scenario import ScenarioConfig
from nest_core.sim.network_runner import RoutedTransport, WorkerHttpBridge, check_health
from nest_core.sim.partition import WorkerPartition
from nest_core.sim.plugin_rpc import RemoteRegistry
from nest_core.sim.plugin_wiring import wire_auth_to_sim_clock
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId

_PEER_READY_TIMEOUT_S = 15.0
_POST_RUN_GRACE_S = 0.5


def _resolve_middleware(config: ScenarioConfig) -> list[Any]:
    registry = MiddlewareRegistry()
    return [registry.instantiate(entry.name, entry.config) for entry in config.middleware]


async def _wait_for_peers(bases: set[str], *, timeout: float = _PEER_READY_TIMEOUT_S) -> None:
    if not bases:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        results = await asyncio.gather(*(check_health(base) for base in bases))
        if all(results):
            return
        await asyncio.sleep(0.1)


async def run_worker_partition(
    partition: WorkerPartition,
    config: ScenarioConfig,
    all_agents: dict[AgentId, Any],
    routes: dict[AgentId, str],
    *,
    plugins: dict[str, Any],
    partition_groups: list[list[str]] | None,
    registry_url: str | None = None,
) -> None:
    """Execute a single worker's agents with HTTP routing for remote peers."""
    local_ids = set(partition.agent_ids)
    worker_agents = {aid: all_agents[aid] for aid in partition.agent_ids if aid in all_agents}
    worker_plugins = dict(plugins)
    if registry_url is not None:
        worker_plugins["registry"] = RemoteRegistry(registry_url)
    failures = config.failures
    sim = Simulator(
        seed=partition.seed,
        trace_path=partition.trace_path,
        message_drop_rate=failures.message_drop,
        byzantine_fraction=failures.byzantine_agents,
        partition_groups=partition_groups,
        partition_heal_at=failures.partition_heal_at_tick,
        plugins=worker_plugins,
        parallel=True,
        middleware=_resolve_middleware(config) or None,
    )
    wire_auth_to_sim_clock(worker_plugins, lambda: sim.clock.now)
    bridge = WorkerHttpBridge(sim.event_queue, sim.clock)
    await bridge.start(partition.listen_port, host=partition.bind_host)
    local_bases = {routes[aid] for aid in local_ids if aid in routes}
    remote_bases = {base for base in routes.values() if base not in local_bases}
    await _wait_for_peers(remote_bases)
    if registry_url is not None:
        await _wait_for_peers({registry_url})

    def transport_factory(
        agent_id: AgentId,
        queue: Any,
        clock: Any,
        all_ids: list[AgentId],
    ) -> RoutedTransport:
        return RoutedTransport(
            agent_id,
            queue,
            clock,
            all_ids,
            local_agents=local_ids,
            routes=routes,
        )

    sim.set_transport_factory(transport_factory)
    for agent_id, agent in worker_agents.items():
        sim.add_agent(agent_id, agent)
    agent_plugins = cast("dict[AgentId, dict[str, Any]]", worker_plugins.pop("_agent_plugins", {}))
    for agent_id, overrides in agent_plugins.items():
        if agent_id in local_ids:
            sim.set_agent_plugins(agent_id, overrides)
    try:
        await sim.run(max_ticks=config.get_max_ticks())
        await asyncio.sleep(_POST_RUN_GRACE_S)
    finally:
        await bridge.stop()
