# SPDX-License-Identifier: Apache-2.0
"""Scenario runner — wires up plugins, agents, and simulator from a ScenarioConfig.
Example::
    runner = ScenarioRunner(config)
    await runner.run()
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, cast

from nest_core.log import get_logger
from nest_core.middleware_registry import MiddlewareRegistry
from nest_core.plugins import PluginRegistry
from nest_core.scenario import ScenarioConfig
from nest_core.sim.http_config import require_http_shared_secret
from nest_core.sim.partition import WorkerPartition, partition_agents
from nest_core.sim.plugin_wiring import wire_auth_to_sim_clock
from nest_core.sim.simulator import Simulator
from nest_core.sim.trace_merge import merge_traces
from nest_core.types import AgentId

log = get_logger(__name__)
_MANUAL_TRACE_TIMEOUT_S = 120.0


def parse_partition_groups(raw: object) -> list[list[str]] | None:
    if not isinstance(raw, list):
        return None
    result: list[list[str]] = []
    for item in raw:  # type: ignore[union-attr]
        if isinstance(item, list):
            result.append([str(v) for v in item])  # type: ignore[union-attr]
    return result if result else None


def _registry_advertise_host(config: ScenarioConfig) -> str:
    if config.worker_hosts:
        return config.worker_hosts[0]
    if config.worker_bind not in ("0.0.0.0", ""):
        return config.worker_bind
    return "127.0.0.1"


def build_routes(partitions: list[WorkerPartition]) -> dict[AgentId, str]:
    routes: dict[AgentId, str] = {}
    for part in partitions:
        base = f"http://{part.advertise_host}:{part.listen_port}"
        for aid in part.agent_ids:
            routes[aid] = base
    return routes


def _worker_spec(
    part: WorkerPartition,
    *,
    routes: dict[AgentId, str],
    config_path: Path,
    registry_url: str | None,
) -> dict[str, object]:
    return {
        "worker_id": part.worker_id,
        "listen_port": part.listen_port,
        "bind_host": part.bind_host,
        "advertise_host": part.advertise_host,
        "agent_ids": [str(a) for a in part.agent_ids],
        "routes": {str(k): v for k, v in routes.items()},
        "seed": part.seed,
        "config_path": str(config_path),
        "trace_path": str(part.trace_path.resolve()),
        "registry_url": registry_url,
    }


async def _wait_for_worker_traces(
    partitions: list[WorkerPartition],
    *,
    timeout: float = _MANUAL_TRACE_TIMEOUT_S,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(p.trace_path.exists() and p.trace_path.stat().st_size > 0 for p in partitions):
            return
        await asyncio.sleep(0.2)
    msg = "timed out waiting for worker trace files in manual mode"
    raise TimeoutError(msg)


class ScenarioRunner:
    """Runs a scenario end-to-end: resolves plugins, creates agents, runs simulation.
    Example::
        config = ScenarioConfig.from_yaml("scenarios/marketplace.yaml")
        runner = ScenarioRunner(config)
        await runner.run()
    """

    def __init__(self, config: ScenarioConfig, registry: PluginRegistry | None = None) -> None:
        self._config = config
        self._registry = registry or PluginRegistry()
        self._middleware_registry = MiddlewareRegistry()
        self._resolved_plugins: dict[str, Any] = {}
        self._metrics: dict[str, float] = {}

    @property
    def metrics(self) -> dict[str, float]:
        return self._metrics

    @property
    def resolved_plugins(self) -> dict[str, Any]:
        return self._resolved_plugins

    def _resolve_plugins(self) -> dict[str, Any]:
        """Resolve all layer plugins from the config.
        Example::
            plugins = runner._resolve_plugins()
        """
        layers = self._config.layers
        return {
            "transport": self._registry.resolve("transport", layers.transport),
            "comms": self._registry.resolve("comms", layers.comms),
            "identity": self._registry.resolve("identity", layers.identity),
            "registry": self._registry.resolve("registry", layers.registry),
            "auth": self._registry.resolve("auth", layers.auth),
            "trust": self._registry.resolve("trust", layers.trust),
            "payments": self._registry.resolve("payments", layers.payments),
            "coordination": self._registry.resolve("coordination", layers.coordination),
            "negotiation": self._registry.resolve("negotiation", layers.negotiation),
            "memory": self._registry.resolve("memory", layers.memory),
            "privacy": self._registry.resolve("privacy", layers.privacy),
            "datafacts": self._registry.resolve("datafacts", layers.datafacts),
        }

    def _resolve_middleware(self) -> list[Any]:
        """Resolve configured middleware plugins."""
        return [
            self._middleware_registry.instantiate(entry.name, entry.config)
            for entry in self._config.middleware
        ]

    def _create_agents(self, plugins: dict[str, Any]) -> dict[AgentId, Any]:
        """Create agents based on scenario config and task type.
        When the agent config specifies ``brain`` as ``"llm"`` or ``"shell"``,
        shell agent factories from *nest-shell* are used instead of the default
        state-machine factories.
        Example::
            agents = runner._create_agents(plugins)
        """
        brain = self._config.agents.brain
        if brain in ("llm", "shell"):
            return self._create_shell_agents(plugins)
        from nest_core.scenarios import get_scenario_factory

        factory = get_scenario_factory(self._config.task.type)
        return factory(self._config, plugins)

    def _create_shell_agents(self, plugins: dict[str, Any]) -> dict[AgentId, Any]:
        """Create LLM-backed shell agents for the configured task type.
        Example::
            agents = runner._create_shell_agents(plugins)
        """
        from nest_shell.agent import shell_marketplace_factory
        from nest_shell.factories import (
            shell_auction_factory,
            shell_consensus_factory,
            shell_reputation_factory,
            shell_supply_chain_factory,
            shell_voting_factory,
        )
        from nest_shell.llm import AnthropicBackend, MockLLMBackend, OpenAIBackend

        provider = self._config.agents.llm_provider
        model = self._config.agents.llm_model
        backend: MockLLMBackend | OpenAIBackend | AnthropicBackend
        if provider == "mock" or model == "mock":
            backend = MockLLMBackend()
        elif provider == "anthropic":
            backend = AnthropicBackend(model=model)
        else:
            backend = OpenAIBackend(model=model)
        factories = {
            "marketplace": shell_marketplace_factory,
            "auction": shell_auction_factory,
            "voting": shell_voting_factory,
            "consensus": shell_consensus_factory,
            "supply_chain": shell_supply_chain_factory,
            "reputation": shell_reputation_factory,
        }
        task_type = self._config.task.type
        factory_fn = factories.get(task_type)
        if factory_fn is None:
            msg = f"No shell factory for task type {task_type!r}"
            raise KeyError(msg)
        return factory_fn(self._config, plugins, backend=backend)

    def prepare(self) -> tuple[dict[str, Any], dict[AgentId, Any]]:
        """Resolve plugins and construct agents without running the simulation."""
        plugins = self._resolve_plugins()
        self._resolved_plugins = plugins
        agents = self._create_agents(plugins)
        return plugins, agents

    async def run(self) -> Path:
        """Run the scenario and return the trace file path.
        Example::
            trace_path = await runner.run()
        """
        if self._config.workers > 1:
            return await self._run_distributed()
        return await self._run_single()

    async def _run_single(self) -> Path:
        plugins = self._resolve_plugins()
        self._resolved_plugins = plugins
        trace_path = Path(self._config.output.trace)
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        failures = self._config.failures
        partition_groups: list[list[str]] | None = None
        if failures.network_partition:
            raw_groups = failures.network_partition.get("groups")
            partition_groups = parse_partition_groups(raw_groups)
        sim = Simulator(
            seed=self._config.seed,
            trace_path=trace_path,
            message_drop_rate=failures.message_drop,
            byzantine_fraction=failures.byzantine_agents,
            partition_groups=partition_groups,
            partition_heal_at=failures.partition_heal_at_tick,
            plugins=plugins,
            parallel=self._config.parallel,
            middleware=self._resolve_middleware() or None,
        )
        agents = self._create_agents(plugins)
        wire_auth_to_sim_clock(plugins, lambda: sim.clock.now)
        for agent_id, agent in agents.items():
            sim.add_agent(agent_id, agent)
        agent_plugins = cast("dict[AgentId, dict[str, Any]]", plugins.pop("_agent_plugins", {}))
        for agent_id, overrides in agent_plugins.items():
            sim.set_agent_plugins(agent_id, overrides)
        await sim.run(max_ticks=self._config.get_max_ticks())
        return self._finalize_output(trace_path)

    async def _run_distributed(self) -> Path:
        require_http_shared_secret(self._config)
        plugins = self._resolve_plugins()
        self._resolved_plugins = plugins
        all_agents = self._create_agents(plugins)
        agent_ids = list(all_agents.keys())
        final_trace = Path(self._config.output.trace)
        trace_dir = final_trace.parent / f".{self._config.name}-workers"
        trace_dir.mkdir(parents=True, exist_ok=True)
        partitions = partition_agents(
            agent_ids,
            self._config.workers,
            master_seed=self._config.seed,
            trace_dir=trace_dir,
            bind_host=self._config.worker_bind,
            worker_hosts=self._config.worker_hosts,
        )
        log.info(
            "distributed_start",
            workers=self._config.workers,
            agent_count=len(agent_ids),
            seed=self._config.seed,
            worker_mode=self._config.worker_mode,
        )
        routes = build_routes(partitions)
        import yaml

        config_path = trace_dir / "scenario.yaml"
        with config_path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(self._config.model_dump(), fh)
        routes_path = trace_dir / "routes.json"
        routes_path.write_text(
            json.dumps({str(k): v for k, v in routes.items()}, indent=2),
            encoding="utf-8",
        )
        registry_server = None
        registry_url: str | None = None
        if self._config.distributed.shared_registry:
            from nest_plugins_reference.registry.in_memory import InMemoryRegistry

            from nest_core.sim.plugin_rpc import RegistryRpcServer

            registry_server = RegistryRpcServer(InMemoryRegistry())
            rpc_host = self._config.worker_bind
            rpc_port = 19000 - 1
            await registry_server.start(rpc_host, rpc_port)
            advertise = _registry_advertise_host(self._config)
            registry_url = f"http://{advertise}:{registry_server.port}"
            log.info("registry_rpc_start", url=registry_url)
        for part in partitions:
            spec = _worker_spec(
                part,
                routes=routes,
                config_path=config_path,
                registry_url=registry_url,
            )
            spec_path = trace_dir / f"worker-{part.worker_id}-spec.json"
            spec_path.write_text(json.dumps(spec, indent=2), encoding="utf-8")
        try:
            if self._config.worker_mode == "manual":
                log.info("manual_worker_mode", manifest_dir=str(trace_dir))
                await _wait_for_worker_traces(partitions)
            else:
                procs: list[asyncio.subprocess.Process] = []
                for part in partitions:
                    spec_path = trace_dir / f"worker-{part.worker_id}-spec.json"
                    procs.append(
                        await asyncio.create_subprocess_exec(
                            sys.executable,
                            "-m",
                            "nest_core.sim.worker_main",
                            str(spec_path),
                        )
                    )
                    log.debug(
                        "worker_spawn",
                        worker_id=part.worker_id,
                        agent_count=len(part.agent_ids),
                        port=part.listen_port,
                        bind_host=part.bind_host,
                    )
                    await asyncio.sleep(0.05)
                await asyncio.gather(*(p.wait() for p in procs))
                exit_codes = [p.returncode if p.returncode is not None else -1 for p in procs]
                if any(code != 0 for code in exit_codes):
                    msg = f"worker subprocess failed: exit codes {exit_codes}"
                    raise RuntimeError(msg)
        finally:
            if registry_server is not None:
                await registry_server.stop()
        merge_traces([part.trace_path for part in partitions], final_trace)
        log.info("trace_merge", output=str(final_trace), worker_count=len(partitions))
        return self._finalize_output(final_trace)

    def _finalize_output(self, trace_path: Path) -> Path:
        if self._config.metrics:
            from nest_core.metrics import compute_metrics, generate_html_report

            self._metrics = compute_metrics(trace_path, self._config.metrics)
            if self._config.output.report:
                report_path = Path(self._config.output.report)
                generate_html_report(trace_path, self._metrics, report_path)
        return trace_path
