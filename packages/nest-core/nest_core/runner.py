# SPDX-License-Identifier: Apache-2.0
"""Scenario runner — wires up plugins, agents, and simulator from a ScenarioConfig.

Example::

    runner = ScenarioRunner(config)
    await runner.run()
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, cast

from nest_core.plugins import PluginRegistry
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import ScenarioEventSink, StateMachineAgent
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId


def _parse_partition_groups(raw: object) -> list[list[str]] | None:
    if not isinstance(raw, list):
        return None
    result: list[list[str]] = []
    for item in raw:  # type: ignore[union-attr]
        if isinstance(item, list):
            result.append([str(v) for v in item])  # type: ignore[union-attr]
    return result if result else None


class PluginResolver(Protocol):
    """Generic layer-plugin resolver consumed by ScenarioRunner."""

    def resolve(self, layer: str, name: str) -> Any:
        """Resolve one configured layer/name pair."""
        ...


class ScenarioRunner:
    """Runs a scenario end-to-end: resolves plugins, creates agents, runs simulation.

    Example::

        config = ScenarioConfig.from_yaml("scenarios/marketplace.yaml")
        runner = ScenarioRunner(config)
        await runner.run()
    """

    def __init__(
        self,
        config: ScenarioConfig,
        registry: PluginRegistry | None = None,
        *,
        participant_override: Mapping[AgentId, StateMachineAgent] | None = None,
        plugin_resolver: PluginResolver | None = None,
        event_sink: ScenarioEventSink | None = None,
    ) -> None:
        if registry is not None and plugin_resolver is not None:
            raise ValueError("registry and plugin_resolver are mutually exclusive")
        self._config = config
        self._plugin_resolver = plugin_resolver or registry or PluginRegistry()
        self._participant_override = dict(participant_override or {})
        self._event_sink = event_sink
        self._resolved_plugins: dict[str, Any] = {}
        self._metrics: dict[str, float] = {}
        self._trace_finalized = False

    @property
    def metrics(self) -> dict[str, float]:
        return self._metrics

    @property
    def resolved_plugins(self) -> dict[str, Any]:
        return self._resolved_plugins

    @property
    def trace_finalized(self) -> bool:
        """Whether this run's Simulator trace closed without raising."""
        return self._trace_finalized

    def _resolve_plugins(self) -> dict[str, Any]:
        """Resolve all layer plugins from the config.

        Example::

            plugins = runner._resolve_plugins()
        """
        layers = self._config.layers
        return {
            "transport": self._plugin_resolver.resolve("transport", layers.transport),
            "comms": self._plugin_resolver.resolve("comms", layers.comms),
            "identity": self._plugin_resolver.resolve("identity", layers.identity),
            "registry": self._plugin_resolver.resolve("registry", layers.registry),
            "auth": self._plugin_resolver.resolve("auth", layers.auth),
            "trust": self._plugin_resolver.resolve("trust", layers.trust),
            "payments": self._plugin_resolver.resolve("payments", layers.payments),
            "coordination": self._plugin_resolver.resolve("coordination", layers.coordination),
            "negotiation": self._plugin_resolver.resolve("negotiation", layers.negotiation),
            "memory": self._plugin_resolver.resolve("memory", layers.memory),
            "privacy": self._plugin_resolver.resolve("privacy", layers.privacy),
            "datafacts": self._plugin_resolver.resolve("datafacts", layers.datafacts),
        }

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

    async def run(self) -> Path:
        """Run the scenario and return the trace file path.

        Example::

            trace_path = await runner.run()
        """
        self._trace_finalized = False
        plugins = self._resolve_plugins()
        self._resolved_plugins = plugins

        agents = self._create_agents(plugins)
        missing_overrides = [
            agent_id for agent_id in self._participant_override if agent_id not in agents
        ]
        if missing_overrides:
            missing = ", ".join(repr(agent_id) for agent_id in missing_overrides)
            raise KeyError(f"participant override targets are not in the scenario: {missing}")
        agents.update(self._participant_override)

        trace_path = Path(self._config.output.trace)
        trace_path.parent.mkdir(parents=True, exist_ok=True)

        failures = self._config.failures
        partition_groups: list[list[str]] | None = None
        if failures.network_partition:
            raw_groups = failures.network_partition.get("groups")
            partition_groups = _parse_partition_groups(raw_groups)

        sim = Simulator(
            seed=self._config.seed,
            trace_path=trace_path,
            message_drop_rate=failures.message_drop,
            byzantine_fraction=failures.byzantine_agents,
            partition_groups=partition_groups,
            partition_heal_at=failures.partition_heal_at_tick,
            partition_start_at_time=failures.partition_start_at_time,
            partition_heal_at_time=failures.partition_heal_at_time,
            plugins=plugins,
            event_sink=self._event_sink,
        )

        primary_error: BaseException | None = None
        primary_traceback: Any = None
        try:
            for agent_id, agent in agents.items():
                sim.add_agent(agent_id, agent)

            # Apply per-agent plugin overrides set by scenario factories
            agent_plugins = cast("dict[AgentId, dict[str, Any]]", plugins.pop("_agent_plugins", {}))
            for agent_id, overrides in agent_plugins.items():
                sim.set_agent_plugins(agent_id, overrides)

            await sim.run(max_ticks=self._config.get_max_ticks())
        except BaseException as exc:
            primary_error = exc
            primary_traceback = exc.__traceback__
        finally:
            cleanup_error: BaseException | None = None
            try:
                sim.close_trace()
            except BaseException as exc:
                cleanup_error = exc
            self._trace_finalized = sim.trace_finalized

        if primary_error is not None:
            raise primary_error.with_traceback(primary_traceback)
        if cleanup_error is not None:
            raise cleanup_error

        if self._config.metrics:
            from nest_core.metrics import compute_metrics, generate_html_report

            self._metrics = compute_metrics(trace_path, self._config.metrics)

            if self._config.output.report:
                report_path = Path(self._config.output.report)
                generate_html_report(trace_path, self._metrics, report_path)

        return trace_path
