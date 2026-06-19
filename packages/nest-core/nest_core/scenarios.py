# SPDX-License-Identifier: Apache-2.0
"""Scenario factory registry — maps task types to agent factory functions.

Example::

    factory = get_scenario_factory("marketplace")
    agents = factory(config, plugins)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId

ScenarioFactory = Callable[[ScenarioConfig, dict[str, Any]], dict[AgentId, Any]]

_FACTORIES: dict[str, ScenarioFactory] = {}


def register_scenario(name: str, factory: ScenarioFactory) -> None:
    """Register a scenario factory by name.

    Example::

        register_scenario("marketplace", marketplace_factory)
    """
    _FACTORIES[name] = factory


def get_scenario_factory(name: str) -> ScenarioFactory:
    """Look up a registered scenario factory.

    Example::

        factory = get_scenario_factory("marketplace")
    """
    if name not in _FACTORIES:
        _try_load_builtin(name)
    factory = _FACTORIES.get(name)
    if factory is None:
        msg = f"No scenario factory registered for {name!r}"
        raise KeyError(msg)
    return factory


def _try_load_builtin(name: str) -> None:
    if name == "marketplace":
        from nest_core.scenarios_builtin.marketplace import marketplace_factory

        register_scenario("marketplace", marketplace_factory)
    elif name == "auction":
        from nest_core.scenarios_builtin.auction import auction_factory

        register_scenario("auction", auction_factory)
    elif name == "voting":
        from nest_core.scenarios_builtin.voting import voting_factory

        register_scenario("voting", voting_factory)
    elif name == "consensus":
        from nest_core.scenarios_builtin.consensus import consensus_factory

        register_scenario("consensus", consensus_factory)
    elif name == "supply_chain":
        from nest_core.scenarios_builtin.supply_chain import supply_chain_factory

        register_scenario("supply_chain", supply_chain_factory)
    elif name == "reputation":
        from nest_core.scenarios_builtin.reputation import reputation_factory

        register_scenario("reputation", reputation_factory)
    elif name == "memory_concurrent_writers":
        from nest_core.scenarios_builtin.memory_concurrent_writers import (
            memory_concurrent_writers_factory,
        )

        register_scenario("memory_concurrent_writers", memory_concurrent_writers_factory)
    elif name == "comms_versioning":
        from nest_core.scenarios_builtin.comms_versioning import comms_versioning_factory

        register_scenario("comms_versioning", comms_versioning_factory)
