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
    elif name == "identity_rotation":
        from nest_core.scenarios_builtin.identity_rotation import (
            identity_rotation_factory,
        )

        register_scenario("identity_rotation", identity_rotation_factory)
    elif name == "gossip_registry":
        from nest_core.scenarios_builtin.gossip_registry import gossip_registry_factory

        register_scenario("gossip_registry", gossip_registry_factory)
    elif name == "memory_concurrent_writers":
        from nest_core.scenarios_builtin.memory_concurrent_writers import (
            memory_concurrent_writers_factory,
        )

        register_scenario("memory_concurrent_writers", memory_concurrent_writers_factory)
    elif name == "comms_versioning":
        from nest_core.scenarios_builtin.comms_versioning import comms_versioning_factory

        register_scenario("comms_versioning", comms_versioning_factory)
    elif name == "comms_downgrade":
        from nest_core.scenarios_builtin.comms_downgrade import comms_downgrade_factory

        register_scenario("comms_downgrade", comms_downgrade_factory)
    elif name == "receipt_reputation":
        from nest_core.scenarios_builtin.receipt_reputation import (
            receipt_reputation_factory,
        )

        register_scenario("receipt_reputation", receipt_reputation_factory)
    elif name == "empic_payments":
        from nest_core.scenarios_builtin.empic_payments import empic_payments_factory

        register_scenario("empic_payments", empic_payments_factory)
    elif name == "multi_attribute_market":
        from nest_core.scenarios_builtin.multi_attribute_market import (
            multi_attribute_market_factory,
        )

        register_scenario("multi_attribute_market", multi_attribute_market_factory)
    elif name == "provenance_supply_chain":
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            provenance_supply_chain_factory,
        )

        register_scenario("provenance_supply_chain", provenance_supply_chain_factory)
    elif name == "bft_hotstuff":
        from nest_core.scenarios_builtin.bft_hotstuff import bft_hotstuff_factory

        register_scenario("bft_hotstuff", bft_hotstuff_factory)
    elif name == "escrow_marketplace":
        from nest_core.scenarios_builtin.escrow_marketplace import (
            escrow_marketplace_factory,
        )

        register_scenario("escrow_marketplace", escrow_marketplace_factory)
    elif name == "failure_detection":
        from nest_core.scenarios_builtin.failure_detection import (
            failure_detection_factory,
        )

        register_scenario("failure_detection", failure_detection_factory)
    elif name == "parc_migration":
        from nest_core.scenarios_builtin.parc_migration import (
            parc_migration_factory,
        )

        register_scenario("parc_migration", parc_migration_factory)
    elif name == "rogue_trusted_agent":
        from nest_core.scenarios_builtin.rogue_trusted_agent import (
            rogue_trusted_agent_factory,
        )

        register_scenario("rogue_trusted_agent", rogue_trusted_agent_factory)
