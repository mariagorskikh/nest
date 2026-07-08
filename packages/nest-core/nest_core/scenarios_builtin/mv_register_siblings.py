# SPDX-License-Identifier: Apache-2.0
"""MV-Register siblings scenario -- concurrent writes must all survive.

This reuses the concurrent-writers harness (each agent owns its own memory
replica, writes one distinct value to a shared key at start-up, then runs a
fixed number of anti-entropy gossip rounds under a lossy network), but it
exists as a separate scenario because its **success criterion is the opposite**
of ``memory_concurrent_writers``.

``memory_concurrent_writers`` pairs with ``lww_register`` and asks the swarm to
*converge to one winning value*. This scenario pairs with ``mv_register`` and
asks the swarm to *converge to the same set of ``N`` sibling values* -- every
concurrent write kept, none dropped. The ``mv_register_siblings`` trace
validator (:func:`nest_core.validators.validate_mv_sibling_preservation`)
checks that property on the ``final:<state>`` record each agent broadcasts on
stop. Run against ``lww_register`` the same scenario would fail it: each replica
would collapse to a single sibling.

Example::

    agents = mv_register_siblings_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.scenarios_builtin.memory_concurrent_writers import CrdtWriterAgent
from nest_core.sim.agent import StateMachineAgent
from nest_core.types import AgentId


def mv_register_siblings_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create N writer agents, each with its own memory replica of a shared key.

    Instantiates one replica of the configured memory plugin per agent (passing
    the agent id as the replica's stable node id) and registers them as
    per-agent overrides through the ``_agent_plugins`` channel the runner
    understands. Each agent's value is derived from its id, so all writes are
    distinct and the scenario replays byte-identically under a fixed seed.

    Example::

        agents = mv_register_siblings_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 20))
    key = str(task_config.get("key", "shared"))
    count = max(config.agents.count, 4)

    memory_cls = plugins["memory"]
    agent_ids = [AgentId(f"writer-{i}") for i in range(count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}
    for aid in agent_ids:
        agents[aid] = CrdtWriterAgent(
            aid,
            key=key,
            value=f"value-from-{aid}".encode(),
            rounds=rounds,
        )
        overrides[aid] = {"memory": memory_cls(str(aid))}

    plugins["_agent_plugins"] = overrides
    return agents
