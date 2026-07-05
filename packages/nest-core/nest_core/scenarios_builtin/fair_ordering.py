# SPDX-License-Identifier: Apache-2.0
"""Fair-ordering scenario -- a batch of orders sequenced under a front-running threat.

Traders each broadcast their order in ``on_start`` (so arrival order is authored
by the engine's monotonic ``corr`` id, not by the sequencer), and submit it to
the coordination plugin. The sequencer finalizes the batch and broadcasts the
execution order:

* **submit**  -- ``order:submit:agent=..:order=..``  (engine-``corr``-ordered)
* **execute** -- ``order:execute:pos=k:agent=..``     (the sequencer's output)

The ``fair_ordering`` validators reconstruct the neutral arrival order from the
``corr`` ids of the ``submit`` broadcasts and assert the ``execute`` order
matches it -- proving the sequencer did not reorder (front-run).

* Under ``coordination: fifo_fair`` the execute order == arrival order -> PASS.
* Under ``coordination: predatory`` the sequencer reorders by price -> FAIL.
* Under the default ``contract_net`` (no ``submit_order``/``finalize``) no
  ``order:*`` events are emitted -> FAIL ("no fair-ordering observed").

Example::

    agents = fair_ordering_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_ROUND = "round-orders"
_TICK_FINALIZE = 5.0


def _emit(kind: str, **fields: Any) -> bytes:
    """Build a structured ``order:<kind>:k=v:...`` broadcast payload.

    Example::

        _emit("submit", agent="trader-0", order="buy_120")
    """
    body = ":".join(f"{k}={v}" for k, v in fields.items())
    return (f"order:{kind}:{body}" if body else f"order:{kind}").encode()


class TraderAgent(StateMachineAgent):
    """Broadcasts and submits its order in ``on_start`` (engine-authored arrival).

    Example::

        agent = TraderAgent(AgentId("trader-0"), price=120)
    """

    def __init__(self, agent_id: AgentId, price: int) -> None:
        self._id = agent_id
        self._order = f"buy_{price}"

    async def on_start(self, ctx: AgentContext) -> None:
        coord = ctx.plugins.get("coordination")
        if coord is None or not hasattr(coord, "submit_order"):
            return  # naive plugin (e.g. contract_net): no fair-ordering -> validators FAIL
        await coord.submit_order(_ROUND, self._id, self._order)
        await ctx.broadcast(_emit("submit", agent=self._id, order=self._order))


class SequencerAgent(StateMachineAgent):
    """Finalizes the batch after all orders arrive and broadcasts the execution order.

    Example::

        agent = SequencerAgent(AgentId("sequencer"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_start(self, ctx: AgentContext) -> None:
        coord = ctx.plugins.get("coordination")
        if coord is None or not hasattr(coord, "finalize"):
            return
        await ctx.schedule(_TICK_FINALIZE, b"ctl:finalize")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if payload.decode("utf-8", errors="replace") != "ctl:finalize":
            return
        coord = ctx.plugins.get("coordination")
        if coord is None or not hasattr(coord, "finalize"):
            return
        batch = await coord.finalize(_ROUND)
        for pos, (agent, _order) in enumerate(batch):
            await ctx.broadcast(_emit("execute", pos=pos, agent=agent))


def fair_ordering_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build a sequencer plus N traders sharing one coordination instance.

    Trader prices are spread so a price-reordering (predatory) sequencer
    produces a visibly different execution order than the arrival order.

    Example::

        agents = fair_ordering_factory(config, plugins)
    """
    n_traders = 8
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "trader":
                n_traders = role.count

    sequencer_id = AgentId("sequencer")
    agents: dict[AgentId, StateMachineAgent] = {sequencer_id: SequencerAgent(sequencer_id)}
    for i in range(n_traders):
        tid = AgentId(f"trader-{i}")
        price = 100 + (i * 7) % 50  # spread; arrival index uncorrelated with price
        agents[tid] = TraderAgent(tid, price=price)

    # One shared coordination instance for every agent. Plugins that need a
    # per-agent id (e.g. contract_net) get one instance each; they lack the
    # fair-ordering API, so no order:* events are emitted and validators FAIL.
    coord_cls = plugins["coordination"]
    try:
        shared = coord_cls()
        overrides: dict[AgentId, dict[str, Any]] = {aid: {"coordination": shared} for aid in agents}
    except TypeError:
        overrides = {aid: {"coordination": coord_cls(aid)} for aid in agents}
    plugins["_agent_plugins"] = overrides

    return agents
