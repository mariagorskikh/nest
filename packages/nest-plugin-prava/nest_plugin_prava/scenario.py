# SPDX-License-Identifier: Apache-2.0
"""Policy commerce scenario: quote, pay, verify, and handle the refusal.

Layer-agnostic. It drives whatever payments plugin the scenario selects,
so it runs against ``prepaid_credits`` with no console and no money, and
against ``prava`` to move real sandbox funds under a policy mandate.

Each buyer is assigned a service. One is priced inside policy and settles;
another is deliberately priced above the per-charge cap so the run also
exercises the refusal path. A refusal is a valid outcome here, not an
error: it is what a bounded agent is supposed to do.

Example::

    agents = policy_commerce_factory(config, plugins)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.sim.agent import StateMachineAgent
from nest_core.types import AgentId, PaymentRef, ServiceRef

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig
    from nest_core.sim.agent import AgentContext

DEFAULT_SERVICES = ["gpu-compute-small", "gpu-compute-xl"]


class PolicyBuyer(StateMachineAgent):
    """Buys one service: quote, pay, verify, and report what happened."""

    def __init__(self, seller: AgentId, service: str) -> None:
        self._seller = seller
        self._service = service

    async def on_start(self, ctx: AgentContext) -> None:
        """Run the full payment cycle once, reporting the outcome."""
        payments = ctx.plugins.get("payments")
        if payments is None:
            return

        try:
            quote = await payments.quote(ServiceRef(self._service))
        except Exception as exc:  # noqa: BLE001 - report, never crash the run
            await self._report(ctx, f"quote-refused {self._service}: {exc}")
            return

        ref = PaymentRef(f"{ctx.agent_id}-{self._service}")
        try:
            receipt = await payments.pay(self._seller, quote.price, ref)
        except Exception as exc:  # noqa: BLE001 - refusals are expected here
            await self._report(ctx, f"pay-refused {self._service}: {exc}")
            return

        status = await payments.verify_payment(ref)
        await self._report(
            ctx,
            f"paid {receipt.amount.amount} {receipt.amount.currency} "
            f"for {self._service} status={status.value}",
        )

    async def _report(self, ctx: AgentContext, line: str) -> None:
        await ctx.send(self._seller, line.encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Buyers do not expect replies."""

    async def on_stop(self, ctx: AgentContext) -> None:
        """Nothing to tear down."""


class PolicySeller(StateMachineAgent):
    """Receives buyer outcomes so they land in the trace."""

    async def on_start(self, ctx: AgentContext) -> None:
        """Sellers wait to be paid."""

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Acknowledge whatever the buyer reported."""
        await ctx.send(sender, b"ack")

    async def on_stop(self, ctx: AgentContext) -> None:
        """Nothing to tear down."""


def policy_commerce_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create buyers and sellers for the policy_commerce scenario.

    ``task.config.services`` assigns a service per buyer, cycling if there
    are more buyers than services.

    Example::

        agents = policy_commerce_factory(config, plugins)
    """
    services = list(config.task.config.get("services") or DEFAULT_SERVICES)
    counts = {role.name: role.count for role in config.agents.roles}
    num_buyers = counts.get("buyer", 1)
    num_sellers = max(1, counts.get("seller", 1))

    # The runner hands the factory the payments CLASS; instantiating it is
    # the scenario's job (see scenarios_builtin/marketplace.py). Without
    # this, agents call unbound methods and every purchase silently fails.
    payments_cls = plugins.get("payments")
    if isinstance(payments_cls, type):
        try:
            plugins["payments"] = payments_cls(
                AgentId("system"),
                initial_balance=0,
                balances={},
                payments={},
            )
        except TypeError:
            plugins["payments"] = payments_cls(AgentId("system"))

    agents: dict[AgentId, StateMachineAgent] = {}
    for index in range(num_sellers):
        agents[AgentId(f"seller-{index}")] = PolicySeller()
    for index in range(num_buyers):
        seller = AgentId(f"seller-{index % num_sellers}")
        agents[AgentId(f"buyer-{index}")] = PolicyBuyer(
            seller=seller,
            service=services[index % len(services)],
        )
    return agents
