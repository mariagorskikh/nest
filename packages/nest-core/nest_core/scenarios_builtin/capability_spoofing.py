# SPDX-License-Identifier: Apache-2.0
"""Capability-spoofing scenario — buyers discover sellers whose claims are not all true.

Honest sellers, always-silent spoofers, and a bait-and-switch seller all
register the identical claim ``capabilities=["sell"]``. Buyers discover
sellers purely through ``registry.lookup(Query(capabilities=["sell"]))`` and
report what they observe back to the registry: a ``sold:`` response before
the round's timeout is a fulfillment, the round's self-scheduled
``TIMEOUT:<round>`` firing first (no response arrived) is a defection.

The same lookup path either keeps returning a silent spoofer forever
(``registry: in_memory``, which has no concept of a defection) or stops
returning it once observed defections cross the threshold
(``registry: verified_capabilities``) -- see
``nest_plugins_reference.validators.capability_validators``.

Identity, trust, and payments layers are intentionally not wired: this
scenario isolates the registry-discovery mechanism from every other check a
real marketplace would layer on top of it.

Example::

    agents = capability_spoofing_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Query

DEFAULT_ROUNDS = 6
DEFAULT_TIMEOUT = 5.0
DEFAULT_PRICE = 50


def _product_from(msg: str) -> str:
    parts = msg.split(":")
    return parts[1] if len(parts) >= 2 else "product"


class HonestSellerAgent(StateMachineAgent):
    """Registers ``sell`` and fulfills every buy request it receives.

    Example::

        agent = HonestSellerAgent(AgentId("honest-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_start(self, ctx: AgentContext) -> None:
        """Register this seller's ``sell`` capability.

        Example::

            await agent.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        if registry is not None:
            await registry.register(
                AgentCard(agent_id=ctx.agent_id, name=str(ctx.agent_id), capabilities=["sell"])
            )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Respond ``sold:`` to every ``buy:`` request.

        Example::

            await agent.on_message(ctx, sender, b"buy:product-0:50")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("buy:"):
            return
        await ctx.send(sender, f"sold:{_product_from(msg)}:{DEFAULT_PRICE}".encode())


class SpoofingSellerAgent(StateMachineAgent):
    """Registers ``sell`` but never responds to a buy request — a pure claim, no fulfillment.

    Example::

        agent = SpoofingSellerAgent(AgentId("spoofer-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_start(self, ctx: AgentContext) -> None:
        """Register the ``sell`` claim this agent will never honor.

        Example::

            await agent.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        if registry is not None:
            await registry.register(
                AgentCard(agent_id=ctx.agent_id, name=str(ctx.agent_id), capabilities=["sell"])
            )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ignore every message — silence is the attack.

        Example::

            await agent.on_message(ctx, sender, b"buy:product-0:50")
        """
        return


class BaitAndSwitchSellerAgent(StateMachineAgent):
    """Registers ``sell``, fulfills exactly one buy request, then goes silent forever.

    Example::

        agent = BaitAndSwitchSellerAgent(AgentId("baitswitch-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._fulfilled_once = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Register the ``sell`` claim this agent will honor exactly once.

        Example::

            await agent.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        if registry is not None:
            await registry.register(
                AgentCard(agent_id=ctx.agent_id, name=str(ctx.agent_id), capabilities=["sell"])
            )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Fulfill the first buy request only; go silent on every one after.

        Example::

            await agent.on_message(ctx, sender, b"buy:product-0:50")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("buy:") or self._fulfilled_once:
            return
        self._fulfilled_once = True
        await ctx.send(sender, f"sold:{_product_from(msg)}:{DEFAULT_PRICE}".encode())


class SpoofCheckBuyerAgent(StateMachineAgent):
    """Buyer that discovers sellers via the registry and reports fulfillment/defection.

    Sends exactly one outstanding ``buy:`` at a time, so a round's outcome
    can never be mis-attributed to a different in-flight round. A ``sold:``
    response before the round's timeout is a fulfillment; the round's
    self-scheduled ``TIMEOUT:<round>`` firing first (no response in time) is
    a defection. A ``reject:`` response is a business decision, not a
    discovery-layer lie, and is reported as neither.

    Example::

        agent = SpoofCheckBuyerAgent(AgentId("buyer-0"), rounds=6)
    """

    def __init__(
        self,
        agent_id: AgentId,
        rounds: int = DEFAULT_ROUNDS,
        timeout: float = DEFAULT_TIMEOUT,
        price: int = DEFAULT_PRICE,
    ) -> None:
        self._id = agent_id
        self._rounds = rounds
        self._timeout = timeout
        self._price = price
        self._round = 0
        self._resolved: set[int] = set()
        self._round_seller: dict[int, AgentId] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Discover a seller and send the first buy request.

        Example::

            await agent.on_start(ctx)
        """
        await self._send_buy(ctx)

    async def _pick_seller(self, ctx: AgentContext) -> AgentId | None:
        """Return a seller discovered via the registry, or ``None`` if none is visible."""
        registry = ctx.plugins.get("registry")
        if registry is None:
            return None
        sellers = await registry.lookup(Query(capabilities=["sell"]))
        if not sellers:
            return None
        return sellers[ctx.rng.randint(0, len(sellers) - 1)].agent_id

    async def _send_buy(self, ctx: AgentContext) -> None:
        """Send a buy request for the current round, or skip it if no seller is visible."""
        seller = await self._pick_seller(ctx)
        if seller is None:
            self._round += 1
            if self._round < self._rounds:
                await self._send_buy(ctx)
            return
        round_num = self._round
        self._round_seller[round_num] = seller
        await ctx.send(seller, f"buy:product-{round_num}:{self._price}".encode())
        await ctx.schedule(self._timeout, f"TIMEOUT:{round_num}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Route a self-timeout to defection handling, everything else to response handling.

        Example::

            await agent.on_message(ctx, sender, b"sold:product-0:50")
        """
        if sender == ctx.agent_id:
            await self._on_timeout(ctx, payload)
        else:
            await self._on_response(ctx, sender, payload)

    async def _on_timeout(self, ctx: AgentContext, payload: bytes) -> None:
        """Report a defection if the round's timeout fires before any response."""
        msg = payload.decode()
        if not msg.startswith("TIMEOUT:"):
            return
        round_num = int(msg.split(":", 1)[1])
        if round_num in self._resolved:
            return
        self._resolved.add(round_num)
        seller = self._round_seller.get(round_num)
        registry = ctx.plugins.get("registry")
        if seller is not None and registry is not None and hasattr(registry, "report_defection"):
            registry.report_defection(seller, "sell")
        self._round += 1
        if self._round < self._rounds:
            await self._send_buy(ctx)

    async def _on_response(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Report a fulfillment on ``sold:``; advance the round on any resolving reply."""
        round_num = self._round
        if round_num in self._resolved or self._round_seller.get(round_num) != sender:
            return
        self._resolved.add(round_num)
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("sold:"):
            registry = ctx.plugins.get("registry")
            if registry is not None and hasattr(registry, "report_fulfillment"):
                registry.report_fulfillment(sender, "sell")
        self._round += 1
        if self._round < self._rounds:
            await self._send_buy(ctx)


def _setup_plugins(plugins: dict[str, Any]) -> None:
    """Instantiate the registry plugin; drop identity/trust/payments (out of scope).

    Example::

        _setup_plugins(plugins)
    """
    if not plugins:
        return
    registry_cls = plugins.get("registry")
    if registry_cls is not None and isinstance(registry_cls, type):
        plugins["registry"] = registry_cls()
    plugins.pop("identity", None)
    plugins.pop("trust", None)
    plugins.pop("payments", None)


def capability_spoofing_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create honest sellers, spoofers, a bait-and-switch seller, and buyers.

    Example::

        agents = capability_spoofing_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = task_config.get("rounds", DEFAULT_ROUNDS)
    timeout = task_config.get("timeout", DEFAULT_TIMEOUT)
    price = task_config.get("price", DEFAULT_PRICE)

    role_counts = {role.name: role.count for role in config.agents.roles}
    honest_count = role_counts.get("honest_seller", 0)
    spoofer_count = role_counts.get("spoofer", 0)
    bait_switch_count = role_counts.get("bait_switch", 0)
    buyer_count = role_counts.get("buyer", 0)

    _setup_plugins(plugins)

    agents: dict[AgentId, StateMachineAgent] = {}
    for i in range(honest_count):
        aid = AgentId(f"honest-{i}")
        agents[aid] = HonestSellerAgent(aid)
    for i in range(spoofer_count):
        aid = AgentId(f"spoofer-{i}")
        agents[aid] = SpoofingSellerAgent(aid)
    for i in range(bait_switch_count):
        aid = AgentId(f"baitswitch-{i}")
        agents[aid] = BaitAndSwitchSellerAgent(aid)
    for i in range(buyer_count):
        aid = AgentId(f"buyer-{i}")
        agents[aid] = SpoofCheckBuyerAgent(aid, rounds=rounds, timeout=timeout, price=price)

    return agents
