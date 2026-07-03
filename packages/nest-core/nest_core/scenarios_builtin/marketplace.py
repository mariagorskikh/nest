# SPDX-License-Identifier: Apache-2.0
"""Marketplace scenario — buyers and sellers exchanging goods.

Buyers discover sellers via the registry plugin, verify identities,
check trust scores, and process payments through the payments layer.
Sellers register their capabilities, verify buyer signatures, check
buyer reputation, and confirm payment before fulfilling orders.

When plugins are not available (empty plugins dict), agents fall back
to direct messaging for backward compatibility.

Example::

    agents = marketplace_factory(config, plugins)
"""

from __future__ import annotations

import contextlib
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Evidence, Money, PaymentRef, Query


class BuyerAgent(StateMachineAgent):
    """A buyer that discovers sellers via registry and purchases using layer plugins.

    When plugins are available, the buyer:
    - Discovers sellers through the registry layer
    - Signs buy messages with the identity layer
    - Checks budget via the payments layer before buying
    - Verifies seller response signatures
    - Transfers payment on successful sale
    - Reports interaction quality to the trust layer

    Falls back to direct messaging when plugins are not configured.

    Example::

        agent = BuyerAgent(AgentId("buyer-0"), num_sellers=10)
    """

    def __init__(self, agent_id: AgentId, num_sellers: int, rounds: int = 10) -> None:
        self._id = agent_id
        self._num_sellers = num_sellers
        self._rounds = rounds
        self._purchases = 0
        self._round = 0
        self._payment_counter = 0

    async def _pick_seller(self, ctx: AgentContext) -> AgentId:
        """Pick a seller via registry lookup, falling back to random selection."""
        registry = ctx.plugins.get("registry")
        if registry is not None:
            sellers = await registry.lookup(Query(capabilities=["sell"]))
            if sellers:
                card = sellers[ctx.rng.randint(0, len(sellers) - 1)]
                return card.agent_id

        # Fallback: direct addressing
        seller_idx = ctx.rng.randint(0, self._num_sellers - 1)
        return AgentId(f"seller-{seller_idx}")

    def _sign_payload(self, ctx: AgentContext, payload: bytes) -> bytes:
        """Sign payload and append signature, or return payload unchanged."""
        identity = ctx.plugins.get("identity")
        if identity is not None:
            sig = identity.sign(payload)
            return payload + b"|sig:" + sig.value.hex().encode()
        return payload

    async def on_start(self, ctx: AgentContext) -> None:
        """Discover a seller and send a signed buy request.

        Example::

            await agent.on_start(ctx)
        """
        seller = await self._pick_seller(ctx)
        price = 50

        # Check budget before buying
        payments = ctx.plugins.get("payments")
        if payments is not None:
            bal = payments.balance(ctx.agent_id)
            if bal < price:
                return

        raw = f"buy:product-0:{price}".encode()
        msg = self._sign_payload(ctx, raw)
        await ctx.send(seller, msg)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle seller responses with identity verification, payment, and trust reporting.

        Example::

            await agent.on_message(ctx, sender, b"sold:product-0:50")
        """
        msg = payload.decode("utf-8", errors="replace")

        # Strip signature from response for verification
        body, verified = self._verify_response(ctx, msg, sender)
        if not verified:
            return

        if body.startswith("sold:"):
            parts = body.split(":")
            if len(parts) >= 3:
                try:
                    price = int(parts[2])
                except ValueError:
                    price = 0

                # Process payment
                payments = ctx.plugins.get("payments")
                if payments is not None and price > 0:
                    self._payment_counter += 1
                    ref = PaymentRef(f"{self._id}-pay-{self._payment_counter}")
                    with contextlib.suppress(ValueError):
                        await payments.pay(sender, Money(amount=price), ref)

                # Report positive interaction to trust layer
                trust = ctx.plugins.get("trust")
                if trust is not None:
                    await trust.report(
                        sender,
                        Evidence(
                            reporter=ctx.agent_id,
                            subject=sender,
                            kind="positive",
                            detail="successful_sale",
                        ),
                    )

            self._purchases += 1
            self._round += 1
            if self._round < self._rounds:
                await self._send_buy(ctx)

        elif body.startswith("reject:"):
            # Report negative interaction to trust layer
            trust = ctx.plugins.get("trust")
            if trust is not None:
                await trust.report(
                    sender,
                    Evidence(
                        reporter=ctx.agent_id,
                        subject=sender,
                        kind="negative",
                        detail="rejected_offer",
                    ),
                )

            self._round += 1
            if self._round < self._rounds:
                await self._send_buy(ctx)

    def _verify_response(self, ctx: AgentContext, msg: str, sender: AgentId) -> tuple[str, bool]:
        """Verify response signature if identity plugin is available."""
        identity = ctx.plugins.get("identity")
        if identity is not None and "|sig:" in msg:
            body, sig_hex = msg.rsplit("|sig:", 1)
            try:
                from nest_core.types import Signature

                sig_bytes = bytes.fromhex(sig_hex)
                sig = Signature(signer=sender, value=sig_bytes, algorithm="hmac-sha256")
                valid = identity.verify(body.encode(), sig, sender)
                return body, valid
            except (ValueError, TypeError):
                return msg, False
        return msg, identity is None  # True when no identity plugin (skip check)

    async def _send_buy(self, ctx: AgentContext) -> None:
        """Pick a seller and send a buy request."""
        seller = await self._pick_seller(ctx)
        price = ctx.rng.randint(10, 100)

        payments = ctx.plugins.get("payments")
        if payments is not None:
            bal = payments.balance(ctx.agent_id)
            if bal < price:
                price = bal
            if price <= 0:
                return

        raw = f"buy:product-{self._round}:{price}".encode()
        msg = self._sign_payload(ctx, raw)
        await ctx.send(seller, msg)


class SellerAgent(StateMachineAgent):
    """A seller that responds to buy requests using layer plugins.

    When plugins are available, the seller:
    - Registers capabilities in the registry on start
    - Verifies buyer signatures via the identity layer
    - Checks buyer reputation via the trust layer before accepting
    - Verifies buyer payment capability via the payments layer
    - Signs responses with the identity layer

    Falls back to simple price-check logic when plugins are not configured.

    Example::

        agent = SellerAgent(AgentId("seller-0"), min_price=20)
    """

    def __init__(self, agent_id: AgentId, min_price: int = 20) -> None:
        self._id = agent_id
        self._min_price = min_price
        self._sales = 0
        self._sold_products: set[str] = set()

    async def on_start(self, ctx: AgentContext) -> None:
        """Register this seller in the registry.

        Example::

            await agent.on_start(ctx)
        """
        registry = ctx.plugins.get("registry")
        if registry is not None:
            card = AgentCard(
                agent_id=ctx.agent_id,
                name=str(ctx.agent_id),
                capabilities=["sell"],
            )
            await registry.register(card)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle buy requests with identity verification, trust check, and payment verification.

        Example::

            await agent.on_message(ctx, sender, b"buy:product-0:50")
        """
        msg = payload.decode("utf-8", errors="replace")

        # Strip and verify buyer signature
        body, verified = self._verify_request(ctx, msg, sender)
        if not verified:
            return

        if body.startswith("buy:"):
            parts = body.split(":")
            if len(parts) >= 3:
                product = parts[1]
                try:
                    price = int(parts[2])
                except ValueError:
                    price = 0

                # Check buyer trust score
                trust = ctx.plugins.get("trust")
                if trust is not None:
                    rep = await trust.score(sender)
                    # Reject buyers with very low reputation (below 0.2)
                    if rep.sample_count > 0 and rep.score < 0.2:
                        response = f"reject:{product}:{self._min_price}".encode()
                        response = self._sign_payload(ctx, response)
                        await ctx.send(sender, response)
                        return

                # Check buyer can afford the purchase
                payments = ctx.plugins.get("payments")
                if payments is not None:
                    bal = payments.balance(sender)
                    if bal < price:
                        response = f"reject:{product}:{self._min_price}".encode()
                        response = self._sign_payload(ctx, response)
                        await ctx.send(sender, response)
                        return

                if product in self._sold_products:
                    response = f"reject:{product}:{self._min_price}".encode()
                    response = self._sign_payload(ctx, response)
                    await ctx.send(sender, response)
                elif price >= self._min_price:
                    self._sold_products.add(product)
                    self._sales += 1
                    response = f"sold:{product}:{price}".encode()
                    response = self._sign_payload(ctx, response)
                    await ctx.send(sender, response)
                else:
                    response = f"reject:{product}:{self._min_price}".encode()
                    response = self._sign_payload(ctx, response)
                    await ctx.send(sender, response)

    def _verify_request(self, ctx: AgentContext, msg: str, sender: AgentId) -> tuple[str, bool]:
        """Verify request signature if identity plugin is available."""
        identity = ctx.plugins.get("identity")
        if identity is not None and "|sig:" in msg:
            body, sig_hex = msg.rsplit("|sig:", 1)
            try:
                from nest_core.types import Signature

                sig_bytes = bytes.fromhex(sig_hex)
                sig = Signature(signer=sender, value=sig_bytes, algorithm="hmac-sha256")
                valid = identity.verify(body.encode(), sig, sender)
                return body, valid
            except (ValueError, TypeError):
                return msg, False
        return msg, identity is None

    def _sign_payload(self, ctx: AgentContext, payload: bytes) -> bytes:
        """Sign payload and append signature, or return payload unchanged."""
        identity = ctx.plugins.get("identity")
        if identity is not None:
            sig = identity.sign(payload)
            return payload + b"|sig:" + sig.value.hex().encode()
        return payload


def marketplace_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create buyer and seller agents for the marketplace scenario.

    Instantiates shared plugin instances (registry, trust, payments) and
    per-agent identity instances from the resolved plugin classes. The
    instances are stored back into the ``plugins`` dict so the simulator
    can pass them to agent contexts.

    When plugin classes are not available or ``plugins`` is empty, agents
    fall back to direct messaging for backward compatibility.

    Example::

        agents = marketplace_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = task_config.get("rounds", 10)

    agents: dict[AgentId, StateMachineAgent] = {}

    if config.agents.roles:
        buyer_count = 0
        seller_count = 0
        for role in config.agents.roles:
            if role.name == "buyer":
                buyer_count = role.count
            elif role.name == "seller":
                seller_count = role.count
    else:
        buyer_count = config.agents.count // 2
        seller_count = config.agents.count - buyer_count

    # Collect all agent IDs
    seller_ids = [AgentId(f"seller-{i}") for i in range(seller_count)]
    buyer_ids = [AgentId(f"buyer-{i}") for i in range(buyer_count)]
    all_ids = seller_ids + buyer_ids

    # Instantiate shared plugins from resolved classes
    _instantiate_plugins(plugins, all_ids)

    for i in range(seller_count):
        aid = seller_ids[i]
        min_price = 10 + (i * 5) % 50
        agents[aid] = SellerAgent(aid, min_price=min_price)

    for i in range(buyer_count):
        aid = buyer_ids[i]
        agents[aid] = BuyerAgent(aid, num_sellers=seller_count, rounds=rounds)

    return agents


def _instantiate_plugins(plugins: dict[str, Any], all_ids: list[AgentId]) -> None:
    """Instantiate plugin classes into shared instances in-place.

    Replaces class references in *plugins* with live instances that the
    simulator will pass to every agent context.  Safe to call when
    *plugins* is empty — it simply returns.

    Per-agent identity instances are stored under ``plugins["_agent_plugins"]``
    so the runner can apply them as per-agent overrides in the simulator.

    Example::

        _instantiate_plugins(plugins, [AgentId("buyer-0"), AgentId("seller-0")])
    """
    if not plugins:
        return

    # Registry — shared instance
    registry_cls = plugins.get("registry")
    if registry_cls is not None and isinstance(registry_cls, type):
        plugins["registry"] = registry_cls()

    # Trust — shared instance
    trust_cls = plugins.get("trust")
    if trust_cls is not None and isinstance(trust_cls, type):
        plugins["trust"] = trust_cls()

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})

    # Payments — per-agent handles over a shared ledger, so pay() debits the
    # calling agent while every participant observes the same balances.
    payments_cls = plugins.get("payments")
    if payments_cls is not None and isinstance(payments_cls, type):
        balances: dict[AgentId, int] = {aid: 1000 for aid in all_ids}
        payment_records: dict[PaymentRef, Any] = {}
        system_id = AgentId("system")
        try:
            plugins["payments"] = payments_cls(
                system_id,
                initial_balance=0,
                balances=balances,
                payments=payment_records,
            )
            for aid in all_ids:
                agent_plugins.setdefault(aid, {})["payments"] = payments_cls(
                    aid,
                    initial_balance=0,
                    balances=balances,
                    payments=payment_records,
                )
        except TypeError:
            plugins["payments"] = payments_cls(system_id, initial_balance=0)

    # Identity — per-agent instances that can verify all peers.
    # Each agent gets its own DidKeyIdentity for signing, with all
    # peers registered so it can also verify any other agent.
    identity_cls = plugins.get("identity")
    if identity_cls is not None and isinstance(identity_cls, type):
        identities: dict[AgentId, Any] = {}
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"sim-seed")

        # Cross-register all peers in every identity instance using public keys only.
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)

        # Store per-agent overrides for the runner to apply
        for aid, ident in identities.items():
            agent_plugins.setdefault(aid, {})["identity"] = ident

        # Remove the class from the shared plugins — identity is per-agent
        plugins.pop("identity", None)
