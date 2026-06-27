# SPDX-License-Identifier: Apache-2.0
"""Marketplace scenario — buyers and sellers exchanging goods.

Buyers discover sellers via the registry plugin, verify identities,
check trust scores, and process payments through the payments layer.
Sellers register their capabilities, verify buyer signatures, check
buyer reputation, and confirm payment before fulfilling orders.

Negotiation is wired in: every buy/sell pair runs through the negotiation
layer (alternating_offers by default) so deals require multiple message
rounds with real counter-offers rather than a single accept/reject exchange.

When plugins are not available (empty plugins dict), agents fall back
to direct messaging for backward compatibility.

Example::

    agents = marketplace_factory(config, plugins)
"""

from __future__ import annotations

import contextlib
import hashlib
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import (
    AgentCard,
    AgentId,
    Evidence,
    Money,
    NegotiationSession,
    PaymentRef,
    Query,
    Terms,
)

# How many ticks a buyer waits for a seller reply before treating the message
# as dropped and retrying with a different seller.
_TIMEOUT_TICKS = 50.0

# Maximum retries per product round when responses are dropped or rejected.
_MAX_RETRIES = 3


class BuyerAgent(StateMachineAgent):
    """A buyer that discovers sellers via registry and purchases using layer plugins.

    Negotiation flow (when the negotiation plugin is available):
    1. Buyer opens a NegotiationSession and sends ``neg_open:<session_id>:<price>``.
    2. Seller responds with ``neg_counter:<session_id>:<price>`` or ``neg_accept:<session_id>``.
    3. Buyer calls ``neg.respond()`` on the counter, loops until accepted or max rounds.
    4. On agreement, buyer sends ``buy_confirm:<session_id>:<price>`` and processes payment.

    Falls back to raw ``buy:`` messages when no negotiation plugin is present.

    Example::

        agent = BuyerAgent(AgentId("buyer-0"), num_sellers=10)
    """

    def __init__(
        self,
        agent_id: AgentId,
        num_sellers: int,
        rounds: int = 10,
        max_open_price: int = 60,
    ) -> None:
        self._id = agent_id
        self._num_sellers = num_sellers
        self._rounds = rounds
        self._max_open_price = max_open_price
        self._purchases = 0
        self._round = 0
        self._payment_counter = 0
        self._retries = 0
        # session_id -> (NegotiationSession, seller_id, last_send_time, retry_count)
        self._open_sessions: dict[str, tuple[NegotiationSession, AgentId, float, int]] = {}
        # session_id -> current timeout sequence number; only the highest fires
        self._timeout_seq: dict[str, int] = {}
        # sent-at tick for each pending non-negotiation send (product -> time)
        self._pending_send_time: float | None = None
        self._pending_seller: AgentId | None = None

    async def _pick_seller(self, ctx: AgentContext) -> AgentId:
        registry = ctx.plugins.get("registry")
        if registry is not None:
            sellers = await registry.lookup(Query(capabilities=["sell"]))
            if sellers:
                card = sellers[ctx.rng.randint(0, len(sellers) - 1)]
                return card.agent_id
        seller_idx = ctx.rng.randint(0, self._num_sellers - 1)
        return AgentId(f"seller-{seller_idx}")

    def _sign_payload(self, ctx: AgentContext, payload: bytes) -> bytes:
        identity = ctx.plugins.get("identity")
        if identity is not None:
            sig = identity.sign(payload)
            return payload + b"|sig:" + sig.value.hex().encode()
        return payload

    def _verify_response(self, ctx: AgentContext, msg: str, sender: AgentId) -> tuple[str, bool]:
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

    async def on_start(self, ctx: AgentContext) -> None:
        await self._start_round(ctx)

    async def _start_round(self, ctx: AgentContext) -> None:
        """Begin a new product round: open a negotiation or send a raw buy."""
        if self._round >= self._rounds:
            return

        seller = await self._pick_seller(ctx)
        # Use this buyer's max_open_price so buyers have varied opening positions
        price = ctx.rng.randint(max(1, self._max_open_price // 2), self._max_open_price)

        payments = ctx.plugins.get("payments")
        if payments is not None:
            bal = payments.balance(ctx.agent_id)
            if bal < price:
                price = bal
            if price <= 0:
                self._round += 1
                await self._start_round(ctx)
                return

        negotiation = ctx.plugins.get("negotiation")
        if negotiation is not None:
            terms = Terms(price=Money(amount=price))
            # Deterministic session ID: buyer-id + round index
            sid = hashlib.sha1(
                f"{self._id}:{self._round}".encode(), usedforsecurity=False
            ).hexdigest()[:16]
            session = await negotiation.open(seller, terms, session_id=sid)
            self._open_sessions[session.id] = (session, seller, ctx.time, 0)
            self._timeout_seq[session.id] = 1
            raw = f"neg_open:{session.id}:{price}".encode()
            msg = self._sign_payload(ctx, raw)
            await ctx.send(seller, msg)
            await ctx.schedule(_TIMEOUT_TICKS, f"timeout:{session.id}:1".encode())
        else:
            raw = f"buy:product-{self._round}:{price}".encode()
            msg = self._sign_payload(ctx, raw)
            self._pending_sell_time = ctx.time
            self._pending_seller = seller
            await ctx.send(seller, msg)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")

        # Self-scheduled timeout messages are never signed — bypass signature check.
        if sender == ctx.agent_id:
            if msg.startswith("timeout:"):
                await self._handle_timeout(ctx, msg)
            return

        body, verified = self._verify_response(ctx, msg, sender)
        if not verified:
            return

        # timeout messages come from self and are handled above; skip here
        if body.startswith("timeout:"):
            return

        # --- negotiation counter-offer ---
        if body.startswith("neg_counter:"):
            parts = body.split(":")
            if len(parts) >= 3:
                session_id = parts[1]
                entry = self._open_sessions.get(session_id)
                if entry is None:
                    return
                session, orig_seller, _, retries = entry

                try:
                    counter_price = int(parts[2])
                except ValueError:
                    return

                negotiation = ctx.plugins.get("negotiation")
                if negotiation is None:
                    return

                from nest_core.types import Money, Terms

                counter_terms = Terms(price=Money(amount=counter_price))
                await negotiation.offer(session, counter_terms)
                resp = await negotiation.respond(session)

                if resp.accepted:
                    # We accept — send confirmation and process payment
                    del self._open_sessions[session_id]
                    self._timeout_seq.pop(session_id, None)
                    agreement = await negotiation.close(session)
                    final_price = counter_price
                    if agreement and agreement.terms.price:
                        final_price = agreement.terms.price.amount

                    raw = f"neg_accept:{session_id}:{final_price}".encode()
                    await ctx.send(orig_seller, self._sign_payload(ctx, raw))
                    await self._process_payment(ctx, orig_seller, final_price)
                    self._purchases += 1
                    self._round += 1
                    await self._start_round(ctx)
                else:
                    # Send our counter-offer back
                    ct = resp.counter_terms
                    new_price = ct.price.amount if ct and ct.price else counter_price
                    self._open_sessions[session_id] = (session, orig_seller, ctx.time, retries)
                    seq = self._timeout_seq.get(session_id, 0) + 1
                    self._timeout_seq[session_id] = seq
                    raw = f"neg_counter:{session_id}:{new_price}".encode()
                    await ctx.send(orig_seller, self._sign_payload(ctx, raw))
                    await ctx.schedule(_TIMEOUT_TICKS, f"timeout:{session_id}:{seq}".encode())
            return

        # --- negotiation: seller accepted our offer ---
        if body.startswith("neg_accept:"):
            parts = body.split(":")
            if len(parts) >= 3:
                session_id = parts[1]
                self._timeout_seq.pop(session_id, None)
                entry = self._open_sessions.pop(session_id, None)
                if entry is None:
                    return
                session, orig_seller, _, _ = entry
                try:
                    final_price = int(parts[2])
                except ValueError:
                    return

                await self._process_payment(ctx, orig_seller, final_price)
                self._purchases += 1
                self._round += 1
                await self._start_round(ctx)
            return

        # --- seller rejected our negotiated open (e.g. trust/budget check failed) ---
        if body.startswith("neg_reject:"):
            parts = body.split(":")
            if len(parts) >= 2:
                session_id = parts[1]
                self._timeout_seq.pop(session_id, None)
                entry = self._open_sessions.pop(session_id, None)
                if entry is None:
                    return
                _, _, _, retries = entry

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
                if retries < _MAX_RETRIES:
                    self._round += 1
                    await self._start_round(ctx)
            return

        # --- legacy non-negotiation path ---
        if body.startswith("sold:"):
            parts = body.split(":")
            if len(parts) >= 3:
                try:
                    price = int(parts[2])
                except ValueError:
                    price = 0
                await self._process_payment(ctx, sender, price)
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
            await self._start_round(ctx)

        elif body.startswith("reject:"):
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
            await self._start_round(ctx)

    async def _handle_timeout(self, ctx: AgentContext, msg: str) -> None:
        """Handle a self-scheduled timeout. Format: timeout:<session_id>:<seq>."""
        parts = msg.split(":")
        if len(parts) < 3:
            return
        session_id = parts[1]
        try:
            incoming_seq = int(parts[2])
        except ValueError:
            return
        current_seq = self._timeout_seq.get(session_id, 0)
        if incoming_seq < current_seq:
            return
        entry = self._open_sessions.get(session_id)
        if entry is not None:
            _, _, sent_at, retries = entry
            if ctx.time - sent_at >= _TIMEOUT_TICKS:
                del self._open_sessions[session_id]
                self._timeout_seq.pop(session_id, None)
                if retries < _MAX_RETRIES:
                    self._round += 1
                    await self._start_round(ctx)

    async def _process_payment(self, ctx: AgentContext, seller: AgentId, price: int) -> None:
        if price <= 0:
            return
        payments = ctx.plugins.get("payments")
        if payments is not None:
            self._payment_counter += 1
            ref = PaymentRef(f"{self._id}-pay-{self._payment_counter}")
            with contextlib.suppress(ValueError):
                await payments.pay(seller, Money(amount=price), ref)

    async def _send_buy(self, ctx: AgentContext) -> None:
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
    """A seller that responds to buy requests and participates in negotiation.

    Negotiation flow (when the negotiation plugin is available):
    1. Receives ``neg_open:<session_id>:<price>`` — opens a local NegotiationSession.
    2. Calls ``neg.respond()`` to decide: accept → ``neg_accept``, counter → ``neg_counter``.
    3. Receives buyer counter-offers in ``neg_counter`` messages, repeats respond loop.
    4. Receives ``neg_accept`` from buyer to confirm the deal.

    Falls back to raw ``sold:``/``reject:`` messages when no negotiation plugin is present.

    Example::

        agent = SellerAgent(AgentId("seller-0"), min_price=20)
    """

    def __init__(self, agent_id: AgentId, min_price: int = 20) -> None:
        self._id = agent_id
        self._min_price = min_price
        self._sales = 0
        self._sold_products: set[str] = set()
        # session_id -> NegotiationSession
        self._open_sessions: dict[str, NegotiationSession] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        registry = ctx.plugins.get("registry")
        if registry is not None:
            card = AgentCard(agent_id=ctx.agent_id, name=str(ctx.agent_id), capabilities=["sell"])
            await registry.register(card)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        body, verified = self._verify_request(ctx, msg, sender)
        if not verified:
            return

        # --- buyer opening a negotiation ---
        if body.startswith("neg_open:"):
            await self._handle_neg_open(ctx, sender, body)
            return

        # --- buyer sending a counter-offer ---
        if body.startswith("neg_counter:"):
            await self._handle_neg_counter(ctx, sender, body)
            return

        # --- buyer accepted our offer; finalise the deal ---
        if body.startswith("neg_accept:"):
            await self._handle_neg_accept(ctx, sender, body)
            return

        # --- legacy non-negotiation path ---
        if body.startswith("buy:"):
            await self._handle_legacy_buy(ctx, sender, body)

    async def _handle_neg_open(self, ctx: AgentContext, buyer: AgentId, body: str) -> None:
        parts = body.split(":")
        if len(parts) < 3:
            return
        session_id = parts[1]
        try:
            offered_price = int(parts[2])
        except ValueError:
            return

        # Hard reject when the buyer's opening bid is below this seller's floor.
        # This produces real rejection_rate > 0 when buyer/seller prices mismatch.
        if offered_price < self._min_price:
            raw = f"neg_reject:{session_id}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, raw))
            return

        if not await self._check_buyer(ctx, buyer, offered_price, session_id):
            return

        negotiation = ctx.plugins.get("negotiation")
        if negotiation is None:
            return

        terms = Terms(price=Money(amount=offered_price))
        session = await negotiation.open(buyer, terms)
        # Override the id so both sides share the buyer's session_id
        session.id = session_id
        self._open_sessions[session_id] = session

        resp = await negotiation.respond(session)
        if resp.accepted:
            final_price = offered_price
            raw = f"neg_accept:{session_id}:{final_price}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, raw))
        else:
            ct = resp.counter_terms
            counter_price = ct.price.amount if ct and ct.price else self._min_price
            raw = f"neg_counter:{session_id}:{counter_price}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, raw))

    async def _handle_neg_counter(self, ctx: AgentContext, buyer: AgentId, body: str) -> None:
        parts = body.split(":")
        if len(parts) < 3:
            return
        session_id = parts[1]
        session = self._open_sessions.get(session_id)
        if session is None:
            return
        try:
            counter_price = int(parts[2])
        except ValueError:
            return

        negotiation = ctx.plugins.get("negotiation")
        if negotiation is None:
            return

        counter_terms = Terms(price=Money(amount=counter_price))
        await negotiation.offer(session, counter_terms)
        resp = await negotiation.respond(session)

        if resp.accepted:
            final_price = counter_price
            del self._open_sessions[session_id]
            raw = f"neg_accept:{session_id}:{final_price}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, raw))
            self._sales += 1
        else:
            ct = resp.counter_terms
            new_price = ct.price.amount if ct and ct.price else self._min_price
            raw = f"neg_counter:{session_id}:{new_price}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, raw))

    async def _handle_neg_accept(self, ctx: AgentContext, buyer: AgentId, body: str) -> None:
        parts = body.split(":")
        if len(parts) < 2:
            return
        session_id = parts[1]
        self._open_sessions.pop(session_id, None)
        self._sales += 1

    async def _handle_legacy_buy(self, ctx: AgentContext, buyer: AgentId, body: str) -> None:
        parts = body.split(":")
        if len(parts) < 3:
            return
        product = parts[1]
        try:
            price = int(parts[2])
        except ValueError:
            price = 0

        if not await self._check_buyer(ctx, buyer, price, product):
            return

        if product in self._sold_products:
            response = f"reject:{product}:{self._min_price}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, response))
        elif price >= self._min_price:
            self._sold_products.add(product)
            self._sales += 1
            response = f"sold:{product}:{price}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, response))
        else:
            response = f"reject:{product}:{self._min_price}".encode()
            await ctx.send(buyer, self._sign_payload(ctx, response))

    async def _check_buyer(self, ctx: AgentContext, buyer: AgentId, price: int, ref: str) -> bool:
        """Return False and send neg_reject when the buyer fails trust/budget checks."""
        trust = ctx.plugins.get("trust")
        if trust is not None:
            rep = await trust.score(buyer)
            if rep.sample_count > 0 and rep.score < 0.2:
                raw = f"neg_reject:{ref}".encode()
                await ctx.send(buyer, self._sign_payload(ctx, raw))
                return False

        payments = ctx.plugins.get("payments")
        if payments is not None:
            bal = payments.balance(buyer)
            if bal < price:
                raw = f"neg_reject:{ref}".encode()
                await ctx.send(buyer, self._sign_payload(ctx, raw))
                return False

        return True

    def _verify_request(self, ctx: AgentContext, msg: str, sender: AgentId) -> tuple[str, bool]:
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

    seller_ids = [AgentId(f"seller-{i}") for i in range(seller_count)]
    buyer_ids = [AgentId(f"buyer-{i}") for i in range(buyer_count)]
    all_ids = seller_ids + buyer_ids

    _instantiate_plugins(plugins, all_ids)

    # Seed a factory RNG from the scenario seed for deterministic agent params.
    import random as _random

    factory_rng = _random.Random(config.seed ^ 0xDEAD)

    for i in range(seller_count):
        aid = seller_ids[i]
        # Seller floors 20–55: centred around 37, enough spread for price variety.
        min_price = factory_rng.randint(20, 55)
        agents[aid] = SellerAgent(aid, min_price=min_price)

    for i in range(buyer_count):
        aid = buyer_ids[i]
        # Buyer openings 25–70: overlaps the seller range so ~30% open below
        # a seller's floor, generating a realistic non-zero rejection_rate.
        max_open = factory_rng.randint(25, 70)
        agents[aid] = BuyerAgent(
            aid, num_sellers=seller_count, rounds=rounds, max_open_price=max_open
        )

    return agents


def _instantiate_plugins(plugins: dict[str, Any], all_ids: list[AgentId]) -> None:
    """Instantiate plugin classes into shared instances in-place.

    Example::

        _instantiate_plugins(plugins, [AgentId("buyer-0"), AgentId("seller-0")])
    """
    if not plugins:
        return

    registry_cls = plugins.get("registry")
    if registry_cls is not None and isinstance(registry_cls, type):
        plugins["registry"] = registry_cls()

    trust_cls = plugins.get("trust")
    if trust_cls is not None and isinstance(trust_cls, type):
        plugins["trust"] = trust_cls()

    # Negotiation — per-agent instances (each agent has its own session store)
    negotiation_cls = plugins.get("negotiation")
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    if negotiation_cls is not None and isinstance(negotiation_cls, type):
        for aid in all_ids:
            agent_plugins.setdefault(aid, {})["negotiation"] = negotiation_cls(aid)
        plugins.pop("negotiation", None)

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

    identity_cls = plugins.get("identity")
    if identity_cls is not None and isinstance(identity_cls, type):
        identities: dict[AgentId, Any] = {}
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"sim-seed")
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)
        for aid, ident in identities.items():
            agent_plugins.setdefault(aid, {})["identity"] = ident
        plugins.pop("identity", None)
