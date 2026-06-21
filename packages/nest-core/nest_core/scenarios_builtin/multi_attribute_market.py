# SPDX-License-Identifier: Apache-2.0
"""Multi-attribute market scenario — price + deadline bilateral negotiation.

Ten buyer-seller pairs each negotiate over two issues, *price* and *deadline*,
driving the configured ``negotiation`` plugin. The pairs are seeded with
deliberately *asymmetric* preferences (Raiffa's integrative / logrolling
structure): the buyer is almost entirely price-driven while the seller is almost
entirely deadline-driven. A price-only haggler leaves value on the table here;
a multi-attribute negotiator can trade the issue each side cares little about
(buyer concedes the deadline, seller concedes the price) and reach a
Pareto-efficient deal.

Every exchanged bundle and each agent's *otherwise private* utility parameters
are written to the trace as colon-delimited frames, so an offline validator can
reconstruct each agent's utility and check the agreement for Pareto-optimality.
Frame grammar (floats are formatted to 6 dp for byte-determinism)::

    mautil:<agent>:<side>:<w_price>:<w_deadline>:<plo>:<phi>:<dlo>:<dhi>:<reservation>
    offer:<sid>:<agent>:<side>:<round>:<price>:<deadline>
    agree:<sid>:<price>:<deadline>:<accepting_agent>
    breakdown:<sid>:<rounds>

The whole bargaining loop runs synchronously inside each buyer's ``on_start``,
so there is no cross-agent event interleaving to make non-deterministic; the
frames are still emitted as real ``ctx.send`` calls, so the trace is authentic.

Example::

    from nest_core.runner import ScenarioRunner
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/multi_attribute_market.yaml"))
    await runner.run()
"""

from __future__ import annotations

import random
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, Terms

N_PAIRS = 10
"""Number of independent buyer-seller negotiations."""

PRICE_RANGE = (50, 150)
"""Feasible price interval (credits), shared by every pair."""

DEADLINE_RANGE = (1, 30)
"""Feasible deadline interval (days), shared by every pair."""

PATIENCE = 0.9
"""Concession discount per round (see ParetoNegotiation aspiration schedule)."""

RESERVATION = 0.0
"""Walk-away utility floor for every agent."""

MAX_ROUNDS = 12
"""Maximum bargaining rounds before a negotiation is declared a breakdown."""

WEIGHT_LOW = 0.85
"""Lower bound of the dominant attribute's weight."""

WEIGHT_HIGH = 0.95
"""Upper bound of the dominant attribute's weight."""


def _mautil_frame(
    agent_id: AgentId,
    side: str,
    w_price: float,
    w_deadline: float,
    plo: int,
    phi: int,
    dlo: int,
    dhi: int,
    reservation: float,
) -> str:
    """Build the once-per-agent frame revealing its private utility parameters."""
    return (
        f"mautil:{agent_id}:{side}:{w_price:.6f}:{w_deadline:.6f}"
        f":{plo}:{phi}:{dlo}:{dhi}:{reservation:.6f}"
    )


def _offer_frame(
    sid: str, agent_id: AgentId, side: str, rnd: int, price: int, deadline: int
) -> str:
    """Build the frame recording one offered (price, deadline) bundle."""
    return f"offer:{sid}:{agent_id}:{side}:{rnd}:{price}:{deadline}"


def _agree_frame(sid: str, price: int, deadline: int, accepting: AgentId) -> str:
    """Build the frame recording an accepted agreement."""
    return f"agree:{sid}:{price}:{deadline}:{accepting}"


def _breakdown_frame(sid: str, rounds: int) -> str:
    """Build the frame recording a failed negotiation."""
    return f"breakdown:{sid}:{rounds}"


def _terms_pd(terms: Terms) -> tuple[int, int]:
    """Extract the (price, deadline) integer pair carried by ``terms``."""
    price = terms.price.amount if terms.price is not None else 0
    deadline = int(terms.conditions.get("deadline_days", 0))
    return price, deadline


class MarketSellerAgent(StateMachineAgent):
    """Passive counterparty: exists for addressing and topology only.

    The seller's negotiation plugin is driven by its paired buyer's ``on_start``
    loop, so the seller agent itself does no work; it only needs to be a real
    addressable node in the simulation.

    Example::

        agent = MarketSellerAgent(AgentId("seller-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id


class MarketBuyerAgent(StateMachineAgent):
    """Drives one bilateral price+deadline negotiation to completion.

    Holds both its own and its paired seller's negotiation-plugin instances and
    runs the full alternating concession loop in ``on_start``. Each plugin still
    only ever sees its own private utility plus the incoming :class:`Terms`, so
    the information asymmetry of real bargaining is preserved.

    Example::

        agent = MarketBuyerAgent(
            AgentId("buyer-0"), AgentId("seller-0"), "pair-0",
            buyer_neg, seller_neg, buyer_weights, seller_weights,
            (50, 150, 1, 30), 0.0,
        )
    """

    def __init__(
        self,
        buyer_id: AgentId,
        seller_id: AgentId,
        sid: str,
        buyer_neg: Any,
        seller_neg: Any,
        buyer_weights: dict[str, float],
        seller_weights: dict[str, float],
        bounds: tuple[int, int, int, int],
        reservation: float,
    ) -> None:
        self._buyer_id = buyer_id
        self._seller_id = seller_id
        self._sid = sid
        self._buyer_neg = buyer_neg
        self._seller_neg = seller_neg
        self._buyer_weights = buyer_weights
        self._seller_weights = seller_weights
        self._bounds = bounds
        self._reservation = reservation

    async def _emit_offer(
        self, ctx: AgentContext, agent_id: AgentId, side: str, rnd: int, terms: Terms
    ) -> None:
        price, deadline = _terms_pd(terms)
        frame = _offer_frame(self._sid, agent_id, side, rnd, price, deadline)
        await ctx.send(self._seller_id, frame.encode())

    async def on_start(self, ctx: AgentContext) -> None:
        """Reveal both agents' utilities, then bargain to agreement or breakdown.

        Opening offers are each side's best-for-self bundle (the buyer wants the
        lowest price and shortest deadline; the seller the highest price and
        longest deadline). Thereafter the two plugins alternate concessions until
        one accepts or ``MAX_ROUNDS`` is exhausted.

        Example::

            await agent.on_start(ctx)
        """
        plo, phi, dlo, dhi = self._bounds

        # Reveal each agent's (normally private) utility parameters to the trace.
        await ctx.send(
            self._seller_id,
            _mautil_frame(
                self._buyer_id,
                "buyer",
                self._buyer_weights["price"],
                self._buyer_weights["deadline"],
                plo,
                phi,
                dlo,
                dhi,
                self._reservation,
            ).encode(),
        )
        await ctx.send(
            self._seller_id,
            _mautil_frame(
                self._seller_id,
                "seller",
                self._seller_weights["price"],
                self._seller_weights["deadline"],
                plo,
                phi,
                dlo,
                dhi,
                self._reservation,
            ).encode(),
        )

        buyer_opener = Terms(price=Money(amount=plo), conditions={"deadline_days": dlo})
        seller_opener = Terms(price=Money(amount=phi), conditions={"deadline_days": dhi})

        buyer_session = await self._buyer_neg.open(self._seller_id, buyer_opener)
        seller_session = await self._seller_neg.open(self._buyer_id, seller_opener)

        await self._emit_offer(ctx, self._buyer_id, "buyer", 0, buyer_opener)
        await self._emit_offer(ctx, self._seller_id, "seller", 0, seller_opener)

        buyer_last: Terms = buyer_opener
        seller_last: Terms = seller_opener

        for rnd in range(1, MAX_ROUNDS + 1):
            # Buyer evaluates the seller's latest offer.
            await self._buyer_neg.offer(buyer_session, seller_last)
            b_resp = await self._buyer_neg.respond(buyer_session)
            if b_resp.accepted:
                price, deadline = _terms_pd(seller_last)
                frame = _agree_frame(self._sid, price, deadline, self._buyer_id)
                await ctx.send(self._seller_id, frame.encode())
                return
            if b_resp.counter_terms is None:
                break
            buyer_last = b_resp.counter_terms
            await self._emit_offer(ctx, self._buyer_id, "buyer", rnd, buyer_last)

            # Seller evaluates the buyer's latest offer.
            await self._seller_neg.offer(seller_session, buyer_last)
            s_resp = await self._seller_neg.respond(seller_session)
            if s_resp.accepted:
                price, deadline = _terms_pd(buyer_last)
                frame = _agree_frame(self._sid, price, deadline, self._seller_id)
                await ctx.send(self._seller_id, frame.encode())
                return
            if s_resp.counter_terms is None:
                break
            seller_last = s_resp.counter_terms
            await self._emit_offer(ctx, self._seller_id, "seller", rnd, seller_last)

        await ctx.send(self._seller_id, _breakdown_frame(self._sid, MAX_ROUNDS).encode())


def multi_attribute_market_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build ten buyer-seller pairs with seeded, asymmetric multi-attribute utilities.

    The configured ``negotiation`` plugin class (``plugins["negotiation"]``) is
    instantiated once per agent, so swapping the ``negotiation:`` layer in the
    YAML swaps the strategy under test. Per-agent instances are also injected via
    the ``_agent_plugins`` override channel so each agent's ``ctx`` carries its
    own negotiator. Each pair's weights are drawn from a generator seeded only
    from ``(config.seed, pair_index)`` — never the global RNG, never wall-clock —
    so the run is fully deterministic.

    Example::

        agents = multi_attribute_market_factory(config, plugins)
    """
    neg_cls = plugins["negotiation"]
    plo, phi = PRICE_RANGE
    dlo, dhi = DEADLINE_RANGE
    bounds = (plo, phi, dlo, dhi)

    agents: dict[AgentId, Any] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    for i in range(N_PAIRS):
        buyer_id = AgentId(f"buyer-{i}")
        seller_id = AgentId(f"seller-{i}")
        sid = f"pair-{i}"

        rng = random.Random(f"{config.seed}:{i}")
        w_price_buyer = rng.uniform(WEIGHT_LOW, WEIGHT_HIGH)
        buyer_weights = {"price": w_price_buyer, "deadline": 1.0 - w_price_buyer}
        w_deadline_seller = rng.uniform(WEIGHT_LOW, WEIGHT_HIGH)
        seller_weights = {"price": 1.0 - w_deadline_seller, "deadline": w_deadline_seller}

        buyer_neg = neg_cls(
            buyer_id,
            weights=buyer_weights,
            price_range=PRICE_RANGE,
            deadline_range=DEADLINE_RANGE,
            side="buyer",
            patience=PATIENCE,
            reservation=RESERVATION,
            max_rounds=MAX_ROUNDS,
        )
        seller_neg = neg_cls(
            seller_id,
            weights=seller_weights,
            price_range=PRICE_RANGE,
            deadline_range=DEADLINE_RANGE,
            side="seller",
            patience=PATIENCE,
            reservation=RESERVATION,
            max_rounds=MAX_ROUNDS,
        )

        agents[buyer_id] = MarketBuyerAgent(
            buyer_id,
            seller_id,
            sid,
            buyer_neg,
            seller_neg,
            buyer_weights,
            seller_weights,
            bounds,
            RESERVATION,
        )
        agents[seller_id] = MarketSellerAgent(seller_id)
        overrides[buyer_id] = {"negotiation": buyer_neg}
        overrides[seller_id] = {"negotiation": seller_neg}

    plugins["_agent_plugins"] = overrides
    return agents
