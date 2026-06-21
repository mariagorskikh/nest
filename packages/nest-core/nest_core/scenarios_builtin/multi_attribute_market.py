# SPDX-License-Identifier: Apache-2.0
"""Multi-attribute market scenario, price + deadline, asymmetric evaluation.

Ten negotiations, each between a *fixed* buyer counterpart and a *configured*
seller plugin under test. This is the ANAC-style asymmetric evaluation: holding
one side fixed turns the other side's ``respond`` into the discriminator, so the
trace shows whether the plugin reasons about the *full* multi-attribute Terms or
only price.

The buyer is deliberately **indifferent to the deadline** (``w_deadline = 0``):
it cares only about price, conceding price monotonically from its best toward a
midpoint over the rounds. Because the deadline costs the buyer nothing, it hands
the deadline-loving seller a long-deadline bundle *early* and cheaply (Raiffa's
integrative / logrolling structure: trade the issue you don't value for the one
your counterpart does). A deadline-aware seller grabs that early bundle and
settles on a Pareto-efficient logroll; a deadline-blind, timeout-driven seller
(e.g. the reference ``alternating_offers``, which never reads
``conditions['deadline_days']`` and only accepts at its round limit) holds out
and closes on a late short-deadline bundle that the early gift dominates.

Every exchanged bundle and each agent's private utility parameters are written
to the trace, so the offline validator can reconstruct utilities and check the
agreement for Pareto-optimality. Frame grammar (floats to 6 dp for
byte-determinism)::

    mautil:<agent>:<side>:<w_price>:<w_deadline>:<plo>:<phi>:<dlo>:<dhi>:<reservation>
    offer:<sid>:<agent>:<side>:<round>:<price>:<deadline>
    agree:<sid>:<price>:<deadline>:<accepting_agent>
    breakdown:<sid>:<rounds>

The buyer drives the whole exchange synchronously inside ``on_start`` (no
cross-agent event interleaving to make non-deterministic), emitting authentic
``ctx.send`` frames. All randomness is seeded only from ``(config.seed, pair)``.

Example::

    from nest_core.runner import ScenarioRunner
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/multi_attribute_market.yaml"))
    await runner.run()
"""

from __future__ import annotations

import inspect
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
"""Concession discount per round for the seller plugin under test."""

RESERVATION = 0.0
"""Walk-away utility floor for every agent."""

MAX_ROUNDS = 10
"""Maximum bargaining rounds before a negotiation is declared a breakdown."""

WEIGHT_LOW = 0.85
"""Lower bound of the seller's dominant (deadline) weight."""

WEIGHT_HIGH = 0.95
"""Upper bound of the seller's dominant (deadline) weight."""

BUYER_WEIGHTS = {"price": 1.0, "deadline": 0.0}
"""The fixed buyer counterpart: price-driven, wholly indifferent to deadline."""

MIDPOINT_PRICE = 100
"""Price the buyer concedes toward by the final round (from its low-price best)."""

GIFT_ROUNDS = (2, 3)
"""Rounds where the buyer offers the maximum deadline, the integrative gift.

Two rounds, not one: a deadline-aware seller's aspiration ``patience ** (r-1)``
is ``0.9`` at round 2 (which a low-deadline-weight seller's utility for the gift
does not always clear) but ``0.81`` at round 3 (which every weight in
``[WEIGHT_LOW, WEIGHT_HIGH]`` clears). Offering the long deadline in both rounds
guarantees the seller accepts a non-dominated frontier bundle regardless of its
drawn weight, while keeping the round-2 anchor the spec calls for.
"""

SHORT_DEADLINE_MAX = 5
"""Upper bound for the buyer's deadline on non-gift rounds.

Late rounds carry a short deadline, so whichever late bundle a timeout-driven
seller closes on is dominated by the early long-deadline gift. The dominance
holds for every seed and every seller weight, not just by luck.
"""


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


def _construct_negotiator(neg_cls: Any, agent_id: AgentId, candidate: dict[str, Any]) -> Any:
    """Instantiate any Negotiation plugin, passing only the kwargs it accepts.

    The Negotiation protocol does not define ``__init__``, so plugins have
    different constructor signatures: ``ParetoNegotiation`` wants the full
    multi-attribute config while the reference ``AlternatingOffers`` takes only
    ``patience``. We introspect ``neg_cls.__init__`` and forward each candidate
    kwarg that names a real parameter, dropping the rest, so swapping the
    ``negotiation:`` layer in the YAML never raises a ``TypeError``. ``agent_id``
    is always passed positionally.

    Example::

        neg = _construct_negotiator(ParetoNegotiation, AgentId("seller-0"), candidate)
    """
    params = inspect.signature(neg_cls.__init__).parameters
    accepted = {key: value for key, value in candidate.items() if key in params}
    return neg_cls(agent_id, **accepted)


def _buyer_schedule(
    rng: random.Random, bounds: tuple[int, int, int, int], max_rounds: int
) -> list[tuple[int, int]]:
    """Build the buyer's deterministic, price-monotonic concession schedule.

    Price rises from just above the floor toward the midpoint (the buyer
    conceding on the only issue it values). The deadline is the maximum on the
    gift rounds and a short, seeded value otherwise. The buyer gives the
    deadline away early because it is indifferent to it.

    Example::

        schedule = _buyer_schedule(random.Random("42:0"), (50, 150, 1, 30), 10)
    """
    plo, _phi, dlo, dhi = bounds
    short_hi = max(dlo, min(dhi, SHORT_DEADLINE_MAX))
    schedule: list[tuple[int, int]] = []
    for r in range(1, max_rounds + 1):
        price = round(plo + (MIDPOINT_PRICE - plo) * r / max_rounds)
        deadline = dhi if r in GIFT_ROUNDS else rng.randint(dlo, short_hi)
        schedule.append((price, deadline))
    return schedule


class MarketSellerAgent(StateMachineAgent):
    """Passive counterparty node: the seller plugin is driven by the buyer's loop.

    The seller agent does no work itself; it only needs to be a real addressable
    node so the buyer's ``ctx.send`` frames have a destination.

    Example::

        agent = MarketSellerAgent(AgentId("seller-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id


class MarketBuyerAgent(StateMachineAgent):
    """The fixed buyer counterpart that drives one negotiation against the plugin.

    Holds the seller's configured negotiation-plugin instance and a precomputed
    price-monotonic concession schedule, and runs the full exchange in
    ``on_start``: it presents each scheduled offer to the seller's ``respond``
    and records every bundle. The buyer never acts on the seller's counteroffers
    (it follows its own schedule), which keeps the evaluation a clean test of the
    seller's ``respond`` rather than an echo loop.

    Example::

        agent = MarketBuyerAgent(
            AgentId("buyer-0"), AgentId("seller-0"), "pair-0", seller_neg,
            BUYER_WEIGHTS, seller_weights, (50, 150, 1, 30), 0.0, schedule, 10,
        )
    """

    def __init__(
        self,
        buyer_id: AgentId,
        seller_id: AgentId,
        sid: str,
        seller_neg: Any,
        buyer_weights: dict[str, float],
        seller_weights: dict[str, float],
        bounds: tuple[int, int, int, int],
        reservation: float,
        schedule: list[tuple[int, int]],
        max_rounds: int,
    ) -> None:
        self._buyer_id = buyer_id
        self._seller_id = seller_id
        self._sid = sid
        self._seller_neg = seller_neg
        self._buyer_weights = buyer_weights
        self._seller_weights = seller_weights
        self._bounds = bounds
        self._reservation = reservation
        self._schedule = schedule
        self._max_rounds = max_rounds

    async def on_start(self, ctx: AgentContext) -> None:
        """Reveal both utilities, then walk the buyer's schedule against the seller.

        The buyer concedes price round by round; the seller plugin evaluates each
        offer. The negotiation ends the moment the seller accepts (agreement) or
        the schedule is exhausted (breakdown).

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

        # The seller opens from its best-for-self position; the buyer's scheduled
        # offers then drive the exchange.
        seller_opener = Terms(price=Money(amount=phi), conditions={"deadline_days": dhi})
        session = await self._seller_neg.open(self._buyer_id, seller_opener)

        for rnd, (price, deadline) in enumerate(self._schedule, start=1):
            buyer_offer = Terms(price=Money(amount=price), conditions={"deadline_days": deadline})
            await self._seller_neg.offer(session, buyer_offer)
            resp = await self._seller_neg.respond(session)

            offer_frame = _offer_frame(self._sid, self._buyer_id, "buyer", rnd, price, deadline)
            await ctx.send(self._seller_id, offer_frame.encode())

            if resp.accepted:
                agree = _agree_frame(self._sid, price, deadline, self._seller_id)
                await ctx.send(self._seller_id, agree.encode())
                return

            if resp.counter_terms is not None:
                cp, cd = _terms_pd(resp.counter_terms)
                counter = _offer_frame(self._sid, self._seller_id, "seller", rnd, cp, cd)
                await ctx.send(self._seller_id, counter.encode())

        await ctx.send(self._seller_id, _breakdown_frame(self._sid, self._max_rounds).encode())


def multi_attribute_market_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build ten pairs: a fixed price-driven buyer against the configured seller.

    Each pair's seller weights and buyer schedule are derived from a generator
    seeded only from ``(config.seed, pair_index)``. The seller is the configured
    ``negotiation`` plugin, instantiated through :func:`_construct_negotiator` so
    swapping the layer in the YAML swaps the strategy under test; its instance is
    also injected via ``_agent_plugins`` so the seller node's ``ctx`` carries it.

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
        w_deadline_seller = rng.uniform(WEIGHT_LOW, WEIGHT_HIGH)
        seller_weights = {"price": 1.0 - w_deadline_seller, "deadline": w_deadline_seller}
        buyer_weights = dict(BUYER_WEIGHTS)
        schedule = _buyer_schedule(rng, bounds, MAX_ROUNDS)

        seller_candidate: dict[str, Any] = {
            "weights": seller_weights,
            "price_range": PRICE_RANGE,
            "deadline_range": DEADLINE_RANGE,
            "side": "seller",
            "patience": PATIENCE,
            "reservation": RESERVATION,
            "max_rounds": MAX_ROUNDS,
        }
        seller_neg = _construct_negotiator(neg_cls, seller_id, seller_candidate)

        agents[buyer_id] = MarketBuyerAgent(
            buyer_id,
            seller_id,
            sid,
            seller_neg,
            buyer_weights,
            seller_weights,
            bounds,
            RESERVATION,
            schedule,
            MAX_ROUNDS,
        )
        agents[seller_id] = MarketSellerAgent(seller_id)
        overrides[seller_id] = {"negotiation": seller_neg}

    plugins["_agent_plugins"] = overrides
    return agents
