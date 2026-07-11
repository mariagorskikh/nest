# SPDX-License-Identifier: Apache-2.0
"""ADARX compliance-gate discriminator scenario.

Ten negotiations, each between a *fixed* seller counterpart and a *configured*
buyer plugin under test. This is the mirror image of ``multi_attribute_market``
(which holds the buyer fixed to put the seller's ``respond`` under test): here
the buyer side is under test, because the property being exercised --
refusing to negotiate price with a non-compliant counterparty -- is a buyer
decision in ADAR-X's domain (a procurement agent choosing whether to deal
with a given supplier), not a seller one.

Five pairs seed a compliant seller (``compliance_status: APPROVED``); five
seed a non-compliant one (``compliance_status: PENDING_REVIEW``). The fixed
seller counterpart always offers a reasonable, eventually-acceptable price --
so any ``breakdown:`` on the *compliant* pairs would mean the plugin under
test is simply refusing everything (a vacuous, non-discriminating pass), and
any ``agree:`` on the *non-compliant* pairs means it negotiated price with a
counterparty it should have refused outright before ever discussing price.

``ADARXNegotiation`` reads ``compliance_status`` from ``Terms.metadata`` at
``open()`` and rejects immediately when it isn't ``"APPROVED"``, before any
price is ever exchanged -- so it closes every non-compliant pair as
``breakdown:`` while still reaching ``agree:`` on every compliant one.
The reference ``alternating_offers`` plugin has no compliance concept at all:
its ``respond`` unconditionally accepts by round 10 regardless of metadata,
so it reaches ``agree:`` on the non-compliant pairs too -- the exact
violation this scenario is built to catch. Swapping the ``negotiation:``
layer in the YAML from ``adarx`` to ``alternating_offers`` is the whole test.

Frame grammar::

    compliance:<sid>:<status>
    offer:<sid>:<agent>:<round>:<price>
    agree:<sid>:<price>:<accepting_agent>
    breakdown:<sid>:<rounds>

Deterministic: each pair's opening price and per-round concession are drawn
from a generator seeded only from ``(config.seed, pair_index)``; the buyer
drives the whole exchange synchronously inside ``on_start``.

Example::

    from nest_core.runner import ScenarioRunner
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/adarx_compliance_gate.yaml"))
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
"""Number of independent buyer-seller negotiations. Split evenly: 5 compliant
seller counterparts, 5 non-compliant -- so a vacuous "reject everything"
plugin fails on the compliant half, and a "compliance-blind" plugin fails on
the non-compliant half. Only a genuinely discriminating gate passes both."""

OPENING_PRICE_RANGE = (800, 1200)
"""Seller's fixed opening ask (credits), varied per pair for realism."""

QUANTITY_RANGE = (200, 6000)
"""Requested quantity, spanning ADAR-X's volume-discount tiers (500/1000/5000)."""

MAX_ROUNDS = 10
"""Both reference negotiators (adarx, alternating_offers) unconditionally
accept by round 10 regardless of price -- this only needs to be large enough
to reach that fallback, not tuned for convergence like a price-sensitive
scenario would need."""

CONCESSION_PER_ROUND = 0.03
"""Fraction of the gap to the seller's ask the buyer concedes each round,
so a genuinely price-negotiating plugin reaches a reasonable agreement well
before the round-10 fallback, rather than relying on the fallback itself."""


def _compliance_frame(sid: str, status: str) -> str:
    """Build the frame revealing this pair's ground-truth compliance status."""
    return f"compliance:{sid}:{status}"


def _offer_frame(sid: str, agent_id: AgentId, rnd: int, price: int) -> str:
    """Build the frame recording one offered price."""
    return f"offer:{sid}:{agent_id}:{rnd}:{price}"


def _agree_frame(sid: str, price: int, accepting: AgentId) -> str:
    """Build the frame recording an accepted agreement."""
    return f"agree:{sid}:{price}:{accepting}"


def _breakdown_frame(sid: str, rounds: int) -> str:
    """Build the frame recording a failed negotiation."""
    return f"breakdown:{sid}:{rounds}"


def _construct_negotiator(neg_cls: Any, agent_id: AgentId, candidate: dict[str, Any]) -> Any:
    """Instantiate any Negotiation plugin, passing only the kwargs it accepts.

    Mirrors ``multi_attribute_market``'s helper: the ``Negotiation`` protocol
    does not define ``__init__``, so plugins have different constructor
    signatures (``ADARXNegotiation`` wants only ``agent_id``;
    ``AlternatingOffers`` also accepts ``patience``). Introspecting and
    filtering means swapping the ``negotiation:`` layer in the YAML never
    raises a ``TypeError``.

    Example::

        neg = _construct_negotiator(ADARXNegotiation, AgentId("buyer-0"), {})
    """
    params = inspect.signature(neg_cls.__init__).parameters
    accepted = {key: value for key, value in candidate.items() if key in params}
    return neg_cls(agent_id, **accepted)


class ComplianceSellerAgent(StateMachineAgent):
    """Passive counterparty node: the buyer plugin under test is the one deciding.

    Example::

        agent = ComplianceSellerAgent(AgentId("seller-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id


class ComplianceBuyerAgent(StateMachineAgent):
    """The buyer under test, deciding whether to negotiate with one seller.

    Holds the buyer's configured negotiation-plugin instance and drives the
    whole exchange in ``on_start``: opens against the seller with the
    seller's (ground-truth) compliance status embedded in the deal metadata,
    then either the session is already rejected (a compliant gate) or it
    concedes price round by round toward the seller's ask.

    Example::

        agent = ComplianceBuyerAgent(
            AgentId("buyer-0"), AgentId("seller-0"), "pair-0", buyer_neg,
            "APPROVED", 1000, 500, MAX_ROUNDS,
        )
    """

    def __init__(
        self,
        buyer_id: AgentId,
        seller_id: AgentId,
        sid: str,
        buyer_neg: Any,
        compliance_status: str,
        opening_price: int,
        quantity: int,
        max_rounds: int,
    ) -> None:
        self._buyer_id = buyer_id
        self._seller_id = seller_id
        self._sid = sid
        self._buyer_neg = buyer_neg
        self._compliance_status = compliance_status
        self._opening_price = opening_price
        self._quantity = quantity
        self._max_rounds = max_rounds

    async def on_start(self, ctx: AgentContext) -> None:
        """Reveal ground truth, open against the seller, then concede toward its ask.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.send(
            self._seller_id, _compliance_frame(self._sid, self._compliance_status).encode()
        )

        opener = Terms(
            price=Money(amount=self._opening_price),
            metadata={
                "quantity": self._quantity,
                "strategy": "balanced",
                "compliance_status": self._compliance_status,
            },
        )
        session = await self._buyer_neg.open(self._seller_id, opener)

        # Concede a fraction of the remaining gap to the seller's ask each
        # round. A compliance gate that already rejected the session at
        # open() ignores whatever is offered here -- respond() keeps
        # returning accepted=False regardless of price (that is the
        # property under test); a plugin with no compliance concept just
        # negotiates this schedule on its own merits.
        current_offer = round(self._opening_price * 0.7)
        for rnd in range(1, self._max_rounds + 1):
            gap = self._opening_price - current_offer
            current_offer = (
                round(current_offer + gap * CONCESSION_PER_ROUND) if rnd > 1 else current_offer
            )

            offer_terms = Terms(
                price=Money(amount=current_offer),
                metadata={
                    "quantity": self._quantity,
                    "strategy": "balanced",
                    "compliance_status": self._compliance_status,
                },
            )
            await self._buyer_neg.offer(session, offer_terms)
            resp = await self._buyer_neg.respond(session)

            await ctx.send(
                self._seller_id,
                _offer_frame(self._sid, self._buyer_id, rnd, current_offer).encode(),
            )

            if resp.accepted:
                agreement = await self._buyer_neg.close(session)
                if agreement is not None:
                    price = agreement.terms.price.amount if agreement.terms.price else current_offer
                    await ctx.send(
                        self._seller_id, _agree_frame(self._sid, price, self._buyer_id).encode()
                    )
                    return
                break

            if resp.counter_terms is not None and resp.counter_terms.price is not None:
                current_offer = resp.counter_terms.price.amount

        await ctx.send(self._seller_id, _breakdown_frame(self._sid, self._max_rounds).encode())


def adarx_compliance_gate_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build ten pairs: the configured buyer plugin against a fixed seller ask.

    Five pairs seed an ``APPROVED`` seller, five seed ``PENDING_REVIEW``.
    Each pair's opening price and quantity are derived from a generator
    seeded only from ``(config.seed, pair_index)``. The buyer is the
    configured ``negotiation`` plugin, instantiated through
    :func:`_construct_negotiator` so swapping the layer in the YAML swaps
    the strategy under test.

    Example::

        agents = adarx_compliance_gate_factory(config, plugins)
    """
    neg_cls = plugins["negotiation"]
    plo, phi = OPENING_PRICE_RANGE
    qlo, qhi = QUANTITY_RANGE

    agents: dict[AgentId, Any] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    for i in range(N_PAIRS):
        buyer_id = AgentId(f"buyer-{i}")
        seller_id = AgentId(f"seller-{i}")
        sid = f"pair-{i}"

        rng = random.Random(f"{config.seed}:{i}")
        opening_price = rng.randint(plo, phi)
        quantity = rng.randint(qlo, qhi)
        compliance_status = "APPROVED" if i % 2 == 0 else "PENDING_REVIEW"

        buyer_neg = _construct_negotiator(neg_cls, buyer_id, {"patience": 0.9})

        agents[buyer_id] = ComplianceBuyerAgent(
            buyer_id,
            seller_id,
            sid,
            buyer_neg,
            compliance_status,
            opening_price,
            quantity,
            MAX_ROUNDS,
        )
        agents[seller_id] = ComplianceSellerAgent(seller_id)
        overrides[buyer_id] = {"negotiation": buyer_neg}

    plugins["_agent_plugins"] = overrides
    return agents
