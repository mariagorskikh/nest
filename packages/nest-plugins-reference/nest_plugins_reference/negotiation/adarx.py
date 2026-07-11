# SPDX-License-Identifier: Apache-2.0
"""ADAR-X negotiation plugin -- tiered-discount, strategy-aware bargaining.

Unlike the reference `alternating_offers` plugin (a generic Rubinstein
patience-discount model with no domain knowledge), this plugin ports the
real, independently-tested negotiation logic from ADAR-X
(https://github.com/merry-tresata/nanda-adarx-procurement), an autonomous
procurement agent.
The underlying math -- volume-tiered discounts and strategy-adjusted
terms -- has been exercised against dozens of real transactions in that
project before being adapted here.

How business context reaches this plugin
------------------------------------------
`Terms.metadata` is a free-form dict (see nest_core.types.Terms), so the
initiating agent is expected to seed it when calling `open()`:

    terms = Terms(
        price=Money(amount=1250),
        metadata={
            "quantity": 1500,
            "strategy": "balanced",       # "aggressive" | "balanced" | "defensive"
            "compliance_status": "APPROVED",
        },
    )
    session = await neg.open(partner, terms)

Everything this plugin computes (negotiated price, discount, payment
terms, warranty, SLA tier) is derived from that seed data using the same
rules as ADAR-X's production ContractNegotiationService.

Example::

    neg = ADARXNegotiation(AgentId("buyer-1"))
    session = await neg.open(AgentId("seller-1"), terms)
    response = await neg.respond(session)
"""

from __future__ import annotations

from nest_core.types import (
    AgentId,
    Agreement,
    Money,
    NegotiationResponse,
    NegotiationSession,
    NegotiationStatus,
    Terms,
)


def volume_discount_percent(quantity: int) -> int:
    """Tiered volume discount -- identical thresholds to ADAR-X production."""
    if quantity >= 5000:
        return 12
    if quantity >= 1000:
        return 8
    if quantity >= 500:
        return 5
    return 0


def apply_strategy(discount: int, lead_time_days: int, strategy: str) -> dict[str, int | str]:
    """
    Strategy-adjusted terms. Mirrors ContractNegotiationService's three
    strategies exactly:
      - aggressive: push for a bigger discount, accept slower delivery
        and slower payment in exchange (cost-optimized).
      - defensive: give up some discount for faster delivery, faster
        payment to the supplier, and a longer warranty (risk-averse).
      - balanced: the default middle ground.
    """
    strategy = (strategy or "balanced").lower()

    if strategy == "aggressive":
        return {
            "discount": discount + 3,
            "lead_time_days": lead_time_days + 2,
            "payment_terms": "Net 60",
            "warranty_months": 12,
            "sla_tier": "COST_OPTIMIZED",
        }
    if strategy == "defensive":
        return {
            "discount": max(discount - 2, 0),
            "lead_time_days": max(lead_time_days - 3, 2),
            "payment_terms": "Net 15",
            "warranty_months": 24,
            "sla_tier": "EXPEDITED",
        }
    # balanced (default)
    return {
        "discount": discount,
        "lead_time_days": lead_time_days,
        "payment_terms": "Net 30",
        "warranty_months": 18,
        "sla_tier": "BALANCED",
    }


class ADARXNegotiation:
    """
    Tiered-discount, strategy-aware negotiation -- adapted from ADAR-X's
    production ContractNegotiationService.

    Example::

        neg = ADARXNegotiation(AgentId("buyer-1"))
        session = await neg.open(AgentId("seller-1"), terms)
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._agent_id = agent_id
        self._sessions: dict[str, NegotiationSession] = {}
        self._session_counter = 0

    async def open(self, partner: AgentId, terms: Terms) -> NegotiationSession:
        """
        Open a negotiation. A hard compliance gate runs immediately: if
        the seeding metadata marks the counterparty non-compliant, the
        session opens already REJECTED rather than proceeding through a
        pointless bargaining round -- matching ADAR-X's production
        behavior, where a non-APPROVED supplier is refused outright.

        Example::
            session = await neg.open(AgentId("seller-1"), terms)
        """

        compliance_status = terms.metadata.get("compliance_status", "APPROVED")

        self._session_counter += 1

        session = NegotiationSession(
            id=f"adarx-{self._agent_id}-{self._session_counter}",
            initiator=self._agent_id,
            partner=partner,
            status=(
                NegotiationStatus.REJECTED
                if compliance_status != "APPROVED"
                else NegotiationStatus.OPEN
            ),
            current_terms=terms,
            history=[terms],
        )
        self._sessions[session.id] = session
        return session

    async def offer(self, session: NegotiationSession, terms: Terms) -> None:
        """
        Record a counter-offer.

        Example::
            await neg.offer(session, Terms(price=Money(amount=1150), metadata={...}))
        """
        session.current_terms = terms
        session.history.append(terms)

    async def respond(self, session: NegotiationSession) -> NegotiationResponse:
        """
        Evaluate the currently offered terms against a FIXED negotiated
        target computed once from the opening price -- not a target that
        shifts every round. The opening price is read from
        session.history[0] (set once, at open()); the current offer being
        evaluated is session.current_terms (which may have moved since,
        via offer()).

        Example::
            resp = await neg.respond(session)
        """

        if session.status == NegotiationStatus.REJECTED:
            return NegotiationResponse(accepted=False, counter_terms=None)

        opening_terms = session.history[0] if session.history else session.current_terms
        if opening_terms is None or opening_terms.price is None:
            return NegotiationResponse(accepted=True)

        base_price = opening_terms.price.amount
        quantity = int(opening_terms.metadata.get("quantity", 100))
        strategy = opening_terms.metadata.get("strategy", "balanced")
        base_lead_time = int(opening_terms.metadata.get("lead_time_days", 10))

        volume_discount = volume_discount_percent(quantity)
        adjusted = apply_strategy(volume_discount, base_lead_time, strategy)

        discount_value = adjusted["discount"]
        assert isinstance(discount_value, int)
        negotiated_price = round(base_price * (1 - discount_value / 100))

        current_terms = session.current_terms
        if current_terms is None or current_terms.price is None:
            return NegotiationResponse(accepted=True)

        current_offer_price = current_terms.price.amount

        our_terms = Terms(
            price=Money(amount=negotiated_price, currency=opening_terms.price.currency),
            conditions={
                "quantity": quantity,
                "lead_time_days": adjusted["lead_time_days"],
                "payment_terms": adjusted["payment_terms"],
                "warranty_months": adjusted["warranty_months"],
                "sla_tier": adjusted["sla_tier"],
            },
            metadata=opening_terms.metadata,
        )

        # Accept once the offer on the table is at or below our fixed
        # negotiated target, or after enough rounds that further haggling
        # has diminishing value (mirrors the round cap in the reference
        # alternating_offers plugin).
        rounds = len(session.history)
        if current_offer_price <= negotiated_price or rounds >= 10:
            return NegotiationResponse(accepted=True)

        return NegotiationResponse(accepted=False, counter_terms=our_terms)

    async def close(self, session: NegotiationSession) -> Agreement | None:
        """
        Close a session, returning an Agreement if terms were reached
        and the counterparty passed the compliance gate.

        Example::
            agreement = await neg.close(session)
        """

        if session.status == NegotiationStatus.REJECTED:
            return None

        if session.current_terms is not None:
            session.status = NegotiationStatus.AGREED
            return Agreement(
                session_id=session.id,
                terms=session.current_terms,
                parties=[session.initiator, session.partner],
            )

        session.status = NegotiationStatus.REJECTED
        return None
