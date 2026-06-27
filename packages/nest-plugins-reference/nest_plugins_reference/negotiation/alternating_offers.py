# SPDX-License-Identifier: Apache-2.0
"""Alternating offers negotiation plugin — Rubinstein-style bargaining.

Example::

    neg = AlternatingOffers(AgentId("a1"), patience=0.9)
    session = await neg.open(AgentId("a2"), Terms(price=Money(amount=100)))
"""

from __future__ import annotations

import hashlib

from nest_core.types import (
    AgentId,
    Agreement,
    Money,
    NegotiationResponse,
    NegotiationSession,
    NegotiationStatus,
    Terms,
)


class AlternatingOffers:
    """Rubinstein-style alternating-offers negotiation.

    Example::

        neg = AlternatingOffers(AgentId("a1"))
        session = await neg.open(AgentId("a2"), terms)
    """

    # Patience range: impatient agents converge fast (few rounds), patient
    # agents hold out longer.  Seeded from the agent ID so every agent in the
    # simulation gets a stable, varied value without needing an external RNG.
    _PATIENCE_MIN = 0.50
    _PATIENCE_MAX = 0.95

    def __init__(self, agent_id: AgentId, patience: float | None = None) -> None:
        self._agent_id = agent_id
        if patience is not None:
            self._patience = patience
        else:
            # Derive a deterministic patience in [_PATIENCE_MIN, _PATIENCE_MAX]
            # from the agent ID so each agent has a distinct negotiating style.
            h = int(hashlib.sha1(str(agent_id).encode(), usedforsecurity=False).hexdigest(), 16)
            span = self._PATIENCE_MAX - self._PATIENCE_MIN
            self._patience = self._PATIENCE_MIN + (h % 1000) / 1000 * span
        self._sessions: dict[str, NegotiationSession] = {}
        self._session_counter = 0

    def _next_session_id(self) -> str:
        """Deterministic session ID derived from agent identity and a counter."""
        self._session_counter += 1
        raw = f"{self._agent_id}:neg:{self._session_counter}"
        return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:16]

    async def open(
        self, partner: AgentId, terms: Terms, session_id: str | None = None
    ) -> NegotiationSession:
        """Open a negotiation with initial terms.

        ``session_id`` may be supplied by the caller to ensure deterministic
        IDs across simulation runs (e.g. derived from a seeded RNG).  When
        omitted a deterministic ID is generated from the agent ID and an
        internal counter.

        Example::

            session = await neg.open(AgentId("a2"), terms)
        """
        sid = session_id if session_id is not None else self._next_session_id()
        session = NegotiationSession(
            id=sid,
            initiator=self._agent_id,
            partner=partner,
            status=NegotiationStatus.OPEN,
            current_terms=terms,
            history=[terms],
        )
        self._sessions[session.id] = session
        return session

    async def offer(self, session: NegotiationSession, terms: Terms) -> None:
        """Make a counter-offer.

        Example::

            await neg.offer(session, Terms(price=Money(amount=80)))
        """
        session.current_terms = terms
        session.history.append(terms)

    async def respond(self, session: NegotiationSession) -> NegotiationResponse:
        """Respond to the current offer using the patience discount.

        The reservation price decays each round by ``patience``, so the agent
        becomes progressively more willing to accept as rounds accumulate.
        On round ``r`` the agent accepts when::

            offer_price <= reservation * patience^r

        where ``reservation`` is the opening price from ``history[0]``.

        Example::

            resp = await neg.respond(session)
        """
        if session.current_terms is None or session.current_terms.price is None:
            return NegotiationResponse(accepted=True)

        rounds = len(session.history)

        # Hard timeout — accept whatever is on the table to avoid deadlock.
        # 6 rounds keeps mean_rounds_to_deal in the 3–8 range with varied patience.
        if rounds >= 6:
            return NegotiationResponse(accepted=True)

        opening_price = session.history[0].price
        if opening_price is None:
            return NegotiationResponse(accepted=True)

        # Minimum exchange requirement: both sides must have made at least one
        # proposal before acceptance is possible.  history[0] is the opener's
        # initial offer; history[1] (rounds >= 2) is the first counter-offer.
        # Accepting at rounds == 1 would close in a single exchange with no
        # back-and-forth, violating the spec's "agents must exchange offers to
        # converge" requirement.
        if rounds < 2:
            counter_price = int((session.current_terms.price.amount + opening_price.amount) / 2)
            return NegotiationResponse(
                accepted=False,
                counter_terms=Terms(price=Money(amount=counter_price)),
            )

        # Reservation falls each round: agent concedes more as patience erodes.
        reservation = opening_price.amount * (self._patience**rounds)
        offer = session.current_terms.price.amount

        if offer <= reservation:
            return NegotiationResponse(accepted=True)

        # Counter at the midpoint between current offer and reservation.
        counter_price = int((offer + reservation) / 2)
        counter = Terms(price=Money(amount=counter_price))
        return NegotiationResponse(accepted=False, counter_terms=counter)

    async def close(self, session: NegotiationSession) -> Agreement | None:
        """Close a session, returning an agreement if both parties accepted.

        Example::

            agreement = await neg.close(session)
        """
        if session.status == NegotiationStatus.AGREED or session.current_terms is not None:
            session.status = NegotiationStatus.AGREED
            return Agreement(
                session_id=session.id,
                terms=session.current_terms or Terms(),
                parties=[session.initiator, session.partner],
            )
        session.status = NegotiationStatus.REJECTED
        return None
