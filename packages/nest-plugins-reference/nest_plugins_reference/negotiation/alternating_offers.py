# SPDX-License-Identifier: Apache-2.0
"""Alternating offers negotiation plugin — Rubinstein-style bargaining.

Example::

    neg = AlternatingOffers(AgentId("a1"), patience=0.9)
    session = await neg.open(AgentId("a2"), Terms(price=Money(amount=100)))
"""

from __future__ import annotations

from nest_core.types import (
    AgentId,
    Agreement,
    NegotiationResponse,
    NegotiationSession,
    NegotiationStatus,
    Terms,
)

from ._ids import derive_session_id


class AlternatingOffers:
    """Rubinstein-style alternating-offers negotiation.

    Example::

        neg = AlternatingOffers(AgentId("a1"))
        session = await neg.open(AgentId("a2"), terms)
    """

    def __init__(self, agent_id: AgentId, patience: float = 0.9) -> None:
        self._agent_id = agent_id
        self._patience = patience
        self._sessions: dict[str, NegotiationSession] = {}
        self._session_seq = 0

    async def open(self, partner: AgentId, terms: Terms) -> NegotiationSession:
        """Open a negotiation with initial terms.

        The session id is derived deterministically from the initiating agent,
        the partner, and a monotonic per-initiator sequence number, so a seeded
        run replays byte-for-byte (ADR-004) instead of drawing a fresh ``uuid4``
        each run. See :func:`._ids.derive_session_id`.

        Example::

            session = await neg.open(AgentId("a2"), terms)
        """
        self._session_seq += 1
        session = NegotiationSession(
            id=derive_session_id(self._agent_id, partner, self._session_seq),
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

        Example::

            resp = await neg.respond(session)
        """
        if session.current_terms is None or session.current_terms.price is None:
            return NegotiationResponse(accepted=True)

        rounds = len(session.history)
        threshold = session.current_terms.price.amount * (self._patience**rounds)
        if session.current_terms.price.amount <= threshold or rounds >= 10:
            return NegotiationResponse(accepted=True)

        return NegotiationResponse(accepted=False, counter_terms=session.current_terms)

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
