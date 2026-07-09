# SPDX-License-Identifier: Apache-2.0
"""Pareto-seeking multi-attribute negotiation plugin.

Bilateral bargaining over *price* and *deadline* using additive multi-attribute
utility and similarity-based trade-off (iso-utility) concessions, so the two
parties move toward Pareto-efficient agreements instead of fighting over price
alone.

Example::

    neg = ParetoNegotiation(
        AgentId("buyer"),
        weights={"price": 0.6, "deadline": 0.4},
        price_range=(10, 100),
        deadline_range=(1, 30),
        side="buyer",
    )
    session = await neg.open(AgentId("seller"), Terms(price=Money(amount=10)))
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


class ParetoNegotiation:
    """Multi-attribute, Pareto-seeking bilateral negotiation.

    Each agent knows only its *own* private utility configuration (weights,
    feasible ranges, reservation level) and negotiates over two issues (price
    and deadline) that ride in ``terms.price`` and ``terms.conditions``.

    The strategy combines three classical results:

    - Keeney & Raiffa additive multi-attribute utility: a bundle's worth is the
      weighted sum of per-issue value functions, each normalized to ``[0, 1]``.
    - Rosenschein & Zlotkin 1994 Monotonic Concession Protocol (Zeuthen): the
      agent's own-utility aspiration is non-increasing across rounds, which
      guarantees the bargaining either converges or terminates.
    - Faratin, Sierra & Jennings 2002 similarity-based trade-off: when the
      opponent's offer is below aspiration, the agent counters with the bundle
      on its current iso-utility set that is *closest* to the opponent's offer,
      yielding integrative ("logrolling") moves that are Pareto-improving.

    The plugin is Tier-1 deterministic: no wall-clock and no RNG. Session ids
    come from a per-instance counter and all scoring is pure integer arithmetic.

    Example::

        neg = ParetoNegotiation(
            AgentId("seller"),
            weights={"price": 0.5, "deadline": 0.5},
            price_range=(10, 100),
            deadline_range=(1, 30),
            side="seller",
        )
        session = await neg.open(AgentId("buyer"), Terms(price=Money(amount=100)))
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        weights: dict[str, float],
        price_range: tuple[int, int],
        deadline_range: tuple[int, int],
        side: str,
        patience: float = 0.9,
        reservation: float = 0.0,
        max_rounds: int = 12,
    ) -> None:
        self._agent_id = agent_id
        self._weights = weights
        self._price_range = price_range
        self._deadline_range = deadline_range
        self._side = side
        self._patience = patience
        self._reservation = reservation
        self._max_rounds = max_rounds
        self._rounds: dict[str, int] = {}
        self._session_counter = 0

    async def open(self, partner: AgentId, terms: Terms) -> NegotiationSession:
        """Open a negotiation with initial terms and a deterministic session id.

        Example::

            session = await neg.open(AgentId("seller"), Terms(price=Money(amount=10)))
        """
        self._session_counter += 1
        return NegotiationSession(
            id=f"pareto-{self._agent_id}-{self._session_counter}",
            initiator=self._agent_id,
            partner=partner,
            status=NegotiationStatus.OPEN,
            current_terms=terms,
            history=[terms],
        )

    async def offer(self, session: NegotiationSession, terms: Terms) -> None:
        """Record an offer as the current terms and append it to history.

        Example::

            await neg.offer(session, Terms(price=Money(amount=80), conditions={"deadline_days": 7}))
        """
        session.current_terms = terms
        session.history.append(terms)

    async def respond(self, session: NegotiationSession) -> NegotiationResponse:
        """Accept if the opponent's offer clears aspiration, else trade off.

        Reads the opponent's latest offer from ``session.current_terms``. If its
        own-utility is at least this round's aspiration ``alpha(t)`` the offer is
        accepted; otherwise the agent returns the aspiration-satisfying grid
        bundle nearest (in normalized issue space) to the opponent's offer, a
        Faratin–Sierra–Jennings trade-off move along the iso-utility curve. When
        aspiration exceeds the agent's reachable maximum it counters with its
        single most-preferred bundle.

        Example::

            resp = await neg.respond(session)
        """
        opponent = session.current_terms
        if opponent is None or opponent.price is None:
            return NegotiationResponse(accepted=True)

        round_index = self._rounds.get(session.id, 0)
        self._rounds[session.id] = round_index + 1
        alpha = self._aspiration(round_index)

        if self.utility(opponent) >= alpha:
            return NegotiationResponse(accepted=True)

        plo, phi = self._price_range
        dlo, dhi = self._deadline_range
        p_span = phi - plo
        d_span = dhi - dlo
        p_opp, d_opp = self._clamp(*self._extract(opponent))

        grid = self._grid()
        acceptable = [(p, d) for (p, d) in grid if self._score(p, d) >= alpha]
        if acceptable:
            p_b, d_b = min(
                acceptable,
                key=lambda b: (
                    ((b[0] - p_opp) / p_span) ** 2 + ((b[1] - d_opp) / d_span) ** 2,
                    b[0],
                    b[1],
                ),
            )
        else:
            # Aspiration above our reachable maximum: offer our most-preferred bundle.
            p_b, d_b = min(grid, key=lambda b: (-self._score(b[0], b[1]), b[0], b[1]))

        counter = Terms(price=Money(amount=p_b), conditions={"deadline_days": d_b})
        return NegotiationResponse(accepted=False, counter_terms=counter)

    async def close(self, session: NegotiationSession) -> Agreement | None:
        """Return an agreement if the session was agreed, else mark it rejected.

        Example::

            agreement = await neg.close(session)
        """
        if session.status == NegotiationStatus.AGREED:
            return Agreement(
                session_id=session.id,
                terms=session.current_terms or Terms(),
                parties=[session.initiator, session.partner],
            )
        session.status = NegotiationStatus.REJECTED
        return None

    def utility(self, terms: Terms) -> float:
        """Return this agent's additive multi-attribute utility for ``terms``.

        Combines the price and deadline value functions (each normalized to
        ``[0, 1]`` per the agent's directional convention) weighted by
        ``weights``. Inputs are clamped into the feasible ranges before scoring.

        Example::

            neg = ParetoNegotiation(
                AgentId("buyer"),
                weights={"price": 0.5, "deadline": 0.5},
                price_range=(10, 20),
                deadline_range=(1, 5),
                side="buyer",
            )
            neg.utility(Terms(price=Money(amount=10), conditions={"deadline_days": 1}))  # 1.0
        """
        return self._score(*self._extract(terms))

    def _aspiration(self, round_index: int) -> float:
        """Non-increasing own-utility floor for a round (Zeuthen/MCP schedule).

        ``alpha(t) = reservation + (1 - reservation) * patience ** t``, with ``t``
        capped at ``max_rounds`` so the floor settles at the agent's deadline
        horizon while staying monotonically non-increasing.
        """
        t = min(round_index, self._max_rounds)
        return self._reservation + (1.0 - self._reservation) * (self._patience**t)

    def _grid(self) -> list[tuple[int, int]]:
        """Deterministic enumeration of every feasible (price, deadline) bundle."""
        plo, phi = self._price_range
        dlo, dhi = self._deadline_range
        return [(p, d) for p in range(plo, phi + 1) for d in range(dlo, dhi + 1)]

    def _extract(self, terms: Terms) -> tuple[int, int]:
        """Pull the raw (price, deadline) pair out of ``terms`` as ints."""
        plo, _ = self._price_range
        dlo, _ = self._deadline_range
        price = terms.price.amount if terms.price is not None else plo
        deadline = int(terms.conditions.get("deadline_days", dlo))
        return price, deadline

    def _clamp(self, price: int, deadline: int) -> tuple[int, int]:
        """Clamp a (price, deadline) pair into the feasible ranges."""
        plo, phi = self._price_range
        dlo, dhi = self._deadline_range
        return max(plo, min(phi, price)), max(dlo, min(dhi, deadline))

    def _score(self, price: int, deadline: int) -> float:
        """Additive MAUT score for a (price, deadline) pair after clamping."""
        plo, phi = self._price_range
        dlo, dhi = self._deadline_range
        p, d = self._clamp(price, deadline)
        if self._side == "buyer":
            # Buyer prefers a low price and a short deadline.
            f_price = (phi - p) / (phi - plo)
            f_deadline = (dhi - d) / (dhi - dlo)
        else:
            # Seller prefers a high price and a long deadline.
            f_price = (p - plo) / (phi - plo)
            f_deadline = (d - dlo) / (dhi - dlo)
        return self._weights["price"] * f_price + self._weights["deadline"] * f_deadline
