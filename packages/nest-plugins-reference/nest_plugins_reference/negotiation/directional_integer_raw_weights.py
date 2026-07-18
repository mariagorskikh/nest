# SPDX-License-Identifier: Apache-2.0
"""Directional integer multi-attribute negotiation.

The preference weights are preserved exactly as supplied. Only the
negotiated attributes are normalized.

Attribute normalization:
    normalized_price = (price - price_min) / (price_max - price_min)
    normalized_delay = (delay - delay_min) / (delay_max - delay_min)

The policy score is:
    score = a * normalized_price + b * normalized_delay

A seller prefers a larger score. A buyer prefers a smaller score. If the
weights are non-negative, the score lies in ``[0, a + b]``. Therefore the
buyer's conventional "higher is better" utility is ``(a + b) - score``.

At response round t, the current threshold is:
    U_t = reservation + (initial_utility - reservation)
          * patience ** min(t, max_rounds)
"""

from __future__ import annotations

# IMPLEMENTATION_VERSION = "raw-weights-normalized-attributes-v1"

import math
from typing import Iterable, Literal

from nest_core.types import (
    AgentId,
    Agreement,
    Money,
    NegotiationResponse,
    NegotiationSession,
    NegotiationStatus,
    Terms,
)

Point = tuple[int, int]
Side = Literal["buyer", "seller"]


class DirectionalIntegerRawWeightsNegotiation:
    """Negotiator implementing the requested directional integer policy.

    Price and deadline are normalized, but the preference weights are not.
    Consequently, ``initial_utility`` and ``reservation`` are interpreted on
    the policy-score scale ``[0, a + b]``:

    * seller accepts when score >= U_t;
    * buyer accepts when score <= U_t.

    If ``initial_utility`` is omitted, the default is ``a + b`` for a seller
    and ``0`` for a buyer—the corresponding ideal policy scores.
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        a: float | None = None,
        b: float | None = None,
        initial_utility: float | None = None,
        U: float | None = None,
        side: Side,
        price_range: tuple[int, int] = (0, 10_000),
        deadline_range: tuple[int, int] = (0, 10_000),
        weights: dict[str, float] | None = None,
        patience: float = 0.9,
        reservation: float = 0.0,
        max_rounds: int = 12,
    ) -> None:
        if a is None and weights is not None:
            a = float(weights["price"])
        if b is None and weights is not None:
            b = float(weights["deadline"])

        if a is None or b is None:
            raise ValueError("Provide a and b, or weights with price/deadline.")
        if not math.isfinite(a) or not math.isfinite(b):
            raise ValueError("a and b must be finite.")
        if a < 0 or b < 0:
            raise ValueError("a and b must be non-negative.")
        if a == 0 and b == 0:
            raise ValueError("a and b cannot both be zero.")
        if side not in {"buyer", "seller"}:
            raise ValueError("side must be 'buyer' or 'seller'.")

        self._validate_range("price_range", price_range)
        self._validate_range("deadline_range", deadline_range)

        self._a = float(a)
        self._b = float(b)
        self._maximum_score = self._a + self._b

        if initial_utility is not None and U is not None and initial_utility != U:
            raise ValueError("initial_utility and U disagree.")

        chosen_u = initial_utility if initial_utility is not None else U
        if chosen_u is None:
            chosen_u = self._maximum_score if side == "seller" else 0.0

        if not math.isfinite(chosen_u):
            raise ValueError("initial utility U must be finite.")
        if not math.isfinite(reservation):
            raise ValueError("reservation must be finite.")
        if not 0.0 <= chosen_u <= self._maximum_score:
            raise ValueError(
                "initial utility U must lie in [0, a + b]."
            )
        if not 0.0 <= reservation <= self._maximum_score:
            raise ValueError(
                "reservation must lie in [0, a + b]."
            )
        if reservation > chosen_u:
            raise ValueError(
                "reservation must not exceed initial utility when U decreases."
            )
        if not math.isfinite(patience) or not 0.0 <= patience <= 1.0:
            raise ValueError("patience must lie in [0, 1].")
        if max_rounds < 0:
            raise ValueError("max_rounds must be non-negative.")

        self._agent_id = agent_id
        self._initial_utility = float(chosen_u)
        self._patience = float(patience)
        self._reservation = float(reservation)
        self._max_rounds = int(max_rounds)
        self._side: Side = side
        self._price_range = price_range
        self._deadline_range = deadline_range

        self._session_counter = 0
        self._rounds: dict[str, int] = {}
        self._first_opponent_bid: dict[str, Point] = {}
        self._first_own_bid: dict[str, Point] = {}

    @property
    def price_preference(self) -> float:
        return self._a

    @property
    def deadline_preference(self) -> float:
        return self._b

    def aspiration(self, round_index: int) -> float:
        """Return the current normalized policy-score threshold."""
        t = min(max(round_index, 0), self._max_rounds)
        return self._reservation + (
            self._initial_utility - self._reservation
        ) * (self._patience**t)

    @property
    def maximum_score(self) -> float:
        """Return the largest possible policy score, equal to a + b."""
        return self._maximum_score

    def weighted_sum(self, terms_or_point: Terms | Point) -> float:
        """Return the attribute-normalized policy score in [0, a + b].

        Higher is better for a seller. Lower is better for a buyer.
        """
        point = (
            self._extract(terms_or_point)
            if isinstance(terms_or_point, Terms)
            else self._clamp(*terms_or_point)
        )
        price, deadline = point
        return (
            self._a * self._normalize_price(price)
            + self._b * self._normalize_deadline(deadline)
        )

    def utility(self, terms_or_point: Terms | Point) -> float:
        """Return conventional utility where higher is better for either side."""
        score = self.weighted_sum(terms_or_point)
        return (
            score
            if self._side == "seller"
            else self._maximum_score - score
        )

    async def open(self, partner: AgentId, terms: Terms) -> NegotiationSession:
        self._session_counter += 1
        session = NegotiationSession(
            id=f"directional-integer-{self._agent_id}-{self._session_counter}",
            initiator=self._agent_id,
            partner=partner,
            status=NegotiationStatus.OPEN,
            current_terms=terms,
            history=[terms],
        )
        self._rounds[session.id] = 0
        return session

    async def offer(self, session: NegotiationSession, terms: Terms) -> None:
        if session.status != NegotiationStatus.OPEN:
            raise ValueError(f"Cannot offer into a {session.status.value} session.")
        session.current_terms = terms
        session.history.append(terms)

    async def respond(self, session: NegotiationSession) -> NegotiationResponse:
        opponent_terms = session.current_terms
        if opponent_terms is None or opponent_terms.price is None:
            raise ValueError("Cannot respond without a price-bearing offer.")

        opponent = self._extract(opponent_terms)
        self._first_opponent_bid.setdefault(session.id, opponent)

        round_index = self._rounds.get(session.id, 0)
        current_u = self.aspiration(round_index)
        self._rounds[session.id] = round_index + 1

        if self._acceptable(opponent, current_u):
            session.status = NegotiationStatus.AGREED
            return NegotiationResponse(accepted=True)

        if session.id not in self._first_own_bid:
            own_bid = self._choose(
                self._first_bid_candidates(current_u),
                current_u,
            )
            self._first_own_bid[session.id] = own_bid
        else:
            own_bid = self._later_bid(session.id, current_u)

        return NegotiationResponse(
            accepted=False,
            counter_terms=self._to_terms(own_bid),
        )

    async def close(self, session: NegotiationSession) -> Agreement | None:
        if session.status == NegotiationStatus.AGREED:
            return Agreement(
                session_id=session.id,
                terms=session.current_terms or Terms(),
                parties=[session.initiator, session.partner],
            )

        session.status = NegotiationStatus.REJECTED
        return None

    def _acceptable(self, opponent: Point, current_u: float) -> bool:
        score = self.weighted_sum(opponent)
        tolerance = 1e-12
        if self._side == "seller":
            return score + tolerance >= current_u
        return score - tolerance <= current_u

    def _first_bid_candidates(self, current_u: float) -> list[Point]:
        """Construct raw integer bids from normalized affine coefficients."""
        price_coefficient, deadline_coefficient, offset = (
            self._raw_affine_representation()
        )
        affine_threshold = current_u + offset
        denominator = (
            price_coefficient * price_coefficient
            + deadline_coefficient * deadline_coefficient
        )

        if denominator == 0:
            return [self._ideal_point()]

        # Preserve the requested swapped coordinate formula.
        price_real = affine_threshold * deadline_coefficient / denominator
        deadline_real = affine_threshold * price_coefficient / denominator

        prices = (math.floor(price_real), math.ceil(price_real))
        deadlines = (math.floor(deadline_real), math.ceil(deadline_real))

        return self._normalize_candidates(
            (price, deadline)
            for price in prices
            for deadline in deadlines
        )

    def _later_bid(self, session_id: str, current_u: float) -> Point:
        r, s = self._first_opponent_bid[session_id]
        m, n = self._first_own_bid[session_id]

        opponent_ratio = self._safe_ratio(r, s)
        own_ratio = self._safe_ratio(m, n)

        if self._side == "seller":
            use_price_axis = opponent_ratio <= own_ratio
        else:
            use_price_axis = opponent_ratio >= own_ratio

        candidates = (
            self._price_axis_candidates(current_u)
            if use_price_axis
            else self._delay_axis_candidates(current_u)
        )
        return self._choose(candidates, current_u)

    def _price_axis_candidates(self, current_u: float) -> list[Point]:
        price_coefficient, _, offset = self._raw_affine_representation()
        if price_coefficient == 0:
            return self._delay_axis_candidates(current_u)

        value = (current_u + offset) / price_coefficient
        return self._normalize_candidates(
            [(math.ceil(value), 0), (math.floor(value), 1)]
        )

    def _delay_axis_candidates(self, current_u: float) -> list[Point]:
        _, deadline_coefficient, offset = self._raw_affine_representation()
        if deadline_coefficient == 0:
            return self._price_axis_candidates(current_u)

        value = (current_u + offset) / deadline_coefficient
        return self._normalize_candidates(
            [(0, math.ceil(value)), (1, math.floor(value))]
        )

    def _choose(self, candidates: Iterable[Point], current_u: float) -> Point:
        """Choose nearest to threshold on the side's acceptable side.

        If the prescribed candidates do not contain a qualifying point, search
        the complete feasible integer grid. This prevents the negotiator from
        proposing an offer that violates its own current threshold.
        """
        prescribed = list(candidates)
        if not prescribed:
            raise RuntimeError("The strategy produced no candidate bids.")

        eligible = self._eligible(prescribed, current_u)
        if not eligible:
            eligible = self._eligible(self._full_grid(), current_u)

        if not eligible:
            return self._ideal_point()

        if self._side == "seller":
            return min(
                eligible,
                key=lambda point: (
                    self.weighted_sum(point),
                    point[0],
                    point[1],
                ),
            )

        return max(
            eligible,
            key=lambda point: (
                self.weighted_sum(point),
                -point[0],
                -point[1],
            ),
        )

    def _eligible(
        self,
        candidates: Iterable[Point],
        current_u: float,
    ) -> list[Point]:
        tolerance = 1e-12
        if self._side == "seller":
            return [
                point
                for point in candidates
                if self.weighted_sum(point) + tolerance >= current_u
            ]
        return [
            point
            for point in candidates
            if self.weighted_sum(point) - tolerance <= current_u
        ]

    def _full_grid(self) -> Iterable[Point]:
        price_min, price_max = self._price_range
        deadline_min, deadline_max = self._deadline_range
        for price in range(price_min, price_max + 1):
            for deadline in range(deadline_min, deadline_max + 1):
                yield (price, deadline)

    def _ideal_point(self) -> Point:
        price_min, price_max = self._price_range
        deadline_min, deadline_max = self._deadline_range
        if self._side == "seller":
            return (price_max, deadline_max)
        return (price_min, deadline_min)

    def _raw_affine_representation(self) -> tuple[float, float, float]:
        """Return c_p, c_d, offset such that score=c_p*p+c_d*d-offset."""
        price_min, price_max = self._price_range
        deadline_min, deadline_max = self._deadline_range

        price_span = price_max - price_min
        deadline_span = deadline_max - deadline_min

        price_coefficient = self._a / price_span if price_span else 0.0
        deadline_coefficient = self._b / deadline_span if deadline_span else 0.0

        offset = (
            price_coefficient * price_min
            + deadline_coefficient * deadline_min
        )
        return price_coefficient, deadline_coefficient, offset

    def _normalize_price(self, price: int) -> float:
        price_min, price_max = self._price_range
        if price_max == price_min:
            return 0.0
        return (price - price_min) / (price_max - price_min)

    def _normalize_deadline(self, deadline: int) -> float:
        deadline_min, deadline_max = self._deadline_range
        if deadline_max == deadline_min:
            return 0.0
        return (deadline - deadline_min) / (deadline_max - deadline_min)

    def _normalize_candidates(self, candidates: Iterable[Point]) -> list[Point]:
        result: list[Point] = []
        seen: set[Point] = set()
        for price, deadline in candidates:
            point = self._clamp(int(price), int(deadline))
            if point not in seen:
                seen.add(point)
                result.append(point)
        return result

    def _extract(self, terms: Terms) -> Point:
        price = terms.price.amount if terms.price is not None else self._price_range[0]
        deadline = int(
            terms.conditions.get("deadline_days", self._deadline_range[0])
        )
        return self._clamp(price, deadline)

    def _to_terms(self, point: Point) -> Terms:
        price, deadline = point
        return Terms(
            price=Money(amount=price),
            conditions={"deadline_days": deadline},
        )

    def _clamp(self, price: int, deadline: int) -> Point:
        price_min, price_max = self._price_range
        deadline_min, deadline_max = self._deadline_range
        return (
            max(price_min, min(price_max, price)),
            max(deadline_min, min(deadline_max, deadline)),
        )

    @staticmethod
    def _safe_ratio(numerator: int, denominator: int) -> float:
        if denominator != 0:
            return numerator / denominator
        if numerator > 0:
            return math.inf
        if numerator < 0:
            return -math.inf
        return 0.0

    @staticmethod
    def _validate_range(name: str, value: tuple[int, int]) -> None:
        if len(value) != 2 or value[0] > value[1]:
            raise ValueError(f"{name} must be an ordered (minimum, maximum) pair.")
