# SPDX-License-Identifier: Apache-2.0
"""Multi-attribute Pareto-frontier negotiation plugin.

Bargains over three attributes — price premium (p), quantity (n), and quality
(q) — and converges to a Pareto-optimal agreement.  Quality is static per
candidate (set once at session open; gates feasibility but is never moved
during bargaining).  The live axes are price and quantity.

Registered as ``("negotiation", "pareto")``.

Utility model
-------------
Each agent holds private ``ParetoParams`` encoding weights, hard reservations,
aspirations, a kappa function for quantity, and a disagreement utility.

    u_i(p, n, q) = w_p * v_p(p) + w_n * v_n(n) + w_q * v_q(q)

Normalized issue values::

    Buyer:  v_p(p) = (max_p - p) / (max_p - min_p)   [lower price → higher]
    Seller: v_p(p) = (p - min_p) / (max_p - min_p)   [higher price → higher]
    Buyer:  v_n(n) = 1 - kappa * (n - target_n)^2    clamped [0,1]
    Seller: v_n(n) = min(n / capacity, 1.0)
    Both:   v_q(q) = max(0, q - min_q) / (1 - min_q)  [quality gate]

Strategy catalog (6 strategies, equations from spec secs 10-12)
---------------------------------------------------------------
Each strategy implements one method::

    def counter(
        self, params, own_grid, opp_cur, opp_prev, own_last, rnd, q,
        meta,
    ) -> tuple[int,int] | None

``own_grid``  — list[(p,n)] feasible for this agent at fixed q.
``opp_cur``   — opponent's current offer (p,n).
``opp_prev``  — opponent's offer from the previous round, or None on round 0.
``own_last``  — this agent's last counter-proposal, or None on round 0.
``rnd``       — current round index (0-based).
``meta``      — mutable session-state dict (allows strategies to read/update
                estimated opponent weights and other per-session bookkeeping).

Strategy 10 — Directional tit-for-tat (``ttt_directional``)
    Mirror a bounded fraction rho_k of the opponent's per-issue movement:

        z_i,k^{t+1} = clip_{[z_i,k^A, z_i,k^R]}(
                           z_i,k^t + rho_i,k * (z_j,k^t - z_j,k^{t-1})
                       )   for k in {p, n}

    where z can be p or n (kappa(n) in the spec; we work in raw n-space and
    apply kappa inside v_n when evaluating utility).  rho_p, rho_n in [0,1]
    are per-agent seeded scalars.  On round 0 (no previous opponent offer),
    falls back to own best feasible point.

Strategy 11a — Zeuthen concession (``zeuthen_concede``)
    Compare normalized disagreement risk and let the lower-risk agent concede:

        R_i^t = [u_i(x_i^t) - u_i(x_j^t)] / [u_i(x_i^t) - d_i]

    Agent i concedes (reduces tau) when R_i^t <= R_j^t.  Concession
    decrement gamma_i^t is the smallest step that would lower R_i below R_j:

        tau_i^{t+1} = max(d_i, tau_i^t - gamma_i^t)

    Implemented as a discrete ladder: gamma = tau_step (a seeded constant).
    When not conceding, proposes the best own-feasible point still above tau.

Strategy 11b — Rubinstein discount (``rubinstein_discount``)
    Apply a per-round patience discount to the continuation value:

        U_i(x, t) = delta_i^t * u_i(x),   0 < delta_i < 1

    Accept x_j^t when u_i(x_j^t) >= delta_i * V_i^{t+1},
    where V_i^{t+1} is the agent's current best reachable utility.
    The counter-proposal is the own-feasible point with highest discounted
    utility that is strictly above the discounted continuation value.

Strategy 12a — Logrolling (``logrolling_tradeoff``)
    Stay on own iso-utility contour while maximising estimated opponent utility:

        x_i^{t+1} = argmax_{x in C_i^t} uhat_j(x)
        uhat_j(x) = what_j,p*vhat_j,p(p) + what_j,n*vhat_j,n(n)
                    + what_j,q*vhat_j,q(q)

    Opponent weights are inferred from offer history: the axis on which the
    opponent moved most (relative to reservation range) gets the highest
    estimated weight.  C_i^t is approximated as points in own_grid whose
    utility is within a patience-scaled tolerance of the current best.

Strategy 12b — Nash bargaining target (``nash_bargaining``)
    Propose the Nash bargaining solution on own feasible grid:

        x^N = argmax_{x in own_grid} (u_i(x) - d_i)^beta_i
                                     * (uhat_j(x) - d_j_hat)^(1-beta_i)

    beta_i is a seeded fairness weight in (0,1).  d_j_hat = 0.  Uses the
    same opponent-weight estimate as logrolling.

Strategy 12c — Kalai-Smorodinsky target (``ks_bargaining``)
    Find the KS point: proportional concession along the line from
    (d_A, d_B) to (m_A, m_B) on the own feasible grid:

        (u_i(x) - d_i) / (m_i - d_i) = lambda   for some lambda in [0,1]

    Proposes the own-feasible point that maximises lambda while remaining
    feasible.  m_i = max over own_grid of u_i(x).

Validator integration
---------------------
Agents using this plugin MUST emit colon-delimited trace lines so the offline
Pareto validator can reconstruct offer sequences and utility configs:

    ``config:<agent_id>:<json_params>``
    ``offer:<agent_id>:<partner_id>:r<round>:p=<p>,n=<n>,q=<q>:<strategy_id>``
    ``close:agreed:<session_id>:p=<p>,n=<n>,q=<q>``
    ``close:breakdown:<session_id>``

These lines are emitted by ``ParetoNegotiatorAgent`` (in
``scenarios_builtin.multi_attribute_market``), not by this plugin, so the
plugin itself is transport-agnostic.

Example::

    params = ParetoParams.for_buyer(agent_id=AgentId("buyer-0"), seed=7)
    neg = ParetoNegotiator(AgentId("buyer-0"), params)
    session = await neg.open(AgentId("seller-0"), Terms(price=Money(amount=80),
                             conditions={"quantity": 10, "quality": 0.75}))
    resp = await neg.respond(session)
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from nest_core.types import (
    AgentId,
    Agreement,
    Money,
    NegotiationResponse,
    NegotiationSession,
    NegotiationStatus,
    Terms,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PRICE_MIN = 0
_PRICE_MAX = 100
_PRICE_STEP = 5
_QUANTITY_STEP = 1

# Iso-utility tolerance band as a fraction of the current tau.
# Points with u_i >= tau * (1 - _CONTOUR_TOL) are considered "on the contour."
_CONTOUR_TOL = 0.05


# ---------------------------------------------------------------------------
# Parameter derivation
# ---------------------------------------------------------------------------


def _agent_rng(agent_id: AgentId, scenario_seed: int) -> random.Random:
    """Deterministic per-agent RNG from agent_id and scenario seed."""
    h = hash(str(agent_id)) & 0xFFFF_FFFF_FFFF_FFFF
    return random.Random(scenario_seed ^ h)


@dataclass
class ParetoParams:
    """Private utility parameters for one agent in a multi-attribute negotiation.

    New fields beyond the basic utility weights
    -------------------------------------------
    rho_p, rho_n : float in [0,1]
        TTT mirroring factors (spec eq. 10).  Controls what fraction of the
        opponent's per-issue movement this agent mirrors each round.
    delta : float in (0,1)
        Rubinstein per-round patience discount (spec eq. 11b).  Closer to 1
        means the agent concedes more slowly.
    tau_step : float > 0
        Smallest Zeuthen concession decrement (spec eq. 11a).  Determines the
        ladder grain.
    beta : float in (0,1)
        Asymmetric Nash bargaining power (spec eq. 12b).  Higher beta weights
        the agent's own surplus more in the Nash product.

    Example::

        p = ParetoParams.for_buyer(AgentId("buyer-0"), seed=7)
        u = p.utility(p=40, n=15, q=0.75)
    """

    agent_id: AgentId
    role: str  # "buyer" or "seller"
    w_p: float
    w_n: float
    w_q: float
    min_p: int
    max_p: int
    target_p: int
    min_n: int
    max_n: int
    target_n: int
    capacity: int
    min_quality: float
    kappa: float
    # Strategy-specific scalars (all seeded, all deterministic)
    disagreement_utility: float = 0.0
    patience: float = 0.85
    rho_p: float = 0.5  # TTT price mirror factor
    rho_n: float = 0.5  # TTT quantity mirror factor
    delta: float = 0.9  # Rubinstein per-round discount
    tau_step: float = 0.05  # Zeuthen concession ladder grain
    beta: float = 0.5  # Nash asymmetric power
    strategy_id: str = "ttt_directional"

    @classmethod
    def for_buyer(cls, agent_id: AgentId, seed: int, pair_index: int = 0) -> ParetoParams:
        """Derive buyer params deterministically from agent_id and scenario seed.

        Example::

            p = ParetoParams.for_buyer(AgentId("buyer-0"), seed=7)
        """
        rng = _agent_rng(agent_id, seed)
        w_p = rng.uniform(0.40, 0.65)
        w_n = rng.uniform(0.10, 0.35)
        w_q = max(0.05, 1.0 - w_p - w_n)
        total = w_p + w_n + w_q
        w_p, w_n, w_q = w_p / total, w_n / total, w_q / total

        max_p = rng.randint(35, 60)
        target_p = rng.randint(10, max_p - 10)
        min_n = rng.randint(3, 8)
        max_n = rng.randint(20, 45)
        target_n = rng.randint(min_n + 5, max(min_n + 6, max_n - 5))
        min_quality = rng.uniform(0.45, 0.80)
        kappa = rng.uniform(0.008, 0.04)

        # Strategy-specific scalars
        rho_p = rng.uniform(0.3, 0.7)
        rho_n = rng.uniform(0.3, 0.7)
        delta = rng.uniform(0.80, 0.95)
        tau_step = rng.uniform(0.03, 0.10)
        beta = rng.uniform(0.4, 0.6)

        strategies = STRATEGY_IDS
        idx = (pair_index * 2) % len(strategies)
        strategy_id = strategies[idx]

        return cls(
            agent_id=agent_id,
            role="buyer",
            w_p=w_p,
            w_n=w_n,
            w_q=w_q,
            min_p=_PRICE_MIN,
            max_p=max_p,
            target_p=target_p,
            min_n=min_n,
            max_n=max_n,
            target_n=target_n,
            capacity=max_n,
            min_quality=min_quality,
            kappa=kappa,
            rho_p=rho_p,
            rho_n=rho_n,
            delta=delta,
            tau_step=tau_step,
            beta=beta,
            strategy_id=strategy_id,
        )

    @classmethod
    def for_seller(cls, agent_id: AgentId, seed: int, pair_index: int = 0) -> ParetoParams:
        """Derive seller params deterministically from agent_id and scenario seed.

        Example::

            p = ParetoParams.for_seller(AgentId("seller-0"), seed=7)
        """
        rng = _agent_rng(agent_id, seed)
        w_p = rng.uniform(0.45, 0.75)
        w_n = rng.uniform(0.10, 0.30)
        w_q = max(0.05, 1.0 - w_p - w_n)
        total = w_p + w_n + w_q
        w_p, w_n, w_q = w_p / total, w_n / total, w_q / total

        min_p = rng.randint(30, 65)
        target_p = rng.randint(min_p + 10, 95)
        capacity = rng.randint(25, 55)
        min_n = rng.randint(1, 5)
        max_n = capacity
        target_n = rng.randint(capacity // 2, capacity)
        min_quality = rng.uniform(0.45, 0.75)
        kappa = rng.uniform(0.003, 0.015)

        rho_p = rng.uniform(0.3, 0.7)
        rho_n = rng.uniform(0.3, 0.7)
        delta = rng.uniform(0.80, 0.95)
        tau_step = rng.uniform(0.03, 0.10)
        beta = rng.uniform(0.4, 0.6)

        strategies = STRATEGY_IDS
        idx = (pair_index * 2 + 1) % len(strategies)
        strategy_id = strategies[idx]

        return cls(
            agent_id=agent_id,
            role="seller",
            w_p=w_p,
            w_n=w_n,
            w_q=w_q,
            min_p=min_p,
            max_p=_PRICE_MAX,
            target_p=target_p,
            min_n=min_n,
            max_n=max_n,
            target_n=target_n,
            capacity=capacity,
            min_quality=min_quality,
            kappa=kappa,
            rho_p=rho_p,
            rho_n=rho_n,
            delta=delta,
            tau_step=tau_step,
            beta=beta,
            strategy_id=strategy_id,
        )

    def feasible(self, p: int, n: int, q: float) -> bool:
        """Return True iff (p,n,q) satisfies this agent's hard reservations.

        Example::

            assert params.feasible(40, 15, 0.75)
        """
        if self.role == "buyer":
            return (
                _PRICE_MIN <= p <= self.max_p
                and self.min_n <= n <= self.max_n
                and q >= self.min_quality
            )
        return (
            self.min_p <= p <= _PRICE_MAX
            and self.min_n <= n <= self.max_n
            and q >= self.min_quality
        )

    def v_p(self, p: int) -> float:
        """Normalised price value in [0,1]."""
        span = self.max_p - self.min_p
        if span == 0:
            return 1.0
        if self.role == "buyer":
            return max(0.0, min(1.0, (self.max_p - p) / span))
        return max(0.0, min(1.0, (p - self.min_p) / span))

    def v_n(self, n: int) -> float:
        """Normalised quantity value in [0,1]."""
        if self.role == "buyer":
            raw = 1.0 - self.kappa * (n - self.target_n) ** 2
            return max(0.0, min(1.0, raw))
        return min(1.0, n / max(1, self.capacity))

    def v_q(self, q: float) -> float:
        """Normalised quality value in [0,1]."""
        span = 1.0 - self.min_quality
        if span <= 0:
            return 1.0 if q >= self.min_quality else 0.0
        return max(0.0, min(1.0, (q - self.min_quality) / span))

    def utility(self, p: int, n: int, q: float) -> float:
        """Local additive utility u_i(p,n,q) in [0,1].

        Example::

            u = params.utility(40, 15, 0.75)
        """
        return self.w_p * self.v_p(p) + self.w_n * self.v_n(n) + self.w_q * self.v_q(q)

    def to_dict(self) -> dict[str, Any]:
        """Serialise params for trace config line."""
        return {
            "role": self.role,
            "w_p": round(self.w_p, 6),
            "w_n": round(self.w_n, 6),
            "w_q": round(self.w_q, 6),
            "min_p": self.min_p,
            "max_p": self.max_p,
            "target_p": self.target_p,
            "min_n": self.min_n,
            "max_n": self.max_n,
            "target_n": self.target_n,
            "capacity": self.capacity,
            "min_quality": round(self.min_quality, 6),
            "kappa": round(self.kappa, 8),
            "disagreement_utility": self.disagreement_utility,
            "patience": self.patience,
            "rho_p": round(self.rho_p, 6),
            "rho_n": round(self.rho_n, 6),
            "delta": round(self.delta, 6),
            "tau_step": round(self.tau_step, 6),
            "beta": round(self.beta, 6),
            "strategy_id": self.strategy_id,
        }


# ---------------------------------------------------------------------------
# Pareto frontier computation (used by offline validator)
# ---------------------------------------------------------------------------


def build_feasible_grid(
    params_a: ParetoParams,
    params_b: ParetoParams,
    q: float,
    p_step: int = _PRICE_STEP,
    n_step: int = _QUANTITY_STEP,
) -> list[tuple[int, int]]:
    """Return all (p,n) feasible for BOTH agents at fixed quality q."""
    p_lo = max(params_a.min_p, params_b.min_p)
    p_hi = min(params_a.max_p, params_b.max_p)
    n_lo = max(params_a.min_n, params_b.min_n)
    n_hi = min(params_a.max_n, params_b.max_n)

    if p_lo > p_hi or n_lo > n_hi:
        return []

    points: list[tuple[int, int]] = []
    p = p_lo
    while p <= p_hi:
        n = n_lo
        while n <= n_hi:
            if params_a.feasible(p, n, q) and params_b.feasible(p, n, q):
                points.append((p, n))
            n += n_step
        p += p_step
    return points


def pareto_nondominated(
    points: list[tuple[int, int]],
    params_a: ParetoParams,
    params_b: ParetoParams,
    q: float,
) -> list[tuple[int, int]]:
    """Return the Pareto-nondominated subset of points for agents A and B.

    Point x dominates y iff u_A(x) >= u_A(y) AND u_B(x) >= u_B(y), one strict.

    Example::

        frontier = pareto_nondominated(points, params_a, params_b, 0.75)
    """
    scored: list[tuple[int, int, float, float]] = [
        (p, n, params_a.utility(p, n, q), params_b.utility(p, n, q)) for p, n in points
    ]
    frontier: list[tuple[int, int]] = []
    for i, (p, n, ua, ub) in enumerate(scored):
        dominated = False
        for j, (_, _, ua2, ub2) in enumerate(scored):
            if i == j:
                continue
            if ua2 >= ua and ub2 >= ub and (ua2 > ua or ub2 > ub):
                dominated = True
                break
        if not dominated:
            frontier.append((p, n))
    return frontier


# ---------------------------------------------------------------------------
# Opponent-weight estimation (shared by logrolling and Nash/KS strategies)
# ---------------------------------------------------------------------------


def _update_opp_weight_estimate(
    meta: dict[str, Any],
    opp_cur: tuple[int, int],
    opp_prev: tuple[int, int] | None,
    params: ParetoParams,
) -> tuple[float, float, float]:
    """Infer opponent weights from directional movement.

    Uses exponential moving average over observed per-issue movements,
    normalised by each issue's reservation range.  Initialises from own
    weights (symmetric prior) when no movement data yet exists.

    Returns (w_p_hat, w_n_hat, w_q_hat) summing to 1.
    """
    # Initialise on first call
    if "opp_hat_w_p" not in meta:
        meta["opp_hat_w_p"] = params.w_p
        meta["opp_hat_w_n"] = params.w_n
        meta["opp_hat_w_q"] = params.w_q

    if opp_prev is None:
        return meta["opp_hat_w_p"], meta["opp_hat_w_n"], meta["opp_hat_w_q"]

    p_cur, n_cur = opp_cur
    p_prev, n_prev = opp_prev

    p_range = max(1, params.max_p - params.min_p)
    n_range = max(1, params.max_n - params.min_n)

    # Normalised absolute movement per issue
    move_p = abs(p_cur - p_prev) / p_range
    move_n = abs(n_cur - n_prev) / n_range
    total_move = move_p + move_n

    if total_move < 1e-9:
        return meta["opp_hat_w_p"], meta["opp_hat_w_n"], meta["opp_hat_w_q"]

    # Opponent moves more on the issue it cares about — higher movement → higher weight
    alpha = 0.4  # EMA smoothing
    w_p_obs = move_p / total_move
    w_n_obs = move_n / total_move
    # Quality not directly observable from (p,n) offers; keep prior
    w_q_prior = meta["opp_hat_w_q"]
    # Redistribute: scale p,n observations to leave room for q
    scale = 1.0 - w_q_prior
    w_p_new = (1 - alpha) * meta["opp_hat_w_p"] + alpha * (w_p_obs * scale)
    w_n_new = (1 - alpha) * meta["opp_hat_w_n"] + alpha * (w_n_obs * scale)
    total = w_p_new + w_n_new + w_q_prior
    if total > 0:
        w_p_new /= total
        w_n_new /= total
        w_q_prior = w_q_prior / total

    meta["opp_hat_w_p"] = w_p_new
    meta["opp_hat_w_n"] = w_n_new
    meta["opp_hat_w_q"] = w_q_prior
    return w_p_new, w_n_new, w_q_prior


def _opp_utility_hat(
    p: int,
    n: int,
    q: float,
    w_p_hat: float,
    w_n_hat: float,
    w_q_hat: float,
    params: ParetoParams,
    opp_role: str = "",
    opp_n_mean: float = -1.0,
    opp_n_var: float = -1.0,
    opp_n_min: float = -1.0,
) -> float:
    """Estimate opponent utility using inferred weights and role-aware issue value forms.

    ``opp_role`` is inferred from the session: the agent who opens the session
    is the buyer; the responder is the seller.  This is observable from the
    wire protocol — not global knowledge of private utility functions.

    Role-aware ``v_n`` forms:

    - Seller (linear): ``v_n = min(n / capacity_hat, 1.0)`` where
      ``capacity_hat`` is the largest ``n`` the opponent has proposed so far.
      Sellers always prefer more volume.

    - Buyer (convex): ``v_n = max(0, 1 - kappa_hat * (n - target_n_hat)^2)``
      where ``target_n_hat`` is the minimum observed ``n`` proposal (buyers
      reveal their preferred quantity through their most favourable bids, not
      their average — which is inflated by concessions made under pressure).
      ``kappa_hat`` is derived from observed variance: zero variance (opponent
      holds ``n`` fixed) implies a sharp preference (high kappa); high variance
      implies a looser preference (low kappa), clamped to [0.003, 0.02].

    When ``opp_role`` is unknown (empty string), falls back to the neutral
    linear form for backward compatibility.
    """
    span_p = max(1, params.max_p - params.min_p)
    # Opponent's price preference is opposite to own
    if params.role == "buyer":
        v_p = max(0.0, min(1.0, (p - params.min_p) / span_p))
    else:
        v_p = max(0.0, min(1.0, (params.max_p - p) / span_p))

    span_n = max(1, params.max_n - params.min_n)
    if opp_role == "seller":
        # Seller v_n: linear, more is better.  Use the largest observed n as
        # a proxy for the seller's capacity.
        capacity_hat = max(opp_n_mean, float(params.min_n + 1))
        v_n = max(0.0, min(1.0, n / capacity_hat))
    elif opp_role == "buyer" and opp_n_min > 0:
        # Buyer v_n: convex penalty around minimum observed n (proxy for target_n).
        # Use min rather than mean: buyers reveal their preferred n through their
        # most favourable bids; concessions push the mean upward and distort it.
        target_n_hat = opp_n_min
        kappa_hat = 0.02 if opp_n_var <= 0 else max(0.003, min(0.02, 1.0 / (4.0 * opp_n_var)))
        v_n = max(0.0, 1.0 - kappa_hat * (n - target_n_hat) ** 2)
    else:
        # Unknown role or no observations yet: neutral linear fallback
        v_n = max(0.0, min(1.0, (n - params.min_n) / span_n))

    span_q = max(1e-9, 1.0 - params.min_quality)
    v_q = max(0.0, min(1.0, (q - params.min_quality) / span_q))

    return w_p_hat * v_p + w_n_hat * v_n + w_q_hat * v_q


# ---------------------------------------------------------------------------
# Strategy catalog
# ---------------------------------------------------------------------------

STRATEGY_IDS = [
    "ttt_directional",
    "zeuthen_concede",
    "rubinstein_discount",
    "logrolling_tradeoff",
    "nash_bargaining",
    "ks_bargaining",
]


class _StrategyBase:
    """Base class for negotiation strategies.

    All strategies implement ``counter()`` with the same signature so
    ``ParetoNegotiator.respond()`` can call any of them uniformly.
    """

    strategy_id: str = "base"

    def counter(
        self,
        params: ParetoParams,
        own_grid: list[tuple[int, int]],
        opp_cur: tuple[int, int],
        opp_prev: tuple[int, int] | None,
        own_last: tuple[int, int] | None,
        rnd: int,
        q: float,
        meta: dict[str, Any],
    ) -> tuple[int, int] | None:
        """Return a (p, n) counter-proposal, or None to signal no feasible move."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Strategy 10 — Directional tit-for-tat
# ---------------------------------------------------------------------------


class _TttDirectional(_StrategyBase):
    """Mirror a bounded fraction of the opponent's per-issue movement.

    Spec eq. 10::

        z_i,k^{t+1} = clip_{[z_i,k^A, z_i,k^R]}(
                           z_i,k^t + rho_i,k * (z_j,k^t - z_j,k^{t-1})
                       )   for k in {p, n}

    ``z_i,k^t`` is this agent's current proposal on issue k.
    ``z_j,k^t - z_j,k^{t-1}`` is the opponent's movement on issue k.
    ``rho_i,k`` is the per-issue mirroring factor from ParetoParams.

    On round 0 (no previous opponent offer), falls back to own best feasible
    point (aspiration).  After computing the raw (p, n) from the formula, we
    snap to the nearest point in own_grid so the result is always feasible.
    """

    strategy_id = "ttt_directional"

    def counter(
        self,
        params: ParetoParams,
        own_grid: list[tuple[int, int]],
        opp_cur: tuple[int, int],
        opp_prev: tuple[int, int] | None,
        own_last: tuple[int, int] | None,
        rnd: int,
        q: float,
        meta: dict[str, Any],
    ) -> tuple[int, int] | None:
        if not own_grid:
            return None

        if opp_prev is None or own_last is None:
            # Round 0: start from aspiration (own best feasible)
            return max(own_grid, key=lambda pn: params.utility(pn[0], pn[1], q))

        opp_p_cur, opp_n_cur = opp_cur
        opp_p_prev, opp_n_prev = opp_prev
        own_p, own_n = own_last

        # Movement the opponent made since their previous offer
        delta_p = opp_p_cur - opp_p_prev
        delta_n = opp_n_cur - opp_n_prev

        # Mirror that movement, scaled by rho
        raw_p = own_p + params.rho_p * delta_p
        raw_n = own_n + params.rho_n * delta_n

        # Clip to own reservation bounds
        clipped_p = max(params.min_p, min(params.max_p, int(round(raw_p))))
        clipped_n = max(params.min_n, min(params.max_n, int(round(raw_n))))

        # Snap to nearest feasible point in own_grid
        return min(
            own_grid,
            key=lambda pn: abs(pn[0] - clipped_p) + abs(pn[1] - clipped_n),
        )


# ---------------------------------------------------------------------------
# Strategy 11a — Zeuthen concession
# ---------------------------------------------------------------------------


class _ZeuthenConcede(_StrategyBase):
    """Zeuthen risk-ratio concession rule.

    Spec eq. 11a::

        R_i^t = [u_i(x_i^t) - u_i(x_j^t)] / [u_i(x_i^t) - d_i]

    Agent i should concede when R_i^t <= R_j^t (where R_j is estimated
    as 1 - R_i for a two-agent symmetric approximation).  When conceding,
    lower tau by tau_step and propose the best own-feasible point still
    above the new tau.  When not conceding, hold tau and propose best above it.
    """

    strategy_id = "zeuthen_concede"

    def counter(
        self,
        params: ParetoParams,
        own_grid: list[tuple[int, int]],
        opp_cur: tuple[int, int],
        opp_prev: tuple[int, int] | None,
        own_last: tuple[int, int] | None,
        rnd: int,
        q: float,
        meta: dict[str, Any],
    ) -> tuple[int, int] | None:
        if not own_grid:
            return None

        opp_p, opp_n = opp_cur
        u_opp_offer = params.utility(opp_p, opp_n, q)
        d = params.disagreement_utility
        tau = meta["tau"]

        # u_i(x_i^t): utility of own current best candidate above tau
        above_tau = [pn for pn in own_grid if params.utility(pn[0], pn[1], q) >= tau]
        if not above_tau:
            above_tau = own_grid
        best_own_pn = max(above_tau, key=lambda pn: params.utility(pn[0], pn[1], q))
        u_own_best = params.utility(best_own_pn[0], best_own_pn[1], q)

        denom = u_own_best - d
        if denom <= 1e-9:
            # Already near disagreement; concede to best feasible
            return max(own_grid, key=lambda pn: params.utility(pn[0], pn[1], q))

        r_i = (u_own_best - u_opp_offer) / denom
        # Symmetric two-agent approximation: R_j ≈ 1 - R_i
        r_j_approx = 1.0 - r_i

        if r_i <= r_j_approx:
            # Agent i has lower risk; should concede
            new_tau = max(d, tau - params.tau_step)
            meta["tau"] = new_tau
            # Propose best own-feasible point at or above new tau
            candidates = [pn for pn in own_grid if params.utility(pn[0], pn[1], q) >= new_tau]
            if not candidates:
                candidates = own_grid
            return max(candidates, key=lambda pn: params.utility(pn[0], pn[1], q))

        # Not conceding: propose best still above current tau
        return best_own_pn


# ---------------------------------------------------------------------------
# Strategy 11b — Rubinstein patience discount
# ---------------------------------------------------------------------------


class _RubinsteinDiscount(_StrategyBase):
    """Rubinstein alternating-offers with per-round patience discount.

    Spec eq. 11b::

        U_i(x, t) = delta_i^t * u_i(x)
        Accept x_j^t when u_i(x_j^t) >= delta_i * V_i^{t+1}

    V_i^{t+1} is the agent's best reachable discounted utility next round,
    approximated as delta_i^{t+1} * max_{x in own_grid} u_i(x).

    For the counter-proposal, the agent proposes the own-feasible point
    with the highest u_i that, after one more discount, still beats the
    opponent's current offer.  If nothing beats it, propose best available.
    """

    strategy_id = "rubinstein_discount"

    def counter(
        self,
        params: ParetoParams,
        own_grid: list[tuple[int, int]],
        opp_cur: tuple[int, int],
        opp_prev: tuple[int, int] | None,
        own_last: tuple[int, int] | None,
        rnd: int,
        q: float,
        meta: dict[str, Any],
    ) -> tuple[int, int] | None:
        if not own_grid:
            return None

        delta = params.delta
        # V_i^{t+1}: best own utility discounted one more round
        u_max = max(params.utility(p, n, q) for p, n in own_grid)
        continuation = delta ** (rnd + 1) * u_max

        # Counter: propose best own-feasible point with u >= continuation
        candidates = [pn for pn in own_grid if params.utility(pn[0], pn[1], q) >= continuation]
        if not candidates:
            candidates = own_grid
        return max(candidates, key=lambda pn: params.utility(pn[0], pn[1], q))


# ---------------------------------------------------------------------------
# Strategy 12a — Logrolling trade-off
# ---------------------------------------------------------------------------


class _LogrollingTradeoff(_StrategyBase):
    """Stay on own iso-utility contour; maximise estimated opponent utility.

    Spec eq. 12a::

        x_i^{t+1} = argmax_{x in C_i^t} uhat_j(x)

    C_i^t is the set of own-feasible points within a tolerance band of
    the current utility target tau (contour approximation).
    uhat_j(x) uses inferred opponent weights updated from offer history.
    """

    strategy_id = "logrolling_tradeoff"

    def counter(
        self,
        params: ParetoParams,
        own_grid: list[tuple[int, int]],
        opp_cur: tuple[int, int],
        opp_prev: tuple[int, int] | None,
        own_last: tuple[int, int] | None,
        rnd: int,
        q: float,
        meta: dict[str, Any],
    ) -> tuple[int, int] | None:
        if not own_grid:
            return None

        # Update opponent weight estimate from observed movement
        w_p_hat, w_n_hat, w_q_hat = _update_opp_weight_estimate(meta, opp_cur, opp_prev, params)

        tau = meta["tau"]
        # Iso-utility contour C_i^t: points within tolerance of tau
        threshold = tau * (1.0 - _CONTOUR_TOL)
        contour = [pn for pn in own_grid if params.utility(pn[0], pn[1], q) >= threshold]
        if not contour:
            contour = own_grid

        # Maximise estimated opponent utility on the contour
        opp_role = meta.get("opp_role", "")
        opp_n_count = meta.get("opp_n_count", 0)
        opp_n_mean = meta["opp_n_sum"] / opp_n_count if opp_n_count > 0 else -1.0
        opp_n_var = (
            meta.get("opp_n_sq_sum", 0.0) / opp_n_count - opp_n_mean**2 if opp_n_count > 1 else 0.0
        )
        opp_n_min = meta.get("opp_n_min", -1.0)
        return max(
            contour,
            key=lambda pn: _opp_utility_hat(
                pn[0],
                pn[1],
                q,
                w_p_hat,
                w_n_hat,
                w_q_hat,
                params,
                opp_role,
                opp_n_mean,
                opp_n_var,
                opp_n_min,
            ),
        )


# ---------------------------------------------------------------------------
# Strategy 12b — Nash bargaining target
# ---------------------------------------------------------------------------


class _NashBargaining(_StrategyBase):
    """Asymmetric Nash bargaining solution on own feasible grid.

    Spec eq. 12b::

        x^N = argmax_{x in own_grid}
                  (u_i(x) - d_i)^beta_i * (uhat_j(x) - d_j_hat)^(1-beta_i)

    d_j_hat = 0 (conservative: assume opponent's disagreement utility is 0).
    beta_i is the seeded fairness parameter.  Used as a final frontier target
    after the contour-based logrolling phase, and as a tie-break near agreement.
    """

    strategy_id = "nash_bargaining"

    def counter(
        self,
        params: ParetoParams,
        own_grid: list[tuple[int, int]],
        opp_cur: tuple[int, int],
        opp_prev: tuple[int, int] | None,
        own_last: tuple[int, int] | None,
        rnd: int,
        q: float,
        meta: dict[str, Any],
    ) -> tuple[int, int] | None:
        if not own_grid:
            return None

        w_p_hat, w_n_hat, w_q_hat = _update_opp_weight_estimate(meta, opp_cur, opp_prev, params)

        d_i = params.disagreement_utility
        beta = params.beta
        opp_role = meta.get("opp_role", "")
        opp_n_count = meta.get("opp_n_count", 0)
        opp_n_mean = meta["opp_n_sum"] / opp_n_count if opp_n_count > 0 else -1.0
        opp_n_var = (
            meta.get("opp_n_sq_sum", 0.0) / opp_n_count - opp_n_mean**2 if opp_n_count > 1 else 0.0
        )
        opp_n_min = meta.get("opp_n_min", -1.0)

        def nash_product(p: int, n: int) -> float:
            u_i = params.utility(p, n, q) - d_i
            u_j_hat = _opp_utility_hat(
                p,
                n,
                q,
                w_p_hat,
                w_n_hat,
                w_q_hat,
                params,
                opp_role,
                opp_n_mean,
                opp_n_var,
                opp_n_min,
            )
            if u_i <= 0 or u_j_hat <= 0:
                return 0.0
            return (u_i**beta) * (u_j_hat ** (1.0 - beta))

        return max(own_grid, key=lambda pn: nash_product(pn[0], pn[1]))


# ---------------------------------------------------------------------------
# Strategy 12c — Kalai-Smorodinsky bargaining target
# ---------------------------------------------------------------------------


class _KsBargaining(_StrategyBase):
    """Kalai-Smorodinsky proportional concession target.

    Spec eq. 12c::

        (u_i(x) - d_i) / (m_i - d_i)  =  lambda   for some lambda in [0,1]
        where m_i = max_{x in own_grid} u_i(x)

    The KS point maximises lambda along the line from the disagreement point
    to the individually-optimal point.  On own_grid this reduces to: propose
    the feasible point maximising lambda = (u_i - d_i) / (m_i - d_i), which
    is simply the point maximising u_i itself.  The KS logic becomes
    meaningful when combined with the estimated opponent: we maximise lambda
    subject to uhat_j(x) also being proportionally close to m_j_hat.

    Concretely: sort own_grid by lambda_i descending; pick the point with
    highest lambda_i such that lambda_j_hat is also high (within tolerance).
    """

    strategy_id = "ks_bargaining"

    def counter(
        self,
        params: ParetoParams,
        own_grid: list[tuple[int, int]],
        opp_cur: tuple[int, int],
        opp_prev: tuple[int, int] | None,
        own_last: tuple[int, int] | None,
        rnd: int,
        q: float,
        meta: dict[str, Any],
    ) -> tuple[int, int] | None:
        if not own_grid:
            return None

        w_p_hat, w_n_hat, w_q_hat = _update_opp_weight_estimate(meta, opp_cur, opp_prev, params)

        d_i = params.disagreement_utility
        m_i = max(params.utility(p, n, q) for p, n in own_grid)
        denom_i = max(1e-9, m_i - d_i)

        opp_role = meta.get("opp_role", "")
        opp_n_count = meta.get("opp_n_count", 0)
        opp_n_mean = meta["opp_n_sum"] / opp_n_count if opp_n_count > 0 else -1.0
        opp_n_var = (
            meta.get("opp_n_sq_sum", 0.0) / opp_n_count - opp_n_mean**2 if opp_n_count > 1 else 0.0
        )
        opp_n_min = meta.get("opp_n_min", -1.0)

        m_j_hat = max(
            _opp_utility_hat(
                p,
                n,
                q,
                w_p_hat,
                w_n_hat,
                w_q_hat,
                params,
                opp_role,
                opp_n_mean,
                opp_n_var,
                opp_n_min,
            )
            for p, n in own_grid
        )
        denom_j = max(1e-9, m_j_hat)

        def ks_score(p: int, n: int) -> float:
            lambda_i = (params.utility(p, n, q) - d_i) / denom_i
            u_j = _opp_utility_hat(
                p,
                n,
                q,
                w_p_hat,
                w_n_hat,
                w_q_hat,
                params,
                opp_role,
                opp_n_mean,
                opp_n_var,
                opp_n_min,
            )
            lambda_j = u_j / denom_j
            # KS: both lambdas should be equal; minimise their difference,
            # with a preference for higher lambda values (min score = lower lambda)
            return -(lambda_i + lambda_j) + abs(lambda_i - lambda_j)

        # Pick point minimising the KS score (maximises balanced lambda)
        return min(own_grid, key=lambda pn: ks_score(pn[0], pn[1]))


# ---------------------------------------------------------------------------
# Strategy dispatch table
# ---------------------------------------------------------------------------

_STRATEGIES: dict[str, _StrategyBase] = {
    "ttt_directional": _TttDirectional(),
    "zeuthen_concede": _ZeuthenConcede(),
    "rubinstein_discount": _RubinsteinDiscount(),
    "logrolling_tradeoff": _LogrollingTradeoff(),
    "nash_bargaining": _NashBargaining(),
    "ks_bargaining": _KsBargaining(),
}


# ---------------------------------------------------------------------------
# Terms helpers
# ---------------------------------------------------------------------------


def _terms_to_pnq(terms: Terms) -> tuple[int, int, float]:
    p = terms.price.amount if terms.price else 50
    n = int(terms.conditions.get("quantity", 10))
    q = float(terms.conditions.get("quality", 0.75))
    return p, n, q


def _pnq_to_terms(p: int, n: int, q: float) -> Terms:
    return Terms(
        price=Money(amount=p),
        conditions={"quantity": n, "quality": q},
    )


# ---------------------------------------------------------------------------
# ParetoNegotiator
# ---------------------------------------------------------------------------


class ParetoNegotiator:
    """Multi-attribute Pareto-frontier negotiation plugin.

    Pass per-agent utility params via the constructor.  The ``Negotiation``
    protocol's method signatures are unchanged.

    The plugin operates only on its own ``ParetoParams``.  It never inspects
    the opponent's params — no global knowledge.

    Session state tracked per session id (``session_meta``)
    -------------------------------------------------------
    round     : int   — current round index (0-based at first respond call).
    tau       : float — current utility aspiration level, decays with patience.
    q         : float — fixed quality for this session.
    own_last  : [p, n] | None — this agent's last counter-proposal.
    opp_prev  : [p, n] | None — opponent's offer from the previous round.
                                Needed by TTT (spec eq. 10 delta term).
    opp_hat_w_p/n/q : float — running EMA estimate of opponent weights
                               (updated by logrolling and Nash/KS strategies).

    Example::

        params = ParetoParams.for_buyer(AgentId("buyer-0"), seed=7)
        neg = ParetoNegotiator(AgentId("buyer-0"), params)
        session = await neg.open(AgentId("seller-0"),
                                 Terms(price=Money(amount=80),
                                       conditions={"quantity": 10, "quality": 0.75}))
        resp = await neg.respond(session)
    """

    def __init__(self, agent_id: AgentId, params: ParetoParams) -> None:
        self._agent_id = agent_id
        self._params = params
        self._sessions: dict[str, NegotiationSession] = {}
        self._meta: dict[str, dict[str, Any]] = {}
        self._strategy: _StrategyBase = _STRATEGIES.get(
            params.strategy_id, _STRATEGIES["ttt_directional"]
        )
        # Monotonic counter used to generate deterministic session IDs.
        # uuid.uuid4() draws from OS entropy and breaks trace replay; this
        # counter is reset when the plugin instance is constructed, which is
        # itself deterministic (the factory creates instances in a fixed order).
        self._session_counter: int = 0

    @property
    def params(self) -> ParetoParams:
        """Read-only access to this agent's private params (for trace emission)."""
        return self._params

    def session_meta(self, session: NegotiationSession) -> dict[str, Any]:
        """Return (or create) per-session state dict for this plugin instance.

        Exposed as public so tests and the validator can inspect session state
        without going through private attributes.

        Example::

            meta = neg.session_meta(session)
            meta["tau"] = 0.9  # override aspiration for testing
        """
        if session.id not in self._meta:
            # Infer opponent role from who opened the session.
            # The initiator is always the buyer (client); the responder is the seller.
            # Each agent knows their own role, so the opponent's role is the opposite.
            opp_role = "seller" if self._params.role == "buyer" else "buyer"
            self._meta[session.id] = {
                "round": 0,
                "tau": 0.5,
                "own_last": None,
                "opp_prev": None,  # opponent's offer from the previous round
                "q": 0.75,
                "opp_role": opp_role,
                "opp_n_sum": 0.0,  # running sum of observed opponent n proposals
                "opp_n_count": 0,  # number of opponent n proposals seen
            }
        return self._meta[session.id]

    async def open(self, partner: AgentId, terms: Terms) -> NegotiationSession:
        """Open a negotiation session with initial multi-attribute terms.

        Example::

            session = await neg.open(AgentId("seller-0"), terms)
        """
        self._session_counter += 1
        session_id = f"pareto-{self._agent_id}-{self._session_counter}"
        session = NegotiationSession(
            id=session_id,
            initiator=self._agent_id,
            partner=partner,
            status=NegotiationStatus.OPEN,
            current_terms=terms,
            history=[terms],
        )
        _, _, q = _terms_to_pnq(terms)
        meta = self.session_meta(session)
        meta["q"] = q
        # Initialise tau at the agent's own best feasible utility — the aspiration
        # level an agent would get if it could unilaterally pick the best deal.
        # Using the opening offer's utility (as before) would make the agent accept
        # the first feasible counter it receives, collapsing bargaining to one round.
        own_grid = self._own_feasible_grid(q)
        if own_grid:
            meta["tau"] = max(self._params.utility(pp, nn, q) for pp, nn in own_grid)
        else:
            meta["tau"] = self._params.utility(*_terms_to_pnq(terms)[:2], q)
        self._sessions[session.id] = session
        return session

    async def offer(self, session: NegotiationSession, terms: Terms) -> None:
        """Record the opponent's offer as the current terms.

        Saves the current ``current_terms`` as ``opp_prev`` before overwriting,
        so strategies can compute the per-issue movement delta.

        Example::

            await neg.offer(session, Terms(price=Money(amount=70),
                                          conditions={"quantity": 15, "quality": 0.75}))
        """
        meta = self.session_meta(session)
        # Save what was the current offer as the previous opponent offer
        if session.current_terms is not None:
            prev_p, prev_n, _ = _terms_to_pnq(session.current_terms)
            meta["opp_prev"] = [prev_p, prev_n]

        # Track running statistics of opponent n proposals for role-aware v_n.
        # For buyer estimation: use the minimum observed n as the target proxy.
        # Buyers reveal their preferred quantity through their most favourable
        # (lowest n) proposals, not through the average — which is distorted by
        # concessions made under pressure.  Variance is tracked to scale kappa_hat:
        # zero variance means the opponent holds n fixed (strong preference).
        _, new_n, _ = _terms_to_pnq(terms)
        meta["opp_n_sum"] = meta.get("opp_n_sum", 0.0) + new_n
        meta["opp_n_sq_sum"] = meta.get("opp_n_sq_sum", 0.0) + new_n * new_n
        meta["opp_n_count"] = meta.get("opp_n_count", 0) + 1
        prev_min = meta.get("opp_n_min", float(new_n))
        meta["opp_n_min"] = min(prev_min, float(new_n))

        session.current_terms = terms
        session.history.append(terms)
        meta["round"] += 1

    async def respond(self, session: NegotiationSession) -> NegotiationResponse:
        """Evaluate the full (p, n, q) offer and return accept or counter.

        Acceptance test
        ---------------
        The Rubinstein-style acceptance condition (spec eq. 11b) is applied
        alongside the basic tau-threshold check:

            Accept when u_i(x_j^t) >= delta_i * V_i^{t+1}
            where V_i^{t+1} = max_{x in own_grid} u_i(x)

        If either condition holds, the agent accepts.

        Counter-proposal
        ----------------
        The active strategy's ``counter()`` is called with the current and
        previous opponent offers so direction-sensitive strategies (TTT) can
        compute the per-issue movement delta.  If the strategy returns None,
        tau is decayed and the best feasible point at or above the new tau is
        proposed as a fallback.

        Example::

            resp = await neg.respond(session)
        """
        if session.current_terms is None:
            return NegotiationResponse(accepted=True)

        p, n, q = _terms_to_pnq(session.current_terms)
        meta = self.session_meta(session)
        q = meta.get("q", q)

        # Hard-reservation gate
        if not self._params.feasible(p, n, q):
            return NegotiationResponse(accepted=False, counter_terms=None)

        u_offer = self._params.utility(p, n, q)
        tau = meta["tau"]
        own_grid = self._own_feasible_grid(q)

        # --- Acceptance conditions ---
        # 1. Utility target (only after at least one counter-offer exchanged)
        rnd = meta["round"]
        if rnd >= 1 and u_offer >= tau:
            return NegotiationResponse(accepted=True)

        # 2. Rubinstein acceptance: u(opp) >= delta * V_next (spec eq. 11b)
        # Applied only from round 1 onward — agents must exchange at least one
        # counter before the patience discount can trigger acceptance.
        if rnd >= 1 and own_grid:
            u_max = max(self._params.utility(pp, nn, q) for pp, nn in own_grid)
            if u_offer >= self._params.delta ** (rnd + 1) * u_max:
                return NegotiationResponse(accepted=True)

        if not own_grid:
            return NegotiationResponse(accepted=False, counter_terms=None)

        # --- Counter-proposal ---
        own_last_raw = meta.get("own_last")
        own_last: tuple[int, int] | None = (
            tuple(own_last_raw) if own_last_raw else None  # type: ignore[assignment]
        )
        opp_prev_raw = meta.get("opp_prev")
        opp_prev: tuple[int, int] | None = (
            tuple(opp_prev_raw) if opp_prev_raw else None  # type: ignore[assignment]
        )
        rnd = meta["round"]

        counter_pn = self._strategy.counter(
            self._params, own_grid, (p, n), opp_prev, own_last, rnd, q, meta
        )

        if counter_pn is None:
            # Fallback: decay tau and propose best above new tau
            meta["tau"] = max(
                self._params.disagreement_utility,
                tau * self._params.patience,
            )
            best = max(own_grid, key=lambda pn: self._params.utility(pn[0], pn[1], q))
            counter_pn = best
        else:
            # Decay tau after a successful counter
            meta["tau"] = max(
                self._params.disagreement_utility,
                meta["tau"] * self._params.patience,
            )

        meta["own_last"] = list(counter_pn)
        return NegotiationResponse(
            accepted=False,
            counter_terms=_pnq_to_terms(counter_pn[0], counter_pn[1], q),
        )

    async def close(self, session: NegotiationSession) -> Agreement | None:
        """Close the session.  Returns None on breakdown.

        Example::

            agreement = await neg.close(session)
        """
        if session.current_terms is None:
            session.status = NegotiationStatus.REJECTED
            return None

        p, n, q = _terms_to_pnq(session.current_terms)
        meta = self.session_meta(session)
        q = meta.get("q", q)

        if not self._params.feasible(p, n, q):
            session.status = NegotiationStatus.REJECTED
            return None

        u = self._params.utility(p, n, q)
        if u <= self._params.disagreement_utility and session.status != NegotiationStatus.AGREED:
            session.status = NegotiationStatus.REJECTED
            return None

        session.status = NegotiationStatus.AGREED
        return Agreement(
            session_id=session.id,
            terms=session.current_terms,
            parties=[session.initiator, session.partner],
        )

    def _own_feasible_grid(self, q: float) -> list[tuple[int, int]]:
        """Grid of (p, n) feasible for this agent at fixed q."""
        points: list[tuple[int, int]] = []
        p = self._params.min_p
        while p <= self._params.max_p:
            n = self._params.min_n
            while n <= self._params.max_n:
                if self._params.feasible(p, n, q):
                    points.append((p, n))
                n += _QUANTITY_STEP
            p += _PRICE_STEP
        return points
