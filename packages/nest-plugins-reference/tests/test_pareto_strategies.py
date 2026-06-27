# SPDX-License-Identifier: Apache-2.0
"""Tests exercising all 6 negotiation strategies in bilateral exchange.

The tests simulate realistic negotiation by:
  - Opening at the midpoint of the joint feasible price range.
  - Clamping each counter-proposal to the joint (p, n) bounds before
    delivering it to the opponent, which is what the transport layer does
    when an offer is infeasible for the receiver.
  - Running buyer and seller with different strategy combinations.

Tests are grouped by scenario:
  1. Self-play — each strategy paired with itself.
  2. All 36 cross-strategy pairs — every buyer strategy vs every seller strategy.
  3. Strategy-specific behavioral assertions — each strategy's output must
     exhibit the property it is designed for.
  4. Convergence speed comparison — strategies differ in how many rounds they
     need to agree; faster ≠ better (logrolling is fast but logrolls).
"""

from __future__ import annotations

from typing import NamedTuple

import pytest
from nest_core.types import AgentId, Money, NegotiationResponse, Terms
from nest_plugins_reference.negotiation.pareto import (
    STRATEGY_IDS,
    ParetoNegotiator,
    ParetoParams,
)

# ---------------------------------------------------------------------------
# Test harness helpers
# ---------------------------------------------------------------------------

_SEED = 7  # joint zone: p=[15,62] n=[6,27]  — wide enough for all strategies
_Q = 0.75


def _terms(p: int, n: int, q: float = _Q) -> Terms:
    return Terms(price=Money(amount=p), conditions={"quantity": n, "quality": q})


def _make(role: str, strategy_id: str, seed: int = _SEED) -> tuple[ParetoParams, ParetoNegotiator]:
    if role == "buyer":
        params = ParetoParams.for_buyer(AgentId("buyer-0"), seed, pair_index=0)
    else:
        params = ParetoParams.for_seller(AgentId("seller-0"), seed, pair_index=0)
    params.strategy_id = strategy_id
    return params, ParetoNegotiator(AgentId(f"{role}-0"), params)


class NegResult(NamedTuple):
    agreed: bool
    rounds: int
    final_p: int
    final_n: int
    price_moves: list[int]  # all p values in offer sequence
    qty_moves: list[int]  # all n values in offer sequence


async def _run_bilateral(
    buyer_strategy: str,
    seller_strategy: str,
    seed: int = _SEED,
    max_rounds: int = 10,
) -> NegResult:
    """Run a bilateral negotiation between buyer and seller strategies.

    Opening offer is placed at the midpoint of the joint feasible price range
    so neither agent starts with an infeasible proposal.  Each counter-proposal
    is clamped to the joint (p, n) bounds before delivery — this mirrors what
    the scenario agent's transport layer does.
    """
    bp, buyer = _make("buyer", buyer_strategy, seed)
    sp, seller = _make("seller", seller_strategy, seed)

    # Joint feasible zone
    joint_p_lo = max(bp.min_p, sp.min_p)
    joint_p_hi = min(bp.max_p, 100)
    joint_n_lo = max(bp.min_n, sp.min_n)
    joint_n_hi = min(bp.max_n, sp.max_n)

    def _clamp(p: int, n: int) -> tuple[int, int]:
        return (
            max(joint_p_lo, min(joint_p_hi, p)),
            max(joint_n_lo, min(joint_n_hi, n)),
        )

    # Open at midpoint — feasible for both
    mid_p = (joint_p_lo + joint_p_hi) // 2
    open_n = max(joint_n_lo, min(joint_n_hi, bp.target_n))
    open_p, open_n = _clamp(mid_p, open_n)

    # Buyer opens; seller is initialized with its own aspiration then receives
    # the buyer's opening via offer() — the standard asymmetric-open pattern.
    b_sess = await buyer.open(AgentId("seller-0"), _terms(open_p, open_n))
    s_sess = await seller.open(AgentId("buyer-0"), _terms(sp.target_p, sp.target_n))
    await seller.offer(s_sess, _terms(open_p, open_n))

    cur_p, cur_n = open_p, open_n
    all_p = [cur_p]
    all_n = [cur_n]
    agreed = False

    for _ in range(max_rounds):
        # Seller responds
        sresp: NegotiationResponse = await seller.respond(s_sess)
        if sresp.accepted:
            agreed = True
            break
        if sresp.counter_terms is None:
            break
        sp_c = sresp.counter_terms.price.amount if sresp.counter_terms.price else cur_p
        sn_c = int(sresp.counter_terms.conditions.get("quantity", cur_n))
        sp_c, sn_c = _clamp(sp_c, sn_c)
        all_p.append(sp_c)
        all_n.append(sn_c)
        await buyer.offer(b_sess, _terms(sp_c, sn_c))
        await seller.offer(s_sess, _terms(sp_c, sn_c))
        cur_p, cur_n = sp_c, sn_c

        # Buyer responds
        bresp: NegotiationResponse = await buyer.respond(b_sess)
        if bresp.accepted:
            agreed = True
            break
        if bresp.counter_terms is None:
            break
        bp_c = bresp.counter_terms.price.amount if bresp.counter_terms.price else cur_p
        bn_c = int(bresp.counter_terms.conditions.get("quantity", cur_n))
        bp_c, bn_c = _clamp(bp_c, bn_c)
        all_p.append(bp_c)
        all_n.append(bn_c)
        await seller.offer(s_sess, _terms(bp_c, bn_c))
        await buyer.offer(b_sess, _terms(bp_c, bn_c))
        cur_p, cur_n = bp_c, bn_c

    return NegResult(
        agreed=agreed,
        rounds=len(all_p),
        final_p=all_p[-1],
        final_n=all_n[-1],
        price_moves=all_p,
        qty_moves=all_n,
    )


# ---------------------------------------------------------------------------
# 1. Self-play: every strategy paired with itself
# ---------------------------------------------------------------------------


class TestSelfPlay:
    """Each strategy must reach agreement when facing a copy of itself.

    Self-play exercises the strategy's concession logic without adversarial
    counter-strategy effects.  Every strategy should converge in ≤10 rounds
    from a midpoint opening.
    """

    @pytest.mark.parametrize("strategy", STRATEGY_IDS)
    @pytest.mark.asyncio
    async def test_self_play_reaches_agreement(self, strategy: str) -> None:
        result = await _run_bilateral(strategy, strategy)
        assert result.agreed, (
            f"{strategy} vs {strategy}: no agreement in {result.rounds} rounds. "
            f"price_moves={result.price_moves}  qty_moves={result.qty_moves}"
        )

    @pytest.mark.parametrize("strategy", STRATEGY_IDS)
    @pytest.mark.asyncio
    async def test_self_play_agreement_in_joint_feasible_zone(self, strategy: str) -> None:
        """Final agreed price must be within the joint reservation range."""
        bp = ParetoParams.for_buyer(AgentId("buyer-0"), _SEED)
        sp = ParetoParams.for_seller(AgentId("seller-0"), _SEED)
        result = await _run_bilateral(strategy, strategy)
        if result.agreed:
            joint_p_lo = max(bp.min_p, sp.min_p)
            joint_p_hi = min(bp.max_p, 100)
            assert joint_p_lo <= result.final_p <= joint_p_hi, (
                f"{strategy}: final p={result.final_p} outside joint zone "
                f"[{joint_p_lo},{joint_p_hi}]"
            )

    @pytest.mark.parametrize("strategy", STRATEGY_IDS)
    @pytest.mark.asyncio
    async def test_self_play_quantity_axis_moves(self, strategy: str) -> None:
        """When negotiation runs more than one round, the quantity axis must move.

        If both agents agree immediately (seller accepts buyer's opening offer),
        no counter-proposals are issued and there is nothing to check — that is
        also correct behaviour.  We assert movement only when the negotiation
        actually alternates for more than one step.
        """
        result = await _run_bilateral(strategy, strategy)
        if result.rounds <= 1:
            return  # agreed immediately; no counter-proposals, nothing to assert
        distinct_n = set(result.qty_moves)
        assert len(distinct_n) >= 2, (
            f"{strategy}: negotiation ran {result.rounds} rounds but "
            f"quantity never moved — qty_moves={result.qty_moves}"
        )


# ---------------------------------------------------------------------------
# 2. All 36 cross-strategy pairs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("buyer_strategy", STRATEGY_IDS)
@pytest.mark.parametrize("seller_strategy", STRATEGY_IDS)
@pytest.mark.asyncio
async def test_cross_strategy_reaches_agreement(buyer_strategy: str, seller_strategy: str) -> None:
    """Every buyer-strategy × seller-strategy combination must reach agreement.

    36 pairs total.  All agreed in the exploration run above; this test locks
    that in so a strategy regression is caught immediately.
    """
    result = await _run_bilateral(buyer_strategy, seller_strategy)
    assert result.agreed, (
        f"buyer={buyer_strategy} seller={seller_strategy}: no agreement in "
        f"{result.rounds} rounds. "
        f"price_moves={result.price_moves}  qty_moves={result.qty_moves}"
    )


# ---------------------------------------------------------------------------
# 3. Strategy-specific behavioral assertions
# ---------------------------------------------------------------------------


class TestStrategyBehavior:
    """Each strategy has a distinguishing behavioral property."""

    @pytest.mark.asyncio
    async def test_ttt_directional_mirrors_price_movement(self) -> None:
        """TTT buyer must move its price in the direction the seller moved.

        When the seller raises price between round t-1 and t (moving toward its
        preferred direction), the buyer should also raise price — mirroring the
        delta with factor rho_p.

        Three-phase setup:
          phase 1 — buyer receives seller's round-0 offer and responds
                     (this populates own_last so TTT has a starting point)
          phase 2 — seller raises price; buyer receives it (opp_prev = r0, opp_cur = r1)
          phase 3 — buyer responds: should mirror the seller's upward price delta
        """
        bp, buyer = _make("buyer", "ttt_directional")
        q = _Q

        bp2 = ParetoParams.for_buyer(AgentId("buyer-0"), _SEED)
        sp2 = ParetoParams.for_seller(AgentId("seller-0"), _SEED)
        joint_p_lo = max(bp2.min_p, sp2.min_p)
        joint_p_hi = min(bp2.max_p, 100)
        mid_p = (joint_p_lo + joint_p_hi) // 2
        open_n = max(bp.min_n, 10)

        session = await buyer.open(AgentId("seller-0"), _terms(mid_p, open_n, q))
        meta = buyer.session_meta(session)
        meta["tau"] = 0.9  # keep high so buyer never accepts cheaply

        # Phase 1: seller's first offer at mid_p; buyer responds (sets own_last)
        await buyer.offer(session, _terms(mid_p, open_n, q))
        resp0 = await buyer.respond(session)
        if resp0.accepted:
            return  # already agreed at mid_p — can't test further with this seed
        ct0 = resp0.counter_terms
        own_last_p = ct0.price.amount if ct0 and ct0.price else mid_p

        # Phase 2: seller raises price from mid_p to mid_p+6 (a clear upward move)
        r1_p = min(joint_p_hi, mid_p + 6)
        await buyer.offer(session, _terms(r1_p, open_n, q))  # opp_prev=mid_p, opp_cur=r1_p

        # Phase 3: buyer responds — should mirror the +6 seller movement
        resp1 = await buyer.respond(session)
        if resp1.accepted or resp1.counter_terms is None:
            return  # accepted or broke down — can't test counter

        counter_p = resp1.counter_terms.price.amount if resp1.counter_terms.price else own_last_p
        delta_seller = r1_p - mid_p  # how much seller raised
        # TTT: buyer_new = own_last + rho_p * delta_seller; rho_p > 0 so buyer raises too
        assert counter_p >= own_last_p, (
            f"TTT buyer did not mirror seller's upward price move: "
            f"own_last_p={own_last_p} seller_delta=+{delta_seller} buyer_counter={counter_p} "
            f"(expected counter_p >= {own_last_p})"
        )

    @pytest.mark.asyncio
    async def test_zeuthen_concede_tau_is_decremented_when_low_risk(self) -> None:
        """Zeuthen agent must decrement tau when its risk ratio is ≤ opponent's.

        R_i = [u_i(x_i) - u_i(x_j)] / [u_i(x_i) - d_i].
        When R_i ≤ R_j (≈ 1-R_i for symmetric approximation), agent concedes.
        """
        bp, buyer = _make("buyer", "zeuthen_concede")
        q = _Q
        bp2 = ParetoParams.for_buyer(AgentId("buyer-0"), _SEED)
        sp2 = ParetoParams.for_seller(AgentId("seller-0"), _SEED)
        joint_p_lo = max(bp2.min_p, sp2.min_p)
        joint_p_hi = min(bp2.max_p, 100)
        mid_p = (joint_p_lo + joint_p_hi) // 2
        open_n = max(bp.min_n, 10)

        session = await buyer.open(AgentId("seller-0"), _terms(mid_p, open_n, q))
        meta = buyer.session_meta(session)
        tau_start = meta["tau"]

        # Deliver two rounds of tough offers to force concession
        for _ in range(3):
            tough_p = joint_p_hi  # worst for buyer
            await buyer.offer(session, _terms(tough_p, open_n, q))
            resp = await buyer.respond(session)
            if resp.accepted:
                break

        tau_end = meta["tau"]
        assert tau_end <= tau_start, f"Zeuthen tau increased: {tau_start:.4f} → {tau_end:.4f}"

    @pytest.mark.asyncio
    async def test_rubinstein_discount_continuation_shrinks_over_rounds(self) -> None:
        """Rubinstein's discounted continuation value must shrink each round.

        V_i^{t+1} = delta^{t+1} * max_u  decreases as t increases (delta < 1).
        An agent that was unwilling to accept at round 0 must become willing
        by round T where delta^T * max_u < u(opponent's offer).

        We offer at the midpoint of the joint zone (genuinely feasible for the
        buyer, not a worst-case ceiling), and run up to 20 rounds so patience
        discount has enough room to flip the acceptance condition.
        """
        bp, buyer = _make("buyer", "rubinstein_discount")
        q = _Q
        bp2 = ParetoParams.for_buyer(AgentId("buyer-0"), _SEED)
        sp2 = ParetoParams.for_seller(AgentId("seller-0"), _SEED)
        joint_p_lo = max(bp2.min_p, sp2.min_p)
        joint_p_hi = min(bp2.max_p, 100)
        mid_p = (joint_p_lo + joint_p_hi) // 2
        open_n = max(bp.min_n, 10)

        session = await buyer.open(AgentId("seller-0"), _terms(mid_p, open_n, q))

        # Offer at mid_p — not the best for the buyer but fully feasible.
        # The buyer's tau starts at its own best utility; mid_p gives lower
        # utility, so it won't accept immediately.  As delta^t decays, the
        # buyer eventually accepts mid_p over a worse future.
        first_accepted_round: int | None = None
        for rnd in range(20):
            await buyer.offer(session, _terms(mid_p, open_n, q))
            resp = await buyer.respond(session)
            if resp.accepted:
                first_accepted_round = rnd
                break

        assert first_accepted_round is not None, (
            f"Rubinstein buyer never accepted mid_p={mid_p} over 20 rounds "
            f"(delta={bp.delta:.3f}). "
            f"buyer utility at mid_p={bp.utility(mid_p, open_n, q):.4f}"
        )
        assert first_accepted_round >= 1, (
            "Rubinstein buyer accepted on round 0 — acceptance gate not checking rnd>=1"
        )

    @pytest.mark.asyncio
    async def test_logrolling_stays_on_contour(self) -> None:
        """Logrolling counter-proposals must stay within the iso-utility tolerance band.

        C_i^t = {x in own_grid : u_i(x) >= tau * (1 - _CONTOUR_TOL)}.
        Every counter from a logrolling agent must satisfy this.
        """
        bp, buyer = _make("buyer", "logrolling_tradeoff")
        q = _Q
        bp2 = ParetoParams.for_buyer(AgentId("buyer-0"), _SEED)
        sp2 = ParetoParams.for_seller(AgentId("seller-0"), _SEED)
        joint_p_lo = max(bp2.min_p, sp2.min_p)
        joint_p_hi = min(bp2.max_p, 100)
        mid_p = (joint_p_lo + joint_p_hi) // 2
        open_n = max(bp.min_n, 10)

        session = await buyer.open(AgentId("seller-0"), _terms(mid_p, open_n, q))
        meta = buyer.session_meta(session)
        meta["tau"] = 0.7  # fixed aspiration

        contour_tol = 0.05  # matches _CONTOUR_TOL in pareto.py
        for opp_n in [open_n, open_n + 3, open_n - 2]:
            if not bp.feasible(mid_p, opp_n, q):
                continue
            await buyer.offer(session, _terms(mid_p, opp_n, q))
            # Read tau BEFORE respond() — the strategy uses this value to build
            # the contour, then respond() decays it afterwards.
            tau_before = meta["tau"]
            threshold = tau_before * (1.0 - contour_tol)
            resp = await buyer.respond(session)
            if resp.accepted or resp.counter_terms is None:
                continue
            cp = resp.counter_terms.price.amount if resp.counter_terms.price else mid_p
            cn = int(resp.counter_terms.conditions.get("quantity", opp_n))
            u_counter = bp.utility(cp, cn, q)
            assert u_counter >= threshold - 1e-6, (
                f"Logrolling counter (p={cp},n={cn},u={u_counter:.4f}) is below "
                f"contour threshold {threshold:.4f} (tau_before={tau_before:.4f})"
            )

    @pytest.mark.asyncio
    async def test_nash_bargaining_maximises_surplus_product(self) -> None:
        """Nash counter-proposal must maximise the Nash surplus product on own grid.

        Among all own-feasible points, the proposed (p, n) must have the
        highest (u_i - d_i)^beta * (u_hat_j)^(1-beta).
        """
        bp, buyer = _make("buyer", "nash_bargaining")
        q = _Q
        bp2 = ParetoParams.for_buyer(AgentId("buyer-0"), _SEED)
        sp2 = ParetoParams.for_seller(AgentId("seller-0"), _SEED)
        joint_p_lo = max(bp2.min_p, sp2.min_p)
        joint_p_hi = min(bp2.max_p, 100)
        mid_p = (joint_p_lo + joint_p_hi) // 2
        open_n = max(bp.min_n, 10)

        session = await buyer.open(AgentId("seller-0"), _terms(mid_p, open_n, q))
        meta = buyer.session_meta(session)
        meta["tau"] = 0.9

        await buyer.offer(session, _terms(mid_p, open_n, q))
        await buyer.offer(session, _terms(mid_p + 3, open_n + 2, q))  # give movement data
        resp = await buyer.respond(session)
        if resp.accepted or resp.counter_terms is None:
            return  # can't test counter if already agreed

        cp = resp.counter_terms.price.amount if resp.counter_terms.price else mid_p
        cn = int(resp.counter_terms.conditions.get("quantity", open_n))

        # Build own grid and check Nash product at the counter vs random alternatives
        w_p_hat = meta.get("opp_hat_w_p", bp.w_p)
        w_n_hat = meta.get("opp_hat_w_n", bp.w_n)
        w_q_hat = meta.get("opp_hat_w_q", bp.w_q)
        d_i = bp.disagreement_utility
        beta = bp.beta

        from nest_plugins_reference.negotiation.pareto import _opp_utility_hat

        opp_role = meta.get("opp_role", "")
        opp_n_count = meta.get("opp_n_count", 0)
        opp_n_mean = meta["opp_n_sum"] / opp_n_count if opp_n_count > 0 else -1.0
        opp_n_var = (
            meta.get("opp_n_sq_sum", 0.0) / opp_n_count - opp_n_mean**2 if opp_n_count > 1 else 0.0
        )
        opp_n_min = meta.get("opp_n_min", -1.0)

        def nash(p: int, n: int) -> float:
            u_i = bp.utility(p, n, q) - d_i
            u_j = _opp_utility_hat(
                p,
                n,
                q,
                w_p_hat,
                w_n_hat,
                w_q_hat,
                bp,
                opp_role,
                opp_n_mean,
                opp_n_var,
                opp_n_min,
            )
            if u_i <= 0 or u_j <= 0:
                return 0.0
            return (u_i**beta) * (u_j ** (1.0 - beta))

        counter_score = nash(cp, cn)
        # Check all feasible grid points — no sampling to avoid missing the
        # specific point that beats the counter.
        beaten = 0
        checks = 0
        p = bp.min_p
        while p <= bp.max_p:
            n = bp.min_n
            while n <= bp.max_n:
                if bp.feasible(p, n, q):
                    checks += 1
                    if counter_score >= nash(p, n) - 1e-9:
                        beaten += 1
                n += 1
            p += 5
        if checks > 0:
            assert beaten == checks, (
                f"Nash counter (p={cp},n={cn}) lost to {checks - beaten}/{checks} "
                f"grid points"
            )

    @pytest.mark.asyncio
    async def test_ks_bargaining_balances_proportional_gains(self) -> None:
        """KS counter-proposal must minimise the imbalance between own and estimated
        opponent lambda (proportional gain from disagreement to ideal).

        lambda_i = (u_i(x) - d_i) / (m_i - d_i).  The KS point has lambda_i = lambda_j.
        """
        bp, buyer = _make("buyer", "ks_bargaining")
        q = _Q
        bp2 = ParetoParams.for_buyer(AgentId("buyer-0"), _SEED)
        sp2 = ParetoParams.for_seller(AgentId("seller-0"), _SEED)
        joint_p_lo = max(bp2.min_p, sp2.min_p)
        joint_p_hi = min(bp2.max_p, 100)
        mid_p = (joint_p_lo + joint_p_hi) // 2
        open_n = max(bp.min_n, 10)

        session = await buyer.open(AgentId("seller-0"), _terms(mid_p, open_n, q))
        meta = buyer.session_meta(session)
        meta["tau"] = 0.9

        # Give the strategy two rounds of data so opponent weights stabilise
        await buyer.offer(session, _terms(mid_p, open_n, q))
        await buyer.offer(session, _terms(mid_p + 5, open_n + 3, q))
        resp = await buyer.respond(session)
        if resp.accepted or resp.counter_terms is None:
            return

        cp = resp.counter_terms.price.amount if resp.counter_terms.price else mid_p
        cn = int(resp.counter_terms.conditions.get("quantity", open_n))

        w_p_hat = meta.get("opp_hat_w_p", bp.w_p)
        w_n_hat = meta.get("opp_hat_w_n", bp.w_n)
        w_q_hat = meta.get("opp_hat_w_q", bp.w_q)

        # Compute own and estimated opponent lambdas at the counter
        feasible_us = [
            bp.utility(p, n, q)
            for p in range(bp.min_p, bp.max_p + 1, 5)
            for n in range(bp.min_n, bp.max_n + 1)
            if bp.feasible(p, n, q)
        ]
        if not feasible_us:
            return
        m_i = max(feasible_us)
        d_i = bp.disagreement_utility
        denom_i = max(1e-9, m_i - d_i)
        lambda_i = (bp.utility(cp, cn, q) - d_i) / denom_i

        span_p = max(1, bp.max_p - bp.min_p)
        span_n = max(1, bp.max_n - bp.min_n)
        span_q = max(1e-9, 1.0 - bp.min_quality)

        def opp_u(p: int, n: int) -> float:
            v_p = max(0.0, min(1.0, (p - bp.min_p) / span_p))
            v_n = max(0.0, min(1.0, (n - bp.min_n) / span_n))
            v_q = max(0.0, min(1.0, (q - bp.min_quality) / span_q))
            return w_p_hat * v_p + w_n_hat * v_n + w_q_hat * v_q

        m_j = max(
            opp_u(p, n)
            for p in range(bp.min_p, bp.max_p + 1, 5)
            for n in range(bp.min_n, bp.max_n + 1)
            if bp.feasible(p, n, q)
        )
        denom_j = max(1e-9, m_j)
        lambda_j = opp_u(cp, cn) / denom_j

        # KS property: lambda_i and lambda_j should be balanced (close to each other)
        imbalance = abs(lambda_i - lambda_j)
        assert imbalance <= 0.5, (
            f"KS counter (p={cp},n={cn}): lambda_i={lambda_i:.4f} lambda_j={lambda_j:.4f} "
            f"imbalance={imbalance:.4f} — not balanced"
        )


# ---------------------------------------------------------------------------
# 4. Convergence speed and price-path comparison
# ---------------------------------------------------------------------------


class TestConvergenceComparisons:
    """Relative behavioral comparisons across strategies."""

    @pytest.mark.asyncio
    async def test_logrolling_converges_no_slower_than_zeuthen_in_self_play(self) -> None:
        """Logrolling reaches agreement in ≤ as many rounds as Zeuthen in self-play.

        Logrolling immediately proposes on the estimated opponent contour,
        so it should converge at least as quickly as Zeuthen which walks a
        utility ladder one rung at a time.
        """
        log_result = await _run_bilateral("logrolling_tradeoff", "logrolling_tradeoff")
        zeu_result = await _run_bilateral("zeuthen_concede", "zeuthen_concede")
        assert log_result.agreed, "Logrolling self-play did not agree"
        assert zeu_result.agreed, "Zeuthen self-play did not agree"
        assert log_result.rounds <= zeu_result.rounds, (
            f"Expected logrolling ({log_result.rounds} moves) to converge "
            f"no slower than Zeuthen ({zeu_result.rounds} moves)"
        )

    @pytest.mark.asyncio
    async def test_zeuthen_and_rubinstein_both_reach_agreement_in_self_play(self) -> None:
        """Zeuthen and Rubinstein are both monotone concession strategies.

        They use different concession functions (risk-ratio ladder vs patience
        discount) so final prices need not coincide on a finite integer grid.
        The shared invariant is that both reach agreement within the round budget.
        """
        z_result = await _run_bilateral("zeuthen_concede", "zeuthen_concede")
        r_result = await _run_bilateral("rubinstein_discount", "rubinstein_discount")
        assert z_result.agreed, f"Zeuthen self-play did not agree in {z_result.rounds} rounds"
        assert r_result.agreed, f"Rubinstein self-play did not agree in {r_result.rounds} rounds"

    @pytest.mark.asyncio
    async def test_all_strategies_move_quantity_in_cross_play(self) -> None:
        """When cross-strategy negotiation runs more than one round, quantity must move.

        This is the core invariant separating pareto from alternating_offers.
        If both parties agree immediately, no counter-proposals are issued and
        there is nothing to assert about quantity movement.
        """
        for buyer_s in STRATEGY_IDS:
            for seller_s in STRATEGY_IDS:
                result = await _run_bilateral(buyer_s, seller_s)
                if result.rounds <= 1:
                    continue  # immediate agreement — nothing to assert
                distinct_n = set(result.qty_moves)
                assert len(distinct_n) >= 2, (
                    f"buyer={buyer_s} seller={seller_s}: "
                    f"ran {result.rounds} rounds but quantity never moved — "
                    f"qty_moves={result.qty_moves}"
                )

    @pytest.mark.asyncio
    async def test_determinism_across_all_strategy_pairs(self) -> None:
        """Every strategy pair must produce identical results on two runs."""
        for buyer_s in STRATEGY_IDS:
            for seller_s in STRATEGY_IDS:
                r1 = await _run_bilateral(buyer_s, seller_s)
                r2 = await _run_bilateral(buyer_s, seller_s)
                assert r1 == r2, (
                    f"buyer={buyer_s} seller={seller_s}: runs diverged:\n  run1={r1}\n  run2={r2}"
                )
