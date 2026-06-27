# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for the multi-attribute Pareto negotiation plugin.

Three properties tested across arbitrary seeds and offer values:

1. **Determinism** — identical (agent_id, seed) always produces identical
   counter-proposals and session IDs for identical offer sequences.  Covers
   the uuid4 fix: session IDs are now derived from a monotonic counter.

2. **Monotonic concession** — across successive rounds the utility aspiration
   tau never increases.  Core property of a monotone concession protocol.

3. **Individual rationality (IR)** — an agent accepts when offered its own
   best feasible point.  An agent never accepts an offer that violates its
   quality reservation.

Hypothesis tests must be synchronous; async helpers are called via asyncio.run().
"""

from __future__ import annotations

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Money, Terms
from nest_plugins_reference.negotiation.pareto import (
    ParetoNegotiator,
    ParetoParams,
)

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_SEEDS = st.integers(min_value=0, max_value=2**31 - 1)
_PAIR_INDICES = st.integers(min_value=0, max_value=5)


# ---------------------------------------------------------------------------
# Async helpers — called via asyncio.run() from sync test bodies
# ---------------------------------------------------------------------------


def _terms(p: int, n: int, q: float) -> Terms:
    return Terms(price=Money(amount=p), conditions={"quantity": n, "quality": q})


def _make_buyer(seed: int, pair: int) -> tuple[ParetoParams, ParetoNegotiator]:
    params = ParetoParams.for_buyer(AgentId("buyer-0"), seed, pair_index=pair)
    return params, ParetoNegotiator(AgentId("buyer-0"), params)


async def _counter_sequence(seed: int, pair: int) -> list[tuple[int, int] | None]:
    """Run 3 rounds of fixed offers and collect counter-proposals."""
    params, plugin = _make_buyer(seed, pair)
    q = max(params.min_quality + 0.05, 0.70)
    opp_p = max(params.min_p, min(params.max_p - 5, 70))
    opp_n = max(params.min_n, min(params.max_n - 2, params.target_n))

    session = await plugin.open(AgentId("seller-0"), _terms(opp_p, opp_n, q))
    plugin.session_meta(session)["tau"] = 0.8

    results: list[tuple[int, int] | None] = []
    for step_n in [opp_n, max(params.min_n, opp_n - 3), min(params.max_n, opp_n + 2)]:
        if not params.feasible(opp_p, step_n, q):
            continue
        await plugin.offer(session, _terms(opp_p, step_n, q))
        resp = await plugin.respond(session)
        if resp.counter_terms is not None:
            ct = resp.counter_terms
            results.append(
                (ct.price.amount if ct.price else opp_p, int(ct.conditions.get("quantity", opp_n)))
            )
        else:
            results.append(None)
        if resp.accepted:
            break
    return results


async def _open_session_id(seed: int, pair: int) -> str:
    params, plugin = _make_buyer(seed, pair)
    q = max(params.min_quality + 0.05, 0.70)
    opp_p = max(params.min_p, min(params.max_p - 5, 60))
    opp_n = max(params.min_n, params.target_n)
    session = await plugin.open(AgentId("seller-0"), _terms(opp_p, opp_n, q))
    return session.id


async def _tau_sequence(seed: int, pair: int, n_rounds: int) -> list[float]:
    params, plugin = _make_buyer(seed, pair)
    q = max(params.min_quality + 0.05, 0.70)
    # Worst offer for the buyer: highest price, fewest units.
    # This keeps utility below tau so the agent never accepts early.
    opp_p = params.max_p
    opp_n = params.min_n
    if not params.feasible(opp_p, opp_n, q):
        opp_p = max(params.min_p, params.max_p - 10)
        opp_n = params.target_n

    session = await plugin.open(AgentId("seller-0"), _terms(opp_p, opp_n, q))
    taus: list[float] = []
    for _ in range(n_rounds):
        await plugin.offer(session, _terms(opp_p, opp_n, q))
        resp = await plugin.respond(session)
        taus.append(plugin.session_meta(session)["tau"])
        if resp.accepted or resp.counter_terms is None:
            break
    return taus


async def _accepts_own_best(seed: int, pair: int) -> bool:
    params, plugin = _make_buyer(seed, pair)
    q = max(params.min_quality + 0.05, 0.70)

    best_p, best_n, best_u = params.min_p, params.target_n, -1.0
    p = params.min_p
    while p <= params.max_p:
        n = params.min_n
        while n <= params.max_n:
            if params.feasible(p, n, q):
                u = params.utility(p, n, q)
                if u > best_u:
                    best_u, best_p, best_n = u, p, n
            n += 1
        p += 5

    session = await plugin.open(AgentId("seller-0"), _terms(params.max_p, params.min_n, q))
    await plugin.offer(session, _terms(best_p, best_n, q))
    resp = await plugin.respond(session)
    return resp.accepted


async def _rejects_infeasible_quality(seed: int, pair: int, q_bad: float) -> tuple[bool, bool]:
    """Quality is static per session — infeasibility is established at open time.

    We open the session with the bad quality so the session-fixed q is below
    min_quality from the start.  The agent must reject the opening feasibility
    check in respond() and return no agreement from close().
    """
    params, _unused = _make_buyer(seed, pair)
    # Raise min_quality so q_bad is always below it
    params.min_quality = max(q_bad + 0.05, 0.40)
    plugin2 = ParetoNegotiator(AgentId("buyer-0"), params)

    opp_p = params.min_p
    opp_n = params.target_n

    # Open with the bad quality — this sets the session-fixed q to q_bad
    session = await plugin2.open(AgentId("seller-0"), _terms(opp_p, opp_n, q_bad))
    # Offer again (same bad quality) so respond() has something to evaluate
    await plugin2.offer(session, _terms(opp_p, opp_n, q_bad))
    resp = await plugin2.respond(session)
    agreement = await plugin2.close(session)
    return resp.accepted, agreement is not None


# ---------------------------------------------------------------------------
# 1. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    @settings(max_examples=30, deadline=None)
    @given(seed=_SEEDS, pair=_PAIR_INDICES)
    def test_same_seed_same_counter_proposals(self, seed: int, pair: int) -> None:
        """Two fresh plugin instances with the same (agent_id, seed) must produce
        identical counter-proposals for the same offer sequence.

        This catches any non-deterministic state — previously uuid.uuid4() broke
        this because session IDs were random."""
        run1 = asyncio.run(_counter_sequence(seed, pair))
        run2 = asyncio.run(_counter_sequence(seed, pair))
        assert run1 == run2, f"seed={seed} pair={pair}: runs diverged\n  run1={run1}\n  run2={run2}"

    @settings(max_examples=20, deadline=None)
    @given(seed=_SEEDS, pair=_PAIR_INDICES)
    def test_session_ids_are_deterministic(self, seed: int, pair: int) -> None:
        """Session IDs must be identical across two fresh instances.

        uuid.uuid4() draws from OS entropy and would fail this; the counter-based
        ID ``pareto-<agent_id>-<counter>`` is fully deterministic."""
        id1 = asyncio.run(_open_session_id(seed, pair))
        id2 = asyncio.run(_open_session_id(seed, pair))
        assert id1 == id2, f"seed={seed} pair={pair}: session IDs differ: {id1!r} vs {id2!r}"


# ---------------------------------------------------------------------------
# 2. Monotonic concession
# ---------------------------------------------------------------------------


class TestMonotonicConcession:
    @settings(max_examples=40, deadline=None)
    @given(
        seed=_SEEDS,
        pair=_PAIR_INDICES,
        n_rounds=st.integers(min_value=3, max_value=8),
    )
    def test_tau_never_increases(self, seed: int, pair: int, n_rounds: int) -> None:
        """tau must be non-increasing across all rounds.

        Monotone concession protocol: once an agent has lowered its utility
        target, it cannot unilaterally raise it again.

            tau_i^{t+1} <= tau_i^t   for all t
        """
        taus = asyncio.run(_tau_sequence(seed, pair, n_rounds))
        for i in range(1, len(taus)):
            assert taus[i] <= taus[i - 1] + 1e-9, (
                f"seed={seed} pair={pair}: tau increased at step {i}: "
                f"{taus[i - 1]:.6f} → {taus[i]:.6f}"
            )


# ---------------------------------------------------------------------------
# 3. Individual rationality
# ---------------------------------------------------------------------------


class TestIndividualRationality:
    @settings(max_examples=40, deadline=None)
    @given(seed=_SEEDS, pair=_PAIR_INDICES)
    def test_accepts_own_best_point(self, seed: int, pair: int) -> None:
        """Agent accepts when offered its own best feasible (p, n).

        IR constraint: a rational agent never rejects an outcome at least as
        good as its own aspiration.  If x* maximises u_i over own_grid, then
        respond(x*) must return accepted=True."""
        accepted = asyncio.run(_accepts_own_best(seed, pair))
        assert accepted, (
            f"seed={seed} pair={pair}: agent rejected its own best point (IR violation)"
        )

    @settings(max_examples=30, deadline=None)
    @given(
        seed=_SEEDS,
        pair=_PAIR_INDICES,
        q_bad=st.floats(min_value=0.0, max_value=0.35, allow_nan=False),
    )
    def test_rejects_infeasible_quality(self, seed: int, pair: int, q_bad: float) -> None:
        """Agent must reject any offer whose quality falls below min_quality.

        Quality is a hard reservation: no price or quantity concession can
        compensate for quality below the threshold.  Both respond() and
        close() must refuse the offer."""
        resp_accepted, close_agreed = asyncio.run(_rejects_infeasible_quality(seed, pair, q_bad))
        assert not resp_accepted, (
            f"seed={seed} pair={pair} q={q_bad:.3f}: "
            "agent accepted infeasible quality (feasibility violation)"
        )
        assert not close_agreed, (
            f"seed={seed} pair={pair} q={q_bad:.3f}: "
            "close() returned Agreement for infeasible quality"
        )
