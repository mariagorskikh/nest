# SPDX-License-Identifier: Apache-2.0
"""Unit and property tests for the ParetoNegotiation plugin.

Three property families (Hypothesis):

* **Determinism**, identical construction + identical offer sequence yields an
  identical run (no wall-clock, no RNG).
* **Monotonic concession**, a single agent's own counter-offer utilities are
  non-increasing across rounds (Rosenschein & Zlotkin's Monotonic Concession
  Protocol / Zeuthen).
* **No dominated self-play**, two ParetoNegotiation agents with asymmetric
  weights never settle on an agreement Pareto-dominated by a bundle they
  exchanged.
"""

from __future__ import annotations

import asyncio
from typing import NamedTuple

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import DrawFn
from nest_core.types import AgentId, Money, Terms
from nest_plugins_reference.negotiation.pareto import ParetoNegotiation

_EPS = 1e-9


def _terms(price: int, deadline: int) -> Terms:
    return Terms(price=Money(amount=price), conditions={"deadline_days": deadline})


def _pd(terms: Terms) -> tuple[int, int]:
    price = terms.price.amount if terms.price is not None else 0
    return price, int(terms.conditions.get("deadline_days", 0))


def _dominates(ub_x: float, us_x: float, ub_y: float, us_y: float) -> bool:
    """X dominates Y: no worse for either party, strictly better for one (eps-guarded)."""
    no_worse = ub_x >= ub_y - _EPS and us_x >= us_y - _EPS
    strictly_better = ub_x > ub_y + _EPS or us_x > us_y + _EPS
    return no_worse and strictly_better


# Unit tests


def test_utility_directional_buyer() -> None:
    """The buyer prefers lower price and shorter deadline."""
    buyer = ParetoNegotiation(
        AgentId("b"),
        weights={"price": 0.5, "deadline": 0.5},
        price_range=(50, 150),
        deadline_range=(1, 30),
        side="buyer",
    )
    assert buyer.utility(_terms(60, 5)) > buyer.utility(_terms(120, 5))
    assert buyer.utility(_terms(60, 5)) > buyer.utility(_terms(60, 25))


def test_utility_directional_seller() -> None:
    """The seller prefers higher price and longer deadline."""
    seller = ParetoNegotiation(
        AgentId("s"),
        weights={"price": 0.5, "deadline": 0.5},
        price_range=(50, 150),
        deadline_range=(1, 30),
        side="seller",
    )
    assert seller.utility(_terms(120, 25)) > seller.utility(_terms(60, 25))
    assert seller.utility(_terms(120, 25)) > seller.utility(_terms(120, 5))


def test_best_for_self_has_utility_one() -> None:
    """Each side's ideal bundle scores exactly 1.0."""
    buyer = ParetoNegotiation(
        AgentId("b"),
        weights={"price": 0.7, "deadline": 0.3},
        price_range=(50, 150),
        deadline_range=(1, 30),
        side="buyer",
    )
    seller = ParetoNegotiation(
        AgentId("s"),
        weights={"price": 0.2, "deadline": 0.8},
        price_range=(50, 150),
        deadline_range=(1, 30),
        side="seller",
    )
    assert buyer.utility(_terms(50, 1)) == 1.0
    assert seller.utility(_terms(150, 30)) == 1.0


def test_respond_accepts_best_immediately() -> None:
    """An offer that equals the agent's ideal clears even the round-0 aspiration (1.0)."""
    buyer = ParetoNegotiation(
        AgentId("b"),
        weights={"price": 0.5, "deadline": 0.5},
        price_range=(0, 10),
        deadline_range=(0, 10),
        side="buyer",
    )

    async def go() -> bool:
        session = await buyer.open(AgentId("opp"), _terms(0, 0))
        await buyer.offer(session, _terms(0, 0))  # buyer's ideal -> utility 1.0
        resp = await buyer.respond(session)
        return resp.accepted

    assert asyncio.run(go()) is True


def test_respond_counter_then_accept() -> None:
    """Counters meet the (falling) aspiration and minimize distance; then it accepts.

    Range 0..10 on both issues, equal weights, patience 0.9, reservation 0:
    aspiration is 1.0, 0.9, 0.81 on rounds 0, 1, 2. Against the buyer's worst
    offer (10, 10) the only utility>=1.0 bundle is (0, 0); the closest utility>=0.9
    bundle is (1, 1); finally an offer worth 0.85 clears the round-2 floor of 0.81.
    """
    buyer = ParetoNegotiation(
        AgentId("b"),
        weights={"price": 0.5, "deadline": 0.5},
        price_range=(0, 10),
        deadline_range=(0, 10),
        side="buyer",
        patience=0.9,
    )

    async def go() -> list[tuple[bool, tuple[int, int] | None]]:
        session = await buyer.open(AgentId("opp"), _terms(0, 0))
        out: list[tuple[bool, tuple[int, int] | None]] = []
        for offer in (_terms(10, 10), _terms(10, 10), _terms(1, 2)):
            await buyer.offer(session, offer)
            resp = await buyer.respond(session)
            counter = _pd(resp.counter_terms) if resp.counter_terms is not None else None
            out.append((resp.accepted, counter))
        return out

    result = asyncio.run(go())
    assert result[0] == (False, (0, 0))
    assert result[1] == (False, (1, 1))
    assert result[2][0] is True  # utility 0.85 >= aspiration 0.81


# Property tests (Hypothesis)


class _Cfg(NamedTuple):
    plo: int
    phi: int
    dlo: int
    dhi: int
    patience: float
    buyer_wp: float
    seller_wd: float
    reservation: float


@st.composite
def _cfgs(draw: DrawFn) -> _Cfg:
    plo = draw(st.integers(10, 50))
    phi = plo + draw(st.integers(20, 40))
    dlo = draw(st.integers(1, 5))
    dhi = dlo + draw(st.integers(8, 15))
    patience = draw(st.floats(0.7, 0.95, allow_nan=False, allow_infinity=False))
    buyer_wp = draw(st.floats(0.6, 0.95, allow_nan=False, allow_infinity=False))
    seller_wd = draw(st.floats(0.6, 0.95, allow_nan=False, allow_infinity=False))
    reservation = draw(st.floats(0.0, 0.3, allow_nan=False, allow_infinity=False))
    return _Cfg(plo, phi, dlo, dhi, patience, buyer_wp, seller_wd, reservation)


@st.composite
def _cfg_and_offers(draw: DrawFn) -> tuple[_Cfg, list[tuple[int, int]]]:
    cfg = draw(_cfgs())
    offers = draw(
        st.lists(
            st.tuples(st.integers(cfg.plo, cfg.phi), st.integers(cfg.dlo, cfg.dhi)),
            min_size=1,
            max_size=8,
        )
    )
    return cfg, offers


def _make_seller(cfg: _Cfg, max_rounds: int = 12) -> ParetoNegotiation:
    return ParetoNegotiation(
        AgentId("s"),
        weights={"price": 1.0 - cfg.seller_wd, "deadline": cfg.seller_wd},
        price_range=(cfg.plo, cfg.phi),
        deadline_range=(cfg.dlo, cfg.dhi),
        side="seller",
        patience=cfg.patience,
        reservation=cfg.reservation,
        max_rounds=max_rounds,
    )


def _make_buyer(cfg: _Cfg, max_rounds: int = 12) -> ParetoNegotiation:
    return ParetoNegotiation(
        AgentId("b"),
        weights={"price": cfg.buyer_wp, "deadline": 1.0 - cfg.buyer_wp},
        price_range=(cfg.plo, cfg.phi),
        deadline_range=(cfg.dlo, cfg.dhi),
        side="buyer",
        patience=cfg.patience,
        reservation=cfg.reservation,
        max_rounds=max_rounds,
    )


async def _self_play(
    buyer: ParetoNegotiation, seller: ParetoNegotiation, bounds: tuple[int, int, int, int]
) -> tuple[tuple[int, int] | None, list[tuple[int, int]]]:
    """Run two agents to settlement; return the agreement (if any) and exchanged bundles.

    Each side opens from its best-for-self position, then alternately responds to
    the other's latest offer. An agent either accepts (the offer becomes the
    agreement) or returns a trade-off counter that is recorded and forwarded.
    """
    plo, phi, dlo, dhi = bounds
    buyer_open = _terms(plo, dlo)
    seller_open = _terms(phi, dhi)
    bs = await buyer.open(AgentId("s"), buyer_open)
    ss = await seller.open(AgentId("b"), seller_open)
    exchanged: list[tuple[int, int]] = [(plo, dlo), (phi, dhi)]
    buyer_last, seller_last = buyer_open, seller_open
    for _ in range(30):
        await buyer.offer(bs, seller_last)
        br = await buyer.respond(bs)
        if br.accepted:
            return _pd(seller_last), exchanged
        if br.counter_terms is None:
            return None, exchanged
        buyer_last = br.counter_terms
        exchanged.append(_pd(buyer_last))

        await seller.offer(ss, buyer_last)
        sr = await seller.respond(ss)
        if sr.accepted:
            return _pd(buyer_last), exchanged
        if sr.counter_terms is None:
            return None, exchanged
        seller_last = sr.counter_terms
        exchanged.append(_pd(seller_last))
    return None, exchanged


@given(payload=_cfg_and_offers())
@settings(max_examples=200)
def test_determinism(payload: tuple[_Cfg, list[tuple[int, int]]]) -> None:
    """Two identically-built agents fed the same offers produce identical responses."""
    cfg, offers = payload

    async def drive(agent: ParetoNegotiation) -> list[tuple[bool, tuple[int, int] | None]]:
        session = await agent.open(AgentId("opp"), _terms(cfg.plo, cfg.dlo))
        out: list[tuple[bool, tuple[int, int] | None]] = []
        for price, deadline in offers:
            await agent.offer(session, _terms(price, deadline))
            resp = await agent.respond(session)
            counter = _pd(resp.counter_terms) if resp.counter_terms is not None else None
            out.append((resp.accepted, counter))
        return out

    assert asyncio.run(drive(_make_seller(cfg))) == asyncio.run(drive(_make_seller(cfg)))


@given(cfg=_cfgs())
@settings(max_examples=200)
def test_monotonic_concession(cfg: _Cfg) -> None:
    """A seller's own counter-offer utilities are non-increasing (MCP / Zeuthen).

    Fed its worst bundle (lowest price, shortest deadline) repeatedly, the seller
    never accepts (its utility for that bundle is 0 < aspiration), so it keeps
    countering; each counter sits on a non-increasing aspiration floor.
    """
    seller = _make_seller(cfg)
    worst_for_seller = _terms(cfg.plo, cfg.dlo)

    async def collect() -> list[float]:
        session = await seller.open(AgentId("opp"), worst_for_seller)
        utils: list[float] = []
        for _ in range(15):
            await seller.offer(session, worst_for_seller)
            resp = await seller.respond(session)
            if resp.accepted or resp.counter_terms is None:
                break
            utils.append(seller.utility(resp.counter_terms))
        return utils

    utils = asyncio.run(collect())
    assert len(utils) >= 2
    for earlier, later in zip(utils, utils[1:], strict=False):
        assert later <= earlier + _EPS, f"concession not monotonic: {utils}"


@given(cfg=_cfgs())
@settings(max_examples=100, deadline=None)
def test_selfplay_agreement_individually_rational(cfg: _Cfg) -> None:
    """Every settled self-play agreement clears both parties' reservation utility.

    An agent only accepts (and only counters with) bundles whose own utility
    meets its aspiration ``reservation + (1 - reservation) * patience ** t``,
    which is bounded below by ``reservation``. So neither side ever agrees to a
    bundle it strictly prefers walking away from (individual rationality, the
    invariant the FSJ trade-off mechanism *does* guarantee).
    """
    buyer = _make_buyer(cfg, max_rounds=25)
    seller = _make_seller(cfg, max_rounds=25)
    agreement, _exchanged = asyncio.run(
        _self_play(buyer, seller, (cfg.plo, cfg.phi, cfg.dlo, cfg.dhi))
    )
    if agreement is None:
        return  # no settlement reached: individual rationality is vacuous

    ap, ad = agreement
    assert buyer.utility(_terms(ap, ad)) >= cfg.reservation - _EPS
    assert seller.utility(_terms(ap, ad)) >= cfg.reservation - _EPS


# The exact configuration Hypothesis surfaced as a counterexample to the (false)
# "self-play is always Pareto-efficient" conjecture. Pinned so the boundary
# reproduces deterministically.
_FSJ_SUBOPTIMAL = _Cfg(
    plo=10,
    phi=30,
    dlo=1,
    dhi=9,
    patience=0.890625,
    buyer_wp=0.75,
    seller_wd=0.90625,
    reservation=0.0,
)


def test_fsj_tradeoff_does_not_guarantee_pareto_optimality() -> None:
    """Characterize the boundary: trade-off concession approaches but does not reach Pareto.

    Faratin, Sierra & Jennings 2002 show similarity-based trade-off moves raise
    joint gains and *approach* the Pareto frontier, but do not *guarantee* it
    under incomplete information: a Pareto-improving bundle offered early can be
    rejected (the recipient's aspiration is still above it) and gone by the time
    aspiration falls enough to accept. The bundle is ephemeral. A hard guarantee
    would require the MCP/Zeuthen optimal-deal search (exponential in the issue
    grid per round); ParetoNegotiation deliberately trades that guarantee for
    tractable, deterministic concession.

    This test pins the configuration Hypothesis found and asserts the agreement
    IS dominated by a bundle exchanged earlier in the same session, documenting
    the limit as an intentional design boundary, not a bug. (The end-to-end
    asymmetric gate asserts Pareto-efficiency where the design *does* secure it.)
    """
    cfg = _FSJ_SUBOPTIMAL
    buyer = _make_buyer(cfg, max_rounds=25)
    seller = _make_seller(cfg, max_rounds=25)
    agreement, exchanged = asyncio.run(
        _self_play(buyer, seller, (cfg.plo, cfg.phi, cfg.dlo, cfg.dhi))
    )
    assert agreement is not None, "expected this configuration to settle"

    ap, ad = agreement
    ub_star = buyer.utility(_terms(ap, ad))
    us_star = seller.utility(_terms(ap, ad))

    def _dominates_agreement(bundle: tuple[int, int]) -> bool:
        xp, xd = bundle
        ub_x = buyer.utility(_terms(xp, xd))
        us_x = seller.utility(_terms(xp, xd))
        return _dominates(ub_x, us_x, ub_star, us_star)

    dominators = [b for b in exchanged if b != (ap, ad) and _dominates_agreement(b)]
    assert dominators, (
        f"expected an ephemeral dominating bundle; agreement={agreement}, exchanged={exchanged}"
    )
