# SPDX-License-Identifier: Apache-2.0
"""Adversarial + property tests for the bonded-trust plugin.

Covers the headline claims (free-minted swarm inert; splitting a scarce budget
buys no influence), the enforcement path (a ledger rejects unfunded bonds), the
self-vouch exclusion, config guards, and the pluggable scarcity anchor
(credit-backed and proof-of-work).
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from nest_core.types import AgentId, Claim, Evidence
from nest_plugins_reference.trust.bonded_trust import BondedTrust
from nest_plugins_reference.trust.stake_ledgers import (
    CreditBackedLedger,
    ProofOfWorkLedger,
)


def _ev(reporter: str, subject: str, kind: str) -> Evidence:
    return Evidence(reporter=AgentId(reporter), subject=AgentId(subject), kind=kind)


# --- the free-minting / wash-trading defenses ------------------------------


@pytest.mark.asyncio
async def test_unbonded_identity_is_pinned_at_floor() -> None:
    """A free-minted identity that never bonds scores 0.0 no matter the praise."""
    trust = BondedTrust()
    for i in range(50):
        await trust.report(AgentId("victim"), _ev(f"fan-{i}", "victim", "positive"))
    rep = await trust.score(AgentId("victim"))
    assert rep.score == 0.0
    assert rep.confidence == 0.0


@pytest.mark.asyncio
async def test_sybil_swarm_cannot_promote_itself() -> None:
    """K unbonded Sybils cross-endorsing cannot lift any of themselves off the floor."""
    trust = BondedTrust()
    swarm = [f"sybil-{i}" for i in range(100)]
    for subject in swarm:
        for reporter in swarm:
            await trust.report(AgentId(subject), _ev(reporter, subject, "positive"))
    for subject in swarm:
        assert (await trust.score(AgentId(subject))).score == 0.0


@pytest.mark.asyncio
async def test_self_vouch_is_ignored() -> None:
    """A bonded agent cannot vouch for itself onto a score."""
    trust = BondedTrust()  # SelfDeclaredLedger grants the bond
    await trust.stake(AgentId("a"), 10)
    await trust.report(AgentId("a"), _ev("a", "a", "positive"))  # self-vouch
    rep = await trust.score(AgentId("a"))
    assert rep.score == 0.5  # bonded but unproven; the self-report did not count


# --- enforcement: the ledger makes bonds scarce ----------------------------


@pytest.mark.asyncio
async def test_unfunded_bond_request_is_rejected() -> None:
    """The security-review attack: a broke Sybil bids a huge bond and gets nothing."""
    ledger = CreditBackedLedger({})  # nobody has credits
    trust = BondedTrust(ledger=ledger)
    await trust.stake(AgentId("sybil"), 1_000_000)
    for i in range(20):
        await trust.report(AgentId("sybil"), _ev(f"buddy-{i}", "sybil", "positive"))
    assert (await trust.score(AgentId("sybil"))).score == 0.0


@pytest.mark.asyncio
async def test_credit_budget_split_buys_no_extra_influence() -> None:
    """A fixed attacker budget exerts the same weight whether held by 1 or 90 ids."""
    honest_positive = 90

    solo_balances: dict[AgentId, int] = {
        AgentId("target"): 2,
        AgentId("whale"): 90,
        AgentId("honest"): 90,
    }
    solo = BondedTrust(ledger=CreditBackedLedger(solo_balances))
    await solo.stake(AgentId("target"), 2)
    await solo.stake(AgentId("whale"), 90)
    await solo.stake(AgentId("honest"), honest_positive)
    await solo.report(AgentId("target"), _ev("honest", "target", "positive"))
    await solo.report(AgentId("target"), _ev("whale", "target", "negative"))
    solo_score = (await solo.score(AgentId("target"))).score

    split_balances: dict[AgentId, int] = {AgentId("target"): 2, AgentId("honest"): 90}
    for i in range(90):
        split_balances[AgentId(f"c-{i}")] = 1
    split = BondedTrust(ledger=CreditBackedLedger(split_balances))
    await split.stake(AgentId("target"), 2)
    await split.stake(AgentId("honest"), honest_positive)
    await split.report(AgentId("target"), _ev("honest", "target", "positive"))
    for i in range(90):
        await split.stake(AgentId(f"c-{i}"), 1)
        await split.report(AgentId("target"), _ev(f"c-{i}", "target", "negative"))

    assert solo_score == pytest.approx((await split.score(AgentId("target"))).score)


# --- pluggable scarcity anchor: proof-of-work ------------------------------


@pytest.mark.asyncio
async def test_proof_of_work_anchor_gates_the_bond() -> None:
    """Swap credits for CPU: a miner earns a bond; a lazy identity earns nothing."""
    pow_ledger = ProofOfWorkLedger(difficulty_bits=8)
    trust = BondedTrust(ledger=pow_ledger)

    pow_ledger.mine(AgentId("worker"), 2)  # pays real hash work
    pow_ledger.mine(AgentId("booster"), 2)
    await trust.stake(AgentId("worker"), 2)
    await trust.stake(AgentId("booster"), 2)
    await trust.report(AgentId("worker"), _ev("booster", "worker", "positive"))

    await trust.stake(AgentId("lazy"), 5)  # never mined → no budget → no bond

    assert (await trust.score(AgentId("worker"))).score == 1.0
    assert (await trust.score(AgentId("lazy"))).score == 0.0


def test_proof_of_work_replay_is_rejected() -> None:
    """Resubmitting one solved nonce cannot inflate budget past the work done."""
    pow_ledger = ProofOfWorkLedger(difficulty_bits=8)
    nonce = pow_ledger.solve(AgentId("miner"), 0)  # one genuine solution
    assert pow_ledger.prove(AgentId("miner"), 0, nonce) is True
    # Replaying the same (counter, nonce) 1000× must grant nothing more.
    for _ in range(1000):
        assert pow_ledger.prove(AgentId("miner"), 0, nonce) is False
    assert pow_ledger.reserve(AgentId("miner"), 1000) == 1  # only the one real unit


def test_proof_of_work_rejects_bad_difficulty() -> None:
    """difficulty_bits outside 1..32 is refused (0 = no work, >32 = crash)."""
    with pytest.raises(ValueError, match="difficulty_bits"):
        ProofOfWorkLedger(difficulty_bits=0)
    with pytest.raises(ValueError, match="difficulty_bits"):
        ProofOfWorkLedger(difficulty_bits=33)


# --- canonical Sybil-resistance bar (EigenTrust, Kamvar et al. 2003) --------
# The adversarial properties that reputation systems are classically measured
# against. bonded_trust anchors trust on a scarce bond rather than a pre-trusted
# seed, but must clear the same bar. Self-contained — no dependency on any other
# plugin; the "trusted" agents are simply the ones that can afford a bond.


@pytest.mark.asyncio
async def test_sybil_clique_cannot_outrank_a_bonded_agent() -> None:
    """A self-vouching Sybil clique cannot out-rank a bonded, endorsed agent."""
    t = BondedTrust(ledger=CreditBackedLedger({AgentId("seed"): 100, AgentId("honest"): 100}))
    await t.stake(AgentId("seed"), 100)
    await t.stake(AgentId("honest"), 100)
    await t.report(AgentId("honest"), _ev("seed", "honest", "positive"))
    sybils = [f"sybil-{i}" for i in range(10)]
    for src in sybils:
        await t.stake(AgentId(src), 1_000_000)  # broke → bond denied
        for dst in sybils:
            if src != dst:
                await t.report(AgentId(dst), _ev(src, dst, "positive"))
    s_honest = (await t.score(AgentId("honest"))).score
    s_sybil = max([(await t.score(AgentId(s))).score for s in sybils])
    assert s_sybil < s_honest


@pytest.mark.asyncio
async def test_self_promotion_does_not_inflate() -> None:
    """Self-reports cannot lift an agent above one a bonded witness vouches for."""
    t = BondedTrust(ledger=CreditBackedLedger({AgentId("witness"): 100, AgentId("b"): 100}))
    await t.stake(AgentId("witness"), 100)
    await t.stake(AgentId("b"), 100)
    for _ in range(10):
        await t.report(AgentId("a"), _ev("a", "a", "positive"))  # self-promotion spam
    await t.report(AgentId("b"), _ev("witness", "b", "positive"))
    assert (await t.score(AgentId("b"))).score > (await t.score(AgentId("a"))).score


@pytest.mark.asyncio
async def test_distrusted_reporter_cannot_swing_a_bonded_agent() -> None:
    """An unbonded rogue's negative blasts cannot swing a bonded, endorsed agent."""
    t = BondedTrust(ledger=CreditBackedLedger({AgentId("seed"): 100, AgentId("target"): 100}))
    await t.stake(AgentId("seed"), 100)
    await t.stake(AgentId("target"), 100)
    for _ in range(3):
        await t.report(AgentId("target"), _ev("seed", "target", "positive"))
    await t.stake(AgentId("rogue"), 1_000_000)  # broke → bond denied
    for _ in range(200):
        await t.report(AgentId("target"), _ev("rogue", "target", "negative"))
    for _ in range(200):
        await t.report(AgentId("rogue"), _ev("rogue", "rogue", "positive"))
    assert (await t.score(AgentId("target"))).score > (await t.score(AgentId("rogue"))).score


# --- config guards + the bonding path --------------------------------------


def test_min_bond_zero_is_rejected() -> None:
    """min_bond=0 would disable the gate, so the constructor refuses it."""
    with pytest.raises(ValueError, match="min_bond"):
        BondedTrust(min_bond=0)


@pytest.mark.asyncio
async def test_bonding_lifts_the_trust_root() -> None:
    """The same evidence that left an identity inert now counts once it bonds."""
    trust = BondedTrust()
    await trust.stake(AgentId("reporter"), 10)
    await trust.report(AgentId("newcomer"), _ev("reporter", "newcomer", "positive"))

    assert (await trust.score(AgentId("newcomer"))).score == 0.0  # unbonded → inert
    await trust.stake(AgentId("newcomer"), 5)  # posts its bond
    assert (await trust.score(AgentId("newcomer"))).score == 1.0  # root established


@pytest.mark.asyncio
async def test_attest_signs_when_identity_supplied() -> None:
    """attest() stays protocol-compatible with score_average's signing path."""
    trust = BondedTrust()
    claim = Claim(subject=AgentId("a1"), predicate="completed_task", value="t-1")
    att = await trust.attest(AgentId("a1"), claim)
    assert att.claim == claim


@given(
    bond=st.integers(min_value=1, max_value=10_000),
    positives=st.integers(min_value=0, max_value=20),
    negatives=st.integers(min_value=0, max_value=20),
)
@pytest.mark.asyncio
async def test_bonded_score_stays_in_unit_interval(
    bond: int, positives: int, negatives: int
) -> None:
    """A bonded agent's score is always a well-formed reputation in [0, 1]."""
    trust = BondedTrust()
    await trust.stake(AgentId("subject"), bond)
    await trust.stake(AgentId("r"), bond)
    for _ in range(positives):
        await trust.report(AgentId("subject"), _ev("r", "subject", "positive"))
    for _ in range(negatives):
        await trust.report(AgentId("subject"), _ev("r", "subject", "negative"))
    rep = await trust.score(AgentId("subject"))
    assert 0.0 <= rep.score <= 1.0
    assert 0.0 <= rep.confidence <= 1.0
