# SPDX-License-Identifier: Apache-2.0
# White-box tests intentionally access plugin/store internals.
# pyright: reportPrivateUsage=false
"""Tests for the four ResonanceBFT adversarial validators.

Each validator must:
  - PASS when given genuine ResonanceBFT outcomes/rounds.
  - FAIL when given contract_net-style objects that lack BFT metadata.

The tests are pure-Python unit tests that build minimal Outcome/Round fixtures
without running the full simulator, so they stay fast and dependency-free.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nest_core.types import AgentId, Outcome, Round, Task
from nest_plugins_reference.coordination.resonance_bft._vectors import _belief_digest
from nest_plugins_reference.validators import (
    BftValidationResult,
    build_equivocation_certificate,
    collect_equivocation_certificates,
    validate_bft_liveness_view_progress,
    validate_bft_no_conflicting_commits,
    validate_bft_no_equivocation,
    validate_bft_no_forged_quorum,
    validate_genuine_consensus,
    validate_no_axis_deadlock,
    verify_equivocation_certificate,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _task() -> Task:
    return Task(
        id="t1",
        description="select routing model",
        requirements=["latency < 100ms", "cost < 0.01"],
    )


def _commitment(belief_vec: list[float], nonce: str) -> str:
    """Derive the SHA-256 commitment over the belief vector (semantic + affective)."""
    payload = f"{belief_vec}:{nonce}".encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _bft_outcome(
    round_id: str,
    winner: str | None,
    status: str = "committed",
    quorum_size: int = 5,
    quorum_needed: int = 5,
    view_number: int = 0,
) -> Outcome:
    # Build a quorum_agents list that is self-consistent with quorum_size (the
    # validator recomputes from it, so it must match). winner is the first member.
    quorum_agents = [f"qa{i}" for i in range(quorum_size)]
    if winner and quorum_size > 0:
        quorum_agents[0] = winner
    return Outcome(
        round_id=round_id,
        winner=AgentId(winner) if winner else None,
        task=_task(),
        metadata={
            "status": status,
            "quorum_size": quorum_size,
            "quorum_needed": quorum_needed,
            "total_participants": 7,
            "f": 2,
            "quorum_agents": quorum_agents,
            "outlier_agents": [],
            "tampered_agents": [],
            "view_number": view_number,
            "threshold": 0.60,
        },
    )


def _contract_net_outcome(round_id: str, winner: str) -> Outcome:
    """Mimics a contract_net Outcome — no BFT metadata keys."""
    return Outcome(
        round_id=round_id,
        winner=AgentId(winner),
        task=_task(),
        metadata={"accepted": True, "bid": 42.0},
    )


def _bft_round(
    round_id: str,
    agents: list[str],
    *,
    tamper: str | None = None,
) -> Round:
    """Build a Round with sealed BFT evaluations for each agent in *agents*.

    The commitment seals all five belief axes (semantic+affective+epistemic+behavioral+
    relational_sealed), as derived at participate() time.  If *tamper* names an agent, the
    stored commitment is set to a wrong hash — simulating equivocation / belief tampering.
    """
    vocab = ["task", "model", "latency", "cost"]
    evaluations: dict[str, dict[str, Any]] = {}
    for aid in agents:
        semantic = [0.5, 0.3, 0.1, 0.1]
        affective = [0.8, 0.6]
        relational = [0.9, 0.7, 0.4, 0.2, 0.5]
        epistemic = [0.7, 0.9]
        behavioral = [0.95, 0.85]
        # The seal now covers all five belief axes (semantic+affective+epistemic+
        # behavioral+relational_sealed), matching _protocol._sealed_belief.
        belief_vec = semantic + affective + epistemic + behavioral + relational
        nonce = f"nonce_{aid}"
        commit = "sha256:" + "0" * 64 if aid == tamper else _commitment(belief_vec, nonce)
        # A valid ed25519 signature over the evaluation text — what resolve() and the
        # equivocation validator now both verify. The `tamper` case only corrupts the
        # SHA commitment (sig stays valid), so the seal check is what flags it.
        eval_text = f"evaluation by {aid}"
        sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(aid.encode()).digest()[:32])
        # Sign over the belief digest (eval_text + commitment + round_id + aid), matching
        # what resolve() and the equivocation validator verify after the round-binding change.
        signature = sk.sign(_belief_digest(eval_text, commit, round_id, aid)).hex()
        evaluations[aid] = {
            "commitment": commit,
            "nonce": nonce,
            "eval_text": eval_text,
            "signature": signature,
            "pubkey": sk.public_key().public_bytes_raw().hex(),
            "combined": semantic + affective + relational + epistemic + behavioral,
            "semantic": semantic,
            "affective": affective,
            "relational": relational,
            "relational_sealed": relational,
            "epistemic": epistemic,
            "behavioral": behavioral,
        }

    return Round(
        id=round_id,
        task=_task(),
        participants=[AgentId(a) for a in agents],
        metadata={
            "protocol": "resonance_bft",
            "version": "pentadic-2.0",
            "view_number": 0,
            "vocab": vocab,
            "evaluations": evaluations,
        },
    )


def _contract_net_round(round_id: str) -> Round:
    """Mimics a contract_net Round — no commitment seals."""
    return Round(
        id=round_id,
        task=_task(),
        participants=[AgentId("agent-0")],
        metadata={"bids": {"agent-0": 42.0}},
    )


# ── validate_bft_no_conflicting_commits ──────────────────────────────────────


class TestNoConflictingCommits:
    def test_passes_when_same_winner(self) -> None:
        outcomes = [
            _bft_outcome("r1", "leader-0"),
            _bft_outcome("r1", "leader-0"),
        ]
        result = validate_bft_no_conflicting_commits(outcomes)
        assert result.passed, result.detail

    def test_passes_on_empty_list(self) -> None:
        result = validate_bft_no_conflicting_commits([])
        assert result.passed

    def test_passes_on_aborted_outcomes(self) -> None:
        outcomes = [_bft_outcome("r1", None, status="aborted", quorum_size=2)]
        result = validate_bft_no_conflicting_commits(outcomes)
        assert result.passed

    def test_fails_on_conflicting_winners(self) -> None:
        """Same round, IDENTICAL quorum (the same agreement evidence) but two different
        winners → a fork: the same evidence must yield the same decision."""
        o1 = _bft_outcome("r1", "leader-0")
        o2 = _bft_outcome("r1", "follower-1")
        o2.metadata["quorum_agents"] = list(o1.metadata["quorum_agents"])  # identical quorum
        result = validate_bft_no_conflicting_commits([o1, o2])
        assert not result.passed
        assert "different winners" in result.detail

    def test_fails_on_inconsistent_shared_core(self) -> None:
        """A real fork: an agent PRESENT in both commits is in one commit's quorum but
        excluded (outlier) by the other — the two views disagree about who agreed."""
        o1 = _bft_outcome("r1", "leader-0")  # quorum {leader-0, qa1, qa2, qa3, qa4}
        o2 = _bft_outcome("r1", "leader-0")
        # qa4 is in-quorum for o1 but o2 saw it and put it OUT (outlier) → inconsistent.
        o2.metadata["quorum_agents"] = ["leader-0", "qa1", "qa2", "qa3", "x5"]
        o2.metadata["outlier_agents"] = ["qa4"]
        result = validate_bft_no_conflicting_commits([o1, o2])
        assert not result.passed
        assert "shared core" in result.detail

    def test_passes_on_divergent_overlapping_quorums(self) -> None:
        """Two honest resolvers seeing different n−f subsets of one round form different
        overlapping quorums; as long as every agent they BOTH saw is classified the same,
        that is approximate agreement, NOT a fork (the earlier whole-certificate check
        wrongly failed here)."""
        o1 = _bft_outcome("r1", "leader-0")  # quorum {leader-0, qa1, qa2, qa3, qa4}
        o2 = _bft_outcome("r1", "leader-0")
        # o2 simply did not see qa4 (absent, not excluded) and saw a new member x5 instead.
        o2.metadata["quorum_agents"] = ["leader-0", "qa1", "qa2", "qa3", "x5"]
        result = validate_bft_no_conflicting_commits([o1, o2])
        assert result.passed, result.detail

    def test_fails_on_contract_net_outcomes(self) -> None:
        outcomes = [_contract_net_outcome("r1", "agent-0")]
        result = validate_bft_no_conflicting_commits(outcomes)
        assert not result.passed
        assert "protocol mismatch" in result.detail

    def test_result_is_bft_validation_result(self) -> None:
        result = validate_bft_no_conflicting_commits([])
        assert isinstance(result, BftValidationResult)


# ── validate_bft_no_equivocation ─────────────────────────────────────────────


class TestNoEquivocation:
    _AGENTS = ["leader-0", "follower-0", "follower-1", "follower-2", "follower-3"]

    def test_passes_with_intact_commitments(self) -> None:
        rounds = [_bft_round("r1", self._AGENTS)]
        result = validate_bft_no_equivocation(rounds)
        assert result.passed, result.detail

    def test_passes_on_empty_list(self) -> None:
        result = validate_bft_no_equivocation([])
        assert result.passed

    def test_fails_when_commitment_tampered(self) -> None:
        rounds = [_bft_round("r1", self._AGENTS, tamper="follower-0")]
        result = validate_bft_no_equivocation(rounds)
        assert not result.passed
        assert "commitment seal mismatch" in result.detail

    def test_fails_when_signature_forged(self) -> None:
        """The validator now verifies the ed25519 signature too — an adversary who keeps
        the SHA seal valid but cannot forge the signature is caught."""
        rnd = _bft_round("r1", self._AGENTS)
        # leave the seal intact but corrupt the signature
        rnd.metadata["evaluations"]["follower-0"]["signature"] = "00" * 64
        result = validate_bft_no_equivocation([rnd])
        assert not result.passed
        assert "signature" in result.detail

    def test_fails_on_contract_net_rounds(self) -> None:
        rounds = [_contract_net_round("r1")]
        result = validate_bft_no_equivocation(rounds)
        assert not result.passed
        assert "protocol mismatch" in result.detail

    def test_multiple_rounds_all_checked(self) -> None:
        rounds = [
            _bft_round("r1", self._AGENTS),
            _bft_round("r2", self._AGENTS),
        ]
        result = validate_bft_no_equivocation(rounds)
        assert result.passed
        assert "10" in result.detail  # 5 agents × 2 rounds = 10 seals

    def test_fails_on_cross_round_equivocation(self) -> None:
        """An agent that submits TWO different, individually-valid signed commitments for the
        SAME round (e.g. one per partition side / resolver view) is equivocating — each record
        verifies internally, but the cross-round check must flag the conflict."""
        r1 = _bft_round("r1", self._AGENTS)
        r1b = _bft_round("r1", self._AGENTS)  # same round id
        # Give leader-0 in the second copy a DIFFERENT but validly-signed commitment.
        rec = r1b.metadata["evaluations"]["leader-0"]
        belief = (
            rec["semantic"]
            + rec["affective"]
            + rec["epistemic"]
            + rec["behavioral"]
            + rec["relational"]
        )
        rec["nonce"] = "equivocation_nonce"
        rec["commitment"] = _commitment(belief, rec["nonce"])
        sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"leader-0").digest()[:32])
        rec["signature"] = sk.sign(
            _belief_digest(rec["eval_text"], rec["commitment"], "r1", "leader-0")
        ).hex()

        result = validate_bft_no_equivocation([r1, r1b])
        assert not result.passed
        assert "EQUIVOCATION" in result.detail


# ── validate_bft_no_forged_quorum ─────────────────────────────────────────────


class TestNoForgedQuorum:
    def test_passes_with_valid_quorum(self) -> None:
        outcomes = [_bft_outcome("r1", "leader-0", quorum_size=5, quorum_needed=5)]
        result = validate_bft_no_forged_quorum(outcomes)
        assert result.passed, result.detail

    def test_fails_when_quorum_size_claim_forged(self) -> None:
        """The validator now RECOMPUTES quorum size from quorum_agents, so lying about
        quorum_size (claiming 5 while actually committing with 3 agents) is caught."""
        outcome = _bft_outcome("r1", "leader-0", quorum_size=5, quorum_needed=5)
        # adversary shrinks the actual quorum but keeps the claimed size at 5
        outcome.metadata["quorum_agents"] = ["leader-0", "f1", "f2"]
        result = validate_bft_no_forged_quorum([outcome])
        assert not result.passed
        assert "metadata tampering" in result.detail

    def test_passes_on_aborted_outcomes(self) -> None:
        # aborted outcomes are not checked (quorum was not achieved)
        outcomes = [_bft_outcome("r1", None, status="aborted", quorum_size=2)]
        result = validate_bft_no_forged_quorum(outcomes)
        assert result.passed

    def test_fails_when_quorum_below_threshold(self) -> None:
        outcomes = [_bft_outcome("r1", "leader-0", quorum_size=3, quorum_needed=5)]
        result = validate_bft_no_forged_quorum(outcomes)
        assert not result.passed
        assert "forged quorum" in result.detail

    def test_fails_on_contract_net_outcomes(self) -> None:
        outcomes = [_contract_net_outcome("r1", "agent-0")]
        result = validate_bft_no_forged_quorum(outcomes)
        assert not result.passed
        assert "protocol mismatch" in result.detail

    def test_passes_when_quorum_exactly_met(self) -> None:
        # 2f+1 = 5 for n=7, f=2
        outcomes = [_bft_outcome("r1", "leader-0", quorum_size=5, quorum_needed=5)]
        result = validate_bft_no_forged_quorum(outcomes)
        assert result.passed

    def test_fails_when_total_participants_under_reported(self) -> None:
        """A forger that under-reports total_participants to shrink f (and thus the
        quorum bar) is caught: the validator recomputes a membership floor from the
        distinct agents actually present (quorum ∪ outlier ∪ tampered) and flags any
        claimed total below it."""
        outcome = _bft_outcome("r1", "leader-0", quorum_size=5, quorum_needed=3)
        # 5 quorum + 3 outliers = 8 distinct agents really participated...
        outcome.metadata["quorum_agents"] = [f"q{i}" for i in range(5)]
        outcome.metadata["quorum_agents"][0] = "leader-0"
        outcome.metadata["outlier_agents"] = ["o1", "o2", "o3"]
        # ...but the adversary claims only 4, which would imply f=1, quorum_needed=3.
        outcome.metadata["total_participants"] = 4
        result = validate_bft_no_forged_quorum([outcome])
        assert not result.passed
        assert "under-reported" in result.detail


# ── validate_bft_liveness_view_progress ──────────────────────────────────────


class TestLivenessViewProgress:
    def test_passes_with_all_commits(self) -> None:
        outcomes = [
            _bft_outcome("r1", "leader-0", view_number=0),
            _bft_outcome("r2", "follower-1", view_number=0),
        ]
        result = validate_bft_liveness_view_progress(outcomes)
        assert result.passed, result.detail

    def test_passes_with_occasional_aborts(self) -> None:
        outcomes = [
            _bft_outcome("r1", None, status="aborted", quorum_size=2, view_number=0),
            _bft_outcome("r2", None, status="aborted", quorum_size=2, view_number=1),
            _bft_outcome("r3", "leader-0", view_number=2),  # commit after 2 aborts
        ]
        result = validate_bft_liveness_view_progress(outcomes, max_consecutive_aborts=3)
        assert result.passed, result.detail

    def test_fails_when_stuck(self) -> None:
        # 4 consecutive aborts > max_consecutive_aborts=3
        outcomes = [
            _bft_outcome("r1", None, status="aborted", quorum_size=2, view_number=0),
            _bft_outcome("r2", None, status="aborted", quorum_size=2, view_number=1),
            _bft_outcome("r3", None, status="aborted", quorum_size=2, view_number=2),
            _bft_outcome("r4", None, status="aborted", quorum_size=2, view_number=3),
        ]
        result = validate_bft_liveness_view_progress(outcomes, max_consecutive_aborts=3)
        assert not result.passed
        assert "stuck" in result.detail or "liveness" in result.detail

    def test_fails_on_contract_net_outcomes(self) -> None:
        outcomes = [_contract_net_outcome("r1", "agent-0")]
        result = validate_bft_liveness_view_progress(outcomes)
        assert not result.passed
        assert "protocol mismatch" in result.detail

    def test_passes_on_empty_list(self) -> None:
        result = validate_bft_liveness_view_progress([])
        assert result.passed

    def test_abort_then_commit_resets_counter(self) -> None:
        outcomes = [
            _bft_outcome("r1", None, status="aborted", quorum_size=2, view_number=0),
            _bft_outcome("r2", None, status="aborted", quorum_size=2, view_number=1),
            _bft_outcome("r3", "leader-0", view_number=2),  # commit resets counter
            _bft_outcome("r4", None, status="aborted", quorum_size=2, view_number=0),
            _bft_outcome("r5", None, status="aborted", quorum_size=2, view_number=1),
            _bft_outcome("r6", "leader-0", view_number=2),  # commit again
        ]
        result = validate_bft_liveness_view_progress(outcomes, max_consecutive_aborts=3)
        assert result.passed, result.detail


# ── Fixtures for process-quality validators ───────────────────────────────────


def _bft_outcome_with_conflict(
    round_id: str,
    winner: str | None,
    *,
    consensus_type: str = "genuine",
    conflict_type: str = "none",
    deadlocked_axes: list[dict[str, Any]] | None = None,
    status: str = "committed",
) -> Outcome:
    """BFT outcome that includes deliberation + conflict metadata."""
    return Outcome(
        round_id=round_id,
        winner=AgentId(winner) if winner else None,
        task=_task(),
        metadata={
            "status": status,
            "quorum_size": 5,
            "quorum_needed": 5,
            "total_participants": 7,
            "f": 2,
            "quorum_agents": [winner] if winner else [],
            "outlier_agents": [],
            "tampered_agents": [],
            "view_number": 0,
            "threshold": 0.60,
            "consensus_type": consensus_type,
            "deliberation": {"steps": 4, "concession_symmetry": 0.8, "depth": 0.15},
            "conflict_type": conflict_type,
            "conflict": {
                "conflict_type": conflict_type,
                "axis_agreement": {
                    "semantic": 0.9,
                    "affective": 0.8,
                    "relational": 0.7,
                    "epistemic": 0.9,
                    "behavioral": 0.85,
                },
                "agreed_axes": ["semantic", "affective", "relational", "epistemic", "behavioral"],
                "disagreed_axes": [],
                "deadlocked_axes": deadlocked_axes or [],
                "persistent_dissenters": [],
            },
        },
    )


# ── validate_genuine_consensus ────────────────────────────────────────────────


class TestGenuineConsensus:
    def test_passes_with_genuine_outcomes(self) -> None:
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="genuine")]
        result = validate_genuine_consensus(outcomes)
        assert result.passed, result.detail

    def test_passes_with_unknown_type(self) -> None:
        """unknown = deliberate() not called; should pass (backward compat)."""
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="unknown")]
        result = validate_genuine_consensus(outcomes)
        assert result.passed, result.detail

    def test_fails_on_capitulated(self) -> None:
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="capitulated")]
        result = validate_genuine_consensus(outcomes)
        assert not result.passed
        assert "capitulated" in result.detail

    def test_fails_on_coerced(self) -> None:
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="coerced")]
        result = validate_genuine_consensus(outcomes)
        assert not result.passed
        assert "coerced" in result.detail

    def test_fails_on_logrolled(self) -> None:
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="logrolled")]
        result = validate_genuine_consensus(outcomes)
        assert not result.passed
        assert "logrolled" in result.detail

    def test_fragile_fails_by_default(self) -> None:
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="fragile")]
        result = validate_genuine_consensus(outcomes)
        assert not result.passed

    def test_fragile_passes_when_allowed(self) -> None:
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="fragile")]
        result = validate_genuine_consensus(outcomes, allow_fragile=True)
        assert result.passed

    def test_fails_on_committed_deadlock_or_polarized(self) -> None:
        """A committed outcome CAN carry consensus_type 'deadlock'/'polarized' (the commit
        gate uses per-axis pentadic similarity while the label uses the deliberation
        mean_sim — they can disagree), and that is non-genuine consensus the validator must
        flag."""
        for ctype in ("deadlock", "polarized"):
            outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type=ctype)]
            result = validate_genuine_consensus(outcomes)
            assert not result.passed, f"committed {ctype} should be flagged non-genuine"
            assert ctype in result.detail

    def test_unknown_flagged_when_deliberation_required(self) -> None:
        """require_deliberation=True flags committed 'unknown' outcomes — authenticity was
        never measured (deliberate() skipped), so the commit's genuineness is unverified."""
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0", consensus_type="unknown")]
        result = validate_genuine_consensus(outcomes, require_deliberation=True)
        assert not result.passed
        assert "unknown" in result.detail

    def test_fails_on_contract_net_outcomes(self) -> None:
        outcomes = [_contract_net_outcome("r1", "agent-0")]
        result = validate_genuine_consensus(outcomes)
        assert not result.passed
        assert "protocol mismatch" in result.detail

    def test_passes_on_empty_list(self) -> None:
        result = validate_genuine_consensus([])
        assert result.passed

    def test_skips_aborted_outcomes(self) -> None:
        """Aborted outcomes are not checked for consensus_type."""
        outcomes = [
            _bft_outcome_with_conflict(
                "r1",
                None,
                consensus_type="capitulated",
                status="aborted",
            )
        ]
        result = validate_genuine_consensus(outcomes)
        assert result.passed

    def test_returns_bft_validation_result(self) -> None:
        result = validate_genuine_consensus([])
        assert isinstance(result, BftValidationResult)


# ── validate_no_axis_deadlock ─────────────────────────────────────────────────


class TestNoAxisDeadlock:
    def test_passes_with_no_deadlocked_axes(self) -> None:
        outcomes = [_bft_outcome_with_conflict("r1", "leader-0")]
        result = validate_no_axis_deadlock(outcomes)
        assert result.passed, result.detail

    def test_fails_when_committed_with_deadlock(self) -> None:
        deadlock = [
            {
                "axis": "semantic",
                "cluster_a": ["a0"],
                "cluster_b": ["a1"],
                "inter_cluster_sim": -0.45,
            }
        ]
        outcomes = [
            _bft_outcome_with_conflict(
                "r1",
                "leader-0",
                conflict_type="axis_deadlock",
                deadlocked_axes=deadlock,
            )
        ]
        result = validate_no_axis_deadlock(outcomes)
        assert not result.passed
        assert "semantic" in result.detail

    def test_passes_on_aborted_with_deadlock(self) -> None:
        """Aborted outcomes with deadlock are expected — not flagged."""
        deadlock = [
            {
                "axis": "affective",
                "cluster_a": ["a0"],
                "cluster_b": ["a1"],
                "inter_cluster_sim": -0.6,
            }
        ]
        outcomes = [
            _bft_outcome_with_conflict(
                "r1",
                None,
                conflict_type="axis_deadlock",
                deadlocked_axes=deadlock,
                status="aborted",
            )
        ]
        result = validate_no_axis_deadlock(outcomes)
        assert result.passed

    def test_fails_on_contract_net_outcomes(self) -> None:
        outcomes = [_contract_net_outcome("r1", "agent-0")]
        result = validate_no_axis_deadlock(outcomes)
        assert not result.passed
        assert "protocol mismatch" in result.detail

    def test_passes_on_empty_list(self) -> None:
        result = validate_no_axis_deadlock([])
        assert result.passed


def _signed_record(
    round_id: str, aid: str, sk: Ed25519PrivateKey, semantic: list[float]
) -> dict[str, Any]:
    """A validly sealed + signed evaluation record for (round_id, aid), parameterised by
    *semantic* so two calls with different vectors yield two DISTINCT commitments — i.e. an
    equivocation when both carry the same (round_id, aid)."""
    affective = [0.8, 0.6]
    relational = [0.9, 0.7, 0.4, 0.2, 0.5]
    epistemic = [0.7, 0.9]
    behavioral = [0.95, 0.85]
    belief = semantic + affective + epistemic + behavioral + relational
    nonce = f"nonce_{aid}_{semantic[0]}"
    commit = _commitment(belief, nonce)
    eval_text = f"evaluation by {aid}"
    sig = sk.sign(_belief_digest(eval_text, commit, round_id, aid)).hex()
    return {
        "commitment": commit,
        "nonce": nonce,
        "eval_text": eval_text,
        "signature": sig,
        "pubkey": sk.public_key().public_bytes_raw().hex(),
        "semantic": semantic,
        "affective": affective,
        "relational": relational,
        "relational_sealed": relational,
        "epistemic": epistemic,
        "behavioral": behavioral,
    }


class TestEquivocationCertificate:
    """A transferable, third-party-verifiable proof that one agent signed two conflicting
    beliefs for the same round (Sheng et al. 2021, BFT Protocol Forensics)."""

    @staticmethod
    def _key(aid: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(aid.encode()).digest()[:32])

    def test_build_and_verify_certificate(self) -> None:
        sk = self._key("a0")
        rec1 = _signed_record("R", "a0", sk, [0.5, 0.3, 0.1, 0.1])
        rec2 = _signed_record("R", "a0", sk, [0.1, 0.1, 0.3, 0.5])  # distinct commitment
        cert = build_equivocation_certificate("R", "a0", [rec1, rec2])
        assert cert is not None
        assert cert["aid"] == "a0" and cert["round_id"] == "R"
        assert len(cert["entries"]) == 2
        # Verifiable by a third party from the certificate ALONE (no rounds, no trust).
        assert verify_equivocation_certificate(cert) is True

    def test_no_certificate_when_consistent(self) -> None:
        sk = self._key("a0")
        rec = _signed_record("R", "a0", sk, [0.5, 0.3, 0.1, 0.1])
        # Same record twice → one distinct commitment → not equivocation.
        assert build_equivocation_certificate("R", "a0", [rec, dict(rec)]) is None

    def test_verify_rejects_forged_certificate(self) -> None:
        sk = self._key("a0")
        rec1 = _signed_record("R", "a0", sk, [0.5, 0.3, 0.1, 0.1])
        rec2 = _signed_record("R", "a0", sk, [0.1, 0.1, 0.3, 0.5])
        cert = build_equivocation_certificate("R", "a0", [rec1, rec2])
        assert cert is not None
        # Forge: swap one commitment string so the signature no longer matches it.
        forged = {
            **cert,
            "entries": [
                {**cert["entries"][0], "commitment": "sha256:" + "f" * 64},
                cert["entries"][1],
            ],
        }
        assert verify_equivocation_certificate(forged) is False

    def test_collect_from_rounds(self) -> None:
        sk = self._key("a0")
        # Two Round objects sharing round id "R": a0 submits a different belief in each
        # (e.g. one to each side of a partition) → equivocation across the snapshots.
        r1 = _bft_round("R", ["a0", "a1"])
        r2 = _bft_round("R", ["a0", "a1"])
        r2.metadata["evaluations"]["a0"] = _signed_record("R", "a0", sk, [0.9, 0.05, 0.0, 0.05])
        r1.metadata["evaluations"]["a0"] = _signed_record("R", "a0", sk, [0.1, 0.2, 0.3, 0.4])
        certs = collect_equivocation_certificates([r1, r2])
        assert len(certs) == 1
        assert certs[0]["aid"] == "a0"
        assert verify_equivocation_certificate(certs[0]) is True

    def test_validator_surfaces_certificate(self) -> None:
        sk = self._key("a0")
        r1 = _bft_round("R", ["a0", "a1"])
        r2 = _bft_round("R", ["a0", "a1"])
        r1.metadata["evaluations"]["a0"] = _signed_record("R", "a0", sk, [0.1, 0.2, 0.3, 0.4])
        r2.metadata["evaluations"]["a0"] = _signed_record("R", "a0", sk, [0.9, 0.05, 0.0, 0.05])
        result = validate_bft_no_equivocation([r1, r2])
        assert result.passed is False
        assert len(result.certificates) == 1
        assert verify_equivocation_certificate(result.certificates[0]) is True
