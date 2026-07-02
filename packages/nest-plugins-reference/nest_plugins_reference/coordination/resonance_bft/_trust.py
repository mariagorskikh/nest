# SPDX-License-Identifier: Apache-2.0
"""TrustStore — all per-agent memory state for ResonanceBFT.

Encapsulates five memory layers:
  1. Global reputation      (first-order, broadcast)
  2. Scalar dyadic trust    (second-order, private, time-decayed)
  3. Per-axis trust overlay (faceted, endogenous — Abdul-Rahman & Hailes 2000 variant)
  4. Co-commit ledger       (coalition memory — Leifeld & Brandenberger 2024)
  5. Adaptive protocol params (learnable weights across three timescales)

Adaptive parameters (den Boer et al. 2024; Mohseni & Bernstein 2022):
  Layer 1 (per-round):  per-dyad trust decay, gain, loss; per-axis epsilon
  Layer 2 (per-epoch):  base_epsilon, similarity threshold
  Layer 3 (slow-epoch): axis weights (Exponentiated Gradient on ConsensusType signal)

BFT safety is preserved by construction: learned parameters shape *who is
counted* and *how deliberation converges*, but never alter the commit
certificate size requirement (n−f).
"""

from __future__ import annotations

import builtins
import itertools
import math
from typing import Any

__all__ = [
    "AXIS_EPSILON_MULTIPLIERS",
    "TrustStore",
    "_DEFAULT_AXIS_WEIGHTS",
    "_EPSILON_CO_COMMIT_BOOST",
    "_EPSILON_CO_COMMIT_CAP",
    "_TRUST_DECAY",
    "_TRUST_GAIN",
    "_TRUST_LOSS",
]

# ── Static protocol constants ─────────────────────────────────────────────────

_REPUTATION_INIT = 1.0
_REPUTATION_GAIN = 0.12
_REPUTATION_LOSS = 0.28

_TRUST_INIT = 1.0
# Base gain/loss used when adaptive params are not yet warm (< 5 interactions).
# Ratio 0.45/0.18 ≈ 2.5 ≈ the classic loss-aversion coefficient λ ≈ 2.25
# (Tversky & Kahneman 1992; see also the Bleichrodt & L'Haridon meta-analysis
# and Martínez-Tomás, Molins & Serrano 2022 on negativity bias — REFERENCES.md).
_TRUST_GAIN = 0.18
_TRUST_LOSS = 0.45
_TRUST_DECAY = 0.92  # per-round exponential decay (half-life ≈ 8 rounds); exponential decay
# best-fits social-interaction memory empirically (Arena, Mulder & Leenders 2023 — REFERENCES.md)

_EPSILON_CO_COMMIT_BOOST = 0.05  # kept for backward compat; sigmoid replaces it
_EPSILON_CO_COMMIT_CAP = 5  # max co-commits counted in legacy linear formula
_NEWCOMER_GRACE_ROUNDS = 3  # first N participations: outlier penalty waived

_AXES = ("semantic", "affective", "relational", "epistemic", "behavioral")

# ── Adaptive-learning constants ───────────────────────────────────────────────

# Per-axis epsilon multipliers — per-topic ε weighting, grounded in the multidimensional
# bounded-confidence model of Li, Luo & Chu (2025, arXiv:2502.00284; see REFERENCES.md), which
# applies a topic-weighted discordance per opinion dimension. We adapt that to per-AXIS ε:
# affective states update faster than cognitive beliefs; epistemic confidence is stickiest.
AXIS_EPSILON_MULTIPLIERS: dict[str, float] = {
    "semantic": 1.0,
    "affective": 1.8,
    "relational": 1.2,
    "epistemic": 0.9,
    "behavioral": 1.3,
}

# Exponentiated-gradient learning rate for axis weights (slow epoch).
_AW_LR = 0.008  # ≈ converges after 500 rounds of noisy signal
_AW_MIN = 0.05  # floor — no axis ever fully devalued
_AW_LOSS_BIAS = 2.0  # negativity bias for bad-round updates (Martínez-Tomás et al. 2022)

# Layer-2 (epoch) constants.
_EPOCH_SIZE = 50  # rounds per medium-epoch
_SLOW_EPOCH_SIZE = 200  # rounds per slow-epoch (axis weights)
_THETA_STEP = 0.02  # max threshold move per epoch
_EPS_STEP = 0.01  # max base-epsilon move per epoch
_LAMBDA_LOSS_AVERSION = 2.25  # fixed by meta-analysis; only scale changes

# ConsensusType quality scores for axis-weight gradient.
_CT_SCORES: dict[str, float] = {
    "genuine": +1.0,
    "fragile": -0.5,
    "capitulated": -0.8,
    "coerced": -0.8,
    "logrolled": -0.3,
    "coalitional": -0.4,
    "deadlock": -0.6,
    "polarized": -0.6,
    "unknown": 0.0,
}


# Canonical initial axis weights — seeded into TrustStore.axis_weights
# and re-exported as _AXIS_WEIGHTS in _protocol.py for backward compatibility.
# After Layer-3 warm-up these are replaced by Exponentiated Gradient updates.
_DEFAULT_AXIS_WEIGHTS: dict[str, float] = {
    "semantic": 0.25,
    "affective": 0.20,
    "relational": 0.25,
    "epistemic": 0.15,
    "behavioral": 0.15,
}


class TrustStore:
    """All memory state for a single ResonanceBFT agent.

    Designed to be owned by ResonanceBFT and accessed via its public helpers
    or directly from tests.  Not thread-safe — one store per agent instance.
    """

    def __init__(self) -> None:
        # First-order: global reputation (broadcast signal)
        self.reputation: dict[str, float] = {}

        # Second-order: time-decayed dyadic trust (private, directional)
        self.trust_matrix: dict[str, dict[str, float]] = {}
        self.round_clock: int = 0

        # Behavioral: per-agent [invited, participated, tampered] counters
        self.behavior: dict[str, list[int]] = {}

        # Per-peer encounter counter (observer-local): how many outcomes this store
        # has processed involving each peer.  Drives the newcomer grace period — a
        # signal the observer genuinely maintains, unlike a peer's own participation
        # count which lives only in the peer's own store.
        self.peer_encounters: dict[str, int] = {}

        # Epistemic: past semantic embeddings per agent (for position_stability)
        self.past_semantics: dict[str, list[list[float]]] = {}

        # Coalition memory: sorted (min, max) pair → co-commit count
        # Leifeld & Brandenberger 2024 — bonding mechanism
        self.co_commit_ledger: dict[tuple[str, str], int] = {}

        # Per-axis trust overlay — falls back to scalar trust when unset.
        self.axis_trust: dict[str, dict[str, dict[str, float]]] = {}

        # ── Adaptive protocol parameters (Layer 1 / 2 / 3) ───────────────────

        # Layer 1: per-dyad last-interaction round (for silence-penalty decay)
        self.last_interaction: dict[tuple[str, str], int] = {}

        # Layer 2: current learnable scalar protocol parameters
        self.base_epsilon: float = 0.15
        self.threshold: float = 0.60

        # Layer 2 history buffers (rolling, capped at 200 entries)
        self.similarity_history: list[float] = []
        self.consensus_type_history: list[str] = []

        # Layer 3: axis weights on simplex (learnable, slow)
        self.axis_weights: dict[str, float] = dict(_DEFAULT_AXIS_WEIGHTS)

    # ── Reputation ────────────────────────────────────────────────────────────

    def get_rep(self, agent_id: str) -> float:
        """Return reputation for *agent_id*, defaulting unknowns to _REPUTATION_INIT.

        The global reputation layer is a first-order, broadcast trust signal in the spirit
        of reputation / word-of-mouth trust (Abdul-Rahman & Hailes 2000, "Supporting Trust in
        Virtual Communities," HICSS-33; see REFERENCES.md) — every honest node accrues the
        same ±deltas from the same committed outcomes.  We adapt it as the replicated,
        outcome-derived signal (distinct from the private, directional dyadic trust below).

        Deliberately does NOT elevate newcomers to the network median.  The low
        starting reputation is the *mechanism* behind Byzantine centroid dampening
        (see test_byzantine_centroid_weight_dampened): a new agent — honest or
        Byzantine — has centroid weight ``rep(=1.0) × trust`` far below an
        established veteran's ``rep(≫1) × trust``, so it cannot capture the
        centroid before it has earned reputation through committed rounds.
        Newcomer *isolation* is mitigated separately and safely via the trust
        grace period (:meth:`_is_newcomer`), which never inflates a stranger's
        pre-detection influence.
        """
        return self.reputation.get(agent_id, _REPUTATION_INIT)

    def update_rep(self, agent_id: str, delta: float) -> None:
        current = self.get_rep(agent_id)
        self.reputation[agent_id] = builtins.round(max(current + delta, 0.01), 4)

    def _is_newcomer(self, agent_id: str) -> bool:
        """True if this store has encountered *agent_id* in ≤ grace-many outcomes.

        Keyed on the observer-local ``peer_encounters`` counter — a signal this
        store actually maintains — so the grace period works in real distributed
        flows where a peer's own participation count is not visible here.
        """
        return self.peer_encounters.get(agent_id, 0) < _NEWCOMER_GRACE_ROUNDS

    # ── Scalar dyadic trust ───────────────────────────────────────────────────

    def get_trust(self, source: str, target: str) -> float:
        return self.trust_matrix.get(source, {}).get(target, _TRUST_INIT)

    def set_trust(self, source: str, target: str, value: float) -> None:
        self.trust_matrix.setdefault(source, {})[target] = builtins.round(max(value, 0.01), 4)

    def dyad_decay(self, source: str, target: str) -> float:
        """Per-dyad adaptive trust decay (Arena et al. 2023; Mohseni & Bernstein 2022).

        High-frequency pairs decay slowly (established memory).
        Long-silent pairs decay faster (stale trust is noise).

        Returns a decay factor in [0.80, 0.99].

        Example::

            d = store.dyad_decay("alice", "bob")
            # 0.92 for new pairs; closer to 0.85 after long silence
        """
        key = (min(source, target), max(source, target))
        co = self.co_commit_ledger.get(key, 0)
        last = self.last_interaction.get(key, self.round_clock)
        silence = max(self.round_clock - last, 0)

        # Silence lowers the retain factor (faster decay — stale trust is noise);
        # accumulated co-commits raise it (slower decay — established memory).
        silence_penalty = 0.015 * silence
        strength_buffer = 0.04 * min(co / 15.0, 1.0)
        d = _TRUST_DECAY - silence_penalty + strength_buffer
        return builtins.round(float(max(min(d, 0.99), 0.80)), 4)

    def dyad_trust_params(self, source: str, target: str) -> tuple[float, float, float]:
        """Return (gain, loss, decay) for a dyad — all stability-guaranteed.

        Stability condition: gain < (1 − decay), enforced by construction.
        Loss:gain ratio ≈ 2.25 — the loss-aversion λ of Tversky & Kahneman (1992). This is the
        HIGH end of the literature range; Bleichrodt & L'Haridon (2023) estimate λ ≈ 1.25–1.45.
        We adopt the T&K value as a deliberately conservative negativity bias (see REFERENCES.md).
        Frequently-interacting dyads get smaller updates (den Boer et al. 2024).

        Example::

            gain, loss, decay = store.dyad_trust_params("alice", "bob")
            assert gain < (1 - decay)   # stability invariant
        """
        key = (min(source, target), max(source, target))
        co = self.co_commit_ledger.get(key, 0)
        decay = self.dyad_decay(source, target)
        available = 1.0 - decay  # ≤ 0.20
        freq_scale = 1.0 / (1.0 + co / 20.0)  # slows at maturity
        gain = builtins.round(available * 0.7 * freq_scale, 5)
        loss = builtins.round(gain * _LAMBDA_LOSS_AVERSION, 5)
        return gain, loss, decay

    def decay(self) -> None:
        """Apply one round of per-dyad adaptive exponential forgetting.

        Called automatically by ``apply_outcome()`` each round.  Per-dyad
        decay rates differ: established pairs (many co-commits) retain trust
        longer than silent pairs.

        Example::

            store = TrustStore()
            store.set_trust("alice", "bob", 1.5)
            store.decay()
            assert store.get_trust("alice", "bob") < 1.5
            assert store.round_clock == 1
        """
        for src, row in self.trust_matrix.items():
            for tgt in list(row):
                d = self.dyad_decay(src, tgt)
                row[tgt] = builtins.round(max(row[tgt] * d, 0.01), 4)
        for src, src_dict in self.axis_trust.items():
            for tgt, tgt_dict in src_dict.items():
                d = self.dyad_decay(src, tgt)
                for ax in tgt_dict:
                    tgt_dict[ax] = builtins.round(max(tgt_dict[ax] * d, 0.01), 4)
        self.round_clock += 1

    # ── Per-axis trust ────────────────────────────────────────────────────────

    def get_axis_trust(self, source: str, target: str, axis: str) -> float:
        """Return per-axis trust, falling back to scalar trust when unset."""
        return (
            self.axis_trust.get(source, {})
            .get(target, {})
            .get(axis, self.get_trust(source, target))
        )

    def update_axis_trust(self, source: str, target: str, axis: str, delta: float) -> None:
        """Apply signed delta to per-axis trust, clamped to [0.01, 2.0]."""
        current = self.get_axis_trust(source, target, axis)
        new_val = builtins.round(max(min(current + delta, 2.0), 0.01), 4)
        self.axis_trust.setdefault(source, {}).setdefault(target, {})[axis] = new_val

    # ── Adaptive per-dyad ε ───────────────────────────────────────────────────

    def get_epsilon(self, base_epsilon: float, a: str, b: str, axis: str = "semantic") -> float:
        """Per-dyad, per-axis bounded-confidence radius.

        Uses a sigmoid co-commit boost — adaptive confidence bounds per Li, Luo &
        Porter 2024 (arXiv:2303.07563); the sigmoid form is our choice — instead of the
        previous linear-capped formula.  Multiplied by a per-axis scale factor
        so affective updates are more open than epistemic ones (Li, Luo & Chu 2025).

        The ``base_epsilon`` argument is overridden by ``self.base_epsilon`` when
        the store has accumulated enough history (≥ 20 rounds), making deliberation
        aware of the Layer-2 learned value.

        Example::

            eps = store.get_epsilon(0.15, "alice", "bob", axis="affective")
            # ≈ 0.27 for established pair on affective axis
        """
        if base_epsilon <= 0:
            return 0.0
        # Use the store's learned base_epsilon once it's warm.
        eff_base = self.base_epsilon if len(self.consensus_type_history) >= 20 else base_epsilon
        key = (min(a, b), max(a, b))
        co = self.co_commit_ledger.get(key, 0)
        # Sigmoid boost: slow start, fast middle, saturation (Gompertz-inspired).
        max_boost = 0.25
        k, x0 = 0.35, 5.0
        boost = max_boost / (1.0 + math.exp(-k * (co - x0)))
        axis_mult = AXIS_EPSILON_MULTIPLIERS.get(axis, 1.0)
        result = (eff_base + boost) * axis_mult
        return builtins.round(float(max(min(result, 0.50), 0.05)), 4)

    # ── Coalition memory ──────────────────────────────────────────────────────

    def record_co_commit(self, agent_ids: list[str]) -> None:
        """Increment co-commit count and refresh last_interaction for every pair."""
        for a, b in itertools.combinations(sorted(agent_ids), 2):
            key = (a, b)
            self.co_commit_ledger[key] = self.co_commit_ledger.get(key, 0) + 1
            self.last_interaction[key] = self.round_clock

    def min_co_commits(self, agent_ids: list[str]) -> int:
        """Return the minimum co-commit count across all pairs in agent_ids."""
        import itertools as _it

        pairs = list(_it.combinations(agent_ids, 2))
        if not pairs:
            return 0
        return min(self.co_commit_ledger.get((min(a, b), max(a, b)), 0) for a, b in pairs)

    def median_co_commits(self, agent_ids: list[str]) -> int:
        """Return the median co-commit count across all pairs in agent_ids.

        Preferred over min_co_commits for the coalitional classifier because a single
        stranger pair (count 0) no longer vetoes all established alliances — the median is
        robust to such outliers.  For an even number of pairs this returns the upper of the
        two middle elements (``scores[len//2]``); note the coalitional gate is
        ``median >= _COALITION_THRESHOLD``, so the upper median is the slightly MORE
        PERMISSIVE tiebreak (a higher value clears the gate more easily, not less). We accept
        that: once at least half the pairs have real co-commit history, treating the round as
        coalition-driven is the intended reading.
        """
        import itertools as _it

        pairs = list(_it.combinations(agent_ids, 2))
        if not pairs:
            return 0
        scores = sorted(self.co_commit_ledger.get((min(a, b), max(a, b)), 0) for a, b in pairs)
        return scores[len(scores) // 2]

    # ── Behavioral tracking ───────────────────────────────────────────────────

    def get_behavior(self, agent_id: str) -> tuple[int, int, int]:
        """Return (invited, participated, tampered) counts."""
        return tuple(self.behavior.get(agent_id, [0, 0, 0]))  # type: ignore[return-value]

    def record_invitation(self, agent_id: str) -> None:
        """Increment the 'invited' counter — call from propose() for each invited agent."""
        b = self.behavior.setdefault(agent_id, [0, 0, 0])
        b[0] += 1  # invited

    def record_participation(self, agent_id: str) -> None:
        """Increment the 'participated' counter — call from participate()."""
        b = self.behavior.setdefault(agent_id, [0, 0, 0])
        b[1] += 1  # participated

    def record_tamper(self, agent_id: str) -> None:
        b = self.behavior.setdefault(agent_id, [0, 0, 0])
        b[2] += 1

    # ── Semantic history ──────────────────────────────────────────────────────

    def push_semantic(self, agent_id: str, embedding: list[float], max_history: int = 10) -> None:
        """Append embedding to semantic history, capping at max_history."""
        past = self.past_semantics.setdefault(agent_id, [])
        if len(past) >= max_history:
            past.pop(0)
        past.append(embedding)

    # ── Snapshot / restore ────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Return a deep-copy snapshot of all memory state.

        Use for simulation replay, A/B testing different deliberation
        parameters, or unit-test isolation.

        Example::

            snap = store.snapshot()
            # run some rounds …
            store.restore(snap)  # rewind to captured state
        """
        import copy

        return {
            "reputation": copy.deepcopy(self.reputation),
            "trust_matrix": copy.deepcopy(self.trust_matrix),
            "round_clock": self.round_clock,
            "behavior": copy.deepcopy(self.behavior),
            "peer_encounters": copy.deepcopy(self.peer_encounters),
            "past_semantics": copy.deepcopy(self.past_semantics),
            "co_commit_ledger": {f"{a},{b}": v for (a, b), v in self.co_commit_ledger.items()},
            "axis_trust": copy.deepcopy(self.axis_trust),
            # Adaptive parameters
            "last_interaction": {f"{a},{b}": v for (a, b), v in self.last_interaction.items()},
            "base_epsilon": self.base_epsilon,
            "threshold": self.threshold,
            "similarity_history": list(self.similarity_history),
            "consensus_type_history": list(self.consensus_type_history),
            "axis_weights": dict(self.axis_weights),
        }

    def restore(self, snap: dict[str, Any]) -> None:
        """Restore memory state from a snapshot produced by :meth:`snapshot`.

        Example::

            store.restore(snap)
            assert store.round_clock == snap["round_clock"]
        """
        import copy

        self.reputation = copy.deepcopy(snap["reputation"])
        self.trust_matrix = copy.deepcopy(snap["trust_matrix"])
        self.round_clock = snap["round_clock"]
        self.behavior = copy.deepcopy(snap["behavior"])
        self.peer_encounters = copy.deepcopy(snap.get("peer_encounters", {}))
        self.past_semantics = copy.deepcopy(snap["past_semantics"])
        self.co_commit_ledger = {
            tuple(k.split(",", 1)): v  # type: ignore[misc]
            for k, v in snap.get("co_commit_ledger", {}).items()
        }
        self.axis_trust = copy.deepcopy(snap.get("axis_trust", {}))
        self.last_interaction = {
            tuple(k.split(",", 1)): v  # type: ignore[misc]
            for k, v in snap.get("last_interaction", {}).items()
        }
        self.base_epsilon = snap.get("base_epsilon", 0.15)
        self.threshold = snap.get("threshold", 0.60)
        self.similarity_history = list(snap.get("similarity_history", []))
        self.consensus_type_history = list(snap.get("consensus_type_history", []))
        self.axis_weights = dict(
            snap.get(
                "axis_weights",
                {
                    "semantic": 0.25,
                    "affective": 0.20,
                    "relational": 0.25,
                    "epistemic": 0.15,
                    "behavioral": 0.15,
                },
            )
        )

    # ── Adaptive parameter updates (Layer 2 / Layer 3) ───────────────────────

    def record_round_outcome(
        self,
        consensus_type: str,
        pentadic_sims: list[float],
        n: int | None = None,
        f: int | None = None,
    ) -> None:
        """Append round outcome to history buffers and trigger epoch updates.

        Called by ResonanceBFT.commit() every round.  Triggers Layer-2 update
        every ``_EPOCH_SIZE`` rounds and Layer-3 update every
        ``_SLOW_EPOCH_SIZE`` rounds.  When ``n`` and ``f`` are supplied, the
        adaptive threshold is clamped to the BFT safety lower bound after each
        Layer-2 update so the learned threshold can never erode the safety margin.

        **Learning signal dependency (by design).** The Layer-3 axis-weight update
        is driven by the ``consensus_type`` quality label, which is only produced
        when :meth:`ResonanceBFT.deliberate` has run.  In flows that skip
        deliberation the label is ``"unknown"`` (quality score 0), so the adaptive
        layer makes *no* update — it never trains on rounds whose quality it did not
        actually measure, rather than fabricating a signal.

        **Timescale note.** ``_EPOCH_SIZE`` (50) and ``_SLOW_EPOCH_SIZE`` (200) are
        long-horizon by design: Layers 2/3 are dormant in short scenarios (e.g. the
        5-round graded runs) and engage only over long simulations.  Their
        invariants (simplex, stability, BFT lower bound) are verified in isolation
        by the property tests rather than via the short scenarios.

        Example::

            store.record_round_outcome("genuine", [0.82, 0.79, 0.76], n=7, f=2)
            # after 50 calls, threshold and base_epsilon auto-adjust (and stay BFT-safe)
        """
        self.consensus_type_history.append(consensus_type)
        self.similarity_history.extend(pentadic_sims)
        # Cap buffers at 400 entries to bound memory.
        if len(self.consensus_type_history) > 400:
            self.consensus_type_history = self.consensus_type_history[-400:]
        if len(self.similarity_history) > 400:
            self.similarity_history = self.similarity_history[-400:]

        if self.round_clock > 0 and self.round_clock % _EPOCH_SIZE == 0:
            self._update_layer2()
            # Enforce the BFT safety floor on the freshly-updated threshold.
            if n is not None and f is not None:
                self.clamp_threshold(n, f)
        if self.round_clock > 0 and self.round_clock % _SLOW_EPOCH_SIZE == 0:
            self._update_layer3()

    def _update_layer2(self) -> None:
        """Layer-2 epoch update: base_epsilon and similarity threshold.

        Two complementary signals inform base_epsilon:
        1. Trajectory signal — deadlock/polarized → ε too tight; coalitional/capitulated → ε too
           loose.
        2. Similarity signal — if median pairwise similarity is persistently low (< 0.50) across the
           epoch, agents are not converging; raise ε to widen their Deffuant neighborhoods.

        threshold calibration:
          Rises when capitulated/coerced rate > 10% (false-quorum pressure).
          Falls when false-rejection evidence is detected (frag > 20%, false_q < 2%).
        """
        window = self.consensus_type_history[-_EPOCH_SIZE:]
        if not window:
            return
        n = len(window)

        # ── epsilon calibration — trajectory signal ──
        frag = sum(1 for t in window if t in ("deadlock", "polarized")) / n
        homo = sum(1 for t in window if t in ("coalitional", "capitulated")) / n
        if frag > 0.35:
            self.base_epsilon = builtins.round(min(self.base_epsilon + _EPS_STEP, 0.50), 3)
        elif homo > 0.40:
            self.base_epsilon = builtins.round(max(self.base_epsilon - _EPS_STEP, 0.05), 3)

        # ── epsilon calibration — similarity signal ──
        sim_window = self.similarity_history[-_EPOCH_SIZE * 5 :]  # ~5 sims per round
        if sim_window:
            sorted_sims = sorted(sim_window)
            median_sim = sorted_sims[len(sorted_sims) // 2]
            if median_sim < 0.50 and frag <= 0.35 and homo <= 0.40:
                # Low similarity, no deadlock pressure, no homogeneity pressure → nudge up.
                # Guard against homo > 0.40 to avoid fighting the decrease signal above.
                self.base_epsilon = builtins.round(min(self.base_epsilon + _EPS_STEP, 0.50), 3)

        # ── threshold calibration ──
        false_q = sum(1 for t in window if t in ("capitulated", "coerced")) / n
        if false_q > 0.10:
            self.threshold = builtins.round(min(self.threshold + _THETA_STEP, 0.85), 3)
        elif false_q < 0.02 and frag > 0.20:
            self.threshold = builtins.round(max(self.threshold - _THETA_STEP, 0.40), 3)

    def _update_layer3(self) -> None:
        """Layer-3 slow-epoch update: axis_weights via Exponentiated Gradient.

        Implements the Exponentiated Gradient (EG) algorithm of Kivinen & Warmuth (1997,
        *Information and Computation* 132(1); see REFERENCES.md): a multiplicative,
        simplex-constrained weight update ``w ← w · exp(−η·grad)`` followed by
        renormalisation — the natural learner for weights that must stay positive and sum
        to 1.  Learning objective: weights that best predict genuine consensus.  Genuinely-
        aligned axes are reinforced on good rounds; axes that showed high alignment on bad
        rounds are penalised.  The update is purely from self-observed signals — no gossip.
        """
        window_types = self.consensus_type_history[-_SLOW_EPOCH_SIZE:]
        if len(window_types) < 20:
            return

        # Compute mean quality signal over window.
        quality = builtins.round(
            sum(_CT_SCORES.get(t, 0.0) for t in window_types) / len(window_types), 4
        )
        if abs(quality) < 0.05:
            return  # not enough signal — skip

        axes = list(self.axis_weights.keys())
        w = [self.axis_weights[a] for a in axes]

        # EG loss gradient: we want to DECREASE loss, so:
        #   good rounds (quality>0) → reinforce current w → grow wi>uniform
        #     ⟹ loss gradient must be negative for wi>uniform ⟹ grad = -quality*(wi-uniform)
        #   bad rounds (quality<0) → push toward uniform → shrink wi>uniform
        #     ⟹ loss gradient must be positive for wi>uniform ⟹ grad = -quality*(wi-uniform)
        #       (same formula, quality<0 reverses sign)
        # Both cases: grad = -quality * (wi - uniform)
        uniform = 1.0 / len(axes)
        grad = [-quality * (wi - uniform) for wi in w]

        # Exponentiated Gradient update on simplex.
        lr = _AW_LR if quality > 0 else _AW_LR * _AW_LOSS_BIAS
        w_new = [wi * math.exp(-lr * g) for wi, g in zip(w, grad, strict=True)]
        # Normalize to the simplex, THEN enforce the per-axis floor on the FINAL weights.
        # (Flooring before normalizing does not guarantee the floor survives the divide —
        # a floored weight can drop back below _AW_MIN once the others are large.)  We lift
        # any sub-floor weight to _AW_MIN and remove the resulting excess from the
        # above-floor weights in proportion to their slack, so every final weight is
        # >= _AW_MIN and the vector still sums to 1.  With 5 axes and _AW_MIN=0.05 the floor
        # mass is at most 0.25, so there is always slack to absorb it.
        total = sum(w_new) or 1.0
        normed = [wi / total for wi in w_new]
        floored = [max(wi, _AW_MIN) for wi in normed]
        excess = sum(floored) - 1.0
        slack = sum(wi - _AW_MIN for wi in floored if wi > _AW_MIN) or 1.0
        adjusted = [wi - excess * (wi - _AW_MIN) / slack if wi > _AW_MIN else wi for wi in floored]
        w_new = [builtins.round(max(wi, _AW_MIN), 5) for wi in adjusted]

        self.axis_weights = dict(zip(axes, w_new, strict=True))

    def bft_safety_lower_bound(self, n: int, f: int) -> float:
        """Theoretical minimum threshold for BFT-safe quorum intersection.

        The bound ``1 − 2f/(n−f)`` is OUR OWN derivation (from the n−f quorum-intersection
        requirement of Lamport, Shostak & Pease 1982); we cite the approximate-agreement /
        Byzantine-collaborative-learning line (Cambus et al. 2025, arXiv:2504.01504) only as
        *context* for adaptive agreement thresholds, NOT as the source of this formula — see
        the honest note at that entry in REFERENCES.md.  The adaptive threshold must never
        fall below this value.

        Example::

            lb = store.bft_safety_lower_bound(n=7, f=2)
            assert store.threshold >= lb
        """
        if n <= 3 * f:
            return 0.0  # BFT is already impossible; don't compound the error
        return builtins.round(max(0.0, 1.0 - 2.0 * f / (n - f)), 4)

    def clamp_threshold(self, n: int, f: int) -> None:
        """Ensure threshold ≥ BFT safety lower bound for current n, f.

        Called after each Layer-2 update to prevent the adaptive system
        from eroding the BFT safety margin.

        Example::

            store = TrustStore()
            store.threshold = 0.10  # artificially low
            store.clamp_threshold(n=7, f=2)
            assert store.threshold >= store.bft_safety_lower_bound(n=7, f=2)
        """
        lb = self.bft_safety_lower_bound(n, f)
        if self.threshold < lb:
            self.threshold = lb

    # ── Batch commit updates ──────────────────────────────────────────────────

    def apply_outcome(
        self,
        me: str,
        *,
        status: str,
        quorum_agents: list[str],
        outlier_agents: list[str],
        tampered_agents: list[str],
        axis_contributors: dict[str, list[str]] | None = None,
    ) -> None:
        """Apply all memory updates for one committed/aborted outcome.

        Called by ResonanceBFT.commit() — pulls the update logic here so the
        protocol class stays thin.
        """
        axis_contributors = axis_contributors or {}

        self.decay()

        # The caller folds tampered agents into outlier_agents for its quorum
        # accounting, so the two lists overlap.  Deduplicate (order-preserving) before
        # applying penalties — otherwise a tamperer that appears in BOTH lists would
        # take every reputation/trust/axis loss twice.  Membership in tampered_agents is
        # still tested separately below (it overrides the newcomer grace period), so the
        # dedup is safe.
        penalised = list(dict.fromkeys(outlier_agents + tampered_agents))

        # On a NON-committed round (partition / liveness abort), honest agents that simply
        # ended up below the quorum bar must NOT be penalised — the round failed for lack of
        # a quorum, not because they misbehaved.  Only provable misbehaviour (tampering) is
        # penalised regardless of outcome.  On a committed round, all outliers are penalised.
        if status == "committed":
            to_penalise = penalised
        else:
            to_penalise = [aid for aid in penalised if aid in tampered_agents]

        # Reputation (global broadcast signal — no grace period)
        if status == "committed":
            for aid in quorum_agents:
                self.update_rep(aid, _REPUTATION_GAIN)
        for aid in to_penalise:
            self.update_rep(aid, -_REPUTATION_LOSS)

        # Scalar trust — use per-dyad adaptive gain/loss
        if status == "committed":
            for other in quorum_agents:
                if other != me:
                    gain, _loss, _ = self.dyad_trust_params(me, other)
                    self.set_trust(me, other, self.get_trust(me, other) + gain)
        for other in to_penalise:
            # Newcomer grace period: for the first _NEWCOMER_GRACE_ROUNDS outcomes
            # this observer has seen *other* in, no LOCAL trust penalty is applied
            # (the cascade risk for cold-start agents).  Reputation is always updated
            # (global, observable); trust is private and slow to recover, so we protect
            # newcomers here specifically.  Tampered agents are penalised regardless of
            # newness — deliberate tampering is not innocent divergence.
            if other != me and (other in tampered_agents or not self._is_newcomer(other)):
                _gain, loss, _ = self.dyad_trust_params(me, other)
                self.set_trust(me, other, self.get_trust(me, other) - loss)

        # Per-axis trust — same adaptive params
        if status == "committed":
            for other in quorum_agents:
                if other != me:
                    gain, loss, _ = self.dyad_trust_params(me, other)
                    for axis in _AXES:
                        ax_gain = gain * (1.3 if other in axis_contributors.get(axis, []) else 1.0)
                        self.update_axis_trust(me, other, axis, ax_gain)
        for other in to_penalise:
            # Same newcomer grace as scalar trust: protect a fresh peer's per-axis
            # trust during the grace window so the two stay consistent (tampered
            # agents are always penalised).
            if other != me and (other in tampered_agents or not self._is_newcomer(other)):
                _gain, loss, _ = self.dyad_trust_params(me, other)
                for axis in _AXES:
                    self.update_axis_trust(me, other, axis, -loss)

        # Behavioral: mark tamperers
        for aid in tampered_agents:
            self.record_tamper(aid)

        # Coalition memory (also refreshes last_interaction timestamps)
        if status == "committed" and len(quorum_agents) >= 2:
            self.record_co_commit(quorum_agents)

        # Bump per-peer encounter counter AFTER the grace check above, so the first
        # _NEWCOMER_GRACE_ROUNDS outcomes involving each peer are genuinely protected.
        for aid in set(quorum_agents) | set(outlier_agents) | set(tampered_agents):
            if aid != me:
                self.peer_encounters[aid] = self.peer_encounters.get(aid, 0) + 1
