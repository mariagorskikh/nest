# SPDX-License-Identifier: Apache-2.0
"""Trajectory classification and conflict analysis.

Pure functions — no protocol state, no I/O.  All inputs are plain data so
these can be unit-tested without spinning up a ResonanceBFT instance.
"""

from __future__ import annotations

import builtins
import math
from typing import Any

from ._types import ConsensusTrajectory, ConsensusType
from ._vectors import _cosine, _mean_pairwise_distance, _mean_vec

__all__ = [
    "_COALITION_THRESHOLD",
    "_classify_trajectory",
    "_compute_conflict_report",
    "_detect_axis_polarization",
    "consensus_quality_metrics",
]


def consensus_quality_metrics(
    traj: ConsensusTrajectory,
    *,
    move_eps: float = 0.02,
    pressure_delta: float = 0.005,
) -> dict[str, float]:
    """Audit a deliberation for GENUINE vs SUPERFICIAL consensus, from its trajectory.

    Three verified-literature-grounded scalars (each in [0, 1]; see REFERENCES.md):

    - ``independence_rate`` — fraction of agents that essentially HELD their position
      (total movement < ``move_eps``).  The independence side of the conformity/independence
      pair of Weng, Chen & Wang (2025, BenchForm, arXiv:2501.13381): high = independent
      thinkers, low = everyone conformed.
    - ``capitulation_rate`` — fraction of agents that MOVED significantly while their
      peer-relative epistemic pull was NEGATIVE (toward less-confident peers), i.e. conceded
      under social pressure rather than evidence.  This is the confidence-weighted
      persuasion-without-evidence idea of Agarwal & Khanna (2025, CW-POR, arXiv:2504.00374),
      read off our own ``evidence_delta`` signal.
    - ``disagreement_collapse`` — how much the group's spread shrank over the deliberation
      (``1 − final_spread/initial_spread``).  High collapse with low evidence is the
      premature-homogenisation / sycophantic "disagreement collapse" of Yao et al. (2025,
      "Peacemaker or Troublemaker," arXiv:2509.23055) and the consensus–diversity tradeoff
      of Wu & Ito (2025).

    These COMPLEMENT (do not replace) the per-agent ``sycophancy`` score and the
    ``consensus_type`` label; together they form the genuine-vs-superficial audit that, per
    our literature survey, no prior consensus system pairs with a BFT commit.  Computed from
    the (trust-free, resolver-independent) auto-deliberation trajectory, so the reported
    metrics are themselves resolver-independent.
    """
    steps = traj.steps
    if len(steps) < 2:
        return {"independence_rate": 1.0, "capitulation_rate": 0.0, "disagreement_collapse": 0.0}
    initial, final = steps[0], steps[-1]
    agents = list(initial.keys())
    n = len(agents) or 1

    def _euclid(a: list[float], b: list[float]) -> float:
        m = max(len(a), len(b))
        a = a + [0.0] * (m - len(a))
        b = b + [0.0] * (m - len(b))
        return sum((x - y) ** 2 for x, y in zip(a, b, strict=True)) ** 0.5

    def _mean_ed(aid: str) -> float:
        ed = traj.evidence_delta.get(aid, [])
        return sum(ed) / len(ed) if ed else 0.0

    move = {a: _euclid(final.get(a, initial[a]), initial[a]) for a in agents}
    independent = sum(1 for a in agents if move[a] < move_eps)
    capitulated = sum(1 for a in agents if move[a] >= move_eps and _mean_ed(a) < -pressure_delta)
    init_spread = _mean_pairwise_distance(initial)
    final_spread = _mean_pairwise_distance(final)
    collapse = 0.0 if init_spread < 1e-9 else max(0.0, min(1.0, 1.0 - final_spread / init_spread))
    return {
        "independence_rate": builtins.round(independent / n, 4),
        "capitulation_rate": builtins.round(capitulated / n, 4),
        "disagreement_collapse": builtins.round(collapse, 4),
    }


# ── Constants ─────────────────────────────────────────────────────────────────

_COALITION_THRESHOLD = 3  # min co-commits to activate coalition shortcut


# ── Trajectory classification ─────────────────────────────────────────────────


def _classify_trajectory(
    traj: ConsensusTrajectory,
    threshold: float,
    final_sim: float,
    min_co_commits: int = 0,
) -> ConsensusType:
    """Derive consensus type from trajectory statistics.

    Uses five signals:
    - velocities: convergence direction/speed
    - concession_symmetry: who moved how much
    - axis_deltas: which axes drove movement (logrolling detection)
    - evidence_delta: did epistemic confidence rise or fall while moving?
      Positive = persuaded; negative = pressured (Agarwal & Khanna 2025, arXiv:2504.00374).
    - min_co_commits: minimum prior co-commits among active agent pairs.
      High value + low evidence_delta → coalitional (alliance shortcut, not persuasion).
      Grounds: Leifeld & Brandenberger 2024 bonding mechanism.
    """
    if len(traj.steps) < 2:
        return "unknown"

    vels = traj.velocities
    sym = traj.concession_symmetry

    # Compute mean epistemic confidence change across all agents and steps
    all_ep = [d for deltas in traj.evidence_delta.values() for d in deltas]
    mean_ep_delta = sum(all_ep) / len(all_ep) if all_ep else 0.0

    depth = final_sim - threshold

    # Deadlock: no movement AND not already in agreement. Agents that are already
    # aligned above threshold (depth > 0) have near-zero velocity because they are
    # genuinely converged — that is consensus, not a failed deadlock.
    if all(abs(v) < 0.005 for v in vels):
        return "genuine" if depth > 0 else "deadlock"

    # Polarized: velocity consistently positive (agents moving apart)
    if all(v > 0 for v in vels):
        return "polarized"

    converging = vels[-1] < 0  # still converging at last step

    if not converging and depth < 0:
        return "polarized"

    # "Fast convergence" = the group settled within a couple of steps and then went quiet,
    # regardless of how many total steps the CALLER chose to run.  Counting the steps with
    # real movement (|v| ≥ 0.005) makes the coalitional/coerced labels independent of the
    # `steps` argument — the earlier `len(vels) <= 2` test made both unreachable whenever a
    # caller passed steps ≥ 3 (e.g. the demo's steps=3), classifying genuinely fast
    # alliance/coercion dynamics as something else.
    active_steps = sum(1 for v in vels if abs(v) >= 0.005)

    # Coalitional: fast convergence driven by alliance memory, not current persuasion.
    # Requires: prior co-commit history above threshold AND low evidence_delta
    # (meaning agents moved together quickly without being newly persuaded — they
    # already trust each other from past rounds). Leifeld & Brandenberger 2024 bonding.
    if (
        min_co_commits >= _COALITION_THRESHOLD
        and active_steps <= 2
        and abs(mean_ep_delta) < 0.01
        and depth > 0
    ):
        return "coalitional"

    # Logrolled: axis deltas show opposite-sign movement across dimensions
    axis_d = traj.axis_deltas
    if axis_d:
        net_signs: list[int] = []
        for deltas in axis_d.values():
            net = sum(deltas)
            net_signs.append(1 if net > 0.01 else (-1 if net < -0.01 else 0))
        if len(set(net_signs)) > 1 and 1 in net_signs and -1 in net_signs:
            return "logrolled"

    # Coerced: converging but concession extremely asymmetric AND fast.
    # Override: rising epistemic confidence means persuasion, not coercion.
    if sym < 0.15 and active_steps <= 2 and mean_ep_delta <= 0.02:
        return "coerced"

    # Capitulated: one-sided movement.
    # But override: if epistemic confidence rose while moving, the minority
    # was genuinely persuaded even if it moved more (Agarwal & Khanna 2025, arXiv:2504.00374).
    if sym < 0.20:
        if mean_ep_delta > 0.02 and depth > 0:
            return (
                "genuine"  # asymmetric movement but evidence-driven — persuasion, not capitulation
            )
        elif mean_ep_delta <= 0.02:
            return "capitulated"

    # Fragile: threshold barely met
    if 0 < depth < 0.05:
        return "fragile"

    # Genuine: bilateral, deep, converging.
    # Override: if epistemic confidence fell while converging, the movement
    # was driven by pressure not persuasion → capitulated regardless of symmetry.
    if sym >= 0.40 and depth > 0:
        if mean_ep_delta < -0.02:
            return "capitulated"
        return "genuine"

    return "fragile"


# ── Conflict analysis ─────────────────────────────────────────────────────────


def _detect_axis_polarization(
    evaluations: dict[str, Any],
    axis: str,
    axis_slice: tuple[int, int],
) -> dict[str, Any] | None:
    """Detect whether agents have split into two opposing clusters on one axis.

    Uses the sign of the mean vector projection to partition agents.  Returns
    a polarization report if the two clusters have negative inter-cluster
    cosine similarity, otherwise None.

    Returns
    -------
    dict with keys: axis, cluster_a, cluster_b, inter_cluster_sim, centroids
    or None if no polarization is detected.
    """
    s, e = axis_slice
    vecs: dict[str, list[float]] = {}
    for aid, rec in evaluations.items():
        combined = rec.get("combined", [])
        if e <= len(combined):
            vecs[aid] = combined[s:e]

    if len(vecs) < 4:
        return None

    global_mean = _mean_vec(list(vecs.values()))
    if not global_mean or all(v == 0 for v in global_mean):
        # Degenerate mean: two perfectly balanced opposing clusters cancel out, which is
        # the STRONGEST polarization, not the absence of it.  Split on a deterministic
        # reference instead — the highest-norm agent vector (ties broken by sorted aid) —
        # so we still detect the deadlock rather than silently returning None.
        ranked = sorted(vecs.items(), key=lambda kv: math.sqrt(sum(x * x for x in kv[1])))
        reference = ranked[-1][1]  # highest-norm vector (vecs has ≥ 4 entries here)
        if all(v == 0 for v in reference):
            return None
        global_mean = reference

    cluster_a = [aid for aid, v in vecs.items() if _cosine(v, global_mean) >= 0]
    cluster_b = [aid for aid, v in vecs.items() if _cosine(v, global_mean) < 0]

    if not cluster_a or not cluster_b:
        return None

    cent_a = _mean_vec([vecs[aid] for aid in cluster_a])
    cent_b = _mean_vec([vecs[aid] for aid in cluster_b])
    inter_sim = _cosine(cent_a, cent_b)

    if inter_sim > -0.1:
        return None

    return {
        "axis": axis,
        "cluster_a": cluster_a,
        "cluster_b": cluster_b,
        "inter_cluster_sim": builtins.round(inter_sim, 4),
        "centroid_a": [builtins.round(v, 4) for v in cent_a],
        "centroid_b": [builtins.round(v, 4) for v in cent_b],
    }


def _compute_conflict_report(
    evaluations: dict[str, Any],
    per_axis: dict[str, dict[str, float]],
    vocab_len: int,
    threshold: float,
) -> dict[str, Any]:
    """Analyse per-axis agreement and detect structural conflict patterns.

    Returns a conflict report attached to the outcome metadata.  The report
    distinguishes three situations that a simple committed/aborted status
    cannot express:

    * **partial_consensus** — some axes are above threshold, others are not.
    * **axis_deadlock** — one or more axes show genuine polarization.
    * **persistent_dissent** — a minority of agents is below threshold on
      every axis simultaneously.
    """
    n_agents = len(evaluations)
    axes = ["semantic", "affective", "relational", "epistemic", "behavioral"]

    axis_agreement: dict[str, float] = {}
    agreed_axes: list[str] = []
    disagreed_axes: list[str] = []
    for ax in axes:
        above = sum(1 for aid in per_axis if per_axis[aid].get(ax, 0.0) >= threshold)
        rate = above / n_agents if n_agents else 0.0
        axis_agreement[ax] = builtins.round(rate, 3)
        if rate >= 0.5:
            agreed_axes.append(ax)
        else:
            disagreed_axes.append(ax)

    n_rel = n_agents
    axis_slices: dict[str, tuple[int, int]] = {
        "semantic": (0, vocab_len),
        "affective": (vocab_len, vocab_len + 2),
        "relational": (vocab_len + 2, vocab_len + 2 + n_rel),
        "epistemic": (vocab_len + 2 + n_rel, vocab_len + 2 + n_rel + 2),
        "behavioral": (vocab_len + 2 + n_rel + 2, vocab_len + 2 + n_rel + 4),
    }

    deadlocked_axes: list[dict[str, Any]] = []
    for ax in disagreed_axes:
        report = _detect_axis_polarization(evaluations, ax, axis_slices[ax])
        if report is not None:
            deadlocked_axes.append(report)

    persistent_dissenters: list[str] = []
    for aid in per_axis:
        if all(per_axis[aid].get(ax, 0.0) < threshold for ax in axes):
            persistent_dissenters.append(aid)

    if deadlocked_axes:
        conflict_type = "axis_deadlock"
    elif agreed_axes and disagreed_axes:
        conflict_type = "partial_consensus"
    elif persistent_dissenters:
        conflict_type = "persistent_dissent"
    else:
        conflict_type = "none"

    return {
        "conflict_type": conflict_type,
        "axis_agreement": axis_agreement,
        "agreed_axes": agreed_axes,
        "disagreed_axes": disagreed_axes,
        "deadlocked_axes": deadlocked_axes,
        "persistent_dissenters": persistent_dissenters,
    }
