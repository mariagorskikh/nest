# SPDX-License-Identifier: Apache-2.0
"""Public data types for ResonanceBFT.

Offer, ConsensusType, ConsensusTrajectory — all pure data, no behaviour.
Import from here or from the top-level package (both work).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# The nine labels are not a flat list — they answer one question ("was a reached
# agreement authentic?") and fall into four families, ordered from healthiest to
# most pathological.  This is the taxonomy the L2 authenticity layer assigns; it
# never changes the L1 commit certificate, only how the round is understood and
# (via L3) learned from.
#
#   AUTHENTIC   genuine                         — real mutual persuasion
#   PRESSURED   capitulated · coerced · fragile — agreement extracted, not earned
#   ALLIANCE    coalitional · logrolled         — driven by bonds/trades, not the merits
#   FAILED      deadlock · polarized            — no legitimate agreement formed
#   (unknown)                                   — deliberation not run; quality not measured
#
# See CONSENSUS_FAMILIES below for the machine-readable grouping.
ConsensusType = Literal[
    "genuine",  # AUTHENTIC  — bilateral convergence, deep basin, all axes together
    "capitulated",  # PRESSURED — one-sided: minority closed gap, majority held still
    "coerced",  # PRESSURED — convergence too fast relative to trust levels
    "fragile",  # PRESSURED — threshold met but near basin edge (perturbation → collapse)
    "coalitional",  # ALLIANCE  — fast convergence from alliance memory, not persuasion
    "logrolled",  # ALLIANCE  — axes move in opposite directions: cross-axis exchange
    "deadlock",  # FAILED    — no movement for ≥ 2 steps despite deliberation
    "polarized",  # FAILED    — two stable sub-clusters, inter-cluster gap widening
    "unknown",  # deliberation not run → quality not measured (L3 does not learn)
]

# Machine-readable family grouping (healthiest → most pathological). Lets callers
# and validators reason at the family level instead of memorising nine labels.
CONSENSUS_FAMILIES: dict[str, tuple[str, ...]] = {
    "authentic": ("genuine",),
    "pressured": ("capitulated", "coerced", "fragile"),
    "alliance": ("coalitional", "logrolled"),
    "failed": ("deadlock", "polarized"),
}


@dataclass
class Offer:
    """A multi-dimensional exchange proposal.

    An agent offers to move toward the centroid on certain axes (``give``)
    in exchange for others moving on different axes (``want``).  This models
    logrolling: "I concede on semantics if you concede on relational trust."

    Attributes
    ----------
    from_agent:
        The agent making the offer.
    round_id:
        The round this offer belongs to.
    give:
        Axes where this agent is willing to move toward the centroid.
        Values are the fraction of distance it will close (0.0–1.0).
    want:
        Axes where this agent expects the counterparty to move.
        Values are the minimum fraction of distance it expects them to close.
    expires_in:
        How many deliberation steps this offer remains valid.
    metadata:
        Arbitrary context (e.g. rationale text, strategic priority).
    """

    from_agent: Any  # AgentId — avoid circular import with nest_core
    round_id: str
    give: dict[str, float]  # axis → fraction of gap to close
    want: dict[str, float]  # axis → fraction expected from counterparty
    expires_in: int = 2
    metadata: dict[str, Any] = field(default_factory=lambda: {})


@dataclass
class ConsensusTrajectory:
    """Record of how agent positions evolved during deliberation.

    Attributes
    ----------
    steps:
        Per-step snapshots: list of {agent_id: pentadic_vec}.
    velocities:
        Mean pairwise distance change between consecutive steps.
        Positive = agents moving apart; negative = converging.
    axis_deltas:
        Per-axis mean absolute movement per step: {axis: [Δt0, Δt1, ...]}.
    concession_symmetry:
        Ratio of min/max total movement across agents.
        1.0 = perfectly symmetric; near 0 = one side barely moved.
    consensus_type:
        Classified outcome of the deliberation process.
    depth:
        Distance from the consensus boundary (threshold) to the final centroid
        similarity.  Positive = inside basin; negative = outside.
    evidence_delta:
        Per-agent per-step change in epistemic confidence (axis index 0).
        Positive = agent was persuaded; negative = agent was pressured.
        Operationalizes Agarwal & Khanna 2025 (arXiv:2504.00374) — persuasion overriding truth.
    """

    steps: list[dict[str, list[float]]] = field(default_factory=lambda: [])
    velocities: list[float] = field(default_factory=lambda: [])
    axis_deltas: dict[str, list[float]] = field(default_factory=lambda: {})
    concession_symmetry: float = 1.0
    consensus_type: ConsensusType = "unknown"
    depth: float = 0.0
    evidence_delta: dict[str, list[float]] = field(default_factory=lambda: {})
