# SPDX-License-Identifier: Apache-2.0
"""ResonanceBFT — Pentadic BFT consensus over five axes of agent alignment.

Thesis
======
Classical BFT asks one question — *did the nodes output identical bytes?* — and
in doing so conflates two things that come apart for **social, goal-directed
agents**: (1) *who counts as agreeing* (a safety question) and (2) *whether the
agreement is genuine* (a quality question — sycophancy, coercion, and alliances
all produce "agreement" that is not real consensus).

ResonanceBFT separates them, on one shared representation, with a learning loop —
and the whole design rests on a single load-bearing invariant:

    >>> the authenticity and adaptation layers NEVER alter the L1 commit
    >>> certificate (quorum = n − f). You get the social-science richness for
    >>> free, without weakening any BFT safety guarantee.

Layered architecture
=====================
::

    L0  REPRESENTATION        five axes — what / feel / trust / sure / integrity
        (_vectors.py)         the single state space everything operates on
              │
       ┌──────┴───────────────────────────────┐
       ▼                                       ▼
    L1  SAFETY (sacred)                     L2  AUTHENTICITY (the contribution)
        (_protocol.resolve)                     (_trajectory, deliberate)
        quorum = n − f          ── never ──►    genuine / pressured / alliance /
        weighted pentadic sim      altered      failed   (see CONSENSUS_FAMILIES)
        tamper-evidence seal       by L2         + sycophancy / evidence_delta
              │ commit certificate                       │ quality label
              └─────────────────┬─────────────────────────┘
                                ▼
    L3  ADAPTATION (3 timescales, _trust.py): learn the *instruments* from the
        quality labels — per-round trust/ε · per-epoch threshold/base-ε · slow
        axis-weights (Exponentiated Gradient).  Tuned params feed back only into
        L2 deliberation — NEVER the L1 commit, which uses fixed threshold/weights.
        (Long-horizon: dormant in short scenarios; invariants property-tested.)

    cross-cutting ROBUSTNESS: Byzantine centroid dampening · cold-start grace ·
                              Sybil guard  — protect L0/L1 at the edges.

Reading guide: each module names the layer it implements; the seams
(`resolve`, `deliberate`, `record_round_outcome`) carry a comment stating which
layer they are and how they connect to the ones above and below.

Package layout
--------------
_vectors.py    L0 — pure vector functions (tokenise, embed, affective, epistemic, …)
_types.py      data types: Offer, ConsensusType, ConsensusTrajectory, CONSENSUS_FAMILIES
_trajectory.py L2 — trajectory classification (authenticity) and conflict analysis
_trust.py      L3 + memory — TrustStore (scalar + per-axis trust, coalition, adaptive params)
_protocol.py   L1 + orchestration — ResonanceBFT coordination class

All public symbols are re-exported here so existing code using::

    from nest_plugins_reference.coordination.resonance_bft import ResonanceBFT, Offer

continues to work without any changes.
"""

from __future__ import annotations

from ._protocol import ResonanceBFT
from ._trajectory import (
    _COALITION_THRESHOLD,
    _classify_trajectory,
    _compute_conflict_report,
    _detect_axis_polarization,
)
from ._trust import (
    _DEFAULT_AXIS_WEIGHTS as _AXIS_WEIGHTS,  # canonical seed; re-exported for back-compat
)
from ._trust import (
    _EPSILON_CO_COMMIT_BOOST,
    _EPSILON_CO_COMMIT_CAP,
    _TRUST_DECAY,
    _TRUST_GAIN,
    _TRUST_LOSS,
    AXIS_EPSILON_MULTIPLIERS,
    TrustStore,
)
from ._types import CONSENSUS_FAMILIES, ConsensusTrajectory, ConsensusType, Offer
from ._vectors import (
    _affective,
    _behavioral,
    _commitment,
    _cosine,
    _embed,
    _epistemic,
    _lerp_vec,
    _mean_pairwise_distance,
    _mean_vec,
    _normalise,
    _relational_vec,
    _tokenise,
    _weighted_centroid,
    pentadic_summary,
    sycophancy_score,
)

__all__ = [
    # Main class
    "ResonanceBFT",
    "_AXIS_WEIGHTS",
    # Memory layer
    "TrustStore",
    # Data types
    "Offer",
    "ConsensusType",
    "ConsensusTrajectory",
    "CONSENSUS_FAMILIES",
    # Vector functions
    "_tokenise",
    "_embed",
    "_normalise",
    "_cosine",
    "_mean_vec",
    "_weighted_centroid",
    "sycophancy_score",
    "pentadic_summary",
    "_lerp_vec",
    "_mean_pairwise_distance",
    "_affective",
    "_epistemic",
    "_behavioral",
    "_relational_vec",
    "_commitment",
    # Trajectory functions
    "_classify_trajectory",
    "_detect_axis_polarization",
    "_compute_conflict_report",
    "_COALITION_THRESHOLD",
    # Adaptive learning
    "AXIS_EPSILON_MULTIPLIERS",
    # Trust constants
    "_TRUST_DECAY",
    "_TRUST_GAIN",
    "_TRUST_LOSS",
    "_EPSILON_CO_COMMIT_BOOST",
    "_EPSILON_CO_COMMIT_CAP",
]
