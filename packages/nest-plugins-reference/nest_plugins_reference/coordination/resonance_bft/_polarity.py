# SPDX-License-Identifier: Apache-2.0
"""Antonym-anchored linear polarity probe — a signed stance signal for consensus.

Why this module exists
----------------------
Cosine over a single semantic vector *conflates topic identity with stance*:
"approve the proposal" and "reject the proposal" score ≈0.8 similar because they
are topically identical, even though they are opposite opinions. A consensus layer
that reads agreement off raw cosine therefore manufactures **false agreement** — a
direct hazard for a Byzantine-fault-tolerant commit. This is reproduced and
quantified in ``BENCHMARKS.md`` next to this package.

The fix, grounded in the stance-representation literature:

  Park, Choe & Veitch (2024). *The Linear Representation Hypothesis and the
  Geometry of Large Language Models.* ICML 2024. arXiv:2311.03658.
  Engler, Sikdar, Lutz & Strohmaier (2023). *SensePOLAR: Word-sense aware
  interpretability for pre-trained contextual word embeddings.* arXiv:2301.04704.
  (Both in REFERENCES.md.)

Polarity is a **linear direction** in embedding space. We anchor that direction
with fixed antonym word lists (approve↔reject) — no training, no labels — and read
each opinion's stance as the *signed projection* onto it:

    direction d = normalise( normalise(mean(embed(PRO))) − normalise(mean(embed(CON))) )
    stance(u)   = clamp( normalise(embed(u)) · d , −1, 1 )
    agree(a,b) ⇔ sign(stance(a)) == sign(stance(b))   (outside a small dead-zone)

How we use it
-------------
We *do not* replace the semantic axis with this — the semantic axis keeps doing
topic identity via cosine. The stance scalar is the principled, geometry-grounded
signal for the **sign-carrying** axes (behavioral/affective), and it powers a
``false_agreement`` consensus-quality audit: pairs that are topically close yet
oppositely signed are flagged as superficial agreement.

It is **diagnostic only**: it feeds the consensus-quality report and never alters
the L1 commit certificate (the load-bearing invariant — L2/L3 never change L1).
Empirically (see BENCHMARKS.md) the probe is near-perfect over a *contextual*
``embed_fn`` (fastembed: 6/6 opposite-stance pairs separated) and unreliable over
static/BoW, so it is meaningful only when a contextual ``embed_fn`` is injected.

All functions here are pure and deterministic given ``embed_fn``.
"""

from __future__ import annotations

from collections.abc import Callable

from ._vectors import _cosine, _mean_vec, _normalise

__all__ = [
    "DEFAULT_CON",
    "DEFAULT_PRO",
    "false_agreement_pairs",
    "false_agreement_rate",
    "polarity_direction",
    "stance_agreement",
    "stance_scalar",
]

# Fixed antonym anchors for the approve↔reject ("go / no-go") polarity axis.
# No training: the direction is fully determined by these word lists + embed_fn.
DEFAULT_PRO: tuple[str, ...] = (
    "approve",
    "accept",
    "agree",
    "support",
    "endorse",
    "favor",
    "yes",
    "proceed",
    "keep it",
    "ship it",
    "in favor",
)
DEFAULT_CON: tuple[str, ...] = (
    "reject",
    "oppose",
    "deny",
    "refuse",
    "veto",
    "disagree",
    "no",
    "halt",
    "drop it",
    "block it",
    "against it",
)


def polarity_direction(
    embed_fn: Callable[[str], list[float]],
    pro: tuple[str, ...] = DEFAULT_PRO,
    con: tuple[str, ...] = DEFAULT_CON,
) -> list[float]:
    """Unit vector pointing from the CON centroid to the PRO centroid.

    Each anchor word is embedded, the two centroids are unit-normalised before
    subtraction (so neither list's vector magnitude dominates the direction), and
    the difference is unit-normalised. Deterministic given *embed_fn*.

    Returns ``[]`` if either anchor list embeds to nothing usable, in which case
    callers should treat stance as unavailable (degrade to no signal, never to a
    wrong signal).
    """
    pro_vecs = [embed_fn(w) for w in pro]
    con_vecs = [embed_fn(w) for w in con]
    if not pro_vecs or not con_vecs:
        return []
    pro_c = _normalise(_mean_vec(pro_vecs))
    con_c = _normalise(_mean_vec(con_vecs))
    n = max(len(pro_c), len(con_c))
    pro_c = pro_c + [0.0] * (n - len(pro_c))
    con_c = con_c + [0.0] * (n - len(con_c))
    diff = [p - c for p, c in zip(pro_c, con_c, strict=True)]
    if all(abs(x) < 1e-12 for x in diff):
        return []  # PRO and CON collapse to the same point — no usable axis
    return _normalise(diff)


def stance_scalar(vec: list[float], direction: list[float]) -> float:
    """Signed stance in [−1, 1]: the projection of *vec* onto the polarity *direction*.

    Both inputs are treated as directions (the projection uses the normalised
    *vec*), so the result is a cosine against the polarity axis: positive = PRO,
    negative = CON, near-zero = neutral / off-axis. Returns ``0.0`` when the
    direction is unavailable.
    """
    if not direction or not vec:
        return 0.0
    return _cosine(vec, direction)


def stance_agreement(stance_a: float, stance_b: float, *, deadzone: float = 0.05) -> bool:
    """True iff two stances share sign and both sit outside the neutral *deadzone*.

    The dead-zone keeps near-zero (off-axis / neutral) opinions from being forced
    into a spurious agree/disagree verdict — two agents who are both neutral are
    not "in agreement" in any load-bearing sense.
    """
    if abs(stance_a) < deadzone or abs(stance_b) < deadzone:
        return False
    return (stance_a > 0) == (stance_b > 0)


def false_agreement_pairs(
    semantics: dict[str, list[float]],
    stances: dict[str, float],
    *,
    topic_threshold: float = 0.60,
    deadzone: float = 0.05,
) -> list[tuple[str, str]]:
    """Pairs that are topically close yet oppositely signed — i.e. *false* agreement.

    A pair ``(i, j)`` is flagged when their semantic vectors are within
    *topic_threshold* cosine (they are talking about the same thing) but their
    stance scalars have opposite sign and both clear the *deadzone* (they actually
    disagree). These are exactly the cases raw cosine would miscount as consensus.

    Returns a sorted list of ``(aid_i, aid_j)`` with ``aid_i < aid_j``.
    """
    ids = sorted(semantics)
    flagged: list[tuple[str, str]] = []
    for a in range(len(ids)):
        for b in range(a + 1, len(ids)):
            i, j = ids[a], ids[b]
            if _cosine(semantics[i], semantics[j]) < topic_threshold:
                continue
            si, sj = stances.get(i, 0.0), stances.get(j, 0.0)
            if abs(si) < deadzone or abs(sj) < deadzone:
                continue
            if (si > 0) != (sj > 0):
                flagged.append((i, j))
    return flagged


def false_agreement_rate(
    semantics: dict[str, list[float]],
    stances: dict[str, float],
    *,
    topic_threshold: float = 0.60,
    deadzone: float = 0.05,
) -> float:
    """Fraction of topically-close pairs whose stances actually oppose.

    ``0.0`` means every same-topic pair also shares stance (genuine agreement);
    higher values mean more of the apparent topical consensus is superficial. The
    denominator is the number of topically-close pairs (cosine ≥ *topic_threshold*);
    returns ``0.0`` when there are none, so an all-distinct round is not penalised.
    """
    ids = sorted(semantics)
    close = 0
    opposed = 0
    for a in range(len(ids)):
        for b in range(a + 1, len(ids)):
            i, j = ids[a], ids[b]
            if _cosine(semantics[i], semantics[j]) < topic_threshold:
                continue
            close += 1
            si, sj = stances.get(i, 0.0), stances.get(j, 0.0)
            if abs(si) < deadzone or abs(sj) < deadzone:
                continue
            if (si > 0) != (sj > 0):
                opposed += 1
    return round(opposed / close, 5) if close else 0.0
