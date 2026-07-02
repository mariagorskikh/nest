# SPDX-License-Identifier: Apache-2.0
"""Pure vector functions for pentadic space construction.

All functions are stateless and side-effect free — they can be tested and
called independently of any protocol instance.
"""

from __future__ import annotations

import builtins
import hashlib as _hashlib
import math
import re
from collections import Counter
from typing import Any, cast

__all__ = [
    "_affective",
    "_behavioral",
    "_belief_digest",
    "_commitment",
    "_cosine",
    "_verify_signature",
    "_embed",
    "_epistemic",
    "_lerp_vec",
    "_mean_pairwise_distance",
    "_mean_vec",
    "_normalise",
    "_box_validity",
    "_reconcile_bow_semantics",
    "_relational_vec",
    "_tokenise",
    "_trimmed_centroid",
    "_trimmed_mean",
    "_weighted_centroid",
    "pentadic_summary",
    "sycophancy_score",
]

# ── Stop words ────────────────────────────────────────────────────────────────

_STOP = frozenset(
    [
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "in",
        "on",
        "at",
        "to",
        "for",
        "of",
        "with",
        "by",
        "from",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "shall",
        "can",
        "need",
        "dare",
        "ought",
        "used",
        "it",
        "its",
        "this",
        "that",
        "these",
        "those",
    ]
)

# ── Affective lexicons (Russell circumplex) ───────────────────────────────────

_POSITIVE = frozenset(
    [
        "good",
        "great",
        "excellent",
        "beneficial",
        "positive",
        "effective",
        "efficient",
        "optimal",
        "strong",
        "robust",
        "reliable",
        "superior",
        "outstanding",
        "promising",
        "favorable",
        "successful",
        "innovative",
        "accurate",
        "precise",
        "consistent",
    ]
)

_NEGATIVE = frozenset(
    [
        "bad",
        "poor",
        "ineffective",
        "negative",
        "weak",
        "unreliable",
        "inferior",
        "problematic",
        "concerning",
        "risky",
        "unstable",
        "inaccurate",
        "inconsistent",
        "limited",
        "inadequate",
        "flawed",
    ]
)

_HIGH_AROUSAL = frozenset(
    [
        "urgent",
        "critical",
        "important",
        "significant",
        "essential",
        "crucial",
        "vital",
        "necessary",
        "must",
        "immediately",
        "now",
        "certainly",
        "definitely",
        "clearly",
        "strongly",
        "absolutely",
        "confidence",
        "confident",
        "sure",
        "certain",
    ]
)

_LOW_AROUSAL = frozenset(
    [
        "perhaps",
        "maybe",
        "possibly",
        "uncertain",
        "unclear",
        "unsure",
        "doubtful",
        "questionable",
        "might",
        "could",
        "sometimes",
        "occasionally",
        "somewhat",
        "rather",
        "fairly",
        "generally",
        "usually",
    ]
)

# ── Epistemic lexicons ────────────────────────────────────────────────────────

_CERTAIN = frozenset(
    [
        "definitely",
        "certainly",
        "clearly",
        "obviously",
        "undoubtedly",
        "absolutely",
        "necessarily",
        "always",
        "proven",
        "confirmed",
        "verified",
        "established",
        "demonstrated",
        "conclusively",
        "known",
    ]
)

_UNCERTAIN = frozenset(
    [
        "perhaps",
        "maybe",
        "possibly",
        "uncertain",
        "unclear",
        "unsure",
        "ambiguous",
        "debatable",
        "questionable",
        "speculate",
        "estimate",
        "tentative",
        "preliminary",
        "approximate",
    ]
)

# ── Core vector functions ─────────────────────────────────────────────────────


def _tokenise(text: str) -> list[str]:
    return [w.lower() for w in re.findall(r"[a-zA-Z]+", text) if w.lower() not in _STOP]


def _embed(text: str, vocab: list[str]) -> list[float]:
    """Normalised TF projection onto shared *vocab*."""
    counts = Counter(_tokenise(text))
    vec = [float(counts.get(w, 0)) for w in vocab]
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _normalise(vec: list[float]) -> list[float]:
    if not vec:
        return []
    norm = math.sqrt(sum(v * v for v in vec))
    if norm < 1e-9:
        # Zero vector — return uniform unit vector rather than silent zeros.
        # Uniform is the most conservative choice: no axis is preferred.
        n = len(vec)
        return [1.0 / math.sqrt(n)] * n
    return [v / norm for v in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    """True cosine similarity — normalises both inputs so the result is in [−1, 1]."""
    n = max(len(a), len(b))
    a = a + [0.0] * (n - len(a))
    b = b + [0.0] * (n - len(b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return sum((x / na) * (y / nb) for x, y in zip(a, b, strict=True))


def _mean_vec(vecs: list[list[float]]) -> list[float]:
    if not vecs:
        return []
    dim = max(len(v) for v in vecs)
    result = [0.0] * dim
    for v in vecs:
        for i, x in enumerate(v):
            result[i] += x / len(vecs)
    return result


def _weighted_centroid(
    vecs: dict[str, list[float]],
    weights: dict[str, float],
) -> list[float]:
    """Asymmetric-trust-weighted centroid, normalised to unit length."""
    if not vecs:
        return []
    dim = max(len(v) for v in vecs.values())
    total = sum(weights.get(aid, 1.0) for aid in vecs) or 1.0
    centroid = [0.0] * dim
    for aid, vec in vecs.items():
        w = weights.get(aid, 1.0) / total
        for i, v in enumerate(vec):
            centroid[i] += w * v
    return _normalise(centroid)


def _reconcile_bow_semantics(
    evaluations: dict[str, Any],
    embed_fn: Any,
) -> tuple[dict[str, list[float]], int | None]:
    """Remap each bag-of-words record's semantic vector onto a canonical union vocabulary.

    Over a transport, followers ``participate()`` on their own deserialized copy of the round
    and may extend the shared vocab with DIFFERENT private words, so their sealed semantic
    vectors end up in divergent coordinate systems (agent A's coordinate *k* is a different
    word than agent B's coordinate *k*).  Comparing them directly is wrong.  This function
    scatters each record's ``semantic[i]`` into the position of its word ``vocab[i]`` in the
    sorted union vocabulary, so every agent's semantic lives in one shared basis.

    Returns ``(semantic_by_agent, width)`` where ``width`` is the canonical vocabulary size
    (or ``None`` when no reconciliation applies).  It is **deterministic** (sorted union of
    the records' own stored vocabs) → resolver-independent, and a **no-op** when every record
    already shares one vocabulary: in-process rounds use a single append-only vocab, so the
    per-record vocabs are prefix-aligned and the remap reproduces the previous zero-padding.
    It does NOT mutate the sealed records (their commitments stay valid for validators).  With
    a dense ``embed_fn`` the semantic axis is a fixed-dim vector with no vocab, so it is skipped.
    """
    semantic_of = {aid: list(rec.get("semantic", [])) for aid, rec in evaluations.items()}
    if embed_fn is not None:
        return semantic_of, None
    vocabs = {
        aid: cast("list[Any]", rec["vocab"])
        for aid, rec in evaluations.items()
        if isinstance(rec.get("vocab"), list)
    }
    if len(vocabs) < 2:
        return semantic_of, None  # legacy records without per-record vocab: nothing to align
    union: set[str] = set()
    for voc in vocabs.values():
        union |= {str(w) for w in voc}
    canonical = sorted(union)
    index = {w: i for i, w in enumerate(canonical)}
    width = len(canonical)
    for aid, voc in vocabs.items():
        sem = evaluations[aid].get("semantic", [])
        vec = [0.0] * width
        for i, word in enumerate(voc):
            if i < len(sem) and str(word) in index:
                vec[index[str(word)]] = sem[i]
        semantic_of[aid] = vec
    return semantic_of, width


def _trimmed_mean(vecs: list[list[float]], trim: int) -> list[float]:
    """Coordinate-wise trimmed mean (NOT normalised) — the raw aggregate point.

    For each coordinate, drop the ``trim`` smallest and ``trim`` largest values, then
    average the rest (absent coordinates of ragged vectors count as 0.0).  ``trim`` is
    capped so ≥ 1 value survives per coordinate.  Sorts per-coordinate *values*, never
    the agents, so it is a pure function of the sealed vectors (resolver-independent).

    Box (trusted-hyperbox) validity: each coordinate of the result lies within
    ``[trim-th smallest, trim-th largest]`` of that coordinate — so with ``trim`` ≥ the
    number of Byzantine values present, the aggregate stays inside the honest
    per-coordinate range and a Byzantine minority cannot push it out (Vaidya & Garg 2013;
    Cambus & Melnyk 2023 — see REFERENCES.md).  This is *box* validity, weaker than
    *convex* validity, which a coordinate-wise aggregate cannot give in d ≥ 2.
    """
    if not vecs:
        return []
    dim = max(len(v) for v in vecs)
    k = len(vecs)
    t = max(0, min(trim, (k - 1) // 2))  # keep ≥ 1 value per coordinate
    mean = [0.0] * dim
    for i in range(dim):
        col = sorted(v[i] if i < len(v) else 0.0 for v in vecs)
        kept = col[t : k - t]
        mean[i] = sum(kept) / len(kept)
    return mean


def _trimmed_centroid(vecs: list[list[float]], trim: int) -> list[float]:
    """Coordinate-wise trimmed-mean centroid, **unit-normalised** (the committed direction).

    This is ``_normalise(_trimmed_mean(vecs, trim))``: the Byzantine-robust aggregate point
    (box-valid; see :func:`_trimmed_mean`), projected to the unit sphere for the commit's
    cosine geometry.  ``trim=0`` reduces to the previous plain unit-normalised mean.  Grounded
    in coordinate-wise trimmed mean (Yin, Chen, Ramchandran & Bartlett 2018,
    "Byzantine-Robust Distributed Learning", arXiv:1803.01498; see REFERENCES.md).
    """
    mean = _trimmed_mean(vecs, trim)
    return _normalise(mean) if mean else []


def _box_validity(vecs: list[list[float]], trim: int, point: list[float]) -> bool:
    """True iff every coordinate of *point* lies within the per-coordinate TRUSTED HYPERBOX of
    *vecs* — the range ``[trim-th smallest, trim-th largest]`` after dropping ``trim`` extremes
    from each end of that coordinate (box validity; Cambus & Melnyk 2023, Vaidya & Garg 2013).

    With ``trim`` ≥ the number of Byzantine values present, those bounds are honest values, so a
    *point* inside the box provably was not pushed outside the honest range by a Byzantine
    minority.  The raw trimmed-mean aggregate (:func:`_trimmed_mean`) satisfies this by
    construction.  Absent coordinates count as 0.0 (matching the aggregate).
    """
    if not vecs:
        return True
    dim = max(len(v) for v in vecs)
    k = len(vecs)
    t = max(0, min(trim, (k - 1) // 2))
    tol = 1e-9
    for i in range(dim):
        col = sorted(v[i] if i < len(v) else 0.0 for v in vecs)
        lo, hi = col[t], col[k - 1 - t]
        pi = point[i] if i < len(point) else 0.0
        if pi < lo - tol or pi > hi + tol:
            return False
    return True


def _lerp_vec(a: list[float], b: list[float], t: float) -> list[float]:
    """Linear interpolation: a + t*(b-a), element-wise."""
    n = max(len(a), len(b))
    a = a + [0.0] * (n - len(a))
    b = b + [0.0] * (n - len(b))
    return [ai + t * (bi - ai) for ai, bi in zip(a, b, strict=True)]


def _mean_pairwise_distance(vecs: dict[str, list[float]]) -> float:
    """Mean cosine distance (1 − similarity) between all pairs."""
    ids = list(vecs.keys())
    if len(ids) < 2:
        return 0.0
    pairs = 0
    total = 0.0
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            total += 1.0 - _cosine(vecs[ids[i]], vecs[ids[j]])
            pairs += 1
    return total / pairs if pairs else 0.0


# ── Axis-specific constructors ────────────────────────────────────────────────


def _affective(text: str) -> list[float]:
    """Normalised (valence, arousal) from sentiment words.

    Implements the two dimensions of Russell's (1980) circumplex model of affect
    (*J. Personality and Social Psychology* 39(6); see REFERENCES.md) as a lexicon-based
    projection — we map text to the valence×arousal plane rather than to discrete emotions:
      Valence ∈ [−1, 1]: positive minus negative word proportion.
      Arousal ∈ [−1, 1]: high-certainty minus hedging word proportion.
    """
    tokens = _tokenise(text)
    if not tokens:
        return [0.0, 0.0]
    n = len(tokens)
    valence = sum(1.0 if t in _POSITIVE else (-1.0 if t in _NEGATIVE else 0.0) for t in tokens) / n
    arousal = (
        sum(1.0 if t in _HIGH_AROUSAL else (-1.0 if t in _LOW_AROUSAL else 0.0) for t in tokens) / n
    )
    # Genuinely neutral text (no sentiment words) has NO affective signal — keep it the
    # zero vector so cosine treats it as orthogonal to everything.  Routing it through the
    # uniform-unit fallback would instead emit [0.707, 0.707] (positive valence AND
    # arousal), giving an unemotional agent a spurious ~0.8 affective alignment with a
    # strongly positive one.  Only normalise when there is real affect to scale.
    if abs(valence) < 1e-9 and abs(arousal) < 1e-9:
        return [0.0, 0.0]
    return _normalise([valence, arousal])


def _epistemic(
    text: str,
    past_semantics: list[list[float]],
    current_semantic: list[float],
) -> list[float]:
    """Normalised (confidence, position_stability) vector."""
    tokens = _tokenise(text)
    if tokens:
        n = len(tokens)
        confidence = (
            sum(1.0 if t in _CERTAIN else (-1.0 if t in _UNCERTAIN else 0.0) for t in tokens) / n
        )
    else:
        confidence = 0.0

    if past_semantics and current_semantic:
        mean_past = _mean_vec(past_semantics)
        stability = max(_cosine(current_semantic, mean_past), 0.0)
    else:
        stability = 0.5  # new agent: neutral, avoids unearned epistemic authority

    # Genuinely no epistemic signal (neutral text AND zero stability) → zero vector, so
    # cosine treats it as orthogonal rather than the uniform-unit fallback's [0.707, 0.707]
    # which would manufacture spurious epistemic alignment (mirrors _affective).
    if abs(confidence) < 1e-9 and abs(stability) < 1e-9:
        return [0.0, 0.0]
    return _normalise([confidence, stability])


def _behavioral(integrity_ok: int, integrity_total: int, engaged: int, invited: int) -> list[float]:
    """Normalised (integrity, engagement) vector."""
    integ = integrity_ok / integrity_total if integrity_total > 0 else 1.0
    eng = engaged / invited if invited > 0 else 1.0
    return _normalise([integ, eng])


def _relational_vec(
    agent_id: str,
    participants: list[str],
    trust_matrix: dict[str, dict[str, float]],
    default: float = 1.0,
) -> list[float]:
    """Time-decayed trust profile over sorted *participants*.

    Returns a unit-normalised vector over all participants (sorted for
    determinism).  An empty participant list returns a single-element
    uniform vector ``[1.0]`` rather than ``[]`` to keep downstream cosine
    operations well-defined.

    Example::

        vec = _relational_vec("alice", ["alice", "bob", "carol"], {})
        assert len(vec) == 3
        assert abs(sum(v*v for v in vec) - 1.0) < 1e-9
    """
    sorted_peers = sorted(participants)
    if not sorted_peers:
        return [1.0]  # degenerate case: no peers → scalar unit vector
    row = trust_matrix.get(agent_id, {})
    vec = [row.get(p, default) for p in sorted_peers]
    return _normalise(vec)


def _commitment(combined_vec: list[float], nonce: str, basis: list[str] | None = None) -> str:
    """SHA-256 commitment over the belief vector, its nonce, and — for the bag-of-words
    semantic axis — the vocabulary *basis* its semantic coordinates are indexed by.

    Binding the basis seals the *meaning* of the semantic coordinates. ``resolve()`` uses
    each record's ``vocab`` to reconcile semantics across records, so a metadata adversary who
    relabels the basis would reinterpret the (otherwise sealed) semantic values; folding the
    basis into the commitment makes that relabelling change the commitment, so the seal check
    flags the record tampered. With no basis (a dense ``embed_fn``, or callers with no vocab)
    the payload is byte-for-byte the old one — backward compatible.
    """
    payload = f"{combined_vec}:{nonce}"
    if basis:
        payload += ":" + "\x00".join(basis)
    return _hashlib.sha256(payload.encode()).hexdigest()


def _belief_digest(
    eval_text: str, commitment: str = "", round_id: str = "", aid: str = ""
) -> bytes:
    """Stable digest of an agent's belief — the message that gets signed.

    Binds the evaluation text, the SHA-256 belief commitment (which hashes all five sealed
    belief axes + nonce), AND the (round_id, aid) the record belongs to:

    - Binding the *commitment* closes the vector-swap attack: an adversary who edits a
      sealed vector must recompute the commitment to pass the seal check, but then the
      signature — over the *old* commitment — no longer verifies and cannot be re-forged
      without the private key.
    - Binding ``round_id`` + ``aid`` makes the signature **round- and identity-bound**: a
      validly signed record from one round (or from another agent) cannot be replayed into
      a different round or substituted for another agent, because the digest — and hence the
      required signature — differs.

    The signer re-signs after any legitimate vocab-extension re-embed (which changes the
    commitment), so honest agents stay valid; the extra fields default to ``""`` for
    backward compatibility with older callers.
    """
    payload = "\x00".join((commitment, eval_text, round_id, aid))
    return _hashlib.sha256(payload.encode()).digest()


def _verify_signature(pubkey_hex: str, message: bytes, signature_hex: str) -> bool:
    """True iff *signature_hex* is a valid ed25519 signature of *message* under *pubkey_hex*.

    An adversary who controls the shared round metadata cannot forge this without the
    agent's private signing key, so it upgrades the SHA-256 seal (tamper-evidence) to
    cryptographic authorship binding.  Binding the public key to the agent *identity*
    is delegated to the stack's ``identity`` layer (ed25519_rotating) — out of scope
    for the coordination plugin, by the layer separation.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pk.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sycophancy_score(evidence_delta: dict[str, list[float]]) -> dict[str, float]:
    """Compute a per-agent sycophancy score from deliberation evidence_delta.

    The score is the mean of the agent's per-step ``evidence_delta`` — the signed,
    trust-weighted **peer-relative** epistemic pull during deliberation.  A *positive*
    score means the agent was pulled toward MORE-confident peers (moving because others
    sounded sure → persuasion / evidence-driven convergence); a *negative* score means it
    moved toward LESS-confident peers (conceding to a less-certain crowd → social pressure
    / capitulation).  Because Hegselmann-Krause movement pulls the agent's own confidence
    toward the neighbour centroid, this peer-relative signal also tracks the agent's own
    confidence change in magnitude — but its sign is the peer direction.  (Operationalises
    "persuasion overrides truth" — agreeing while knowing less; Agarwal & Khanna 2025,
    arXiv:2504.00374, see REFERENCES.md.)

    Example::

        traj = await plugin.deliberate(rnd, steps=3)
        scores = sycophancy_score(traj.evidence_delta)
        pressured = [aid for aid, s in scores.items() if s < -0.01]
        print("Agents under social pressure:", pressured)
    """
    return {
        aid: builtins.round(sum(deltas) / len(deltas), 5) if deltas else 0.0
        for aid, deltas in evidence_delta.items()
    }


_AXIS_LABELS: dict[str, str] = {
    "semantic": "Semantic (belief content)",
    "affective": "Affective (valence·arousal)",
    "relational": "Relational (trust profile)",
    "epistemic": "Epistemic (confidence·stability)",
    "behavioral": "Behavioral (integrity·engagement)",
}

_SIM_BANDS: list[tuple[float, str]] = [
    (0.90, "strong"),
    (0.75, "moderate"),
    (0.60, "borderline"),
    (0.00, "weak"),
]


def _sim_label(sim: float) -> str:
    for threshold, label in _SIM_BANDS:
        if sim >= threshold:
            return label
    return "weak"


def pentadic_summary(outcome_metadata: dict[str, Any]) -> str:
    """Return a human-readable per-axis alignment breakdown from a resolved outcome.

    Reads ``outcome_metadata["per_axis"]`` (produced by ``ResonanceBFT.resolve()``)
    and formats each agent's five-axis similarity scores plus the overall pentadic
    score into a structured text report.

    Example::

        outcome = await plugin.resolve(rnd)
        print(pentadic_summary(outcome.metadata))
        # ╔══════════════════════════════════════════════════════╗
        # ║         ResonanceBFT — Pentadic Alignment Report     ║
        # ╠══════════════════════════════════════════════════════╣
        # ║  Agent    Semantic  Affect  Relational  Epist  Behav  Overall  ║
        # ║  a0       0.92★     0.81    0.77        0.68   0.89   0.82★    ║
        # ...

    Returns an empty string if *outcome_metadata* lacks ``per_axis`` data.
    """
    per_axis: dict[str, dict[str, float]] = outcome_metadata.get("per_axis", {})
    if not per_axis:
        return ""

    threshold: float = outcome_metadata.get("threshold", 0.60)
    status: str = outcome_metadata.get("status", "unknown")
    quorum_size: int = outcome_metadata.get("quorum_size", 0)
    quorum_needed: int = outcome_metadata.get("quorum_needed", 0)
    tampered: list[str] = outcome_metadata.get("tampered_agents", [])
    axes = ("semantic", "affective", "relational", "epistemic", "behavioral")

    # Build inner content rows first so we can compute box width dynamically.
    header_inner = (
        f"  {'Agent':<12} {'Sem':>6} {'Aff':>6} {'Rel':>6} {'Epi':>6} {'Beh':>6}  "
        f"{'Overall':>8}  {'Align'}"
    )

    data_rows: list[str] = []
    for aid, scores in sorted(per_axis.items()):
        pentadic = scores.get("pentadic", 0.0)
        flag = "✓" if pentadic >= threshold else " "
        cells = "".join(f"{scores.get(ax, 0.0):>6.3f}" for ax in axes)
        data_rows.append(f"  {aid:<12}{cells}  {pentadic:>8.4f}  [{flag}] {_sim_label(pentadic)}")

    aw = outcome_metadata.get(
        "axis_weights",
        {
            "semantic": 0.25,
            "affective": 0.20,
            "relational": 0.25,
            "epistemic": 0.15,
            "behavioral": 0.15,
        },
    )
    aw_str = (
        f"sem={aw.get('semantic', 0):.2f}  "
        f"aff={aw.get('affective', 0):.2f}  "
        f"rel={aw.get('relational', 0):.2f}  "
        f"epi={aw.get('epistemic', 0):.2f}  "
        f"beh={aw.get('behavioral', 0):.2f}"
    )
    weights_inner = f"  Commit weights (fixed): {aw_str}  "
    # Also surface the LEARNED (Layer-3) weights when present, so the slow self-tuning is
    # observable distinctly from the fixed weights the commit uses.
    adaptive_inner: str | None = None
    aaw_raw = outcome_metadata.get("adaptive_axis_weights")
    if isinstance(aaw_raw, dict):
        aaw: dict[str, float] = {str(k): float(v) for k, v in aaw_raw.items()}  # type: ignore[misc]
        adaptive_inner = (
            f"  Learned weights (L3):   "
            f"sem={aaw.get('semantic', 0):.2f}  aff={aaw.get('affective', 0):.2f}  "
            f"rel={aaw.get('relational', 0):.2f}  epi={aaw.get('epistemic', 0):.2f}  "
            f"beh={aaw.get('behavioral', 0):.2f}  "
        )
    status_inner = (
        f"  Status: {status:<10}  Quorum: {quorum_size}/{quorum_needed}  "
        f"Threshold: {threshold:.2f}  "
    )

    # Box width = widest inner content + 2 border chars (║…║).
    inner_w = max(
        len(header_inner) + 2,
        len(weights_inner),
        len(adaptive_inner) if adaptive_inner else 0,
        len(status_inner),
        *(len(r) + 2 for r in data_rows),
        54,  # minimum aesthetic width
    )

    def _box(inner: str) -> str:
        return "║" + inner + " " * (inner_w - len(inner) - 2) + "║"

    title = "ResonanceBFT — Pentadic Alignment Report"
    pad = (inner_w - 2 - len(title)) // 2

    lines: list[str] = []
    lines.append("╔" + "═" * (inner_w - 2) + "╗")
    lines.append("║" + " " * pad + title + " " * (inner_w - 2 - pad - len(title)) + "║")
    lines.append("╠" + "═" * (inner_w - 2) + "╣")
    lines.append(_box(status_inner))
    if tampered:
        lines.append(_box(f"  ⚠ Tampered: {', '.join(tampered)}  "))
    lines.append("╠" + "═" * (inner_w - 2) + "╣")
    lines.append(_box(header_inner + " "))
    lines.append("║" + "─" * (inner_w - 2) + "║")
    for row in data_rows:
        lines.append(_box(row + " "))
    lines.append("╠" + "═" * (inner_w - 2) + "╣")
    lines.append(_box(weights_inner))
    if adaptive_inner is not None:
        lines.append(_box(adaptive_inner))
    lines.append("╚" + "═" * (inner_w - 2) + "╝")
    return "\n".join(lines)
