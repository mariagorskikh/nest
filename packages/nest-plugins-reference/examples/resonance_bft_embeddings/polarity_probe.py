"""Reproducible test of the antonym-anchored linear POLARITY PROBE.

Run:
    pip install -r requirements-embeddings.txt   # optional, no torch
    python polarity_probe.py

Motivation. benchmark.py shows raw cosine cannot separate stance: "approve the
proposal" vs "reject the proposal" score ~0.8 similar. This script tests the fix
recommended by the stance-representation literature (Park et al., ICML 2024, the
Linear Representation Hypothesis; Engler et al. 2023, SensePOLAR): the *polarity*
concept is a linear DIRECTION in the embedding space, so projecting onto an
antonym-anchored direction recovers a signed stance scalar that cosine throws away.

    direction d = normalise( mean(embed(PRO words)) - mean(embed(CON words)) )
    stance(u)   = normalise(embed(u)) . d          # signed scalar in [-1, 1]
    two agents AGREE iff stance(a) and stance(b) share sign.

Reported per vectoriser:
    opp_sep_rate   fraction of OPPOSITE-stance pairs that get OPPOSITE signs (want 1.0)
    same_sign_rate fraction of SAME-stance pairs that get the SAME sign      (want 1.0)
    cos_baseline   mean raw cosine of the opposite-stance pairs (the broken signal)
"""

from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

_PKG = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PKG))
from nest_plugins_reference.coordination.resonance_bft._vectors import (  # noqa: E402
    _embed,
    _tokenise,
)


def _pad(a: list[float], b: list[float]) -> tuple[list[float], list[float]]:
    n = max(len(a), len(b))
    return a + [0.0] * (n - len(a)), b + [0.0] * (n - len(b))


def cos(a: list[float], b: list[float]) -> float:
    a, b = _pad(a, b)
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return sum(x * y for x, y in zip(a, b, strict=True)) / (na * nb)


def dot(a: list[float], b: list[float]) -> float:
    a, b = _pad(a, b)
    return sum(x * y for x, y in zip(a, b, strict=True))


def unit(a: list[float]) -> list[float]:
    m = math.sqrt(sum(x * x for x in a)) or 1.0
    return [x / m for x in a]


def mean_vec(vs: list[list[float]]) -> list[float]:
    n = max(len(v) for v in vs)
    acc = [0.0] * n
    for v in vs:
        for i, x in enumerate(v):
            acc[i] += x
    return [x / len(vs) for x in acc]


# Antonym anchors for the approve <-> reject ("go / no-go") polarity axis.
PRO = [
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
]
CON = [
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
]

# Opposite stance on the same proposal -> the probe should give OPPOSITE signs.
OPP = [
    ("we should approve the proposal", "we must reject the proposal"),
    ("ship it now, it is ready", "do not ship, hold the release"),
    ("we should accept this plan", "we should refuse this plan"),
    ("endorse the change", "oppose the change"),
    ("vote yes on the measure", "vote no on the measure"),
    ("I support merging this", "I am against merging this"),
]
# Same stance, different words -> the probe should give the SAME sign.
SAME = [
    ("we should approve the proposal", "we should accept this plan"),
    ("we must reject the proposal", "oppose the change"),
    ("ship it now", "I support merging this"),
    ("do not ship, hold the release", "I am against merging this"),
]


def evaluate(name: str, encode):
    d = unit(
        [
            p - c
            for p, c in zip(
                unit(mean_vec([encode(w) for w in PRO])),
                unit(mean_vec([encode(w) for w in CON])),
                strict=False,
            )
        ]
    )

    def stance(u: str) -> float:
        return dot(unit(encode(u)), d)

    opp = [(stance(a), stance(b)) for a, b in OPP]
    same = [(stance(a), stance(b)) for a, b in SAME]
    opp_sep = sum(1 for sa, sb in opp if sa * sb < 0) / len(opp)
    same_ok = sum(1 for sa, sb in same if sa * sb > 0) / len(same)
    cos_base = sum(cos(encode(a), encode(b)) for a, b in OPP) / len(OPP)
    return name, opp_sep, same_ok, cos_base, opp


def main() -> None:
    rows = []

    pro_con_vocab = sorted({w for p in PRO + CON for w in _tokenise(p)})

    def bow_encode(t: str) -> list[float]:
        vocab = sorted(set(_tokenise(t)) | set(pro_con_vocab))
        return _embed(t, vocab)

    rows.append(evaluate("BoW", bow_encode))

    if importlib.util.find_spec("model2vec"):
        from model2vec import StaticModel

        mv = StaticModel.from_pretrained("minishlab/potion-base-8M")
        rows.append(evaluate("model2vec", lambda t: mv.encode([t])[0].tolist()))

    if importlib.util.find_spec("fastembed"):
        from fastembed import TextEmbedding

        fe = TextEmbedding("BAAI/bge-small-en-v1.5")
        rows.append(evaluate("fastembed bge-small", lambda t: list(fe.embed([t]))[0].tolist()))

    print(f"{'vectoriser':<22}{'opp_sep_rate':>13}{'same_sign_rate':>16}{'cos_baseline':>14}")
    print("-" * 65)
    for name, opp, same, cb, _ in rows:
        print(f"{name:<22}{opp:>13.2f}{same:>16.2f}{cb:>14.3f}")
    print("\nopp_sep_rate: want ~1.0 -- probe gives opposite stances opposite sign")
    print("cos_baseline: the broken signal -- high = opposite stances look similar")
    print("\nper-pair stance scalars (opposite pairs; signs should differ):")
    for name, _opp, _same, _cb, signs in rows:
        print(f"  {name}:")
        for (sa, sb), (a, b) in zip(signs, OPP, strict=True):
            tag = "OK " if sa * sb < 0 else "BAD"
            print(f"    [{tag}] {sa:+.3f} / {sb:+.3f}   {a[:26]!r} vs {b[:22]!r}")


if __name__ == "__main__":
    main()
