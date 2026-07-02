"""Reproducible horizontal benchmark of semantic-axis vectorisers for ResonanceBFT.

Run:
    pip install -r requirements-embeddings.txt   # optional deps, NOT core deps
    python benchmark.py

The core plugin never imports any of these models -- they are injected through the
``embed_fn`` hook on ResonanceBFTCoordination. This script exists only to justify,
with numbers, *which* embedding direction is worth recommending for the optional
semantic-axis upgrade. See BENCHMARKS.md (next to the plugin) for the write-up.

Two jobs are measured separately, because they are genuinely different:

  topic_margin = mean(same-topic) - mean(different-topic)
      The semantic axis's REAL job: "are two agents discussing the same proposition?"
      Higher is better. This is what an opinion-vectoriser must get right so the
      consensus layer does not fuse unrelated opinions.

  para_recall = mean(paraphrase pairs)
      Same opinion, different words. Higher = better synonym/paraphrase sensitivity.

  unrel = mean(unrelated pairs)
      Different topics. LOWER is better. A high "similarity floor" here is dangerous
      for a BFT consensus system: it manufactures FALSE agreement between agents who
      are not actually aligned.

  stance_leak = mean(opposite-stance, same-topic pairs)
      "approve" vs "reject", "increase" vs "decrease". ALL embeddings score these
      HIGH because they are topically identical. This is the headline negative
      result: a single semantic vector cannot carry stance -- which is exactly why
      ResonanceBFT keeps stance in the affective + behavioral axes, not the
      semantic one.
"""

from __future__ import annotations

import importlib.util
import math
import sys
import time
from pathlib import Path

# Import the plugin's own BoW vectoriser as the baseline.
_PKG = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PKG))
from nest_plugins_reference.coordination.resonance_bft._vectors import (  # noqa: E402
    _embed,
    _tokenise,
)


def cos(a: list[float], b: list[float]) -> float:
    n = max(len(a), len(b))
    a = list(a) + [0.0] * (n - len(a))
    b = list(b) + [0.0] * (n - len(b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return sum(x * y for x, y in zip(a, b, strict=True)) / (na * nb)


# --- labelled opinion pairs in a multi-agent decision context -------------------
# Same topic + same stance, different words -> the semantic axis SHOULD judge HIGH.
PARAPHRASE = [
    ("the latency is far too high", "response time is excessive and slow"),
    ("we should pick the cheaper option", "cost minimization is the priority"),
    ("the proposal is too risky to approve", "this plan carries unacceptable danger"),
    ("ship it now, it's ready", "this is production-ready, let's release"),
    ("we need more test coverage first", "the suite is under-tested, add tests before merge"),
    ("rollback immediately", "revert the change right away"),
]
# Same topic, OPPOSITE stance -> topically identical; distinguishing these is NOT
# the semantic axis's job (it belongs to the affective/behavioral axes).
OPPOSITE = [
    ("we should approve the proposal", "we must reject the proposal"),
    ("ship it now", "do not ship, hold the release"),
    ("increase the timeout", "decrease the timeout"),
    ("the cheaper option is best", "pay more for the premium option"),
]
# Different topic -> the semantic axis SHOULD judge LOW.
UNRELATED = [
    ("the latency is far too high", "the documentation needs a rewrite"),
    ("rollback immediately", "let's schedule lunch tomorrow"),
    ("increase the timeout", "the logo color should be blue"),
    ("we need more test coverage", "the office coffee machine is broken"),
]


def measure(sim) -> dict[str, float]:
    par = [sim(a, b) for a, b in PARAPHRASE]
    opp = [sim(a, b) for a, b in OPPOSITE]
    unr = [sim(a, b) for a, b in UNRELATED]
    same_topic = par + opp
    return {
        "topic_margin": sum(same_topic) / len(same_topic) - sum(unr) / len(unr),
        "para_recall": sum(par) / len(par),
        "stance_leak": sum(opp) / len(opp),
        "unrel": sum(unr) / len(unr),
    }


def timeit(encode, n: int = 20) -> float:
    encode("warmup")
    t0 = time.perf_counter()
    for _ in range(n):
        encode("a moderately sized opinion sentence about latency")
    return (time.perf_counter() - t0) / n * 1000.0  # ms / encode


def det_ok(encode) -> bool:
    return encode("determinism probe") == encode("determinism probe")


def main() -> None:
    rows = []

    # 1) BoW baseline -- the plugin's current zero-dependency default.
    def bow_sim(a: str, b: str) -> float:
        vocab = sorted(set(_tokenise(a)) | set(_tokenise(b)))
        return cos(_embed(a, vocab), _embed(b, vocab))

    rows.append(("BoW (current default)", measure(bow_sim), 0.0, True, "0 MB / stdlib"))

    # 2) model2vec static embeddings -- numpy only, no torch, no onnx.
    if importlib.util.find_spec("model2vec"):
        from model2vec import StaticModel

        mv = StaticModel.from_pretrained("minishlab/potion-base-8M")
        enc = lambda t: mv.encode([t])[0].tolist()  # noqa: E731
        rows.append(
            (
                "model2vec potion-8M",
                measure(lambda a, b: cos(enc(a), enc(b))),
                timeit(enc),
                det_ok(enc),
                "~8 MB / numpy",
            )
        )

    # 3) fastembed bge-small -- onnxruntime, no torch.
    if importlib.util.find_spec("fastembed"):
        from fastembed import TextEmbedding

        fe = TextEmbedding("BAAI/bge-small-en-v1.5")
        enc2 = lambda t: list(fe.embed([t]))[0].tolist()  # noqa: E731
        rows.append(
            (
                "fastembed bge-small (onnx)",
                measure(lambda a, b: cos(enc2(a), enc2(b))),
                timeit(enc2),
                det_ok(enc2),
                "~30 MB / onnxruntime",
            )
        )

    torch_present = importlib.util.find_spec("torch") is not None
    print(f"torch present? {torch_present}  (target: False)\n")
    hdr = (
        f"{'method':<28}{'topic_margin':>13}{'para_recall':>12}"
        f"{'stance_leak':>12}{'unrel':>8}{'ms/enc':>8}{'det':>6}"
    )
    print(hdr)
    print("-" * len(hdr))
    for name, m, ms, det, _fp in rows:
        print(
            f"{name:<28}{m['topic_margin']:>13.3f}{m['para_recall']:>12.3f}"
            f"{m['stance_leak']:>12.3f}{m['unrel']:>8.3f}{ms:>8.2f}{str(det):>6}"
        )
    print("\nfootprint:")
    for name, _m, _ms, _det, fp in rows:
        print(f"  {name:<28} {fp}")
    print(
        "\ntopic_margin HIGHER=better (semantic axis job) | "
        "unrel LOWER=better (false-consensus risk)"
    )
    print(
        "stance_leak HIGH for ALL -> stance is not a semantic-vector property "
        "(handled by affective/behavioral axes)"
    )


if __name__ == "__main__":
    main()
