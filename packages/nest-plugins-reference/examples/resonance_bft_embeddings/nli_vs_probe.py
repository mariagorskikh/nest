"""How much stronger is the attention tier? Linear probe vs NLI cross-encoder.

Both are no-torch. The point of this benchmark is to measure, honestly, what the
cheap antonym-anchored polarity probe gives up versus a real attention-based NLI
cross-encoder for stance/agreement.

  * linear probe (over fastembed bge-small): one signed projection per utterance onto
    a fixed approve<->reject direction. Cheap, deterministic, zero-training, but it
    has exactly ONE polarity axis and cannot model negation or off-axis opinions.
  * NLI cross-encoder (Xenova/nli-deberta-v3-small, ONNX, no torch): reads the two
    utterances JOINTLY with cross-attention and classifies entailment / contradiction
    / neutral, i.e. general pairwise agree/disagree.

Run:
    pip install -r requirements-embeddings.txt
    python nli_vs_probe.py

Result (typical): the two tie on EASY explicit approve/reject pairs, and the NLI
cross-encoder decisively wins on HARD pairs (negation, implicit stance, off-axis
opinions) where the single-vector probe abstains or flips. That is the measured cost
of staying single-vector — and the reason the probe is the in-protocol audit while
NLI is the optional high-accuracy analyzer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

_PKG = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PKG))
from nest_plugins_reference.coordination.resonance_bft._polarity import (  # noqa: E402
    polarity_direction,
    stance_scalar,
)

# Labelled agree/disagree pairs.  EASY = explicit approve/reject; HARD = negation,
# implicit stance, or opinions that are simply off the approve<->reject axis.
EASY = [
    ("approve the proposal", "reject the proposal", "disagree"),
    ("we should accept this plan", "we should refuse this plan", "disagree"),
    ("approve the proposal", "we should accept this plan", "agree"),
    ("reject the proposal", "oppose the change", "agree"),
    ("ship it now", "do not ship, hold the release", "disagree"),
    ("endorse the change", "support the change", "agree"),
]
HARD = [
    ("I don't think we should reject it", "we must reject it", "disagree"),
    ("this will break production", "ship it now", "disagree"),
    ("the latency is far too high", "response time is unacceptably slow", "agree"),
    ("I'm not opposed to merging", "block the merge", "disagree"),
    ("let's hold off until tests pass", "we need more test coverage before merge", "agree"),
    ("there's no reason to delay", "we should postpone this", "disagree"),
]


def build_probe():
    from fastembed import TextEmbedding

    fe = TextEmbedding("BAAI/bge-small-en-v1.5")
    emb = lambda t: list(fe.embed([t]))[0].tolist()  # noqa: E731
    direction = polarity_direction(emb)

    def predict(a: str, b: str, deadzone: float = 0.05) -> str:
        sa, sb = stance_scalar(emb(a), direction), stance_scalar(emb(b), direction)
        if abs(sa) < deadzone or abs(sb) < deadzone:
            return "abstain"  # off the single anchored axis → no verdict
        return "agree" if (sa > 0) == (sb > 0) else "disagree"

    return predict


def build_nli():
    import onnxruntime as ort
    from huggingface_hub import hf_hub_download
    from tokenizers import Tokenizer

    repo = "Xenova/nli-deberta-v3-small"
    with open(hf_hub_download(repo, "config.json")) as fh:
        cfg = json.load(fh)
    id2label = {int(k): v for k, v in cfg["id2label"].items()}
    tok = Tokenizer.from_file(hf_hub_download(repo, "tokenizer.json"))
    sess = ort.InferenceSession(
        hf_hub_download(repo, "onnx/model.onnx"), providers=["CPUExecutionProvider"]
    )
    names = {i.name for i in sess.get_inputs()}

    def predict(a: str, b: str) -> str:
        enc = tok.encode(a, b)
        feed = {
            "input_ids": np.array([enc.ids], np.int64),
            "attention_mask": np.array([enc.attention_mask], np.int64),
        }
        if "token_type_ids" in names:
            feed["token_type_ids"] = np.array([enc.type_ids], np.int64)
        logits = sess.run(None, feed)[0][0]
        label = {id2label[i]: logits[i] for i in range(len(logits))}
        return "disagree" if label["contradiction"] > label["entailment"] else "agree"

    return predict


def _score(rows, predict) -> tuple[int, int, int]:
    correct = covered = 0
    for a, b, gold in rows:
        pred = predict(a, b)
        if pred == "abstain":
            continue
        covered += 1
        correct += pred == gold
    return correct, covered, len(rows)


def main() -> None:
    probe = build_probe()
    nli = build_nli()
    print(f"{'method':<30}{'EASY (correct/cov)':>22}{'HARD (correct/cov)':>22}")
    print("-" * 74)
    for name, predict in (("linear probe (fastembed)", probe), ("NLI cross-encoder", nli)):
        ec, ecov, en = _score(EASY, predict)
        hc, hcov, hn = _score(HARD, predict)
        print(f"{name:<30}{f'{ec}/{ecov} (of {en})':>22}{f'{hc}/{hcov} (of {hn})':>22}")
    print("\nHARD per-pair (where the single-vector probe runs out of road):")
    for a, b, gold in HARD:
        print(f"  gold={gold:<8} probe={probe(a, b):<8} nli={nli(a, b):<8} | {a[:30]!r}")


if __name__ == "__main__":
    main()
