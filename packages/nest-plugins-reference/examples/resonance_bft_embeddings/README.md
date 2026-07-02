# ResonanceBFT — semantic-axis embedding benchmark

Optional, no-torch experiment that justifies *which* dense vectoriser is worth
injecting into the ResonanceBFT semantic axis via the `embed_fn` hook. The core
plugin does **not** depend on anything here — its default semantic axis is a
zero-dependency bag-of-words vectoriser.

## Run

```bash
pip install -r requirements-embeddings.txt   # model2vec + fastembed (no torch)
python benchmark.py        # semantic-axis comparison (topic identity)
python polarity_probe.py   # stance separation via antonym-anchored linear probe
python nli_vs_probe.py     # how much stronger is the attention tier (NLI) than the probe
```

Or, without touching your environment:

```bash
uv run --with model2vec --with fastembed python benchmark.py
uv run --with model2vec --with fastembed python polarity_probe.py
```

## What it shows

A consensus-relevant comparison of BoW vs `model2vec` (static, numpy) vs
`fastembed` (bge-small via ONNX Runtime). Full analysis and the recommendation
(**`fastembed` — a contextual, attention-based encoder via ONNX, no torch — as the
recommended real encoder; `model2vec` as the ultra-light static alternative; BoW
stays the zero-dependency default**) are in
[`BENCHMARKS.md`](../../nest_plugins_reference/coordination/resonance_bft/BENCHMARKS.md).

Headline: `model2vec` wins the raw topic-discrimination margin, but `fastembed` is the
recommended real encoder because it is the only no-torch option that delivers *both*
paraphrase robustness *and* a working stance audit — the attention it has is what makes
the polarity direction linear. No *cosine* separates *stance*
(approve vs reject) — but `polarity_probe.py` shows a one-line antonym-anchored
linear probe over a contextual embedding recovers it perfectly (6/6 opposite-stance
pairs, where cosine reads 0.81 false-agreement). That is exactly why ResonanceBFT
keeps stance in the sign-carrying affective/behavioral axes, not the semantic one.
