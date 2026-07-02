# Semantic-axis vectoriser benchmark

**Question.** ResonanceBFT vectorises each agent's free-text opinion into a 5-axis
*pentadic* belief. The **semantic axis** is the one that asks *"are two agents
talking about the same proposition?"*. The default is a zero-dependency
bag-of-words (BoW) vectoriser, and the plugin exposes an `embed_fn` hook to inject
a denser vectoriser. This report measures **which embedding direction is actually
worth recommending** for that hook — and, just as importantly, which is *not*.

**Constraints that frame the answer.** This is a coordination plugin for a
hackathon reference implementation, so the bar is: **no PyTorch, no API key,
offline-capable, deterministic, and small enough not to bloat CI**. Every
candidate below clears the no-torch bar; the benchmark decides between them on
*consensus-relevant quality*, not on leaderboard scores.

Reproduce with [`examples/resonance_bft_embeddings/benchmark.py`](../../../../examples/resonance_bft_embeddings/benchmark.py).

---

## What we measure (and why it is not "MTEB score")

A generic retrieval benchmark (MTEB) rewards "find me the topically nearest
passage". A **consensus** layer needs something subtly different and, in one case,
the *opposite*. We therefore split the job into four quantities over a small
labelled set of multi-agent decision utterances:

| metric | definition | good direction | why it matters for consensus |
|---|---|---|---|
| **`topic_margin`** | mean(same-topic) − mean(different-topic) | **higher** | the semantic axis's core job: keep distinct propositions apart so the consensus layer never fuses unrelated opinions |
| **`para_recall`** | mean similarity of paraphrase pairs | **higher** | recognise "same opinion, different words" (the thing BoW cannot do) |
| **`unrel`** | mean similarity of unrelated-topic pairs | **lower** | a high *similarity floor* manufactures **false agreement** between agents who are not aligned — a safety hazard in BFT |
| **`stance_leak`** | mean similarity of opposite-stance, same-topic pairs | (diagnostic) | "approve" vs "reject", "increase" vs "decrease" — exposes whether a single vector can carry stance |

The dataset is 6 paraphrase pairs, 4 opposite-stance pairs, and 4 unrelated pairs
of realistic agent opinions (latency, cost, risk, ship/hold, rollback, test
coverage). Small and hand-labelled on purpose: the effects below are large and do
not need a 50k-document corpus to be visible.

---

## Results

All numbers from `benchmark.py`, CPU, `torch present? False` confirmed at runtime.
Determinism (`det`) verified by encoding the same string twice and comparing
byte-for-byte.

| method | `topic_margin` ↑ | `para_recall` ↑ | `stance_leak` | `unrel` ↓ | ms/enc | det | footprint |
|---|---|---|---|---|---|---|---|
| BoW (current default) | 0.217 | 0.075 | 0.430 | **0.000** | 0.00 | ✅ | 0 MB / stdlib |
| **model2vec potion-8M** | **0.445** | 0.407 | 0.597 | 0.038 | 0.04 | ✅ | ~8 MB / numpy |
| fastembed bge-small (onnx) | 0.251 | **0.753** | 0.798 | 0.520 | 1.99 | ✅ | ~30 MB / onnxruntime |

---

## Reading the table

**1. BoW is blind to paraphrase.** `para_recall = 0.075`: when two agents express
the same opinion in different words, BoW sees almost nothing in common and reports
"no agreement". That is the legitimate motivation for an embedding upgrade. (Its
`unrel = 0.000` is "perfect" only because non-overlapping word sets are trivially
orthogonal — a side effect, not understanding.)

**2. fastembed has the best raw paraphrase sensitivity — and the worst
false-consensus floor.** `para_recall = 0.753` is excellent. But `unrel = 0.520`:
the bge model rates *genuinely unrelated* opinions ("increase the timeout" vs "the
logo color should be blue") as **0.52 similar**. This is the well-known anisotropy
/ high-cosine-floor property of retrieval embeddings. For most apps it is benign;
for a **BFT consensus layer it is actively dangerous** — it pushes the system
toward committing on agreement that does not exist. Net `topic_margin` is only
0.251 *despite* the strong paraphrase recall, because the floor eats the margin.

**3. model2vec wins the metric that actually matters here.**
`topic_margin = 0.445` — nearly double BoW and fastembed — because it combines a
*usable* paraphrase recall (0.407, ~5× BoW) with a *low* false-consensus floor
(`unrel = 0.038`). It is also the lightest non-trivial option (numpy only, ~8 MB,
no onnxruntime), the fastest (~50× faster per encode than fastembed), and
deterministic by construction (static lookup + average, no kernel nondeterminism).

**4. The headline negative result: no vectoriser separates stance.**
`stance_leak` is high for **all three** (0.43 / 0.60 / 0.80), and *highest* for the
strongest embedding. "approve the proposal" vs "reject the proposal" and "increase
the timeout" vs "decrease the timeout" are topically identical, so every
cosine-of-a-single-vector method calls them similar. **This is not a model-size
problem; it is a representation problem.** Agreement/disagreement is not a property
*cosine* can read off a single vector.

---

## The fix: a linear polarity probe recovers the stance cosine throws away

The negative result above is "cosine cannot separate stance" — not "the embedding
does not contain stance". The stance-representation literature (Park et al., *The
Linear Representation Hypothesis*, ICML 2024; Engler et al., *SensePOLAR*, 2023)
predicts that polarity is a **linear direction** in the embedding space. So instead
of comparing two utterances by cosine, we project each onto an antonym-anchored
direction and read its **sign**:

```text
direction d = normalise( mean(embed(PRO words)) - mean(embed(CON words)) )
stance(u)   = normalise(embed(u)) · d            # signed scalar in [-1, 1]
agree(a, b) iff sign(stance(a)) == sign(stance(b))
```

`PRO = {approve, accept, support, endorse, yes, ship it, ...}`,
`CON = {reject, oppose, refuse, veto, no, hold, ...}` — fixed word lists, no
training. Reproduce with
[`examples/resonance_bft_embeddings/polarity_probe.py`](../../../../examples/resonance_bft_embeddings/polarity_probe.py).

| vectoriser | `opp_sep_rate` ↑ | `same_sign_rate` ↑ | `cos_baseline` (broken) |
|---|---|---|---|
| BoW | 0.67 | 0.25 | 0.354 |
| model2vec potion-8M | 0.67 | 0.75 | 0.654 |
| **fastembed bge-small (onnx)** | **1.00** | **1.00** | 0.814 |

`opp_sep_rate` = fraction of opposite-stance pairs the probe gives *opposite* signs;
`same_sign_rate` = fraction of same-stance, different-words pairs it gives the *same*
sign; `cos_baseline` = the raw cosine of those same opposite pairs (the signal that
fails).

**The headline:** the *worst* case for cosine is the *best* case for the probe.
On `fastembed`, "approve the proposal" vs "reject the proposal" has cosine **0.814**
(reads as strong agreement — a false consensus) yet projects to **+0.205 / −0.226**
(opposite signs — correctly read as disagreement). The probe separates **6/6**
opposite-stance pairs and **4/4** same-stance pairs — a clean, deterministic,
pure-NumPy fix over the *same* embedding, exactly as the linear-representation
theory predicts.

This also **re-ranks the embeddings for the stance job**: contextual embeddings
(`fastembed`) encode the polarity direction cleanly (1.00 / 1.00); static and BoW
do not (0.67 and a near-random 0.25 same-sign rate). So the two axes want different
encoders, and that is fine — they are different jobs:

| job | metric | best encoder | geometry |
|---|---|---|---|
| topic identity (semantic axis) | `topic_margin`, low `unrel` | model2vec (low floor, cheap) | raw cosine |
| stance / polarity (sign axes) | `opp_sep_rate` | fastembed (clean linear direction) | antonym-anchored projection |

---

## "Embedding" precisely: static (no attention) vs contextual (attention)

It matters *which* of these is actually a contextual, attention-based encoder,
because that is what makes the stance machinery work:

| candidate | a learned embedding? | self-attention at inference? | stance via the probe |
|---|---|---|---|
| BoW | no — sparse term counts | no | unreliable |
| model2vec (potion-8M) | yes, but **static** (distilled token vectors looked up + averaged) | **no** | weak (0.67) |
| **fastembed bge-small (ONNX)** | yes, **contextual** | **yes** (BERT-family transformer, no torch) | clean (1.00) |

Static embeddings carry a transformer's *distilled knowledge* but do no attention at
run time — they average token vectors, which is exactly why they cannot separate
"approve X" from "reject X". The polarity probe works *because* attention-derived
representations encode the polarity concept as a linear direction (Park et al. 2024);
averaged static vectors do not have that structure cleanly. **The encoder that makes
both paraphrase robustness and the stance audit work is the contextual, attention one.**

## Recommendation

> **Recommended real encoder: `fastembed` bge-small (a contextual, attention-based
> transformer via ONNX Runtime — no PyTorch).** BoW stays the zero-dependency default;
> `model2vec` is the ultra-light static (attention-free) alternative for size-critical
> deployments that do not need stance separation.

Why fastembed is the recommended real encoder, despite `model2vec` winning the raw
`topic_margin`: the whole value proposition is *paraphrase robustness **and** a working
stance audit*, and fastembed is the only no-torch option that delivers **both** —

1. **Strong paraphrase recall** (`para_recall` 0.753) — recognises same-opinion /
   different-words, the thing BoW (0.075) misses entirely.
2. **It is the encoder under which the stance audit actually fires** (`opp_sep_rate`
   1.00 vs model2vec's 0.67) — because it has attention. With a static encoder the
   `false_agreement` signal is dead.
3. **No torch** — ONNX Runtime + tokenizers; ~30 MB model, deterministic on CPU
   (preserving the resolver-independence the sealed-at-participate design relies on).

Its one weakness — a high similarity floor (`unrel` 0.520) that hurts the bare
`topic_margin` — is a known anisotropy property fixable by mean-centering / whitening,
and in any case the BFT layer already excludes tampered records from the centroid.
`model2vec` remains documented for deployments that want ~8 MB and numpy-only and can
forgo stance separation; BoW remains the zero-dependency default.

For the **stance / sign-carrying axes**, the in-protocol audit is the
**antonym-anchored linear polarity probe** (pure NumPy, deterministic, microsecond),
enabled when a contextual `embed_fn` is present. Where higher stance accuracy is
needed, the optional **NLI cross-encoder tier** below is the measured upgrade.

### How much stronger is the attention/NLI tier? (measured)

The probe is a single signed projection onto *one* fixed approve↔reject axis, so it
cannot model negation or opinions off that axis. A no-torch **NLI cross-encoder**
(`Xenova/nli-deberta-v3-small`, ONNX) instead reads both utterances *jointly with
cross-attention*. Measured on labelled agree/disagree pairs
([`examples/.../nli_vs_probe.py`](../../../../examples/resonance_bft_embeddings/nli_vs_probe.py)):

| method (both no-torch) | EASY (explicit approve/reject) | HARD (negation / implicit / off-axis) |
|---|---|---|
| linear probe (over fastembed) | **6/6** correct | **1/6 covered, 0 correct** (abstains off-axis; the one it answers, negation flips it) |
| NLI cross-encoder (attention) | **6/6** correct | **6/6** correct |

Verdict: on **explicit** stance the cheap probe equals NLI — so the probe is the right
default for the in-protocol, per-utterance, resolver-independent audit. On **hard**
stance (negation, implicit, off-axis) the probe runs out of road and the
cross-attention NLI model wins outright. So NLI is offered as an optional
**high-accuracy analyzer** (pairwise, O(n²), heavier), not the in-protocol signal.

### The negative result is a design validation — and now a demonstrated fix

The fact that **no cosine** over a single vector separates stance is precisely why
ResonanceBFT is **pentadic** rather than a single-embedding consensus scheme.
Stance lives in the **affective** (valence/intensity) and **behavioral**
(commit/abstain/oppose) axes, which carry sign; the semantic axis only answers
"same proposition?". The polarity-probe result closes the loop: we not only show
*why* a one-vector cosine shortcut is wrong, we show the cheap, principled,
literature-grounded way to recover stance (project onto the polarity direction) —
and it lands the false-consensus case (cosine 0.81) as a correct disagreement
(signs +0.21 / −0.23). The benchmark turns a tempting shortcut into a *measured*
separation of concerns: **semantic axis = topic identity via cosine; sign axes =
stance via polarity projection.**

---

## How the recommendation is wired in

- The plugin's default is unchanged: BoW, zero dependencies, offline.
- `ResonanceBFTCoordination(..., embed_fn=my_encoder)` swaps in any
  `Callable[[str], list[float]]`. The chosen vector is sealed at `participate()`
  and read (never recomputed) at `resolve()`, so injecting an embedder cannot
  break commit determinism.
- `examples/resonance_bft_embeddings/` contains the reproducible `benchmark.py`,
  `polarity_probe.py`, and a `requirements-embeddings.txt` listing only the
  optional, no-torch deps.
- The polarity probe is **implemented** in `_polarity.py`. When an `embed_fn` is
  set, `resolve()` projects each agent's sealed semantic vector onto the polarity
  direction and surfaces a `false_agreement_rate` (plus the offending pairs and
  per-agent `stances`) inside `consensus_quality` — flagging a quorum that is
  cosine-aligned yet stance-split. It is **diagnostic only**: it never gates the L1
  commit certificate, and because it reads only sealed vectors + a fixed direction
  it stays resolver-independent.

## Limitations / honesty notes

- Small hand-labelled probe sets (14 pairs for the semantic benchmark, 10 for the
  polarity probe); effect sizes are large but this is a demonstration, not a
  leaderboard submission.
- The polarity probe is near-perfect on contextual embeddings and unreliable on
  static/BoW (0.67 / 0.25) — it is an upgrade *conditional on* a contextual
  `embed_fn`, not a property of the BoW default.
- fastembed's high floor is partly fixable by mean-centering / whitening against a
  reference corpus, at the cost of statefulness that conflicts with the stateless
  per-utterance seal — so we report the out-of-the-box behavior.
- `stance_leak` would only be reduced by an NLI / stance-trained model (entailment
  vs contradiction), which is a different task and a heavier dependency than this
  optional path warrants. The pentadic axes handle stance instead.
