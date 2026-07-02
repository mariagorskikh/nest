# Real-LLM ResonanceBFT consensus demo

LLM agents form opinions on a question; ResonanceBFT vectorises them into the five-axis
pentadic space, runs bounded-confidence deliberation, and commits an `n−f` quorum with the
genuine-vs-superficial audit — **at different scales**.

This is the "transformer-at-the-edge, deterministic core" design in action: the **LLM's
nondeterministic output is the opinion, but it is *sealed* at `participate()`**, so the commit
is a deterministic, resolver-independent function of the sealed vectors. The model informs
*perception*; it never forks the *decision*.

## Run

```bash
# Offline, deterministic (mock LLM — no keys, no network). Runs anywhere:
python demo.py
python demo.py --scales 4,7,12,20

# With a REAL LLM (nondeterministic — a demonstration, not a test):
#   subscription CLI, NO API KEY (uses your local `claude`/`codex`/`agy` login).
#   Lowest/fastest models are plenty — the deterministic core needs no frontier model:
python demo.py --backend claude --model haiku --scales 4,7         # --model haiku|sonnet|opus
python demo.py --backend codex --scales 4                          # ChatGPT-account default model
python demo.py --backend agy --model "Gemini 3.5 Flash (Low)"      # Antigravity; see `agy models`

# Real-TOWN evidence (actual nandatown agents via ScenarioRunner, not this direct-call demo):
python evidence_town.py --tiers claude:haiku --reps 1   # → EVIDENCE.md (live-marked, not in CI)
#   local, no key:  install ollama, `ollama pull llama3.2`
python demo.py --backend ollama --model llama3.2 --scales 4,7
#   any OpenAI-compatible endpoint:
OPENAI_API_KEY=... OPENAI_BASE_URL=https://api.openai.com/v1 \
    python demo.py --backend openai --model gpt-4o-mini

# Dense (attention) embedding on the semantic axis (no torch):
python demo.py --embed fastembed        # pip install fastembed

# Adversarial + quality suite (non-consensus, evil agents, malformed records):
python demo.py --suite
python demo.py --suite --embed fastembed   # also fires the false-consensus stance audit
```

Flags: `--backend mock|ollama|openai|claude|codex|agy`, `--model`,
`--embed none|fastembed|model2vec`, `--scales 4,7,12`, `--question "..."`, `--suite`.

**Subscription CLIs (no API key).** `--backend claude|codex|agy` shells out to your
locally-authenticated agent CLI in headless one-shot mode and returns the model's clean text
response — **exactly like an API call**, but billed to your interactive subscription login
(zero setup, real frontier model, model switching via `--model`). All three verified live:

| backend | CLI | model switching |
|---|---|---|
| `claude` | `claude -p` (Anthropic) | `--model haiku\|sonnet\|opus` |
| `codex` | `codex exec` (ChatGPT account) | default model only — a custom `-m` is rejected on that tier |
| `agy` | `agy -p` (Antigravity) | `--model "<name>"` — run `agy models` (Gemini 3.x, Claude Sonnet/Opus 4.6, GPT-OSS 120B) |

`agy` is the **Antigravity** CLI, not a model — it fronts Google **Gemini** (and Claude / GPT-OSS)
models through one login; the evidence runs used `Gemini 3.5 Flash (Low)`. The **exact model ids,
metrics, and per-backend configuration** used for the evidence are documented in
[`MODELS.md`](MODELS.md) (and appended to every generated report).

## The adversarial + quality suite (`--suite`)

A commit is **not** the same as genuine agreement: the protocol commits a coherent `n−f`
quorum, the **audit** tells you whether that commit is real, tampered records are detected and
excluded, and it **aborts (no consensus)** when faults exceed the tolerance `f`. Six cases:

| # | case | outcome |
|---|---|---|
| 1 | **Genuine** — aligned honest agents | COMMIT (clean: tampered=[], false_agreement 0) |
| 2 | **False consensus** — same proposition, opposite stance | COMMIT, but `false_agreement > 0` flags it (with `--embed fastembed`, ≈0.6) |
| 3 | **Manufactured** — unrelated opinions | COMMIT a quorum, but the audit marks it not-genuine (coerced/capitulated) |
| 4 | **Evil contained** — 2 Byzantine tamper records (k = f) | detected + excluded → honest quorum **COMMITS**, `tampered=2` |
| 5 | **Evil overwhelm** — 3 Byzantine (k > f) | `tampered_exceeds_f` → **ABORT** (safety: refuses to commit a corrupted result) |
| 6 | **Malformed** — 2 non-finite (inf) vectors | flagged tampered by schema validation, excluded → honest quorum COMMITS |

## What you see, per scale

- each agent's **LLM-generated opinion** (from a distinct persona/lean);
- the **pentadic alignment report** (`pentadic_summary`): per-axis similarity + overall;
- the **commit**: `status`, `quorum k/n−f`, `consensus_type`, `false_agreement`, quality
  metrics (independence / capitulation / disagreement-collapse), `tampered`.

Example (mock, `--embed none`, 12 agents): `COMMITTED quorum 11/9 (n=12, f=3)`,
`consensus_type: genuine`.

## Honest notes

- **Determinism.** With `--backend mock` the whole run is deterministic (so it can be a CI
  smoke test). With a real LLM it is **nondeterministic** — a demonstration, not a correctness
  test; BFT correctness itself is tested deterministically by the unit/property suite.
- **`false_agreement`.** This audit flags pairs that are *topically the same proposition* yet
  opposite in stance. Real opinions vary in wording, so they often fall below the
  topic-closeness bar and the signal reads `0.0` — that is the audit being conservative, not
  broken; it fires cleanly when opinions are near-identical in topic (see the scripted
  `resonance_bft_consensus.yaml` split rounds). Stance still shows up in `consensus_type`.
- **Motivation.** *Can AI Agents Agree?* (Berdoz, Rugli & Wattenhofer 2026, arXiv:2603.01213)
  finds real LLM Byzantine consensus is unreliable, dominated by **liveness** failures —
  exactly what ResonanceBFT targets with the `n−f` commit + bounded-round HK convergence.
