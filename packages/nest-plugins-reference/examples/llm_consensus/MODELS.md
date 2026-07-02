## Models, metrics & configuration

Every real tier is a **key-free subscription CLI**: it drops the metered API-key env var so the
interactive login drives the model, runs each call in an isolated temp cwd, and retries 3× on a
transient failure. The opinion prompt is `persona (name / angle / lean) + the question → one
sentence`. Lowest thinking tier / smallest model each — the deterministic core needs no frontier
model.

| tier label | CLI | provider · exact model | config |
|---|---|---|---|
| `mock` | — | deterministic stub (no model) | scripted persona stance |
| `claude:haiku` | `claude -p` | Anthropic · `claude-haiku-4-5` | `--model haiku --no-session-persistence` |
| `codex` | `codex exec` | OpenAI · `gpt-5.5` | `--skip-git-repo-check -c model_reasoning_effort=low -o <file>` |
| `agy:Gemini 3.5 Flash (Low)` | `agy -p` | Google · **Gemini 3.5 Flash**, Low thinking tier | `--model "Gemini 3.5 Flash (Low)"` |

So **`agy` is not a model** — it is the Antigravity CLI fronting a Google **Gemini 3.5 Flash**
model at its lowest (`Low`) thinking tier. (`agy models` also exposes Gemini 3.1 Pro and
Claude / GPT-OSS models through the same login; we used the cheapest Gemini one.)

### Metrics captured per run

| field | meaning |
|---|---|
| `status` | `committed` / `no-commit` (partitioned minority) / `aborted` (below the BFT floor) |
| `quorum` | `quorum_size / quorum_needed` — the committed set vs the required `n − f` |
| `f` | Byzantine tolerance `⌊(n−1)/3⌋` |
| `tampered` | sealed records whose seal / signature failed → detected and excluded |
| `consensus_type` | L2 audit verdict: `genuine` / `fragile` / `coerced` / `capitulated` / `coalitional` |
| `false_agreement` | stance-audit rate (same proposition, opposite stance); `n/a` under bag-of-words |
| `rounds_committed`, `types_by_round` | multi-round: committed-round count + per-round type trajectory |
| `elapsed` | wall-clock seconds for the run (opinion generation dominates) |

### Town configuration

Real `ScenarioRunner` stack (in-memory transport, `did_key` identity, `score_average` trust,
`resonance_bft` coordination); semantic-axis embedding `demo` (deterministic stance bag-of-words);
opinions injected via the scenario's **default-off** `opinions` hook. The commit itself uses the
protocol's fixed threshold `0.60` and axis weights (sem `.25` / aff `.20` / rel `.25` / epi `.15` /
beh `.15`) over a coordinate-wise trimmed-mean centroid (trim = the configured fault bound `f = ⌊(n−1)/3⌋`) — **independent of which
model wrote the opinions**. That independence is the whole point: the model informs *perception*,
the deterministic BFT core owns the *decision*.
