# Concepts
Nanda Town is a **testing rig for agent protocols**. You bring a protocol —
payments, identity, coordination, trust, anything a swarm of agents has
to agree on — and Nanda Town gives you the rest of the stack, a scenario to
exercise it, and a trace you can validate.
This document explains the pieces that make that work.
## The 12 layers
Nanda Town decomposes the agent stack into 12 Python `Protocol`s (structural
typing — no inheritance required). Every scenario picks one
implementation per layer.
| # | Layer | What it does | Reference default |
|---|---|---|---|
|  1 | **Transport** | Move bytes between agents. | `in_memory` (zero-latency event queue) |
|  2 | **Communication** | Frame messages, request/response semantics. | `nest_native`, `versioned` |
|  3 | **Identity** | Sign / verify per-agent payloads. | `did_key`, `ed25519_rotating` |
|  4 | **Registry** | Publish and discover agent cards. | `in_memory`, `gossip` |
|  5 | **Auth** | Issue, verify, revoke capability tokens. | `jwt` (HMAC-signed, *not* RFC JWT) |
|  6 | **Trust** | Reputation scores, attestations, reports. | `score_average` (running mean) |
|  7 | **Payments** | Quote, pay, verify, refund. | `prepaid_credits`, `streaming`, `escrow` |
|  8 | **Coordination** | Group decisions, task allocation. | `contract_net`, `hotstuff` (BFT) |
|  9 | **Negotiation** | Bilateral bargaining. | `alternating_offers`, `pareto` |
| 10 | **Memory** | Shared K/V with subscribe + CAS. | `blackboard`, `lww_register` |
| 11 | **Privacy** | Encrypt, decrypt, zero-knowledge proofs. | `noop`, `hybrid_x25519` |
| 12 | **Data Facts** | Dataset publish / fetch / ACL. | `datafacts_v1`, `cid_facts` |
All reference defaults are deliberately simplified — testing scaffolding,
not production code. The point is to replace the one layer you care
about and leave the rest as a host.
Each layer has its own page under [`layers/`](layers/) with the method
signatures and a pointer to its reference plugin.
## Scenarios
A scenario is a YAML file that pins together:
- **agents**: how many, what roles, what brain (state-machine or LLM)
- **layers**: which plugin to use for each of the 12 layers
- **task**: what the agents are *trying* to do (`marketplace`, `auction`, …)
- **failures**: drop rate, Byzantine fraction, partitions
- **duration / seed / output**: how long to run, what to seed, where to write the trace
See [`writing-a-scenario.md`](writing-a-scenario.md) for the full
schema. The repository ships **21 built-in scenarios** — see the
[README scenarios table](../README.md#built-in-scenarios) for the full list.
The original seven hackathon scenarios are:
| Name | Stresses |
|---|---|
| `marketplace` | payments · trust · registry · negotiation under bilateral price discovery |
| `auction` | coordination + multi-round messaging |
| `voting` | tally correctness, no double-voting |
| `consensus` | quorum agreement (default 2/3, not full BFT) |
| `supply_chain` | multi-hop reliability under drop / partition |
| `reputation` | trust under probabilistically-cheating agents |
| `shell_marketplace` | same as marketplace, but agents are LLM-driven (Tier 2) |
## Plugins
A plugin is a Python package that implements one of the 12 layer
interfaces. Nanda Town discovers plugins via `importlib.metadata` entry points
under the group `nest.plugins.<layer>`:
```toml
[project.entry-points."nest.plugins.payments"]
my_scheme = "my_pkg.module:MyClass"
```
When a scenario says `payments: my_scheme`, the
[`PluginRegistry`](../packages/nest-core/nest_core/plugins.py) looks up
that entry point (or a built-in fallback) and instantiates it. Because
layer interfaces are `typing.Protocol`, your class doesn't need to
inherit from anything — it just needs to match the method signatures.
See [`writing-a-plugin.md`](writing-a-plugin.md) for the full walkthrough.
## Fidelity tiers
| Tier | Agent | Scale | Deterministic | Use case |
|---|---|---|---|---|
| **1** | `StateMachineAgent` | 10,000+ | Yes | Protocol correctness, parameter sweeps, regression. |
| **2** *(experimental)* | `ShellAgent` (OpenAI / Anthropic / mock) | 10–100 | No | Emergent behavior of LM agents. Not for benchmarks. |
Tier 2 requires `pip install "nest-core[llm]"` and an
`OPENAI_API_KEY` or `ANTHROPIC_API_KEY` env var. Activate it in YAML
with `agents.brain: shell` and `agents.llm_provider: openai|anthropic|mock`.
There is no Tier 3.
## Determinism — what the clock does
Two things to know that surprise newcomers:
1. **Same seed → identical trace.** The master RNG is seeded once,
   derives a per-agent RNG and a separate failure-injection RNG, then
   replays exactly under the same seed. Use this for regression
   benchmarks.
2. **The default `in_memory` transport is zero-latency.** Messages are
   delivered at `time = now`, so `mean_latency` and `duration` in your
   report will both be `0.0`. The event queue still orders events
   deterministically, so correctness checks are fine — but if you need
   *latency numbers*, agents must call `ctx.schedule(delay, ...)` or
   you must write a transport plugin that introduces per-hop delay.
## Traces
Every run writes a JSONL trace — one event per line, in order. Events
are flat dicts with at least `ts` (logical time), `kind` (`start`,
`send`, `receive`, `stop`), `agent`, and a payload. `nest inspect`,
`nest report`, `nest dashboard`, and `nest_core.validators.validate_trace`
all read the same JSONL.
You can grep, `jq`, diff, or check it into git — it's just text.
## Validators
`nest_core.validators` ships property checks for each scenario. They're
intentional **property checks**, not blanket "did the scenario run?"
assertions. Read the table in [the README](../README.md#validators) for
what each one verifies. Passing validators are regression signals, not a
formal proof of protocol correctness.
