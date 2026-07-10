[![PyPI](https://img.shields.io/pypi/v/nest-core.svg)](https://pypi.org/project/nest-core/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/projnanda/nandatown/actions/workflows/ci.yml/badge.svg)](https://github.com/projnanda/nandatown/actions/workflows/ci.yml)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-orange.svg)]()



# Nanda Town


**You have an agent protocol. Nanda Town tells you whether it actually works.**

You wrote a payments scheme, an identity scheme, a coordination scheme, a
trust scheme — something a fleet of agents has to agree on. Nanda Town is the
test rig: it spins up a swarm, plugs your protocol into a 12-layer agent
stack, runs them through a scenario (marketplace, auction, voting,
consensus, supply chain, reputation), and gives you a trace you can grep,
diff, and validate against properties you care about.

It is a **testing tool first**, a simulator second.

```bash
pip install "nest-core[plugins]"
nest run marketplace
```

That's the whole "hello world". No clone, no path, no setup.

> **Before you push** (contributors only): run `make ci-local`. It runs the
> exact CI command sequence — `uv sync`, `ruff check`, `ruff format --check`,
> `pyright`, `pytest -v` — and hard-fails on the first red command. See the
> [Definition of Done](CONTRIBUTING.md#definition-of-done) in `CONTRIBUTING.md`.

---

## Table of Contents

- [Hackathon](#hackathon)
- [Install](#install)
- [The 60-second tour](#the-60-second-tour)
- [Test your own protocol](#test-your-own-protocol)
- [Built-in scenarios](#built-in-scenarios)
- [The 12 layers](#the-12-layers)
- [Validators](#validators)
- [Fidelity tiers](#fidelity-tiers)
- [Determinism &amp; what the clock does](#determinism--what-the-clock-does)
- [Limitations](#limitations)
- [Scoreboard](#scoreboard)
- [Contributing](#contributing)
- [Citation](#citation)
- [License](#license)

---

## Hackathon

Nanda Town is hosting a month-long open hackathon. Pick one undersolved
problem from the 12-layer stack, ship a plugin or scenario or
validator that fixes it, prove it works under adversarial conditions.
Every submission is scored by an automated judge panel along six
dimensions (correctness, test rigor, API fit, docs, novelty, persona
fidelity), each on a 1-5 scale.

- [Charter](docs/hackathon/charter.md) — the participant brief: what
  to build, the rules, branch naming.
- [Problems](docs/hackathon/problems/) — the 10 open problems, each
  with motivation, success criteria, anti-patterns, and the
  reference files you'll touch.
- [Judging](docs/hackathon/judging.md) — the six-dimension rubric
  and how the scoreboard works.

If this is your first time here, read the charter first. Scoreboard
details and judge-panel internals are in the
[Scoreboard](#scoreboard) section below.

---

## Install

```bash
pip install "nest-core[plugins]"
```

That brings in the reference implementations for all 12 layers, the CLI,
and the seven built-in scenarios. Optionally:

```bash
pip install "nest-core[llm]"        # adds nest-shell for Tier 2 (LLM) agents
pip install "nest-core[full]"       # plugins + llm
```

Verify:

```bash
nest doctor
```

You should see `7/7 checks passed`. If you don't, the message tells you
what's missing.

---

## The 60-second tour

You don't need to clone the repo. The seven reference scenarios ship
inside the wheel.

```bash
# What's in the box
nest scenarios list

# Run one
nest run marketplace

# Look at the trace
nest inspect ./traces/marketplace.jsonl

# Get a metrics report (HTML)
nest report ./traces/marketplace.jsonl -o report.html

# Open the interactive dashboard
nest dashboard ./traces/marketplace.jsonl
```

Every `nest run <name>` writes a JSONL trace to `./traces/<name>.jsonl`.
Same seed → byte-identical trace, every time.

> **Read this if `nest run scenarios/marketplace.yaml` errors out:** that
> command only works *inside a clone of this repo* — the `scenarios/`
> directory isn't installed by pip. Use `nest run marketplace` (a built-in
> name) or copy a built-in out to edit:
> `nest scenarios cp marketplace .`

---

## Test your own protocol

This is the loop Nanda Town is for. You have a protocol; you want to know if
it survives 50 agents, a 5% message-drop rate, and a few Byzantine
peers.

### 1. Pick the layer your protocol slots into

```
transport · comms · identity · registry · auth · trust ·
payments · coordination · negotiation · memory · privacy · datafacts
```

Say you're testing a new **payments** scheme.

### 2. Implement the layer interface

```python
# my_payments/plugin.py
from nest_sdk import (
    Payments, AgentId, Money, PaymentRef, Receipt, Quote,
    ServiceRef, PaymentStatus,
)

class MyPaymentProtocol(Payments):
    async def quote(self, service: ServiceRef) -> Quote: ...
    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt: ...
    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus: ...
    async def refund(self, ref: PaymentRef) -> None: ...
```

### 3. Register it as a plugin

```toml
# pyproject.toml
[project.entry-points."nest.plugins.payments"]
my_scheme = "my_payments.plugin:MyPaymentProtocol"
```

Install it: `pip install -e .`

### 4. Point a scenario at it

```bash
# Get a scenario you can edit
nest scenarios cp marketplace .

# In marketplace.yaml, change one line:
#   payments: prepaid_credits
# to:
#   payments: my_scheme
```

### 5. Run it and compare

```bash
nest run marketplace.yaml -o ./traces/with-prepaid.jsonl    # baseline
# edit marketplace.yaml to flip back to your scheme
nest run marketplace.yaml -o ./traces/with-mine.jsonl

nest report ./traces/with-prepaid.jsonl -o ./report-baseline.html
nest report ./traces/with-mine.jsonl    -o ./report-mine.html

# Or assert properties programmatically:
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/with-mine.jsonl'), 'marketplace'):
    print(('PASS' if r.passed else 'FAIL'), r.name, r.detail)
"
```

That's the whole loop. Pick a layer, plug in your implementation, point
a scenario at it, watch what changes in the trace, run validators
against the trace. Repeat with `failures.message_drop: 0.05`, with 10×
more agents, with a Byzantine fraction — the same flow.

You can do this for any of the 12 layers. Trust, coordination, identity,
auth — all of them follow the same recipe.

---

## Built-in scenarios

Each one stresses a different part of the stack. Open them with
`nest scenarios show <name>` or copy them out with `nest scenarios cp <name> .`.

| Scenario | Agents | What it stresses |
|---|---|---|
| `marketplace` | 50 buyers, 50 sellers | Payments · trust · registry · negotiation under bilateral price discovery. |
| `auction` | 1 auctioneer + 19 bidders | Coordination + multi-round messaging; "the highest bid wins" is checked as a property. |
| `voting` | 1 proposer + 1 coordinator + 18 voters | Simple majority. Properties: every vote counted, no double-voting, tally matches. |
| `consensus` | 1 leader + 19 followers | Quorum agreement (default 2/3). Not a full BFT — useful for testing quorum-shaped protocols. |
| `supply_chain` | 4 (supplier → manufacturer → distributor → retailer) | Multi-hop message reliability under drop / partition. |
| `reputation` | 16 honest + 4 malicious + 1 observer | Trust layer under adversarial agents that cheat probabilistically. |
| `shell_marketplace` | 3 buyers + 3 sellers (LLM-backed) | Same as marketplace but agents are LLM-driven via `nest-shell`. Non-deterministic (Tier 2). |

Failure injection is per-scenario, edit the YAML:

```yaml
failures:
  message_drop: 0.05               # 5% of messages dropped
  byzantine_agents: 0.10           # 10% of agents send garbled messages
  network_partition:
    groups: [["agent-0","agent-1"], ["agent-2","agent-3"]]
```

---

## The 12 layers

Every layer is a Python `Protocol` (structural typing). Plugins are
resolved by name via entry points or a built-in default.

| # | Layer | Interface | Default plugin |
|---|---|---|---|
|  1 | Transport     | `Transport`     | `in_memory` (in-process event queue; no network I/O) |
|  2 | Communication | `CommsProtocol` | `nest_native` (JSON envelope, base64 payload) |
|  3 | Identity      | `Identity`      | `did_key` (deterministic public-key signatures for simulation; not Ed25519) |
|  4 | Registry      | `Registry`      | `in_memory` (dict lookup, no persistence) |
|  5 | Auth          | `Auth`          | `jwt` (HMAC-SHA256 token; not RFC JWT) |
|  6 | Trust         | `Trust`         | `score_average` (running mean reputation; no Sybil resistance) |
|  7 | Payments      | `Payments`      | `prepaid_credits` (in-memory ledger) |
|  8 | Coordination  | `Coordination`  | `contract_net` (FIPA: propose · bid · resolve · commit) |
|  9 | Negotiation   | `Negotiation`   | `alternating_offers` (Rubinstein, with patience discount) |
| 10 | Memory        | `Memory`        | `blackboard` (shared KV, subscribe, CAS) |
| 11 | Privacy       | `Privacy`       | `noop` (stub passthrough) |
| 12 | Data Facts    | `DataFacts`     | `datafacts_v1` (dataset publish · fetch · ACL) |

All defaults are **reference implementations for testing**, not
production-ready. That is the point: you replace the layer you care about
with your real implementation and use the rest as a host.

---

## Validators

`nest_core.validators` ships property checks for each scenario. They
read a JSONL trace and verify protocol-level invariants — not just
message counts.

```python
from pathlib import Path
from nest_core.validators import validate_trace

for r in validate_trace(Path("traces/auction.jsonl"), "auction"):
    print(f"{'PASS' if r.passed else 'FAIL'}: {r.name} — {r.detail}")
```

| Scenario | Validator checks |
|---|---|
| Auction | Winner has the highest bid; exactly one winner per item; every bidder is notified. |
| Voting | Announced tally matches the count; every vote counted; no double-voting. |
| Consensus | Committed rounds have ≥ 2/3 accepts; only proposed values committed; ≤ 1 commit per round. |
| Supply chain | Delivered goods trace through all four hops; no materials lost. |
| Reputation | Cheaters get bad reports; agents with score ≤ −3 are warned. |
| Marketplace | No double-sell (same product to two buyers); every buy answered; sold price matches the offer. |

> **Important.** Validators are property *checks*, not blessings of the
> bundled scenarios. They inspect trace evidence and can still only verify
> properties encoded in the trace. Treat a passing validator as a regression
> signal, not a proof of protocol correctness.

---

## Fidelity tiers

| Tier | Agent | Clock | Scale | Deterministic | Use case |
|---|---|---|---|---|---|
| **1** | State-machine (`StateMachineAgent`) | Logical event ordering — see below | 10,000+ | Yes | Protocol correctness, parameter sweeps, regression. |
| **2** *(experimental)* | LLM-backed (`ShellAgent`) — OpenAI / Anthropic / mock | Same as Tier 1 | 10–100 | No | Exploring emergent behavior of LM agents. Not for benchmarks. |

Tier 2 needs `pip install "nest-core[llm]"` and an API key in
`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. Use `agents.brain: shell` and
`agents.llm_provider: anthropic|openai|mock` in the scenario YAML.

---

## Determinism &amp; what the clock does

Two things to know that aren't obvious:

1. **Same seed → identical trace.** The master RNG is seeded once,
   derives a per-agent RNG and a separate failure-injection RNG, and
   replays exactly under the same seed. You can use that for regression
   benchmarks.
2. **The default transport is zero-latency.** The bundled `in_memory`
   transport delivers at `time = now`, so the virtual clock stays at
   `0.0` and `mean_latency` / `duration` will both be `0.0` in your
   trace. The event queue still orders events deterministically, so
   *correctness* tests are fine. Latency *numbers* become meaningful
   only when agents use `ctx.schedule(delay, ...)` or you write a
   transport plugin that introduces per-hop delay.

---

## Limitations

- **Reference plugins are deliberately simplified.** They're testing
  scaffolding, not production code. Deterministic simulation signatures,
  no-op privacy, in-memory ledger, etc.
- **Reference scenarios are minimal baselines.** They check whether
  agents *interact*, not whether a real implementation of the protocol
  *is correct*. That's what your plugin is for.
- **Single process.** No distributed execution.
- **In-memory transport only out of the box.** No TCP, gRPC, or HTTP
  yet.
- **Tier 2 is non-deterministic.** Don't use it for benchmarks.

---

## Scoreboard

> Live scoreboard: [`docs/hackathon/scores.json`](docs/hackathon/scores.json) — machine-readable scores for every open hackathon PR. A marketplace UI on top of this file is coming.

The judge panel lives in [`scripts/judge/`](scripts/judge/):

- [`scripts/judge/rubric.md`](scripts/judge/rubric.md) — the rubric prompt (versioned).
- [`scripts/judge/judge_pr.py`](scripts/judge/judge_pr.py) — score one PR with N parallel judges via the Anthropic API, with prompt caching on the rubric.
- [`scripts/judge/run_all.py`](scripts/judge/run_all.py) — CLI that scores every open `hackathon/*` PR and writes the scoreboard JSON. Idempotent on HEAD SHA.

Re-run the full scoreboard with three live Opus judges per PR:

```bash
export ANTHROPIC_API_KEY=...
uv run python -m scripts.judge.run_all --output docs/hackathon/scores.json
```

Without an API key the CLI falls back to deterministic mock judges so the
schema is exercised even in CI. See the in-repo PR description for the
full cost model and how to reproduce.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding
standards, and how to add scenarios or layer plugins.

Issues and pull requests are welcome at
[github.com/projnanda/nandatown](https://github.com/projnanda/nandatown).

---

## Citation

```bibtex
@software{nest2026,
  title  = {Nanda Town},
  author = {MIT Media Lab},
  year   = {2026},
  url    = {https://github.com/projnanda/nandatown},
  license = {Apache-2.0}
}
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
