# Writing a scenario

A scenario YAML pins together: how many agents, which plugin to use for
each of the 12 layers, what task they run, what failures to inject, how
long to run, and where to write the trace.

The fastest way to get a valid scenario is to copy a built-in one and
edit it:

```bash
nest scenarios cp marketplace ./my.yaml
nest run ./my.yaml
```

This page is the reference for what each field does.

## Full schema, with defaults

```yaml
# SPDX-License-Identifier: Apache-2.0
name: my_scenario                   # required, becomes the trace filename if `output.trace` is unset
description: "What this tests."     # optional, free text

tier: 1                             # 1 (state-machine) or 2 (LLM-backed). No tier 3.
seed: 42                            # required; same seed → identical trace

agents:
  count: 100                        # total number of agents
  brain: state-machine              # or `shell` for tier 2
  # llm_provider: anthropic         # required only when brain=shell. one of: anthropic | openai | mock
  roles:                            # optional; sums must equal `count`
    - name: buyer
      count: 50
    - name: seller
      count: 50

layers:                             # any layer left out uses the built-in default
  transport: in_memory
  comms: nest_native
  identity: did_key
  registry: in_memory
  auth: jwt
  trust: score_average
  payments: prepaid_credits
  coordination: contract_net
  negotiation: alternating_offers
  memory: blackboard
  privacy: noop
  datafacts: datafacts_v1

task:
  type: marketplace                 # one of the built-in task types (see below)
  config:                           # task-specific knobs, free-form dict
    rounds: 10
    catalog_size: 200

failures:                           # all optional
  message_drop: 0.05                # P(drop) per send
  byzantine_agents: 0.10            # fraction of agents that misbehave
  network_partition:
    groups:
      - ["agent-0", "agent-1"]
      - ["agent-2", "agent-3"]
  partition_heal_at_tick: 1800       # optional; heal partition at this tick (see bft_consensus_partition)

middleware:                         # optional; composable message hooks
  - name: observability
  - name: auth_scope
    config:
      required_scope: read

workers: 1                          # 1 = single process; >1 = distributed (needs NEST_HTTP_SHARED_SECRET)
worker_bind: "127.0.0.1"            # bind address for worker HTTP bridges
worker_hosts: []                    # advertise hosts for multi-machine routing
worker_mode: auto                   # auto | manual

distributed:                        # optional distributed options
  shared_registry: false            # coordinator-hosted registry RPC across workers

duration: "ticks: 10000"            # NOTE: string, not nested dict. Format: "ticks: N"

metrics:                            # which metrics to compute by default
  - success_rate
  - mean_latency
  - message_count

output:
  trace: ./traces/my_scenario.jsonl # where to write the JSONL trace
```

> **Watch the `duration` field.** It looks like it should be a nested
> dict (`duration:\n  ticks: 10000`) but the scenario loader parses it
> as a *string*. Use `duration: "ticks: 10000"` exactly.

## Built-in task types

`task.type` selects an agent factory bundled with `nest-core`:

| `task.type` | What agents do |
|---|---|
| `marketplace` | Buyers send buy requests; sellers price-quote and respond. |
| `auction` | One auctioneer announces; bidders submit bids over multiple rounds. |
| `voting` | A proposer broadcasts; voters reply; a coordinator tallies. |
| `consensus` | A leader proposes a value; followers accept/reject; quorum decides. |
| `supply_chain` | 4-hop chain (supplier → manufacturer → distributor → retailer). |
| `reputation` | Honest + malicious agents; an observer reports cheaters. |
| `shell_marketplace` | Marketplace, but agent decisions come from an LLM (tier 2). |

To build a *new* task type you need to register a factory inside
`nest-core` — see the "Adding a new scenario" section of
[CONTRIBUTING.md](../CONTRIBUTING.md). Custom task types from external
packages aren't supported yet.

## Failure injection

All three knobs in the `failures:` block are evaluated by the simulator
against the failure-injection RNG (separate from per-agent RNGs, so
agents stay deterministic when you toggle failures on/off):

- **`message_drop`** — A float in `[0, 1]`. Each outbound message is
  dropped with this probability.
- **`byzantine_agents`** — A float in `[0, 1]`. That fraction of agents
  is flipped into a Byzantine mode where they send garbled payloads.
- **`network_partition.groups`** — A list of lists of agent IDs. Agents
  can only deliver messages to other agents in the same group.
- **`partition_heal_at_tick`** — Optional integer. When set, the simulator
  clears the partition at this tick and emits a `partition_healed` trace
  event. Works in both single-process and distributed (`workers > 1`) runs.
  See [`bft_consensus_partition.yaml`](../scenarios/bft_consensus_partition.yaml).

## Middleware

Optional composable hooks on outbound (`send` / `broadcast`) and inbound
(`receive`) message paths. Resolved by name from built-ins or the
`nest.middleware` entry-point group.

| Name | Purpose |
|---|---|
| `resilience` | Isolate `on_message` failures |
| `observability` | Structured per-message logging |
| `auth_scope` | Enforce bearer tokens with a required scope; **denies** when auth plugin is missing |
| `latency` | Deterministic per-hop delivery delay |

```yaml
middleware:
  - name: auth_scope
    config:
      required_scope: read
```

When `auth_scope` is enabled, ensure `layers.auth: jwt` (or your auth
plugin) is configured — otherwise inbound messages are denied with
`auth_plugin_missing`.

## Distributed execution fields

| Field | Default | Purpose |
|---|---|---|
| `workers` | `1` | Number of worker partitions; `> 1` requires `NEST_HTTP_SHARED_SECRET` |
| `worker_bind` | `127.0.0.1` | Bind address for worker HTTP bridges |
| `worker_hosts` | `[]` | Hostnames other workers use to reach each bridge |
| `worker_mode` | `auto` | `auto` (spawn subprocesses) or `manual` (remote launch) |
| `distributed.shared_registry` | `false` | Coordinator-hosted registry RPC |

See [`distributed.md`](distributed.md) for multi-host launch, HTTP auth,
and environment variables.

## Tier 2 (LLM-backed) scenarios

```yaml
tier: 2
agents:
  count: 6
  brain: shell
  llm_provider: anthropic     # anthropic | openai | mock
  roles:
    - name: buyer
      count: 3
    - name: seller
      count: 3
```

Requires `pip install "nest-core[llm]"` and an
`OPENAI_API_KEY` or `ANTHROPIC_API_KEY` env var. Tier 2 is
non-deterministic — same seed will *not* give the same trace. Use it
for exploring emergent behavior, not for benchmarks.

## Worked example: stress-test a new payments scheme

```bash
# Start from the marketplace baseline
nest scenarios cp marketplace ./bench.yaml

# Edit bench.yaml:
#   layers.payments: flat_fee
#   failures.message_drop: 0.05
#   agents.count: 200
#   agents.roles: [{name: buyer, count: 100}, {name: seller, count: 100}]

nest run ./bench.yaml -o ./traces/bench.jsonl
nest report ./traces/bench.jsonl -o bench-report.html

python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/bench.jsonl'), 'marketplace'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```

Same seed → repeatable. Tweak one knob at a time and diff the reports.
