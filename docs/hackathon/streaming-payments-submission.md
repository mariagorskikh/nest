# Streaming payments scenario factory

**Problem:** `03-payments-streaming-x402` (difficulty: easy)
**Layer:** payments
**Branch:** `hackathon/<your-handle>-streaming-payments`

---

## What the problem asked for

The `StreamingPayments` plugin (per-tick metered payments with mid-stream cancellation) and its three adversarial validators were already present in the repo but unrunnable — there was no scenario factory to wire them together. Running `nest run streaming_payments` crashed immediately:

```
KeyError: "No scenario factory registered for 'streaming_payments'"
```

The scenario YAML, the plugin code, and all three validators existed. The missing piece was the agent factory that actually exercises the streaming API.

---

## What I built

Two files changed, one file added.

### 1. `packages/nest-core/nest_core/scenarios_builtin/streaming_payments.py` (new)

A scenario factory with two agent types:

- **`StreamingBuyerAgent`** — on start, picks a random seller and calls `open_stream(rate_per_tick=10, max_total=1000)`. Pre-schedules all 100 tick self-messages upfront so the 5% message-drop rate does not silently kill the heartbeat. Each tick calls `tick_stream` and emits `payment_debited` / `payment_credited` events into the trace. Closes the stream (via `close_stream`) when `max_total` is exhausted or in `on_stop` if the simulation ends first.

- **`StreamingSellerAgent`** — passive. Acks `stream_open` and `stream_close` messages so the buyer knows the seller is reachable.

The factory mirrors the marketplace factory's shared-ledger pattern: all agents share a single `balances` dict and `streams` dict, so the conservation invariant (total debited = total credited) holds across the whole simulation, not just per-agent.

### 2. `packages/nest-core/nest_core/sim/simulator.py` (small addition)

Added `ctx.emit(event: dict)` to `_SimAgentContext`. The three streaming validators read structured records directly from the JSONL trace (`event_type: stream_opened`, `kind: payment_debited`, etc.). The `AgentContext` protocol had no way for agents to write custom trace records, so `emit` was added as a concrete method on the implementation class. Agents access it via `getattr(ctx, "emit", None)` so it degrades gracefully if called against a mock context.

### 3. `packages/nest-core/nest_core/scenarios.py` (two lines)

Registered `streaming_payments` and `streaming_payments_partition` in `_try_load_builtin`.

---

## Commands

```bash
# Run the scenario
uv run nest run streaming_payments

# Validate the trace
uv run python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/streaming_payments.jsonl'), 'streaming_payments'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"

# Full gate (must all pass before opening a PR)
uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest -v
```

---

## Before and after

**Before:**

```
Running scenario: streaming_payments
  agents: 10  seed: 42  ticks: 10000
KeyError: "No scenario factory registered for 'streaming_payments'"
```

**After:**

```
Running scenario: streaming_payments
  agents: 10  seed: 42  ticks: 10000
Trace written to: traces/streaming_payments.jsonl

PASS streaming_conservation          - conservation verified: 4740 total flow
PASS streaming_no_drain_after_close  - verified 5 streams, no drain-after-close
PASS streaming_no_overbill_on_partition - verified 5 streams across 5 partition edges, no over-bill

541 passed, 0 type errors
```

The trace is deterministic: same seed (42) produces the same JSONL byte-for-byte on every run.

---

## Limits and honest caveats

- **One stream per buyer.** Each buyer opens exactly one stream for the duration of the simulation. The problem description allows multi-stream behaviour; this submission does not exercise it.

- **Sellers are passive.** Sellers do not open counter-streams, check buyer reputation, or reject buyers. The scenario is a minimal bilateral test of the streaming API, not a full marketplace.

- **`ctx.emit` is not on the `AgentContext` Protocol.** It is a concrete method on `_SimAgentContext`. Any test that mocks `AgentContext` directly will not have it. The `_emit` helper degrades gracefully (`getattr` with a `None` fallback), so the scenario runs without it — it just produces no structured trace events, which means validators pass vacuously. This is a known gap.

- **Tick pre-scheduling.** All 100 tick self-messages are pushed to the event queue at simulation start. This keeps them from being dropped by the message-drop rate (which also applies to scheduled self-messages in the current simulator). The side effect is a larger initial event queue. It is not a problem at the scale of this scenario (5 buyers × 100 ticks = 500 events), but it would not scale cleanly to thousands of agents with long-running streams.
