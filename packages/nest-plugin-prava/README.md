# nest-plugin-prava

A NANDA Town **payments layer** plugin that moves real money in the Prava
Agentic Payments Sandbox, bounded by a human-granted policy.

Agents quote, pay, and verify. When policy or funding says no, the plugin
says no — with the reason, the failing clause, and no Prava call made.

```python
payments = PravaPayments(AgentId("agent_a"), console_url="http://localhost:3000")

quote = await payments.quote(ServiceRef("gpu-compute-small"))   # merchant's price
receipt = await payments.pay(AgentId("agent_b"), quote.price, PaymentRef("p1"))
assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
```

## Two locks stand between an agent and money

This adapter exists because "autonomous agent with a credit card" is the
wrong shape. Authority is split in two:

- **LOCK 2 — BIOMETRICS, once per envelope.** The owner approves a bounded
  *envelope* with their passkey: merchant-scoped, per-charge-capped, one
  charge per payment cycle, enforced by the Visa network. This happens
  **once, by a human, before the simulation runs.** The plugin never
  automates, simulates, or bypasses a passkey.
- **LOCK 1 — POLICY, on every single charge.** A deterministic arbiter
  evaluates every proposed charge against a signed policy mandate
  (counterparty allowlist, per-charge cap, cumulative cap, attribute
  constraints). No LLM sits in the decision path. Then a router selects
  which envelope funds it.

Inside that approved envelope the agent transacts autonomously. To exceed
policy it must ask a human. To exceed the portfolio it needs a fingerprint
again.

## Concepts

| Term | Meaning |
|---|---|
| **Policy mandate** | A signed, immutable clause tree the arbiter evaluates on every charge. Amendments are *new* mandates that supersede the old, recorded in the ledger. |
| **Envelope** | One Prava mandate: a merchant-scoped, per-charge-capped standing authorization created by one passkey approval. |
| **Cycle** | Visa enforces **one charge per envelope per payment cycle** (weekly here). This is a network rule, not a preference. |
| **Portfolio** | Several envelopes approved together. When envelope A's cycle is spent, the router moves to B — so a second autonomous charge needs no new human touch. |
| **Ledger** | Append-only record. Every cent is attributed to a mandate clause path *and* an envelope. `verify_payment` reads this, not a cache. |

Cycle eligibility is checked in the Quartermaster ledger **before** any
Prava call, so a second same-cycle draw is never attempted.

## Installation

Requires Python 3.12+ (NANDA Town's floor).

```bash
pip install -e .            # from this directory
nest plugins list | grep payments
```

Registered via entry point:

```toml
[project.entry-points."nest.plugins.payments"]
prava = "nest_plugin_prava.plugin:PravaPayments"
```

Select it in a scenario:

```yaml
layers:
  payments: prava
```

A ready-made scenario is included at
[`scenarios/prava_marketplace.yaml`](scenarios/prava_marketplace.yaml).

## Configuration

| Option | Env var | Default | Meaning |
|---|---|---|---|
| `console_url` | `QUARTERMASTER_CONSOLE_URL` | `http://localhost:3000` | Quartermaster console base URL. |
| `service_catalog` | — | 3 GPU services | Maps a `ServiceRef` to a capacity need. |
| `timeout_seconds` | — | `120.0` | HTTP timeout; settlement is a multi-hop call. |
| `client` | — | — | Inject an `httpx.AsyncClient` (used by the offline tests). |

`initial_balance` and `balances` are accepted so the plugin is a drop-in
for the bundled `marketplace` scenario, and are **ignored**: funds live in
passkey-approved envelopes, not in a simulated balance.

Built-in services: `gpu-compute` (80GB, 4h), `gpu-compute-small`
(40GB, 2h), `gpu-compute-xl` (80GB, 6h), plus a dynamic
`gpu:<vram_gb>:<hours>[:<budget_cents>]` form.

The console needs `PRAVA_BASE_URL` and `PRAVA_SECRET_KEY` (a `sk_test_`
sandbox key). This plugin never sees card data: Prava mints a one-time,
merchant-scoped credential per charge, and only the last four digits are
ever rendered or logged.

## Protocol behaviour

| Method | Behaviour |
|---|---|
| `quote(service)` | Asks the merchant through the console registry. The price is the merchant's, computed by its published rounding rule, and is returned unmodified with `run_id` / `quote_id` in `metadata`. |
| `pay(to, amount, ref)` | Arbiter evaluates → router selects an envelope with cycle capacity → Prava mints a one-time credential → merchant is paid → charge reported → ledger appended. Requires a prior `quote()` at that exact amount. |
| `verify_payment(ref)` | Reads the append-only ledger. `CONFIRMED` only when a ledger row backs the payment; `PENDING` if charged but not yet recorded; `FAILED` otherwise. |
| `refund(ref)` | **Always raises** `PravaPaymentError("REFUND_NOT_SUPPORTED")`. See Limits. |

### Failure handling

Every refusal raises `PravaPaymentError` (a `ValueError` subclass, so
existing scenarios catch it) carrying `.code`, `.message`, and `.details`:

| Code | Cause | Prava calls made |
|---|---|---|
| `POLICY_REFUSE` | A hard clause failed. The agent may not proceed and may not ask. | 0 |
| `POLICY_NEEDS_HUMAN` | Only escalatable clauses failed (e.g. per-charge cap). The agent must ask its owner. | 0 |
| `NO_ENVELOPE_CAPACITY` | No envelope matched the merchant with cycle capacity. Fails closed. | 0 |
| `NO_QUOTE` / `AMOUNT_MISMATCH` | The caller tried to pay a price no merchant quoted. | 0 |
| `DUPLICATE_REF` | That `PaymentRef` already settled. | 0 |
| `SETTLEMENT_FAILED` | Prava or the merchant failed mid-settlement. Surfaced verbatim, never retried blindly. | 1 attempt |
| `REFUND_NOT_SUPPORTED` | Refunds are out of scope. | 0 |

`POLICY_NEEDS_HUMAN` details include `failingClausePath`, `onFail`, and
`mandateId`, so a scenario can escalate intelligently instead of retrying.

## Tests

```bash
pytest tests/test_plugin_contract.py -v     # offline, no console, no money
QUARTERMASTER_CONSOLE_URL=http://localhost:3000 pytest -v   # + live sandbox
```

- **`test_plugin_contract.py`** — offline. Protocol conformance
  (`isinstance(plugin, Payments)`), merchant-priced quotes, refusal
  mapping, ledger-backed verification, refund refusal. Runs in CI with no
  network.
- **`test_sandbox_live.py`** — real sandbox money. Skips unless a console
  is reachable. The happy path costs **one** sandbox charge and needs an
  envelope with cycle capacity; the failure case costs **zero**. Ids for
  each run are written to `sandbox-evidence.json`.

## Scenario run

`scenarios/prava_marketplace.yaml` drives the `policy_commerce` scenario
(in `nest_plugin_prava/scenario.py`), which is layer-agnostic: it runs
against `prepaid_credits` with no console and no money, and against
`prava` for real settlement.

```bash
QUARTERMASTER_CONSOLE_URL=http://localhost:3000 nest run scenarios/prava_marketplace.yaml
nest inspect traces/output.jsonl
```

Two buyers, two outcomes, one run:

| Agent | Service | Outcome |
|---|---|---|
| `buyer-0` | `gpu-compute-small` | Settled `$18.00`, Prava txn `txn_01KZ1VWC3YVWG94VFDX1H89PK7`, envelope `env_a_1785695413265`, merchant order `ord_02d56bb3-930`, ledger `autonomous=1` |
| `buyer-1` | `gpu-compute-xl` | Refused: `POLICY_NEEDS_HUMAN`, "amount $70.50 exceeds cap $47.00", clause `root.all_of[3]`, zero Prava calls |

Trace: `traces/prava_marketplace.jsonl` (16 events).

The refusal is not a failed run. It's a bounded agent doing the correct
thing when a price exceeds what its owner authorised.

## Verified sandbox transactions

Recorded by `test_sandbox_live.py` on 2 Aug 2026 against the Prava
sandbox. Full records in [`sandbox-evidence.json`](sandbox-evidence.json).

**Successful settlement** (`test_happy_path_settles_in_sandbox`)

| Field | Value |
|---|---|
| Prava transaction | `txn_01KZ1TGNA0VPNE1BSYCK5C7B9T` |
| Amount | `$18.00 USD` |
| Envelope | `env_a_1785693994048` → Prava mandate `mdt_01KZ1TFWBV1PR1QEYFQ45T9Y26` |
| Merchant order | `ord_781e1da2-ab9` |
| Price rule | `ceil(2h x 900c/GPU-h) = 1800c` (the merchant's own) |
| Ledger | `autonomous=1`, all seven clause paths attributed |
| Human touches | 0 during settlement; 1 passkey earlier, to approve the envelope |

**Refusal** (`test_failure_case_policy_refusal_costs_nothing`)

| Field | Value |
|---|---|
| Error code | `POLICY_NEEDS_HUMAN` |
| Detail | `amount $70.50 exceeds cap $47.00` |
| Failing clause | `root.all_of[3]` on mandate `qm_mdt_policy_v2` |
| Prava calls made | **0** — the arbiter refuses before the network is touched |

## Limits

- **No refunds.** Prava exposes none on the mandate-charge surface used
  here. `refund()` raises rather than pretending to succeed.
- **One charge per envelope per cycle**, enforced by the Visa network.
  Concurrency within a cycle comes from approving more envelopes, not
  from retrying.
- **A passkey cannot be automated.** Envelopes must be approved by a human
  before a simulation can spend. That is the design, not a gap.
- **Sandbox test cards are rate-limited** (30 transactions/day) and
  per-team. `FETCH_AGENTIC_CREDS_ERROR` from Prava means the card is
  exhausted, not that the adapter is broken.
- **Amounts are integer minor units** (cents), currency `USD`. Currency
  mismatches fail closed at the arbiter.
- Settlement is `SANDBOX` unless the console runs in `production` mode;
  the environment is labelled on every surface and in the audit bundle.

## How it fits together

```
NANDA agent
  └── PravaPayments (this plugin)
        └── Quartermaster console  ── arbiter (LOCK 1) ── router ── ledger
              └── Prava sandbox    ── envelope mandate (LOCK 2, passkey)
                    └── Visa network (per-charge cap, one charge per cycle)
```

Licence: Apache-2.0.
