# ChainAIM Outcome-Verified Settlement (`payments` / `outcome_verified_settlement`)

ChainAIM contribution for Nanda Town hackathon **Problem 03 — Payments / Streaming (x402)**
(`docs/hackathon/problems/03-payments-streaming-x402.md`).

All code here is **new** and namespaced under `chainaim/`. No vanilla file is changed
except a small number of strictly-additive registry seams (see the conceptual design doc).

## What this is

A payments plugin that drains funds from a payer to a payee **one logical tick at a
time**, capped at `max_total`, where **either party can close the stream at any tick**
and the unused remainder is never spent — and where **each tick settles only after a
verifiable outcome is gated**, not merely because time elapsed. It satisfies the existing
`nest_core.layers.payments.Payments` protocol, so `quote` / `pay` / `verify_payment` /
`refund` keep working; `pay` is exactly a one-tick stream that drains the whole amount.

## Why "outcome-verified settlement", not "streaming"

"Streaming" names the *mechanism* — a per-tick drain. The contribution here is the
*property*: a unit settles only when its outcome is verified, and the adversarial
validators reconcile billed-vs-verified **from the trace**. Keying the plugin
`outcome_verified_settlement` (rather than `streaming`) keeps it from reading as "a faster
`prepaid_credits`" or "a renamed escrow": the key names the invariant the validators
enforce — `billed ≤ rate × verified units` — instead of the drain loop that happens to
implement it. `("payments","outcome_verified_settlement")` is the canonical
registration. The Problem 03 spec's suggested key `("payments","streaming")` is already
taken by merged upstream PR #21,
so per the hackathon's anti-duplicate rule this contribution registers under the
distinct `outcome_verified_settlement` key (the spec sanctions an alternative name such
as `per_tick_metered`).

## The verification ladder (L1 / L2 / L3)

Settlement is gated by a pluggable `Gate` (`scenarios_builtin/chainaim/gates.py`:
`Gate.from_name`, `AckReceivedGate`, `ChecksumGate`, `EvaluatorGate`). Each rung is
cumulative — it re-checks everything the rung below checks, plus one more thing — and
each has a correct scenario and a runnable buggy variant:

| Rung | Gate config | Checks | Correct (all validators PASS) | Injected bug (one validator FAILS) |
|---|---|---|---|---|
| **L1 — delivery** | `gate: ack_received` (default) | a tick bills on the seller's `ack` | `outcome_verified_settlement.yaml` | `outcome_verified_settlement_overbill.yaml` (`bill_on_send: true`) → `no_overbill` fails |
| **L2 — integrity** | `gate: checksum` | + delivered bytes match the seller's own declared checksum | `outcome_verified_settlement_degrade.yaml` | `outcome_verified_settlement_degrade_billbug.yaml` (`bill_regardless: true`) → `no_overbill_on_failed_verification` fails |
| **L3 — conformance** | `gate: evaluator`, `criterion: reference_match` | + delivered content matches the buyer's *committed* acceptance criterion for THIS unit, not just some real unit's honestly-checksummed bytes | `outcome_verified_settlement_nonconforming.yaml` | `outcome_verified_settlement_nonconforming_billbug.yaml` (`bill_regardless: true`) → `no_overbill_on_failed_verification` fails |

`EvaluatorGate` composes `ChecksumGate` internally (`require_integrity=True`, the
default): an integrity failure short-circuits before the criterion is ever evaluated,
so an L3 pass means delivered AND intact AND conforming. The case L2 alone cannot
catch — and the reason L3 exists — is a seller that delivers a *different, real* unit's
content with an *honest* checksum of what it actually sent: `ChecksumGate` passes (the
bytes match their own claim), `reference_match` fails (wrong unit's content). See
`test_outcome_verified_settlement_b5_checksum_passes_criterion_fails` for the isolated
proof and `test_outcome_verified_settlement_b6_nonconform_checksum_is_honest_at_failing_seq`
for the same proof through the real driver.

The default (L1) gate reproduces the pre-gate delivery-gated billing **byte-for-byte**;
L2 and L3 are additive axes, opted into via `task.config.gate`.

`json_schema` and `artifact_match` are two additional, real, independently unit-tested
criteria in `gates.py` (see `test_outcome_verified_settlement_b7_criteria.py`) —
deliberately not yet wired through `Gate.from_name` / scenario YAML, since they take
parameters the wire-level config doesn't carry in this iteration. `reference_match` is
the only criterion reachable from a scenario today.

## Spec criterion -> where it lives

| Spec criterion | Location |
|---|---|
| Plugin registered `("payments","outcome_verified_settlement")` (distinct key; the spec's suggested `streaming` key is taken by a merged PR) | `nest_core/plugins.py` `_BUILTINS` + `pyproject.toml` entry point (`nest.plugins.payments`) |
| `open_stream(to, rate_per_tick, max_total, ref, *, opened_at_tick=0) -> StreamHandle` | `outcome_verified_settlement.py::OutcomeVerifiedSettlement.open_stream` |
| `close_stream(ref, *, now_tick=None) -> Receipt`, deterministic, any tick | `outcome_verified_settlement.py::OutcomeVerifiedSettlement.close_stream` |
| Drain one tick at a time, capped at `max_total` | `outcome_verified_settlement.py::OutcomeVerifiedSettlement.advance` (idempotent, monotonic, capped) |
| Conservation (debit == credit each step) | enforced inside `advance` (atomic debit/credit); proven by a `hypothesis` total-funds-conservation test |
| `pay` == one-tick full drain | `outcome_verified_settlement.py::OutcomeVerifiedSettlement.pay` |
| `verify_payment` for a half-drained stream | returns `PaymentStatus.STREAMING` (the plugin's `half_open_status`, default `STREAMING`) |
| Stream record keyed by `PaymentRef` | `outcome_verified_settlement.py::StreamHandle` in the `streams` dict |
| Settlement gate seam (`ack_received` default, `checksum` L2, `evaluator` L3) | `scenarios_builtin/chainaim/gates.py` |
| Criterion library (`reference_match` wired; `json_schema`/`artifact_match` unit-tested, not yet wired) | `scenarios_builtin/chainaim/gates.py` |
| Scenario driver + trace grammar | `scenarios_builtin/chainaim/outcome_verified_settlement.py` (`outcome_verified_settlement_factory`) |
| Adversarial validators (4 — spec requires 2) | `nest_core/chainaim/outcome_verified_settlement_validator.py`, registered under `VALIDATORS["outcome_verified_settlement"]` |
| Scenarios: 5×5 base + 5 controls (L1/L2/L3 × correct/bug) | `scenarios/outcome_verified_settlement{,_overbill,_degrade,_degrade_billbug,_nonconforming,_nonconforming_billbug}.yaml` |

## Provenance

The per-tick settlement **semantics** are informed by the `midstream` reference
(a separate off-chain/x402 project): pay only for the delivered
prefix, stop authorizing on close, treat cancellation as a spending bound rather than a
refund. **No code is ported** — `midstream` implements that pattern off-chain; this is
an in-process Python per-tick stream. Only the design idea transfers.

## Threat model

A metered payment stream is a small settlement system, so it is reviewed as one: every
tick moves real value, and the dangerous failure modes are billing faults, not crashes.
Three attacks are in scope. Each has a positive control and a negative control that ships
as a runnable buggy scenario, and every validator reconciles **from the trace**, never
from the plugin's own accounting.

| # | Attack | Invariant that defeats it | Enforced / caught by |
|---|--------|---------------------------|----------------------|
| 1 | **Drain-after-close** — a buggy or hostile plugin keeps debiting after the stream was closed | A closed stream bills nothing further; cumulative drain never exceeds `max_total`; every debited unit is credited in the same step (conservation) | `advance` is a no-op once closed and is capped; `validate_outcome_verified_settlement_no_drain_after_close` flags any metered tick after the close tick or any drain over cap; conservation is proved by a `hypothesis` property test |
| 2 | **Over-bill on partition** (delivery gate) — the payer is network-partitioned mid-stream and a naive plugin bills for ticks the payee never received | Bill only for the delivered prefix: `drained ≤ rate × acks received` | billing is delivery-gated (a tick bills only on the payee's `ack`); `validate_outcome_verified_settlement_no_overbill` reconciles billed-vs-delivered from the trace; the `bill_on_send: true` variant (`_overbill.yaml`) ships the bug this validator fails |
| 3 | **Over-bill on failed verification** (content gate, L2 or L3) — the seller delivers corrupt or nonconforming content and a naive plugin bills anyway | Bill only the verified prefix: `drained ≤ rate × (pass verdicts)` | the content gate emits `gate:<ref>:<seq>:pass\|fail`; `validate_outcome_verified_settlement_no_overbill_on_failed_verification` reconciles drained vs pass-verdicts from the trace (and skips streams that produced no verdicts); the `bill_regardless: true` variant of either the L2 (`_degrade_billbug.yaml`) or L3 (`_nonconforming_billbug.yaml`) scenario ships the bug this validator fails |

Beyond the three attacks the spec requires, a fourth validator,
`validate_outcome_verified_settlement_verdicts_match_committed_criterion`, re-derives
the integrity component of every `gate:pass` verdict directly from the logged bytes and
checksum — never trusting the gate's own claim — so a gate implementation that lies
about passing despite a checksum mismatch is provably caught, not merely assumed honest.
Its scope is deliberately one-directional (a legitimate L3 conformance `fail` is never
flagged, only a dishonest `pass` is) because the trace does not yet commit which
criterion was configured for a stream (`criterion_hash` on the wire is a roadmap item).

Design stance: cancellation is a **spending bound**, not a refund — closing freezes the
bill at the delivered/verified amount and the unused remainder is never authorized. The
validators trust the trace, never the plugin's own accounting, because the threat being
modelled is precisely a plugin whose accounting is wrong.

## Trace grammar (what an auditor reads)

```
stream-open:<ref>:<payer>:<payee>:<rate>:<max_total>:<opened_tick>
tick:<ref>:<seq>:<rate>:<now_tick>                        buyer -> seller (metered request)
ack:<ref>:<seq>                                           seller -> buyer (delivery confirm)
ack:<ref>:<seq>:<chunk_hex>:<declared_checksum>           content gate only (delivered bytes + claim)
gate:<ref>:<seq>:pass|fail                                content gate only (settle verdict)
stream-close:<ref>:<seq>:<drained>:<close_tick>:<reason>
```

The `gate:` line and the extended `ack:` line appear only under a content gate (L2 or
L3); the default (L1) delivery-gated path emits a byte-identical trace to the pre-gate
scenario. L3 (nonconforming) units reuse this exact grammar unchanged — no new trace
lines were needed; the *bytes* the seller sends differ, not the message shape.

## Verification

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest packages/nest-core/tests/chainaim/ -v
```

## Anti-patterns avoided

- **No prepay-and-lie**: every billed unit is a distinct tick drain in `advance`, tied
  to a logical tick.
- **No best-effort close**: `close_stream` is a synchronous state mutation; `advance`
  is a no-op once closed.
- **No `PaymentStatus` bypass**: a `STREAMING` member is added to the enum (the spec
  permits adding) rather than overloading an unrelated status; the plugin's
  `half_open_status` defaults to it.
- **Not a renamed escrow**: this is its own design; the repo has no `htlc_escrow`.
- **No unearned "outcome" claim**: the name became literally true in code (L3
  conformance-gated) in this iteration, not just in prose — see the verification
  ladder above and `test_outcome_verified_settlement_b5_checksum_passes_criterion_fails`.
