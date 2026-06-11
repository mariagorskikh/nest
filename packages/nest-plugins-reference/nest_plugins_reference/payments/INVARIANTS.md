# Streaming Payments — Invariants & Security Model

> *"In agent economies, trust is not assumed — it is proven at every tick boundary."*

## Persona: `payments-engineer`

This plugin is designed with **ledger discipline** — the mindset of a financial
engineer building payment infrastructure for autonomous agents. Every design
decision is documented and defended against the obvious alternative (one-shot
prepaid credits).

## The Double-Entry Bookkeeping Model

StreamingPayments implements a strict double-entry ledger:

```
For every tick drain:
  SUM(debits from payers) == SUM(credits to payees)
```

This is not just tested — it is **proven by construction.** The `drain_tick()`
method contains a single debit→credit loop with no early exits, no conditional
credits without matching debits, and no external state mutations.

## Conservation Invariant

**At every tick boundary, after `drain_tick()` returns:**

```
SUM(all agent balances) == SUM(all agent balances at construction)
```

This invariant is:
1. **Documented** in the class docstring
2. **Exposed** via `total_balance()` for validators to check
3. **Verified** by 3 adversarial validators (drain-after-close, over-bill, conservation)
4. **Fuzzed** across 20 randomized trials, 3 deterministic seeds (42/7/1337)
5. **Stress-tested** with 10 agents, 50 streams, 1000 ticks

## Attack Classes Defended

### 1. Drain-After-Close
**Threat:** Payer closes a stream, but a buggy plugin keeps debiting.
**Defense:** `close_stream()` sets `stream.closed = True`. `drain_tick()` checks
`stream.closed` before every debit. After close, no funds can move.
**Validator:** `validator_drain_after_close()` — FAILS on prepaid_credits (no concept
of closing), PASSES on streaming.

### 2. Over-Bill on Partition
**Threat:** Payer runs out of funds mid-stream. Plugin keeps debiting, causing
negative balance.
**Defense:** `drain_tick()` checks `payer_balance >= debit` before every debit.
If insufficient, the stream silently pauses (no error, no partial debit).
**Validator:** `validator_over_bill_partition()` — payer balance never goes negative.

### 3. Byzantine Drain
**Threat:** Malicious agent opens streams from N victims, delivers zero work,
drains all ticks simultaneously.
**Defense:** Victims observe the drain in real-time (per-tick debits are visible),
close their streams, and preserve their remaining balance. Unused `max_total`
is never spent.
**Validator:** `test_byzantine_drain_attack_victims_can_defend()` — 5 victims
preserve >50% of their balance after closing streams. prepaid_credits would
lose all funds upfront.

### 4. Trust-Gated Rate Limiting (Cross-Layer)
**Threat:** Low-reputation agent opens high-rate streams to drain honest agents.
**Defense:** `TrustAwareStreamingPayments` caps `rate_per_tick` based on the
payer's trust score. This is the architectural bridge to **TrustGuard** (main
event), which provides live ELO reputation scoring, risk assessment, and
denylist enforcement.
**Validator:** `test_trust_aware_low_reputation_agent_rate_limited()` — agent
with trust_score=10 gets rate-capped at 3 regardless of requested rate.

## Why Streaming Over One-Shot Payments

| Property | prepaid_credits | StreamingPayments |
|----------|----------------|-------------------|
| Per-tick billing | ❌ | ✅ |
| Mid-stream cancellation | ❌ | ✅ |
| Unused funds preserved | ❌ | ✅ |
| Byzantine drain resistance | ❌ | ✅ |
| Trust-gated rate limiting | ❌ | ✅ (TrustAware variant) |
| Conservation invariant | Partial | ✅ Proven |
| Zero-balance protection | N/A | ✅ Silent pause |

## Determinism

All tests are deterministic given a seed. Same seed → same trace, every time.
The plugin uses no wall-clock time, no unseeded RNG, and no external API calls
in Tier 1. The trust-aware variant accepts a trust_score parameter rather than
calling an external service — this keeps Tier 1 deterministic while proving the
architectural pattern that TrustGuard (Tier 2, main event) implements live.

## Connection to TrustGuard (Main Event)

The NandaHack main event submission — [TrustGuard](https://trustguard-production.up.railway.app) —
implements the live version of what `TrustAwareStreamingPayments` proves
conceptually:

- **ELO reputation scoring** → `trust_score` parameter
- **Risk assessment (0-100)** → `trust_threshold` parameter
- **Denylist enforcement** → streams from denylisted agents rejected
- **Rate anomaly detection** → `max_rate_for_untrusted` cap
- **Full audit trail** → `total_billed`, `security_blocks`, `ticks_elapsed`

Together, the warm-up (this plugin) and the main event (TrustGuard) form a
complete reputation-backed secure payment system for autonomous agents.
