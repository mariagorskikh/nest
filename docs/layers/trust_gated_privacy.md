# Trust-Gated Privacy: disclosure tiers driven by live reputation

Plugin: `("privacy", "trust_gated")` —
[`nest_plugins_reference/privacy/trust_gated.py`](../../packages/nest-plugins-reference/nest_plugins_reference/privacy/trust_gated.py)

## Problem

[Problem 09 (privacy)](../hackathon/problems/09-privacy-hybrid-encryption-with-selective-disclosure.md)
was solved by the merged `hybrid_x25519` plugin: real hybrid encryption,
selective disclosure, revocation. But that plugin — by design — answers only
*"who can read this?"* with a **static, all-or-nothing audience**: every agent
the sender lists receives the full plaintext, whether its reputation is 0.99
or 0.01. Meanwhile the trust layer (layer 6) computes reputation scores that
**no privacy plugin consumes**. The two layers that most obviously belong
together — *how much do I trust you* and *how much may you see* — are not
connected anywhere in the stack. Concretely, with `hybrid_x25519` a sender
who must include a low-reputation broker in a workflow has exactly two
options: leak everything to it, or exclude it and break the workflow.

## Solution

`TrustGatedPrivacy` connects them by **composition, not re-implementation**:
all cryptography is delegated to the merged `hybrid_x25519` plugin; this
plugin adds the disclosure policy it deliberately lacks. At encrypt time the
sender queries the live `Trust` layer per audience member and assigns a tier:

| Trust score | Tier | What the recipient can decrypt |
|---|---|---|
| ≥ 0.8 | full | The complete plaintext (inner hybrid envelope #1). |
| 0.5 – 0.8 | partial | A redacted view (inner envelope #2): the policy's `reveal_fields` subset **plus a salted-Merkle selective-disclosure proof** that the hidden fields are committed under the same root. Opaque payloads get an honest SHA-256 commitment — never a pretend proof. |
| < 0.5 | denied | Nothing. No wrap entry exists in any envelope — the cryptography enforces the gate, not the JSON. The refusal carries a **signed denial receipt** (Identity-signed, or HMAC as sender-verifiable fallback) naming the score and failed threshold, so denials are auditable. |

Tamper resistance: the gate table (agent → tier → score) is hashed and the
digest sealed **inside** every AEAD-authenticated inner plaintext, so a
doctored gate cannot be re-attached to real ciphertexts (`TamperError`).
Poisoned trust feeds (NaN, ±inf, out-of-range) **fail closed** to denied.
With `deterministic=True`, envelopes are byte-reproducible for Tier-1 traces.

Ships with four adversarial validators
([`validators/trust_gate_validators.py`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/trust_gate_validators.py))
— low-trust exfiltration, partial-tier overexposure, gate laundering, silent
denial — that **fail against both `noop` and `hybrid_x25519`** and pass
against this plugin, plus a wired scenario
([`scenarios/trust_gated_exchange.yaml`](../../scenarios/trust_gated_exchange.yaml)).

## How to run

```bash
uv sync

# Full test suite for this plugin (36 tests: tiers, discrimination,
# Byzantine, validators, scenario integration):
uv run pytest packages/nest-plugins-reference/tests/test_trust_gated.py \
              packages/nest-plugins-reference/tests/test_trust_gated_scenario.py -v

# Run the wired scenario (resolves ./scenarios/trust_gated_exchange.yaml):
uv run nest run trust_gated_exchange

# The whole CI gate:
make ci-local
```

## Results

Measured over 200 structured payloads (4 fields, 2 sensitive) sent to a
3-member audience with trust scores 0.9 / 0.6 / 0.1, same machine, same seed
(script: encrypt + 3 decrypts per message):

| Plugin | Low-trust plaintext reads | Mid-trust hidden-field exposures | Wire leaks | Auditable denials | Mean envelope | Mean enc+3×dec |
|---|---|---|---|---|---|---|
| `noop` | 200/200 | 200/200 | 200/200 | 0 | 82 B | ~0 ms |
| `hybrid_x25519` | 200/200 | 200/200 | 0/200 | 0 | 676 B | 0.76 ms |
| `trust_gated` | **0/200** | **0/200** | **0/200** | **200/200** | 3 558 B | 1.32 ms |

Low-trust and mid-trust data exposure drop from 100% (under both reference
plugins — `hybrid_x25519` encrypts *to* whoever is listed, trust-blind) to
**0%**, and every denial is refused with a receipt the issuer can verify.
The price is ~5× envelope size versus `hybrid_x25519` (two inner envelopes +
gate table + receipts) and +0.6 ms per message — stated honestly below.

## Limits

- **Gate-time trust, not read-time.** Tiers bind the score *at encrypt time*.
  A recipient whose reputation later collapses keeps envelopes it already
  received (same future-only stance as `hybrid_x25519` revocation, for the
  same reason). Pair with `revoke()` for key-level exclusion going forward.
- **No exfiltration control.** A full-tier recipient can always re-share
  plaintext out-of-band; the gate governs disclosure, not use.
- **HMAC receipts are sender-verifiable only.** Without an `Identity` plugin
  the denial receipt proves nothing to third parties. Supply one (e.g.
  `did_key`) for third-party-verifiable receipts.
- **Merkle commitments, not zero-knowledge circuits.** The partial tier
  proves *set membership under a committed root* (salted-Merkle, per the
  problem-09 pattern); it does not prove arbitrary predicates over hidden
  values. Full zk-SNARKs are explicitly out of scope per the problem brief.
- **Overhead.** ~5× envelope size and ~2× latency versus plain
  `hybrid_x25519` for a 3-member tiered audience. If every recipient is the
  same tier, prefer the composed plugin directly.
- **Trust quality is upstream.** The gate is only as good as the trust
  layer's scores. It fails closed on malformed scores, but it cannot detect
  a *plausible-but-wrong* score (e.g. Sybil-inflated averages) — that is the
  trust layer's problem statement, not this plugin's.
