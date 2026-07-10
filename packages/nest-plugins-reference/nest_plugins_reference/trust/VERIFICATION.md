# delegated_admission — verification guide

## What this is

`delegated_admission` is a Tier-1, deterministic Python port of the
audited nexartis-nanda-node delegation-grant verifier
(`nexartis-nanda-node/src/lib/server/delegation-grants.ts`) plugged
into Nanda Town's `trust` layer. Evidence from a reporter is admitted
into reputation scoring iff, at the currently injected logical clock:

1. The reporter is bound to a delegation grant in the plugin's local
   store.
2. The grant is not revoked, not expired, and not transitively
   invalidated by a revoked or earlier-expiring ancestor within
   `MAX_HOPS` hops (cycle-safe).
3. The grant's scope contains `AdmissionPolicy.required_scope`.
4. The grant's `PuhProof` re-canonicalises to the same envelope bytes,
   its `bound_at_ms` / `issued_at_ms` fall inside
   `[now_ms - PUH_FRESHNESS_MS, now_ms + PUH_SKEW_MS]`, and (by default)
   the proof carries an Ed25519 signature by the principal's trusted
   public key over those bytes.

Everything else is quarantined with a stable machine-string reason so
adversarial validators can gate on the reason byte-exactly.

Bundled companions:

- `nest_core/scenarios_builtin/delegated_admission.py` — the scenario
  factory (five reporter roles).
- `scenarios/delegated_trust_market.yaml` — the Tier-1 YAML.
- `validate_delegated_*` in `nest_core/validators.py` — four
  discriminating trace validators.

## How to verify

Everything below runs offline, deterministically, and requires only
the workspace's `uv` toolchain. All commands are run from the
repository root (`nandatown-lane3` here — the branch worktree).

Run the plugin's own 60-plus-test suite (unit + property + Byzantine
input + integration):

```bash
uv run pytest packages/nest-plugins-reference/tests/test_delegated_admission.py -v
```

Run the scenario end-to-end under the delegated plugin and inspect the
trace:

```bash
uv run nest run scenarios/delegated_trust_market.yaml
uv run nest validate --trace ./traces/delegated_admission.jsonl --type delegated_admission
```

Invoke the four validators programmatically (same result the CLI's
`nest validate` produces):

```bash
uv run python - <<'PY'
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path("./traces/delegated_admission.jsonl"), "delegated_admission"):
    print(f"{'PASS' if r.passed else 'FAIL'}: {r.name} — {r.detail}")
PY
```

Byte-determinism (same seed → identical trace bytes):

```bash
uv run pytest packages/nest-plugins-reference/tests/test_delegated_admission.py::test_delegated_scenario_is_byte_deterministic -v
```

Flip test (swap `trust: delegated_admission` for `trust: score_average`
in memory and rerun the validators):

```bash
uv run pytest packages/nest-plugins-reference/tests/test_delegated_admission.py::test_scenario_baseline_fails_unattested_quarantined -v
```

## Adversarial validators

Four validators live in `nest_core/validators.py` under the
`"delegated_admission"` key. Each is chosen to fail in a distinct,
useful way when the trust layer is `score_average` instead of
`delegated_admission`:

1. **`validate_delegated_unattested_quarantined`** — the primary
   discriminator. Every reporter labelled `no-grant` in the trace's
   `admission:` lines must have its report quarantined, the victim's
   final `repscore` must sit at or above the neutral prior `0.5`, and
   every reporter labelled `live` (the anti-degenerate guard) *must*
   appear as admitted. Under `score_average` every `no-grant`
   reporter's negatives are admitted, the victim's average collapses
   under 0.5, and this validator FAILs.
2. **`validate_delegated_revocation_cascade`** — requires at least one
   `cascade:<root>:<n_descendants>` line in the trace with
   `n_descendants >= 1`, and forbids any `admission:<r>:revoked:admitted`
   line strictly after the cascade line. Under `score_average` no
   cascade line exists (baseline has no `revoke` surface), so this
   validator FAILs on the "cascade never happened" branch.
3. **`validate_delegated_scope_escalation_blocked`** — requires at
   least one `admission:<r>:scope-invalid:...` attempt and forbids any
   `scope-invalid` reporter from appearing as admitted. Under
   `score_average` the required scope is never consulted so every
   scope-invalid attempt is admitted and this validator FAILs.
4. **`validate_delegated_stale_proof_rejected`** — requires at least
   one `admission:<r>:stale-proof:...` attempt and forbids any
   `stale-proof` reporter from appearing as admitted. Under
   `score_average` the proof clock is never consulted so every stale
   attempt is admitted and this validator FAILs.

The paired scenario+plugin passes all four at seeds `[42, 7, 1337]`.
The baseline `score_average` fails all four; the flip test
(`test_scenario_baseline_fails_unattested_quarantined`) only asserts
the primary discriminator flips, matching how the attested-peering
suite writes the same shape.

## Honest limitations

These are the intentional divergences from the production system this
plugin ports. They are consequential — a production reviewer should
know them before treating the Tier-1 plugin as a drop-in replacement.

1. **`require_signed_puh=True` is stricter than production.** The
   audited nanda-node treats proof-of-human signatures as optional at
   runtime, pending the ceremony's mobile signing rollout. The Python
   port defaults to *requiring* the Ed25519 signature over the
   canonical envelope. Set `AdmissionPolicy(require_signed_puh=False)`
   for parity with production's current toggle.
2. **`trusted_principals` roster is an enhancement.** The production
   verifier trusts a *single* configured principal key. The Python
   port carries a `dict[principal_id, public_key]` so scenarios can
   express multi-principal fixtures and unknown-principal rejection
   independently of the roster shape. Configuring exactly one entry
   reproduces the production behaviour.
3. **Cascading revocation composes with the trust layer.** In the
   production KYM VC pipeline, revocation is flat and per-credential:
   revoking one credential does not revoke child credentials it issued.
   The Python port ports the nanda-node grant semantics
   (`collectDescendants` + `MAX_HOPS`), which do cascade. If the
   plugin is deployed against a real KYM registry, the cascade must
   either be disabled at the policy layer or the underlying registry
   must be extended with a parent field — this is not a swap-in.
4. **The biometric principal is a deterministic fixture in Tier 1.**
   `derive_principal(seed)` fabricates a stable Ed25519 keypair for a
   test/scenario principal from arbitrary seed bytes. In production
   the principal key is bound to a live Yanez proof-of-human ceremony
   over an out-of-band biometric channel that is deliberately not
   modelled here — the ceremony's transport is out of scope for a
   protocol-level simulator, and the fixture buys the discriminating
   trace + validator set at Tier 1 without pretending otherwise.
5. **As-of binding: admission evaluates at report time.** When
   `report()` is called, the plugin re-verifies the stored proof
   against the *current* clock, not the clock at which the grant was
   issued. This is what lets the stale-proof role fail
   deterministically (issue at `now - freshness - 60_000`, advance
   clock, present evidence, watch the plugin reject with
   `puh-proof-stale`). It also means a proof that was fresh at grant
   time but is stale by report time is rejected — matching
   `verifyPuhProof`'s behaviour but worth stating explicitly for any
   consumer that thinks in terms of certificate-style
   "issued=valid-forever" semantics.
6. **Ancestor-expiry narrowing is strictly tighter than production.**
   The TS `checkDelegation` narrows a child's reported `expiresAt` only
   when it encounters an ancestor that is *currently expired*, then
   stops walking. The Python port computes the effective expiry as the
   minimum across the whole ancestor chain unconditionally, so
   `CheckResult.expires_at_effective` can be earlier than production
   would report even while the grant is still valid. The `valid` /
   `expired` verdicts — the security-relevant outputs, including the
   production CRITICAL-3 fix — are identical in both implementations;
   only the reported effective-expiry timestamp is more conservative
   here.
7. **Chain depth is capped at mint time (`chain-too-deep`) — production
   does not cap it.** The TS source bounds the revocation cascade and
   the check-time ancestor walk at 32 hops each but allows unbounded
   mint depth, so a grant more than 64 hops below a revoked ancestor
   would evade both bounded walks and remain valid (fail-open). The
   Python port refuses to mint a grant whose ancestor chain would
   exceed `MAX_HOPS` (32), guaranteeing every legal chain is fully
   covered by both walks. Stricter than production, by design;
   regression-tested (`test_chain_too_deep_rejected_at_mint`).
