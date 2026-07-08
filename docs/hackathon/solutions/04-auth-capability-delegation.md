---
title: Delegatable capability tokens — reference solution & threat model
layer: auth
problem: 04-auth-capability-delegation
plugin: ("auth", "delegatable")
difficulty: easy
---

# Delegatable capability tokens — reference solution & threat model

## Solution overview

The `DelegatableAuth` plugin replaces the default `JwtAuth` with a
macaroon-inspired capability-token system. Three new primitives sit
on top of the base `Auth` protocol:

| Primitive | What it does |
|---|---|
| `issue_root(subject, audience, scopes, ttl_seconds, max_depth)` | Mint a root token with N levels of delegatable depth. Root tokens carry the full scope set and a `max_depth` ceiling. |
| `delegate(parent, subject, audience, scopes, ttl_seconds)` | Carve a strictly-narrower child token from an existing one. Scopes must be a subset of the parent's, TTL must be <= parent's TTL, and the remaining depth budget must be > 0. Every delegation re-signs the child using the parent's HMAC context so revocation propagates transitively. |
| `revoke_tree(token_str)` | Revoke a token and *every* descendant in a single O(n) traversal of the in-memory ancestry forest. The revoked set is returned so callers can audit how many tokens were invalidated. |
| `verify_capability(token_str, audience, required_scopes, now)` | Verify signature, expiry, audience binding, scope sufficiency, and recursive revocation ancestry in one call. Raises `CapabilityError` with a typed reason string on every failure path. |

### HMAC-chain construction

```
root_hash  = HMAC(server_secret,  root_claims)
child_hash = HMAC(parent_hash,  child_claims)  ← anchored to parent
```

Each token carries `parent_id` and the parent's truncated hash in its
claims. Verifying a token recomputes the expected chain from the known
root — if any ancestor was revoked its `token_id` appears in the
revocation set and verification fails with `revoked`.

This means revoking the **root** token immediately invalidates every
token in its subtree at the next `verify_capability` call, with zero
per-child bookkeeping.

---

## Threat model

### Assets

1. **Token secrecy / integrity** — ability to forge, tamper, or replay a
   capability token to gain unauthorised access.
2. **Scope integrity** — ability to widen one's authority beyond what
   the granting agent intended.
3. **Audience binding** — ability to present a token issued for agent B
   as if it were issued for agent A.
4. **Liveness / timeliness** — ability to use an expired or revoked
   token long past its intended expiry.
5. **Delegation-tree integrity** — ability to delegate deeper than the
   root allowed, or to create cycles / DAGs that confuse revocation.

### Adversary model

We assume an in-process, in-memory adversary that:

- Can read *any* serialized token string it obtains (network sniffing,
  shared memory, log files, side channels).
- Can call the public `delegate()`, `verify_capability()`, `revoke_tree()`,
  and `inspect()` APIs on the same `DelegatableAuth` instance.
- **Cannot** read the `server_secret` (it lives in memory only, never
  serialized).
- **Cannot** forge a valid HMAC without the secret — so forging a root
  token is infeasible.
- **Can** attempt to delegate from a token it legitimately holds but
  with escalated scopes, longer TTL, different audience, or deeper
  depth.
- **Can** attempt to verify a legitimate token after its parent was
  revoked (observing a valid `parent_id` in the wild and replaying it).

### Attack tree

```
1. FORGE_ROOT_TOKEN                               [IMPOSSIBLE]
   └── 1.1 Guess/crack server_secret               [infeasible — HMAC-SHA256]
   └── 1.2 Blind signature collision               [infeasible]
   └── 1.3 NaN/Inf injection in claims             [BLOCKED — _check_finite]

2. SCOPE_ESCALATION                               [BLOCKED]
   └── 2.1 child scopes ⊈ parent scopes            [BLOCKED — strict subset check]
   └── 2.2 child has broader scope than parent      [BLOCKED — max one scope set intersection]
   └── 2.3 parent has no admin, child requests it  [BLOCKED — CapabilityError("scope")]

3. TTL_ABUSE                                       [BLOCKED]
   └── 3.1 child ttl > parent ttl                  [BLOCKED — clamped to parent.expires_at]
   └── 3.2 child ttl = NaN / Inf / negative        [BLOCKED — _check_finite]
   └── 3.3 token used after expiry                 [BLOCKED — _check_expiry → expires_at < now]

4. AUDIENCE_CONFUSION                             [BLOCKED]
   └── 4.1 token for "market" presented to "escrow" [BLOCKED — audience must match exactly]
   └── 4.2 audience field tampered in serialized token [BLOCKED — HMAC mismatch on verification]

5. REVOCATION_ESCAPE                              [BLOCKED]
   └── 5.1 child used after parent revoked         [BLOCKED — recursive ancestral check]
   └── 5.2 revoked token re-played after rebinding [BLOCKED — token.hash in _revoked set]
   └── 5.3 double-revoke corrupts state            [BLOCKED — idempotent set discard]
   └── 5.4 revoke unknown token hangs or crashes   [BLOCKED — returns empty set after proper validation]

6. DEPTH_ESCAPE                                   [BLOCKED]
   └── 6.1 delegate beyond max_depth               [BLOCKED — remaining_depth <= 0 check]
   └── 6.2 child delegates further than parent could [BLOCKED — depth = parent.depth + 1 ≤ max_depth]

7. IMPERSONATION                                   [MITIGATED]
   └── 7.1 subject field tampered                  [BLOCKED — HMAC mismatch]
   └── 7.2 token replayed by different agent        [MITIGATED — audience binding; full replay
        protection would need DPoP binding (PR #9)]
```

### Mitigations by layer

| Layer | Mitigation | Test coverage |
|---|---|---|
| **Claims construction** | `_check_finite` rejects NaN/Inf/negative on every numeric field | `test_adversarial_rejects_nan_ttl`, `test_adversarial_rejects_nan_in_decoded_token`, `test_nan_rejected_in_delegate_child_ttl` |
| **Scope integrity** | Subset check: `child_scopes <= parent_scopes` | `test_child_token_is_narrower_and_audience_bound`, `test_delegate_rejects_scope_escalation_and_longer_lifetime` |
| **TTL enforcement** | Child `expires_at = min(child_requested, parent.expires_at)` | `test_delegate_rejects_scope_escalation_and_longer_lifetime` |
| **Audience binding** | Exact-match audience comparison at verify time | `test_child_token_is_narrower_and_audience_bound` |
| **Revocation tracking** | `_revoked: set[str]` of token hashes; ancestral traversal up to root | `test_depth_limit_and_cascading_revocation`, `test_revoke_tree_rejects_unknown_token`, `test_double_revoke_is_idempotent` |
| **Depth ceiling** | `parent.remaining_depth - 1` passed to child; `<= 0` blocks delegation | `test_depth_limit_and_cascading_revocation` |
| **Signature anchoring** | HMAC chain: `child_hash = HMAC(parent_hash, child_claims)` | Cryptographic — all verify tests implicitly |
| **Issuer binding** | `iss` field matched against plugin's configured issuer | `test_adversarial_rejects_wrong_issuer` |

### Residual risks (accepted)

1. **No DPoP / sender constraining.** A token can be stolen at rest
   and replayed by any agent that holds it. Full mitigation would be
   PR #9's DPoP-style proof-of-possession binding. The adversarial
   validator catches this as *audience confusion*, but a stolen token
   with the correct audience would still verify. **Accept** because
   Problem 04's scope explicitly excludes it.

2. **In-memory revocation set.** `_revoked` is an in-process `set[str]`
   that disappears when the plugin instance is destroyed. Persistent
   revocation would need a shared KV store. **Accept** — Nanda Town
   scenarios are single-process simulations.

3. **Single-parent tree (not DAG).** Each token has exactly one parent.
   A token cannot be delegated from two separate parents. This means
   the revocation ancestry is always a simple chain, not a graph.
   **Accept** — strict tree is simpler, sufficient, and explicitly
   recommended in the problem statement.

4. **No token rotation.** A revoked root means reinstating the subtree
   requires re-issuing from scratch. **Accept** — this is by design
   for cascade revocation.

---

## Adversarial validator: `CapabilityDelegationValidator`

The validator ships as
`nest_plugins_reference.validators.auth_delegation_validators:CapabilityDelegationValidator`
and exercises the YAML scenario
[`scenarios/auth_capability_delegation.yaml`](../../../scenarios/auth_capability_delegation.yaml).

### What it catches (three attack classes)

| # | Attack | Scenario event sequence | Expected failure against `jwt` |
|---|---|---|---|
| 1 | **Scope escalation** | root→broker (scopes `[quote,pay]`) → rogue (scopes `[pay]` — but rogue doesn't hold `pay` because `quote` + `pay` aren't a subset of `[quote]`) | JwtAuth has no delegation at all, so the whole scenario fails before scope is checked |
| 2 | **Audience confusion** | broker token presented to `market` instead of `escrow` | JwtAuth's `aud` field is opaque to it — a token is a token. The scenario would verify the wrong audience |
| 3 | **Post-revocation verification** | root revoked then broker token verified | JwtAuth only tracks individual token revocation; cascading doesn't exist. Broker token would still verify |

The validator runs the full YAML event sequence and asserts every event
succeeds or fails with the expected error reason (`audience`, `scope`,
`revoked`). Against `DelegatableAuth` all 7 events pass. Against
`JwtAuth` the scenario fails at event 4 or later.

### Validator output

```
CapabilityDelegationValidator:
  events: 7
  passed: 7
  detail: "All scenario events match expected outcomes"
```

---

## Scenario: coordinator → intermediary → leaf

The YAML scenario
[`scenarios/auth_capability_delegation.yaml`](../../../scenarios/auth_capability_delegation.yaml)
builds a three-tier delegation tree of 1 coordinator, 3 intermediaries,
and 12 leaf agents (4 per intermediary):

```
coordinator-0  (depth 0, max_depth=2)
  ├── int-0 ── leaf-0 … leaf-3
  ├── int-1 ── leaf-4 … leaf-7
  └── int-2 ── leaf-8 … leaf-11
```

The scenario factory builds `CoordinatorAgent`, `IntermediaryAgent`,
and `LeafAgent` classes that propagate tokens down the tree and
acknowledge receipt. At the end the coordinator's root is revoked and
every leaf agent's verify call must raise `CapabilityError("revoked")`.

The factory is registered in `nest_core/scenarios.py` as
`auth_capability_delegation` and can be invoked as:

```python
from nest_core.scenario import ScenarioConfig
from nest_core.scenarios_builtin.auth_capability_delegation import (
    auth_capability_delegation_factory,
)

agents = auth_capability_delegation_factory(
    ScenarioConfig(seed=42),
    {"auth": DelegatableAuth(secret=b"s3cr3t")},
)
```

---

## Verification

| Check | Status |
|---|---|
| `uv run ruff check .` | ✅ |
| `uv run ruff format --check .` | ✅ |
| `uv run pytest -v packages/nest-plugins-reference/tests/test_auth_delegation.py` | ✅ 12/12 |
| `uv run pytest -v packages/nest-plugins-reference/tests/test_auth_delegation_properties.py` | ✅ 8/8 |
| `pytest -v packages/nest-plugins-reference/` (full suite) | ✅ |
| Example:: docstrings on every public method | ✅ |
| Validator passes against `DelegatableAuth` | ✅ |
| Validator fails against `JwtAuth` | ✅ (by construction — no delegation API) |
