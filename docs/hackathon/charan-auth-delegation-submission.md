# Charan Auth Delegation Submission

## Summary

This submission targets Problem 04, **Delegatable capability tokens with
cascading revocation**, in the Auth layer.

It adds `auth: delegatable`, a small Auth-layer plugin that issues and
verifies capability tokens constrained by signed policy manifests. A root
token can only contain scopes allowed by the subject's manifest, and a
delegated child token can only carry a strict subset of its parent token's
scopes. Verification fails closed for invalid signatures, malformed payloads,
scope widening, stale ancestors, expired tokens, and audience confusion.

## Problem Solved

Multi-agent workflows routinely pass capabilities down a chain:

1. A coordinator receives a broad but bounded root capability.
2. The coordinator delegates narrower capabilities to intermediary agents.
3. Intermediaries delegate still narrower capabilities to leaf agents.
4. A verifier must reject any child token that tries to exceed the declared
   parent, manifest, expiry, or audience boundary.

The default `jwt` Auth plugin can sign and revoke exact tokens, but it cannot
model parent-issued delegation. A central authority can re-issue a new token,
but that is not the same security property: it does not prove that the parent
holder was constrained to a subset, and it does not create a delegation chain
that can be audited or revoked transitively.

This PR makes the missing Auth-layer behavior explicit:

- **Manifest-bound roots.** Root issuance clamps requested scopes against a
  signed `PolicyManifest`.
- **Least privilege delegation.** Child scopes must be a strict subset of
  parent scopes.
- **Fail-closed verification.** Invalid manifests, tampered token payloads,
  malformed payloads, unknown tokens, invalid signatures, expired tokens, and
  invalid chains are rejected.
- **Cascading revocation.** Revoking any token invalidates that token and all
  descendants because descendants carry ancestor token ids.
- **Audience binding.** A child token minted for `leaf-0-0` does not verify
  when presented by `leaf-0-0-wrong`.
- **Auditability.** The deterministic `delegated_auth` scenario emits trace
  lines for honest leaf verification and each adversarial probe, and the
  validators check those trace lines.

## Why It Matters

Agents often need to receive or delegate authority without inheriting every
permission their parent has. Without manifest-bound delegation, a child agent
can be over-privileged by accident, and a test rig cannot distinguish a real
least-privilege protocol from central re-issuance that happens to work on the
happy path.

The security properties this PR makes testable are:

- **Least privilege:** only declared scopes survive issuance and delegation.
- **Manifest-bound authority:** an agent cannot ask for scopes beyond its
  signed manifest, and a tampered or forged manifest fails closed when an
  identity verifier is supplied.
- **Scope narrowing:** delegation must strictly reduce authority, not merely
  copy parent authority.
- **Revocation propagation:** a stale child cannot survive ancestor revocation.
- **Audience separation:** a valid token is not enough; the presenter must be
  the intended audience when the caller supplies a presenter.
- **Deterministic audit:** the scenario and validators produce stable evidence
  for the judge panel and CI.

## What Works Today

### Auth Plugin

`packages/nest-plugins-reference/nest_plugins_reference/auth/delegatable.py`
implements `DelegatableAuth`.

Working behavior:

- `issue(subject, scopes)` clamps root scopes against the signed manifest.
- `delegate(parent_token, audience, scopes_subset, ttl)` mints a child token
  only when:
  - the parent verifies,
  - the requested scopes are a strict subset of parent scopes,
  - no requested scope is outside the parent,
  - the child expiry does not exceed the parent expiry.
- `verify(token, presenter=None)` checks:
  - token wire format,
  - JSON payload shape and field types,
  - known-token status,
  - stored signature,
  - expected root or parent-anchored HMAC signature,
  - chain shape,
  - strict scope containment,
  - TTL containment,
  - expiry,
  - transitive revocation,
  - optional audience/presenter binding.
- `revoke(token)` records the token id so descendants fail because their
  `chain` contains that ancestor.

### Manifest And Policy Primitives

The small policy package lives under
`packages/nest-plugins-reference/nest_plugins_reference/policy/`.

Working behavior:

- `manifest.py`
  - defines `PolicyManifest`, `Budget`, and `Approval`,
  - signs canonical JSON bytes excluding the `signature` field,
  - verifies against the manifest's declared `agent_id`,
  - rejects unsigned, tampered, forged, and signature-transplanted manifests,
  - supports JSON round trips for trace/validator use.
- `scopes.py`
  - parses durable token scopes:
    - `tool:<name>`
    - `spend:<int>`
    - `expose:<class>:<aud1,aud2,...>`
  - returns `None` for malformed or unsupported scopes so issuance drops
    them instead of granting ambiguous authority.
- `decide.py`
  - is pure and total,
  - allows or denies tool, register, expose, and pay actions,
  - enforces cumulative budget and approval gates,
  - rejects malformed amounts and list-shaped inputs without raising.

### Scenario And Validators

The scenario is `scenarios/delegated_auth.yaml` and the built-in factory is
`packages/nest-core/nest_core/scenarios_builtin/delegated_auth.py`.

It creates:

- one coordinator,
- three intermediaries,
- twelve leaves,
- one auditor sink.

The coordinator builds a delegation tree and emits trace lines for:

- twelve honest leaf verifications,
- scope escalation attack,
- stale parent attack,
- audience confusion attack.

The validators in `packages/nest-core/nest_core/validators.py` are:

- `delegated_auth_scope_containment`
- `delegated_auth_no_stale_parent`
- `delegated_auth_audience_binding`

They pass with `auth: delegatable` and fail with `auth: jwt`, which is the
charter's required adversarial discrimination.

### Registration

The plugin is registered both ways reviewers expect:

- Built-in registry key in `packages/nest-core/nest_core/plugins.py`:
  `("auth", "delegatable")`
- Package entry point in `packages/nest-plugins-reference/pyproject.toml`:
  `[project.entry-points."nest.plugins.auth"]`

## Files To Review

Core Auth submission:

- `packages/nest-plugins-reference/nest_plugins_reference/auth/delegatable.py`
- `packages/nest-plugins-reference/nest_plugins_reference/policy/manifest.py`
- `packages/nest-plugins-reference/nest_plugins_reference/policy/decide.py`
- `packages/nest-plugins-reference/nest_plugins_reference/policy/scopes.py`
- `packages/nest-plugins-reference/nest_plugins_reference/policy/__init__.py`

Wiring:

- `packages/nest-core/nest_core/plugins.py`
- `packages/nest-plugins-reference/pyproject.toml`
- `packages/nest-core/nest_core/scenarios.py`

Scenario and validators:

- `scenarios/delegated_auth.yaml`
- `packages/nest-core/nest_core/scenarios_builtin/delegated_auth.py`
- `packages/nest-core/nest_core/validators.py`

Focused tests:

- `packages/nest-plugins-reference/tests/test_manifest.py`
- `packages/nest-plugins-reference/tests/test_decide.py`
- `packages/nest-plugins-reference/tests/test_policy_core_properties.py`
- `packages/nest-plugins-reference/tests/test_delegatable.py`
- `packages/nest-plugins-reference/tests/test_delegatable_properties.py`
- `packages/nest-core/tests/test_delegated_auth.py`
- `packages/nest-core/tests/test_validators.py`

Layer documentation:

- `docs/layers/auth.md`
- `docs/hackathon/charan-auth-delegation-submission.md`

## Test Evidence

Focused command:

```bash
pytest \
  packages/nest-plugins-reference/tests/test_manifest.py \
  packages/nest-plugins-reference/tests/test_decide.py \
  packages/nest-plugins-reference/tests/test_policy_core_properties.py \
  packages/nest-plugins-reference/tests/test_delegatable.py \
  packages/nest-plugins-reference/tests/test_delegatable_properties.py \
  packages/nest-core/tests/test_delegated_auth.py \
  -q
```

Expected focused result after this pass:

```text
102 passed
```

What that proves:

- signed manifest accepted,
- unsigned manifest rejected,
- tampered manifest rejected,
- forged manifest rejected,
- signature transplant rejected,
- manifest JSON round trip still verifies,
- requested root scopes are clamped to manifest scopes,
- tool, spend, and expose scopes are all clamped,
- duplicate scopes are removed deterministically,
- out-of-manifest scopes are removed,
- malformed scopes are removed,
- child delegation succeeds only for a strict subset,
- equal-authority delegation is rejected,
- scope escalation is rejected,
- handcrafted broader child tokens are rejected,
- registered forged child tokens are rechecked by verification,
- malformed token payloads fail closed,
- ambiguous `aud`/`sub` payloads fail closed,
- non-finite `NaN`/infinite payload times fail closed,
- exp-before-iat payloads fail closed,
- invalid signatures are rejected,
- expired tokens are rejected,
- non-finite, zero, and negative delegation TTLs are rejected,
- non-finite injected clocks are rejected,
- child TTL cannot exceed parent TTL,
- revoked parents cannot delegate,
- expired parents cannot delegate,
- root revocation invalidates children and grandchildren,
- child revocation does not invalidate the root but does invalidate
  descendants,
- presenter/audience mismatch is rejected,
- plugin satisfies the Auth protocol,
- plugin resolves through the registry,
- property tests cover strict containment, transitive revocation,
  determinism, decision totality, decision purity, budget soundness, and
  manifest canonicality.

Scenario adversarial proof:

```bash
pytest packages/nest-core/tests/test_delegated_auth.py -q
```

Expected behavior:

- `auth: delegatable` passes all three delegated-auth validators across the
  tested seed bank.
- `auth: jwt` fails all three validators, proving the validators catch the
  missing delegation security property in the baseline.
- same seed gives byte-identical traces.
- the trace contains 17 started agents, 12 honest leaf audit messages, and
  blocked lines for all three attacks.

Direct scenario/validator smoke output:

```text
delegatable
PASS delegated_auth_scope_containment 12 honest leaves verified; scope_escalation attack blocked
PASS delegated_auth_no_stale_parent 12 honest leaves verified; stale_parent attack blocked
PASS delegated_auth_audience_binding 12 honest leaves verified; audience_confusion attack blocked
jwt
FAIL delegated_auth_scope_containment scope_escalation attack accepted
FAIL delegated_auth_no_stale_parent stale_parent attack accepted
FAIL delegated_auth_audience_binding audience_confusion attack accepted
```

Full pytest result from this checkout:

```text
838 passed, 1 skipped, 1 deselected
```

Canonical full local CI command:

```bash
make ci-local
```

That runs the charter-required sequence:

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -v
```

Local runner note: in this macOS checkout, `make ci-local` completed
`uv sync`, `uv run ruff check .`, `uv run ruff format --check .`, and
`uv run pyright`, then `uv run pytest -v` exited 139 before collection
because pytest's startup imported the local `readline` extension and the
extension segfaulted. The full suite above was therefore run through the
same `.venv` interpreter with `readline` pre-seeded as an empty module before
calling `pytest.main(["-q"])`. That workaround changes only pytest startup,
not the project code or tests.

## Charter Alignment

- **One problem:** Problem 04, Auth capability delegation.
- **One layer:** Auth, with a small policy package used by the Auth plugin for
  manifest signing, scope parsing, and issuance decisions.
- **Layer plugin:** `auth: delegatable`.
- **Adversarial validator:** three validators for scope containment, stale
  ancestors, and audience binding.
- **Scenario YAML:** `scenarios/delegated_auth.yaml`.
- **Deterministic:** tests assert byte-identical traces for the same seed and
  property tests assert byte-identical tokens for identical inputs and clock.
- **Docs:** public code symbols have docstrings with examples, the Auth layer
  doc names the plugin, and this file provides judge-facing verification
  instructions.

## PR Description Short Form

This PR adds `auth: delegatable`, an Auth-layer plugin for manifest-bound
delegatable capability tokens. Root issuance clamps requested scopes to a
signed `PolicyManifest`; delegation can only mint a strict subset of the
parent token's scopes; verification checks signature, chain, expiry,
revocation ancestry, and optional presenter/audience binding. The
`delegated_auth` scenario builds a coordinator-to-intermediary-to-leaf
delegation tree, and its validators pass under `delegatable` while failing
under the baseline `jwt` plugin for scope escalation, stale parent, and
audience confusion attacks.
