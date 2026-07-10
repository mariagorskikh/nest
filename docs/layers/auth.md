# Auth layer

**What it does.** Issue, verify, and revoke capability tokens (scopes
granted to a subject).

## Interface

```python
class Auth(Protocol):
    async def issue(self, subject: AgentId, scopes: list[str]) -> Token: ...
    async def verify(self, token: Token) -> AuthContext: ...
    async def revoke(self, token: Token) -> None: ...
```

Full definition: [`nest_core/layers/auth.py`](../../packages/nest-core/nest_core/layers/auth.py).

## Default plugin

`jwt` — HMAC-SHA256-signed token. **Not an RFC 7519 JWT.** Convenient
shape (header.payload.sig), no claim validation beyond the signature.

Source: [`nest_plugins_reference/auth/jwt_auth.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/jwt_auth.py).

## Hardened plugin: `delegatable`

Macaroon-style HMAC-chained capability tokens. Any token holder mints
attenuated child tokens **offline** via
`delegate(parent_token, audience, scopes_subset, ttl)`; each child's
signature is keyed by its parent's signature, so revoking any segment
invalidates every descendant at the next `verify` — cascading revocation
by construction, no per-child revocation lists. `verify` re-checks the
full chain (signature, per-segment revocation and expiry, monotonic scope
and expiry attenuation); `verify_presented(token, presenter)` additionally
binds presentation to the token's audience.

Adversarial validators (`check_no_scope_escalation`,
`check_no_stale_ancestor_use`, `check_audience_binding`) fail against the
`jwt` plugin and pass against `delegatable`; the `delegated_auth` scenario
exercises all three attacks deterministically.

Source: [`nest_plugins_reference/auth/delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/delegatable.py).
Validators: [`nest_plugins_reference/validators/delegation_validators.py`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/delegation_validators.py).
Scenario: [`scenarios/delegated_auth.yaml`](../../scenarios/delegated_auth.yaml).

## Manifest-bound plugin: `manifest_delegatable`

`manifest_delegatable` extends the delegation idea with signed policy
manifests. Root-token issuance clamps requested scopes to the subject's
`PolicyManifest`, then delegated child tokens must carry a strict subset of
the parent's scopes and a TTL no longer than the parent token's remaining
lifetime.

The small policy package supplies the manifest and scope grammar the Auth
layer needs:

- `PolicyManifest` signs the owner-authored allowlist for tools, data
  exposure, spend budget, and approval gates.
- `scope_to_op()` maps durable token scopes such as `tool:buy`,
  `spend:250`, and `expose:pii:seller-1` into policy checks.
- `decide()` is a pure, fail-closed decision core used by issuance to drop
  scopes that the manifest does not authorize.

The `manifest_delegated_auth` scenario adds a manifest-tamper probe in
addition to scope escalation, stale ancestor, and audience-confusion probes.
That keeps this plugin distinct from `delegatable`: a widened or tampered
manifest does not widen root-token authority.

Sources:

- [`nest_plugins_reference/auth/manifest_delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/manifest_delegatable.py)
- [`nest_plugins_reference/policy/manifest.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/manifest.py)
- [`nest_plugins_reference/policy/decide.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/decide.py)
- [`nest_plugins_reference/policy/scopes.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/scopes.py)

Scenario and validators:

- [`scenarios/manifest_delegated_auth.yaml`](../../scenarios/manifest_delegated_auth.yaml)
- `manifest_delegated_auth_manifest_binding`
- `manifest_delegated_auth_scope_containment`
- `manifest_delegated_auth_no_stale_parent`
- `manifest_delegated_auth_audience_binding`

Judge-facing submission notes:
[`docs/hackathon/charan-auth-delegation-submission.md`](../hackathon/charan-auth-delegation-submission.md).

Focused verification:

```bash
pytest \
  packages/nest-plugins-reference/tests/test_manifest.py \
  packages/nest-plugins-reference/tests/test_decide.py \
  packages/nest-plugins-reference/tests/test_policy_core_properties.py \
  packages/nest-plugins-reference/tests/test_manifest_delegatable.py \
  packages/nest-plugins-reference/tests/test_manifest_delegatable_properties.py \
  packages/nest-core/tests/test_manifest_delegated_auth.py
```

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
