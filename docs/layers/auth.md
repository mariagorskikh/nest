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

## Bundled alternative: `delegatable`

`delegatable` is the Auth-layer capability-delegation plugin. It issues
root tokens whose requested scopes are clamped to a signed
`PolicyManifest`, then lets a token holder mint a child token for another
agent with a strict subset of the parent's scopes and a TTL no longer than
the parent token's remaining lifetime.

The small policy package supplies the manifest and scope grammar the Auth
layer needs:

- `PolicyManifest` signs the owner-authored allowlist for tools, data
  exposure, spend budget, and approval gates.
- `scope_to_op()` maps durable token scopes such as `tool:buy`,
  `spend:250`, and `expose:pii:seller-1` into policy checks.
- `decide()` is a pure, fail-closed decision core used by issuance to drop
  scopes that the manifest does not authorize.

Delegated tokens use a parent-anchored HMAC chain. Verification recomputes
the chain, rejects scope widening, rejects equal-authority delegation,
checks expiry, checks revocation transitively, and optionally checks that
the presenter matches the token audience. Revoking a parent invalidates
all descendants because each child carries the parent token id in its
delegation chain.

Sources:

- [`nest_plugins_reference/auth/manifest_delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/manifest_delegatable.py)
- [`nest_plugins_reference/policy/manifest.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/manifest.py)
- [`nest_plugins_reference/policy/decide.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/decide.py)
- [`nest_plugins_reference/policy/scopes.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/scopes.py)

Scenario and validators:

- [`scenarios/manifest_delegated_auth.yaml`](../../scenarios/manifest_delegated_auth.yaml)
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
