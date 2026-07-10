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

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
