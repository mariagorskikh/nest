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

## Strict holder-derived variant: `delegatable_strict`

`delegatable_strict` coexists with the baseline `delegatable` plugin while
making three additional choices load-bearing: every child must remove at
least one parent scope, child-signing keys are derived from the parent token's
signature and hash rather than the issuer secret, and the public-API validator
crafts a direct parent-signature key-confusion forgery.

The base protocol's `verify(token)` call authenticates a valid child as a
bearer token. Call `verify_for(token, presenter)` when the caller must also
enforce that the presenter matches the child's audience. `AuthContext.subject`
therefore identifies the holder/audience; the token's `sub` claim retains the
original delegator.

The validator records the exception type for every rejected attack so a typed
security rejection remains distinguishable from an unrelated plugin crash.
The deterministic `strict_delegated_auth` scenario preserves the requested
1 coordinator, 3 intermediary, and 12 leaf topology.

Source: [`nest_plugins_reference/auth/strict_delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/strict_delegatable.py).
Validator: [`nest_plugins_reference/validators/strict_delegation_validators.py`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/strict_delegation_validators.py).
Scenario: [`scenarios/strict_delegated_auth.yaml`](../../scenarios/strict_delegated_auth.yaml).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
