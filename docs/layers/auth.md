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

## `delegatable` — macaroon-style delegation with cascading revocation

`jwt` issues flat tokens and revokes by exact token string, so it cannot
model *delegation* (an agent minting a narrower sub-capability for another
agent without the issuer) or *cascading revocation* (revoke a parent →
every descendant fails automatically). `delegatable` adds both, following
the macaroon construction (Birgisson et al., 2014).

A token carries its whole chain of links; each link's HMAC is keyed on the
previous link's signature, so **delegation needs only the parent token, not
the root secret**:

```python
auth = DelegatableAuth(secret=b"authority-secret")
root  = await auth.issue(AgentId("coordinator-0"), ["read", "write", "admin"])
child = await auth.delegate(root, AgentId("worker-3"), ["read"], ttl=100)
ctx   = await auth.verify_presented(child, AgentId("worker-3"))   # audience-bound
await auth.revoke(root)          # cascades: child now fails to verify
```

Extra surface on top of the base `Auth` protocol:

- `delegate(parent_token, audience, scopes_subset, ttl) -> Token` — child
  scopes must be a subset of the parent's (a superset raises
  `ScopeEscalationError`); child expiry is clamped to never outlive the
  parent.
- `verify_presented(token, presenter) -> AuthContext` — everything `verify`
  checks, plus that the presenter is the tip's declared audience.

Three attacks it stops at verify time — an attacker holding a token can
always *append* a validly-signed link, so every restriction is re-checked on
the way in — that the `jwt` plugin silently allows:

| Attack | `jwt` | `delegatable` |
|---|---|---|
| **Scope escalation** (child grants a scope the parent lacked) | accepted | `ScopeEscalationError` |
| **Stale ancestor** (child verifies after parent revoked/expired) | accepted | `RevokedAncestorError` / `ExpiredTokenError` |
| **Audience confusion** (token for B presented by C) | accepted | `AudienceConfusionError` |

The shipped adversarial validator
([`validators/auth_validators.py`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/auth_validators.py))
encodes these as pure checks over observed grants: it **fails** against `jwt`
and **passes** against `delegatable`. Determinism is preserved — token ids are
content hashes, signatures are HMAC-SHA256, and expiry is measured against a
logical tick clock, never wall time.

Sources:
[`auth/delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/delegatable.py),
scenario [`scenarios/delegated_auth.yaml`](../../scenarios/delegated_auth.yaml).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
