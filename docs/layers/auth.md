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

## Delegation plugin

`delegatable` — macaroon-style capability tokens (Birgisson et al., 2014).
Implements the two things `jwt` cannot: **capability delegation** and
**revocation propagation**. A token carries its whole delegation chain plus one
running HMAC signature (`s_i = HMAC(s_{i-1}, link_i)`), so any holder can mint a
narrowed, shorter-lived sub-token for another agent *without the issuer*, and
revoking a parent link's id invalidates every descendant at the next verify —
no per-child revocation list.

Adds `delegate(parent, audience, scopes_subset, ttl)` on top of the base `Auth`
contract; `verify` takes an optional `presenter` (audience binding) and
`context` (first-party caveats). Delegation is attenuation-only: child scopes
must be a subset of the parent's and child TTL must be ≤ the parent's.

Source: [`nest_plugins_reference/auth/delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/delegatable.py).
Demo scenario: [`scenarios/delegated_auth.yaml`](../../scenarios/delegated_auth.yaml)
with the `delegated_auth` validators (scope escalation, cascading revocation,
audience binding).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
