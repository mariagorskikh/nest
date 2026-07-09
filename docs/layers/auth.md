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

## Delegatable plugin

`delegatable` — macaroon-style capability tokens with **cascading
revocation**. On top of the base `Auth` surface it adds:

```python
async def delegate(
    self, parent_token: Token, audience: AgentId,
    scopes_subset: list[str], ttl: float,
) -> Token: ...

async def verify(self, token: Token, *, presenter: AgentId | None = None) -> AuthContext: ...
```

A holder mints a narrower, shorter-lived child token **without going back
to the issuer**. Each token carries its whole root→leaf chain, and each
link's HMAC is keyed by the previous link's signature (Birgisson et al.,
2014). Because a link's intermediate signature equals the outer signature
of the corresponding ancestor token, revoking an ancestor invalidates
every descendant at the next `verify` — no per-child revocation list.
`delegate` enforces scope subsetting and TTL ≤ parent; the optional
`presenter` argument binds a token to its audience (an impostor is
rejected) while leaving `verify(token)` — the base contract — unchanged.

Source: [`nest_plugins_reference/auth/delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/delegatable.py).

**Adversarial validators** (`nest_plugins_reference.validators`):
`check_scope_escalation_rejected`, `check_stale_parent_rejected`,
`check_audience_confusion_rejected` — each FAILS against `jwt` and PASSES
against `delegatable`. The [`delegated_auth`](../../scenarios/delegated_auth.yaml)
scenario (a coordinator + 3 intermediaries + 12 leaves) drives a full
cascading-revocation run whose trace is checked by
`validate_delegated_auth_*`.

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
