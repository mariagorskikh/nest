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

## Capability delegation plugin: `capability_tokens`

`capability_tokens` is an HMAC-chained, macaroon-style capability-token
plugin for offline attenuation. A root token is signed by the issuer. Each
holder can delegate a child token without an issuer round-trip by signing the
child caveats with the parent link signature as the HMAC key. Verification
replays the entire chain from the root secret, so scope widening, TTL
extension, signature tampering, and parent-hash substitution fail closed.

The plugin satisfies the base `Auth` protocol and adds explicit audience and
resource guards:

```python
auth = CapabilityTokens(secret=b"root", clock=0.0)
root = await auth.issue(AgentId("coordinator"), ["read", "write"])
child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60)
ctx = await auth.verify_for_audience(child, AgentId("worker"))
ctx = await auth.authorize(child, AgentId("worker"), "read")
```

Revocation is by chain hash. Revoking any ancestor causes every descendant
to fail verification with `RevokedAncestorError` once the verifier has a
fresh revocation view. Revocation views also carry a monotonic epoch: a
verifier configured with `stale_after=0` and cut off from the latest epoch
raises `RevocationViewStaleError` instead of accepting with stale knowledge.

Source: [`nest_plugins_reference/auth/capability_tokens.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/capability_tokens.py).
Scenario: [`scenarios/capability_tokens_delegated_auth.yaml`](../../scenarios/capability_tokens_delegated_auth.yaml).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
