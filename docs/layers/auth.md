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

`delegatable` — HMAC-chained capability tokens for Problem 04. A
coordinator can issue a broad root token, intermediaries can mint narrower
child tokens, and every verify walks the parent chain so revoking or
expiring an ancestor invalidates its descendants.

This is Tier 1 simulator code, not a production auth server. It is
in-process, clockable, and deterministic. The bundled scenarios use it
to test scope narrowing, cascading revocation, presenter binding,
replay rejection, and offline path-scoped write receipts.

Delegated scopes must be covered by the parent grant. For `efs.write:`
scopes, paths are rejected rather than normalized when they contain empty
segments, `.`, `..`, missing leading slashes, or wildcards outside the
final path segment. A child also cannot receive an unchanged wildcard
such as `efs.write:/agents/*`; it must be narrowed to a concrete path
or a narrower wildcard like `efs.write:/agents/leaf-0/*`.

Source: [`nest_plugins_reference/auth/delegatable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/delegatable.py).
Scenario: [`scenarios/delegated_auth.yaml`](../../scenarios/delegated_auth.yaml).

Example::

    auth = DelegatableAuth(clock=0.0)
    root = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
    child = await auth.delegate(root, AgentId("leaf-0"), ["efs.write:/agents/leaf-0/*"], 10.0)
    await auth.verify_for(child, AgentId("leaf-0"), ["efs.write:/agents/leaf-0/report.json"])

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, resource-audience claims, and revocation propagation across replicas.
