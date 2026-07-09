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

### Virtual clock wiring

`ScenarioRunner` automatically instantiates `JwtAuth` (when still a class)
and binds it to the simulator's virtual clock via `wire_auth_to_sim_clock()`.
Token expiry and revocation therefore follow `sim.clock.now`, not wall
clock time. This applies in both single-process and distributed worker runs.

### Secrets

| Variable | Purpose |
|----------|---------|
| `NEST_JWT_SECRET` | HMAC secret for JwtAuth outside simulation defaults |

The reference plugin ships with `KNOWN_WEAK_SECRET = b"nest-default-secret"`
for simulation convenience. `JwtAuth` emits a runtime warning when this
default is used. **Set `NEST_JWT_SECRET` for any non-simulation deployment.**

## Auth scope middleware

The built-in `auth_scope` middleware enforces bearer tokens with a
required scope on **inbound** messages:

```yaml
middleware:
  - name: auth_scope
    config:
      required_scope: read
```

Behavior:

- **Missing token** — message denied (`missing_auth_token`)
- **Invalid or expired token** — message denied
- **Missing required scope** — message denied (`missing_scope:read`)
- **No auth plugin configured** — message denied (`auth_plugin_missing`);
  does not silently pass through

Ensure `layers.auth: jwt` (or your auth plugin) is set when using
`auth_scope`. See [`security-audit.md`](../security-audit.md).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
