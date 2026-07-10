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

## Hardened plugin: `macaroon`

An independent macaroon implementation (Birgisson et al., NDSS 2014) of the
same capability-delegation shape, built around the observation that the HMAC
chain proves *provenance*, not *permission*: any holder can extend the chain
with an arbitrary link and compute a valid signature, so `verify`
independently re-walks every link and rejects scope escalation, TTL
widening, broken delegator→audience linkage, expiry, and revoked prefixes —
each with a typed `ValueError` subclass. Presentation binding extends the
protocol surface without breaking it: `verify(token, presenter=None)` keeps
the exact `Auth` signature for presenter-blind callers. Delegation TTLs are
anchored at the logical *now* and may never outlive the parent
(`TtlViolationError` at mint — no dead-on-arrival children); offline
`attenuate` needs no clock and no secret. Attack probes run against **both**
this plugin and `jwt` via adapters (denied here, admitted there), and the
`capability_delegation` scenario's trace is replayed offline by an
independent validator, byte-deterministic in both arms.

Source: [`nest_plugins_reference/auth/macaroon.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/macaroon.py).
Validators: [`nest_plugins_reference/validators/capability_delegation_validators.py`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/capability_delegation_validators.py).
Scenario: [`scenarios/capability_delegation.yaml`](../../scenarios/capability_delegation.yaml).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.auth`.

Good fits to test here: real JWT/PASETO/biscuit/macaroons, OAuth-style
flows, capability delegation, revocation propagation.
