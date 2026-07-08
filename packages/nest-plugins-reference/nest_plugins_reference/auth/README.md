# DelegatableAuth Plugin

Solves Problem 04 (auth-capability-delegation): the reference `jwt_auth` plugin supports only flat credential issuance with no delegation, revocation cascading, or scope enforcement beyond expiry.

## How to run it

```bash
cd packages/nest-plugins-reference
pip install -e .
nest run ../../scenarios/delegated_auth.yaml -o ./traces/delegated_auth.jsonl
```

## How to test it

```bash
cd packages/nest-plugins-reference
pytest tests/test_delegatable_auth.py -v
```

## How it works

- **HMAC-chain delegation**: each delegated token carries the HMAC of all ancestor payloads. The verifier recomputes the chain to ensure no intermediary was forged.
- **Prefix-trie revocation**: revoking `"alice"` cascades to all `"alice.*"` delegates. Revoke checks run in O(path segment count).
- **Scope monotonicity**: delegates cannot grant scopes they don't possess (`ScopeEscalationError`).
- **Audience enforcement**: every verification requires `resource_id` to match the token's `aud`.

## Result

- 29 tests covering issue, verify, revoke, delegate, scope escalation, stale-parent invalidation, audience mismatch, and reuse.
- 3 adversarial validators prove the reference `jwt_auth` is vulnerable to all three attacks; `DelegatableAuth` blocks all three.

## Limits

Does not yet handle token expiry (TTL). Does not support wildcard resource patterns (e.g. `doc:*`).
