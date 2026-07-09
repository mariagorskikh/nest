# Identity layer

**What it does.** Sign payloads, verify signatures, resolve an `AgentId`
to a public identity record.

## Interface

```python
class Identity(Protocol):
    def sign(self, payload: bytes) -> Signature: ...
    def verify(self, payload: bytes, sig: Signature, agent: AgentId) -> bool: ...
    async def resolve(self, agent: AgentId) -> AgentIdentity: ...
```

Full definition: [`nest_core/layers/identity.py`](../../packages/nest-core/nest_core/layers/identity.py).

## Default plugin

`did_key` — DID:key-shaped identity for tests. **Uses deterministic
public-key signatures for simulation, not Ed25519.** Don't use it for
anything that needs real cryptographic identity.

Source: [`nest_plugins_reference/identity/did_key.py`](../../packages/nest-plugins-reference/nest_plugins_reference/identity/did_key.py).

## Also available: `ed25519_rotating`

Real Ed25519 (RFC 8032) with key rotation and continuity proofs. Scenario:
`scenarios/identity_rotation.yaml`.

Source: [`nest_plugins_reference/identity/ed25519_rotating.py`](../../packages/nest-plugins-reference/nest_plugins_reference/identity/ed25519_rotating.py).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.identity`.

Good fits to test here: real Ed25519/secp256k1 signing, DID method
implementations, key rotation, multi-key agents.
