# Communication layer

**What it does.** Frame messages, do (de)serialization, and provide
request/response + discovery semantics on top of raw transport.

## Interface

```python
class CommsProtocol(Protocol):
    def serialize(self, msg: Message) -> bytes: ...
    def deserialize(self, raw: bytes) -> Message: ...
    async def send(self, to: AgentId, msg: Message) -> Response: ...
    async def advertise(self, card: AgentCard) -> None: ...
    async def discover(self, query: Query) -> list[AgentCard]: ...
```

Full definition: [`nest_core/layers/comms.py`](../../packages/nest-core/nest_core/layers/comms.py).

## Default plugin

`nest_native` — minimal JSON envelope with base64-encoded payload.

Source: [`nest_plugins_reference/comms/nest_native.py`](../../packages/nest-plugins-reference/nest_plugins_reference/comms/nest_native.py).

## Alternative plugins

`versioned` — adds an in-band `schema_version` + `kind`, preserves unknown
fields from newer-minor peers, and rejects breaking majors. Solves
*compatibility* across a rolling upgrade, but trusts the wire.

Source: [`nest_plugins_reference/comms/versioned.py`](../../packages/nest-plugins-reference/nest_plugins_reference/comms/versioned.py).

`authenticated` — a strict superset of `versioned` that binds an
`HMAC-SHA256` tag over the *entire* canonical envelope (version, kind, and
every field), keyed by a per-pair channel secret an on-path attacker does not
hold. This makes tampering **evident**: rewriting `schema_version` back to an
older, more permissive value (a *version rollback*, cf. TLS `POODLE`/`FREAK`)
or stripping a field a newer peer added breaks the tag and the envelope is
refused with a `DowngradeError`. Untagged legacy traffic still flows in the
default permissive mode; set `require_auth=True` once every peer is upgraded to
refuse any unauthenticated envelope.

Source: [`nest_plugins_reference/comms/authenticated.py`](../../packages/nest-plugins-reference/nest_plugins_reference/comms/authenticated.py).

Verify the downgrade defense end-to-end (the validator fails on `versioned`,
passes on `authenticated`):

```bash
nest run scenarios/comms_downgrade_attack.yaml
python -c "from pathlib import Path; from nest_core.validators import validate_trace; \
    [print('PASS' if r.passed else 'FAIL', r.name, '-', r.detail) \
     for r in validate_trace(Path('traces/comms_downgrade_attack.jsonl'), 'comms_downgrade')]"
```

Threat model: the tag proves *integrity and pairwise authenticity* under an
on-path attacker who can read, modify, drop, or reorder bytes but lacks the
channel key. Key exchange (the pre-shared secret stands in for an ECDH session
key) and replay of verbatim envelopes are out of scope — bind a nonce into
`metadata` to close replay separately.

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.comms`.
