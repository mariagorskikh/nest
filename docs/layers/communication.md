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

## Also available: `versioned`

Schema-version envelopes for migration testing. Scenario:
`scenarios/comms_versioning.yaml`.

Source: [`nest_plugins_reference/comms/versioned.py`](../../packages/nest-plugins-reference/nest_plugins_reference/comms/versioned.py).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.comms`.
