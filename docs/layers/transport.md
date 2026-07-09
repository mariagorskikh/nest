# Transport layer

**What it does.** Move opaque byte payloads between agents.

## Interface

```python
class Transport(Protocol):
    async def send(self, to: AgentId, payload: bytes) -> None: ...
    async def receive(self) -> tuple[AgentId, bytes]: ...
    async def broadcast(self, payload: bytes) -> None: ...
```

Full definition: [`nest_core/layers/transport.py`](../../packages/nest-core/nest_core/layers/transport.py).
Import from `nest_sdk` in plugin code.

## Default plugin

`in_memory` — an in-process event queue. Zero latency: `mean_latency`
and `duration` come out as `0.0` unless agents use `ctx.schedule(delay)`
or you write a transport that introduces per-hop delay.

Source: [`nest_plugins_reference/transport/in_memory.py`](../../packages/nest-plugins-reference/nest_plugins_reference/transport/in_memory.py).

## HTTP transport (distributed experiments)

`http` — delivers payloads between workers over HTTP. Used by
`nest run --workers N` and documented in [`../distributed.md`](../distributed.md).

When `workers > 1` or `worker_bind` is not localhost, set
`NEST_HTTP_SHARED_SECRET` before running — the coordinator fails fast
without it, and all bridge traffic requires the `X-Nest-Auth` header.
See [`../security-audit.md`](../security-audit.md).

Source: [`nest_plugins_reference/transport/http_transport.py`](../../packages/nest-plugins-reference/nest_plugins_reference/transport/http_transport.py).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md) for the full walkthrough.
Register under entry point group `nest.plugins.transport`.

A plugin may declare static capabilities:

```python
from nest_sdk import TransportCapabilities

class MyTransport:
    capabilities = TransportCapabilities(
        supports_streaming=False,
        ordered=True,
        reliable=True,
    )
    async def send(self, to, payload): ...
    async def receive(self): ...
    async def broadcast(self, payload): ...
```
