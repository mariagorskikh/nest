# Registry layer
**What it does.** Let agents publish an `AgentCard` describing
themselves and discover other agents by `Query`.
## Interface
```python
class Registry(Protocol):
    async def register(self, card: AgentCard) -> None: ...
    async def lookup(self, query: Query) -> list[AgentCard]: ...
    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]: ...
    async def deregister(self, agent: AgentId) -> None: ...
```
Full definition: [`nest_core/layers/registry.py`](../../packages/nest-core/nest_core/layers/registry.py).
## Default plugin
`in_memory` — dict-based; no persistence, no replication.
Source: [`nest_plugins_reference/registry/in_memory.py`](../../packages/nest-plugins-reference/nest_plugins_reference/registry/in_memory.py).
## Also available: `gossip`
Push-pull anti-entropy registry with per-agent local views. Scenario:
`scenarios/gossip_registry.yaml`.
Source: [`nest_plugins_reference/registry/gossip.py`](../../packages/nest-plugins-reference/nest_plugins_reference/registry/gossip.py).
## Writing your own
See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.registry`.
Good fits to test here: DHT-backed registries, gossip-based discovery,
filtering / capability queries, registry consensus protocols.
