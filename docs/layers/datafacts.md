# Data Facts layer
**What it does.** Publish dataset metadata at a URL, fetch it, gate
access via grants, check whether a published record is still fresh.
## Interface
```python
class DataFacts(Protocol):
    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl: ...
    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata: ...
    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant: ...
    async def verify_freshness(self, url: DataFactsUrl) -> bool: ...
```
Full definition: [`nest_core/layers/datafacts.py`](../../packages/nest-core/nest_core/layers/datafacts.py).
## Default plugin
`datafacts_v1` — in-process metadata registry. Publish → URL; fetch by
URL; permissive ACL.
Source: [`nest_plugins_reference/datafacts/datafacts_v1.py`](../../packages/nest-plugins-reference/nest_plugins_reference/datafacts/datafacts_v1.py).
## Also available: `cid_facts`
Content-addressed registry with provenance DAG and signed freshness proofs.
Scenario: `scenarios/provenance_supply_chain.yaml`.
Source: [`nest_plugins_reference/datafacts/cid_facts.py`](../../packages/nest-plugins-reference/nest_plugins_reference/datafacts/cid_facts.py).
## Writing your own
See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.datafacts`.
Good fits to test here: content-addressed storage (IPFS-style),
signed-manifest schemes, fine-grained ACLs, expiry / TTL policies.
