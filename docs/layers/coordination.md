# Coordination layer

**What it does.** Group decisions: propose a task, collect bids/votes,
resolve, commit.

## Interface

```python
class Coordination(Protocol):
    async def propose(self, task: Task) -> Round: ...
    async def participate(self, round: Round) -> Vote | Bid: ...
    async def resolve(self, round: Round) -> Outcome: ...
    async def commit(self, outcome: Outcome) -> None: ...
```

Full definition: [`nest_core/layers/coordination.py`](../../packages/nest-core/nest_core/layers/coordination.py).

## Default plugin

`contract_net` — classic FIPA Contract Net Protocol: propose → bid →
resolve → commit.

Source: [`nest_plugins_reference/coordination/contract_net.py`](../../packages/nest-plugins-reference/nest_plugins_reference/coordination/contract_net.py).

Scenarios that exercise this layer: `auction`, `voting`, `consensus`.
The `consensus` validator checks quorum (default 2/3); it is not full
BFT — that's a great thing to plug your own implementation into.

## Also available: HotStuff BFT

Full multi-replica HotStuff BFT lives in the built-in scenario factory
`bft_hotstuff` with scenarios `bft_consensus_partition` and
`bft_consensus_byzantine`. Wire plugin name `hotstuff` for the conformance wrapper.

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.coordination`.

Good fits to test here: Raft, Paxos, BFT variants (Tendermint, HotStuff,
PBFT), gossip-based aggregation.
