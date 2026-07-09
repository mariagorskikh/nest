---
title: Partition-tolerant BFT consensus with view-change and liveness proofs
layer: coordination
difficulty: hard
status: solved
---
> **Status: SOLVED** — implemented in `scenarios/bft_consensus_partition.yaml` and `scenarios/bft_consensus_byzantine.yaml` with HotStuff BFT.
# Partition-tolerant BFT consensus with view-change and liveness proofs
## Motivation
The default coordination plugin
[`nest_plugins_reference/coordination/contract_net.py`](../../../packages/nest-plugins-reference/nest_plugins_reference/coordination/contract_net.py)
is 95 lines of FIPA Contract Net — a single-round bidding scaffold
that does not even *attempt* consensus: no quorums, no view changes,
no leader election. The `consensus` scenario in
[`scenarios/consensus.yaml`](../../../scenarios/consensus.yaml)
exercises a 2/3 quorum but the validator (`validate_consensus_*` in
[`nest_core/validators.py`](../../../packages/nest-core/nest_core/validators.py)
lines 510-665) only checks that *committed* rounds had ≥2/3 accepts —
it does **not** test what happens under partition, byzantine
followers lying about their votes, or leader failure mid-round. As
the [`docs/layers/coordination.md`](../../../docs/layers/coordination.md)
file explicitly says: "it is not full BFT — that's a great thing to
plug your own implementation into."
PR #5 added sealed-bid coordination (FPSB/Vickrey) — useful for
mechanism design but *not* a consensus protocol. The 4-agent
partition story remains untested.
The simulator already supports partitions
([`nest_core/sim/simulator.py`](../../../packages/nest-core/nest_core/sim/simulator.py)
lines 246-260) and byzantine agents (lines 240-244). The plumbing is
there; the *protocol* to test against it isn't.
Anyone using Nanda Town to validate a real BFT protocol (Tendermint,
HotStuff, PBFT) benefits directly. Anyone building agent
infrastructure that has to survive a single replica failure without
losing a commit benefits. This is hard because BFT is hard — but
Nanda Town is the right place to test it, because the simulator gives you
deterministic adversarial conditions you can't get on a real network.
## Success criteria
- Ship a coordination plugin (suggested name: `bft_hotstuff`,
  `pbft`, or similar — pick one BFT protocol and implement it
  faithfully). Register as `(\"coordination\", \"<your_name>\")` in
  [`nest_core/plugins.py`](../../../packages/nest-core/nest_core/plugins.py).
- The plugin satisfies the existing `Coordination` protocol
  (`propose`/`participate`/`resolve`/`commit`) so the existing
  `consensus` scenario can be pointed at it via
  `layers.coordination: <your_name>`.
- View-change: when the leader fails (or is partitioned from a
  majority), the protocol elects a new leader within a bounded
  number of rounds. The trace must show evidence of the view change.
- **Safety property**: under up to *f* byzantine agents out of *3f+1*
  total, no two honest agents commit conflicting values for the same
  round. (For *f=1*, 4 agents minimum. For *f=2*, 7 agents.)
- **Liveness property**: in the absence of partition, the protocol
  makes progress (commits a round) within bounded time.
- Ship an adversarial validator suite that catches **all four**:
  1. *Conflicting commits*: two honest agents committing different
     values in the same view.
  2. *Equivocation*: a leader sending different proposals to
     different followers.
  3. *Forged quorum*: a `commit` event in the trace not backed by
     ≥ 2f+1 signed votes from distinct agents.
  4. *Stuck view*: no commit progress for K rounds after the
     network is healed.
- Validator FAILS against `contract_net` (trivially, no quorum) and
  PASSES against your plugin.
- Ship `scenarios/bft_consensus_partition.yaml` with 7 agents
  (f=2), a partition splitting them 4/3 for the first 30% of the
  scenario, plus a heal. Trace deterministic under seeds 42, 7,
  1337, and 0xdeadbeef.
- Ship `scenarios/bft_consensus_byzantine.yaml` with 7 agents and
  `failures.byzantine_agents: 0.28` (i.e. 2 byzantine). Safety
  validator must pass; liveness may degrade but commits must still
  happen post-recovery.
## Suggested approach pointers
- HotStuff is the cleanest reference — three-phase voting, linear
  view-change. Castro-Liskov PBFT is more traditional but more
  edges.
- Cryptographic signatures: lean on the `did_key` identity plugin
  for vote signatures. Quorum certificates are sets of signatures.
- Determinism under byzantine: a byzantine agent in Nanda Town sends
  "garbage" (see
  [`nest_core/sim/simulator.py`](../../../packages/nest-core/nest_core/sim/simulator.py)
  line 333) — your protocol must not deserialize garbage as a vote.
- View-change timer: derive timeout from the simulator's logical
  clock, not wall time.
- Borrow the FIPA-state-tracking pattern from PR #5's sealed-bid
  plugin — explicit `status` transitions make traces inspectable.
- Test with `Hypothesis` strategies that generate random partition
  schedules and byzantine vote patterns; safety must hold across
  all of them.
## Anti-patterns
- Don't ship a "consensus" plugin that's actually leader-election +
  Raft (Raft is CFT, not BFT — byzantine validator suite will catch
  it).
- Don't claim BFT and then trust unsigned votes.
- Don't make view-change require global knowledge of agent set.
- Don't skip the equivocation check by assuming an honest leader.
- Don't ship without the byzantine scenario — partition-only is
  half the problem.
## Out of scope
- Open membership (dynamic add/remove of agents mid-scenario).
- Cross-chain interop / IBC-style relay.
- Production-grade performance optimization (pipelining,
  aggregation). Correctness first.
- VRF-based leader election. Round-robin is fine.
