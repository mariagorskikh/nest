# Memory layer

**What it does.** Shared key-value store with subscribe and
compare-and-swap.

## Interface

```python
class Memory(Protocol):
    async def read(self, key: str) -> bytes | None: ...
    async def write(self, key: str, value: bytes) -> None: ...
    async def subscribe(self, key: str) -> AsyncIterator[bytes]: ...
    async def cas(self, key: str, expected: bytes, new: bytes) -> bool: ...
```

Full definition: [`nest_core/layers/memory.py`](../../packages/nest-core/nest_core/layers/memory.py).

## Default plugin

`blackboard` -- shared in-process dict with subscribe + CAS.

Source: [`nest_plugins_reference/memory/blackboard.py`](../../packages/nest-plugins-reference/nest_plugins_reference/memory/blackboard.py).

## CRDT plugin: `lww_register`

`lww_register` -- a state-based **LWW-Register CvRDT**. Unlike `blackboard`,
which resolves concurrent writes by wall-arrival order and silently diverges
when replicas apply the same writes in a different order, `lww_register` tags
every write with a Lamport clock and a stable node id so that *merge* is
commutative, associative, and idempotent. Replicas that have seen the same
writes converge to byte-identical state regardless of delivery order,
duplication, or loss -- strong eventual consistency.

Source: [`nest_plugins_reference/memory/lww_register.py`](../../packages/nest-plugins-reference/nest_plugins_reference/memory/lww_register.py).

It implements the full `Memory` protocol (`read` / `write` / `cas` /
`subscribe`) plus a small replication channel -- `export` / `merge` /
`export_all` / `merge_all` -- used to gossip register state between replicas.
The register for a key is stored as grep-able JSON so it stays inspectable in
a trace::

    {"crdt": "lww_register", "payload": "<base64>", "lamport": 3, "node": "agent-2"}

```python
a = LwwRegisterMemory("a")
b = LwwRegisterMemory("b")
await a.write("k", b"from-a")
await b.write("k", b"from-b")
await b.merge("k", a.export("k"))   # gossip a -> b
await a.merge("k", b.export("k"))   # gossip b -> a
assert await a.read("k") == await b.read("k")   # converged, any order
```

### Convergence validators

`nest_core.validators` ships two checks for this plugin:

- `validate_crdt_convergence(make_replica, writes, delivery_orders)` --
  the adversarial driver: it delivers the same writes to each replica in a
  *different* order and asserts they all read back the same value. It **fails**
  for `blackboard` and **passes** for `lww_register`.
- `validate_memory_convergence(events)` -- registered for the
  `memory_concurrent_writers` scenario; confirms every agent's final replica
  state in the trace is identical.

### Demo scenario

`scenarios/memory_concurrent_writers.yaml` -- 8 agents each own a replica,
write the same key, and gossip to convergence under 10% message drop:

```bash
nest run scenarios/memory_concurrent_writers.yaml
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/memory_concurrent_writers.jsonl'), 'memory_concurrent_writers'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```

The trace is byte-identical under seeds 42, 7, and 1337.

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.memory`.

Good fits to test here: CRDTs (LWW-Register, OR-Set), tuple spaces,
eventually-consistent stores, snapshot isolation.

## CRDT plugin: `pn_counter`

`pn_counter` -- a state-based **PN-Counter CvRDT** for signed evidence
aggregation. Where `lww_register` picks one winning payload, `pn_counter`
preserves every observed positive and negative delta exactly once. This is the
right memory shape for vote deltas, reputation reports, calculator-project
readiness scores, or any workflow where concurrent updates should accumulate
instead of clobbering one another.

The mathematical state is two grow-only maps:

```text
positive: node -> non-negative integer
negative: node -> non-negative integer
value = sum(positive) - sum(negative)
merge = pointwise max on both maps
```

The merge is commutative, associative, and idempotent. In the language of
structured memory, convergence is not enough: the invariant is that every
signed evidence contribution survives gossip exactly once.

Trust model: `pn_counter` is primarily a delivery-chaos CRDT -- it tests drops,
duplication, reordering, and merge idempotence, and the pointwise-max join is
immune to all of them. On top of that it **defends its own coordinate**: a
replica knows exactly how much it has locally written, so on merge it clamps any
incoming state that tries to inflate `positive[self]` / `negative[self]` beyond
that truth and counts it in `detected_forgeries`. This closes the one Byzantine
hole a monotone CRDT would otherwise latch forever -- a peer forging *your*
coordinate. Forging a *third* node's coordinate is still not detectable without
per-contribution signatures, so cross-node authorship proof remains the job of
an authenticated wrapper or transport layer.

```python
a = PnCounterMemory("builder")
b = PnCounterMemory("tester")
await a.write("calculator:ready_score", b'{"op":"inc","amount":2}')
await b.write("calculator:ready_score", b'{"op":"dec","amount":1}')
await a.merge("calculator:ready_score", b.export("calculator:ready_score"))
await b.merge("calculator:ready_score", a.export("calculator:ready_score"))
assert await a.read("calculator:ready_score") == b"1"
```

## Gated plugin: `basis_gated`

`basis_gated` -- a thin `Memory` that wraps an inner counter (a `pn_counter` by
default) and only lets a report become a delta if it *restricts onto a declared
basis*. Where `pn_counter` answers "how do concurrent signed deltas converge
without loss", `basis_gated` answers the second question that used to be buried
in scenario glue: "which reports are even allowed to fuse". It validates every
`write`/`fuse` before anything reaches the inner counter:

```text
declare: node -> {basis dimensions}
fuse(report) accepts iff report is a JSON object whose `node` is declared and
whose `basis` is one of that node's dimensions, and (node, basis) has not fused
before; otherwise it is ignored (not-json / not-object / no-overlap /
outside-basis / duplicate) and never written.
```

This makes "memory that only fuses legal evidence" a reusable layer artifact
rather than a property of one bespoke agent: context saturation -- a wall of
natural-language or code-shaped text -- has no `node`/`basis` that restricts
onto the task, so it is ignored no matter how large or plausible it looks.
`read`/`subscribe`/`cas` and the CRDT gossip helpers delegate to the inner
counter, so a basis-gated counter still converges across replicas exactly like a
plain `pn_counter`.

```python
mem = BasisGatedMemory("coordinator", bases={"calculator": {"add", "divide"}})
outcome = await mem.fuse("calculator:ready_score", b'{"node":"calculator","basis":"add"}')
assert outcome.accepted
assert await mem.read("calculator:ready_score") == b"1"
```

### Demo scenario

`scenarios/memory_pn_counter_reports.yaml` -- 8 agents aggregate signed
calculator-project evidence while one noisy stream contributes an explicit
negative signal for irrelevant copypasta-like contamination. The validator
checks both convergence and preservation of the signed total:

```bash
nest run scenarios/memory_pn_counter_reports.yaml
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/memory_pn_counter_reports.jsonl'), 'memory_pn_counter_reports'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```

`scenarios/memory_basis_fusion_calculator.yaml` -- a coordinator acts like a
small typed memory brain. The basis gate lives in the [`basis_gated`](#gated-plugin-basis_gated)
memory plugin (`BasisGatedMemory` wrapping `pn_counter`): `pn_counter` preserves
signed deltas, and the wrapper decides which reports may become deltas. The
coordinator just forwards raw reports to `memory.fuse` and traces the decision.
Reports can fuse into the `calculator` node only if
they restrict onto one of its declared basis dimensions: `add`, `subtract`,
`multiply`, or `divide`. A frozen Project Gutenberg excerpt is used as a
public-domain context-saturation payload with no legal overlap, and an
otherwise well-formed `"horoscope"` report is outside the node's basis, so both
are ignored instead of being stored as meaningful evidence. The coordinator
ships only after all required basis dimensions fuse and the PN-Counter score
reaches the action threshold:

```bash
nest run scenarios/memory_basis_fusion_calculator.yaml
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/memory_basis_fusion_calculator.jsonl'), 'memory_basis_fusion_calculator'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```

`scenarios/memory_code_saturation_calculator.yaml` -- the same basis-fusion
rule, but the saturation payload is a code-shaped excerpt from the permissively
licensed `drivers/gpu/drm/amd/amdgpu/amdgpu_object.c` file in
`torvalds/linux`. This guards against a subtler failure mode: a payload can look
plausibly technical while still having no legal node/basis overlap with the
calculator task. This YAML reuses `task.type: memory_basis_fusion_calculator`
with a different fixture, so the validator and factory stay shared.

```bash
nest run scenarios/memory_code_saturation_calculator.yaml
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/memory_code_saturation_calculator.jsonl'), 'memory_basis_fusion_calculator'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```
