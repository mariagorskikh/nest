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

## CRDT plugin: `or_set`

`or_set` -- a state-based **observed-remove set CvRDT** (Shapiro, Preguica,
Baquero & Zawirski 2011, §3.3.5). Where `lww_register` gives each key a single
last-writer-wins *value*, `or_set` gives each key a *set* with principled add
**and** remove: exactly what a claim/release marketplace needs. Every `add`
mints a unique `(node_id, counter)` tag; every `remove` tombstones only the tags
the remover has *observed*; an element is present iff it has an add-tag that is
not tombstoned. Merge is the pairwise union of the add and tombstone sets
(commutative, associative, idempotent), and concurrent `add`||`remove` resolves
**add-wins**.

Source: [`nest_plugins_reference/memory/or_set.py`](../../packages/nest-plugins-reference/nest_plugins_reference/memory/or_set.py).

`read` returns the present-element list as canonical JSON (sorted,
byte-deterministic); `write` takes a structured op `{"op": "add"|"remove",
"element": <json>}`, with a plain-bytes fallback treated as an add. The per-key
state stays grep-able in a trace::

    {"crdt": "or_set", "adds": {"\"slot-1\"": [["agent-0", 1]]}, "removed": [["agent-1", 4]]}

```python
a = OrSetMemory("a")
b = OrSetMemory("b")
await a.write("held", b'{"op": "add", "element": "slot-1"}')
await b.write("held", b'{"op": "add", "element": "slot-2"}')
await b.merge("held", a.export("held"))   # gossip a -> b
await a.merge("held", b.export("held"))   # gossip b -> a
assert await a.read("held") == await b.read("held")   # converged, any order
```

### Why an OR-Set: a Byzantine-liveness gap `lww_register` has

`lww_register.merge` adopts the higher Lamport clock
(`lww_register.py:305`, `self._clock = max(self._clock, incoming.lamport)`), so
a Byzantine replica that exports a register forged with `lamport = 2**60`
silently suppresses every honest write with a smaller clock. An OR-Set has no
global clock to forge: a Byzantine replica can inflate its own tag counters, but
that only mints Byzantine-owned tags for Byzantine-owned elements -- it cannot
tombstone an add-tag it never observed, so it cannot suppress an honest claim.

`nest_core.validators` ships three checks for `or_set`:

- `validate_memory_honest_write_liveness(make_replica, forge=..., honest_op=...,
  is_visible=...)` -- a Byzantine replica forges state, an honest replica writes
  before observing it, both gossip to convergence. It **fails** `lww_register`
  (forged clock wins) and `blackboard` (later clobber), and **passes** `or_set`.
- `validate_crdt_add_wins_convergence(make_replica, add_op=..., remove_op=...,
  present=...)` -- concurrent `add`||`remove` on one element must converge
  byte-identically *and* resolve add-wins. **Fails** `blackboard`, **passes**
  `or_set`.
- `validate_orset_claims_convergence` / `validate_orset_claims_honest_liveness`
  -- registered for the `memory_orset_claims` scenario; confirm every replica's
  final state is identical and every honest claim survived the attack.

### Demo scenario

`scenarios/memory_orset_claims.yaml` -- 10 honest replicas claim/release slot
ids in one shared OR-Set under 10% message drop while **one Byzantine replica**
injects forged, inflated-counter state throughout the run:

```bash
nest run scenarios/memory_orset_claims.yaml
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/memory_orset_claims.jsonl'), 'memory_orset_claims'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```

Every replica converges and all ten honest claims survive; the trace is
byte-identical under seeds 42, 7, and 1337.

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.memory`.

Good fits to test here: CRDTs (LWW-Register, OR-Set), tuple spaces,
eventually-consistent stores, snapshot isolation.
