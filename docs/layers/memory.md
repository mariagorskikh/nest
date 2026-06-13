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
