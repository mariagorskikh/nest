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

## CRDT plugin: `mv_register`

`mv_register` -- a state-based **Multi-Value Register CvRDT**. It is the
causality-tracking counterpart of `lww_register`, and it exists to fix a
property that plugin cannot have.

`lww_register` totally orders writes by their Lamport clock, so a concurrent
write to the same key always has a loser: the register keeps one payload and
**silently drops the other**. That is correct for last-writer-wins, but it means
a value written by a live agent can vanish with no error and no trace line.

`mv_register` instead tags every write with a **version vector** -- a
`{node: counter}` map that records, per replica, how many writes this value
causally descends from. Version vectors form a *partial* order, so the register
can tell a causal overwrite (keep the newer, drop the older) apart from a
genuine conflict (two writes that never saw each other) and keep **both** of the
latter as *siblings*. Merge keeps the maximal elements of that order, which is
commutative, associative, and idempotent -- so replicas still reach strong
eventual consistency, but the invariant they converge on is stronger: **no
concurrently-written value is ever lost.**

Source: [`nest_plugins_reference/memory/mv_register.py`](../../packages/nest-plugins-reference/nest_plugins_reference/memory/mv_register.py).

It implements the full `Memory` protocol plus the same `export` / `merge` /
`export_all` / `merge_all` replication channel, and adds one method --
`values(key)` -- that returns every concurrent sibling (base `read` returns a
single deterministic representative to satisfy the single-value protocol). The
value for a key is stored as grep-able JSON; two concurrent writes leave two
entries, a causal overwrite leaves one::

    {"crdt": "mv_register",
     "values": [{"payload": "<base64>", "vv": {"agent-0": 1}},
                {"payload": "<base64>", "vv": {"agent-1": 1}}]}

```python
a = MvRegisterMemory("a")
b = MvRegisterMemory("b")
await a.write("k", b"from-a")       # concurrent: neither has seen the other
await b.write("k", b"from-b")
await b.merge("k", a.export("k"))   # gossip a -> b
await a.merge("k", b.export("k"))   # gossip b -> a
assert await a.values("k") == await b.values("k") == [b"from-a", b"from-b"]
```

### When to pick which

Use `lww_register` when one value must win and losing a concurrent write is
acceptable (a last-known-status field, a cache entry). Use `mv_register` when
losing a concurrent write is a bug and the application would rather see the
conflict and resolve it (a shared tag set, an agent's claim on a resource, any
"merge later" field). The difference is observable: after `N` agents write the
same key concurrently, `lww_register` keeps 1 value and `mv_register` keeps `N`.

### No-loss validators

- `validate_mv_no_concurrent_loss(make_replica, values)`
  ([`nest_plugins_reference/validators`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/mv_register_validators.py))
  -- the adversarial driver: it makes each replica write a distinct value
  concurrently, gossips all-to-all, and asserts every value survives on every
  replica. It **fails** for `lww_register` (each replica keeps one, so `N-1`
  values are lost) and **passes** for `mv_register`.
- `validate_mv_sibling_preservation(events)` -- registered for the
  `mv_register_siblings` scenario; confirms every replica's final state in the
  trace holds the same set of all `N` sibling values.

### Demo scenario

`scenarios/mv_register_siblings.yaml` -- 6 agents each own a replica, write the
same key concurrently, and gossip under 10% message drop. Every replica ends
holding all 6 writes as siblings:

```bash
nest run mv_register_siblings
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/mv_register_siblings.jsonl'), 'mv_register_siblings'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```

The trace is byte-identical under seeds 42, 7, and 1337.

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.memory`.

Good fits to test here: CRDTs (`lww_register` and `mv_register` are already
here; a sequence CRDT such as RGA or an OR-Map would be new ground), tuple
spaces, eventually-consistent stores, snapshot isolation.
