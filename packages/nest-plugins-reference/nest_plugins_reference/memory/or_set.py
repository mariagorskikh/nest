# SPDX-License-Identifier: Apache-2.0
"""OR-Set CRDT memory plugin -- concurrent adds survive, nothing is lost.

This module implements a **state-based observed-remove set** (OR-Set CvRDT)
for the Nanda Town memory layer. It is the complement to the existing
``lww_register`` plugin: where an LWW-Register resolves a concurrent-write
race by *discarding* all but one winner, the OR-Set *keeps every
concurrently added element*. That is the right shape for the shared-catalogue
pain called out in the memory-CRDT problem: when fifty sellers race to claim
entries under one key in ``scenarios/marketplace.yaml``, an LWW register
silently drops forty-nine of them; this plugin preserves all fifty.

Through the base :class:`~nest_core.layers.memory.Memory` protocol the plugin
behaves like a multi-value register built on an OR-Set:

- ``write(key, value)`` performs an *observed-remove* of every element this
  replica has seen for ``key``, then adds ``value`` with a fresh unique tag.
  Locally that reads back exactly like a register write.
- ``read(key)`` returns the element payload when exactly one element is
  live. When concurrent writes from other replicas have merged in, it
  returns **all** live elements as a canonical, sorted JSON array -- a
  deterministic encoding, byte-identical on every converged replica.

Replicas exchange state with ``export`` / ``merge`` exactly like
``lww_register``; the merge is a join on (adds ∪ adds, removes ∪ removes)
and is commutative, associative, and idempotent, which yields strong
eventual consistency: same multiset of operations, any delivery order,
identical bytes on read.

The serialized state for a single key is inspectable JSON so it stays
grep-able inside a JSONL trace::

    {"crdt": "or_set", "adds": {"agent-1:3": "<base64>"}, "removes": ["agent-0:1"]}

Add-tags are ``(node_id, counter)`` pairs -- deterministic, no wall clock, no
global RNG -- so the same seed and operation sequence always produces a
byte-identical merged state.

Example::

    a = OrSetMemory("a")
    b = OrSetMemory("b")
    await a.write("catalogue", b"from-a")
    await b.write("catalogue", b"from-b")
    # Gossip both ways; order does not matter.
    await b.merge("catalogue", a.export("catalogue"))
    await a.merge("catalogue", b.export("catalogue"))
    assert await a.read("catalogue") == await b.read("catalogue")
    # Both concurrent adds survive -- unlike lww_register.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, cast

CRDT_KIND = "or_set"
"""Schema tag stamped into every serialized set, used to detect and validate
CRDT state when it is read back from a trace or the wire."""


class CrdtStateError(ValueError):
    """Raised when a byte string is not a valid serialized OR-Set.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    keep working while callers that care can catch the specific type.

    Example::

        try:
            OrSet.decode(b"not json")
        except CrdtStateError:
            ...
    """


@dataclass
class OrSet:
    """The pure OR-Set state for a single key: tagged adds plus removed tags.

    An element is *live* when at least one of its add-tags has not been
    removed. ``adds`` maps ``"node:counter"`` tags to payload bytes;
    ``removes`` is the set of tags whose adds have been observed-removed.
    The join of two states is the pairwise union of both fields, which is
    commutative, associative, and idempotent -- a genuine semilattice join.

    Example::

        s = OrSet()
        s.adds["a:1"] = b"x"
        assert s.live() == {b"x"}
    """

    adds: dict[str, bytes] = field(default_factory=dict)
    removes: set[str] = field(default_factory=set)

    def live(self) -> set[bytes]:
        """The set of currently visible element payloads.

        Example::

            elements = state.live()
        """
        return {v for tag, v in self.adds.items() if tag not in self.removes}

    def live_tags(self) -> set[str]:
        """Tags of adds that have not been removed.

        Example::

            tags = state.live_tags()
        """
        return {tag for tag in self.adds if tag not in self.removes}

    def join(self, other: OrSet) -> OrSet:
        """Least-upper-bound merge of two OR-Set states.

        Union of adds, union of removes. Commutative, associative, and
        idempotent by construction.

        Example::

            merged = mine.join(theirs)
        """
        return OrSet(
            adds={**self.adds, **other.adds},
            removes=self.removes | other.removes,
        )

    def encode(self) -> bytes:
        """Serialize to canonical, grep-able JSON bytes.

        Keys are sorted at every level, so two equal states always encode to
        identical bytes -- the property the determinism tests pin down.

        Example::

            raw = state.encode()
        """
        data = {
            "crdt": CRDT_KIND,
            "adds": {
                tag: base64.b64encode(payload).decode("ascii")
                for tag, payload in sorted(self.adds.items())
            },
            "removes": sorted(self.removes),
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    @staticmethod
    def decode(raw: bytes) -> OrSet:
        """Parse serialized OR-Set state, validating shape and schema tag.

        Raises:
            CrdtStateError: if ``raw`` is not valid OR-Set JSON.

        Example::

            state = OrSet.decode(raw)
        """
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CrdtStateError(f"not valid OR-Set JSON: {exc}") from exc
        if not isinstance(obj, dict) or obj.get("crdt") != CRDT_KIND:
            raise CrdtStateError("missing or wrong 'crdt' schema tag")
        adds_raw = obj.get("adds")
        removes_raw = obj.get("removes")
        if not isinstance(adds_raw, dict) or not isinstance(removes_raw, list):
            raise CrdtStateError("'adds' must be an object and 'removes' a list")
        try:
            adds = {
                str(tag): base64.b64decode(cast("str", b64), validate=True)
                for tag, b64 in adds_raw.items()
            }
        except (ValueError, TypeError) as exc:
            raise CrdtStateError(f"bad base64 payload: {exc}") from exc
        return OrSet(adds=adds, removes={str(t) for t in removes_raw})


class OrSetMemory:
    """An observed-remove set CRDT implementing the ``Memory`` protocol.

    Each instance is an independent **replica**. Local writes observed-remove
    the elements this replica can currently see, then add the new value under
    a fresh ``node_id:counter`` tag; replicas exchange state with
    :meth:`export` / :meth:`merge`. Because removes only ever name tags the
    replica has *observed*, an add performed concurrently on another replica
    is never covered by the remove and therefore survives the merge -- the
    defining OR-Set guarantee, and the exact behaviour an LWW register cannot
    provide.

    The standard :class:`~nest_core.layers.memory.Memory` surface
    (``read`` / ``write`` / ``cas`` / ``subscribe``) treats values as opaque
    user payloads; the CRDT machinery is internal. The extra
    :meth:`export` / :meth:`merge` / :meth:`export_all` / :meth:`merge_all`
    methods are the replication channel and are additive -- a caller that only
    speaks the base protocol never has to know a set lives underneath.

    Example::

        mem = OrSetMemory("agent-0")
        await mem.write("catalogue", b"widget")
        assert await mem.read("catalogue") == b"widget"
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a replica with a stable, unique ``node_id``.

        The ``node_id`` must be stable for the lifetime of the replica and
        unique across replicas: it namespaces add-tags, which is what makes
        every tag globally unique without wall clocks or global RNG.

        Example::

            mem = OrSetMemory("agent-0")
        """
        self._node_id = str(node_id)
        self._store: dict[str, OrSet] = {}
        self._counter: int = 0
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    @property
    def node_id(self) -> str:
        """The stable node identifier namespacing this replica's add-tags.

        Example::

            assert OrSetMemory("agent-0").node_id == "agent-0"
        """
        return self._node_id

    # -- canonical read encoding -----------------------------------------

    @staticmethod
    def _canonical(elements: set[bytes]) -> bytes | None:
        """Deterministic byte encoding of the live element set.

        One element decodes to itself (register-like reads); several encode
        to a sorted JSON array of base64 strings, so converged replicas
        return byte-identical reads regardless of merge order.

        Example::

            assert OrSetMemory._canonical({b"x"}) == b"x"
        """
        if not elements:
            return None
        if len(elements) == 1:
            return next(iter(elements))
        encoded = sorted(base64.b64encode(e).decode("ascii") for e in elements)
        return json.dumps(encoded, sort_keys=True).encode("utf-8")

    # -- Memory protocol -------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read the live value(s) for ``key`` or ``None`` if empty.

        A single live element is returned as-is. Multiple concurrent
        elements are returned as a canonical sorted JSON array so that the
        caller sees *everything that survived*, deterministically.

        Example::

            val = await mem.read("catalogue")
        """
        state = self._store.get(key)
        if state is None:
            return None
        return self._canonical(state.live())

    async def write(self, key: str, value: bytes) -> None:
        """Observed-remove current elements, then add ``value``.

        Locally this reads back like a register write. Concurrently added
        elements on *other* replicas are untouched -- their tags were not
        observed here, so the remove cannot cover them and they survive the
        next merge. Subscribers are notified, matching the ``blackboard``
        contract that every local write is observable.

        Example::

            await mem.write("catalogue", b"widget")
        """
        state = self._store.setdefault(key, OrSet())
        state.removes |= state.live_tags()
        self._counter += 1
        state.adds[f"{self._node_id}:{self._counter}"] = value
        await self._notify(key)

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Compare-and-swap in terms of the set's natural merge semantics.

        Succeeds when the current canonical read equals ``expected``; the
        swap is an ordinary observed-remove write, so it composes with
        concurrent remote adds instead of clobbering them.

        Example::

            ok = await mem.cas("catalogue", b"widget", b"gadget")
        """
        if await self.read(key) != expected:
            return False
        await self.write(key, new)
        return True

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Subscribe to changes of the canonical value for ``key``.

        Example::

            async for val in mem.subscribe("catalogue"):
                print(val)
        """
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    # -- replication channel ----------------------------------------------

    def export(self, key: str) -> bytes | None:
        """Serialize this replica's full state for ``key`` for gossip.

        Example::

            raw = mem.export("catalogue")
        """
        state = self._store.get(key)
        return state.encode() if state is not None else None

    async def merge(self, key: str, raw: bytes | None) -> None:
        """Join remote serialized state for ``key`` into this replica.

        Merging is idempotent and order-independent; subscribers are only
        notified when the canonical read value actually changes.

        Raises:
            CrdtStateError: if ``raw`` is not valid OR-Set state.

        Example::

            await mem.merge("catalogue", remote_state)
        """
        if raw is None:
            return
        incoming = OrSet.decode(raw)
        current = self._store.get(key, OrSet())
        before = self._canonical(current.live())
        merged = current.join(incoming)
        self._store[key] = merged
        if self._canonical(merged.live()) != before:
            await self._notify(key)

    def export_all(self) -> dict[str, bytes]:
        """Serialize every key's state, for whole-store gossip.

        Example::

            for key, raw in mem.export_all().items():
                await peer.merge(key, raw)
        """
        return {key: state.encode() for key, state in self._store.items()}

    async def merge_all(self, states: dict[str, bytes]) -> None:
        """Merge a whole-store export from a peer replica.

        Example::

            await mem.merge_all(peer.export_all())
        """
        for key, raw in states.items():
            await self.merge(key, raw)

    # -- internals ---------------------------------------------------------

    async def _notify(self, key: str) -> None:
        """Push the current canonical value to subscribers of ``key``.

        Example::

            await mem._notify("catalogue")
        """
        state = self._store.get(key)
        value = self._canonical(state.live()) if state is not None else None
        if value is None:
            return
        for q in self._subscribers.get(key, []):
            await q.put(value)


def _protocol_check() -> None:
    """Static guard that ``OrSetMemory`` satisfies the ``Memory`` protocol.

    Example::

        _protocol_check()
    """
    from nest_core.layers.memory import Memory

    mem: Any = OrSetMemory("check")
    assert isinstance(mem, Memory)
