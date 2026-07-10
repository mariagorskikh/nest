# SPDX-License-Identifier: Apache-2.0
"""OR-Set CRDT memory plugin -- conflict-free shared *sets*.

This module implements a **state-based observed-remove set** (an OR-Set CvRDT)
for the Nanda Town memory layer. Where the ``lww_register`` plugin models a
single-value cell whose concurrent writers fight until one wins, an OR-Set
models a *growing set* whose concurrent writers all survive: two replicas that
each add a different element to the same key converge to the **union** of both
adds, never dropping one. That makes it the right primitive whenever the value
under a key is a collection -- a capability list, a set of subscriptions, group
membership, a bag of observed peers -- rather than a scalar.

The defining property is **add-wins under concurrency**: a remove only cancels
the specific adds it has *observed* (each add carries a unique tag), so an add
that is concurrent with a remove is not observed by that remove and therefore
survives. A last-writer-wins register cannot express this; it would silently
discard one of the two concurrent contributions.

Like every CvRDT here, the merge (:meth:`OrSet.join`) is the least-upper-bound
of two grow-only tag sets and is therefore **commutative, associative, and
idempotent** -- the three laws that guarantee *strong eventual consistency*:
replicas that have observed the same operations converge to byte-identical
state regardless of delivery order, duplication, or loss.

State for a single key is encoded as inspectable JSON so it stays grep-able
inside a JSONL trace::

    {"crdt": "or_set",
     "adds": [["YQ==", "agent-2", 1]],   # [base64(element), node, counter]
     "removes": [["agent-2", 0]]}         # [node, counter]

An element is *present* iff it has at least one add-tag that is not in
``removes``. Because tags are globally unique ``(node, counter)`` pairs, the
union of two states is a genuine semilattice join and the present-set is a
deterministic function of that state.

The set is exposed through the standard
:class:`~nest_core.layers.memory.Memory` surface with **set semantics**:
``write(key, value)`` *adds* ``value`` to the set at ``key`` (it accumulates;
use :meth:`remove` to retract), and ``read(key)`` returns the current members
as a canonical JSON array of base64 strings. The extra
:meth:`add` / :meth:`remove` / :meth:`elements` / :meth:`contains` methods are
the natural set API, and :meth:`export` / :meth:`merge` (plus the ``_all``
variants) are the replication channel, exactly mirroring ``lww_register``.

Example::

    a = OrSetMemory("a")
    b = OrSetMemory("b")
    await a.write("caps", b"read")     # concurrent adds to the same key
    await b.write("caps", b"write")
    await b.merge("caps", a.export("caps"))   # gossip both ways
    await a.merge("caps", b.export("caps"))
    assert await a.elements("caps") == [b"read", b"write"]  # both survive
    assert await a.read("caps") == await b.read("caps")
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

Tag = tuple[str, int]
"""A globally unique add identifier: ``(node_id, per_replica_counter)``."""


def _empty_adds() -> frozenset[tuple[bytes, Tag]]:
    return frozenset()


def _empty_removes() -> frozenset[Tag]:
    return frozenset()


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


@dataclass(frozen=True)
class OrSet:
    """An immutable observed-remove set with add-wins merge semantics.

    ``adds`` is the observed set of ``(element, tag)`` pairs; ``removes`` is the
    set of tombstoned tags. An element is present iff it owns an add-tag that is
    not tombstoned. Every mutating method returns a *new* ``OrSet``, so the
    value is safe to share and its :meth:`join` is a pure semilattice join --
    commutative, associative, and idempotent.

    Example::

        s = OrSet().add(b"x", ("a", 1))
        assert s.contains(b"x")
        assert not s.remove(b"x").contains(b"x")
    """

    adds: frozenset[tuple[bytes, Tag]] = field(default_factory=_empty_adds)
    removes: frozenset[Tag] = field(default_factory=_empty_removes)

    def add(self, element: bytes, tag: Tag) -> OrSet:
        """Return a copy with ``element`` observed under a fresh unique ``tag``.

        Example::

            s = OrSet().add(b"x", ("a", 1))
        """
        return OrSet(self.adds | {(element, tag)}, self.removes)

    def remove(self, element: bytes) -> OrSet:
        """Return a copy with every *currently observed* tag of ``element`` tombstoned.

        This is the observed-remove rule: only add-tags visible in this state
        are cancelled, so an add of the same element that this state has not yet
        seen (a concurrent add) is left untouched and will win the merge.

        Example::

            s = OrSet().add(b"x", ("a", 1)).remove(b"x")
            assert not s.contains(b"x")
        """
        live = {tag for (el, tag) in self.adds if el == element and tag not in self.removes}
        if not live:
            return self
        return OrSet(self.adds, self.removes | live)

    def contains(self, element: bytes) -> bool:
        """Return True if ``element`` has a non-tombstoned add-tag.

        Example::

            assert OrSet().add(b"x", ("a", 1)).contains(b"x")
        """
        return any(el == element and tag not in self.removes for (el, tag) in self.adds)

    def elements(self) -> list[bytes]:
        """Return the present members, sorted for determinism.

        Example::

            assert OrSet().add(b"b", ("n", 2)).add(b"a", ("n", 1)).elements() == [b"a", b"b"]
        """
        present = {el for (el, tag) in self.adds if tag not in self.removes}
        return sorted(present)

    def join(self, other: OrSet) -> OrSet:
        """Least-upper-bound merge (commutative, associative, idempotent).

        Example::

            merged = a.join(b)
            assert merged.join(b) == merged  # idempotent
        """
        return OrSet(self.adds | other.adds, self.removes | other.removes)

    def is_empty(self) -> bool:
        """Return True if the state carries no adds and no removes.

        Example::

            assert OrSet().is_empty()
        """
        return not self.adds and not self.removes

    def value(self) -> bytes:
        """Encode the *present members* as canonical JSON bytes (the read value).

        The value is a sorted JSON array of base64 element strings, so it is
        deterministic and grep-able and two convergent replicas produce
        identical bytes.

        Example::

            v = OrSet().add(b"x", ("a", 1)).value()
        """
        members = [base64.b64encode(el).decode("ascii") for el in self.elements()]
        return json.dumps(members).encode("utf-8")

    def encode(self) -> bytes:
        """Serialize the full CRDT state (adds and removes) to canonical JSON.

        Example::

            raw = OrSet().add(b"x", ("a", 1)).encode()
        """
        data = {
            "crdt": CRDT_KIND,
            "adds": sorted(
                [base64.b64encode(el).decode("ascii"), tag[0], tag[1]] for (el, tag) in self.adds
            ),
            "removes": sorted([node, counter] for (node, counter) in self.removes),
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    @staticmethod
    def decode(state: bytes) -> OrSet:
        """Parse canonical JSON bytes back into an :class:`OrSet`.

        Raises :class:`CrdtStateError` for anything that is not a well-formed
        ``or_set`` state.

        Example::

            s = OrSet.decode(OrSet().add(b"x", ("a", 1)).encode())
        """
        try:
            obj = json.loads(state)
        except (ValueError, TypeError) as exc:
            msg = "state is not valid JSON"
            raise CrdtStateError(msg) from exc
        if not isinstance(obj, dict):
            msg = f"not an {CRDT_KIND} state: {obj!r}"
            raise CrdtStateError(msg)
        data = cast("dict[str, Any]", obj)
        if data.get("crdt") != CRDT_KIND:
            msg = f"not an {CRDT_KIND} state: {data!r}"
            raise CrdtStateError(msg)
        adds = _decode_adds(data.get("adds", []))
        removes = _decode_removes(data.get("removes", []))
        return OrSet(frozenset(adds), frozenset(removes))


def _decode_adds(raw: object) -> set[tuple[bytes, Tag]]:
    if not isinstance(raw, list):
        msg = "'adds' must be a list"
        raise CrdtStateError(msg)
    out: set[tuple[bytes, Tag]] = set()
    for row in cast("list[Any]", raw):
        try:
            payload_b64, node, counter = row
            element = base64.b64decode(payload_b64)
            tag: Tag = (str(node), int(counter))
        except (ValueError, TypeError) as exc:
            msg = f"malformed add row: {row!r}"
            raise CrdtStateError(msg) from exc
        out.add((element, tag))
    return out


def _decode_removes(raw: object) -> set[Tag]:
    if not isinstance(raw, list):
        msg = "'removes' must be a list"
        raise CrdtStateError(msg)
    out: set[Tag] = set()
    for row in cast("list[Any]", raw):
        try:
            node, counter = row
            out.add((str(node), int(counter)))
        except (ValueError, TypeError) as exc:
            msg = f"malformed remove row: {row!r}"
            raise CrdtStateError(msg) from exc
    return out


class OrSetMemory:
    """An OR-Set CRDT implementing the ``Memory`` protocol with set semantics.

    Each instance is an independent **replica**. Local adds are tagged with this
    replica's ``node_id`` and a monotonically increasing counter, guaranteeing
    globally unique tags; replicas exchange state with :meth:`export` /
    :meth:`merge` (typically gossiped over the transport layer). The merge is
    conflict-free, so any set of replicas that have observed the same operations
    read back identical members no matter what order those operations arrived
    in -- and, unlike ``lww_register``, concurrent adds to one key are all
    retained rather than reduced to a single winner.

    The base :class:`~nest_core.layers.memory.Memory` surface is interpreted as
    a set: :meth:`write` adds an element and :meth:`read` returns the members.
    The :meth:`add` / :meth:`remove` / :meth:`elements` / :meth:`contains`
    methods are the explicit set API, and the ``export`` / ``merge`` family is
    the replication channel -- additive, so a caller that only speaks the base
    protocol never has to know the values are CRDT sets.

    Example::

        mem = OrSetMemory("agent-0")
        await mem.write("caps", b"read")
        await mem.write("caps", b"write")
        assert await mem.elements("caps") == [b"read", b"write"]
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a replica with a stable, unique ``node_id``.

        The ``node_id`` must be stable for the replica's lifetime and unique
        across replicas, since it is the node component of every add-tag. Two
        replicas sharing a ``node_id`` could mint colliding tags and break the
        convergence guarantee.

        Example::

            mem = OrSetMemory("agent-0")
        """
        self._node_id = str(node_id)
        self._store: dict[str, OrSet] = {}
        self._clock: int = 0
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    @property
    def node_id(self) -> str:
        """The stable node identifier used in every add-tag minted here.

        Example::

            assert OrSetMemory("agent-0").node_id == "agent-0"
        """
        return self._node_id

    @property
    def clock(self) -> int:
        """The replica's current add counter.

        Example::

            mem = OrSetMemory("a")
            assert mem.clock == 0
        """
        return self._clock

    # -- Memory protocol -------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Return the present members of ``key`` as canonical JSON, or None if unset.

        The value is a sorted JSON array of base64 element strings. A key that
        has never been touched reads as ``None``; a key whose every element was
        removed reads as the empty array ``b"[]"`` -- distinguishing "unset"
        from "empty".

        Example::

            members = await mem.read("caps")
        """
        current = self._store.get(key)
        return current.value() if current is not None else None

    async def write(self, key: str, value: bytes) -> None:
        """Add ``value`` to the set at ``key`` (set semantics: writes accumulate).

        This is an alias for :meth:`add`. To retract a value, use
        :meth:`remove`; a plain write never deletes.

        Example::

            await mem.write("caps", b"read")
        """
        await self.add(key, value)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Yield the canonical member list for ``key`` each time it changes.

        Example::

            async for members in mem.subscribe("caps"):
                print(members)
        """
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Conditionally add ``new`` iff the current member list equals ``expected``.

        ``expected`` is compared against :meth:`read` (the canonical member
        list). On a match this adds ``new`` as an element and returns ``True``;
        otherwise it leaves the set untouched and returns ``False``. As with all
        set operations, cross-replica conflicts are reconciled by the CRDT merge
        rather than by CAS.

        Example::

            ok = await mem.cas("caps", b'["cmVhZA=="]', b"write")
        """
        current = await self.read(key)
        if current == expected:
            await self.add(key, new)
            return True
        return False

    # -- Set API ---------------------------------------------------------

    async def add(self, key: str, element: bytes) -> None:
        """Observe ``element`` under a fresh unique tag and notify subscribers.

        Example::

            await mem.add("caps", b"read")
        """
        self._clock += 1
        current = self._store.get(key, OrSet())
        updated = current.add(element, (self._node_id, self._clock))
        self._store[key] = updated
        await self._notify(key, updated.value())

    async def remove(self, key: str, element: bytes) -> bool:
        """Tombstone every observed tag of ``element`` at ``key`` (observed-remove).

        Returns ``True`` if the element was present and is now removed, ``False``
        if it was already absent. A concurrent add of the same element on
        another replica is *not* observed here and survives the merge.

        Example::

            removed = await mem.remove("caps", b"read")
        """
        current = self._store.get(key)
        if current is None or not current.contains(element):
            return False
        updated = current.remove(element)
        self._store[key] = updated
        await self._notify(key, updated.value())
        return True

    async def elements(self, key: str) -> list[bytes]:
        """Return the present members of ``key`` as decoded bytes, sorted.

        Example::

            members = await mem.elements("caps")
        """
        current = self._store.get(key)
        return current.elements() if current is not None else []

    async def contains(self, key: str, element: bytes) -> bool:
        """Return True if ``element`` is a present member of ``key``.

        Example::

            has_read = await mem.contains("caps", b"read")
        """
        current = self._store.get(key)
        return current.contains(element) if current is not None else False

    # -- CRDT replication channel ---------------------------------------

    def export(self, key: str) -> bytes | None:
        """Serialize the OR-Set state for ``key`` for gossip, or None if unset.

        The result is valid input to another replica's :meth:`merge`.

        Example::

            state = mem.export("caps")
        """
        current = self._store.get(key)
        return current.encode() if current is not None else None

    def export_all(self) -> bytes:
        """Serialize this replica's full state for a full-state anti-entropy push.

        Example::

            snapshot = mem.export_all()
        """
        data = {
            "crdt": CRDT_KIND,
            "keys": {key: json.loads(state.encode()) for key, state in sorted(self._store.items())},
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    async def merge(self, key: str, state: bytes) -> bool:
        """Merge a remote OR-Set for ``key`` into this replica.

        Joins the incoming state by least-upper-bound. Returns ``True`` if the
        present member list changed, in which case subscribers are notified.
        Idempotent: merging the same state twice is a no-op.

        Example::

            changed = await mem.merge("caps", other.export("caps"))
        """
        incoming = OrSet.decode(state)
        current = self._store.get(key, OrSet())
        merged = current.join(incoming)
        self._store[key] = merged
        before = current.value()
        after = merged.value()
        if after != before:
            await self._notify(key, after)
            return True
        return False

    async def merge_all(self, state: bytes) -> list[str]:
        """Merge a full-state snapshot, returning the keys whose members changed.

        Example::

            changed_keys = await mem.merge_all(other.export_all())
        """
        keys = _decode_snapshot(state)
        changed: list[str] = []
        for key in sorted(keys):
            if await self.merge(key, json.dumps(keys[key], sort_keys=True).encode("utf-8")):
                changed.append(key)
        return changed

    # -- internals -------------------------------------------------------

    async def _notify(self, key: str, value: bytes) -> None:
        for q in self._subscribers.get(key, []):
            await q.put(value)


def _decode_snapshot(state: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(state)
    except (ValueError, TypeError) as exc:
        msg = "snapshot is not valid JSON"
        raise CrdtStateError(msg) from exc
    if not isinstance(obj, dict):
        msg = f"not an {CRDT_KIND} snapshot: {obj!r}"
        raise CrdtStateError(msg)
    data = cast("dict[str, Any]", obj)
    if data.get("crdt") != CRDT_KIND:
        msg = f"not an {CRDT_KIND} snapshot: {data!r}"
        raise CrdtStateError(msg)
    raw = data.get("keys", {})
    if not isinstance(raw, dict):
        msg = "snapshot 'keys' must be an object"
        raise CrdtStateError(msg)
    return cast("dict[str, Any]", raw)
