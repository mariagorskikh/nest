# SPDX-License-Identifier: Apache-2.0
"""Multi-Value Register CRDT memory plugin -- concurrent writes survive.

This module implements a **state-based multi-value register** (an MV-Register
CvRDT) for the Nanda Town memory layer. It is the causality-tracking sibling
of the ``lww_register`` plugin, and it exists to fix a property that plugin
*cannot* have.

``lww_register`` tags every write with a Lamport clock and totally orders the
writes, so a concurrent write to the same key always has a loser: the register
keeps one payload and **silently drops the other**. That is correct for a
last-writer-wins register, but it means information written by a live agent can
vanish with no error and no trace.

An MV-Register instead tags every write with a **version vector** -- a
``{node: counter}`` map that records, per replica, how many writes this value
causally descends from. Version vectors form a *partial* order, so the register
can tell the difference between:

* one write that *causally follows* another (keep the newer, drop the older), and
* two writes that are *concurrent* (neither has seen the other) -- keep **both**.

The value of a key is therefore a small set of **siblings**: the writes that are
pairwise concurrent under the version-vector order. Merge keeps the maximal
elements of that order, which makes it commutative, associative, and idempotent
-- the three laws that give *strong eventual consistency*. Two replicas that
have observed the same writes hold the same sibling set regardless of delivery
order, duplication, or loss. The difference from LWW is the headline: **no
concurrently-written value is ever lost.**

The serialized state for one key is inspectable JSON so it stays grep-able
inside a JSONL trace::

    {"crdt": "mv_register",
     "values": [{"payload": "<base64>", "vv": {"agent-0": 1}},
                {"payload": "<base64>", "vv": {"agent-1": 1}}]}

Two concurrent writes leave two entries in ``values``. A causal overwrite
leaves one. That shape is exactly what the ``mv_register_siblings`` scenario and
the ``validate_mv_no_concurrent_loss`` adversarial validator assert on.

Example::

    a = MvRegisterMemory("a")
    b = MvRegisterMemory("b")
    await a.write("k", b"from-a")   # concurrent: neither has seen the other
    await b.write("k", b"from-b")
    await b.merge("k", a.export("k"))
    await a.merge("k", b.export("k"))
    assert await a.values("k") == await b.values("k") == [b"from-a", b"from-b"]
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast

CRDT_KIND = "mv_register"
"""Schema tag stamped into every serialized register, used to detect and
validate CRDT state when it is read back from a trace or the wire."""


class MvStateError(ValueError):
    """Raised when a byte string is not a valid serialized MV-Register.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    keep working while callers that care can catch the specific type.

    Example::

        try:
            MvRegisterMemory._decode(b"not json")
        except MvStateError:
            ...
    """


@dataclass(frozen=True)
class VersionVector:
    """An immutable ``{node: counter}`` clock ordered by the CRDT partial order.

    Stored as a tuple of ``(node, counter)`` pairs sorted by node with all
    zero entries dropped, so two vectors that describe the same causal history
    are ``==`` and hash equal regardless of how they were built. That
    canonical form is what makes serialized state byte-identical across
    replicas.

    Example::

        vv = VersionVector.from_dict({"a": 2, "b": 0, "c": 1})
        assert vv.get("a") == 2 and vv.get("b") == 0
    """

    items: tuple[tuple[str, int], ...]

    @staticmethod
    def empty() -> VersionVector:
        """Return the bottom vector (all counters zero).

        Example::

            assert VersionVector.empty().get("a") == 0
        """
        return VersionVector(())

    @staticmethod
    def from_dict(counts: dict[str, int]) -> VersionVector:
        """Build a canonical vector from a ``{node: counter}`` map.

        Zero (and negative) counters are dropped and the remaining pairs are
        sorted by node, so equal histories canonicalize to equal vectors.

        Example::

            VersionVector.from_dict({"b": 1, "a": 2})
        """
        items = tuple(sorted((n, c) for n, c in counts.items() if c > 0))
        return VersionVector(items)

    def as_dict(self) -> dict[str, int]:
        """Return a plain ``{node: counter}`` copy for serialization or edits.

        Example::

            VersionVector.from_dict({"a": 1}).as_dict() == {"a": 1}
        """
        return dict(self.items)

    def get(self, node: str) -> int:
        """Return this vector's counter for ``node`` (0 if absent).

        Example::

            assert VersionVector.from_dict({"a": 3}).get("a") == 3
        """
        for name, count in self.items:
            if name == node:
                return count
        return 0

    def _nodes(self, other: VersionVector) -> set[str]:
        return {n for n, _ in self.items} | {n for n, _ in other.items}

    def merge(self, other: VersionVector) -> VersionVector:
        """Return the pointwise maximum (the join) of two vectors.

        Example::

            a = VersionVector.from_dict({"a": 1})
            b = VersionVector.from_dict({"b": 2})
            assert a.merge(b).as_dict() == {"a": 1, "b": 2}
        """
        merged = {n: max(self.get(n), other.get(n)) for n in self._nodes(other)}
        return VersionVector.from_dict(merged)

    def with_bump(self, node: str, counter: int) -> VersionVector:
        """Return a copy with ``node`` set to ``counter`` (used on local write).

        Example::

            VersionVector.empty().with_bump("a", 1).get("a") == 1
        """
        counts = self.as_dict()
        counts[node] = counter
        return VersionVector.from_dict(counts)

    def dominates(self, other: VersionVector) -> bool:
        """Return True if this vector is >= ``other`` at every node.

        Equal vectors dominate each other; that is intentional and lets the
        merge treat a duplicate as already-seen.

        Example::

            hi = VersionVector.from_dict({"a": 2})
            lo = VersionVector.from_dict({"a": 1})
            assert hi.dominates(lo) and not lo.dominates(hi)
        """
        return all(self.get(n) >= other.get(n) for n in self._nodes(other))

    def strictly_dominates(self, other: VersionVector) -> bool:
        """Return True if this vector causally follows (and differs from) ``other``.

        Example::

            hi = VersionVector.from_dict({"a": 2})
            lo = VersionVector.from_dict({"a": 1})
            assert hi.strictly_dominates(lo)
        """
        return self != other and self.dominates(other)

    def concurrent(self, other: VersionVector) -> bool:
        """Return True if neither vector dominates the other (a real conflict).

        Example::

            a = VersionVector.from_dict({"a": 1})
            b = VersionVector.from_dict({"b": 1})
            assert a.concurrent(b)
        """
        return not self.dominates(other) and not other.dominates(self)


@dataclass(frozen=True)
class Value:
    """A single register payload tagged with the version vector that wrote it.

    Two values are siblings iff their vectors are :meth:`~VersionVector.concurrent`.
    Ordering the tuple ``(vv.items, payload)`` gives a total order used only to
    serialize siblings deterministically -- it is not the causal order.

    Example::

        v = Value(b"hi", VersionVector.from_dict({"a": 1}))
    """

    payload: bytes
    vv: VersionVector

    def sort_key(self) -> tuple[tuple[tuple[str, int], ...], bytes]:
        """Return a deterministic total-order key for stable serialization.

        Example::

            Value(b"x", VersionVector.empty()).sort_key()
        """
        return (self.vv.items, self.payload)


def _keep_maximal(values: list[Value]) -> list[Value]:
    """Return the concurrent survivors: drop any value another strictly follows.

    Deduplicates identical ``(payload, vv)`` pairs, discards every value that is
    strictly dominated by some other value, and returns the result sorted by
    :meth:`Value.sort_key`. What remains is an antichain under the version-vector
    order -- the register's sibling set. This is the whole of the MV-Register
    join, so it is commutative, associative, and idempotent by construction.

    Example::

        survivors = _keep_maximal([older, newer])  # -> [newer]
    """
    unique: dict[tuple[tuple[tuple[str, int], ...], bytes], Value] = {}
    for value in values:
        unique[value.sort_key()] = value
    candidates = list(unique.values())
    survivors = [
        value
        for value in candidates
        if not any(other.vv.strictly_dominates(value.vv) for other in candidates)
    ]
    survivors.sort(key=Value.sort_key)
    return survivors


class MvRegisterMemory:
    """A multi-value register CRDT implementing the ``Memory`` protocol.

    Each instance is an independent **replica**. A local :meth:`write` records
    a value tagged with a version vector that dominates every sibling this
    replica currently holds, so it supersedes them locally; replicas exchange
    state with :meth:`export` / :meth:`merge` (typically gossiped over the
    transport layer). Concurrent writes made on different replicas are kept as
    **siblings** rather than one silently winning, which is the property the
    ``lww_register`` plugin cannot provide.

    The base :class:`~nest_core.layers.memory.Memory` surface
    (``read`` / ``write`` / ``cas`` / ``subscribe``) treats values as opaque
    payloads. Because the base ``read`` returns a single ``bytes``, it returns
    a **deterministic representative** when siblings exist; the additional
    :meth:`values` method returns the full sibling set, and
    :meth:`export` / :meth:`merge` are the replication channel. All three are
    additive -- a caller that only speaks the base protocol never has to know
    the value is multi-valued.

    Example::

        mem = MvRegisterMemory("agent-0")
        await mem.write("counter", b"42")
        assert await mem.read("counter") == b"42"
        assert await mem.values("counter") == [b"42"]
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a replica with a stable, unique ``node_id``.

        The ``node_id`` labels this replica's component of every version
        vector, so it must be stable for the replica's lifetime and unique
        across replicas. Two replicas sharing a ``node_id`` could stamp two
        distinct writes with the same vector and lose the distinction between
        them.

        Example::

            mem = MvRegisterMemory("agent-0")
        """
        self._node_id = str(node_id)
        self._store: dict[str, list[Value]] = {}
        self._clock: int = 0
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    @property
    def node_id(self) -> str:
        """The stable node id labelling this replica in every version vector.

        Example::

            assert MvRegisterMemory("agent-0").node_id == "agent-0"
        """
        return self._node_id

    @property
    def clock(self) -> int:
        """This replica's monotonic local write counter.

        Example::

            assert MvRegisterMemory("a").clock == 0
        """
        return self._clock

    # -- Memory protocol -------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read a single representative payload for ``key`` (``None`` if unset).

        When the key holds concurrent siblings, the representative is the
        smallest payload under the deterministic sibling order, so ``read`` is
        stable and replica-independent. Use :meth:`values` to see every
        sibling -- ``read`` deliberately hides multiplicity to satisfy the
        single-value base protocol, it never resolves the conflict.

        Example::

            val = await mem.read("counter")
        """
        siblings = self._store.get(key)
        if not siblings:
            return None
        return siblings[0].payload

    async def values(self, key: str) -> list[bytes]:
        """Return every concurrent sibling payload for ``key``, deterministically ordered.

        One element for a settled key, several while concurrent writes are
        unresolved, empty if the key is unset. This is the method that exposes
        the MV-Register's defining property: concurrent writes are all here,
        none were dropped.

        Example::

            assert await mem.values("counter") == [b"42"]
        """
        siblings = self._store.get(key)
        if not siblings:
            return []
        return [value.payload for value in siblings]

    async def write(self, key: str, value: bytes) -> None:
        """Locally write ``value`` for ``key``, superseding this replica's siblings.

        The write is tagged with the join of every current sibling's vector,
        with this replica's component advanced to a fresh monotonic counter.
        That vector strictly dominates each current sibling, so the local write
        replaces them -- a write always overrides what *this* replica has
        already observed. Concurrency only arises across replicas, and is
        reconciled at :meth:`merge`. Subscribers are notified, matching the
        blackboard contract that every local write is observable.

        Example::

            await mem.write("counter", b"42")
        """
        self._clock += 1
        joined = VersionVector.empty()
        for sibling in self._store.get(key, []):
            joined = joined.merge(sibling.vv)
        new_vv = joined.with_bump(self._node_id, self._clock)
        self._store[key] = [Value(payload=value, vv=new_vv)]
        await self._notify(key, value)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Yield the representative payload for ``key`` each time it advances.

        Example::

            async for val in mem.subscribe("counter"):
                print(val)
        """
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Compare-and-swap on this replica's representative payload.

        Succeeds iff the current representative equals ``expected``, in which
        case it performs a normal tagged :meth:`write` of ``new``. Like the
        LWW plugin, this is linearizable *on this replica*; across replicas the
        CRDT merge -- not CAS -- reconciles state, so a swap that raced a
        concurrent write elsewhere surfaces as a sibling at the next
        :meth:`merge` rather than being lost.

        Example::

            ok = await mem.cas("counter", b"42", b"43")
        """
        current = await self.read(key)
        if current == expected:
            await self.write(key, new)
            return True
        return False

    # -- CRDT replication channel ---------------------------------------

    def export(self, key: str) -> bytes | None:
        """Serialize the sibling set for ``key`` for gossip (``None`` if unset).

        The result is valid input to another replica's :meth:`merge`.

        Example::

            state = mem.export("counter")
        """
        siblings = self._store.get(key)
        if not siblings:
            return None
        return self._encode_values(siblings)

    def export_all(self) -> bytes:
        """Serialize this replica's full state for a full-state anti-entropy push.

        Example::

            snapshot = mem.export_all()
        """
        data = {
            "crdt": CRDT_KIND,
            "registers": {
                key: {"values": self._values_to_json(siblings)}
                for key, siblings in sorted(self._store.items())
            },
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    async def merge(self, key: str, state: bytes) -> bool:
        """Merge a remote sibling set for ``key`` into the local replica.

        Unions the incoming siblings with the local ones and keeps the maximal
        elements of the version-vector order (:func:`_keep_maximal`), so causal
        overwrites collapse and genuine conflicts stay as siblings. Advances
        this replica's local counter past any observed component so a later
        local write still dominates. Returns ``True`` if the representative
        payload changed, in which case subscribers are notified. Idempotent:
        merging the same state twice is a no-op.

        Example::

            changed = await mem.merge("counter", other.export("counter"))
        """
        incoming = self._decode_values(state)
        before = self._store.get(key, [])
        before_repr = before[0].payload if before else None
        for value in incoming:
            self._clock = max(self._clock, value.vv.get(self._node_id))
        merged = _keep_maximal(before + incoming)
        self._store[key] = merged
        after_repr = merged[0].payload if merged else None
        if merged != before:
            if after_repr is not None and after_repr != before_repr:
                await self._notify(key, after_repr)
            return True
        return False

    async def merge_all(self, state: bytes) -> list[str]:
        """Merge a full-state snapshot, returning the keys whose value changed.

        Example::

            changed_keys = await mem.merge_all(other.export_all())
        """
        registers = self._decode_all(state)
        changed: list[str] = []
        for key in sorted(registers):
            if await self.merge(key, self._encode_values(registers[key])):
                changed.append(key)
        return changed

    # -- internals -------------------------------------------------------

    async def _notify(self, key: str, payload: bytes) -> None:
        for q in self._subscribers.get(key, []):
            await q.put(payload)

    @staticmethod
    def _values_to_json(values: list[Value]) -> list[dict[str, Any]]:
        return [
            {
                "payload": base64.b64encode(value.payload).decode("ascii"),
                "vv": value.vv.as_dict(),
            }
            for value in values
        ]

    @classmethod
    def _encode_values(cls, values: list[Value]) -> bytes:
        data = {"crdt": CRDT_KIND, "values": cls._values_to_json(values)}
        return json.dumps(data, sort_keys=True).encode("utf-8")

    @staticmethod
    def _loads_object(state: bytes) -> object:
        try:
            return json.loads(state)
        except (ValueError, TypeError) as exc:
            msg = "state is not valid JSON"
            raise MvStateError(msg) from exc

    @staticmethod
    def _value_from_fields(fields: dict[str, Any]) -> Value:
        try:
            payload = base64.b64decode(fields["payload"])
            raw_vv = fields["vv"]
        except (KeyError, ValueError, TypeError) as exc:
            msg = f"malformed value fields: {fields!r}"
            raise MvStateError(msg) from exc
        if not isinstance(raw_vv, dict):
            msg = f"version vector must be an object: {raw_vv!r}"
            raise MvStateError(msg)
        counts: dict[str, int] = {}
        for node, count in cast("dict[str, Any]", raw_vv).items():
            try:
                counts[str(node)] = int(count)
            except (ValueError, TypeError) as exc:
                msg = f"version-vector counter for {node!r} is not an int"
                raise MvStateError(msg) from exc
        return Value(payload=payload, vv=VersionVector.from_dict(counts))

    @classmethod
    def _values_from_list(cls, raw: object, ctx: str) -> list[Value]:
        if not isinstance(raw, list):
            msg = f"{ctx} 'values' must be a list"
            raise MvStateError(msg)
        result: list[Value] = []
        for entry in cast("list[Any]", raw):
            if not isinstance(entry, dict):
                msg = f"{ctx} value must be an object: {entry!r}"
                raise MvStateError(msg)
            result.append(cls._value_from_fields(cast("dict[str, Any]", entry)))
        return result

    @classmethod
    def _decode_values(cls, state: bytes) -> list[Value]:
        obj = cls._loads_object(state)
        if not isinstance(obj, dict):
            msg = f"not an {CRDT_KIND} register: {obj!r}"
            raise MvStateError(msg)
        data = cast("dict[str, Any]", obj)
        if data.get("crdt") != CRDT_KIND:
            msg = f"not an {CRDT_KIND} register: {data!r}"
            raise MvStateError(msg)
        return cls._values_from_list(data.get("values"), "register")

    @classmethod
    def _decode_all(cls, state: bytes) -> dict[str, list[Value]]:
        obj = cls._loads_object(state)
        if not isinstance(obj, dict):
            msg = f"not an {CRDT_KIND} snapshot: {obj!r}"
            raise MvStateError(msg)
        data = cast("dict[str, Any]", obj)
        if data.get("crdt") != CRDT_KIND:
            msg = f"not an {CRDT_KIND} snapshot: {data!r}"
            raise MvStateError(msg)
        raw = data.get("registers", {})
        if not isinstance(raw, dict):
            msg = "snapshot 'registers' must be an object"
            raise MvStateError(msg)
        result: dict[str, list[Value]] = {}
        for key, fields in cast("dict[str, Any]", raw).items():
            if not isinstance(fields, dict):
                msg = f"register for {key!r} must be an object"
                raise MvStateError(msg)
            values = cast("dict[str, Any]", fields).get("values")
            result[str(key)] = cls._values_from_list(values, f"register {key!r}")
        return result
