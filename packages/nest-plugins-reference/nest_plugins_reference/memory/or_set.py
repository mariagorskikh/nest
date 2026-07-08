# SPDX-License-Identifier: Apache-2.0
"""OR-Set (observed-remove set) CRDT memory plugin -- a set that survives Byzantine merges.

This module implements a **state-based, observed-remove set** (an OR-Set CvRDT)
for the Nanda Town memory layer. Where the ``lww_register`` plugin gives every
key a single last-writer-wins *value*, an OR-Set gives every key a *set* with
principled add **and** remove semantics: exactly what a claim/release
marketplace needs, where ten agents concurrently claim and release slot ids and
the swarm has to converge on *which slots are held* without a coordinator.

The construction is the classic tag-set OR-Set of Shapiro, Preguica, Baquero &
Zawirski, "A comprehensive study of Convergent and Commutative Replicated Data
Types" (INRIA RR-7506, 2011), Section 3.3.5 ("Observed-Remove Set"). Every
``add(e)`` mints a globally unique **tag** and records ``(e, tag)`` in an add
set; every ``remove(e)`` moves the tags the remover has *observed* for ``e``
into a tombstone set. An element is *present* iff it carries at least one
add-tag that is not tombstoned. Merge is the pairwise union of the add sets and
the tombstone sets -- **commutative, associative, and idempotent** -- so any
replicas that have observed the same operations read back byte-identical state
regardless of delivery order, duplication, or loss. Concurrent ``add(e)`` and
``remove(e)`` resolve **add-wins**: the remove only tombstones the tags it saw,
so a concurrent add mints a *fresh* tag the remove could not have observed and
the element stays present.

**Why the tags are structural, not random.** The charter's headline
anti-pattern is nondeterminism smuggled in through ``uuid4``, ``time.time()``,
or an unseeded RNG. This OR-Set mints tags as ``(node_id, counter)`` where
``node_id`` is the replica's stable id and ``counter`` is a per-node,
strictly-monotone integer bumped once per local add. Two tags collide only if
two replicas share a ``node_id`` (the same misconfiguration that breaks
``lww_register``'s tie-break), so uniqueness is *structural* and the whole
plugin replays byte-for-byte under a fixed seed.

**Why an OR-Set and not just an LWW-Register.** A register has no principled
delete -- "erase" is modelled as writing a tombstone sentinel and hoping every
replica agrees it means "gone". More importantly, ``lww_register`` merges by
adopting the higher Lamport clock (``lww_register.py:305``), so a Byzantine
replica that exports a register forged with ``lamport = 2**60`` silently
suppresses every honest write with a smaller clock. An OR-Set has no global
clock to forge: a Byzantine replica can inflate its *own* tag counters as high
as it likes, but that only mints Byzantine-owned tags for Byzantine-owned
elements. It cannot tombstone an add-tag it never observed, so it cannot
suppress an honest claim. That difference is the point of this submission and
is pinned by ``validate_memory_honest_write_liveness``.

The per-key state is encoded as inspectable, canonical JSON so it stays
grep-able inside a JSONL trace::

    {"crdt": "or_set",
     "adds": {"\\"slot-1\\"": [["agent-0", 1]]},
     "removed": [["agent-1", 4]]}

Example::

    a = OrSetMemory("a")
    b = OrSetMemory("b")
    await a.write("held", b'{"op": "add", "element": "slot-1"}')
    await b.write("held", b'{"op": "add", "element": "slot-2"}')
    # Gossip both ways; order does not matter.
    await b.merge("held", a.export("held"))
    await a.merge("held", b.export("held"))
    assert await a.read("held") == await b.read("held")
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, cast

CRDT_KIND = "or_set"
"""Schema tag stamped into every serialized OR-Set, used to detect and validate
CRDT state when it is read back from a trace or the wire."""

# A causal add-tag: a replica's stable node id paired with a per-node,
# strictly-monotone counter. Structural (not random), so replays are
# byte-identical under a fixed seed.
Tag = tuple[str, int]

# Structured-write op verbs understood by :meth:`OrSetMemory.write`.
_OP_ADD = "add"
_OP_REMOVE = "remove"


class OrSetStateError(ValueError):
    """Raised when a byte string is not a valid serialized OR-Set state.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    (such as the gossip loop in the concurrent-writers scenario) keep working
    while callers that care can catch the specific type. Decoding validates the
    whole payload *before* any local state is touched, so a malformed or
    Byzantine-garbled merge can never leave a replica half-updated.

    Example::

        try:
            OrSetMemory._decode(b"not json")
        except OrSetStateError:
            ...
    """


@dataclass
class _KeyState:
    """The OR-Set state for a single key: an add set and a tombstone set.

    ``adds`` maps each element's canonical-JSON key to the set of add-tags
    minted for it; ``removed`` is the set of tombstoned tags. An element is
    present iff ``adds[element_key] - removed`` is non-empty.

    Example::

        st = _KeyState()
        st.adds["\\"slot-1\\""] = {("agent-0", 1)}
        assert st.present() == {"\\"slot-1\\""}
    """

    adds: dict[str, set[Tag]] = field(default_factory=lambda: dict[str, set[Tag]]())
    removed: set[Tag] = field(default_factory=lambda: set[Tag]())

    def present(self) -> set[str]:
        """Return the element keys with at least one non-tombstoned add-tag.

        Example::

            keys = state.present()
        """
        return {ek for ek, tags in self.adds.items() if tags - self.removed}

    def all_tags(self) -> set[Tag]:
        """Return every tag this key has observed (added or tombstoned).

        Used by :meth:`OrSetMemory.cas` to decide whether a caller's observed
        context still covers the live state.

        Example::

            observed = state.all_tags()
        """
        tags: set[Tag] = set(self.removed)
        for element_tags in self.adds.values():
            tags |= element_tags
        return tags


def _element_key(element: Any) -> str:
    """Canonicalize an element to a stable, hashable string key.

    Two elements are the same set member iff their canonical JSON is equal, so
    ``{"a": 1, "b": 2}`` and ``{"b": 2, "a": 1}`` collapse to one member. The
    compact separators keep the key short inside a trace.

    Example::

        assert _element_key({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    """
    return json.dumps(element, sort_keys=True, separators=(",", ":"))


class OrSetMemory:
    """An observed-remove set CRDT implementing the ``Memory`` protocol.

    Each instance is an independent **replica**. Local writes are structured
    ops that add or remove elements from the set stored at a key; each add
    mints a fresh ``(node_id, counter)`` tag. Replicas exchange state with
    :meth:`export` / :meth:`merge` (typically gossiped over the transport
    layer). Merge is the pairwise union of the add and tombstone sets, so it is
    conflict-free: any set of replicas that have observed the same ops read
    back identical elements no matter the order, duplication, or loss.

    The standard :class:`~nest_core.layers.memory.Memory` surface
    (``read`` / ``write`` / ``cas`` / ``subscribe``) is honoured exactly; the
    CRDT machinery is internal. :meth:`read` returns the present-element list as
    canonical JSON (sorted, byte-deterministic). The extra
    :meth:`export` / :meth:`merge` / :meth:`export_all` / :meth:`merge_all`
    methods are the replication channel and are additive -- a caller that only
    speaks the base protocol never has to know the values are OR-Sets.

    Example::

        mem = OrSetMemory("agent-0")
        await mem.write("held", b'{"op": "add", "element": "slot-1"}')
        assert await mem.read("held") == b'["slot-1"]'
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a replica with a stable, unique ``node_id``.

        The ``node_id`` must be stable for the lifetime of the replica and
        unique across replicas, since it is the first component of every add
        tag. Two replicas sharing a ``node_id`` could mint colliding tags and
        break the convergence guarantee -- the same constraint ``lww_register``
        places on its tie-break id.

        Example::

            mem = OrSetMemory("agent-0")
        """
        self._node_id = str(node_id)
        self._store: dict[str, _KeyState] = {}
        self._counter: int = 0
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    @property
    def node_id(self) -> str:
        """The stable node identifier stamped into every add-tag.

        Example::

            assert OrSetMemory("agent-0").node_id == "agent-0"
        """
        return self._node_id

    @property
    def counter(self) -> int:
        """The current per-node monotone add counter of this replica.

        Example::

            mem = OrSetMemory("a")
            assert mem.counter == 0
        """
        return self._counter

    # -- Memory protocol -------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read the present-element list for ``key`` as canonical JSON bytes.

        Returns ``None`` if the key was never written. Otherwise returns the
        JSON array of currently-present elements, sorted by their canonical
        key so the bytes are identical on every converged replica -- e.g.
        ``b'["slot-1","slot-3"]'``. An empty set reads back as ``b'[]'``.

        Example::

            val = await mem.read("held")
        """
        state = self._store.get(key)
        if state is None:
            return None
        present = sorted(state.present())
        elements = [json.loads(ek) for ek in present]
        return json.dumps(elements, separators=(",", ":")).encode("utf-8")

    async def write(self, key: str, value: bytes) -> None:
        """Apply a structured add/remove op to the set at ``key``.

        ``value`` is parsed as a JSON object ``{"op": "add"|"remove",
        "element": <json>}``. An ``add`` mints a fresh ``(node_id, counter)``
        tag for the element; a ``remove`` tombstones exactly the add-tags this
        replica has *observed* for the element (observed-remove semantics), so
        a concurrent add elsewhere is unaffected and add-wins holds.

        **Plain-bytes fallback.** If ``value`` is not a well-formed op object,
        it is treated as ``add`` of the raw payload decoded as a UTF-8 string.
        This keeps the plugin drop-in for base-protocol callers (and scenarios)
        that write opaque byte values without knowing the memory layer is a
        set: ``await mem.write("held", b"slot-1")`` adds the element
        ``"slot-1"``. A remove therefore always requires the explicit op form,
        which is the safe default -- an ambiguous byte string never silently
        deletes.

        Example::

            await mem.write("held", b'{"op": "add", "element": "slot-1"}')
            await mem.write("held", b'{"op": "remove", "element": "slot-1"}')
        """
        op, element = self._parse_op(value)
        state = self._store.setdefault(key, _KeyState())
        if op == _OP_REMOVE:
            element_key = _element_key(element)
            observed = state.adds.get(element_key, set())
            if observed:
                state.removed |= observed
        else:
            self._counter += 1
            tag: Tag = (self._node_id, self._counter)
            element_key = _element_key(element)
            state.adds.setdefault(element_key, set()).add(tag)
        await self._notify(key)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Yield the present-element JSON each time the set at ``key`` advances.

        Example::

            async for val in mem.subscribe("held"):
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
        """Observed-context compare-and-swap: apply ``new`` only if not raced.

        Unlike a register CAS -- which compares a single winning value --
        an OR-Set CAS compares *causal context*. ``expected`` is an OR-Set
        state export (typically ``mem.export(key)`` captured earlier) describing
        the tag-set the caller has observed. The swap succeeds iff that observed
        context **covers** the key's current tag-set -- i.e. no add or remove
        tag has appeared that the caller did not see. On success ``new`` (a
        structured op) is applied; on a stale context the call returns ``False``
        without mutating state, so it can never blindly clobber a concurrent
        update it never observed.

        This is the CRDT's *natural* conflict rule rather than blackboard's
        racing last-writer CAS: because merge unions add-tags, an update
        admitted here is never lost, and an update it did *not* see is never
        overwritten. :mod:`test_or_set_properties` pins the lost-update-freedom
        invariant against a blackboard that races.

        Example::

            ctx = mem.export("held")
            ok = await mem.cas("held", ctx or b"", b'{"op": "add", "element": "slot-9"}')
        """
        try:
            observed = self._observed_tags(expected)
        except OrSetStateError:
            return False
        state = self._store.get(key)
        current = state.all_tags() if state is not None else set[Tag]()
        if not current <= observed:
            return False
        await self.write(key, new)
        return True

    # -- CRDT replication channel ---------------------------------------

    def export(self, key: str) -> bytes | None:
        """Serialize the OR-Set state for ``key`` for gossip.

        Returns ``None`` if the key was never written. The result is valid
        input to another replica's :meth:`merge`.

        Example::

            state = mem.export("held")
        """
        state = self._store.get(key)
        if state is None:
            return None
        return self._encode_state(state)

    def export_all(self) -> bytes:
        """Serialize this replica's full state for a full-state anti-entropy push.

        Example::

            snapshot = mem.export_all()
        """
        data = {
            "crdt": CRDT_KIND,
            "keys": {key: self._state_fields(state) for key, state in sorted(self._store.items())},
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    async def merge(self, key: str, state: bytes) -> bool:
        """Merge a remote OR-Set for ``key`` into the local replica.

        Unions the incoming add and tombstone sets into the local state
        (commutative, associative, idempotent) and advances this replica's
        counter past any observed tag it minted under the same ``node_id`` so a
        future local add cannot re-mint a colliding tag. Returns ``True`` iff
        the present-element set changed, in which case subscribers are
        notified. Idempotent: merging the same state twice is a no-op. Raises
        :class:`OrSetStateError` on malformed input *before* touching state.

        Example::

            changed = await mem.merge("held", other.export("held"))
        """
        incoming = self._decode(state)
        local = self._store.get(key)
        before = local.present() if local is not None else set[str]()
        target = self._store.setdefault(key, _KeyState())
        for element_key, tags in incoming.adds.items():
            target.adds.setdefault(element_key, set()).update(tags)
        target.removed |= incoming.removed
        self._advance_counter(incoming)
        after = target.present()
        if after != before:
            await self._notify(key)
            return True
        return False

    async def merge_all(self, state: bytes) -> list[str]:
        """Merge a full-state snapshot, returning the keys whose value changed.

        Example::

            changed_keys = await mem.merge_all(other.export_all())
        """
        keys = self._decode_all(state)
        changed: list[str] = []
        for key in sorted(keys):
            if await self.merge(key, self._encode_state(keys[key])):
                changed.append(key)
        return changed

    # -- internals -------------------------------------------------------

    async def _notify(self, key: str) -> None:
        subscribers = self._subscribers.get(key)
        if not subscribers:
            return
        snapshot = await self.read(key)
        if snapshot is None:
            return
        for q in subscribers:
            await q.put(snapshot)

    def _advance_counter(self, incoming: _KeyState) -> None:
        """Bump the local counter past any self-minted tag in ``incoming``.

        Keeps ``(node_id, counter)`` strictly monotone for this replica even
        after merging back a state that echoes its own earlier adds, so a fresh
        local add never re-mints a tag that is already tombstoned.
        """
        highest = self._counter
        for tags in incoming.adds.values():
            for node, counter in tags:
                if node == self._node_id and counter > highest:
                    highest = counter
        for node, counter in incoming.removed:
            if node == self._node_id and counter > highest:
                highest = counter
        self._counter = highest

    def _parse_op(self, value: bytes) -> tuple[str, Any]:
        """Parse a structured op, falling back to ``add`` of the raw payload."""
        try:
            obj = json.loads(value)
        except (ValueError, TypeError):
            return _OP_ADD, value.decode("utf-8", errors="replace")
        if isinstance(obj, dict):
            data = cast("dict[str, Any]", obj)
            op = data.get("op")
            if op in (_OP_ADD, _OP_REMOVE) and "element" in data:
                return str(op), data["element"]
        return _OP_ADD, value.decode("utf-8", errors="replace")

    def _observed_tags(self, state: bytes) -> set[Tag]:
        """Decode an export and return every tag it records (adds and removes)."""
        return self._decode(state).all_tags()

    @staticmethod
    def _encode_state(state: _KeyState) -> bytes:
        return json.dumps(
            OrSetMemory._state_fields(state) | {"crdt": CRDT_KIND},
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def _state_fields(state: _KeyState) -> dict[str, Any]:
        return {
            "adds": {
                element_key: _encode_tags(tags)
                for element_key, tags in sorted(state.adds.items())
                if tags
            },
            "removed": _encode_tags(state.removed),
        }

    @staticmethod
    def _loads_object(state: bytes) -> object:
        try:
            return json.loads(state)
        except (ValueError, TypeError) as exc:
            msg = "state is not valid JSON"
            raise OrSetStateError(msg) from exc

    @staticmethod
    def _decode(state: bytes) -> _KeyState:
        obj = OrSetMemory._loads_object(state)
        if not isinstance(obj, dict):
            msg = f"not an {CRDT_KIND} state: {obj!r}"
            raise OrSetStateError(msg)
        data = cast("dict[str, Any]", obj)
        if data.get("crdt") != CRDT_KIND:
            msg = f"not an {CRDT_KIND} state: {data!r}"
            raise OrSetStateError(msg)
        return OrSetMemory._state_from_fields(data)

    @staticmethod
    def _decode_all(state: bytes) -> dict[str, _KeyState]:
        obj = OrSetMemory._loads_object(state)
        if not isinstance(obj, dict):
            msg = f"not an {CRDT_KIND} snapshot: {obj!r}"
            raise OrSetStateError(msg)
        data = cast("dict[str, Any]", obj)
        if data.get("crdt") != CRDT_KIND:
            msg = f"not an {CRDT_KIND} snapshot: {data!r}"
            raise OrSetStateError(msg)
        raw = data.get("keys", {})
        if not isinstance(raw, dict):
            msg = "snapshot 'keys' must be an object"
            raise OrSetStateError(msg)
        raw_keys = cast("dict[str, Any]", raw)
        result: dict[str, _KeyState] = {}
        for key, fields in raw_keys.items():
            if not isinstance(fields, dict):
                msg = f"state for {key!r} must be an object"
                raise OrSetStateError(msg)
            result[str(key)] = OrSetMemory._state_from_fields(cast("dict[str, Any]", fields))
        return result

    @staticmethod
    def _state_from_fields(fields: dict[str, Any]) -> _KeyState:
        raw_adds = fields.get("adds", {})
        raw_removed = fields.get("removed", [])
        if not isinstance(raw_adds, dict):
            msg = f"'adds' must be an object: {raw_adds!r}"
            raise OrSetStateError(msg)
        adds: dict[str, set[Tag]] = {}
        for element_key, tag_list in cast("dict[str, Any]", raw_adds).items():
            adds[str(element_key)] = _decode_tags(tag_list)
        removed = _decode_tags(raw_removed)
        return _KeyState(adds=adds, removed=removed)


def _encode_tags(tags: set[Tag]) -> list[list[Any]]:
    """Serialize a tag set to a sorted list of ``[node, counter]`` pairs.

    Sorting makes the encoding canonical, so two converged replicas emit
    byte-identical JSON.

    Example::

        assert _encode_tags({("b", 2), ("a", 1)}) == [["a", 1], ["b", 2]]
    """
    return [[node, counter] for node, counter in sorted(tags)]


def _decode_tags(raw: Any) -> set[Tag]:
    """Parse a ``[[node, counter], ...]`` list back into a tag set.

    Raises :class:`OrSetStateError` on any malformed pair so a garbled or
    Byzantine payload is rejected wholesale rather than partially applied.

    Example::

        assert _decode_tags([["a", 1]]) == {("a", 1)}
    """
    if not isinstance(raw, list):
        msg = f"tag list must be an array: {raw!r}"
        raise OrSetStateError(msg)
    tags: set[Tag] = set()
    for item in cast("list[Any]", raw):
        if not isinstance(item, list):
            msg = f"tag must be a [node, counter] pair: {item!r}"
            raise OrSetStateError(msg)
        pair = cast("list[Any]", item)
        if len(pair) != 2:
            msg = f"tag must have exactly two fields: {pair!r}"
            raise OrSetStateError(msg)
        try:
            node = str(pair[0])
            counter = int(pair[1])
        except (ValueError, TypeError) as exc:
            msg = f"malformed tag: {pair!r}"
            raise OrSetStateError(msg) from exc
        if isinstance(pair[1], bool):
            msg = f"tag counter must be an integer, not a bool: {pair!r}"
            raise OrSetStateError(msg)
        tags.add((node, counter))
    return tags
