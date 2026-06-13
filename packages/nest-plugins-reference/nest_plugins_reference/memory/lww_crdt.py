# SPDX-License-Identifier: Apache-2.0
"""LWW-Register CRDT memory plugin — conflict-free shared state under concurrent writers.

The default :class:`~nest_plugins_reference.memory.blackboard.Blackboard` resolves
concurrent writes by wall-arrival order with no causal history, so replicas that
observe the same writes in different orders silently diverge. This plugin replaces
that model with a state-based **Last-Writer-Wins Register** (a CvRDT) tagged with
Lamport logical clocks.

Each replica owns a node id used to break timestamp ties deterministically, so a
merge is commutative, associative, and idempotent: every replica that has observed
the same set of writes converges to byte-identical state regardless of delivery
order or dropped messages.

Example::

    a = LWWRegister(node_id="a")
    b = LWWRegister(node_id="b")
    await a.write("x", b"from-a")
    await b.write("x", b"from-b")
    a.merge(b)
    b.merge(a)
    assert a.export_state() == b.export_state()  # converged
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator

# An entry is the value plus the (logical clock, node id) tag that ordered it.
_Entry = tuple[bytes, int, str]


class LWWRegister:
    """Last-Writer-Wins register CRDT over a key-value store.

    Conflicts are resolved by ``(lamport_ts, node_id)`` order: the highest tag
    wins, with the node id breaking ties so the outcome never depends on message
    arrival order.

    Example::

        reg = LWWRegister(node_id="seller-1")
        await reg.write("catalog/item-7", b"claimed")
        val = await reg.read("catalog/item-7")
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a replica identified by *node_id* (used for deterministic tie-breaks).

        Example::

            reg = LWWRegister(node_id="agent-3")
        """
        self._node_id = node_id
        self._clock = 0
        self._store: dict[str, _Entry] = {}
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    # -- Memory protocol -----------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read the currently winning value for *key*, or ``None`` if absent.

        Example::

            val = await reg.read("counter")
        """
        entry = self._store.get(key)
        return entry[0] if entry is not None else None

    async def write(self, key: str, value: bytes) -> None:
        """Write *value* for *key*, tagging it with a fresh logical timestamp.

        The new write always supersedes anything this replica has already seen,
        because the timestamp is drawn one tick above the current clock.

        Example::

            await reg.write("counter", b"42")
        """
        ts = self._tick()
        await self._apply(key, value, ts, self._node_id)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Yield each new winning value for *key* as it changes.

        Example::

            async for val in reg.subscribe("counter"):
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
        """Compare-and-swap via CRDT merge: write *new* only if the winner equals *expected*.

        Unlike the blackboard's optimistic CAS, the swap is realised as an ordinary
        timestamped write, so a successful CAS still merges cleanly with concurrent
        updates from other replicas.

        Example::

            ok = await reg.cas("counter", b"42", b"43")
        """
        current = await self.read(key)
        if current == expected:
            await self.write(key, new)
            return True
        return False

    # -- CvRDT replication ---------------------------------------------------

    def merge(self, other: LWWRegister) -> None:
        """Merge another replica's state into this one (commutative and idempotent).

        Example::

            a.merge(b)
        """
        for key, (value, ts, node) in other._store.items():
            self._merge_entry(key, value, ts, node)

    def export_state(self) -> bytes:
        """Serialise the full CRDT state as canonical (sorted) JSON bytes.

        Two replicas that have observed the same writes produce byte-identical
        output, which makes this value safe to compare for convergence and to
        gossip over the wire as the ``bytes`` payload the memory layer expects.

        Example::

            blob = reg.export_state()
        """
        obj = {
            key: [base64.b64encode(value).decode("ascii"), ts, node]
            for key, (value, ts, node) in self._store.items()
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")

    def merge_state(self, raw: bytes) -> None:
        """Merge a state blob produced by :meth:`export_state` into this replica.

        Example::

            reg.merge_state(peer_blob)
        """
        obj = json.loads(raw.decode("ascii"))
        for key, (value_b64, ts, node) in obj.items():
            value = base64.b64decode(value_b64)
            self._merge_entry(key, value, int(ts), str(node))

    # -- internals -----------------------------------------------------------

    def _tick(self) -> int:
        """Advance the Lamport clock for a local event and return the new value."""
        self._clock += 1
        return self._clock

    def _merge_entry(self, key: str, value: bytes, ts: int, node: str) -> bool:
        """Apply one tagged entry, keeping the ``(ts, node)``-maximal winner.

        Returns ``True`` when the incoming entry won and replaced the current one.
        """
        self._clock = max(self._clock, ts)
        current = self._store.get(key)
        if current is None or (ts, node) > (current[1], current[2]):
            self._store[key] = (value, ts, node)
            return True
        return False

    async def _apply(self, key: str, value: bytes, ts: int, node: str) -> None:
        """Merge an entry and notify subscribers if it became the new winner."""
        if self._merge_entry(key, value, ts, node):
            for q in self._subscribers.get(key, []):
                await q.put(value)
