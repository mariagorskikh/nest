# SPDX-License-Identifier: Apache-2.0
"""OR-Set CRDT memory plugin -- conflict-free set with add/remove.

Implements a state-based OR-Set CvRDT (Shapiro et al., SSS 2011). Each
replica maintains a set of (tag, payload) pairs and a set of tombstones.
A value is present if at least one of its tags is not tombstoned.

Merge is just: union elements, union tombstones.

Example::

    a = OrSetMemory("a")
    b = OrSetMemory("b")

    await a.write("x", b"hello")
    await b.write("x", b"hello")

    await b.merge("x", a.export("x"))
    await a.merge("x", b.export("x"))

    assert await a.read("x") == b"hello"
    assert await b.read("x") == b"hello"
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from typing import Any

# Keep the public surface small: just what Memory + the replication channel needs.
# We avoid leaking internal types into nest_core.

_CRDT_KIND: str = "or_set"


class OrSetMemory:
    """OR-Set CRDT implementing the ``Memory`` protocol plus export/merge.

    Each replica is independent. Writes create a unique (tag, payload) entry;
    removes tombstone tags. Merge unions elements and tombstones,
    guaranteeing convergence regardless of message order.

    Example::

        mem = OrSetMemory("agent-0")
        await mem.write("catalog", b"apple")
        await mem.remove("catalog", b"apple")
    """

    def __init__(self, node_id: str = "node") -> None:
        """Initialize the OR-Set replica.

        Example::

            mem = OrSetMemory("agent-0")
        """
        self._node_id: str = str(node_id)
        self._tick: int = 0
        # key -> {"elements": {tag: b64(payload), ...}, "tombstones": [tag, ...]}
        self._store: dict[str, dict[str, Any]] = {}
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    @property
    def tick(self) -> int:
        """The current tick value of this replica's clock.

        Example::

            mem = OrSetMemory("a")
            assert mem.tick == 0
        """
        return self._tick

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _b64(value: bytes) -> str:
        """Deterministic base64 encoding.

        Example::

            assert OrSetMemory._b64(b"hi") == "aGk="
        """
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _b64dec(s: str) -> bytes:
        """Decode base64 back to bytes.

        Example::

            assert OrSetMemory._b64dec("aGk=") == b"hi"
        """
        return base64.b64decode(s)

    def _next_tag(self) -> str:
        """Deterministic, globally-unique tag for an operation.

        Uses node_id + local tick to avoid collisions without UUIDs or RNG.

        Example::

            mem = OrSetMemory("node")
            mem._tick = 0
            assert mem._next_tag() == "node:0"
        """
        tag = f"{self._node_id}:{self._tick}"
        self._tick += 1
        return tag

    @staticmethod
    def _parse_tag(tag: str) -> tuple[int, str]:
        """Parse a tag of form node_id:tick into (tick, node_id) for sorting.

        Example::

            assert OrSetMemory._parse_tag("writer-1:100") == (100, "writer-1")
        """
        try:
            node_id, tick_str = tag.rsplit(":", 1)
            return int(tick_str), node_id
        except (ValueError, IndexError):
            return 0, tag

    def _get_or_create(self, key: str) -> dict[str, Any]:
        """Get or initialize the CRDT state for a key.

        Example::

            state = mem._get_or_create("k")
            assert "elements" in state and "tombstones" in state
        """
        state = self._store.get(key)
        if (
            state is None
            or state.get("crdt") != _CRDT_KIND
            or not isinstance(state.get("elements"), dict)
            or not isinstance(state.get("tombstones"), list)
        ):
            new_state: dict[str, Any] = {"crdt": _CRDT_KIND, "elements": {}, "tombstones": []}
            self._store[key] = new_state
            return new_state
        return state

    @staticmethod
    def _canonical_json_bytes(state: dict[str, Any]) -> bytes:
        """Canonical JSON encoding of CRDT state for deterministic comparisons.

        Tombstones are sorted to guarantee byte-identical output regardless
        of merge delivery order. This is critical: json.dumps(sort_keys=True)
        only sorts dict keys, not list elements.

        Example::

            state = {"crdt": "or_set", "elements": {}, "tombstones": ["b:1", "a:0"]}
            b = OrSetMemory._canonical_json_bytes(state)
            assert b == b'{"crdt": "or_set", "elements": {}, "tombstones": ["a:0", "b:1"]}'
        """
        canonical = {
            "crdt": state["crdt"],
            "elements": dict(sorted(state["elements"].items())),
            "tombstones": sorted(state["tombstones"]),
        }
        return json.dumps(canonical, sort_keys=True).encode("utf-8")

    # ------------------------------------------------------------------
    # Memory protocol
    # ------------------------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read the most recently added present value from the OR-Set, or None.

        Returns the payload of the element with the lexicographically largest
        tag (i.e. the latest write) that is not tombstoned. Sorting in reverse
        ensures standard agents interacting via the Memory protocol see the
        latest value, not the first-ever write.

        Use export() to inspect the full multi-value CRDT state.

        Example::

            val = await mem.read("k")
        """
        state = self._store.get(key)
        if state is None or "elements" not in state:
            return None
        elements: dict[str, str] = state["elements"]
        tombstones: set[str] = set(state.get("tombstones", []))
        # Sort primarily by tick (descending), then by node_id (descending)
        # to avoid priority inversion.
        sorted_elements = sorted(
            elements.items(),
            key=lambda item: self._parse_tag(item[0]),
            reverse=True,
        )
        for tag, b64payload in sorted_elements:
            if tag not in tombstones:
                return self._b64dec(b64payload)
        return None

    async def write(self, key: str, value: bytes) -> None:
        """Add a value to the OR-Set (or re-add if previously removed).

        Generates a new unique tag and stores (tag -> base64(value)).
        Notifies subscribers with the raw payload bytes, matching the
        Memory protocol contract (not the internal CRDT envelope).

        Example::

            await mem.write("k", b"hello")
        """
        state = self._get_or_create(key)
        tag = self._next_tag()
        state["elements"][tag] = self._b64(value)
        # Notify with raw payload, not the CRDT envelope, to stay compliant
        # with the Memory protocol (matches lww_register._notify(key, reg.payload)).
        await self._notify(key, value)

    async def remove(self, key: str, value: bytes) -> bool:
        """Remove a value from the OR-Set (best-effort; ignores unknown values).

        Observes current payload-tag bindings and tombstones all matching tags.
        Returns True if at least one tag was tombstoned. Notifies subscribers
        with the new raw read() value (or b"" if the set is now empty), matching
        the Memory protocol contract.

        Example::

            await mem.remove("k", b"x")
        """
        state = self._store.get(key)
        if state is None or "elements" not in state or "tombstones" not in state:
            return False
        elements: dict[str, str] = state["elements"]
        tombstones: list[str] = state["tombstones"]
        removed = False
        target_b64 = self._b64(value)
        for tag, b64payload in list(elements.items()):
            if b64payload == target_b64 and tag not in tombstones:
                tombstones.append(tag)
                removed = True
        if removed:
            # Notify with the new winning raw payload (not the CRDT envelope).
            new_val = await self.read(key)
            await self._notify(key, new_val if new_val is not None else b"")
        return removed

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Compare-and-swap on the winning raw payload.

        Succeeds iff the current raw read() payload equals ``expected``, in
        which case it performs a normal tagged write() of ``new``. This matches
        the Memory protocol contract (same pattern as LwwRegisterMemory.cas)
        where callers operate on raw user payloads, not internal CRDT state.

        Example::

            ok = await mem.cas("k", b"old", b"new")
        """
        current_payload = await self.read(key)
        if current_payload == expected:
            await self.write(key, new)
            return True
        return False

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Yield the canonical CRDT state each time it changes.

        Example::

            async for state in mem.subscribe("k"):
                print(state)
        """
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    async def _notify(self, key: str, payload: bytes) -> None:
        """Push a payload to all subscribers of a key.

        Example::

            await mem._notify("k", b'{"crdt":"or_set"}')
        """
        for q in self._subscribers.get(key, []):
            await q.put(payload)

    # ------------------------------------------------------------------
    # Replication channel (CvRDT interface used by validate_crdt_convergence)
    # ------------------------------------------------------------------

    def export(self, key: str) -> bytes | None:
        """Export the current CRDT state for a key as canonical JSON bytes.

        Returns ``None`` if the key has never been written.

        Example::

            b = mem.export("k")
        """
        state = self._store.get(key)
        if state is None:
            return None
        return self._canonical_json_bytes(state)

    async def merge(self, key: str, remote_state_bytes: bytes) -> bool:
        """Merge remote CRDT state into this replica (state-based CvRDT).

        Performs: elements = union; tombstones = union.
        Only notifies subscribers if the local state actually changed, preventing
        the infinite broadcast cascade that unconditional notification would cause
        in a gossip protocol. Mirrors the early-exit pattern in LwwRegisterMemory.

        Example::

            await a.merge("k", b.export("k"))
        """
        try:
            remote = json.loads(remote_state_bytes)
        except (ValueError, TypeError):
            return False

        if not isinstance(remote, dict):
            return False

        from typing import cast

        remote_dict = cast("dict[str, Any]", remote)
        elements = remote_dict.get("elements")
        tombstones = remote_dict.get("tombstones")

        # Defensive schema check: ignore unexpected schemas or structures.
        if (
            remote_dict.get("crdt") != _CRDT_KIND
            or not isinstance(elements, dict)
            or not isinstance(tombstones, list)
        ):
            return False

        state = self._get_or_create(key)
        changed = False

        # Union elements: only add tags not already known locally.
        local_elements: dict[str, str] = state["elements"]
        remote_elements = cast("dict[str, str]", elements)
        for tag, b64payload in remote_elements.items():
            if tag not in local_elements:
                local_elements[tag] = b64payload
                changed = True

        # Union tombstones: only add tombstones not already known locally.
        local_ts: list[str] = state["tombstones"]
        remote_ts = cast("list[str]", tombstones)
        local_ts_set: set[str] = set(local_ts)
        for t in remote_ts:
            if t not in local_ts_set:
                local_ts.append(t)
                local_ts_set.add(t)
                changed = True

        # Update local _tick based on any merged tags matching our _node_id to prevent collisions
        local_prefix = f"{self._node_id}:"
        max_seen_tick = -1
        for tag in remote_elements:
            if tag.startswith(local_prefix):
                try:
                    tick_str = tag.rsplit(":", 1)[1]
                    max_seen_tick = max(max_seen_tick, int(tick_str))
                except (ValueError, IndexError):
                    pass
        for tag in remote_ts:
            if tag.startswith(local_prefix):
                try:
                    tick_str = tag.rsplit(":", 1)[1]
                    max_seen_tick = max(max_seen_tick, int(tick_str))
                except (ValueError, IndexError):
                    pass
        if max_seen_tick >= self._tick:
            self._tick = max_seen_tick + 1

        if changed:
            # Notify with the new winning raw payload (not the CRDT envelope).
            new_val = await self.read(key)
            await self._notify(key, new_val if new_val is not None else b"")

        return True

    # ------------------------------------------------------------------
    # Bulk helpers used by scenarios/tests
    # ------------------------------------------------------------------

    def export_all(self) -> dict[str, bytes]:
        """Export all keys as a mapping key -> canonical JSON bytes.

        Example::

            all_state = mem.export_all()
        """
        return {k: self._canonical_json_bytes(v) for k, v in self._store.items()}

    async def merge_all(self, remote: dict[str, bytes]) -> list[str]:
        """Merge a remote export_all into this replica.

        Example::

            await a.merge_all(b.export_all())
        """
        changed: list[str] = []
        for k, state_bytes in remote.items():
            if await self.merge(k, state_bytes):
                changed.append(k)
        return changed
