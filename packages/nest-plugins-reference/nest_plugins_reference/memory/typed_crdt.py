# SPDX-License-Identifier: Apache-2.0
"""Typed CRDT memory plugin.

This starts as a Blackboard-compatible memory plugin. Later commits will
replace last-writer-wins writes with type-aware CRDT merge behavior.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from collections.abc import AsyncIterator
from typing import Any


class TypedCrdtMemory:
    """Shared key-value memory plugin.

    For now, this intentionally behaves like Blackboard:
    writes replace the old value.

    Later, write() will merge values instead of overwriting them.
    """

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    async def read(self, key: str) -> bytes | None:
        """Read a value by key."""
        return self._store.get(key)

    async def write(self, key: str, value: bytes) -> None:
        """Merge a value into a key, notifying subscribers."""
        current = self._store.get(key)

        if current is None:
            merged = self._encode(self._normalize_state(self._decode(value)))
        else:
            old_state = self._decode(current)
            new_state = self._decode(value)
            merged = self._encode(self._merge_state(old_state, new_state))

        self._store[key] = merged

        for q in self._subscribers.get(key, []):
            await q.put(merged)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Subscribe to changes for a key."""
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Compare-and-swap: update only if current value matches expected."""
        current = self._store.get(key)
        if current == expected:
            self._store[key] = new
            for q in self._subscribers.get(key, []):
                await q.put(new)
            return True
        return False
    
    def _decode(self, value: bytes) -> dict[str, Any]:
        """Decode JSON bytes into a Python dictionary."""
        try:
            decoded = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("TypedCrdtMemory values must be JSON-encoded bytes") from exc

        if not isinstance(decoded, dict):
            raise ValueError("TypedCrdtMemory value must decode to a JSON object")

        return decoded
    
    def _encode(self, state: dict[str, Any]) -> bytes:
        """Encode a Python dictionary into deterministic JSON bytes."""
        return json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    
    def _normalize_state(self, state: dict[str, Any]) -> dict[str, Any]:
        """Convert a user write into the canonical stored CRDT shape."""
        memory_type = state.get("type")

        if memory_type == "set":
            return self._normalize_set(state)
        
        if memory_type == "counter":
            return self._normalize_counter(state)

        raise ValueError(f"Unsupported typed CRDT memory type: {memory_type!r}")
    
    def _merge_state(self, old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
        """Merge two decoded CRDT states."""
        old_type = old.get("type")
        new_type = new.get("type")

        if old_type != new_type:
            raise ValueError(f"Cannot merge different memory types: {old_type!r} and {new_type!r}")

        if old_type == "set":
            return self._merge_set(old, new)
        
        if old_type == "counter":
            return self._merge_counter(old, new)

        raise ValueError(f"Unsupported typed CRDT memory type: {old_type!r}")
    
    def _normalize_set(self, state: dict[str, Any]) -> dict[str, Any]:
        """Normalize set memory into a deterministic add-only set.

        Accepted simple write shape:
            {"type": "set", "writer": "agent_1", "value": "fact A"}

        Canonical stored shape:
            {
                "type": "set",
                "items": {
                    "agent_1:fact A": {"writer": "agent_1", "value": "fact A"}
                },
                "values": ["fact A"]
            }
        """
        items = state.get("items", {})

        if not items and "writer" in state and "value" in state:
            writer = str(state["writer"])
            value = state["value"]
            tag = str(state.get("tag", f"{writer}:{value}"))
            items = {
                tag: {
                    "writer": writer,
                    "value": value,
                }
            }

        if not isinstance(items, dict):
            raise ValueError("set memory requires an 'items' object")

        sorted_items = {
            str(tag): items[tag]
            for tag in sorted(items, key=str)
        }

        values = [
            sorted_items[tag].get("value")
            for tag in sorted_items
        ]

        return {
            "type": "set",
            "items": sorted_items,
            "values": values,
        }

    def _merge_set(self, old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
        """Merge set memory by unioning tagged items."""
        old_norm = self._normalize_set(old)
        new_norm = self._normalize_set(new)

        merged_items = dict(old_norm["items"])
        merged_items.update(new_norm["items"])

        return self._normalize_set({
            "type": "set",
            "items": merged_items,
        })
    
    def _normalize_counter(self, state: dict[str, Any]) -> dict[str, Any]:
        """Normalize counter memory into per-writer counts.

        Accepted simple write shape:
            {"type": "counter", "writer": "agent_1", "count": 1}

        Canonical stored shape:
            {
                "type": "counter",
                "counts": {"agent_1": 1},
                "total": 1
            }
        """
        counts = state.get("counts", {})

        if not counts and "writer" in state:
            writer = str(state["writer"])
            count = int(state.get("count", state.get("value", 1)))
            counts = {writer: count}

        if not isinstance(counts, dict):
            raise ValueError("counter memory requires a 'counts' object")

        clean_counts = {
            str(writer): int(count)
            for writer, count in counts.items()
        }

        sorted_counts = {
            writer: clean_counts[writer]
            for writer in sorted(clean_counts, key=str)
        }

        return {
            "type": "counter",
            "counts": sorted_counts,
            "total": sum(sorted_counts.values()),
        }
    
    def _merge_counter(self, old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
        """Merge counter memory by taking the max count per writer."""
        old_norm = self._normalize_counter(old)
        new_norm = self._normalize_counter(new)

        merged_counts = dict(old_norm["counts"])

        for writer, count in new_norm["counts"].items():
            merged_counts[writer] = max(merged_counts.get(writer, 0), count)

        return self._normalize_counter({
            "type": "counter",
            "counts": merged_counts,
        })