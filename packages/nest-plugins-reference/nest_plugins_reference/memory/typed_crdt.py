# SPDX-License-Identifier: Apache-2.0
"""Typed CRDT memory plugin.

This plugin stores JSON-encoded bytes and merges updates according to the
declared memory type instead of using last-writer-wins replacement.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from collections.abc import AsyncIterator
from typing import cast

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | dict[str, JsonValue] | list[JsonValue]
type JsonObject = dict[str, JsonValue]


class TypedCrdtMemory:
    """Shared key-value memory plugin with type-aware CRDT merge behavior.

    Supported memory types:
    - set: union of tagged items
    - counter: max count per writer, with total derived from counts
    - vote: one ballot per writer, with majority result derived from ballots
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
        merged = self._merge_bytes(current, value)
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
        """Compare-and-swap: merge new value only if current matches expected."""
        current = self._store.get(key)
        if current != expected:
            return False

        merged = self._merge_bytes(current, new)
        self._store[key] = merged

        for q in self._subscribers.get(key, []):
            await q.put(merged)

        return True

    def _merge_bytes(self, old_bytes: bytes | None, new_bytes: bytes) -> bytes:
        """Merge an optional existing encoded state with a new encoded update."""
        new_state = self._decode(new_bytes)

        if old_bytes is None:
            return self._encode(self._normalize_state(new_state))

        old_state = self._decode(old_bytes)
        return self._encode(self._merge_state(old_state, new_state))

    def _decode(self, value: bytes) -> JsonObject:
        """Decode JSON bytes into a Python dictionary."""
        try:
            decoded = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("TypedCrdtMemory values must be JSON-encoded bytes") from exc

        if not isinstance(decoded, dict):
            raise ValueError("TypedCrdtMemory value must decode to a JSON object")

        return cast("JsonObject", decoded)

    def _encode(self, state: JsonObject) -> bytes:
        """Encode a Python dictionary into deterministic JSON bytes."""
        return json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _object_field(self, state: JsonObject, field: str, error_message: str) -> JsonObject:
        """Read a JSON object field, defaulting to an empty object."""
        raw_value = state.get(field, {})
        if not isinstance(raw_value, dict):
            raise ValueError(error_message)
        return cast("JsonObject", raw_value)

    def _to_int(self, value: JsonValue) -> int:
        """Convert a JSON scalar to int, rejecting objects and arrays."""
        if isinstance(value, str | int | float | bool):
            return int(value)
        raise ValueError(f"counter values must be numeric, got {value!r}")

    def _normalize_state(self, state: JsonObject) -> JsonObject:
        """Convert a user write into the canonical stored CRDT shape."""
        memory_type = state.get("type")

        if memory_type == "set":
            return self._normalize_set(state)

        if memory_type == "counter":
            return self._normalize_counter(state)

        if memory_type == "vote":
            return self._normalize_vote(state)

        raise ValueError(f"Unsupported typed CRDT memory type: {memory_type!r}")

    def _merge_state(self, old: JsonObject, new: JsonObject) -> JsonObject:
        """Merge two decoded CRDT states."""
        old_type = old.get("type")
        new_type = new.get("type")

        if old_type != new_type:
            raise ValueError(f"Cannot merge different memory types: {old_type!r} and {new_type!r}")

        if old_type == "set":
            return self._merge_set(old, new)

        if old_type == "counter":
            return self._merge_counter(old, new)

        if old_type == "vote":
            return self._merge_vote(old, new)

        raise ValueError(f"Unsupported typed CRDT memory type: {old_type!r}")

    def _normalize_set(self, state: JsonObject) -> JsonObject:
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
        raw_items = state.get("items", {})
        items: dict[str, JsonObject] = {}

        if not raw_items and "writer" in state and "value" in state:
            writer = str(state["writer"])
            value = state["value"]
            tag = str(state.get("tag", f"{writer}:{value}"))
            items[tag] = {"writer": writer, "value": value}
        else:
            if not isinstance(raw_items, dict):
                raise ValueError("set memory requires an 'items' object")

            for raw_tag, raw_item in cast("JsonObject", raw_items).items():
                if not isinstance(raw_item, dict):
                    raise ValueError("set memory items must be objects")

                item = cast("JsonObject", raw_item)
                writer = str(item.get("writer", ""))
                value = item.get("value")
                items[str(raw_tag)] = {"writer": writer, "value": value}

        sorted_items: dict[str, JsonObject] = {tag: items[tag] for tag in sorted(items, key=str)}
        values: list[JsonValue] = [sorted_items[tag]["value"] for tag in sorted_items]

        return {
            "type": "set",
            "items": cast("JsonValue", sorted_items),
            "values": cast("JsonValue", values),
        }

    def _merge_set(self, old: JsonObject, new: JsonObject) -> JsonObject:
        """Merge set memory by unioning tagged items."""
        old_norm = self._normalize_set(old)
        new_norm = self._normalize_set(new)

        old_items = self._object_field(old_norm, "items", "set memory requires an 'items' object")
        new_items = self._object_field(new_norm, "items", "set memory requires an 'items' object")

        merged_items: JsonObject = dict(old_items)
        merged_items.update(new_items)

        return self._normalize_set(
            {
                "type": "set",
                "items": cast("JsonValue", merged_items),
            }
        )

    def _normalize_counter(self, state: JsonObject) -> JsonObject:
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
        raw_counts = state.get("counts", {})
        counts: dict[str, int] = {}

        if not raw_counts and "writer" in state:
            writer = str(state["writer"])
            count_source = state.get("count", state.get("value", 1))
            counts[writer] = self._to_int(count_source)
        else:
            if not isinstance(raw_counts, dict):
                raise ValueError("counter memory requires a 'counts' object")

            for writer, count in cast("JsonObject", raw_counts).items():
                counts[str(writer)] = self._to_int(count)

        sorted_counts: dict[str, int] = {
            writer: counts[writer] for writer in sorted(counts, key=str)
        }

        return {
            "type": "counter",
            "counts": cast("JsonValue", sorted_counts),
            "total": sum(sorted_counts.values()),
        }

    def _merge_counter(self, old: JsonObject, new: JsonObject) -> JsonObject:
        """Merge counter memory by taking the max count per writer."""
        old_norm = self._normalize_counter(old)
        new_norm = self._normalize_counter(new)

        old_counts = self._object_field(
            old_norm, "counts", "counter memory requires a 'counts' object"
        )
        new_counts = self._object_field(
            new_norm, "counts", "counter memory requires a 'counts' object"
        )

        merged_counts: dict[str, int] = {
            writer: self._to_int(count) for writer, count in old_counts.items()
        }

        for writer, count in new_counts.items():
            new_count = self._to_int(count)
            merged_counts[writer] = max(merged_counts.get(writer, 0), new_count)

        return self._normalize_counter(
            {
                "type": "counter",
                "counts": cast("JsonValue", merged_counts),
            }
        )

    def _normalize_vote(self, state: JsonObject) -> JsonObject:
        """Normalize vote memory into per-writer ballots.

        Accepted simple write shape:
            {"type": "vote", "writer": "agent_1", "value": "approve"}

        Canonical stored shape:
            {
                "type": "vote",
                "ballots": {"agent_1": "approve"},
                "result": {
                    "winner": "approve",
                    "confidence": 1.0,
                    "counts": {"approve": 1}
                }
            }
        """
        raw_ballots = state.get("ballots", {})
        ballots: dict[str, str] = {}

        if not raw_ballots and "writer" in state and "value" in state:
            writer = str(state["writer"])
            ballots[writer] = str(state["value"])
        else:
            if not isinstance(raw_ballots, dict):
                raise ValueError("vote memory requires a 'ballots' object")

            for writer, value in cast("JsonObject", raw_ballots).items():
                ballots[str(writer)] = str(value)

        sorted_ballots: dict[str, str] = {
            writer: ballots[writer] for writer in sorted(ballots, key=str)
        }

        counts: Counter[str] = Counter(sorted_ballots.values())

        if counts:
            # Deterministic tie-break:
            # 1. highest vote count wins
            # 2. if tied, lexicographically smallest value wins
            winner, winner_count = sorted(
                counts.items(),
                key=lambda item: (-item[1], item[0]),
            )[0]
            confidence = winner_count / len(sorted_ballots)
        else:
            winner = None
            confidence = 0.0

        sorted_counts: dict[str, int] = {value: counts[value] for value in sorted(counts, key=str)}

        return {
            "type": "vote",
            "ballots": cast("JsonValue", sorted_ballots),
            "result": {
                "winner": winner,
                "confidence": confidence,
                "counts": cast("JsonValue", sorted_counts),
            },
        }

    def _merge_vote(self, old: JsonObject, new: JsonObject) -> JsonObject:
        """Merge vote memory by keeping one ballot per writer.

        The majority result is derived from the preserved ballots.
        """
        old_norm = self._normalize_vote(old)
        new_norm = self._normalize_vote(new)

        old_ballots = self._object_field(
            old_norm, "ballots", "vote memory requires a 'ballots' object"
        )
        new_ballots = self._object_field(
            new_norm, "ballots", "vote memory requires a 'ballots' object"
        )

        merged_ballots: JsonObject = dict(old_ballots)
        merged_ballots.update(new_ballots)

        return self._normalize_vote(
            {
                "type": "vote",
                "ballots": cast("JsonValue", merged_ballots),
            }
        )
