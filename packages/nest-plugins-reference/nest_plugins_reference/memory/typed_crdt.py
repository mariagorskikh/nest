# SPDX-License-Identifier: Apache-2.0
"""Typed CRDT memory plugin.

This starts as a Blackboard-compatible memory plugin. Later commits will
replace last-writer-wins writes with type-aware CRDT merge behavior.
"""

from __future__ import annotations

import asyncio
import json
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
        """Write a value for a key, notifying subscribers."""
        self._store[key] = value
        for q in self._subscribers.get(key, []):
            await q.put(value)

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