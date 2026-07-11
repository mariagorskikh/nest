from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator


class CollectiveMemory:
    """A concrete implementation of the Memory Protocol for distributed agent learning."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._listeners: dict[str, set[asyncio.Queue[bytes]]] = {}

    async def read(self, key: str) -> bytes | None:
        return self._store.get(key, None)

    async def write(self, key: str, value: bytes) -> None:
        self._store[key] = value
        if key in self._listeners:
            for queue in self._listeners[key]:
                await queue.put(value)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        if key not in self._listeners:
            self._listeners[key] = set()
        self._listeners[key].add(queue)

        try:
            if key in self._store:
                yield self._store[key]
            while True:
                yield await queue.get()
        finally:
            self._listeners[key].remove(queue)
            if not self._listeners[key]:
                del self._listeners[key]

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        current = self._store.get(key, b"")
        if current == expected:
            await self.write(key, new)
            return True
        return False
