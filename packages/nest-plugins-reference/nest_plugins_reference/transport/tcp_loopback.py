# SPDX-License-Identifier: Apache-2.0
"""Loopback TCP transport plugin — RFC-001 alpha.

Agents register over 127.0.0.1 TCP with length-prefixed frames; message
routing uses in-process queues with optional seeded per-hop delay and
partition groups (deterministic when delay is zero).

Example::

    hub = TcpLoopbackHub(seed=42)
    await hub.start()
    t1 = StandaloneTcpLoopbackTransport(AgentId("a1"), hub)
    t2 = StandaloneTcpLoopbackTransport(AgentId("a2"), hub)
    await t1.send(AgentId("a2"), b"hello")
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import struct
from typing import TYPE_CHECKING

from nest_core.types import AgentId, TransportCapabilities

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter

_LEN = struct.Struct("!I")
_MAX_FRAME = 16 * 1024 * 1024


class TcpLoopbackHub:
    """Broker: TCP registration plus in-process routed delivery."""

    def __init__(
        self,
        *,
        seed: int = 0,
        min_delay_ms: float = 0.0,
        max_delay_ms: float = 0.0,
    ) -> None:
        self._rng = random.Random(seed)
        self._min_delay_ms = min_delay_ms
        self._max_delay_ms = max_delay_ms
        self._queues: dict[str, asyncio.Queue[tuple[AgentId, bytes]]] = {}
        self._agents: list[AgentId] = []
        self._partition_groups: list[set[str]] | None = None
        self._server: asyncio.Server | None = None
        self._port: int = 0
        self._ready: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    @property
    def port(self) -> int:
        return self._port

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        sock = self._server.sockets[0]
        self._port = int(sock.getsockname()[1])

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._ready.clear()

    def set_partition_groups(self, groups: list[list[str]] | None) -> None:
        if not groups:
            self._partition_groups = None
            return
        self._partition_groups = [set(g) for g in groups]

    def _same_partition(self, sender: AgentId, to: AgentId) -> bool:
        if self._partition_groups is None:
            return True
        sa, sb = str(sender), str(to)
        for group in self._partition_groups:
            in_a = sa in group
            in_b = sb in group
            if in_a and in_b:
                return True
            if in_a or in_b:
                return False
        return True

    def _delay_seconds(self) -> float:
        if self._max_delay_ms <= 0 and self._min_delay_ms <= 0:
            return 0.0
        lo = min(self._min_delay_ms, self._max_delay_ms)
        hi = max(self._min_delay_ms, self._max_delay_ms)
        return self._rng.uniform(lo, hi) / 1000.0

    async def _handle_client(self, reader: StreamReader, writer: StreamWriter) -> None:
        try:
            agent_raw = await _read_frame(reader)
            agent_id = AgentId(agent_raw.decode("utf-8"))
            async with self._lock:
                if str(agent_id) not in self._queues:
                    self._queues[str(agent_id)] = asyncio.Queue()
                    self._agents.append(agent_id)
                ready = self._ready.setdefault(str(agent_id), asyncio.Event())
                ready.set()
            writer.write(_pack_frame(b"ok"))
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, UnicodeDecodeError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                await writer.wait_closed()

    async def deliver(self, sender: AgentId, to: AgentId, payload: bytes) -> None:
        """Route a message from *sender* to *to* (in-process, seeded delay optional)."""
        if not self._same_partition(sender, to):
            return
        delay = self._delay_seconds()
        if delay > 0:
            await asyncio.sleep(delay)
        key = str(to)
        if key not in self._queues:
            self._queues[key] = asyncio.Queue()
            self._agents.append(to)
        await self._queues[key].put((sender, payload))

    def register_queue(self, agent_id: AgentId) -> asyncio.Queue[tuple[AgentId, bytes]]:
        key = str(agent_id)
        if key not in self._queues:
            self._queues[key] = asyncio.Queue()
            self._agents.append(agent_id)
        return self._queues[key]

    def get_agents(self) -> list[AgentId]:
        return list(self._agents)

    def ready_event(self, agent_id: AgentId) -> asyncio.Event:
        return self._ready.setdefault(str(agent_id), asyncio.Event())


class StandaloneTcpLoopbackTransport:
    """TCP loopback transport for Tier 2 / standalone use (RFC-001 alpha)."""

    capabilities = TransportCapabilities(
        supports_streaming=False,
        ordered=True,
        reliable=True,
    )

    def __init__(self, agent_id: AgentId, hub: TcpLoopbackHub) -> None:
        self._agent_id = agent_id
        self._hub = hub
        self._queue: asyncio.Queue[tuple[AgentId, bytes]] | None = None
        self._connected = False
        self._connect_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Register this agent with the loopback hub (TCP handshake)."""
        await self._ensure_connected()

    async def _ensure_connected(self) -> None:
        if self._connected:
            return
        async with self._connect_lock:
            if self._connected:
                return
            await self._hub.start()
            ready = self._hub.ready_event(self._agent_id)
            reader, writer = await asyncio.open_connection("127.0.0.1", self._hub.port)
            writer.write(_pack_frame(str(self._agent_id).encode("utf-8")))
            await writer.drain()
            ack = await _read_frame(reader)
            if ack != b"ok":
                msg = f"unexpected tcp registration ack: {ack!r}"
                raise RuntimeError(msg)
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(ready.wait(), timeout=5.0)
            self._queue = self._hub.register_queue(self._agent_id)
            self._connected = True

    async def send(self, to: AgentId, payload: bytes) -> None:
        await self._ensure_connected()
        await self._hub.deliver(self._agent_id, to, payload)

    async def receive(self) -> tuple[AgentId, bytes]:
        await self._ensure_connected()
        assert self._queue is not None
        return await self._queue.get()

    async def broadcast(self, payload: bytes) -> None:
        await self._ensure_connected()
        for aid in self._hub.get_agents():
            if aid != self._agent_id:
                await self.send(aid, payload)


def _pack_frame(data: bytes) -> bytes:
    if len(data) > _MAX_FRAME:
        msg = f"frame too large: {len(data)}"
        raise ValueError(msg)
    return _LEN.pack(len(data)) + data


async def _read_frame(reader: StreamReader) -> bytes:
    raw_len = await reader.readexactly(_LEN.size)
    (size,) = _LEN.unpack(raw_len)
    if size > _MAX_FRAME:
        msg = f"frame too large: {size}"
        raise ValueError(msg)
    return await reader.readexactly(size)
