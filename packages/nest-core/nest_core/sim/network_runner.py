# SPDX-License-Identifier: Apache-2.0
"""HTTP bridge for cross-worker message delivery in distributed simulations."""

from __future__ import annotations
import asyncio
import base64
import json
import os
import urllib.error
import urllib.request
from typing import TYPE_CHECKING
from nest_core.log import get_logger
from nest_core.sim.events import Event
from nest_core.sim.http_config import (
    http_auth_headers,
    http_auth_valid,
    http_max_body_bytes,
    http_retries,
    http_retry_rng,
    http_timeout,
)
from nest_core.sim.http_retry import http_retry_sleep
from nest_core.sim.transport import InMemoryTransport
from nest_core.types import AgentId, CorrelationId, TransportCapabilities

if TYPE_CHECKING:
    from nest_core.sim.clock import VirtualClock
    from nest_core.sim.events import EventQueue


log = get_logger(__name__)


class RoutedTransport(InMemoryTransport):
    """In-memory transport that forwards remote agents over HTTP."""

    def __init__(
        self,
        agent_id: AgentId,
        event_queue: EventQueue,
        clock: VirtualClock,
        all_agents: list[AgentId] | None = None,
        *,
        local_agents: set[AgentId],
        routes: dict[AgentId, str],
    ) -> None:
        super().__init__(agent_id, event_queue, clock, all_agents)
        self._local_agents = local_agents
        self._routes = routes

    async def send(
        self,
        to: AgentId,
        payload: bytes,
        correlation_id: CorrelationId | None = None,
        *,
        deliver_at: float | None = None,
    ) -> None:
        if to in self._local_agents:
            await super().send(
                to,
                payload,
                correlation_id=correlation_id,
                deliver_at=deliver_at,
            )
            return
        base = self._routes.get(to)
        if base is None:
            msg = f"No route for remote agent {to!s}"
            raise KeyError(msg)
        body = json.dumps(
            {
                "from": str(self._agent_id),
                "to": str(to),
                "payload": base64.b64encode(payload).decode("ascii"),
                "corr": str(correlation_id) if correlation_id is not None else None,
            }
        ).encode("utf-8")
        url = f"{base.rstrip('/')}/agents/{to}/deliver"
        req = urllib.request.Request(  # noqa: S310
            url,
            data=body,
            headers={"Content-Type": "application/json", **http_auth_headers()},
            method="POST",
        )
        timeout = http_timeout()
        retries = http_retries()
        retry_rng = http_retry_rng()

        def _post() -> None:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                resp.read()

        last_err: urllib.error.URLError | None = None
        for attempt in range(retries):
            try:
                await asyncio.to_thread(_post)
                return
            except urllib.error.URLError as exc:
                last_err = exc
                if os.environ.get("NEST_LOG", "").strip():
                    log.warning(
                        "http_delivery_retry",
                        url=url,
                        attempt=attempt + 1,
                        error=str(exc),
                    )
                await http_retry_sleep(attempt, retry_rng)
        if last_err is not None:
            if os.environ.get("NEST_LOG", "").strip():
                log.warning("http_delivery_failed", url=url, error=str(last_err))
            raise last_err


class WorkerHttpBridge:
    """Minimal HTTP server that enqueues inbound deliveries for one worker."""

    def __init__(
        self,
        event_queue: EventQueue,
        clock: VirtualClock,
    ) -> None:
        self._queue = event_queue
        self._clock = clock
        self._server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self.host: str = "127.0.0.1"

    async def start(self, port: int = 0, host: str = "127.0.0.1") -> int:
        """Start listening; returns the bound port."""
        self.host = host
        self._server = await asyncio.start_server(self._handle_client, host, port)
        sockets = self._server.sockets
        if not sockets:
            msg = "HTTP bridge failed to bind"
            raise RuntimeError(msg)
        self.port = int(sockets[0].getsockname()[1])
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            parts = request_line.decode("utf-8", errors="replace").strip().split(" ")
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]
            content_length = 0
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                header = line.decode("utf-8", errors="replace").strip()
                if ":" in header:
                    key, value = header.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
                header_lower = header.lower()
                if header_lower.startswith("content-length:"):
                    content_length = int(header_lower.split(":", 1)[1].strip())
            if not http_auth_valid(headers):
                writer.write(
                    (
                        "HTTP/1.1 401 Unauthorized\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: 27\r\n"
                        "\r\n"
                        '{"ok":false,"error":"unauthorized"}'
                    ).encode("ascii")
                )
                await writer.drain()
                return
            body = b""
            status = 404
            response_body = b'{"ok":false}'
            max_body = http_max_body_bytes()
            if content_length > max_body:
                status = 413
                response_body = b'{"ok":false,"error":"payload too large"}'
            else:
                if content_length > 0:
                    body = await reader.readexactly(content_length)
                if method == "GET" and path == "/health":
                    status = 200
                    response_body = b'{"ok":true}'
                elif method == "POST" and path.startswith("/agents/") and path.endswith("/deliver"):
                    agent_part = path[len("/agents/") : -len("/deliver")].strip("/")
                    target = AgentId(agent_part)
                    payload_obj = json.loads(body.decode("utf-8"))
                    sender = AgentId(str(payload_obj["from"]))
                    raw = base64.b64decode(str(payload_obj["payload"]))
                    corr_raw = payload_obj.get("corr")
                    corr = CorrelationId(str(corr_raw)) if corr_raw else None
                    self._queue.push(
                        Event(
                            time=self._clock.now,
                            kind="deliver",
                            agent_id=target,
                            target_id=sender,
                            payload=raw,
                            correlation_id=corr,
                        )
                    )
                    status = 200
                    response_body = b'{"ok":true}'
            writer.write(
                (
                    f"HTTP/1.1 {status} OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    "\r\n"
                ).encode("ascii")
                + response_body
            )
            await writer.drain()
        except (json.JSONDecodeError, ValueError, asyncio.IncompleteReadError, KeyError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()


async def check_health(base_url: str) -> bool:
    """Return True if ``GET {base_url}/health`` succeeds."""
    url = f"{base_url.rstrip('/')}/health"
    req = urllib.request.Request(  # noqa: S310
        url,
        method="GET",
        headers=http_auth_headers(),
    )

    def _get() -> bool:
        with urllib.request.urlopen(req, timeout=http_timeout()) as resp:  # noqa: S310
            return resp.status == 200

    try:
        return await asyncio.to_thread(_get)
    except urllib.error.URLError:
        return False


class HttpNetwork:
    """Registry of agent routes for the reference HttpTransport plugin."""

    def __init__(self) -> None:
        self._routes: dict[AgentId, str] = {}
        self._agents: list[AgentId] = []

    def register(self, agent_id: AgentId, base_url: str) -> None:
        self._routes[agent_id] = base_url.rstrip("/")
        if agent_id not in self._agents:
            self._agents.append(agent_id)

    def get_agents(self) -> list[AgentId]:
        return list(self._agents)

    def route_for(self, agent_id: AgentId) -> str | None:
        return self._routes.get(agent_id)


class HttpTransport:
    """Reference HTTP transport plugin (standalone / Tier 2 use)."""

    capabilities = TransportCapabilities(
        supports_streaming=False,
        ordered=True,
        reliable=True,
    )

    def __init__(self, agent_id: AgentId, network: HttpNetwork) -> None:
        self._agent_id = agent_id
        self._network = network
        self._inbound: asyncio.Queue[tuple[AgentId, bytes]] = asyncio.Queue()

    def bind_inbound(self, queue: asyncio.Queue[tuple[AgentId, bytes]]) -> None:
        self._inbound = queue

    async def send(self, to: AgentId, payload: bytes) -> None:
        base = self._network.route_for(to)
        if base is None:
            msg = f"No HTTP route registered for {to!s}"
            raise KeyError(msg)
        body = json.dumps(
            {
                "from": str(self._agent_id),
                "to": str(to),
                "payload": base64.b64encode(payload).decode("ascii"),
            }
        ).encode("utf-8")
        url = f"{base}/agents/{to}/deliver"
        req = urllib.request.Request(  # noqa: S310
            url,
            data=body,
            headers={"Content-Type": "application/json", **http_auth_headers()},
            method="POST",
        )

        def _post() -> None:
            with urllib.request.urlopen(req, timeout=http_timeout()) as resp:  # noqa: S310
                resp.read()

        await asyncio.to_thread(_post)

    async def receive(self) -> tuple[AgentId, bytes]:
        return await self._inbound.get()

    async def broadcast(self, payload: bytes) -> None:
        targets = [aid for aid in self._network.get_agents() if aid != self._agent_id]
        if targets:
            await asyncio.gather(*(self.send(aid, payload) for aid in targets))
