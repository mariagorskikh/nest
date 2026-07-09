# SPDX-License-Identifier: Apache-2.0
"""HTTP RPC for shared plugins across distributed workers."""

from __future__ import annotations
import asyncio
import json
import urllib.error
import urllib.request
from collections.abc import AsyncGenerator
from typing import Any, cast
from nest_core.layers.registry import Registry
from nest_core.sim.http_config import (
    http_auth_headers,
    http_auth_valid,
    http_max_body_bytes,
    http_retries,
    http_timeout,
)
from nest_core.sim.http_retry import http_retry_sleep
from nest_core.types import AgentCard, AgentId, Query


def _card_to_dict(card: AgentCard) -> dict[str, Any]:
    return {
        "agent_id": str(card.agent_id),
        "name": card.name,
        "capabilities": list(card.capabilities),
        "endpoint": card.endpoint,
        "metadata": dict(card.metadata),
    }


def _card_from_dict(data: dict[str, Any]) -> AgentCard:
    return AgentCard(
        agent_id=AgentId(str(data["agent_id"])),
        name=str(data["name"]),
        capabilities=[str(c) for c in data.get("capabilities", [])],
        endpoint=data.get("endpoint"),
        metadata=dict(data.get("metadata", {})),
    )


def _query_to_dict(query: Query) -> dict[str, Any]:
    return {
        "capabilities": list(query.capabilities),
        "name_pattern": query.name_pattern,
        "metadata_filter": dict(query.metadata_filter),
    }


def _query_from_dict(data: dict[str, Any]) -> Query:
    return Query(
        capabilities=[str(c) for c in data.get("capabilities", [])],
        name_pattern=data.get("name_pattern"),
        metadata_filter=dict(data.get("metadata_filter", {})),
    )


async def _http_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
) -> object:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", **http_auth_headers()}
    req = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        headers=headers,
        method=method,
    )

    def _call() -> object:
        with urllib.request.urlopen(req, timeout=http_timeout()) as resp:  # noqa: S310
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else {}

    last_err: urllib.error.URLError | None = None
    for attempt in range(http_retries()):
        try:
            return await asyncio.to_thread(_call)
        except urllib.error.URLError as exc:
            last_err = exc
            await http_retry_sleep(attempt)
    if last_err is not None:
        raise last_err
    return {}


class RemoteRegistry:
    """Registry client that forwards calls to a coordinator RPC server."""

    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")

    async def register(self, card: AgentCard) -> None:
        await _http_json("POST", f"{self._base}/registry/register", _card_to_dict(card))

    async def lookup(self, query: Query) -> list[AgentCard]:
        result = await _http_json(
            "POST",
            f"{self._base}/registry/lookup",
            _query_to_dict(query),
        )
        if not isinstance(result, list):
            return []
        return [
            _card_from_dict(cast("dict[str, Any]", item))
            for item in cast("list[Any]", result)
            if isinstance(item, dict)
        ]

    async def subscribe(self, query: Query) -> AsyncGenerator[AgentCard, None]:
        del query
        if False:
            yield AgentCard(agent_id=AgentId("never"), name="")

    async def deregister(self, agent: AgentId) -> None:
        await _http_json(
            "POST",
            f"{self._base}/registry/deregister",
            {"agent_id": str(agent)},
        )


class RegistryRpcServer:
    """HTTP server exposing a local Registry implementation to remote workers."""

    def __init__(self, registry: Registry) -> None:
        self._registry = registry
        self._server: asyncio.AbstractServer | None = None
        self.port: int = 0

    async def start(self, host: str, port: int) -> int:
        self._server = await asyncio.start_server(self._handle_client, host, port)
        sockets = self._server.sockets
        if not sockets:
            msg = "Registry RPC failed to bind"
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
            elif content_length > 0:
                body = await reader.readexactly(content_length)
            payload_obj: dict[str, Any] = {}
            if body:
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict):
                    payload_obj = cast("dict[str, Any]", parsed)
            if method == "GET" and path == "/health":
                status = 200
                response_body = b'{"ok":true}'
            elif method == "POST" and path == "/registry/register":
                await self._registry.register(_card_from_dict(payload_obj))
                status = 200
                response_body = b'{"ok":true}'
            elif method == "POST" and path == "/registry/lookup":
                cards = await self._registry.lookup(_query_from_dict(payload_obj))
                status = 200
                response_body = json.dumps([_card_to_dict(c) for c in cards]).encode("utf-8")
            elif method == "POST" and path == "/registry/deregister":
                await self._registry.deregister(AgentId(str(payload_obj["agent_id"])))
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
        except (json.JSONDecodeError, ValueError, KeyError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
