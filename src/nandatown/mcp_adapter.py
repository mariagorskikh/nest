"""The MCP adapter: any MCP host can play a role in the town.

HTTP is canonical; MCP is an adapter, not a competing protocol. This
is a real Model Context Protocol server over stdio (JSON-RPC 2.0,
protocol version 2025-06-18) whose tools are exactly the participant
surface: find peers, wait for a hint, claim work under a lease, send
work, acknowledge, inspect. Point Claude, or anything else that speaks
MCP, at `nandatown mcp serve` and it literally becomes a participant.

The probe (`nandatown mcp test`) runs the client side of the same
handshake against any external MCP server and reports what it found.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from typing import Any

from . import __version__

PROTOCOL_VERSION = "2025-06-18"
MAX_PROBE_RESPONSE_BYTES = 1024 * 1024

TOOLS = [
    {"name": "town_status",
     "description": "The run this participant is joined to: task,"
                    " roles, and your name.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "town_participants",
     "description": "List participants with roles and capabilities.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "town_notify",
     "description": "Wait briefly for a wake-up hint. The hint is never"
                    " the only copy of the work; claim regardless.",
     "inputSchema": {"type": "object", "properties": {
         "wait": {"type": "number", "default": 0.5}}}},
    {"name": "town_claim",
     "description": "Claim one piece of inbox work under a lease with a"
                    " fence.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "town_send",
     "description": "Send work to a participant. Idempotent by"
                    " message_id.",
     "inputSchema": {"type": "object", "properties": {
         "message_id": {"type": "string"},
         "to": {"type": "string"},
         "kind": {"type": "string"},
         "body": {"type": "object"}},
         "required": ["message_id", "to", "kind", "body"]}},
    {"name": "town_ack",
     "description": "Acknowledge claimed work: received, processed,"
                    " rejected, retryable, or failed, with your note as"
                    " your attributed assertion.",
     "inputSchema": {"type": "object", "properties": {
         "message_id": {"type": "string"},
         "fence": {"type": "string"},
         "status": {"type": "string"},
         "note": {"type": "object"}},
         "required": ["message_id", "fence", "status"]}},
]


class MCPTownServer:
    """One MCP server bound to one run and one participant name."""

    def __init__(self, url: str, run_id: str, name: str,
                 token: str = "", grant_json: str | None = None,
                 client=None):
        self.url = url
        self.run_id = run_id
        self.name = name
        self.token = token
        self.grant_json = grant_json
        self._client = client
        self._joined = False

    def _town(self):
        if self._client is None:
            from .client import TownClient

            self._client = TownClient(self.url, self.run_id)
        if not self._joined:
            self._client.join_auto(self.name, self.token,
                                   self.grant_json)
            self._joined = True
        return self._client

    # -- tool execution -------------------------------------------------

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        town = self._town()
        if name == "town_status":
            return {"name": self.name, "run": town.run_context}
        if name == "town_participants":
            return town.participants()
        if name == "town_notify":
            return {"hint": town.notify(
                wait=float(arguments.get("wait", 0.5)))}
        if name == "town_claim":
            claim = town.claim()
            return claim if claim is not None else {"work": None}
        if name == "town_send":
            return town.send(arguments["message_id"], arguments["to"],
                             arguments["kind"], arguments["body"])
        if name == "town_ack":
            return town.ack(arguments["message_id"], arguments["fence"],
                            arguments["status"],
                            arguments.get("note") or {})
        raise ValueError(f"unknown tool {name}")

    # -- JSON-RPC -------------------------------------------------------

    def handle_message(self, message: dict[str, Any]
                       ) -> dict[str, Any] | None:
        method = message.get("method")
        message_id = message.get("id")

        def result(payload: Any) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": message_id,
                    "result": payload}

        def error(code: int, text: str) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": message_id,
                    "error": {"code": code, "message": text}}

        if method == "initialize":
            return result({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nandatown",
                               "version": __version__},
            })
        if method == "notifications/initialized":
            return None
        if method == "ping":
            return result({})
        if method == "tools/list":
            return result({"tools": TOOLS})
        if method == "tools/call":
            params = message.get("params", {})
            try:
                payload = self._call_tool(params.get("name", ""),
                                          params.get("arguments") or {})
                return result({"content": [
                    {"type": "text", "text": json.dumps(payload)}]})
            except Exception as exc:
                return result({"content": [
                    {"type": "text",
                     "text": f"{type(exc).__name__}: {exc}"}],
                    "isError": True})
        if message_id is None:
            return None
        return error(-32601, f"method {method!r} not found")

    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = self.handle_message(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()


class _ProbeFailure(Exception):
    pass


def _stop_probe_process(process: subprocess.Popen) -> None:
    """Stop the probe and its process group on POSIX.

    Non-POSIX platforms fall back to stopping the direct child because
    Python does not expose one portable descendant-process primitive.
    """
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            stream.close()


def probe(command: list[str], timeout: float = 15.0) -> dict[str, Any]:
    """Client side of the handshake against any external MCP server.

    ``timeout`` is one wall-clock deadline for the entire handshake, not a
    per-read timeout. Responses are line-delimited and individually bounded.
    """
    report: dict[str, Any] = {"ok": False, "problems": []}
    deadline = time.monotonic() + max(timeout, 0.0)
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        start_new_session=(os.name == "posix"))
    responses: queue.Queue[bytes | BaseException | None] = queue.Queue()

    def read_responses() -> None:
        assert process.stdout is not None
        try:
            while True:
                line = process.stdout.readline(MAX_PROBE_RESPONSE_BYTES + 1)
                if not line:
                    responses.put(None)
                    return
                if len(line) > MAX_PROBE_RESPONSE_BYTES:
                    responses.put(_ProbeFailure(
                        "MCP response is too large (limit 1048576 bytes)"))
                    return
                responses.put(line)
        except (OSError, ValueError) as exc:
            responses.put(exc)

    reader = threading.Thread(target=read_responses, daemon=True)
    reader.start()

    def rpc(message: dict[str, Any]) -> dict[str, Any] | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProbeFailure("MCP probe timed out")
        assert process.stdin is not None
        try:
            process.stdin.write((json.dumps(message) + "\n").encode())
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise _ProbeFailure("MCP server closed stdin") from exc
        if "id" not in message:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProbeFailure("MCP probe timed out")
        try:
            response = responses.get(timeout=remaining)
        except queue.Empty as exc:
            raise _ProbeFailure("MCP probe timed out") from exc
        if isinstance(response, BaseException):
            if isinstance(response, _ProbeFailure):
                raise response
            raise _ProbeFailure("could not read MCP response") from response
        if response is None:
            raise _ProbeFailure("MCP server closed stdout")
        try:
            decoded = json.loads(response)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise _ProbeFailure("MCP server returned malformed JSON") from exc
        if not isinstance(decoded, dict):
            raise _ProbeFailure("MCP server returned non-object JSON")
        return decoded

    try:
        init = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": PROTOCOL_VERSION,
                               "capabilities": {},
                               "clientInfo": {"name": "nandatown-probe",
                                              "version": __version__}}})
        if not init or "result" not in init:
            report["problems"].append("initialize failed")
            return report
        result = init["result"]
        report["protocolVersion"] = result.get("protocolVersion")
        report["serverInfo"] = result.get("serverInfo", {})
        if "tools" not in result.get("capabilities", {}):
            report["problems"].append("server does not declare the"
                                      " tools capability")
        rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listed = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                      "params": {}})
        if not listed or "result" not in listed:
            report["problems"].append("tools/list failed")
            return report
        tools = listed["result"].get("tools", [])
        report["tools"] = [t.get("name") for t in tools]
        for tool in tools:
            if not tool.get("description"):
                report["problems"].append(
                    f"tool {tool.get('name')} has no description")
            if "inputSchema" not in tool:
                report["problems"].append(
                    f"tool {tool.get('name')} has no input schema")
        report["ok"] = not report["problems"]
        return report
    except _ProbeFailure as exc:
        report["problems"].append(str(exc))
        return report
    finally:
        _stop_probe_process(process)
        reader.join(timeout=0.2)


def main() -> None:
    import argparse
    import os

    parser = argparse.ArgumentParser(prog="nandatown-mcp")
    parser.add_argument("--url", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--token", default=os.environ.get("TOKEN", ""))
    parser.add_argument("--grant-file", default=None)
    args = parser.parse_args()
    grant_json = None
    if args.grant_file:
        with open(args.grant_file) as f:
            grant_json = f.read()
    MCPTownServer(args.url, args.run, args.name, args.token,
                  grant_json).serve()


if __name__ == "__main__":
    main()
