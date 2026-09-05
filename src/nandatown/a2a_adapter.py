"""The A2A edge: serve a town seller as an Agent2Agent agent, test any
A2A endpoint, and bridge a Track role to one.

A2A here means the real wire shape: an agent card at
/.well-known/agent-card.json, JSON-RPC 2.0 message/send returning a
task with artifacts, and tasks/get. The bridge makes an external A2A
agent a first-class participant: the town's mailbox semantics stay
canonical and the A2A hop is just how that role thinks.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Request

from . import __version__
from .path_profiles import QUOTE_INTENT_FIELDS
from .a2a_transport import (
    DEFAULT_MAX_RESPONSE_BYTES,
    HTTPStatusError,
    a2a_client,
    read_json,
    validate_response_budget,
)

CARD_PATHS = ["/.well-known/agent-card.json", "/.well-known/agent.json"]


def build_agent_card(base_url: str) -> dict[str, Any]:
    return {
        "name": "nandatown-quote-seller",
        "description": "The town's reference seller as an A2A agent:"
                       " send a JSON quote request, receive a priced"
                       " quote.",
        "url": base_url,
        "version": __version__,
        "capabilities": {"streaming": False,
                         "pushNotifications": False},
        "defaultInputModes": ["text"],
        "defaultOutputModes": ["text"],
        "skills": [{
            "id": "quote",
            "name": "Quote",
            "description": "Given JSON {sku, quantity,"
                           " unit_price_cents}, returns JSON"
                           " {request_id, total_cents}. Optional item terms"
                           " {color, merchant_id, currency} request an explicit"
                           " quote echoing sku, quantity and those terms."
                           " This reference fixture performs no purchase.",
            "tags": ["quote", "commerce", "nandatown"],
        }],
    }


def build_a2a_app(base_url: str = "http://127.0.0.1:8940",
                  defect: str | None = None):
    """The reference A2A seller, optionally with one planted defect:
    wrong_total, wrong_item, duplicate_fulfillment, or card_drift. Planted defects
    are how the path test's failure cases are demonstrated for real."""
    app = FastAPI(title="nandatown a2a seller", version=__version__)
    tasks: dict[str, dict[str, Any]] = {}
    fulfillment_counts: dict[str, int] = {}
    card_fetches = {"n": 0}

    @app.get("/.well-known/agent-card.json")
    @app.get("/.well-known/agent.json")
    def agent_card():
        card = build_agent_card(base_url)
        if defect == "card_drift":
            card_fetches["n"] += 1
            card["revision"] = card_fetches["n"]
        return card

    def _quote(text: str) -> tuple[str, dict[str, Any]]:
        request = json.loads(text)
        total = int(request["quantity"]) * int(request["unit_price_cents"])
        request_id = request.get("request_id", "q-1")
        if defect == "wrong_total":
            total += 100
        if defect == "duplicate_fulfillment":
            count = fulfillment_counts.get(request_id, 0) + 1
            fulfillment_counts[request_id] = count
            if count > 1:
                return "completed", {"request_id": request_id,
                                     "total_cents": total,
                                     "fulfillment_number": count}
        quote = {"request_id": request_id, "total_cents": total}
        if any(field in request for field in ("color", "merchant_id", "currency")):
            quote.update({field: request[field] for field in QUOTE_INTENT_FIELDS
                          if field in request})
        if defect == "wrong_item":
            quote.update({"color": "red", "total_cents": 3000})
        return "completed", quote

    @app.post("/")
    async def rpc(request: Request):
        message = await request.json()
        method = message.get("method")
        message_id = message.get("id")

        def result(payload):
            return {"jsonrpc": "2.0", "id": message_id,
                    "result": payload}

        if method == "message/send":
            params = message.get("params", {})
            parts = params.get("message", {}).get("parts", [])
            text = next((p.get("text", "") for p in parts
                         if p.get("kind") == "text"), "{}")
            task_id = "task-" + uuid.uuid4().hex[:12]
            try:
                state, quote = _quote(text)
                artifacts = [{"artifactId": "a-1",
                              "name": "quote",
                              "parts": [{"kind": "text",
                                         "text": json.dumps(quote)}]}]
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                state, artifacts = "failed", [
                    {"artifactId": "a-1", "name": "error",
                     "parts": [{"kind": "text",
                                "text": f"bad request: {exc}"}]}]
            task = {"id": task_id, "contextId": "ctx-" + task_id,
                    "status": {"state": state},
                    "artifacts": artifacts, "kind": "task"}
            tasks[task_id] = task
            return result(task)
        if method == "tasks/get":
            task_id = message.get("params", {}).get("id", "")
            task = tasks.get(task_id)
            if task is None:
                return {"jsonrpc": "2.0", "id": message_id,
                        "error": {"code": -32001,
                                  "message": "task not found"}}
            return result(task)
        return {"jsonrpc": "2.0", "id": message_id,
                "error": {"code": -32601,
                          "message": f"method {method!r} not found"}}

    return app


# -- client side -------------------------------------------------------


def fetch_card(base_url: str,
               http: httpx.Client | None = None, *,
               max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
               timeout_seconds: float = 15.0) -> dict[str, Any]:
    budget = validate_response_budget(max_response_bytes)
    with a2a_client(base_url, http, timeout_seconds) as client:
        for path in CARD_PATHS:
            try:
                return read_json(client, "GET", path,
                                 max_response_bytes=budget,
                                 timeout_seconds=timeout_seconds)
            except HTTPStatusError as exc:
                if exc.status_code not in (404, 410):
                    raise
    raise ValueError("a2a_card_missing")


def send_message(base_url: str, text: str,
                 http: httpx.Client | None = None, *,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
                 timeout_seconds: float = 30.0) -> dict[str, Any]:
    budget = validate_response_budget(max_response_bytes)
    request = {
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": {"message": {
            "role": "user",
            "messageId": "m-" + uuid.uuid4().hex[:8],
            "parts": [{"kind": "text", "text": text}]}}}
    with a2a_client(base_url, http, timeout_seconds) as client:
        payload = read_json(client, "POST", "/", payload=request,
                            max_response_bytes=budget,
                            timeout_seconds=timeout_seconds,
                            success_statuses=range(200, 300))
    if "error" in payload:
        raise ValueError("a2a_rpc_error")
    if not isinstance(payload.get("result"), dict):
        raise ValueError("a2a_rpc_invalid_result")
    return payload["result"]


def artifact_text(task: dict[str, Any]) -> str:
    for artifact in task.get("artifacts", []):
        for part in artifact.get("parts", []):
            if part.get("kind") == "text":
                return part.get("text", "")
    return ""


def artifact_texts(task: dict[str, Any]) -> list[Any]:
    """Return every text output without silently selecting the first one.

    The strict Path profiles count each text part as a possible fulfillment.
    Malformed artifact containers produce no text outputs; malformed text
    values are retained so the caller can report them as unparseable rather
    than mistaking them for an absent response.
    """
    artifacts = task.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    texts: list[Any] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        parts = artifact.get("parts", [])
        if not isinstance(parts, list):
            continue
        for part in parts:
            if isinstance(part, dict) and part.get("kind") == "text":
                texts.append(part.get("text", ""))
    return texts


def probe_endpoint(base_url: str,
                   http: httpx.Client | None = None) -> dict[str, Any]:
    """Card validation plus one message/send round trip."""
    report: dict[str, Any] = {"ok": False, "problems": []}
    try:
        card = fetch_card(base_url, http=http)
    except (ValueError, httpx.HTTPError) as exc:
        report["problems"].append(str(exc))
        return report
    report["card"] = {k: card.get(k) for k in ("name", "version", "url")}
    for field in ("name", "version", "url", "skills",
                  "defaultInputModes"):
        if field not in card:
            report["problems"].append(f"agent card missing {field!r}")
    if not card.get("skills"):
        report["problems"].append("agent card declares no skills")
    try:
        task = send_message(
            base_url,
            json.dumps({"request_id": "probe-1", "sku": "widget",
                        "quantity": 2, "unit_price_cents": 1995}),
            http=http)
        report["task_state"] = task.get("status", {}).get("state")
        report["artifact"] = artifact_text(task)[:200]
        if task.get("kind") != "task":
            report["problems"].append("message/send did not return a"
                                      " task")
        if report["task_state"] not in ("completed", "input-required",
                                        "working", "failed"):
            report["problems"].append(
                f"unknown task state {report['task_state']!r}")
    except (ValueError, httpx.HTTPError) as exc:
        report["problems"].append(f"message/send round trip failed:"
                                  f" {exc}")
    report["ok"] = not report["problems"]
    return report


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(prog="nandatown-a2a")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8940)
    args = parser.parse_args()
    base_url = f"http://{args.host}:{args.port}"
    print(f"A2A reference seller on {base_url}")
    print(f"agent card: {base_url}/.well-known/agent-card.json")
    uvicorn.run(build_a2a_app(base_url), host=args.host, port=args.port,
                log_level="warning")


if __name__ == "__main__":
    main()
