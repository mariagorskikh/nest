# SPDX-License-Identifier: Apache-2.0
"""StreamPay — Metered streaming payments API for AI agents.

Open rate-limited payment streams between agents, drain by tick, close/cancel
at any time, and get verifiable receipts. Idempotency-keyed: retrying the same
operation returns the original result instead of raising.

Example::

    curl -X POST https://streampay.onrender.com/streams \
      -H "Content-Type: application/json" \
      -d '{"stream_id":"s-1","payer":"agent-a","payee":"agent-b",
           "rate_per_tick":10,"max_total":500}'
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="StreamPay",
    description="Metered streaming payments for AI agents",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_streams: dict[str, dict[str, Any]] = {}
_closed_receipts: dict[str, dict[str, Any]] = {}
_refund_receipts: dict[str, dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class StreamCreate(BaseModel):
    """Request to open a new stream."""

    stream_id: str = Field(..., description="Unique idempotency key")
    payer: str = Field(..., description="Payer agent ID")
    payee: str = Field(..., description="Payee agent ID")
    rate_per_tick: int = Field(..., ge=1, description="Amount drained per tick")
    max_total: int = Field(..., description="Maximum total to drain")


class StreamResponse(BaseModel):
    """Stream state returned to the caller."""

    stream_id: str
    payer: str
    payee: str
    rate_per_tick: int
    max_total: int
    total_debited: int
    remaining: int
    is_open: bool
    entries: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stream_response(sid: str) -> StreamResponse:
    s = _streams[sid]
    return StreamResponse(
        stream_id=s["stream_id"],
        payer=s["payer"],
        payee=s["payee"],
        rate_per_tick=s["rate_per_tick"],
        max_total=s["max_total"],
        total_debited=s["total_debited"],
        remaining=s["max_total"] - s["total_debited"],
        is_open=s["is_open"],
        entries=s["entries"],
    )


# ---------------------------------------------------------------------------
# SKILL.md
# ---------------------------------------------------------------------------

_SKILL_MD_TEMPLATE = """# StreamPay — Metered Streaming Payments for AI Agents

Open a rate-limited payment stream between two agents, drain by tick,
close at any time, and get verifiable receipts. Every mutation is
idempotency-keyed: retrying the same operation returns the original result.

## Base URL
{BASE_URL}

## Endpoints

### GET /health
Returns service status.
Example: curl {BASE_URL}/health
Response: {{"status":"ok","service":"streampay","version":"1.0.0"}}

### POST /streams
Open a streaming payment. The first tick drains immediately so the payee
observes a non-zero balance. Idempotent by stream_id.
Body: {{"stream_id": "s-1", "payer": "agent-a", "payee": "agent-b",
       "rate_per_tick": 10, "max_total": 500}}
Example: curl -X POST {BASE_URL}/streams -H "Content-Type: application/json"
         -d '{{"stream_id":"s-1","payer":"agent-a","payee":"agent-b",
              "rate_per_tick":10,"max_total":500}}'
Response 201: {{"stream_id":"s-1","payer":"agent-a","payee":"agent-b",
               "rate_per_tick":10,"max_total":500,"total_debited":10,
               "remaining":490,"is_open":true}}
Response 200: same data (idempotent — stream already exists and is open)
Response 409: {{"error":"stream_already_closed"}}

### POST /streams/{{id}}/tick
Drain one tick from a stream. Idempotent: repeating the same tick is a no-op.
Body: {{"tick": 1}} (optional, increments if omitted)
Example: curl -X POST {BASE_URL}/streams/s-1/tick -H "Content-Type: application/json"
         -d '{{"tick":1}}'
Response: {{"stream_id":"s-1","total_debited":20,"remaining":480,"is_open":true}}
Or:     {{"stream_id":"s-1","total_debited":500,"remaining":0,"is_open":false}}
        (stream exhausted — max_total reached)

### POST /streams/{{id}}/close
Close the stream and get a receipt. Either payer or payee can close.
Idempotent: returns the original receipt on retry.
Example: curl -X POST {BASE_URL}/streams/s-1/close
Response: {{"stream_id":"s-1","receipt":{{"payer":"agent-a","payee":"agent-b",
          "amount":500,"status":"closed"}}}}

### GET /streams/{{id}}
Get the current state of a stream.
Example: curl {BASE_URL}/streams/s-1
Response: full stream state (same shape as POST /streams response)

### GET /streams/{{id}}/receipt
Get the receipt for a closed stream. Returns 404 if stream is still open
or doesn't exist.
Example: curl {BASE_URL}/streams/s-1/receipt
Response: {{"payer":"agent-a","payee":"agent-b","amount":500,"status":"closed"}}

### POST /streams/{{id}}/refund
Refund a closed stream, returning the debited funds to the payer.
Only works on closed streams where the payee hasn't already spent the funds.
Idempotent: returns the original refund receipt on retry.
Example: curl -X POST {BASE_URL}/streams/s-1/refund
Response: {{"stream_id":"s-1","refund_amount":500,"refunded_to":"agent-a"}}
Error 409: {{"error":"stream_still_open","detail":"Cannot refund open stream"}}

### GET /streams?agent={{agent_id}}
List all streams where the given agent is the payer or payee.
Example: curl "{BASE_URL}/streams?agent=agent-a"
Response: {{"streams": [...], "count": 3}}

## How the agent should use this

1. When hiring another agent for a metered task (LLM inference, compute
   rental, bandwidth billing), POST /streams with a unique stream_id,
   the payer, payee, rate_per_tick, and max_total.
2. On each billing interval, POST /streams/{{id}}/tick. Check the
   response: if is_open is false, the stream is exhausted.
3. When the task completes or is cancelled: POST /streams/{{id}}/close
   to seal the stream and get a receipt. The unused remainder is never
   spent.
4. To get paid funds back: POST /streams/{{id}}/refund (only on closed
   streams, and only if the payee still holds the funds).
5. To verify that payment occurred: GET /streams/{{id}}/receipt returns
   the receipt with amount and payer/payee.

## Notes
- All mutations are idempotent: repeating the same call returns the
  original result. You can safely retry on network errors.
- rate_per_tick must be >= 1, max_total must be >= rate_per_tick.
- Streams are purely in-memory (no persistence across restarts).
- This service implements the streaming semantics validated by the
  Nanda Town streaming payments plugin (Phase 1 of NandaHack).
"""


@app.get("/skill.md", response_class=PlainTextResponse)
async def skill_md() -> str:
    """Serve the SKILL.md for agent discovery."""
    base = os.environ.get("SKILL_BASE_URL", "https://steamplay.onrender.com")
    return _SKILL_MD_TEMPLATE.format(BASE_URL=base)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness check."""
    return {"status": "ok", "service": "streampay", "version": "1.0.0"}


@app.post("/streams", status_code=201)
async def create_stream(body: StreamCreate) -> dict[str, Any]:
    """Open a streaming payment. Idempotent by stream_id."""
    sid = body.stream_id

    # Idempotency: stream already exists
    if sid in _streams:
        if not _streams[sid]["is_open"]:
            raise HTTPException(
                status_code=409,
                detail={"error": "stream_already_closed", "detail": f"Stream {sid} is closed"},
            )
        return _stream_response(sid).model_dump()

    if body.max_total < body.rate_per_tick:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_params",
                "detail": (
                    f"max_total ({body.max_total}) must be >= rate_per_tick ({body.rate_per_tick})"
                ),
            },
        )

    entry = {"tick": 0, "amount": body.rate_per_tick, "kind": "debit"}
    exhausted = body.max_total == body.rate_per_tick

    _streams[sid] = {
        "stream_id": sid,
        "payer": body.payer,
        "payee": body.payee,
        "rate_per_tick": body.rate_per_tick,
        "max_total": body.max_total,
        "total_debited": body.rate_per_tick,
        "is_open": not exhausted,
        "entries": [entry],
        "opened_at": 0,
    }
    return _stream_response(sid).model_dump()


@app.post("/streams/{stream_id}/tick")
async def tick_stream(stream_id: str, body: dict[str, int] | None = None) -> dict[str, Any]:
    """Drain one tick from a stream. Idempotent by tick number."""
    if stream_id not in _streams:
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    s = _streams[stream_id]
    if not s["is_open"]:
        raise HTTPException(status_code=409, detail={"error": "stream_closed"})

    tick = (body or {}).get("tick", s["entries"][-1]["tick"] + 1)

    # Idempotency: don't double-bill the same tick
    if s["entries"] and s["entries"][-1]["tick"] == tick:
        return _stream_response(stream_id).model_dump()

    remaining = s["max_total"] - s["total_debited"]
    if remaining <= 0:
        s["is_open"] = False
        return _stream_response(stream_id).model_dump()

    amount = min(s["rate_per_tick"], remaining)
    s["total_debited"] += amount
    s["entries"].append({"tick": tick, "amount": amount, "kind": "debit"})

    if s["total_debited"] >= s["max_total"]:
        s["is_open"] = False

    return _stream_response(stream_id).model_dump()


@app.post("/streams/{stream_id}/close")
async def close_stream(stream_id: str) -> dict[str, Any]:
    """Close a stream and return a receipt. Idempotent."""
    # Idempotency: return existing receipt
    if stream_id in _closed_receipts:
        return {
            "stream_id": stream_id,
            "receipt": _closed_receipts[stream_id],
        }

    if stream_id not in _streams:
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    s = _streams[stream_id]
    s["is_open"] = False

    receipt = {
        "payer": s["payer"],
        "payee": s["payee"],
        "amount": s["total_debited"],
        "status": "closed",
    }
    _closed_receipts[stream_id] = receipt

    return {"stream_id": stream_id, "receipt": receipt}


@app.get("/streams/{stream_id}")
async def get_stream(stream_id: str) -> dict[str, Any]:
    """Get stream state."""
    if stream_id not in _streams:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return _stream_response(stream_id).model_dump()


@app.get("/streams/{stream_id}/receipt")
async def get_receipt(stream_id: str) -> dict[str, Any]:
    """Get receipt for a closed stream."""
    if stream_id in _closed_receipts:
        return _closed_receipts[stream_id]
    if stream_id in _streams:
        raise HTTPException(
            status_code=409,
            detail={"error": "stream_not_closed", "detail": f"Stream {stream_id} is still open"},
        )
    raise HTTPException(status_code=404, detail={"error": "not_found"})


@app.post("/streams/{stream_id}/refund")
async def refund_stream(stream_id: str) -> dict[str, Any]:
    """Refund a closed stream. Idempotent."""
    if stream_id in _refund_receipts:
        return _refund_receipts[stream_id]

    if stream_id not in _streams:
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    s = _streams[stream_id]
    if s["is_open"]:
        raise HTTPException(
            status_code=409,
            detail={"error": "stream_still_open", "detail": "Cannot refund open stream"},
        )

    refund = {
        "stream_id": stream_id,
        "refund_amount": s["total_debited"],
        "refunded_to": s["payer"],
        "from": s["payee"],
        "status": "refunded",
    }
    _refund_receipts[stream_id] = refund
    return refund


@app.get("/streams")
async def list_streams(agent: str = "") -> dict[str, Any]:
    """List streams for a given agent (payer or payee)."""
    if not agent:
        return {"streams": [], "count": 0, "detail": "?agent=agent_id is required"}
    result = [
        _stream_response(sid).model_dump()
        for sid, s in _streams.items()
        if s["payer"] == agent or s["payee"] == agent
    ]
    return {"streams": result, "count": len(result)}
