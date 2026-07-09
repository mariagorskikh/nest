# StreamPay — Metered Streaming Payments for AI Agents

Open a rate-limited payment stream between two agents, drain by tick,
close at any time, and get verifiable receipts. Every mutation is
idempotency-keyed: retrying the same operation returns the original result.

## Base URL
https://{{BASE_URL}}

## Endpoints

### GET /health
Returns service status.
Example: curl https://{{BASE_URL}}/health
Response: {"status":"ok","service":"streampay","version":"1.0.0"}

### POST /streams
Open a streaming payment. The first tick drains immediately so the payee
observes a non-zero balance. Idempotent by stream_id.
Body: {"stream_id": "s-1", "payer": "agent-a", "payee": "agent-b",
       "rate_per_tick": 10, "max_total": 500}
Example: curl -X POST https://{{BASE_URL}}/streams -H "Content-Type: application/json"
         -d '{"stream_id":"s-1","payer":"agent-a","payee":"agent-b","rate_per_tick":10,"max_total":500}'
Response 201: {"stream_id":"s-1","payer":"agent-a","payee":"agent-b",
               "rate_per_tick":10,"max_total":500,"total_debited":10,
               "remaining":490,"is_open":true}
Response 200: same data (idempotent — stream already exists and is open)
Response 409: {"error":"stream_already_closed"}

### POST /streams/{id}/tick
Drain one tick from a stream. Idempotent: repeating the same tick is a no-op.
Body: {"tick": 1} (optional, increments if omitted)
Example: curl -X POST https://{{BASE_URL}}/streams/s-1/tick -H "Content-Type: application/json"
         -d '{"tick":1}'
Response: {"stream_id":"s-1","total_debited":20,"remaining":480,"is_open":true}
Or:    {"stream_id":"s-1","total_debited":500,"remaining":0,"is_open":false}
       (stream exhausted — max_total reached)

### POST /streams/{id}/close
Close the stream and get a receipt. Either payer or payee can close.
Idempotent: returns the original receipt on retry.
Example: curl -X POST https://{{BASE_URL}}/streams/s-1/close
Response: {"stream_id":"s-1","receipt":{"payer":"agent-a","payee":"agent-b",
          "amount":500,"status":"closed"}}

### GET /streams/{id}
Get the current state of a stream.
Example: curl https://{{BASE_URL}}/streams/s-1
Response: full stream state (same shape as POST /streams response)

### GET /streams/{id}/receipt
Get the receipt for a closed stream. Returns 404 if stream is still open
or doesn't exist.
Example: curl https://{{BASE_URL}}/streams/s-1/receipt
Response: {"payer":"agent-a","payee":"agent-b","amount":500,"status":"closed"}

### POST /streams/{id}/refund
Refund a closed stream, returning the debited funds to the payer.
Only works on closed streams. Idempotent.
Example: curl -X POST https://{{BASE_URL}}/streams/s-1/refund
Response: {"stream_id":"s-1","refund_amount":500,"refunded_to":"agent-a"}
Error 409: {"error":"stream_still_open","detail":"Cannot refund open stream"}

### GET /streams?agent={agent_id}
List all streams where the given agent is the payer or payee.
Example: curl "https://{{BASE_URL}}/streams?agent=agent-a"
Response: {"streams": [...], "count": 3}

## How the agent should use this

1. When hiring another agent for a metered task (LLM inference, compute
   rental, bandwidth billing), POST /streams with a unique stream_id,
   the payer, payee, rate_per_tick, and max_total.
2. On each billing interval, POST /streams/{id}/tick. Check the
   response: if is_open is false, the stream is exhausted.
3. When the task completes or is cancelled: POST /streams/{id}/close
   to seal the stream and get a receipt. Unused remainder is never spent.
4. To get paid funds back: POST /streams/{id}/refund (only on closed streams).
5. To verify payment: GET /streams/{id}/receipt returns the receipt.

## Notes
- All mutations are idempotent: repeat calls return original results.
- rate_per_tick must be >= 1; max_total must be >= rate_per_tick.
- Streams are purely in-memory (no persistence across restarts).
- This service implements the streaming semantics validated by the
  Nanda Town streaming payments plugin (Phase 1 of NandaHack).