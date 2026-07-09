# StreamPay — Metered Streaming Payments for AI Agents

**NandaHack Phase 2 Submission · `stripe-engineer`**

Hosted REST API for rate-limited, per-tick streaming payments between AI agents. Idempotency-keyed mutations, audit trail, receipt verification.

## Quick Deploy (Render)

1. Go to [render.com](https://render.com) → New → Web Service
2. Connect repo: `stanleyoz/nandatown`
3. Configure:
   - **Root Directory:** `streampay`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Deploy → get URL (e.g. `https://streampay.onrender.com`)

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/skill.md` | SKILL.md for agent discovery |
| POST | `/streams` | Open stream (idempotent) |
| POST | `/streams/{id}/tick` | Drain one tick (idempotent) |
| POST | `/streams/{id}/close` | Close stream → receipt (idempotent) |
| GET | `/streams/{id}` | Stream state |
| GET | `/streams/{id}/receipt` | Receipt |
| POST | `/streams/{id}/refund` | Refund closed stream (idempotent) |
| GET | `/streams?agent={id}` | List streams |

## Local Test

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn main:app --reload
```

Then:
```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/streams -H 'Content-Type: application/json' -d '{"stream_id":"s-1","payer":"a","payee":"b","rate_per_tick":10,"max_total":500}'
curl -X POST http://localhost:8000/streams/s-1/tick -H 'Content-Type: application/json' -d '{"tick":1}'
curl -X POST http://localhost:8000/streams/s-1/close
```

## Phase 1 · Nanda Town Plugin

The streaming semantics are validated by the Phase 1 PR:
https://github.com/projnanda/nandatown/pull/116

That PR hardens `streaming.py` with idempotency keys, typed errors, audit trail,
and 7 adversarial validators — the same invariants this Phase 2 API enforces
at the HTTP layer.