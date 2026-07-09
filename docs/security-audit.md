# Nanda Town — Security Audit (Red Team / Blue Team)

Last updated: July 2026, after P0/P1 remediation.

This document is the canonical security posture record for Nanda Town. It
preserves the adversarial framing from the original autopsy and marks each
finding as **FIXED**, **OPEN**, or **ACCEPTED_RISK**.

For operator setup, see the [operator checklist](#operator-checklist) and
[`distributed.md`](distributed.md). For dashboard API hardening, see
[`apps/nest-dashboard/README.md`](../apps/nest-dashboard/README.md).

---

## Executive summary

Nanda Town is a **strong Tier-1 simulation engine** with a clean middleware
seam and good single-process determinism. The weak spots clustered in three
places:

1. **Distributed HTTP surface** — was open by default; now gated by
   `NEST_HTTP_SHARED_SECRET` when `workers > 1` or bind is not localhost
2. **Next.js `/skills` API** — was public write with SSRF risk; now guarded
   by API key (prod), rate limit, body cap, and URL blocklist
3. **Operational gaps** — JwtAuth sim-clock wiring, worker `partition_heal_at`,
   and `auth_scope` silent bypass are **fixed**; trace token leakage and TLS
   remain on the P2/P3 backlog

**P0/P1 items from the July 2026 audit are remediated in code.** Remaining
work is documented under [Open backlog (P2/P3)](#open-backlog-p2p3).

---

## Runtime evidence

### At audit time (historical)

| Check | Result | Implication |
|-------|--------|-------------|
| `nest doctor` | 7/7 passed | Core engine healthy |
| `http_shared_secret()` | `None` | No HTTP auth configured |
| `http_auth_valid({})` | `True` | Any request accepted on worker bridges |
| `GET /skills` | 500 | `DATABASE_URL` missing — no graceful fallback |
| `.env.local` | absent | Skills registry not initialized |
| `worker.py` Simulator | no `partition_heal_at` | Partition heal disabled in distributed runs |

### After remediation (current)

| Check | Result | Implication |
|-------|--------|-------------|
| `require_http_shared_secret()` with `workers: 2` | raises without secret | Distributed runs fail fast until secret is set |
| `http_auth_valid` with wrong header | `False` via `hmac.compare_digest` | Timing-safe comparison |
| `check_health()` with secret set | succeeds | Sends `http_auth_headers()` on GET |
| Worker `Simulator` | passes `partition_heal_at_tick` | Partition heal works in distributed runs |
| `wire_auth_to_sim_clock()` | JwtAuth uses `sim.clock.now` | Token expiry follows virtual clock |
| `auth_scope` without auth plugin | denies (`auth_plugin_missing`) | No silent bypass |
| `POST /api/skills` in production | 503 without `NEST_SKILLS_API_KEY` | Writes disabled until configured |
| SSRF to `http://127.0.0.1/...` | 400 on API; blocked in form action | Private/internal hosts rejected |

---

## Findings register

### Remediated (P0/P1)

| ID | Finding | Status | Fix |
|----|---------|--------|-----|
| 1 | Worker HTTP bridge unauthenticated by default | **FIXED** | `require_http_shared_secret()` in `runner._run_distributed()` |
| 4 | `check_health()` omits auth headers | **FIXED** | `check_health` sends `http_auth_headers()` |
| 5 | `/api/skills` POST unauthenticated | **FIXED** | `NEST_SKILLS_API_KEY` + `X-Skills-API-Key` in prod |
| 6 | SSRF in skill reachability probe | **FIXED** | `isSafeExternalUrl()` in API route + server action |
| — | HTTP secret compare uses `==` | **FIXED** | `hmac.compare_digest` in `http_auth_valid` |
| — | `partition_heal_at` not passed to workers | **FIXED** | `worker.py` forwards `failures.partition_heal_at_tick` |
| — | JwtAuth not wired to sim clock | **FIXED** | `wire_auth_to_sim_clock()` in runner + worker |
| — | Auth scope silent bypass when no auth plugin | **FIXED** | `auth_scope` denies with `auth_plugin_missing` |

### Still open or accepted

| ID | Finding | Status | Notes |
|----|---------|--------|-------|
| 2 | Publicly known JWT default secret | **ACCEPTED_RISK** | `KNOWN_WEAK_SECRET` warns at runtime; use `NEST_JWT_SECRET` outside sim |
| 3 | No TLS on worker bridges | **OPEN (P2)** | Cleartext `X-Nest-Auth`; use reverse proxy for WAN |
| 7 | Registry RPC on port 18999 | **OPEN (P2)** | Hardcoded; binds to `worker_bind` |
| 8 | Trace JSONL logs full payloads | **OPEN (P2)** | `metadata.auth_token` may appear in trace `msg` |
| — | `/skills` hard-fails without DB | **OPEN (P3)** | Returns 500; graceful empty state not implemented |
| — | `ObservabilityMiddleware.dropped_count` dead | **OPEN (P3)** | Counter never incremented |
| — | Auth scope inbound-only | **ACCEPTED_RISK** | Outbound `on_send` passes through by design |
| — | `deploy-local.ps1` hardcodes `7/7` doctor match | **OPEN (P3)** | Brittle if doctor checks change |
| — | `npm audit \|\| true` in CI | **OPEN (P3)** | Silences vulnerability failures |

---

## Architecture map (attack surface)

```mermaid
flowchart TB
  subgraph fixed [Fixed P0/P1]
    HttpSecret[NEST_HTTP_SHARED_SECRET gate]
    SkillsGuard[Skills API guard]
    SSRFBlock[SSRF URL blocklist]
    HealthAuth[check_health auth headers]
    PartitionHeal[partition_heal_at in workers]
    JwtClock[JwtAuth sim clock wiring]
    AuthScopeDeny[auth_scope denies missing plugin]
  end
  subgraph open [Still open P2/P3]
    TraceLeak[Trace msg leaks auth_token]
    WeakJwt[KNOWN_WEAK_SECRET warning only]
    NoTLS[No TLS on worker bridges]
    SkillsGrace[No graceful /skills without DB]
    DeadCounter[Observability dropped_count]
  end
  subgraph exposed [Always exposed when running]
    WorkerBridge[WorkerHttpBridge :19000+]
    RegistryRPC[RegistryRpcServer :18999]
    SkillsAPI[POST /api/skills]
    TraceFiles[JSONL traces with full msg]
  end
  HttpSecret --> WorkerBridge
  HttpSecret --> RegistryRPC
  SkillsGuard --> SkillsAPI
  NeonDB[DATABASE_URL] --> SkillsAPI
```

---

## RED TEAM — Critical and high exposures

### Critical (remediated)

**1. Worker HTTP bridge unauthenticated by default** — **FIXED**

Previously `http_auth_valid()` returned `True` when `NEST_HTTP_SHARED_SECRET`
was unset. Now `require_http_shared_secret()` raises before distributed runs
when `workers > 1` or `worker_bind` is not localhost.

**2. Publicly known JWT default secret** — **ACCEPTED_RISK**

`KNOWN_WEAK_SECRET = b"nest-default-secret"` still exists for simulation
convenience. `JwtAuth` emits a runtime warning. Set `NEST_JWT_SECRET` for
any non-simulation deployment.

### High (remediated or open)

| Finding | Status |
|---------|--------|
| No TLS on worker bridges | **OPEN** — use a reverse proxy |
| `check_health()` omits auth headers | **FIXED** |
| `/api/skills` POST unauthenticated | **FIXED** |
| SSRF in reachability probe | **FIXED** |
| Registry RPC on port 18999 | **OPEN** |
| Trace JSONL logs full payloads | **OPEN** |

---

## BLUE TEAM — Hardened vs still weak

### Hardened (keep)

| Area | Evidence |
|------|----------|
| Middleware chain drop/transform | `middleware.py` — `None` short-circuit, `kind: denied` / `kind: error` traces |
| Latency determinism | Uses seeded `ctx.rng`, not wall clock |
| JwtAuth signature | `hmac.compare_digest` for token sigs |
| Bounded revocation LRU | `OrderedDict` eviction tested |
| HTTP shared-secret gate | Required for distributed / exposed binds |
| HTTP auth comparison | `hmac.compare_digest` in `http_auth_valid` |
| Health check auth | `check_health` sends auth headers |
| Retry jitter | `http_retry.py` with seeded backoff |
| Single-process determinism | `test_middleware.py`, `test_sim.py` byte-identical traces |
| Skills API guards | Rate limit, body cap, SSRF blocklist, prod API key |
| `deploy-local.ps1` | StrictMode, exit-code checks, port cleanup |
| Worker partition heal | `partition_heal_at_tick` forwarded in workers |
| JwtAuth sim clock | `wire_auth_to_sim_clock()` in runner/worker |
| Auth scope fail-closed | Denies when auth plugin missing |

### Weak / regressions (remaining)

| Gap | Location | Severity |
|-----|----------|----------|
| Trace redaction | `simulator.py` trace `msg` field | P2 |
| No TLS on HTTP bridges | `network_runner.py` | P2 (mitigate with proxy) |
| `/skills` without `DATABASE_URL` | `db.ts` | P3 (UX) |
| `ObservabilityMiddleware.dropped_count` | `observability.py` | P3 |
| `KNOWN_WEAK_SECRET` warning-only | `jwt_auth.py` | Accepted for sim |

---

## Open backlog (P2/P3)

| Priority | Fix | Effort |
|----------|-----|--------|
| P2 | Redact `metadata.auth_token` from trace `msg` field | Medium |
| P2 | CSP + stricter `source_url` protocol allowlist on skills page | Medium |
| P2 | TLS termination guidance / optional mTLS for worker bridges | Medium |
| P3 | Graceful `/skills` empty state when no `DATABASE_URL` | Small |
| P3 | Increment `ObservabilityMiddleware.dropped_count` | Small |
| P3 | Parameterize registry RPC port | Small |

See [`roadmap.md`](roadmap.md) Phase 6.

---

## Operator checklist

| Variable | When required | Example |
|----------|---------------|---------|
| `NEST_HTTP_SHARED_SECRET` | `nest run --workers N` (N>1) or `worker_bind` not localhost | `export NEST_HTTP_SHARED_SECRET=$(openssl rand -hex 32)` |
| `NEST_JWT_SECRET` | Non-simulation deployments using JwtAuth | `export NEST_JWT_SECRET=$(openssl rand -hex 32)` |
| `NEST_SKILLS_API_KEY` | `POST /api/skills` when `NODE_ENV=production` | Set in `apps/nest-dashboard/.env.local` |
| `DATABASE_URL` | `/skills` page (Neon Postgres) | Neon console connection string |

**Distributed run example:**

```bash
export NEST_HTTP_SHARED_SECRET="your-long-random-secret"
nest run marketplace --workers 2 --ticks 2000
```

**Skills API example (production):**

```bash
curl -X POST http://localhost:3000/api/skills \
  -H "Content-Type: application/json" \
  -H "X-Skills-API-Key: $NEST_SKILLS_API_KEY" \
  -d '{"name":"my-skill","source_type":"content","content":"# SkillMD\n..."}'
```

**Local full stack:**

```powershell
.\scripts\deploy-local.ps1 -Mode Prod -RunScenario -InitSkills `
  -DatabaseUrl "postgresql://user:pass@host/db?sslmode=require"
# Also set NEST_SKILLS_API_KEY in apps/nest-dashboard/.env.local for prod POST
```

---

## Kill critic — what NOT to over-fix

- **`privacy: noop` default** — intentional for simulation; documented limitation
- **Distributed non-determinism** — by design for HTTP workers
- **Reference plugins simplified** — testing scaffolding, not production crypto
- **Local Postgres for skills** — won't work; `@neondatabase/serverless` needs Neon

---

## Active production state (local)

- Dashboard prod mode: http://localhost:3000 (`/`, `/hackathon`, `/visualizer` → 200)
- `/skills`: 500 until `DATABASE_URL` is set and `node scripts/db-init.mjs` runs
- `nest doctor`: 7/7 when engine is healthy
- Distributed runs: require `NEST_HTTP_SHARED_SECRET` when `workers > 1`
