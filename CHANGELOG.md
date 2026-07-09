# Changelog
All notable changes to Nanda Town are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
## [Unreleased]
### Added
- [`docs/security-audit.md`](docs/security-audit.md) — post-audit security posture (red/blue team findings register)
- Middleware layer: `resilience`, `observability`, `auth_scope`, `latency` built-ins
- `wire_auth_to_sim_clock()` — JwtAuth bound to simulator virtual clock
- Skills API guards: rate limit, body cap, SSRF blocklist (`skills-api-guard.ts`, `url-safety.ts`)
- `scripts/deploy-local.ps1` — one-command local deployment (Dev/Prod, InitSkills)
- Dashboard `.env.local.example` with `DATABASE_URL` and `NEST_SKILLS_API_KEY`
### Security
- Require `NEST_HTTP_SHARED_SECRET` when `workers > 1` or `worker_bind` is not localhost
- `hmac.compare_digest` in `http_auth_valid` (timing-safe secret comparison)
- `check_health()` sends `http_auth_headers()` for peer readiness probes
- `partition_heal_at_tick` forwarded to worker `Simulator` instances
- `auth_scope` middleware denies inbound messages when auth plugin is missing
- `POST /api/skills`: `NEST_SKILLS_API_KEY` required in production; 30 req/min/IP rate limit; 256 KB body cap
- SSRF blocklist for skill `source_url` in API route, server action, and page hrefs
### Changed
- `hackathon-types.ts` is now generated; display helpers moved to `hackathon-display.ts`
- `hackathon-data.json` is built from committed fixture for CI reproducibility
- **Phase 2 (air-gapped operation) removed from roadmap** — existing offline paths retained; see [`docs/roadmap.md`](docs/roadmap.md)
- Hackathon type generator: `scripts/generate_hackathon_types.py` with `--check` gate
- Hackathon data drift check: `scripts/check_hackathon_data.py` + `fixtures/hackathon_prs.json`
- Optional structured logging via `NEST_LOG=debug|info` (structlog in simulator/runner)
- Python 3.13 in CI test matrix
- Vendored `d3.min.js` for offline `nest dashboard` (no CDN)
- `apps/README.md` documenting both front-end apps
### Added (Phase 5 — distributed hardening)
- Configurable `worker_bind`, `worker_hosts`, and `worker_mode` (`auto`|`manual`) for distributed runs
- Worker manifest files (`routes.json`, `worker-N-spec.json`) under `.{scenario}-workers/`
- `nest worker run --spec` for remote worker processes
- `GET /health` on worker HTTP bridges; `nest doctor --distributed` manifest checks
- Shared registry RPC (`distributed.shared_registry`) with `RemoteRegistry` client
- HTTP transport tuning via `NEST_HTTP_RETRIES` and `NEST_HTTP_TIMEOUT`
- [`docs/roadmap.md`](docs/roadmap.md) (Phase 2 removed from plan)
## Phase 3 — Parallel and distributed execution
### Added
- `--parallel` flag and `parallel: true` scenario YAML for concurrent agent dispatch
- `--workers N` for multi-process partitions with HTTP bridges and trace merge
- `RoutedTransport`, `WorkerHttpBridge`, HTTP transport plugin
- `docs/distributed.md`
### Changed
- Byzantine payload mangling uses `randbytes` (deterministic for fixed seeds)
- Registry capability index for O(1) lookup
- `PrepaidCredits` uses `threading.Lock` for concurrent safety
## Phase 1 — Security and supply-chain hardening
### Added
- `uv.lock` with `uv sync --frozen` in CI
- CI security job: `pip-audit` + `bandit`
- Dependabot for pip and GitHub Actions
- pytest coverage gate (75% minimum)
- PyPI OIDC Trusted Publisher with attestations
### Changed
- JwtAuth requires explicit secret; warns on weak default
- GitHub Actions pinned to commit SHAs
- Default identity plugin: `did_key` (simulation-only deterministic signatures)
- HTML metrics report escapes agent names (XSS fix)
### Security
- Removed hardcoded HMAC default secret from jwt_auth
