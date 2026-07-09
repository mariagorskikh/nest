# Nanda Town roadmap
| Phase | Status | Summary |
|---|---|---|
| Phase 1 — Security + supply-chain | **Done** | Lockfile, pinned CI, OIDC publish, coverage gate |
| ~~Phase 2 — Air-gapped operation~~ | **Removed** | Tier-1 sim is already offline; mock LLM/judge and fixture-based dashboard data cover remaining egress without a dedicated milestone |
| Phase 3 — Parallel + distributed foundation | **Done** | `--parallel`, `--workers`, HTTP bridge, trace merge |
| Phase 4 — Product-readiness | **Done** | Dashboard CI, schema/data automation, CHANGELOG, structlog |
| Phase 5 — Distributed hardening | **Done** | Multi-host workers, manual worker mode, shared registry RPC |
| Phase 6 — Post-audit remediation (P2/P3) | **Open** | Trace redaction, graceful `/skills` without DB, CSP, observability counter, registry port config |
Phase 2 was dropped because the simulator's default path requires no network,
`nest dashboard` ships vendored assets, the judge panel supports `--mock`, and
marketplace data builds from committed fixtures. A separate air-gap milestone
added process overhead without closing a functional gap.
**Phase 6** tracks remaining items from the July 2026 security audit
([`security-audit.md`](security-audit.md)):
- Redact `metadata.auth_token` from trace `msg` field (P2)
- Graceful `/skills` empty state when `DATABASE_URL` is unset (P3)
- CSP headers and stricter `source_url` allowlist on skills page (P2)
- Fix `ObservabilityMiddleware.dropped_count` dead counter (P3)
- Parameterize registry RPC port (P3)
P0/P1 items (HTTP shared-secret gate, skills API guards, SSRF blocklist,
health auth headers, partition heal in workers, JwtAuth sim clock, auth_scope
fail-closed) are **done** — see [`CHANGELOG.md`](../CHANGELOG.md).
See [`distributed.md`](distributed.md) for execution modes,
[`security-audit.md`](security-audit.md) for the full findings register, and
[`CHANGELOG.md`](../CHANGELOG.md) for release notes.
