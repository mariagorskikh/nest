# Nanda Town Trace Schema

**Schema version:** `1.0`  
**Format:** JSON Lines (JSONL) — one JSON object per line, UTF-8.

## Versioning policy

- Every trace file **must** begin with a `trace_header` line containing `schema_version`.
- **Patch** changes (clarify docs, optional fields): same major schema version.
- **Minor** changes (new optional event fields): bump `schema_version` minor (e.g. `1.1`).
- **Major** changes (breaking required fields or semantics): bump major (e.g. `2.0`).

Traces produced before schema `1.0` had no header line. Same-seed runs are **not** byte-identical across the `1.0` boundary because the header is prepended.

## Line 1: trace_header

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | e.g. `"1.0"` |
| `kind` | string | yes | always `"trace_header"` |
| `ts` | number | yes | logical time (always `0.0` for header) |
| `generator` | string | yes | e.g. `"nest-core"` |
| `generator_version` | string | yes | package version at write time |

Example:

```json
{"generator":"nest-core","generator_version":"0.1.4","kind":"trace_header","schema_version":"1.0","ts":0.0}
```

## Simulation events (lines 2+)

All simulation events include:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ts` | number | yes | logical simulation time |
| `kind` | string | yes | see kinds below |
| `agent` | string | yes* | agent id (*omitted only on broadcast metadata) |

Common optional fields: `to`, `from`, `msg`, `corr`, `size`.

### Event kinds

| kind | Description |
|------|-------------|
| `start` | Agent started |
| `stop` | Agent stopped |
| `send` | Outbound message |
| `receive` | Inbound message |
| `broadcast` | Broadcast message |

Validators and metrics **ignore** `trace_header` lines automatically via `filter_simulation_events()`.

## Machine-readable schema

See [`trace-schema.json`](trace-schema.json) for JSON Schema Draft 07 definitions.

## Tools

- `nest inspect <trace.jsonl>` — summary (includes header in event counts)
- `nest report <trace.jsonl>` — HTML metrics
- `nest_core.validators.validate_trace(path, scenario)` — property checks
