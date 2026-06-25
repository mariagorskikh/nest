# ADR-003: JSONL Traces with Schema Version Header

**Status:** Accepted  
**Date:** 2026-06-25

## Context

Simulation output must be grep-able, diff-able, and validator-friendly. No formal contract existed before schema 1.0.

## Decision

- Traces are **JSON Lines** (one object per line).
- **Line 1** is always a `trace_header` with `schema_version` (currently `"1.0"`).
- Validators and metrics filter header via `filter_simulation_events()`.

See [trace-schema.md](../trace-schema.md) and [trace-schema.json](../trace-schema.json).

## Alternatives Considered

- SQLite — queryable but not diff-friendly.
- OpenTelemetry — production-oriented; overkill for local sim.
- Protobuf — not human-readable.

## Consequences

- Human-readable audit trail; large files at 10K agents.
- Traces before 1.0 are not byte-identical to 1.0+ (header prepended).

## Risks

Schema drift without version bumps.

## Rollback

Make header optional behind a scenario flag (not recommended).
