# ADR-004: Seeded Determinism for Tier 1

**Status:** Accepted  
**Date:** 2026-06-25

## Context

Protocol regression testing requires reproducible runs. Tier 2 LLM agents are intentionally non-deterministic.

## Decision

- **Tier 1** (`StateMachineAgent`): master `seed` derives per-agent RNG and failure-injection RNG.
- Same seed → byte-identical trace (including `trace_header` from schema 1.0).
- Default `in_memory` transport is zero-latency; logical time stays at 0.0 unless `ctx.schedule()` or a delay transport is used.

## Alternatives Considered

- Wall-clock simulation — realistic latency but non-reproducible.
- Record-replay — heavier infrastructure.

## Consequences

- Excellent regression signal; latency metrics meaningless with default transport.

## Risks

Users may misread `duration: 0.0` as broken simulation.

## Rollback

Optional wall-clock mode per scenario (future).
