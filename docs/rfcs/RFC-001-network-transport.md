# RFC-001: Network Transport Plugin

**Status:** Draft (alpha: `tcp_loopback` plugin shipped 2026-06-25)  
**Date:** 2026-06-25  
**Related:** [ADR-001](../adr/ADR-001-twelve-layer-decomposition.md) · Risk R-004 in enterprise audit

## Problem

The default `in_memory` transport runs all agents in one process with zero network I/O. This cannot test:

- Real latency and jitter
- TCP/gRPC/HTTP framing errors
- Partial network partitions across hosts

## Goals

1. Define a **network transport plugin** interface compatible with existing `Transport` Protocol.
2. Map failure injection (`message_drop`, `byzantine_agents`, `network_partition`) to network semantics.
3. Preserve Tier 1 determinism when seeded (synthetic delay from RNG, not wall clock).

## Non-Goals (v1 implementation)

- Full distributed multi-process runner
- Production TLS/mTLS stack
- Kubernetes deployment

## Proposed Design

### Interface extensions

Existing [`Transport`](../../packages/nest-core/nest_core/layers/transport.py) methods remain. New reference plugin: `tcp_sim` or `grpc_sim`:

| Capability | in_memory (today) | network (proposed) |
|------------|-------------------|---------------------|
| Delivery | Immediate at `ts=now` | `ts=now+delay` from seeded RNG |
| Partition | Logical groups in sim | Drop messages across groups |
| Scale | Single process | Still single process initially; sockets loopback |

### Determinism

- Per-hop delay = `rng.uniform(min_ms, max_ms)` from agent-derived RNG.
- Drop decisions use failure-injection RNG (unchanged).
- **No** `time.time()` in Tier 1 network transport.

### Failure injection mapping

```yaml
failures:
  message_drop: 0.05
  network_partition:
    groups: [["agent-0", "agent-1"], ["agent-2", "agent-3"]]
```

Partition = transport refuses cross-group delivery until healed (scenario-defined).

## Implementation Phases

| Phase | Deliverable |
|-------|-------------|
| 60-day | Loopback TCP transport plugin + scenario example |
| 90-day | Optional multi-process runner (out of scope for this RFC) |

## Open Questions

1. gRPC vs raw TCP vs HTTP/2 for agent messaging?
2. Should trace events include `transport_hop` metadata?
3. How to test network transport in CI without flaky timing?

## References

- [`nest_plugins_reference.transport.in_memory`](../../packages/nest-plugins-reference/nest_plugins_reference/transport/in_memory.py)
- [`Simulator`](../../packages/nest-core/nest_core/sim/simulator.py) failure injection
