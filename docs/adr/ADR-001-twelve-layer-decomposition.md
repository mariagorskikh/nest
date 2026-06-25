# ADR-001: Twelve-Layer Protocol Decomposition

**Status:** Accepted  
**Date:** 2026-06-25

## Context

Multi-agent systems combine transport, identity, payments, coordination, and other concerns. Testing a single protocol in isolation misses interaction failures.

## Decision

Decompose the agent stack into **12 layers**, each a Python `Protocol` with swappable plugins:

transport · comms · identity · registry · auth · trust · payments · coordination · negotiation · memory · privacy · datafacts

Scenarios pin one implementation per layer via YAML.

## Alternatives Considered

- Monolithic agent runtime — simpler but cannot isolate the layer under test.
- Microservice per layer — too heavy for a local test rig.

## Consequences

- High composability; plugin authors replace one layer at a time.
- Boundary overlap risk between auth and identity, trust and reputation.

## Risks

Layer taxonomy may not match every real-world stack.

## Rollback

Merge layers in a future major version with deprecation notices.
