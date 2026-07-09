# Nanda Town documentation
This folder is the long-form companion to the top-level
[README](../README.md). The README is the elevator pitch; these pages
go deeper.
## Start here
- **[quickstart.md](quickstart.md)** — Install, run a scenario,
  validate the trace. Five minutes, no clone required.
- **[concepts.md](concepts.md)** — The 12 layers, fidelity tiers,
  scenarios, plugins, traces, determinism.
## Build something
- **[writing-a-plugin.md](writing-a-plugin.md)** — End-to-end
  walkthrough: implement a `Payments` plugin, register it, swap it
  into a scenario, compare against the baseline.
- **[writing-a-scenario.md](writing-a-scenario.md)** — Full YAML
  schema with every field annotated, plus failure-injection knobs
  and a worked stress-test example.
## Layer reference
Each page lists the `Protocol` signature, the built-in default, and
where to look for inspiration.
| Layer | Page | Default plugin |
|---|---|---|
| Transport | [transport.md](layers/transport.md) | `in_memory` |
| Communication | [communication.md](layers/communication.md) | `nest_native` |
| Identity | [identity.md](layers/identity.md) | `did_key` |
| Registry | [registry.md](layers/registry.md) | `in_memory` |
| Auth | [auth.md](layers/auth.md) | `jwt` |
| Trust | [trust.md](layers/trust.md) | `score_average` |
| Payments | [payments.md](layers/payments.md) | `prepaid_credits` |
| Coordination | [coordination.md](layers/coordination.md) | `contract_net` |
| Negotiation | [negotiation.md](layers/negotiation.md) | `alternating_offers` |
| Memory | [memory.md](layers/memory.md) | `blackboard` |
| Privacy | [privacy.md](layers/privacy.md) | `noop` |
| Data Facts | [datafacts.md](layers/datafacts.md) | `datafacts_v1` |
## Going further
- **[security-audit.md](security-audit.md)** — Red/blue team security
  posture, findings register (fixed vs open), operator checklist.
- **[distributed.md](distributed.md)** — Parallel and distributed execution,
  HTTP authentication, worker configuration.
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** — Development setup
  (`uv sync`), code style, how to add a *built-in* scenario, CI
  checks.
- **[examples/](../examples/)** — Stub starting points for common
  plugin shapes.
