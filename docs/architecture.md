# Architecture

One package, two testing modes, one evidence pipeline.

## Module map

```
src/nandatown/
  records.py       shared record types: TestProfile, RunRecord, Intent,
                   TownEvent, AgentMessage, ReleaseRef, EvidenceRecord,
                   StageResult, EvidenceResult, canonical fingerprinting
  schemas.py       exports the shared concepts as JSON Schemas

  layers/          the twelve protocol layers, one module each, plus the
                   plugin registry (register, resolve, plugins)

  sim/             the Lab
    engine.py      seeded discrete event queue, logical clock, layer wiring
    api.py         TownAPI: the only door between an agent and the world
    agents.py      reference role state machines
    scenario.py    ScenarioSpec, YAML loading, bundled scenarios
    scenarios/     six bundled YAML scenarios
    validators.py  per-scenario stage checks computed from events alone
    runner.py      run_lab: engine, redaction, evaluation, bundle

  db.py            the Track's durable truth: SQLite mailbox with leases,
                   fencing tokens, idempotent accept, event log
  coordinator.py   FastAPI app over db.py plus coordinator-side faults
  client.py        participant HTTP client with safe 503 retries
  participants/    buyer.py and seller.py (tier one, scripted) and
                   llm.py (tier two: the model tool-loop harness with
                   MockBrain default, OpenAI-compatible endpoints, and
                   the context_truncation agent-native fault)
  profiles.py      the seven Track profiles (the boring quote)
  runner.py        run_town: coordinator subprocess, participants by
                   runtime, external command overrides for BYOA,
                   crash restart, evaluation, bundle
  evaluator.py     the Track stage evaluator

  onramp.py        OpenAPI to reviewable SkillMD candidate: snapshot,
                   exact release fingerprint, structural checks as
                   evidence records, pinned services catalog
  pulse.py         Town Pulse: scheduled probes, SQLite history,
                   availability report, operational-history records
  new.py           scaffolding templates (scenario, plugin, skill, agent)
  board.py         the local leaderboard over evidence bundles
  protocols.py     PR import from the upstream repo: snapshot at the
                   head sha, classification, checks, catalog
  sim/upstream.py  adapter for upstream scenario files: role maps per
                   task type, layer substitution, tick durations, rate
                   faults, every adaptation disclosed
  identity_portable.py  Ed25519 controller keys, the town registry,
                   run grants, pluggable resolvers (file, eth_call)
  compare.py       baseline versus swapped-layer runs, side by side
  mirror.py        content-addressed mirroring and walk-away recovery
  mcp_adapter.py   MCP stdio server over the participant tool surface,
                   plus the conformance probe
  a2a_adapter.py   A2A agent card and JSON-RPC edge: serve, test, and
                   (participants/a2a_bridge.py) bridge a Track role
  campaign.py      precommitted campaigns, distributions, drift canary
  tui.py           the terminal GUI, also served in a browser

  bundle.py        write, load, verify evidence bundles (both modes)
  report.py        the System Fitness Report renderer
  replay.py        step-through event replay
  visualizer.py    single-file HTML replay with the town map
  campaign.py      precommitted multi-trial campaigns with distributions
  skills/          SkillMD parsing, validation, bundled skills
  cli.py           the one command
```

## The evidence pipeline

Both modes end the same way: a bundle directory holding the five
records (profile, run, intents, events, result) plus a manifest of
hashes and a rendered report. The evaluator or validator judges from
the exported events alone, so `verify` can recompute every hash and
replay the judgment. In the Lab, privacy redaction runs before
evaluation, so the recorded result is reproducible from public records
by construction.

## Determinism rules (Lab)

No wall clock and no unseeded randomness inside a run. Time is logical.
The event queue orders by (time, insertion sequence). Iteration is over
lists and sorted views, never bare sets or unsorted dicts, wherever
order reaches the trace. The only nondeterministic value in a Lab
bundle is the run id.

## Trust boundaries (Track)

The coordinator owns coordination facts and never holds participant
credentials. Participants own their own state directories and journals.
Runner observations (crash, restart, exit codes) are posted as events
attributed to the runner. Model-facing tools are join, discover,
notify, claim, send, ack, inspect; run creation and fault plans are
admin-only.
A grant's permissions (join, claim, send, ack) are checked at join and
on every mailbox action; a role pinned to a portable identity can join
only through its grant, never with a bare token. Pinned identities and
session permissions live in the database, so both hold across a
coordinator restart. Denials are recorded as intents plus
`grant_permission_denied` (or `grant_required`) events.

## Extending the town

- New layer plugin: `@register("payments", "yourledger.v1")` on a class
  taking the engine, then name it in a scenario under `layers:`.
- New scenario: a YAML file with agents, roles, faults, seed; run it by
  path, and add a validator under `sim/validators.py` with
  `@validator("your-name")` for stage verdicts.
- New role: `@role("your-role")` on a SimAgent subclass in
  `sim/agents.py`.
- Your own agent on the Track: speak the coordinator HTTP contract
  (`nandatown coordinator`); the schemas under `schemas/` define every
  shared record.
