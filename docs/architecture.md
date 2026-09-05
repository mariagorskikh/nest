# Architecture

One Python package, three testing modes, one evidence pipeline. The website
dashboard is a separate Next.js application; its catalog does not execute agents.

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
    scenarios/     bundled YAML scenarios (list with nandatown scenarios)
    validators.py  stage checks from the frozen scenario and events
    runner.py      run_lab: engine, redaction, evaluation, bundle

  db.py            the Track's durable truth: SQLite mailbox with leases,
                   fencing tokens, idempotent accept, event log
  coordinator.py   FastAPI app over db.py plus coordinator-side faults
  client.py        participant HTTP client with safe 503 retries
  participants/    buyer.py and seller.py (tier one, scripted) and
                   llm.py (tier two: the model tool-loop harness with
                   MockBrain default, OpenAI-compatible endpoints, and
                   the context_truncation agent-native fault)
  profiles.py      Track profiles (list with nandatown profiles)
  runner.py        run_town: coordinator subprocess, participants by
                   runtime, external command overrides for BYOA,
                   crash restart, evaluation, bundle
  evaluator.py     the Track stage evaluator

  path_profiles.py frozen, fingerprinted synthetic A2A test contracts
  path_runner.py   Path: direct URL/local index fixture, card comparison,
                   protocol call, semantic and duplicate-response checks
  a2a_transport.py bounded native JSON transport: response bytes,
                   identity encoding, redirect and client-ownership policy

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
                   plus the initialization and tool-list probe
  a2a_adapter.py   A2A agent card and JSON-RPC edge: serve, test, and
                   (participants/a2a_bridge.py) bridge a Track role
  campaign.py      precommitted campaigns, distributions, drift canary
  tui.py           the terminal GUI, also served in a browser

  bundle.py        write, load and verify evidence bundles (all three modes)
  receipt.py       signed derived claims, bundle-aware agreement checks,
                   full-coverage/freshness gate for the local proof badge
  report.py        the System Fitness Report renderer
  replay.py        step-through event replay
  visualizer.py    single-file HTML replay with the town map
  skills/          SkillMD parsing, validation, bundled skills
  cli.py           the one command
```

## The evidence pipeline

All three modes end with a bundle directory holding the five
records (profile, run, intents, events, result) plus a manifest of
hashes and a rendered report. The evaluator or validator judges from
the frozen profile and exported events, so `verify` can recompute every hash and
replay the judgment. In the Lab, privacy redaction runs before
evaluation, so the recorded result is reproducible from public records
by construction. Verification compares deterministic evaluation output, not the
evaluation wall-clock timestamp. A different evaluator version is reported
explicitly; stored results are not silently upgraded.

The root commits the five named record files only. Reports, receipts,
attestations, viewer HTML and participant state are side artifacts. A receipt
can be valid with partial coverage; the local TOWN-TESTED view additionally
requires full coverage, a passed verdict, freshness and verified evidence.
Signatures prove key commitment, not the truth of the underlying observations.

## Determinism rules (Lab)

No wall clock and no unseeded randomness inside a run. Time is logical.
The event queue orders by (time, insertion sequence). Iteration is over
lists and sorted views, never bare sets or unsorted dicts, wherever
order reaches the logical trace. Run IDs, generated identities and wall-clock
creation/evaluation metadata can differ between attempts. Determinism means
repeatable logical behavior and evaluation under controlled inputs, not
byte-identical evidence bundles or interchangeable fingerprints.

## Trust boundaries (Track)

The coordinator owns mailbox state and coordination facts. It stores join/session
credentials and identity pins; controller private keys remain in the operator
keystore. Participants own their state directories and journals. Separate local
processes are not a security sandbox for hostile commands or plugins.
Runner observations (crash, restart, exit codes) are posted as events
attributed to the runner. The model tool loop exposes `list_participants`,
`claim_work`, `send_work`, `ack_work` and `finish`; its harness owns joining and
the HTTP session. The MCP server separately wraps the participant HTTP surface.
Run creation and fault plans are admin-only.
A grant's permissions (join, claim, send, ack) are checked at join and
on every mailbox action; a role pinned to a portable identity can join
only through its grant, never with a bare token. Pinned identities and
session permissions live in the database, so both hold across a
coordinator restart. Denials are recorded as intents plus
`grant_permission_denied` (or `grant_required`) events.

Grant time validity is checked at join. Existing sessions are not a general
revocation/continuing-expiry mechanism; a future authority-lifetime change needs
an explicit contract and migration policy. Model-provider credentials and custom
process environment behavior are separate from Town session permissions.

Bundled processes receive only runtime configuration and their test credentials;
hosted-model harnesses also receive the configured model key, URL and standard
proxy variables. Scripted and mock harnesses do not need those credentials.
Explicit custom commands retain their ambient environment and run with the
operator's privileges. On POSIX, the runner signals its process groups before
export; other platforms currently settle only direct children. This is bounded
lifecycle cleanup, not hostile-code isolation.

Bundled harness provenance describes the module Town launched. Operator-supplied
commands, separately joined participants and external A2A participants instead
record their connector kind and an explicitly unrecorded immutable release basis.
Their rerun metadata omits raw commands and endpoint URLs and identifies inputs
the operator must resupply; it must not silently replace them with stock agents.
This metadata is not a secret scanner for arbitrary participant events.

## Path boundary

Path acts as a deterministic requester of an existing A2A agent. A direct URL
or a local JSON fixture supplies the locator; the latter is not an actual NANDA
Index integration. An optional expected AgentCard digest permits a consistency
comparison. Without it that stage is not tested.

The native transport limits response bytes and rejects redirects and nonidentity
encodings. HTTPX phase timeouts are not total wall-clock deadlines. Explicit
remote/LAN endpoints remain supported. The synthetic quote checks do not verify
real payments or establish complete A2A protocol conformance. See the
[testing guide](testing-an-existing-agent.md) and [proposal mapping](convergence.md).

## Extending the town

- New layer plugin: `@register("payments", "yourledger.v1")` on a class
  taking the engine, then name it in a scenario under `layers:`.
- New scenario: a YAML file with agents, roles, faults, seed; run it by
  path, and add a validator under `sim/validators.py` with
  `@validator("your-name")` for stage verdicts.
- New role: `@role("your-role")` on a SimAgent subclass in
  `sim/agents.py`.
- Your own agent on the Track: speak the coordinator HTTP contract
  (`nandatown coordinator`); the examples and exported schemas describe the
  current boundary. The schema exporter covers the listed concepts, not every
  HTTP route or every internal model.
