# nandatown

A test track for the Internet of AI agents, running on your laptop.

> **August 2026 rebuild.** The town was rebuilt around the team's converged design (the identity statement, Run Zero, and the path proposal). The previous codebase is preserved untouched on the [`archive/legacy`](https://github.com/projnanda/nandatown/tree/archive/legacy) branch and frozen at the tag `v1-final`. Open pull requests written against it now target `archive/legacy`, where their diffs still apply exactly as authored. To pull a legacy contribution into the new town and test it against the reference agents, use `nandatown import-pr <number>`. Nothing was deleted.

Bring an agent. Give it a task. Break something on purpose. Leave with evidence of what actually happened. Agent, task, failure, evidence.

Most AI evaluation asks how capable one model is on one task. The harder question is what happens when populations of agents must discover one another, establish trust, exchange value, negotiate, and coordinate under imperfect conditions. That question is what this town measures. Every report answers it stage by stage: did agents discover the right collaborators, did the marketplace reach a valid outcome, did every vote get counted, did the trust mechanism withstand manipulation, and did the network keep functioning when conditions changed.

This is a testing tool first and a simulator second: a local-first sandbox and test harness for NANDA protocols, services, and agent-to-agent workflows. Two ways to test, twelve replaceable protocol layers, deterministic replayable traces, an LLM-powered mode for emergent behavior, protocol comparison, campaigns for statistical evidence, portable identity, signed attestations, and evidence bundles anyone can verify. A full run takes seconds and costs nothing.

The framing comes from Ramesh Raskar's NandaTown introduction and the paper "Towards Sandboxes for the Internet of Agents" (papers.ssrn.com/sol3/papers.cfm?abstract_id=5801322): agent evaluation must move from isolated task competence to system fitness. This build makes that loop executable end to end: define a population, select a scenario, swap a protocol component, inject a failure, run, inspect every interaction, and compare the outcome against properties that should remain true.

![Architecture of nandatown: a CLI, TUI, and browser front door; the Lab, a seeded simulation over twelve replaceable protocol layers; the Track, a FastAPI coordinator over SQLite with subprocess participants; and one evidence pipeline that both modes write to](images/Flow.png)

*How the town is built: one front door, two ways to test, one evidence pipeline.*

![Sequence diagram of the quote-crash-restart profile: the buyer posts a quote request, the seller claims it under fence 1 and crashes, the runner restarts it, the seller reclaims under fence 2, any ack with the stale fence is rejected, and the buyer verifies the 3990-cent total](images/Test_track.png)

*The default Track run, `quote-crash-restart`: the task is trivial on purpose; custody, recovery, and fence rejection are what get judged.*


## Install

From the repository root, in a virtual environment:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Python 3.11 or newer. The venv step matters on macOS and modern
Linux: Homebrew and distro Pythons are externally managed (PEP 668)
and refuse bare pip installs. `pipx install .` works too if you prefer
pipx-managed CLIs.

## The front door

```
nandatown
```

Bare `nandatown` opens the interactive town: a full-screen terminal
GUI with six tabs. Town (the journey and one-click proofs, including
breaking the auth layer on purpose), Run (pick any scenario or
profile, connect a harness per role, watch the stage table fill),
Agents (test your own agent and read the N-of-M stages line),
Protocols (import a PR from the upstream repo), Services (onboard an
OpenAPI document), and Evidence (browse, report, verify, visualize
every bundle). Everything the GUI does is also a plain command, so
anything you click is scriptable.

## One command

```
nandatown run
```

That runs the default Track profile: the boring quote. A buyer asks a seller for 2 widgets at 1995 cents. The seller crashes after claiming the work. The town fences the dead attempt, redelivers, the restarted seller answers, and the buyer checks the total is 3990 cents. The task is not the demo. Custody, recovery, stale-attempt rejection, correlation, and correctness are the demo.

```
nandatown run marketplace
```

That runs a Lab scenario instead: two sellers and a buyer discover each other through the town index, haggle to a price, settle through escrow, survive a duplicated delivery, build reputation from signed receipts, and reuse a remembered counterparty in round two. Deterministic, seeded, replayable.

## The two ways to test

**The Lab** is repeatable: scripted, mechanical participants in a seeded discrete event simulation. Same scenario and seed, same trace, every time. Faults are declared in the scenario and injected by the transport layer. Fast enough for CI and for campaigns of many trials.

**The Track** is realistic: isolated participant subprocesses talking to a durable coordinator over real HTTP, with leases, fencing tokens, at-least-once delivery, and real process crashes and restarts. It is where a bring-your-own agent plugs in.

Both produce the same evidence bundle, so report, verify, replay, visualize, and campaign work identically on either.

## The twelve layers

Everything in the town runs on twelve replaceable protocol layers. Each has a working default plugin, and a scenario can swap any of them.

| Layer | Default | What it does |
|---|---|---|
| transport | memory.v1 | delivers envelopes, injects drop, duplicate, delay, and rate faults |
| communication | envelope.v1 | message envelopes, conversation ids, correlation |
| identity | keys.v1 | per-agent keys and AgentFacts-style cards |
| registry | index.v1 | the town's internal index: publish cards, look up capabilities |
| auth (authorization) | hmac.v1 | signs and verifies messages and cards; forged senders fail |
| trust | reputation.v1 | receipt-driven reputation with a public formula |
| payments | ledger.v1 | balances, transfers, escrow; money is conserved |
| coordination | contractnet.v1 | announce, bid, award, with late bids rejected |
| negotiation | haggle.v1 | alternating offers to an auditable agreed price |
| memory | kv.v1 | durable per-agent memory |
| privacy | redact.v1 | declared fields never leave the run |
| data_facts | evidence.v1 | signed one-observer, one-subject, one-time records |

```
nandatown layers
```

Register your own plugin with `@register("payments", "yourledger.v1")` and name it in a scenario under `layers:`, swap one in for a single run with `--layer`, or put two rule sets head to head:

```
nandatown compare capability_spoofing --swap auth=plain.v1
```

Same agents, same scenario, same seed; only the rules differ. The comparison report shows the stage verdicts side by side and names exactly what the swap changed, each column backed by its own verifiable bundle. A researcher tests a new reputation algorithm without rebuilding the marketplace; a standards group compares competing protocols through repeatable experiments.

## Upstream scenarios run here

Scenario files from the projnanda/nandatown repository (agent populations declared as roles with counts, tick durations, rate-based failures) are detected and adapted automatically: roles map onto the reference agents per task type, upstream layer plugins substitute to local defaults, and every substitution is disclosed in the report as an adaptation. `nandatown import-pr N` then `nandatown run <imported scenario>` just works, judged by the generic adapted validator: population active, discovery worked, messages flowed, the task completed, money conserved.

## Lab scenarios

```
nandatown scenarios
nandatown run auction --seed 7
```

| Scenario | What it proves |
|---|---|
| marketplace | discovery, negotiation, escrow settlement, duplicate recognition, reputation, memory reuse |
| auction | sealed signed bids, highest bid wins, late bid rejected, exactly one payment |
| voting | one agent one vote, double ballot rejected, tally matches, result broadcast |
| consensus | quorum commit under dropped acknowledgements, retries recover the missing acceptors |
| supply_chain | contract-net bidding, milestone escrow per part, assembly ordering, delayed delivery survived |
| capability_spoofing | a forged capability card is unverified, contained, and gets no business |
| capability_spoofing_weak_auth | the same scenario with auth swapped for plain.v1: the run FAILS on purpose, showing what the auth layer is for |

Every scenario also gets two standing checks: the ledger conserved money across every movement, and no redacted field leaked into the exported records.

A scenario is a short YAML file: agents and roles, the plugin per layer, the faults, the seed. Point `nandatown run path/to/your.yaml` at your own; `plugin_files:` in the YAML loads your own plugin and validator modules first.

## Track profiles

```
nandatown profiles
```

| Profile | What breaks | What must hold |
|---|---|---|
| quote-clean | nothing | the calibration baseline |
| quote-crash-restart | the seller stops after claiming | the stale attempt is fenced, the town redelivers, the task applies once |
| quote-drop-wakeup | the wake-up hint is lost | the durable inbox still delivers |
| quote-duplicate-delivery | the same work is offered twice | the seller recognizes work it already handled |
| quote-lost-ack | the first acknowledgement is lost | the retry is safe, nothing applies twice |
| quote-llm | nothing (tier two baseline) | model-driven participants complete the task through the tool loop |
| quote-llm-truncation | the agents' context is truncated mid-run | the protocol carries the recovery: rediscover, resend the same identity, reclaim |
| quote-llm-tool-error | a tool result is lost mid-call | the agent notices the error, retries the tool, and the claimed work survives its lease |

Delivery semantics, in one paragraph: the coordinator's database is the source of operational truth. Accepted work and the intent to notify are recorded in one transaction. Delivery is at least once, under leases with fencing tokens; an expired fence can never acknowledge. Duplicate delivery is possible by design, and each participant keeps a durable journal so effects apply once. Retrying the same message identity with identical content returns the original acceptance; the same identity with different content is rejected. Notifications are wake-up hints, never the only copy of the work.

## Evidence, not claims

Every run writes one bundle directory with five records: `profile.json` (the recipe), `run.json` (the attempt), `intents.jsonl` (the requested actions), `events.jsonl` (the attributed facts), `result.json` (the evaluator's stage verdicts), plus `manifest.json` with a hash of every record. `report.md` is a readable view, not a sixth record.

```
nandatown report runs/<id>
nandatown verify runs/<id>
nandatown replay runs/<id> --kind escrow_released
nandatown visualize runs/<id>
```

`verify` recomputes every hash and replays the pinned evaluator over the recorded events; edits to the result or the events are caught. `visualize` writes a single HTML file: agents on a town map, messages animating along the timeline, the event log, and the stage table.

Stages are separate claims with separate failure boundaries. An HTTP success is never proof an agent understood or completed a task. Missing evidence stays missing. Every event names its observer, and the town cannot synthesize a participant's assertions.

## Tier two: real model participants

The scripted participants are tier one. Tier two runs the same task
through a model tool loop:

```
nandatown run quote-llm
nandatown run quote-llm-truncation
nandatown run quote-llm --model qwen2.5
```

The harness is always infrastructure: it owns the town client, the
durable journal, the claim fence, and a small tool surface (find peers,
claim, send, acknowledge, finish). The brain only emits tool calls. By
default the brain is `mock:v1`, a deterministic policy that needs no
inference, so tier two runs free and in CI. Pass `--model` to use any
OpenAI-compatible endpoint; the default endpoint is a local Ollama
(`TOWN_MODEL_URL` overrides it, `TOWN_MODEL_KEY` adds a bearer token).
A hosted model is recorded in the run as an observed mutable
dependency, because it can change underneath a pinned release.

`quote-llm-truncation` is the first agent-native fault: past a message
budget the harness drops the middle of the conversation, exactly what a
real agent meets when its context compacts mid-task. The system prompt
survives; everything else must be recoverable through the protocol.
The agents report their truncation count in their acknowledgement
notes, so surviving the fault is an attributed assertion in the
evidence.

## Connect any harness

Every Track role runs behind a harness connector, so any agent runtime
plugs into a run:

```
nandatown run quote-clean --agent seller=cmd:"python my_agent.py"
nandatown run quote-clean --agent seller=llm:qwen2.5 --agent buyer=scripted
nandatown run quote-clean --agent seller=a2a:http://host:8940
nandatown run quote-clean --agent buyer=external
```

`scripted` is the stock reference agent, `llm` and `llm:MODEL` the
model tool loop, `cmd:COMMAND` your own process in any language,
`a2a:URL` bridges the role to an external Agent2Agent endpoint, and
`external` hands out join credentials so an agent anywhere can connect.

## The MCP and A2A edges

HTTP is canonical; MCP and A2A are adapters, not competing protocols.

```
nandatown mcp serve --url http://127.0.0.1:8477 --run <run> --name seller --token <t>
nandatown mcp test --cmd "python their_mcp_server.py"
nandatown a2a serve --port 8940
nandatown a2a test http://host:8940
```

`mcp serve` is a real Model Context Protocol server over stdio whose
tools are exactly the participant surface, so Claude or any MCP host
literally plays a role in the town. `mcp test` runs the client side of
the handshake against any external MCP server and reports conformance.
`a2a serve` exposes the reference seller as an Agent2Agent agent with
an agent card and message/send; `a2a test` validates any A2A endpoint
with a card check and a round trip.

## Portable identity and signed attestations

```
nandatown identity new my-agent
nandatown run quote-clean --identity
```

A long-lived Ed25519 controller key lives in the keystore and never
enters a participant's environment. A Run Grant, signed by the
controller, authorizes one disposable session key for one run with
named permissions; the coordinator verifies the chain against the
controller key pinned at run creation, and the report's
portable_identity stage turns Passed with the verifying events as
evidence. The join itself and every claim, send, and acknowledgement
are checked against the grant's permissions, and a role pinned to an
identity cannot sidestep them with a bare token; a refused action is
recorded as an intent plus a `grant_permission_denied` event, so a
bundle can show an agent attempting something it was not authorized
to do. Identity resolvers are pluggable: the file registry is the
town's testnet registry, and an eth_call resolver reads a chain
registry whose contract and selector are configuration.

Every bundle also carries an attestation: the operator's key signs the
bundle fingerprint and verdict, so each run is a signed, replayable
attestation with provenance. `verify` checks the signature along with
every hash and the evaluator replay.

## Walk-away recovery

```
nandatown mirror runs/<id> /backup/mirror-a
nandatown recover sha256:<fingerprint> --mirror /backup/mirror-a --mirror /backup/mirror-b
```

Bundles are content addressed by fingerprint. Lose the original, lose
all but one mirror, and the run still restores and verifies byte for
byte.

## Test protocols from the upstream repo

```
nandatown import-pr 220
nandatown protocols
nandatown run marketplace --plugin protocols/<dir>/plugin.py --layer trust=their.v2
```

`import-pr` pulls a contribution from projnanda/nandatown (or any
`--repo`): the changed files at the exact head commit, fingerprinted,
classified (plugin with its detected layer, scenario, skill, test),
checked (including the secret scan), and cataloged as
imported-untrusted. Importing never runs the code. When you choose to,
`--plugin` loads the contributed module and `--layer` swaps it into a
scenario, so the contribution runs against the town's reference agents
and comes back with a stage report.

## Test the path, not just the protocol

Every component can look healthy in isolation while the composition
fails. The path test answers the question that matters: can this exact
agent complete this exact NANDA journey, and if not, which boundary
broke first?

```
nandatown test-agent --url http://127.0.0.1:9999
nandatown test-agent --index my-index.json --agent-name maya-seller --pin-card-digest sha256:...
```

Your agent is already running; you migrate nothing and supply no model
key. Town acts as a deterministic counterpart and observer, walking an
exact versioned profile (`a2a-capability-fulfillment@0.1`): resolve
the subject, fetch and digest the agent card, check it against the
pinned descriptor, make a native protocol exchange, check the semantic
result (a two-widget order with a run nonce, exactly one terminal
fulfillment), then apply the controlled condition: the same logical
order delivered twice, where the invariant is no second distinct
fulfillment. The report names the first broken stage with expected and
observed digests, and every result carries a rerun command. Five
statuses keep it honest: PASS, FAIL, NOT TESTED, INCONCLUSIVE, and
ERROR, where ERROR means Town itself malfunctioned and is never blamed
on your agent. Try the failure modes against the reference seller:
`nandatown a2a serve --defect wrong_total` (or `duplicate_fulfillment`
or `card_drift`).

## Receipts and Town Proof

```
nandatown receipt runs/<id>
nandatown verify-receipt runs/<id>/receipt.json --bundle runs/<id>
nandatown proof runs/<id> --freshness-days 30
```

Private artifacts stay in the bundle. A receipt is the sanitized
signed derivative that can cross organizational boundaries: the exact
claim, digests, observer, time window, coverage, and limitations. The
signature proves a named key committed to those bytes, not that the
observation was true or the agent safe. `proof` renders the
TOWN-TESTED badge sentence only from conclusive, covered, fresh,
verified evidence, and otherwise says exactly why not: the badge is
narrow and expiring, a policy view over evidence, never the evidence
itself. See docs/convergence.md for the full mapping to the path
proposal.

## Test a town-joining agent

```
nandatown test-agent --role seller --cmd "python examples/byoa_seller.py"
nandatown test-agent --role seller --wait
```

Your agent plays one role; the town supplies the counterpart, the
fault, the evaluator, and the report, ending with the line that
matters: how many town stages your agent passed. `--cmd` starts your
agent as a subprocess with TOWN_URL, RUN_ID, NAME, TOKEN in its
environment; `--wait` prints those credentials and waits while you
start it anywhere else. `examples/byoa_seller.py` is a complete
reference agent in plain standard-library Python: no nandatown import,
no dependency, just the HTTP contract. Under `--identity` a pinned role is
handed `TOWN_GRANT` instead of `TOKEN` and must join with an Ed25519
session proof (`TownClient.join_with_grant`); the runner stops early,
with a `harness_refused_grant` event, if an agent tries the bare token
instead. The standard-library example is for token runs.

## Onboard a service

```
nandatown onramp path/to/openapi.json
nandatown services
nandatown services paylite
```

The On-Ramp turns a provider's LOCAL OpenAPI document into a
reviewable candidate: a generated SKILL.md with every operation and its
declared side effect, the open questions a reviewer must resolve, an
exact release fingerprint over the snapshot, and structural checks
recorded as evidence (parsed, operations found, https-only servers,
auth declared, embedded-secret scan). Nothing is fetched from the
network and nothing in the document is ever executed. The candidate is
published to a pinned catalog as community-generated, unclaimed, and
not provider-endorsed: the SKILL.md is a claim, not a fact, and town
tests plus provider authorization stay separate evidence.

## Watch services over time

```
nandatown pulse --target paylite=https://api.example.com/health --count 10 --interval 60
nandatown pulse --report --db pulse.db
nandatown pulse --records --db pulse.db
```

A sandbox test at onboarding is one moment and cannot show next week.
Pulse probes each target on a schedule, keeps the full history in
SQLite, reports availability per service, and exports every probe as an
operational-history evidence record.

## Campaigns

One run resolving to one verdict certifies luck. A campaign precommits its plan before the first trial and reports the whole distribution:

```
nandatown campaign marketplace --trials 20
nandatown campaign quote-lost-ack --trials 5
```

Every pass, failure, incomplete, and error stays in the record. The unit of evidence is the distribution.

## Skills

```
nandatown skills
nandatown skills town-protocol
nandatown skills --validate my-skill.md
```

A SkillMD is a short Markdown file with YAML frontmatter that any agent can read and follow. The bundled skills document the shared town protocol and each reference role.

## Contribute a piece

```
nandatown new scenario my-town
nandatown new plugin trust mytrust.v1
nandatown new skill my.skill
nandatown new agent my-agent
nandatown board runs
```

A contribution usually carries a protocol (the rules), a plugin (the
code that runs those rules inside one layer), and a test that proves it
holds up. `new` starts each piece from a working template; `board` is
the local leaderboard over your evidence bundles, ranked by pass rate,
every line backed by a verifiable bundle.

## The raw HTTP contract

The stock participants are just clients of a small HTTP contract. Anything that speaks it can take their place:

```
nandatown coordinator --port 8477
```

| Method and path | Who | What it does |
|---|---|---|
| `POST /runs` | admin | create a run from a profile; returns join tokens |
| `POST /runs/{run}/join` | agent | enter the run; returns a session and the task |
| `GET /runs/{run}/participants` | agent | find peers and their capabilities |
| `POST /runs/{run}/messages` | agent | send work; idempotent by message identity |
| `GET /runs/{run}/inbox/notify` | agent | long-poll for a wake-up hint |
| `POST /runs/{run}/inbox/claim` | agent | claim one piece of work under a lease |
| `POST /runs/{run}/inbox/ack` | agent | acknowledge: received, processed, rejected, retryable, failed |
| `GET /runs/{run}/events` | admin | export the attributed event log |
| `GET /runs/{run}/intents` | admin | export the requested actions |
| `POST /runs/{run}/finish` | admin | close the run |

Agent routes take `X-Town-Session` from join; admin routes take `X-Town-Admin`. Run creation and fault plans are never agent tools. The shared concepts (run plan, agent message, town event, release reference, evidence record) ship as JSON Schemas under `schemas/`, regenerated with `nandatown schemas`. Python is the first implementation, not the protocol.

## What a run does not prove

One run is one scoped observation. It does not prove general reliability, provider endorsement, exactly-once external side effects, independent judgment, or any universal score. Reliability claims need precommitted campaigns and independent observers. Later conclusions can reference the evidence; they never rewrite it.

## Where this is heading

Built here: the Lab and the Track with scripted, model-driven, command, MCP, and A2A harnesses; two agent-native faults (context truncation and lost tool results) beside the transport faults; portable identity with run grants and pluggable resolvers; signed attestations with provenance on every bundle; upstream scenario compatibility; protocol comparison; walk-away mirroring; the On-Ramp, Town Pulse, campaigns with a model-drift canary, and operator mode (docs/operators.md, service units in deploy/). The wider research vision this feeds, per the sandboxes paper: a network of interoperable, domain-specialized sandboxes whose attestations make trust measurable rather than claimed. What a shared public deployment of this code needs next is operational, not technical: named owners, funding, and stewardship.

## Development

```
pip install -e ".[dev]"
pytest
```

See `docs/architecture.md` for the module map. Apache 2.0. Part of the NANDA Town effort under Project NANDA.
