# nandatown

A test track for the Internet of AI agents, running on your laptop.

> **Current code and history.** This README describes the rebuilt `main` branch. The previous codebase is preserved at [`archive/legacy`](https://github.com/projnanda/nandatown/tree/archive/legacy) and the frozen tag [`v1-final`](https://github.com/projnanda/nandatown/tree/v1-final). A legacy PR's merge status does not establish that its original code runs here. `nandatown import-pr <number>` imports a bounded, untrusted snapshot for review; executing it is a separate action.

Bring an agent. Give it a task. Break something on purpose. Leave with evidence of what actually happened. Agent, task, failure, evidence.

Most AI evaluation asks how capable one model is on one task. Town also explores what happens when agents must discover one another, establish trust, exchange value, negotiate, and coordinate under imperfect conditions. Each report answers only the questions exercised by its selected scenario or profile: marketplace settlement, voting, trust, network faults, or a small single-agent exchange. A passing quote test is not evidence about all of those systems.

Town is a local test harness with three modes: simulated populations in the Lab, HTTP mailbox participants on the Track, and an existing A2A endpoint on the Path. It produces stage results and portable evidence. Built-in scripted and mock-model runs take seconds and need no model account. External agents and explicitly configured model endpoints may have their own costs.

The framing comes from Ramesh Raskar's NandaTown introduction and the paper "Towards Sandboxes for the Internet of Agents" (papers.ssrn.com/sol3/papers.cfm?abstract_id=5801322): agent evaluation must move from isolated task competence to system fitness. In the Lab, this build makes a bounded simulation of that loop executable: define a population, select a scenario, swap a protocol component, inject a failure, run, inspect the recorded interactions, and compare the outcome against properties that should remain true.

![Architecture of nandatown: a CLI, TUI, and browser front door; the Lab, a seeded simulation over twelve replaceable protocol layers; the Track, a FastAPI coordinator over SQLite with subprocess participants; and one evidence pipeline that both modes write to](images/Flow.png)

*Lab and Track overview. The Path mode also writes to the shared evidence pipeline; see the current [architecture map](docs/architecture.md).*

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

Start with the [existing-agent testing guide](docs/testing-an-existing-agent.md)
for A2A endpoints, OpenClaw or another runtime, and a reproducible handoff.

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

For a browser kiosk, use `nandatown ui --web --kiosk`. It disables visitor commands
and server-path reads and defaults model runs to the local mock. Hosted-model
access requires an explicit operator opt-in; see [kiosk controls](docs/operators.md#browser-kiosk)
before exposing it to visitors.

## One command

```
nandatown run
```

That runs the default Track profile: the boring quote. A buyer asks a seller for 2 widgets at 1995 cents. The seller crashes after claiming the work. The town fences the dead attempt, redelivers, the restarted seller answers, and the buyer checks the total is 3990 cents. The task is not the demo. Custody, recovery, stale-attempt rejection, correlation, and correctness are the demo.

```
nandatown run marketplace
```

That runs a Lab scenario instead: two sellers and a buyer discover each other through the town index, haggle to a price, settle through escrow, survive a duplicated delivery, build reputation from signed receipts, and reuse a remembered counterparty in round two. Deterministic, seeded, replayable.

## The three ways to test

**The Lab** uses scripted participants in a seeded discrete event simulation. The same inputs reproduce the logical interactions and evaluation. Run IDs, key material, and wall-clock metadata can differ, so bundles are not byte-identical. Faults are declared in the scenario and injected by the selected layers.

**The Track** runs separate participant processes against a SQLite-backed coordinator over real HTTP, with leases, fencing tokens, at-least-once delivery, and process crashes and restarts. Custom commands and plugins execute with the user's operating-system privileges: separate processes and state directories are not a sandbox for hostile code.

**The Path** calls an already-running A2A endpoint, checks a versioned synthetic quote contract, and repeats the logical request to test its observed response. Town does not need the agent's model credentials. Direct URLs and a local JSON index fixture are supported; the fixture is not an integration with a deployed NANDA Index.

All three produce bundles for `report`, `verify`, `replay`, and `visualize`.
Campaigns currently target Lab scenarios and Track profiles.

## The twelve layers

The Lab has twelve replaceable protocol layers. Track uses the mailbox contract and Path uses its A2A driver; neither automatically inherits Lab plugins.

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

Legacy scenario files (agent populations declared as roles with counts, tick durations, rate-based failures) are detected and adapted automatically. `nandatown import-pr N` then `nandatown run <imported scenario>` runs a local reference flow: roles map onto Town's reference agents and upstream layer plugins are replaced by local defaults. The generic checks cover population activity, discovery, message flow, a completion fact, and money conservation.

**A passing adapted run is not a pass for the original contribution.** The report and exported result include `original_scenario: not_tested`; the verdict applies only to the adapted reference flow. Original agent configuration, plugin code and validators are not executed. Duration becomes bounded local logical time, not a reproduction of legacy event-count ticks. `message_drop` maps to seeded drops, capped at 0.2 with the cap disclosed. Every other declared failure key, including `network_partition` and `byzantine_agents`, is explicitly reported as not modeled, even when its value is zero or disabled. These notes travel in `profile.json` and the human report; unsupported payload values are not copied into the notes. Testing streaming-payment or gossip-partition invariants requires a scenario and implementation that actually exercise those semantics.

The current Lab evaluator is `lab-0.2.6`. Marketplace settlement checks bind exactly two configured-buyer negotiations to their purchase orders and escrow records by negotiation ID, seller, subject, order ID, quantity, unit price, exact total, ledger parties, run, causal order and unique event IDs. Marketplace reputation checks match each score update to a prior receipt event from the same observer, about the same subject and outcome, and replay the reference +1/-1 arithmetic. Missing records mean insufficient evidence; conflicting attribution, malformed records, repeated IDs or incorrect arithmetic fail. These checks validate correlated Lab records, not external settlement, claim truth, reporter authority or receipt signatures. A bad outcome can reduce a still-positive total. Other scoring algorithms need their own declared evaluator.

Older Lab bundles retain their recorded results, but verification reports an evaluator-version mismatch rather than replaying them as if the checks were unchanged.

## Lab scenarios

```
nandatown scenarios
nandatown run auction --seed 7
```

| Scenario | What it checks |
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

`verify` checks the five canonical records, their hashes and cross-record bindings,
then replays evaluation over the recorded events with a matching local evaluator.
This verifies integrity and reproducible judgment; it does not independently
establish that an observer's account of the outside world was true. `report.md`,
receipts, attestations, viewer HTML and `state/` are not members of the five-record
root. Existing attestations receive their own signature and claim checks.
`visualize` writes a self-contained HTML view of a Lab, Track or Path bundle.

Path evaluators are versioned. Replay a `path-0.1` bundle with its matching
`path-0.1` evaluator; a newer evaluator reports the version difference rather
than treating the bundle as corrupt. The bundle's existing signature remains
valid for its recorded bytes.

Stages are separate claims with separate failure boundaries. An HTTP success is never proof an agent understood or completed a task. Missing evidence stays missing. Every event names its observer; attribution in a local trace is not independent authentication of every asserted fact.

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
`external` hands out join credentials for an agent that can reach the coordinator.
The automatic local runner binds to loopback; an agent on another machine needs
a tunnel or a separately operated reachable coordinator. A remote A2A endpoint
can be tested directly without moving the agent onto the Town machine.

For command, externally joined, and A2A Track participants, the run records the
connector kind and explicitly says an immutable external release was not recorded.
It does not credit them to the bundled buyer or seller. Command text and A2A
connector URLs are omitted from rerun metadata; supply those inputs again and
record the agent/adapter versions separately. The printed recipe names missing
inputs rather than silently substituting reference agents.

## The MCP and A2A edges

HTTP is Track's canonical participant boundary. MCP adapts that surface;
A2A is used by a Track bridge and directly by Path.

```
nandatown mcp serve --url http://127.0.0.1:8477 --run <run> --name seller --token <t>
nandatown mcp test --cmd "python their_mcp_server.py"
nandatown a2a serve --port 8940
nandatown a2a test http://host:8940
```

`mcp serve` is a real Model Context Protocol server over stdio whose
tools are exactly the participant surface, so Claude or any MCP host
can use those tools to play a role in the town. `mcp test` probes initialization
and tool listing on an external MCP server; it does not run an upstream MCP
conformance suite or exercise every tool.
`a2a serve` exposes the reference seller as an Agent2Agent agent with
an agent card and message/send; `a2a test` probes selected card fields
and one round trip. It is not a full A2A conformance test.

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

Normal run commands also write an attestation: the operator's key signs the
bundle fingerprint and verdict, so each run is a signed, replayable
attestation with provenance. `verify` checks the signature along with
every hash and the evaluator replay. Unsigned bundles can still be verified;
signatures establish a key's commitment, not independent observation.

## Walk-away recovery

```
nandatown mirror runs/<id> /backup/mirror-a
nandatown recover sha256:<fingerprint> --mirror /backup/mirror-a --mirror /backup/mirror-b
```

Bundles are addressed by the fingerprint of their five records. Recovery checks
the surviving copy before using it and refuses to overwrite an existing destination.
Mirroring copies the five records, manifest, and any verified receipt or
attestation; it regenerates `report.md` from verified records. Private `state/`
and generated `town.html` are not copied. Other unexpected members are refused;
keep unrelated attachments outside the bundle. Regenerate a viewer after recovery.
These helpers require successful bundle verification. Historical bundles with an
evaluator-version mismatch need the matching evaluator checkout first.

## Test protocols from the upstream repo

```
nandatown import-pr 220
nandatown protocols
nandatown run marketplace --plugin protocols/<dir>/plugin.py --layer trust=their.v2
```

`import-pr` reads a contribution from projnanda/nandatown (or another
`--repo`): up to 50 changed files, each at the observed head commit and limited
to 200,000 declared bytes. Deleted, oversized, non-text or unreadable files and
files beyond the cap are disclosed as skipped; a partial snapshot's file check
is inconclusive. The retained text is fingerprinted,
classified (plugin with its detected layer, scenario, skill, test),
checked (including the secret scan), and cataloged as
imported-untrusted. Importing never runs the code. When you choose to,
`--plugin` loads the contributed module and `--layer` swaps it into a
scenario, so the contribution runs against the town's reference agents
and comes back with a stage report.

## Test the path, not just the protocol

Every component can look healthy in isolation while the composition
fails. The path test asks: can this selected endpoint complete this declared
synthetic A2A journey, and if not, which boundary
broke first?

```
nandatown test-agent --url http://127.0.0.1:9999
nandatown test-agent --index my-index.json --agent-name maya-seller --pin-card-digest sha256:...
```

Your agent is already running; you migrate nothing and supply no model
key. Town acts as a deterministic counterpart and observer, walking an
exact versioned profile (`a2a-capability-fulfillment@0.3`): resolve
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

The default Path profile pins a **1,048,576-byte (1 MiB) response budget**
for both AgentCard and JSON-RPC envelopes. The shared native A2A client
requests identity encoding, rejects other content encodings before
decompression, checks any declared length, and counts actual streamed
bytes before retaining or parsing them. Malformed/non-object JSON and
transport, HTTP, or RPC failures produce bounded diagnostic categories,
not remote error bodies. An oversized response means this run exceeded
the selected local budget; it does not establish maliciousness or general
agent incapability. Later stages remain untested when retrieval fails.

Redirects are refused per request. Internally owned clients ignore ambient
proxy/environment configuration, use zero transport retries, and are closed
after each native operation or complete Path run (which retains one session);
card fallback is only for HTTP 404/410. This also
disables environment-supplied corporate proxy and CA configuration. Trusted
injected clients remain caller-owned and can supply explicit transport/TLS
configuration; their proxy and retry behavior is recorded as caller-controlled,
and allocations made by their already-buffered responses are outside the
streaming guarantee. The deliberate second logical order is a test condition,
not an automatic POST retry. Explicit localhost and LAN agents remain allowed.

Each new bundle records `config.a2a_transport_policy`: policy ID
`a2a-bounded-json@0.1`, effective byte limit and its basis, encoding,
redirect/environment/retry settings, client ownership, phase timeout, and
`total_deadline_seconds: null`. Path uses a 15-second HTTPX phase timeout;
direct native card/RPC calls default to 15/30 seconds respectively. These
are not hard wall-clock deadlines: a peer that keeps making progress may
take longer. Cancellable total deadlines and connection-bound address
policy remain follow-ups. This is not a public-hosted arbitrary-fetch policy,
input URL sanitization, or business-output sanitization.

The original `a2a-capability-fulfillment@0.1` profile and fingerprint remain
unchanged. The response-budget addition in `@0.2` retained the old evaluator.
Select the original profile explicitly with
`--path-profile a2a-capability-fulfillment@0.1`; newly executed old-profile
runs disclose the same 1 MiB implementation ceiling rather than claiming
the old profile specified it. Existing stored evidence is not reinterpreted.

The current `@0.3` profile uses evaluator contract `path-evaluator@0.2` and
records result evaluator version `path-0.3`: the task must be
`completed`, and each attempt must return exactly one text part across all
artifacts containing one JSON quote object. Town counts every text part rather
than accepting only the first one and ignoring later outputs. Nonterminal or
failed tasks cannot pass semantics. This is the selected synthetic profile's
output contract, not a claim that every A2A capability must use one text part.
The old `@0.1`/`@0.2` profiles remain available under `path-0.2`, including their
weaker first-text/nonempty-state checks. Use the new profile for new tests;
verification does not silently strengthen old evidence.

Requirements credit: [#145 by abhishekeb211](https://github.com/projnanda/nandatown/pull/145)
(`ddc5f4c5ee67db7b9784b1198446eee596facf53`), and bounded-read technique
credit: [James's #222](https://github.com/projnanda/nandatown/pull/222)
(`77c9ff3a39260e31640360be7ccb23652a13d307`). This replacement does not
adopt their legacy middleware, Town-specific handshake, deployment code,
or loopback-only origin restrictions.

#### Check the item, not only the price

Select `--path-profile a2a-quote-intent@0.2` to test an explicit quote:
two blue widgets from `town-reference`, denominated in USD, with a maximum
total of 3,990 cents. The response must contain the exact `sku`, `color`,
`quantity`, `merchant_id`, `currency`, and current `request_id`.
`total_cents` must be a JSON integer from 0 through 3990; discounts and free
quotes are allowed, strings, floats and booleans are not. Missing terms fail;
Town never substitutes request values for an agent's missing response fields.

In two terminals:

```bash
nandatown a2a serve --defect wrong_item
nandatown test-agent --url http://127.0.0.1:8940 --path-profile a2a-quote-intent@0.2
```

The reference seller deliberately offers a red item for 3,000 cents. The price
is within budget, but the report names `color` as the semantic mismatch.
Restart the seller without `--defect wrong_item` and rerun for the healthy
control. Other A2A agents can implement this same JSON contract; no specific
agent runtime, model key or payment provider is required by Town.

The bundle stores the selected profile, observed quote fields, request
correlation, response digest and `path-quote-intent-0.2` evaluator version.
`nandatown verify BUNDLE_DIR` replays the judgment offline. The controlled
duplicate checks whether the returned quote changes, not whether a merchant
performed a second purchase. A matching merchant identifier is a returned
claim, not independent proof of merchant ownership. This is a synthetic quote
conformance test, not purchase authorization, payment settlement, physical
delivery verification or outside-user adoption evidence.

The default is `a2a-capability-fulfillment@0.3`. The earlier price-only profiles
and `a2a-quote-intent@0.1` keep their original fingerprints and evaluator meanings.
The new quote-intent revision also requires completed tasks and exactly one text
part per response. Non-object quote
artifacts are now recorded as unparseable subject output rather than a Town
driver exception. Older recorded events retain their original interpretation.

Requirements credit: [#215 by chainaim-sathya](https://github.com/projnanda/nandatown/pull/215)
(`0b7667d5896bedd80f237a188f7cd0607d46237f`) identified the cheaper-but-wrong-item
gap. This fresh implementation preserves that narrow requirement; it does not
port the legacy Prava client, live charges, intent certificates, FX conversions,
return policy or hosted service.

## Receipts and Town Proof

```
nandatown receipt runs/<id>
nandatown verify-receipt runs/<id>/receipt.json --bundle runs/<id>
nandatown proof runs/<id> --freshness-days 30
```

Keep private artifacts in private storage. A receipt is a smaller signed
derivative that includes the exact
claim, digests, observer, time window, coverage, and limitations. The
signature proves a named key committed to those bytes, not that the
observation was true or the agent safe. `proof` renders the
TOWN-TESTED badge sentence only from passed, fresh, verified evidence with
an empty `coverage.not_tested` list. Partial or failed receipts remain valid
signed evidence; they cannot earn this badge. Bundle-aware receipt verification
also checks that claims, coverage and time window agree with the bundle.
Review subject URLs, release labels and custom limitations before sharing:
the receipt is not a universal secret scrubber. A refusal names its reason; the badge is
narrow and expiring, a policy view over evidence, never the evidence
itself. See [convergence](docs/convergence.md) for the mapping to the path
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
start it wherever the coordinator is reachable. `examples/byoa_seller.py` is a complete
reference agent in plain standard-library Python: no nandatown import,
no dependency, just the HTTP contract. For `nandatown run ... --identity`, a pinned role is
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
written to a local pinned catalog as community-generated, unclaimed, and
not provider-endorsed: the SKILL.md is a claim, not a fact, and town
tests plus provider authorization stay separate evidence. Re-importing identical
bytes preserves the existing candidate. Changed bytes require a different
`--name` or `--out`; the command refuses to overwrite the pinned snapshot.

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

A campaign precommits its plan before the first trial and reports the whole distribution:

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

The implemented foundation is local: Lab, Track and Path, replayable evaluation,
optional model harnesses, portable identity, receipts, mirroring and onboarding
checks. The next product validation is an independently developed agent, a useful
failure its existing tests miss, and another operator reproducing the result.
Neither reference-agent tests nor CI alone satisfy that milestone. A pinned
deployed NANDA Index integration, upstream protocol-conformance selection,
accepted-observer policy and public-service admission/resource controls remain
technical work as well as ownership decisions. See the [proposal mapping](docs/convergence.md)
and [operator guide](docs/operators.md).

## Development

```
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for tests, dashboard checks and schema
generation, and [architecture](docs/architecture.md) for the module map.
Apache 2.0. Part of the NANDA Town effort under Project NANDA.
