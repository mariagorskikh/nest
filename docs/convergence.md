# Alignment with “Test the Path, Not Just the Protocol”

The proposal asks whether an exact agent, service or protocol implementation can
complete a declared NANDA journey, and where a failure begins. Town has useful
local building blocks for that goal. A functioning local harness is not yet
evidence of an independently adopted, end-to-end NANDA integration.

This document separates current implementation from acceptance work still
needed. The [README](../README.md) and [testing guide](testing-an-existing-agent.md)
describe executable workflows.

## Current components

| Proposal component | Current implementation and scope |
| --- | --- |
| CLI and profiles | `cli.py`, `path_profiles.py`, `profiles.py`, `sim/scenario.py`; separate Lab, Track and Path contracts |
| Orchestration | `sim/runner.py` for simulation, `runner.py` for trusted local processes, `path_runner.py` for an existing A2A endpoint |
| Resolution | Direct endpoint or a local JSON index fixture; hops are in `events.jsonl`. This is not a deployed NANDA Index client |
| Drivers | Native A2A request/card checks, MCP initialization/tool-list probe, and Town's HTTP mailbox; no complete upstream conformance-suite claim |
| Evaluation | Stage judgments from recorded observations, using a named evaluator version |
| Evidence | Five canonical files, a manifest, optional signatures, replayable evaluation and separate reports |
| Service onboarding | Local OpenAPI becomes a reviewable candidate; no provider code or operation is executed |

The Lab's replaceable layers are simulation components. They do not automatically
establish compatibility with similarly named deployed identity, discovery or
payment protocols. Adapting a legacy scenario does not execute its original
plugins; `original_scenario` remains not tested.

## Result meanings

Each stage is Passed, Failed, Not tested, Inconclusive, or Error. Failure at an
earlier boundary can leave later checks not tested. A Town driver exception is
attributed to Town, not silently counted as a subject failure. These meanings
depend on correct observations and evaluation; tests protect particular cases,
not every possible malfunction.

A successful HTTP exchange is separate from a successful semantic result.
The synthetic quote profiles test declared returned fields and duplicate-response
behavior. They do not place orders, charge money, establish merchant ownership,
or verify physical delivery. Select the exact profile for repeatable comparisons:

```bash
nandatown test-agent --url http://127.0.0.1:8940 \
  --path-profile a2a-capability-fulfillment@0.3
```

Use `--path-profile` with `--url` or `--index`; `--profile` belongs to the
Town-joining Track flow.

## Evidence and badge eligibility

`run.json` carries the subject, profile, configured descriptor basis, transport
policy and rerun information. `events.jsonl` carries resolution hops, observed
card digests, protocol outcomes and semantic observations. Evaluation replay
recomputes judgments from the frozen profile and events; it does not rerun the network or independently
recover every raw response.

A receipt contains selected claims, coverage, time window, digests and the
signing observer. It omits full prompts and message bodies, but caller-supplied
URLs or labels can still be sensitive. Review it before sharing. A signature
establishes commitment by a key, not truth, independence or endorsement.

Partial and failed receipts remain legitimate signed evidence. `TOWN-TESTED`
requires a passed result, verified bundle and matching receipt, fresh evidence,
and no stage in `coverage.not_tested`. An unpinned direct run ordinarily leaves
`descriptor_consistency` untested and cannot earn the badge. A local-operator
badge is not an independent observer's acceptance.

Portable identity includes file and configured `eth_call` resolvers. It does
not implement ERC-8004 proof publication or EFS/Ethereum evidence anchoring.
Those remain separate proposed integrations.

## Acceptance milestones still open

| Milestone | Local prerequisite available | Evidence still required |
| --- | --- | --- |
| One existing independent agent | A2A Path and Town-joining Track entry points; reference controls and failure attribution | Independently developed agent, previous test baseline, useful missed failure, correction, non-author reproduction |
| Two real runtimes | Separate processes, HTTP mailbox, restart/duplicate tests, optional model harnesses | Two independently configured runtimes completing an agreed workflow with pinned versions and reproducible evidence |
| Pinned NANDA journey | Local index fixture, card comparison, protocol/semantic checks | Exact deployed Index revision and API, pinned card/runtime/A2A basis, stage-distinct failures and independent evidence consumer |

The [testing guide](testing-an-existing-agent.md) provides a small handoff packet.
It does not establish a willing partner, independent reproducer or outside CI
integration.

## Product and architecture boundaries

- Discovery grants no installation, execution, payment or secret-use authority.
- A card is a declaration; a result is an observation under a named contract.
- Pulse availability does not refresh semantic test evidence.
- Local process separation does not contain untrusted code.
- Public hosting needs admission, resource limits, deployment and ownership decisions.
- Independent proof promotion needs an accepted-observer policy; the local badge does not invent one.

Future work should be driven by a useful external pilot and measured defects.
Adding profiles or protocol names alone does not establish that value.
