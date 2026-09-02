# Test a local agent adapter

Nanda Town can exercise one strict boundary between Town and code you control.
Town sends a separate local adapter three bounded observations—start, one
synthetic request, and stop—and the adapter returns one permitted intent for
each observation.

This Bring Your Agent preview slice is intentionally narrower than “test any agent.” It gives
agent authors a repeatable integration check without a public network, model
credential, or hosted dependency. The checked-in reference is Python, but the
HTTP contract is language-neutral.

Generation 1 is the first frozen agent-test contract/profile generation, not a
Town or nest-core 1.0 release.

> **What a pass means:** Town observed valid, request-bound responses to its
> bearer-authenticated requests for the frozen capability-fulfillment profile.
> The responses carried one stable, self-asserted adapter instance ID. Town
> translated the adapter's declared capability into a card in its pinned,
> run-local Registry implementation, and Town's reference requester discovered
> and exercised that card through the simulator.
>
> **What it does not mean:** The bearer is a caller credential; it does not
> authenticate the adapter as a server identity. The adapter instance ID is
> metadata supplied by the adapter, not a verified identity. This profile does
> not test an external agent's own Registry protocol or discovery
> implementation. It also does not establish that a model was used, that the
> response was not hardcoded, or that the agent is generally compatible, safe,
> trusted, or reliable.

## Security boundary: trusted local code, not a sandbox

The adapter and any runtime it calls execute with your operating-system user
privileges. A separate process and a loopback-only endpoint are useful
boundaries, but **Town does not sandbox the adapter or runtime**. Only run code
you trust. It can read or modify anything your user account can access.

The reference adapter reads and validates `TOWN_AGENT_TOKEN`, hashes it, and
removes the raw value from its own process environment before accepting a
decision. Exporting a variable in a shell still leaves it in that parent shell,
and other processes under the same OS account may be able to inspect it.

If your adapter starts a child runtime, construct the child's environment from
an explicit allowlist of only the variables it needs. Do not pass a copy of
`os.environ`, and never include `TOWN_AGENT_TOKEN` in the child environment.
Keep model or service credentials in the runtime's own narrowly scoped secret
configuration, not in Town's bearer variable.

## Run the reference journey

The reference adapter declares `sell`, answers `buy:widget:2` with
`sold:widget:2`, and stops. Its job is to prove the integration path before you
connect your own runtime.

This Alpha feature is **checkout-only**. It requires Python 3.12 or newer and
[uv](https://docs.astral.sh/uv/getting-started/installation/). From the repository
checkout, install the exact locked workspace:

```bash
uv sync --frozen
```

Do not use an older or unpinned package install to evaluate this checkout.

Generate one fresh 64-character local test token:

```bash
uv run python -c 'import secrets; print(secrets.token_hex(32))'
```

Copy that value into `TOWN_AGENT_TOKEN` in both terminals. Do not pass it as a
command-line argument or save it in source, shell history, logs, or a committed
file.

**Terminal 1 — run the reference adapter**

```bash
read -r -s TOWN_AGENT_TOKEN && export TOWN_AGENT_TOKEN
uv run python examples/agent-test/reference_adapter.py
```

Paste the generated value at the hidden prompt, then press Enter. The adapter
listens only on `127.0.0.1:8787`.

**Terminal 2 — after the adapter is running, run Town**

```bash
read -r -s TOWN_AGENT_TOKEN && export TOWN_AGENT_TOKEN
uv run nest test agent --endpoint http://127.0.0.1:8787 \
  --target-label my-local-agent
```

The `read -r -s` snippets are for Bash and zsh. In PowerShell, set the same
value in each terminal with
`$env:TOWN_AGENT_TOKEN = Read-Host -MaskInput`, then use the same `uv run`
commands.

After Town finishes and after you stop the adapter, remove the token from both
parent shells:

```bash
unset TOWN_AGENT_TOKEN
```

```powershell
Remove-Item Env:TOWN_AGENT_TOKEN
```

A successful run ends with `RESULT: PASS` and writes a new evidence directory
under `.town/runs/<run-id>/`. Use `--output-dir <new-or-empty-directory>` to
choose an exact location. For automation, add `--format json`; advanced callers
that need the exact frozen reference can add
`--profile nanda/agent/capability-fulfillment@1`. After an admitted run, stdout
is byte-for-byte identical to `result.json`, while safe progress and diagnostics
remain on stderr.

## What Town evaluates

The report separates five questions so that a downstream success cannot hide
an earlier failure:

1. **Bearer-authenticated driver contract** — did one stable, self-asserted
   adapter instance return valid, request-bound intents for the required
   exchanges?
2. **Provider registered** — did Town translate the adapter's declared `sell`
   capability into a provider card in the pinned, run-local Registry
   implementation?
3. **Provider discovered** — did Town's reference requester find and select that
   card through the Registry lookup result?
4. **Request routed** — did Town route the exact synthetic request through its
   simulator to the selected provider?
5. **Exact fulfillment returned** — did the expected response travel back
   through Town and reach the requester?

This is a test of Town's pinned Registry implementation and the adapter's
declared capability, not the external agent's own Registry protocol.

`Not evaluated` means Town could not produce a sound verdict for a check in this
run, including when an earlier required stage prevented a dependent check from
running. `Not tested` is reserved for a property the profile deliberately places
outside its coverage. Neither means pass.

The evidence directory contains:

- `result.json`: the terminal verdict, per-check outcomes, coverage boundaries,
  diagnostics, and trace digest.
- `trace.jsonl`: the simulator trace plus typed `test.*` observations referenced
  by the report.

These files are mutable local diagnostics, not attestations. On POSIX systems,
Town creates the default `.town/runs/<run-id>/` hierarchy with mode `0700` and
artifact files with mode `0600`. If you provide an existing empty
`--output-dir`, Town preserves that directory's mode; you are responsible for
securing it. Other operating systems do not share a portable POSIX-mode
guarantee. `.town/` is ignored by this repository, but ignore rules are not a
security boundary.

## Connect your own runtime

Start from
[`examples/agent-test/reference_adapter.py`](../examples/agent-test/reference_adapter.py).
Preserve its HTTP framing, strict validation, digest binding, replay handling,
and one-run state machine. Before testing your code:

1. Change `ADAPTER_INSTANCE_ID` from `town-reference-adapter` to a stable
   value that describes your adapter, such as `my-agent-adapter`. It remains
   self-asserted metadata, not a verified identity.
2. Replace only this deterministic decision function with a call to your trusted
   runtime:

```python
def decide_intent(observation: dict[str, Any]) -> dict[str, Any]:
    """Deterministic replace point: map one validated observation to one intent."""
    kind = observation["kind"]
    if kind == "start":
        return {"kind": "declare_capability", "capabilities": ["sell"]}
    if kind == "message":
        return {
            "kind": "send_to_sender",
            "media_type": "text/plain; charset=utf-8",
            "text": "sold:widget:2",
        }
    return {"kind": "none"}
```

The mapping is bounded:

| Observation | Allowed result used by the reference adapter |
|---|---|
| `start` | declare the `sell` capability |
| `message` containing `buy:widget:2` | return a plain-text response to the sender |
| `stop` | return `none` and release the run |

Your bridge may call a state machine, local model, hosted model, or another
runtime. Town observes only the adapter's response to Town's
bearer-authenticated request; it cannot infer which implementation produced it.

## HTTP contract and exact resources

The public wire contract is `town-agent-driver/1`:

- `GET /town-driver/1/ready` advertises the exact supported profile and current
  one-run capacity.
- `POST /town-driver/1/decide` carries one observation and accepts one intent.
- Requests use `Authorization: Bearer <token>`,
  `Town-Driver-Contract: town-agent-driver/1`, and exact SHA-256 body binding.
  The bearer lets the adapter authenticate its caller; it is not server identity.
- The endpoint must be a canonical literal-loopback origin with an explicit
  port. Redirects, proxy environment variables, cookies, compression, remote
  hosts, and ambiguous URL forms are rejected.
- Successful events are idempotent. Repeating one event with the same bytes
  returns the same response bytes; reusing its event ID with changed bytes is a
  conflict.
- If a custom start or message decision raises an exception, the adapter returns
  a fixed retryable `ADAPTER_INTERNAL` error without advancing the run. The same
  event and exact request bytes may be retried after the runtime recovers. The
  first schema-valid request still binds its event ID, so changed bytes conflict.
  Raw exception text is never returned or logged.
- Legal terminal stops return `none`, release the one-run capacity, and remain
  byte-idempotent after release. A `run_failed`, `run_incomplete`, or
  `user_interrupted` stop may account for a missing or failed message decision;
  `run_complete` cannot skip the required exchange.

The exact frozen Generation 1 profile and schemas are checked-in resources:

- [Generation 1 capability-fulfillment profile](../packages/nest-core/nest_core/agent_test/resources/profiles/capability-fulfillment-1.json)
- [Generation 1 driver request schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-request-1.schema.json)
- [Generation 1 driver response schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-response-1.schema.json)
- [Generation 1 driver readiness schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-ready-1.schema.json)
- [Generation 1 driver error schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-error-1.schema.json)
- [Generation 1 Test Profile schema](../packages/nest-core/nest_core/agent_test/resources/schemas/test-profile-1.schema.json)
- [Generation 1 test observation schema](../packages/nest-core/nest_core/agent_test/resources/schemas/test-observation-1.schema.json)
- [Generation 1 test result schema](../packages/nest-core/nest_core/agent_test/resources/schemas/test-result-1.schema.json)

The standard-library reference is a teaching example, not a production server.
Its focused notes are in
[`examples/agent-test/README.md`](../examples/agent-test/README.md).

## Exit codes and artifact admission

| Code | Meaning |
|---:|---|
| `0` | Completed with all required checks passing. |
| `1` | Completed with a conclusive failed check, or the adapter returned an invalid contract response. |
| `2` | Configuration or compatibility was rejected before admission. |
| `3` | Town encountered an internal execution error. |
| `4` | The run was incomplete or evidence was inconclusive. |
| `130` | The user interrupted the invocation. |

If the invocation stops before Town admits a run, machine JSON stdout is empty
and Town creates no `result.json`, `trace.jsonl`, or run directory. After
admission, `result.json` is the authoritative terminal record even when output
rendering is interrupted.

## Troubleshooting

- **`TOWN_AGENT_TOKEN is not set` or token format error:** enter the same fresh
  64-character lowercase hexadecimal value in both terminals.
- **Connection refused or incomplete result:** start the adapter first and
  verify that no other process owns port 8787.
- **Unsupported profile or contract:** use the exact command above; the Bring
  Your Agent preview supports only the Generation 1 `capability-fulfillment`
  profile.
- **Pinned reference Registry is unavailable:** from the same checkout, rerun
  `uv sync --frozen`, then invoke Town through `uv run nest`.
- **Output directory rejected:** choose a path that does not exist or is an
  empty, non-symlink directory. Town does not overwrite an earlier run.
- **Contract failure:** inspect the safe diagnostic in `result.json` when a run
  was admitted, compare requests and responses with the linked schemas, and
  retry with a new output path.

For maintainers, the source-tree process journey runs in normal pytest. Before a
release handoff, also run the explicit clean-package proof:

```bash
TOWN_RUN_PACKAGE_QUICKSTART=1 \
  uv run pytest \
  packages/nest-core/tests/agent_test/test_end_to_end.py::test_clean_archive_wheel_quickstart_checker
```

## Deliberately deferred

This slice does not include OpenClaw, Docker, A2A, MCP, remote endpoints,
authentication beyond the local bearer, multi-turn workflows, model scoring,
signed evidence, public identity or reputation, services, arbitrary SDK
execution, or hosted testing. Those can be added behind new profiles and
adapters without changing what this Generation 1 result claims.
