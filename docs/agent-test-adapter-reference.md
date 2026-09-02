# Agent-test adapter technical reference

This reference documents Town's advanced endpoint mode and the exact
Generation 1 adapter contract. Most users testing through the local OpenClaw
CLI should start with the
[short OpenClaw guide](bring-your-agent.md).

Generation 1 is the first frozen agent-test contract and profile generation,
not a Town or `nest-core` 1.0 release. Endpoint mode is a deterministic teaching
and integration seam, not a hosted service, production server, or sandbox.

## Run the reference adapter

The checked-in standard-library adapter declares `sell` and answers
`buy:widget:2` with `sold:widget:2`. The run state is released after stop; the
adapter process continues serving until you press Ctrl-C. From a clean checkout
with Python 3.12 or newer and `uv`, install the locked workspace:

```bash
uv sync --frozen
uv run python -c 'import secrets; print(secrets.token_hex(32))'
```

Copy the fresh 64-character lowercase hexadecimal value into
`TOWN_AGENT_TOKEN` in both terminals. Never pass it as a command-line argument
or save it in source, shell history, logs, or a committed file.

Terminal 1, from the repository root:

```bash
read -r -s TOWN_AGENT_TOKEN && export TOWN_AGENT_TOKEN
uv run python examples/agent-test/reference_adapter.py
```

Terminal 2, after the adapter is ready:

```bash
read -r -s TOWN_AGENT_TOKEN && export TOWN_AGENT_TOKEN
uv run nest test agent --endpoint http://127.0.0.1:8787 \
  --target-label my-local-agent
```

The snippets above are for Bash and zsh. In PowerShell, use
`$env:TOWN_AGENT_TOKEN = Read-Host -MaskInput` in both terminals. After the run
and adapter have stopped, remove the parent-shell value with
`unset TOWN_AGENT_TOKEN` or `Remove-Item Env:TOWN_AGENT_TOKEN`.

The bearer authenticates Town as the adapter's caller. It does not authenticate
the adapter as a server identity. The adapter hashes the value and removes the
raw value from its own environment before accepting decisions. A parent shell
that exported it still retains it. If an adapter launches another runtime,
construct the child's environment from an explicit allowlist and exclude
`TOWN_AGENT_TOKEN`.

## Replace the deterministic decision

Start from
[`examples/agent-test/reference_adapter.py`](../examples/agent-test/reference_adapter.py).
Preserve the HTTP framing, validation, digest binding, replay handling, and
one-run state machine. Change `ADAPTER_INSTANCE_ID` to stable self-asserted
metadata for your adapter, then replace only `decide_intent` with the call to
your trusted runtime:

```python
def decide_intent(observation: dict[str, Any]) -> dict[str, Any]:
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

The adapter accepts a bounded `start`, `message`, and terminal `stop` sequence.
Town observes only the returned intents. It cannot infer whether a state
machine, local model, hosted model, or hardcoded function produced them.

## HTTP contract

The public wire contract is `town-agent-driver/1`:

- `GET /town-driver/1/ready` advertises the exact supported profile and current
  one-run capacity.
- `POST /town-driver/1/decide` carries one observation and accepts one intent.
- Requests use `Authorization: Bearer <token>`,
  `Town-Driver-Contract: town-agent-driver/1`, and exact SHA-256 body binding.
- The endpoint must be a canonical literal-loopback origin with an explicit
  port. Redirects, proxy environment variables, cookies, compression, remote
  hosts, and ambiguous URL forms are rejected.
- A successful event is byte-idempotent. Repeating its event ID with the same
  bytes returns the same response bytes; changed bytes conflict.
- A custom start or message exception returns the fixed retryable
  `ADAPTER_INTERNAL` error without advancing the run. The first schema-valid
  request still binds that event ID, so only the exact request bytes may retry.
  Raw exception text is not returned or logged.
- A legal terminal stop returns `none`, releases capacity, and remains
  byte-idempotent. `run_complete` cannot skip the required exchange.

The frozen resources are:

- [Capability-fulfillment profile](../packages/nest-core/nest_core/agent_test/resources/profiles/capability-fulfillment-1.json)
- [Driver request schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-request-1.schema.json)
- [Driver response schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-response-1.schema.json)
- [Driver readiness schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-ready-1.schema.json)
- [Driver error schema](../packages/nest-core/nest_core/agent_test/resources/schemas/driver-error-1.schema.json)
- [Test Profile schema](../packages/nest-core/nest_core/agent_test/resources/schemas/test-profile-1.schema.json)
- [Test observation schema](../packages/nest-core/nest_core/agent_test/resources/schemas/test-observation-1.schema.json)
- [Test result schema](../packages/nest-core/nest_core/agent_test/resources/schemas/test-result-1.schema.json)

The reference adapter's focused implementation notes are in
[`examples/agent-test/README.md`](../examples/agent-test/README.md).

## Managed OpenClaw boundary

The connector reads the installed OpenClaw version and reports it in command
progress; it has no exact-release allowlist. Before dispatching an agent
command, it validates the version probe, local configuration, read-only JSON
inventory, and Gateway status JSON. The required CLI, Gateway, and RPC versions
must agree; optional server and plugin versions must also agree when OpenClaw
reports them. `2026.7.1-2` is the only release tested against a real OpenClaw
installation. A missing or incompatible pre-dispatch command/JSON response, or
a version disagreement, fails clearly before an agent/model turn.

After dispatch begins, an agent command/flag failure or incompatible response
envelope can be detected after a model turn. Town reports that outcome and does
not retry the turn with alternate command syntax.

Before agent turns, Town requires exact local Gateway mode, rejects configured
`OPENCLAW_GATEWAY_URL` overrides, and clears inherited URL overrides. The probe
and RPC URLs used by the connector must be literal-loopback URLs; Town does not
require the Gateway to be exposed only on loopback. Each Town run creates a
fresh OpenClaw session key and uses it for exactly two model turns. Prompts are
passed through private temporary files and removed after each invocation. Town
does not use `--deliver` or `--local` and does not pass its internal bearer or
`TOWN_*` environment into OpenClaw.

The accepted sanitized envelope must report one stable session, configured
provider/model, completed turn, and no fallback or explicit delivery/tool
activity. Absence of such activity fields leaves activity unknown; it is not
proof that configured tools, hooks, or plugins did not run. Town does not replay
an uncertain model turn after a timeout or malformed response.

## Automation, exit codes, and evidence

Add `--format json` for automation. Advanced endpoint callers can select the
exact frozen profile with
`--profile nanda/agent/capability-fulfillment@1`. Safe progress and diagnostics
remain on stderr.

| Code | Meaning |
|---:|---|
| `0` | Completed with all required checks passing. |
| `1` | Completed with a conclusive failed check, or invalid contract response. |
| `2` | Configuration or compatibility was rejected before admission. |
| `3` | Town encountered an internal execution error. |
| `4` | The run was incomplete or evidence was inconclusive. |
| `130` | The user interrupted the invocation. |

Before admission, machine JSON stdout is empty and no run directory is
created. After admission, stdout is byte-for-byte identical to `result.json`.
The default directory is `.town/runs/<run-id>/`; `--output-dir` accepts an exact
new or empty non-symlink directory.

- `result.json` is the terminal verdict, five check outcomes, coverage
  boundaries, diagnostics, and trace digest.
- `trace.jsonl` is the simulator trace and typed `test.*` evidence referenced by
  the result.

These are mutable local diagnostics, not attestations. On POSIX, Town creates
the default hierarchy with mode `0700` and artifact files with mode `0600`.
For an existing explicit output directory, its mode is the caller's
responsibility. Other operating systems do not share a portable POSIX-mode
guarantee, and ignore rules are not a security boundary.

## Maintainer verification

The normal process-level E2E uses a fake OpenClaw executable and never contacts
a live OpenClaw host. Before a release handoff, also run the clean
committed-archive and installed-wheel proof:

```bash
python scripts/check_agent_test_quickstart.py
```

The checker rejects dirty or untracked inputs, archives committed `HEAD`,
replaces source installs with built wheels, disables source package paths, and
then exercises both the endpoint reference adapter and the auto-detected plus
explicit OpenClaw commands.
