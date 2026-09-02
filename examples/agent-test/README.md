# Reference local agent adapter

`reference_adapter.py` is the one Python reference for Nanda Town's strict local
agent-driver boundary. The HTTP contract is language-neutral. This is a
deterministic teaching bridge, not a hosted service, general agent runtime,
benchmark agent, or production server.

It uses only Python's standard library, binds literal `127.0.0.1`, reads the
bearer only from `TOWN_AGENT_TOKEN`, and supports exactly one active
Generation 1 `capability-fulfillment` run. Generation 1 is the first frozen
agent-test contract/profile generation, not a Town or nest-core 1.0 release. It
never accepts the token as a command-line argument or writes it into responses,
run/decision state, or logs. After
validating and hashing the token, it removes the raw value from its own process
environment before serving decisions. The parent shell still retains an
exported value until you remove it.

**This is not a sandbox.** The adapter and anything it calls run with your user
privileges. Only connect trusted code. If the adapter starts a child runtime,
build the child's environment from an explicit allowlist and exclude
`TOWN_AGENT_TOKEN`; never copy the adapter's full environment.

The Generation 1 Bring Your Agent preview is checkout-only and requires Python
3.12 or newer. From a clean checkout, install
[uv](https://docs.astral.sh/uv/getting-started/installation/) using its official
guide, then install the exact locked workspace and run the adapter:

```bash
uv sync --frozen
read -r -s TOWN_AGENT_TOKEN && export TOWN_AGENT_TOKEN
uv run python examples/agent-test/reference_adapter.py
```

Paste the same fresh 64-character lowercase hexadecimal token at the hidden
`read` prompt in both terminals. Then run Town in the second terminal:

```bash
read -r -s TOWN_AGENT_TOKEN && export TOWN_AGENT_TOKEN
uv run nest test agent --endpoint http://127.0.0.1:8787
```

Do not pass the token as an argument or save it in source, shell history, logs,
or a committed file. The `read -r -s` snippets are for Bash and zsh; the full
guide gives the PowerShell equivalent and cleanup commands.

To connect a real runtime, preserve the HTTP framing, strict request validation,
digest binding, replay handling, and one-run state machine. Change
`ADAPTER_INSTANCE_ID` to a stable value for your adapter; it is self-asserted
metadata, not a verified identity. Replace only the `decide_intent` function
with a call to your trusted runtime. The adapter keeps a failed start/message
decision retryable without advancing state, but still binds that event ID to the
first schema-valid request bytes. An exact request can retry after recovery;
changed bytes conflict. The adapter handles terminal stop/release itself. The
full workflow, claims, limitations, and troubleshooting guide are in
[`docs/bring-your-agent.md`](../../docs/bring-your-agent.md).

The optional `--port` flag changes only the literal-loopback port; `--port 0` is
reserved for ephemeral test processes.
