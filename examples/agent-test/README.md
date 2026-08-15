# Reference local agent adapter

`reference_adapter.py` is the checked-in Python teaching implementation for
Town's strict Generation 1 local agent-driver boundary. It is deterministic,
uses only the standard library, and supports one active
`capability-fulfillment` run. It is not a hosted service, general agent runtime,
benchmark agent, production server, or sandbox.

The canonical instructions for running, modifying, and automating this example
are in the
[`agent-test adapter technical reference`](../../docs/agent-test-adapter-reference.md).
That reference owns the security boundary, caller credential, wire contract,
schemas, state machine, evidence, exit codes, and maintainer verification so
this implementation note does not drift into a second guide.

The intended customization point is `decide_intent`: preserve the surrounding
validation and lifecycle and replace the deterministic decision with a call to
trusted code. Change `ADAPTER_INSTANCE_ID` to stable self-asserted metadata for
your adapter; it is not a verified identity.

The optional `--port` flag changes only the loopback port; `--port 0` is
reserved for ephemeral test processes.
