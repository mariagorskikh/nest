# Schema Version (wire) — migration note

This short note explains the `schema_version` envelope field and operator guidance for rolling upgrades.

- What is `schema_version`:
  - Every outgoing wire envelope now carries an explicit `schema_version` (SemVer string, e.g. `1.1`) and a `kind` tag.
  - Missing `schema_version` from older peers is treated as `1.0` for backward compatibility.

- Forward-compat behavior (minor bumps):
  - Unknown top-level fields from newer-minor peers are preserved into `metadata['_unknown']` by older nodes and re-emitted on subsequent sends.
  - This preserves data and avoids silent field loss during rolling upgrades.

- Breaking changes (major bumps):
  - If a node receives an envelope whose major version is greater than the running build's supported major, the envelope is rejected with `UnsupportedSchemaError` (safe failure).
  - Rejection is intentional: a breaking major change cannot be safely decoded.

Operator guidance for rolling upgrades:

1. Stage minor bumps first when adding non-breaking fields:
   - Deploy the newer-minor build to a subset of nodes first. Older nodes will accept and preserve unknown fields.
   - When all nodes have received the newer-minor, you can safely roll forward.

2. Plan major bumps carefully:
   - Coordinate downtime or full-cluster upgrade for major version increases.
   - Expect `UnsupportedSchemaError` rejections from older nodes; monitor logs for these errors during the transition.

3. Testing and validation:
   - Run the included scenario `scenarios/comms_schema_evolution.yaml` to validate `schema_version` behavior in your environment.
   - Use `nest` validators (e.g. `comms_reject_unknown_major`, `comms_no_silent_drop`) against traces to confirm correct behavior.

4. Observability:
   - Log the `schema_version` and `kind` for incoming envelopes at INFO level during an upgrade window.
   - Capture and trace any `UnsupportedSchemaError` occurrences to ensure they are expected (planned major upgrades) and not accidental.


