# Registry reference plugins

This directory contains the registry implementations shipped with
`nest-plugins-reference`.

| Plugin | Storage | Replication | Registration checks |
|---|---|---|---|
| `in_memory` | local dictionary | none | none |
| `gossip` | per-agent view | gossip | none |
| `verified` | shared dictionary | none | verifies the card owner's signature at registration |
| `byzantine_gossip` | per-agent view | gossip | verifies signed writes on each hop and detects equivocation |

## `verified`

`VerifiedRegistry` rejects unsigned cards, cards signed by an identity other
than the claimed `agent_id`, and cards changed after signing. Rejections use
the reason codes `missing_signature`, `signer_mismatch`, and `bad_signature`.

The plugin requires an `Identity` verifier when it is constructed. It is used
by the `registry_integrity` scenario, which provisions the verifier and signing
identities explicitly.

```bash
uv run nest run scenarios/registry_integrity.yaml
uv run pytest packages/nest-plugins-reference/tests/test_verified_registry.py \
  packages/nest-plugins-reference/tests/test_verified_registry_properties.py \
  packages/nest-core/tests/test_registry_integrity.py -v
```

`verified` is an admission gate for a non-replicated registry. It does not
authenticate `deregister`, check signature age, replicate cards, verify gossip
messages, or detect signed equivocation. Use `byzantine_gossip` when those
network-level properties are required.
