# Mesh-Revocable Auth: revocation that survives the network

Plugin: `("auth", "mesh_revocable")` —
[`nest_plugins_reference/auth/mesh_revocable.py`](../../packages/nest-plugins-reference/nest_plugins_reference/auth/mesh_revocable.py)

## Problem

The delegation problem was solved by the merged `delegatable` plugin: real
macaroon chains, offline attenuation, audience binding, and cascading
revocation. But that plugin's revocation knowledge is a single in-process
`set[str]`, and the `delegated_auth` scenario hands **one plugin instance to
all sixteen agents**. Under that wiring cascading revocation is trivially
global — it is one Python object.

Give every agent its own replica (the only shape a real network permits) and
the guarantee evaporates: a revocation performed at the issuer is invisible
to every other verifier, forever. Nothing in the plugin propagates it, and
nothing in the merged scenario notices, because no second verifier exists.
The layer has correct capability *semantics* and no capability
*distribution*.

## Solution

`MeshRevocableAuth` supplies the missing half by **composition, not
re-implementation**. It subclasses `DelegatableAuth` — token format, HMAC
chain, attenuation rules, and all five exception types inherited verbatim,
zero overrides of `issue` / `delegate` / `verify` / `verify_presented` /
`revoke` — and reinterprets the inherited revocation set as one replica of a
**grow-only set CRDT** (G-Set). Two additive methods are the replication
channel:

| Method | Contract |
|---|---|
| `export_revocations() -> bytes` | Canonical, sorted JSON (`{"crdt": "revocation_gset", "revoked": [...]}`). Identical state exports identical bytes, so traces stay replay-deterministic. |
| `merge_revocations(state) -> bool` | Set union with a peer's state; returns whether anything new arrived. Malformed or foreign state raises `RevocationStateError` and leaves the replica untouched — gossip input is attacker-adjacent. |

Union is commutative, associative, and idempotent, so replicas converge
under **any** delivery order and duplicated gossip is a no-op. That is
enforced by Hypothesis property tests, not merely asserted. A revocation
recorded anywhere reaches every replica, directly or through any chain of
intermediaries, once gossip has flowed.

Because delegation semantics live in the shared secret, all replicas are
constructed with the same one: tokens minted at any replica verify at every
replica; only *revocation knowledge* is replica-local until gossiped.

## The CAP position, stated and validated

Partition-tolerant revocation cannot be instantly consistent. This plugin
chooses availability during the split, and bounded convergence after it —
and the [`delegated_auth_partition`](../../scenarios/delegated_auth_partition.yaml)
scenario enforces **both halves** with a validator each, so neither can rot:

- `check_partition_liveness` — during the split, a verifier cut off from the
  revoker **must still accept** the revoked lineage. A design that denied
  instantly would be exhibiting knowledge the network never delivered. This
  check fails against the shared-single-instance shortcut.
- `check_revocation_converges` — after the heal plus a gossip-propagation
  bound, **no verifier anywhere** accepts the revoked lineage, and at least
  one verifier *other than the revoker* explicitly denied it (so a scenario
  where presentations merely stopped cannot pass vacuously).

Deliberately **not** asserted here: `check_no_stale_ancestor_use`'s global
"no success at or after the revoke tick". Under a partition that property is
unattainable; the bounded convergence check is its honest replacement. The
merged `check_no_scope_escalation` and `check_audience_binding` do run green
on this trace — the scenario reuses `delegated_auth`'s audit vocabulary on
purpose.

## Measured behavior

`nest run delegated_auth_partition` (10 agents, seed 42, byte-deterministic
across runs). The mesh splits at t=10, the coordinator revokes
intermediary-1's grant at t=20 — while that subtree is unreachable — and the
network heals at t=55. Gossip runs every 5 ticks. The far-side gateway's
verdicts on the revoked lineage:

```
t= 3..51  accept   (partition open from t=10; the gateway cannot know)
t=57..87  DENY     (heal at t=55; converged within one gossip round)
```

The healthy subtree verifies 69/69 throughout. Swap in per-replica
`delegatable` and the gateway accepts the revoked lineage at every tick to
the end of the run:

| Wiring | partition liveness | revocation converges |
|---|---|---|
| `delegatable`, one shared instance | ✗ (denies impossibly fast) | ✓ (vacuously — one object) |
| `delegatable`, one replica per agent | ✓ | **✗ stale forever** |
| `mesh_revocable`, one replica per agent | ✓ | ✓ |

That middle row is the gap this plugin closes.

## Supporting core change

Partitions previously activated at event 0, with only the heal tick-gated,
so no scenario could establish cross-boundary state before the split. This
adds `partition_start_at_time` / `partition_heal_at_time` to `FailureConfig`,
gating on **simulation time** rather than processed-event count. Event counts
drift with message volume — a gossiping plugin processes far more events per
simulated tick, so an event-count window would put the two plugins under
different partitions and void the comparison. The pre-existing
`partition_heal_at_tick` keeps its event-count meaning; both are tested.

## Limits

- **Revocation window.** A revoked token remains usable on an isolated
  replica for the partition's duration plus up to one gossip interval. That
  is the CAP price, made explicit and bounded rather than hidden. Shrink the
  gossip interval to shrink the window; you cannot reach zero.
- **Grow-only, by design.** Revocations are never removed, matching the
  base plugin's no-unrevoke semantics. State is bounded by the number of
  revocations, each a 16-hex-character tid — not by traffic.
- **Gossip is the scenario's job.** The plugin exposes the channel; it does
  not own a transport. The scenario broadcasts `export_revocations()` on a
  cadence. A deployment that never gossips converges never.
- **Symmetric secret, inherited.** Verification requires the shared HMAC
  secret, so any holder can also mint. Public-key verification across trust
  domains is out of scope here (it would change the token format, which this
  plugin deliberately does not touch).
- **Couples to the base plugin's revocation set.** `_revoked` is inherited
  private state. Inherited-behavior regression tests guard the coupling, so
  an upstream refactor fails loudly rather than silently.
