# Caching Resolver Registry — design notes

A DNS-inspired registry plugin (`registry: resolver`) that keeps agent discovery
*honest about liveness*. This document explains the gap it closes, the system
design, how it maps onto DNS, how it compares to the other NANDA Town registries,
and how it scales.

## The gap

The registry layer answers one question: *"which agents can do X right now?"* The
default `in_memory` registry answers it with a plain dictionary. Once an agent
registers, its card is returned by every future `lookup` — forever, even after the
agent has crashed and will never respond again. There is no notion of time, so
discovery cannot tell a live agent from a dead one. At any real scale this turns the
registry into a graveyard: lookups keep handing out addresses that no longer work,
and the only cleanup is a manual `deregister` that a crashed agent can never send.

The `gossip` registry solves a different problem (spreading records across a
partitioned network), and the `verified` and persistent-backend registries solve
integrity and durability. None of them expire stale records. That is the gap here.

## System design

A record is a card plus the wall-time it stops being resolvable:

```
_Record = (card, expires_at)
```

Three mechanisms operate on it:

1. **TTL and self-eviction.** On `register`, a record's `expires_at` is set to
   `now + ttl`. `lookup` prunes and ignores anything with `expires_at <= now`, so a
   crashed agent disappears on its own once its TTL lapses. No tombstones, no
   background sweeper — pruning is lazy, done at lookup time.

2. **Heartbeat to stay alive.** Re-registering is a heartbeat: it pushes
   `expires_at` forward. A healthy agent that re-registers within its TTL stays
   resolvable indefinitely; a crashed one does not. Liveness becomes an emergent
   property of "did you check in recently," not a flag someone has to clear.

3. **Per-record TTL.** Each agent chooses its own freshness via
   `card.metadata["ttl"]`, exactly like a DNS zone sets TTL per record. Fast-moving
   agents pick a short TTL; stable infrastructure agents pick a long one. No core
   type changes were needed.

On top of that, **negative caching**: a query that matches nothing is remembered for
a short `negative_ttl`. A storm of lookups for something that does not exist is then
answered in O(1) from the negative cache instead of rescanning the table. The
negative cache is dropped whenever a new agent registers, because that registration
might satisfy a previously-empty query — so it never serves a false "not found."

## How it maps onto DNS

| DNS concept | Here |
|---|---|
| Record TTL | `card.metadata["ttl"]`, enforced at lookup |
| Records expire unless refreshed | Re-register = heartbeat pushes `expires_at` forward |
| Negative caching (SOA minimum, RFC 2308) | `negative_ttl` on empty lookups |
| Authoritative data vs cached view | Live records vs the negative cache |
| No manual cleanup of dead hosts | Crashed agents self-evict at TTL |

The point of the comparison is not novelty for its own sake: DNS scaled discovery
for the entire internet precisely because caches expire and refresh. An agent
registry needs the same discipline, and it did not have it.

## Compared to the other NANDA registries

| Registry | What it optimizes | Expires stale records? |
|---|---|---|
| `in_memory` | simplicity | no — serves dead agents forever |
| `gossip` | partition-tolerant propagation | no |
| `verified` | Sybil resistance via signatures | no |
| SQL / Redis backends | durability, multi-process | no |
| **`resolver`** | **liveness / freshness** | **yes (TTL + heartbeat)** |

It is complementary, not competing: a production registry would layer signature
verification and a durable backend *under* these caching semantics, the same way a
real DNS resolver sits in front of authoritative, signed (DNSSEC) zones.

## Scaling

- **Memory is bounded by *live* agents, not *ever-seen* agents.** Expired records are
  pruned, so a system that churns through millions of short-lived agents does not
  grow without bound the way the in-memory dict does.
- **Negative lookups are O(1).** Under a thundering herd of lookups for a capability
  no one offers, the negative cache absorbs the load instead of an O(n) rescan each
  time.
- **Pruning is lazy and amortized.** No background thread; expiry work happens on the
  lookups that would have read the stale data anyway.
- **Per-record TTL lets the operator tune the freshness/traffic tradeoff** per agent
  class, exactly as DNS operators tune record TTLs.
- **Extends cleanly to a distributed deployment.** The same record-with-TTL model
  shards by capability or agent-id prefix, and a gossip or SQL backend can carry the
  authoritative records while each node keeps this caching/negative-cache layer in
  front — mirroring the recursive-resolver / authoritative-server split in DNS.

## Tradeoffs and future work

- The clock is injected (`set_clock`) for deterministic simulation; a production
  build would read a monotonic clock.
- Negative-cache invalidation is coarse (cleared on any register). A finer scheme
  would invalidate only the capability keys a new card could satisfy.
- Third-party health probes (actively pinging endpoints) could complement
  heartbeat-based liveness for agents that cannot re-register on their own.

## Try it

```bash
uv run pytest packages/nest-plugins-reference/tests/test_caching_resolver.py \
               packages/nest-plugins-reference/tests/test_discovery_resolver_scenario.py -v
uv run nest run discovery_resolver     # 8 stable providers resolve, 4 crashed self-evict
```
