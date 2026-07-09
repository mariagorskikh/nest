---
title: Content-addressed datasets with provenance chains and freshness proofs
layer: datafacts
difficulty: medium
status: solved
---
> **Status: SOLVED** — implemented in `scenarios/provenance_supply_chain.yaml` with the `cid_facts` DataFacts plugin.
# Content-addressed datasets with provenance chains and freshness proofs
## Motivation
The default datafacts plugin
[`nest_plugins_reference/datafacts/datafacts_v1.py`](../../../packages/nest-plugins-reference/nest_plugins_reference/datafacts/datafacts_v1.py)
is 79 lines of "dict of metadata records." The URL scheme is
`df://<dataset.name>` (line 39) — i.e., addressed by the publisher's
**chosen name**, not by content. `verify_freshness` (line 68-78) is
`(time.time() - self._timestamps[url]) < 3600` — a wall-clock check
with **no cryptographic proof at all**. `request_access` (line 57-66)
unconditionally grants `tier="read"` to anyone who asks.
That means three classes of bug are silently impossible to detect in
any current Nanda Town scenario:
1. *Substitution attack*: an attacker republishes a different dataset
   under the same name. Nothing in the protocol or trace catches it.
2. *Stale-claim attack*: the publisher claims a dataset is fresh by
   re-touching its timestamp without re-publishing the actual content.
3. *Provenance washing*: a dataset derived from a polluted upstream
   source loses the provenance trail at the first hop because there
   is no chain.
Zero PRs touched datafacts. The
[`docs/layers/datafacts.md`](../../../docs/layers/datafacts.md)
wishlist explicitly calls out "content-addressed storage (IPFS-style),
signed-manifest schemes, fine-grained ACLs, expiry / TTL policies" —
nobody picked any of them. Anyone running Nanda Town scenarios that touch
data quality, audit trails, or supply-chain provenance (see
[`scenarios/supply_chain.yaml`](../../../scenarios/supply_chain.yaml))
benefits.
## Success criteria
- Ship a datafacts plugin (suggested name: `cid_facts` or
  `content_addressed`) registered as `(\"datafacts\", \"<your_name>\")`
  in [`nest_core/plugins.py`](../../../packages/nest-core/nest_core/plugins.py).
- URLs are **content hashes**, not names. `publish(dataset)` returns
  `DataFactsUrl(\"df://sha256-<hex>\")`. Republishing the same content
  returns the same URL; republishing different content under a "name"
  is no longer possible.
- A `DatasetMetadata` carries a `parents: list[DataFactsUrl]` field
  (extend the type in
  [`nest_core/types.py`](../../../packages/nest-core/nest_core/types.py)
  or use a `metadata` dict). Derived datasets *must* reference the
  hashes of every dataset they were derived from.
- `verify_freshness` returns a **proof object** (signed by the
  publisher's identity-layer key — call into the identity layer from
  PR-of-your-choice or the default `did_key`) attesting "this hash
  was published at tick T by agent A." A verifier without trusting
  wall-clock time can still validate the chain.
- Ship an adversarial validator that catches:
  1. *Substitution*: an attacker publishes new content under an old
     hash — must be detected (it's impossible by construction; the
     validator asserts the impossibility holds in the trace).
  2. *Stale freshness*: a publisher claims freshness without
     re-publishing — validator detects no proof was issued.
  3. *Broken provenance*: a derived dataset's `parents` chain
     references a hash that doesn't exist in the trace.
- Validator FAILS against `datafacts_v1`, PASSES against yours.
- Ship `scenarios/provenance_supply_chain.yaml` based on the existing
  supply-chain scenario but with each hop publishing a content-
  addressed dataset and the retailer verifying the chain end-to-end.
## Suggested approach pointers
- The hash is just `sha256(canonical_json(metadata) + payload_bytes)`
  — don't over-engineer.
- Re-use the `did_key` identity plugin for the freshness signature.
  You can take an `Identity` instance via the constructor (just like
  PR #2/#3/#6's EigenTrust plugins took it).
- Provenance is a DAG, not a tree — datasets can have multiple
  parents.
- `request_access` is the right place to enforce ACLs based on the
  content hash, not the dataset name.
- Don't make freshness depend on `time.time()`. Use the simulator's
  logical clock if you can plumb it in, or the agent's own tick
  counter.
## Anti-patterns
- Don't keep the `df://name` URL scheme alongside content hashing —
  that defeats substitution resistance.
- Don't sign the metadata but not the payload. A freshness proof
  has to bind to the *content*.
- Don't require a central authority to issue hashes.
- Don't reuse `datafacts_v1` and patch in `parents` — the URL scheme
  has to change.
## Out of scope
- Real IPFS / libp2p integration. In-process content addressing is
  fine.
- Erasure coding / replication strategies.
- Encrypted-payload datasets (that's the privacy layer's job).
