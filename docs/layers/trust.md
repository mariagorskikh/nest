# Trust layer

**What it does.** Maintain per-agent reputation, accept attestations
and abuse reports, optionally support stake.

## Interface

```python
class Trust(Protocol):
    async def score(self, agent: AgentId) -> ReputationScore: ...
    async def attest(self, agent: AgentId, claim: Claim) -> Attestation: ...
    async def report(self, agent: AgentId, evidence: Evidence) -> None: ...
    async def stake(self, agent: AgentId, amount: int) -> None: ...
```

Full definition: [`nest_core/layers/trust.py`](../../packages/nest-core/nest_core/layers/trust.py).

## Default plugin

`score_average` — running mean of feedback scores. No Sybil resistance,
no decay, no stake economics.

Source: [`nest_plugins_reference/trust/score_average.py`](../../packages/nest-plugins-reference/nest_plugins_reference/trust/score_average.py).

The `reputation` scenario exercises this layer — 16 honest + 4
malicious + 1 observer that samples cheat reports probabilistically.

## `agent_receipts` — receipt-corroborated, collusion-resistant reputation

Derives reputation from **cross-signed receipts** of real interactions
instead of self-asserted feedback. A receipt builds reputation only if
its Ed25519 issuer signature verifies, a *distinct* counterparty
co-signed the same interaction, and the receipt does not sit inside an
isolated collusion component (Tarjan SCC severance over the
corroboration graph) — so a wash-trading ring collapses to score ~0
while honest agents keep their corroborated score.

Source: [`nest_plugins_reference/trust/agent_receipts.py`](../../packages/nest-plugins-reference/nest_plugins_reference/trust/agent_receipts.py).
Scenario: `receipt_reputation` (honest anchor + isolated 4-agent ring +
byzantine co-signers).

## `parc` — portable reputation credentials

Reputation elsewhere in this layer dies with the run. `parc` extends
`agent_receipts` with **portability**: it exports an agent's receipt
ledger as a W3C-Verifiable-Credential-shaped document (a
`behavioral_merkle_root` committing to the carried receipts plus
`nanda-rep/0.2` scores recomputable from them), signed **through the
identity layer** (`ed25519_rotating`), and admits presented credentials
at the border of a new trust domain by *recomputing rather than
trusting*:

- the Merkle root and scores are re-derived from the carried receipts —
  an issuer-inflated-then-re-signed score passes proof verification and
  is still rejected (**a valid signature is not admission**);
- the proof is checked against the issuer's key-rotation window *as-of*
  the credential's `validFrom` tick, so a credential signed with a
  rotated-out key is rejected;
- the presenter must *be* the credential subject (stolen credentials
  are rejected);
- an inline single-subject ledger is a star graph and cannot show an
  N-party ring, so the gate also re-runs whole-graph collusion
  severance over the originating domain's **published ledger**.

**Selective disclosure.** A holder need not show a verifier the whole
ledger: `build_presentation` packages chosen receipts, each with a
Merkle inclusion proof against the credential's signed
`behavioral_merkle_root`, and `verify_presentation` confirms every
disclosed receipt is committed under that root — and that each proof's
`leaf_count` equals the signed `receipt_count`, the bound on the
undisclosed remainder — without needing the rest of the ledger. Scores
are **not** recomputed from a disclosed subset: the reputation
aggregate is a whole-graph property (collusion severance needs every
edge), so the signed score stands — re-deriving it from a hand-picked
subset is exactly the cherry-picking this split forbids. Full-ledger
recomputation remains `admit`'s job.

Source: [`nest_plugins_reference/trust/parc.py`](../../packages/nest-plugins-reference/nest_plugins_reference/trust/parc.py).
Scenario: `parc_migration` (two trust domains in one run; forged,
replayed, stale-key, inflated, and wash-ring credentials each denied
with a typed reason).

## `aae_permit_gate` — pre-action authorization with signed denial receipts

Every other trust plugin scores what agents **did**. `aae_permit_gate`
decides what an agent **may do**, before it does it — and signs the
verdict either way. A well-reputed agent attempting an unauthorized
action sails through every post-hoc reputation layer on its record
alone; this gate answers the request before it runs, and a refusal it
returns is a signed, first-class receipt — provable from the envelope
chain by anyone, not a silent absence. The refusal does not consult
reputation, so no amount of prior good standing outranks it; the
`rogue_trusted_agent` scenario below turns that returned verdict into a
blocked action and proves it.

Source:
[`trust/aae_permit_gate.py`](../../packages/nest-plugins-reference/nest_plugins_reference/trust/aae_permit_gate.py)
· envelope format:
[`trust/aae_envelope.py`](../../packages/nest-plugins-reference/nest_plugins_reference/trust/aae_envelope.py).

**The permit envelope.** Before an action runs, the gate evaluates it
against a declarative policy table and issues a signed JSON object — a
*pre-action envelope* — recording the verdict. Eight fields, no more:

| Field | Meaning |
|---|---|
| `agent_id` | The acting agent's town identity (whatever string the identity layer yields). |
| `action` | `{verb, resource, params}` — what the agent intends to do. |
| `policy_id` | Which policy rule the action was evaluated against. |
| `outcome` | `"authorized"` \| `"denied"` \| `"conditional"` — denials are first-class. |
| `prev_hash` | Hash of this agent's previous envelope, or `null` — a per-agent causal chain. |
| `issued_at` | Evaluation time (RFC 3339). |
| `sig` | Ed25519 signature over the canonical envelope (sorted keys, compact separators) minus `sig`. |
| `pubkey` | The verification key. |

`permits(envelope)` is `True` only for `"authorized"`; `"conditional"`
means authorized subject to the caller honoring the stated condition
params, and is not itself permission.

**How agents consult it.** The engine does not intercept actions, so
gating is a scenario contract: an agent calls `evaluate(...)` before
acting and proceeds only on an authorized envelope. A plugin without an
`evaluate` method (like `score_average`) is consulted the old way — as a
score — so scenarios stay drop-in. This is the standard capability-gate
pattern (`hasattr(trust, "evaluate")`).

**Quickstart.**

```python
from nest_plugins_reference.trust.aae_permit_gate import AAEPermitGate, permits

gate = AAEPermitGate(
    policy=[
        {"role": "resident", "verb": "read", "resource": "town/*", "effect": "authorized"},
        {"agent": "*", "verb": "spend", "resource": "town/treasury", "effect": "denied"},
    ],
    roles={"veteran": "resident"},
    key_seed=bytes(32),  # deterministic; supply your own
)
env = await gate.evaluate("veteran", "spend", "town/treasury", {}, now="2026-07-04T00:00:00Z")
assert env["outcome"] == "denied" and not permits(env)   # signed denial receipt
```

**The `rogue_trusted_agent` scenario.** One agent earns a strong
reputation through many in-policy actions, then reaches for the treasury.
Run it under `aae_permit_gate` and the reach is refused before it runs:

```
exec:veteran:read:town/events                       <- reputation accrued (8th in-policy action)
rogue_attempt:veteran:spend:town/treasury
permit:veteran:spend:town/treasury:denied:84773277  <- signed denial
blocked:veteran:spend:town/treasury                 <- never executes
```

Swap one line — `trust: score_average` — and reputation buys the
treasury:

```
rogue_attempt:veteran:spend:town/treasury
exec:veteran:spend:town/treasury                    <- the rogue action executes
```

The adversarial validator `rogue_trusted_agent_blocked` FAILS on the
first trace and PASSES on the second — with no crash on either.

**Trace-line protocol.**
`permit:<agent>:<verb>:<resource>:<outcome>:<envelope_hash_prefix8>`.

**Relationship to Agent Action Capsules (#32).** Capsules and permit
envelopes are two halves of one accountability story, on opposite sides
of the action. A capsule seals a record of what *happened*; a permit
envelope signs a decision about what *may* happen. They compose as an
authorization layer over a transparency layer: when the `capsule-emit`
package is present and anchoring is enabled, each permit — authorization
or denial — is sealed to the capsule ledger under a `permit.granted` /
`permit.denied` namespace so it never reads as an executed action. A
denial that is anchored is evidence that the gate worked. Anchoring is a
no-op when the package is absent; there is no hard dependency in either
direction.

**Boundary.** Chain integrity is bound by hash commitment
(`envelope_hash` covers the signature and key), not by pinning an agent
to a fixed key — binding an identity to a stable key across its chain is
the identity layer's job (see `ed25519_rotating`), which this gate
composes with rather than reimplements. `attest` signs a claim with the
gate key; `report` records evidence a future policy may reference;
`stake` is a documented parity no-op.

## `bonded_trust` : a Sybil-resistant **trust root**

With `bonded_trust`, reputation influence is bounded by a *scarce, verified* resource, not identity count. Both `score_average` and the EigenTrust plugins ration influence among identities that already exist; none stops the free *minting* of them, and `did_key` mints for free. `bonded_trust` moves the Sybil anchor out of the identity layer into a metered bond — Douceur (2002) taken seriously: the resource must be scarce and verified, never self-asserted.

**Mechanism.**
- **Self-bond gate.** An identity scores the untrusted floor (`0.0`) until it *reserves* a bond through a `StakeLedger`. A broke Sybil bidding `bond:1000000` gets nothing.
- **Reporter-weighting.** Reports weigh by the reporter's bond; unbonded reporters and self-reports carry zero. Splitting a budget across K identities buys no more influence than concentrating it.

### Pluggable scarcity anchor

The scarce resource isn't baked in — `StakeLedger` (one method, `reserve(agent, amount) -> int`) makes the anchor **swappable**, so the same trust root runs on credits, CPU, consensus, or any metered quantity. This relocation is the contribution; the bond-weighting is deliberately simple.

| ledger | scarcity |
|---|---|
| `CreditBackedLedger` | payments-layer credits |
| `ProofOfWorkLedger` | sha256 PoW (`difficulty_bits`) |
| `SelfDeclaredLedger` *(default)* | none — **test only** |

Any scarce, verified quantity works — not just raw resources. A BBS+ **capability badge** (`BadgeBackedLedger`, phase-2 `captcha4agents`) or an anchored **PARC** reputation standing (`NotaryBackedLedger`) fits the same seam; both are planned, and the PR sketches how they compose.

### Quickstart

```python
from nest_plugins_reference.trust.bonded_trust import BondedTrust
from nest_plugins_reference.trust.stake_ledgers import CreditBackedLedger

trust = BondedTrust(identity, ledger=CreditBackedLedger({AgentId("a1"): 100}), min_bond=1)
```

Or in a scenario: `trust: bonded_trust`.

### The `sybil_bond` scenario

20 unbonded Sybils cross-endorse against 5 bonded honest traders. Swap `trust:`:

```
score_average → Sybils 1.0 → FAIL      bonded_trust → Sybils 0.0 → PASS
```

Three validators FAIL on the baseline, PASS on `bonded_trust`:
`sybil_bond_no_free_trust` (no unbonded Sybil above the floor) ·
`sybil_bond_honest_trusted` (honest rank strictly above Sybils) ·
`sybil_bond_attempts_rejected` (Sybils bid and were rejected — enforced, not assumed).

### Composition

- **identity** — `bonded_trust` exists *because* `did_key` mints identities for free; it doesn't harden identity, it makes free identities inert.
- **payments** — `CreditBackedLedger` draws its scarcity straight from the payments layer's balances.
- **other trust plugins** — orthogonal to graph reputation (EigenTrust): `bonded_trust` *gates* who can hold nonzero influence; a transitive-reputation algorithm can run over the bonded set.

### Boundary

Spend *real* bond, gain real influence — intended ("most at stake, most say"), bounded by spend and independent of identity count. Free Sybils get `0.0`.

**Source:** [`bonded_trust.py`](../../packages/nest-plugins-reference/nest_plugins_reference/trust/bonded_trust.py) ·
[`stake_ledgers.py`](../../packages/nest-plugins-reference/nest_plugins_reference/trust/stake_ledgers.py) ·
[`sybil_bond.yaml`](../../scenarios/sybil_bond.yaml) · `sybil_bond_*` in
[`validators.py`](../../packages/nest-core/nest_core/validators.py)

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under entry point group `nest.plugins.trust`.

Good fits to test here: EigenTrust-style transitive reputation, proof-of-stake reputation, decaying scores, attestation graphs.
