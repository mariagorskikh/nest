# Registry layer

**What it does.** Let agents publish an `AgentCard` describing
themselves and discover other agents by `Query`.

## Interface

```python
class Registry(Protocol):
    async def register(self, card: AgentCard) -> None: ...
    async def lookup(self, query: Query) -> list[AgentCard]: ...
    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]: ...
    async def deregister(self, agent: AgentId) -> None: ...
```

Full definition: [`nest_core/layers/registry.py`](../../packages/nest-core/nest_core/layers/registry.py).

## Default plugin

`in_memory` — dict-based; no persistence, no replication.

Source: [`nest_plugins_reference/registry/in_memory.py`](../../packages/nest-plugins-reference/nest_plugins_reference/registry/in_memory.py).

## Byzantine-resistant plugin: `byzantine_gossip`

`byzantine_gossip` -- a hardened counterpart to the merged `gossip` plugin
(eventually-consistent, partition-honest discovery). `gossip` assumes every
participant is honest: no forged cards, no publisher signing two conflicting
writes at the same version, no coordinated attempt to starve a victim's
random peer sampling. `byzantine_gossip` drops that assumption on three
specific fronts:

1. **Signed cards, re-verified on every gossip hop, not just at
   registration.** Every `register`/`deregister` signs
   `(content, version, tombstone)` with the agent's `Identity`; every
   `handle_gossip` `OP_PUSH` re-verifies that signature before merging, so an
   unsigned, impersonating, forged, or replayed-under-a-different-version/
   tombstone card is dropped and logged in `rejections`, never applied. This
   extends prior art `#67` (registration-only signing): `#67` checks a card
   once, at its source: nothing downstream re-checks it as it hops through
   the mesh, so a compromised relay can still poison every honest view it
   touches.
2. **Signed-equivocation detection + permanent quarantine.** A byzantine
   publisher can validly sign two *different* cards at the same version --
   both pass every signature check in isolation, so `#67`-style
   registration-signing cannot catch it. `byzantine_gossip` witnesses every
   verified write against `(publisher, version)`; a second, verified,
   content-differing write at the same key proves the publisher itself is
   byzantine. It is quarantined on the spot -- evicted from the local view,
   recorded in `equivocations`, and every later card from it (honest-looking
   or not) is refused permanently, on this registry instance, with no
   re-trust mechanism.
3. **Eclipse-resistant peer sampling.** `gossip`'s `gossip_round` draws
   fanout peers uniformly at random every round, with no memory between
   rounds -- a large-enough byzantine peer fraction (or an unlucky draw) can
   exclude a victim's only honest peer indefinitely. `byzantine_gossip`
   splits each round's draw into a deterministic **anchor set** (the
   lexicographically-first half of the peer list by `AgentId`) plus a
   seeded-random remainder, so a fixed, stable contact is retried every
   round instead of only when the dice happen to land right. This is a
   **heuristic, not a proof** -- see
   [`VERIFICATION.md`](../../packages/nest-plugins-reference/nest_plugins_reference/registry/VERIFICATION.md)
   for the topology it cannot defend.

Source:
[`nest_plugins_reference/registry/byzantine_gossip.py`](../../packages/nest-plugins-reference/nest_plugins_reference/registry/byzantine_gossip.py).

### Validators

[`validators/registry_byzantine_validators.py`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/registry_byzantine_validators.py)
ships three adversarial checks, each FAILing against the reference
`gossip`/`in_memory` plugins and PASSing against `byzantine_gossip`:

- `check_no_forged_card_in_view` -- every card in an honest view must carry
  a signature that verifies under its claimed publisher. An entry that
  cannot be checked at all (missing card or identity) is reported as
  `unverifiable` and counted as a FAIL, never a silent pass.
- `check_no_equivocation_accepted` -- whenever two honest agents' views
  disagree on the content behind the same `(publisher, version)` key, at
  least one agent's `equivocations` ledger must record it.
- `check_no_eclipse` -- every honest agent's view must hold at least one
  live card from another honest publisher (the weaker "reached one," not
  "reached every one," bar -- matching what the anchor heuristic actually
  guarantees).

### Demo scenarios

Three scenarios under [`scenarios/`](../../scenarios/), deterministic under
seeds 42, 7, 1337:

- `gossip_byzantine_forgery.yaml` -- 16 honest agents + 4 forgers injecting
  unsigned/impersonated/forged phantom cards.
- `gossip_signed_equivocation.yaml` -- **the novelty proof**: one publisher
  genuinely signs two conflicting cards at the same version and delivers
  them to two honest groups in opposite order.
- `gossip_eclipse.yaml` -- 2 honest agents drowned in 40 inert byzantine
  "black hole" peers.

```bash
uv sync

# Full byzantine_gossip test suite (unit + properties + scenario gate):
uv run pytest packages/nest-plugins-reference/tests/test_byzantine_gossip.py \
              packages/nest-plugins-reference/tests/test_byzantine_gossip_properties.py \
              packages/nest-plugins-reference/tests/test_registry_byzantine_validators.py \
              packages/nest-plugins-reference/tests/test_byzantine_gossip_scenario.py -v

# Run one scenario directly:
uv run nest run scenarios/gossip_signed_equivocation.yaml

# The whole CI gate:
make ci-local
```

See
[`VERIFICATION.md`](../../packages/nest-plugins-reference/nest_plugins_reference/registry/VERIFICATION.md)
for the full FAIL/PASS matrix (validators x plugins x scenarios) and every
honest limitation found while building this plugin.

## Capability-conformance plugin: `verified_capabilities`

`verified_capabilities` -- closes a gap none of the identity-focused registry
plugins touch. `AgentCard.capabilities` is a bare, self-asserted `list[str]`;
`ed25519_rotating` and `byzantine_gossip` verify who published a card and that
its content wasn't forged in transit, and `agent_receipts`/`score_average`
score an agent's reputation *overall* -- but nothing checks a specific
capability claim against whether the agent has ever actually fulfilled it. An
agent can register `capabilities=["sell"]` with a perfectly valid signature
and stay discoverable via that claim forever, even if it never completes a
single sale. This is the exact gap A2A v1.0's signed Agent Cards and NANDA's
Verified AgentFacts layer both name and neither closes: a signature proves
the publisher, not the capability.

`verified_capabilities` wraps an inner registry and tracks
fulfillment/defection evidence **per `(agent_id, capability)` pair**, not per
agent:

* **Bootstrap allowance.** A pair with no evidence yet is never excluded --
  discovery cannot punish a claim nobody has tested.
* **Per-capability exclusion.** Once a pair accumulates `defection_threshold`
  defections (default 1, justified against this scenario's zero
  message-drop rate), `lookup` stops returning that agent for queries naming
  that capability. A defection on `"sell"` does not affect the same agent's
  `"deliver"` capability -- the gate is on the claim, not the identity.
* **Re-admission, not blacklisting.** A single `report_fulfillment` call
  resets that pair's defection count to zero. This is a documented
  trade-off, not an oversight: an attacker who fulfills once per
  `defection_threshold - 1` defections evades exclusion indefinitely.
  Closing that requires a windowed or decaying counter, out of scope here.

`report_fulfillment`/`report_defection` are not part of the `Registry`
Protocol -- callers (agents, scenario factories, tests) call them directly on
the concrete instance, the same way `GossipRegistry` exposes `gossip_round`
beyond the interface it implements.

Source:
[`nest_plugins_reference/registry/verified_capabilities.py`](../../packages/nest-plugins-reference/nest_plugins_reference/registry/verified_capabilities.py).

### Validator

[`validators/capability_validators.py`](../../packages/nest-plugins-reference/nest_plugins_reference/validators/capability_validators.py)'s
`check_capability_conformance` asserts the one property that actually
distinguishes a real skill from an advertised one: after enough observed
defections, the registry must stop returning the claimant for that
capability. Registry `lookup` calls aren't traced (`nest_core.sim.simulator`
traces send/broadcast/deliver/receive events only), so this validator isn't a
trace parser -- it runs directly against `ScenarioRunner.resolved_plugins["registry"]`,
the same pattern `registry_byzantine_validators`/`gossip_validators` use for
properties that live in plugin state rather than message content. It checks
two things together, so a gate that blocks everyone can't pass by accident:
no spoofer is still discoverable, and every honest seller still is.

### Demo scenario

[`scenarios/capability_spoofing.yaml`](../../scenarios/capability_spoofing.yaml) --
3 honest sellers, 2 always-silent spoofers, 1 bait-and-switch seller (fulfills
once, then goes silent), 5 buyers. Buyers discover sellers via
`registry.lookup(Query(capabilities=["sell"]))`, send one outstanding `buy:`
at a time, and self-schedule a `TIMEOUT:<round>` tick; a `sold:` response
before the timeout reports a fulfillment, the timeout firing first reports a
defection. Deterministic under seeds 42, 7, 1337, with a
byte-identical-trace determinism test.

Literal output, same scenario YAML, only `layers.registry` overridden:

```
registry='in_memory'             passed=False detail="still discoverable for 'sell': ['baitswitch-0', 'spoofer-0', 'spoofer-1']"
registry='verified_capabilities' passed=True  detail="3 spoofer(s) excluded from 'sell', 3 honest agent(s) still discoverable"
```

```bash
uv sync

# Unit + scenario test suite:
uv run pytest packages/nest-plugins-reference/tests/test_verified_capabilities.py \
              packages/nest-plugins-reference/tests/test_capability_spoofing_scenario.py -v

# Run the scenario directly:
uv run nest run scenarios/capability_spoofing.yaml

# The whole CI gate:
make ci-local
```

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.registry`.

Good fits to test here: DHT-backed registries, gossip-based discovery,
filtering / capability queries, registry consensus protocols.
