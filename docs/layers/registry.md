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

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.registry`.

Good fits to test here: DHT-backed registries, gossip-based discovery,
filtering / capability queries, registry consensus protocols.
