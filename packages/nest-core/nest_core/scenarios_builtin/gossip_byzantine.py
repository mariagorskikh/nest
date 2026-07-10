# SPDX-License-Identifier: Apache-2.0
"""Byzantine gossip driver agents + three adversarial scenario factories.

``nest_core.scenarios_builtin.gossip_registry`` drives the honest,
partition-honest ``GossipRegistry``/``ByzantineGossipRegistry`` plugins: every
agent registers its own card and periodically runs a gossip round. That
driver assumes every participant is honest. This module adds the flagged
*byzantine* driver agents Task 6 needs to actually exercise the moats Tasks
2-4 built — forged/impersonated cards, signed-equivocation, and eclipse — end
to end inside the simulator, plus the three scenario factories that wire
honest and byzantine agents together over one shared
``nest_plugins_reference.registry.gossip.GossipNetwork``.

Both the reference ``gossip`` plugin and the ``byzantine_gossip`` plugin can
run the *same* scenario YAML (only ``layers.registry`` differs) because each
factory reads ``plugins["registry"]`` — the class the runner already resolved
from that field — rather than hardcoding an import, and instantiates it with
an ``Identity`` only when its constructor actually asks for one (via
``inspect.signature``). This is what lets Task 6's gate run one scenario
under both plugins and see the validators diverge.

Three attacks, three factories:

* ``gossip_byzantine_forgery_factory`` — ``forger`` agents ``ctx.broadcast`` a
  hand-crafted ``OP_PUSH`` payload once, at start, claiming fabricated
  ("phantom") agent ids with a missing, impersonating, or forged signature.
  ``gossip`` merges all three on sight (no verification at all);
  ``byzantine_gossip`` verifies and drops every one before ``_apply`` — see
  ``byzantine_gossip.py``'s Task 2 section.
* ``gossip_signed_equivocation_factory`` — **the novelty proof**: the single
  ``equivocator`` agent genuinely signs two *different* cards at the *same*
  version with its own real key (both individually verify — nothing here is
  forged), then sends them to two peer groups in opposite arrival order so
  the reference plugin's peers *actually disagree* about the equivocator's
  content instead of just uniformly picking whichever one happened to be
  first everywhere. ``gossip``'s last-writer-wins keeps the first arrival
  and drops the rest silently, with no ledger anywhere recording the
  conflict; ``byzantine_gossip``'s witness map (Task 3) catches the *second*
  arrival at every recipient, quarantines the publisher, and evicts it from
  every honest view.
* ``gossip_eclipse_factory`` — a small honest pair surrounded by a majority
  of totally inert ``byzantine`` agents (``InertByzantineDriverAgent``: never
  registers, never gossips, never answers). The honest pair's ids are chosen
  to sort lexicographically ahead of every byzantine id, so
  ``byzantine_gossip``'s deterministic anchor half of
  ``_sample_eclipse_resistant`` always includes the other honest agent;
  ``gossip``'s pure-uniform sampling has no such guarantee and, for the
  seeds this scenario is tuned against, never independently draws the other
  honest agent within the scenario's short duration.

Example::

    from nest_core.runner import ScenarioRunner
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/gossip_byzantine_forgery.yaml"))
    await runner.run()
"""

from __future__ import annotations

import inspect
import json
from typing import TYPE_CHECKING, Any

from nest_plugins_reference.registry.byzantine_gossip import canonical_write_bytes
from nest_plugins_reference.registry.gossip import (
    DEFAULT_FANOUT,
    GOSSIP_PREFIX,
    OP_PUSH,
    GossipNetwork,
    _WriteTag,  # pyright: ignore[reportPrivateUsage]
)

from nest_core.scenarios_builtin.gossip_registry import (
    DEFAULT_GOSSIP_INTERVAL,
    GossipDriverAgent,
)
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId

if TYPE_CHECKING:
    from nest_core.scenario import ScenarioConfig

_PushEntry = tuple[AgentCard, _WriteTag, bool]


# ---------------------------------------------------------------------------
# Wire helpers (structural copy of gossip.py/byzantine_gossip.py's private
# push codec -- duplicated here instead of importing the private
# ``_encode_push`` across the nest_core / nest_plugins_reference boundary,
# mirroring how ``test_byzantine_gossip.py`` hand-encodes ``OP_PUSH``
# payloads for the same reason).
# ---------------------------------------------------------------------------


def _encode_push(entries: list[_PushEntry]) -> bytes:
    """Encode ``entries`` as an ``OP_PUSH`` body, byte-identical to the plugins' own codec.

    Example::

        body = _encode_push([(card, tag, False)])
    """
    obj = [
        {
            "card": card.model_dump(mode="json"),
            "version": tag.version,
            "publisher": str(tag.publisher_id),
            "tombstone": tombstone,
        }
        for card, tag, tombstone in entries
    ]
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _push_payload(entries: list[_PushEntry]) -> bytes:
    """Wrap ``entries`` in a full ``GOSSIP_PREFIX + OP_PUSH`` wire message.

    Example::

        payload = _push_payload([(card, tag, False)])
    """
    return GOSSIP_PREFIX + OP_PUSH + _encode_push(entries)


def _sign(card: AgentCard, version: int, tombstone: bool, identity: Any) -> AgentCard:
    """Return a copy of ``card`` with ``metadata["sig"]`` from ``identity`` over the write.

    Structural copy of ``byzantine_gossip._sign_card`` (private, not
    imported across the package boundary): signs
    ``canonical_write_bytes(card, version, tombstone)`` and stores the
    signature hex-encoded, exactly as the plugin itself does when
    ``register``/``deregister`` sign a real write.

    Example::

        signed = _sign(card, 1, False, identity)
    """
    sig = identity.sign(canonical_write_bytes(card, version, tombstone))
    metadata = dict(card.metadata)
    metadata["sig"] = {
        "signer": str(sig.signer),
        "value": sig.value.hex(),
        "algorithm": sig.algorithm,
    }
    return card.model_copy(update={"metadata": metadata})


def _build_identities(
    identity_cls: type, agent_ids: list[AgentId], seed: bytes
) -> dict[AgentId, Any]:
    """Build one ``identity_cls`` instance per agent, cross-registering every peer's public key.

    Every agent gets the *same* ``seed``, so a peer that derives another
    agent's public key from ``(seed, that agent's id)`` always matches what
    that agent's own instance would produce -- mirrors
    ``bft_hotstuff.instantiate_identity``/``marketplace``'s identity-wiring
    block. Built for **every** id passed in, honest and byzantine alike: a
    byzantine agent that equivocates still needs a *real* keypair for its
    signature to genuinely verify (that is the whole point of the
    all-signed-equivocation scenario).

    Example::

        identities = _build_identities(DidKeyIdentity, [AgentId("a"), AgentId("b")], b"seed")
    """
    identities: dict[AgentId, Any] = {aid: identity_cls(aid, seed=seed) for aid in agent_ids}
    for aid, ident in identities.items():
        if not hasattr(ident, "register_peer"):
            continue
        for peer_id, peer_ident in identities.items():
            if peer_id != aid:
                ident.register_peer(peer_id, peer_ident.public_key)
    return identities


def _build_registries(
    registry_cls: type,
    network: GossipNetwork,
    agent_ids: list[AgentId],
    identities: dict[AgentId, Any],
) -> dict[AgentId, Any]:
    """Instantiate ``registry_cls`` for every honest agent, passing ``identity`` only if needed.

    ``GossipRegistry.__init__(agent_id, network)`` and
    ``ByzantineGossipRegistry.__init__(agent_id, network, identity)`` are the
    two shapes this needs to support without hardcoding either class name --
    ``inspect.signature`` decides which constructor shape applies, which is
    what lets one factory run the same scenario under both plugins.

    Example::

        registries = _build_registries(GossipRegistry, network, [AgentId("a")], {})
    """
    needs_identity = "identity" in inspect.signature(registry_cls.__init__).parameters
    registries: dict[AgentId, Any] = {}
    for aid in agent_ids:
        registries[aid] = (
            registry_cls(aid, network, identities[aid])
            if needs_identity
            else registry_cls(aid, network)
        )
    return registries


def _roles_by_name(config: ScenarioConfig) -> dict[str, list[AgentId]]:
    """Group ``config.agents.roles`` into ``{role_name: [agent ids]}``.

    Agent ids follow the codebase-wide ``f"{role.name}-{i}"`` convention (see
    ``gossip_registry_factory``), so role naming doubles as the id's
    lexicographic sort prefix -- used by the eclipse factory to guarantee an
    honest agent sorts ahead of every byzantine one.

    Example::

        roles = _roles_by_name(config)
        honest_ids = roles["honest"]
    """
    out: dict[str, list[AgentId]] = {}
    for role in config.agents.roles:
        out[role.name] = [AgentId(f"{role.name}-{i}") for i in range(role.count)]
    return out


# ---------------------------------------------------------------------------
# Scenario 1: forgery -- unsigned / impersonated / forged cards
# ---------------------------------------------------------------------------


def _forged_entries(phantom_prefix: str, forger_id: AgentId) -> list[_PushEntry]:
    """Build three forged/unsigned/impersonated cards under fabricated ("phantom") ids.

    None of these ids ever legitimately registered, so there is no genuine
    card to collide with -- purely additive poisoning:

    * ``{phantom_prefix}-missing``: no ``metadata["sig"]`` at all.
    * ``{phantom_prefix}-mismatch``: signature claims signer ``forger_id``
      while ``card.agent_id`` names the phantom -- impersonation.
    * ``{phantom_prefix}-badsig``: signature claims the right signer but the
      bytes are garbage (never produced by any real key) -- forgery.

    Example::

        entries = _forged_entries("phantom-0", AgentId("forger-0"))
    """
    tag_version = 1

    missing_id = AgentId(f"{phantom_prefix}-missing")
    missing_card = AgentCard(agent_id=missing_id, name="phantom (missing sig)")

    mismatch_id = AgentId(f"{phantom_prefix}-mismatch")
    mismatch_card = AgentCard(
        agent_id=mismatch_id,
        name="phantom (impersonated)",
        metadata={
            "sig": {"signer": str(forger_id), "value": "00" * 32, "algorithm": "sim-rsa-sha256"}
        },
    )

    badsig_id = AgentId(f"{phantom_prefix}-badsig")
    badsig_card = AgentCard(
        agent_id=badsig_id,
        name="phantom (forged sig)",
        metadata={
            "sig": {"signer": str(badsig_id), "value": "ff" * 32, "algorithm": "sim-rsa-sha256"}
        },
    )

    return [
        (missing_card, _WriteTag(version=tag_version, publisher_id=missing_id), False),
        (mismatch_card, _WriteTag(version=tag_version, publisher_id=mismatch_id), False),
        (badsig_card, _WriteTag(version=tag_version, publisher_id=badsig_id), False),
    ]


class ForgerDriverAgent(StateMachineAgent):
    """Byzantine agent: broadcasts unsigned/impersonated/forged cards once, at start.

    Never registers a card of its own and never runs a gossip round -- its
    only action is one ``ctx.broadcast`` of a hand-built ``OP_PUSH`` payload
    so delivery is immediate and does not depend on any peer's random
    sampling. See ``_forged_entries`` for the three cards it injects.

    Example::

        agent = ForgerDriverAgent(AgentId("forger-0"), phantom_prefix="phantom-0")
    """

    def __init__(self, agent_id: AgentId, phantom_prefix: str) -> None:
        self._id = agent_id
        self._phantom_prefix = phantom_prefix

    async def on_start(self, ctx: AgentContext) -> None:
        """Broadcast the forged/unsigned/impersonated cards.

        Example::

            await agent.on_start(ctx)
        """
        entries = _forged_entries(self._phantom_prefix, self._id)
        await ctx.broadcast(_push_payload(entries))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """No-op: a forger never participates in honest gossip.

        Example::

            await agent.on_message(ctx, sender, payload)
        """


def gossip_byzantine_forgery_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build the fleet for ``scenarios/gossip_byzantine_forgery.yaml``.

    Roles: ``honest`` (runs the normal ``GossipDriverAgent`` over a real
    per-agent registry resolved from ``plugins["registry"]``) and ``forger``
    (``ForgerDriverAgent``, no registry of its own). Stashes
    ``_byzantine_registries``/``_byzantine_identities``/``_honest_ids``/
    ``_byzantine_ids`` on ``plugins`` for the gate test to build validator
    evidence from after the run.

    Example::

        agents = gossip_byzantine_forgery_factory(config, plugins)
    """
    task_cfg = config.task.config or {}
    gossip_interval = float(task_cfg.get("gossip_interval", DEFAULT_GOSSIP_INTERVAL))
    seed = str(task_cfg.get("key_seed", "gossip-byzantine-forgery")).encode()

    roles = _roles_by_name(config)
    honest_ids = roles.get("honest", [])
    forger_ids = roles.get("forger", [])
    all_ids = [*honest_ids, *forger_ids]

    identity_cls = plugins["identity"]
    registry_cls = plugins["registry"]
    identities = _build_identities(identity_cls, all_ids, seed)
    network = GossipNetwork(agent_ids=all_ids)
    registries = _build_registries(registry_cls, network, honest_ids, identities)

    plugins["_agent_plugins"] = {aid: {"registry": reg} for aid, reg in registries.items()}
    plugins["_gossip_network"] = network
    plugins["_byzantine_registries"] = registries
    plugins["_byzantine_identities"] = identities
    plugins["_honest_ids"] = set(honest_ids)
    plugins["_byzantine_ids"] = set(forger_ids)

    agents: dict[AgentId, Any] = {
        aid: GossipDriverAgent(
            agent_id=aid, capabilities=["gossip_peer"], gossip_interval=gossip_interval
        )
        for aid in honest_ids
    }
    for i, aid in enumerate(forger_ids):
        agents[aid] = ForgerDriverAgent(agent_id=aid, phantom_prefix=f"phantom-{i}")
    return agents


# ---------------------------------------------------------------------------
# Scenario 2: signed equivocation -- THE NOVELTY PROOF
# ---------------------------------------------------------------------------


class EquivocatorDriverAgent(StateMachineAgent):
    """Byzantine agent: validly signs two conflicting cards at one version, splits delivery.

    Both cards are signed with this agent's own real key over
    ``canonical_write_bytes(card, version, tombstone=False)`` -- neither is
    forged, mutated, or impersonated; every check ``byzantine_gossip`` Task 2
    (and a registration-only scheme like ``#67``) runs on either card in
    isolation passes. The only way to catch this is comparing the two
    writes to each other -- see ``byzantine_gossip``'s Task 3 witness map.

    ``group_a`` receives ``[card_1, card_2]`` in one ``OP_PUSH`` payload;
    ``group_b`` receives ``[card_2, card_1]`` -- the *opposite* order. Under
    ``gossip``'s last-writer-wins, group A's registries keep card_1 (the
    first arrival wins, the second is dropped by ``existing.tag >=
    tag``) while group B's keep card_2 -- a genuine content split between
    two honest agents' views, with no ledger anywhere recording it. Under
    ``byzantine_gossip``, every recipient's witness map sees both cards
    (regardless of order), detects the conflict on the second one, records
    ``(agent_id, version)`` in ``equivocations``, and evicts the publisher
    from its view.

    Example::

        agent = EquivocatorDriverAgent(
            AgentId("equivocator-0"), network=net, identity=ident,
            group_a=[AgentId("honest-0")], group_b=[AgentId("honest-1")],
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        network: GossipNetwork,
        identity: Any,
        group_a: list[AgentId],
        group_b: list[AgentId],
    ) -> None:
        self._id = agent_id
        self._network = network
        self._identity = identity
        self._group_a = group_a
        self._group_b = group_b

    async def on_start(self, ctx: AgentContext) -> None:
        """Sign both conflicting cards and push them to each group in opposite order.

        Example::

            await agent.on_start(ctx)
        """
        version = self._network.next_version(self._id)
        tag = _WriteTag(version=version, publisher_id=self._id)
        card_1 = _sign(
            AgentCard(agent_id=self._id, name=str(self._id), capabilities=["sell"]),
            version,
            False,
            self._identity,
        )
        card_2 = _sign(
            AgentCard(agent_id=self._id, name=str(self._id), capabilities=["buy"]),
            version,
            False,
            self._identity,
        )
        payload_a = _push_payload([(card_1, tag, False), (card_2, tag, False)])
        payload_b = _push_payload([(card_2, tag, False), (card_1, tag, False)])
        for peer in self._group_a:
            await ctx.send(peer, payload_a)
        for peer in self._group_b:
            await ctx.send(peer, payload_b)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """No-op: the equivocator never participates in honest gossip beyond its one push.

        Example::

            await agent.on_message(ctx, sender, payload)
        """


def gossip_signed_equivocation_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build the fleet for ``scenarios/gossip_signed_equivocation.yaml`` (the novelty proof).

    Roles: ``honest`` (normal ``GossipDriverAgent``) and ``equivocator``
    (exactly one, by convention -- ``EquivocatorDriverAgent``). Honest agents
    are split in half (by sorted id) into the two delivery-order groups; see
    ``EquivocatorDriverAgent`` for why the split matters.

    Example::

        agents = gossip_signed_equivocation_factory(config, plugins)
    """
    task_cfg = config.task.config or {}
    gossip_interval = float(task_cfg.get("gossip_interval", DEFAULT_GOSSIP_INTERVAL))
    seed = str(task_cfg.get("key_seed", "gossip-signed-equivocation")).encode()

    roles = _roles_by_name(config)
    honest_ids = roles.get("honest", [])
    equivocator_ids = roles.get("equivocator", [])
    all_ids = [*honest_ids, *equivocator_ids]

    identity_cls = plugins["identity"]
    registry_cls = plugins["registry"]
    identities = _build_identities(identity_cls, all_ids, seed)
    network = GossipNetwork(agent_ids=all_ids)
    registries = _build_registries(registry_cls, network, honest_ids, identities)

    plugins["_agent_plugins"] = {aid: {"registry": reg} for aid, reg in registries.items()}
    plugins["_gossip_network"] = network
    plugins["_byzantine_registries"] = registries
    plugins["_byzantine_identities"] = identities
    plugins["_honest_ids"] = set(honest_ids)
    plugins["_byzantine_ids"] = set(equivocator_ids)

    sorted_honest = sorted(honest_ids)
    half = max(1, len(sorted_honest) // 2)
    group_a = sorted_honest[:half]
    group_b = sorted_honest[half:] or sorted_honest[:half]

    agents: dict[AgentId, Any] = {
        aid: GossipDriverAgent(
            agent_id=aid, capabilities=["gossip_peer"], gossip_interval=gossip_interval
        )
        for aid in honest_ids
    }
    for aid in equivocator_ids:
        agents[aid] = EquivocatorDriverAgent(
            agent_id=aid,
            network=network,
            identity=identities[aid],
            group_a=group_a,
            group_b=group_b,
        )
    return agents


# ---------------------------------------------------------------------------
# Scenario 3: eclipse -- a victim surrounded by byzantine peers
# ---------------------------------------------------------------------------


class InertByzantineDriverAgent(StateMachineAgent):
    """Byzantine agent: a total gossip black hole.

    Never registers a card, never runs a gossip round, and never answers an
    inbound digest or push -- it just occupies a slot in the shared
    ``GossipNetwork`` peer set, diluting the pool an honest agent's uniform
    random sample is drawn from without ever relaying anything honest
    through itself.

    Example::

        agent = InertByzantineDriverAgent(AgentId("byz-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_start(self, ctx: AgentContext) -> None:
        """No-op: never registers, never gossips.

        Example::

            await agent.on_start(ctx)
        """

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """No-op: drops every inbound message, honest or otherwise.

        Example::

            await agent.on_message(ctx, sender, payload)
        """


def gossip_eclipse_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build the fleet for ``scenarios/gossip_eclipse.yaml``.

    Roles: ``0honest`` (normal ``GossipDriverAgent``; the leading ``0``
    keeps these ids sorted lexicographically ahead of every ``9byz`` id, so
    ``byzantine_gossip``'s deterministic anchor half of
    ``_sample_eclipse_resistant`` always includes another honest agent) and
    ``9byz`` (``InertByzantineDriverAgent``, a majority of gossip black
    holes). ``task.config.fanout`` overrides ``GossipNetwork``'s default
    fanout.

    Example::

        agents = gossip_eclipse_factory(config, plugins)
    """
    task_cfg = config.task.config or {}
    gossip_interval = float(task_cfg.get("gossip_interval", DEFAULT_GOSSIP_INTERVAL))
    fanout = int(task_cfg.get("fanout", DEFAULT_FANOUT))
    seed = str(task_cfg.get("key_seed", "gossip-eclipse")).encode()

    roles = _roles_by_name(config)
    honest_ids = roles.get("0honest", [])
    byzantine_ids = roles.get("9byz", [])
    all_ids = [*honest_ids, *byzantine_ids]

    identity_cls = plugins["identity"]
    registry_cls = plugins["registry"]
    identities = _build_identities(identity_cls, honest_ids, seed)
    network = GossipNetwork(agent_ids=all_ids, fanout=fanout)
    registries = _build_registries(registry_cls, network, honest_ids, identities)

    plugins["_agent_plugins"] = {aid: {"registry": reg} for aid, reg in registries.items()}
    plugins["_gossip_network"] = network
    plugins["_byzantine_registries"] = registries
    plugins["_byzantine_identities"] = identities
    plugins["_honest_ids"] = set(honest_ids)
    plugins["_byzantine_ids"] = set(byzantine_ids)

    agents: dict[AgentId, Any] = {
        aid: GossipDriverAgent(
            agent_id=aid, capabilities=["gossip_peer"], gossip_interval=gossip_interval
        )
        for aid in honest_ids
    }
    for aid in byzantine_ids:
        agents[aid] = InertByzantineDriverAgent(aid)
    return agents
