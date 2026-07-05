# SPDX-License-Identifier: Apache-2.0
"""Registry integrity scenario — registration authenticity under Sybil attack.

Honest agents sign their own ``AgentCard`` through the configured identity
plugin and register it.  Sybil agents attempt the three registration attacks
an unauthenticated registry cannot refuse:

* **impersonate** — register a card claiming a *victim's* ``agent_id``
  (signed, but with the attacker's own key: the signer does not match the
  claimed id).  Against ``in_memory`` this silently **overwrites the victim's
  card** and poisons every subsequent lookup.
* **unsigned** — register a card claiming the victim's ``agent_id`` with no
  signature at all.  ``in_memory`` accepts it without question.
* **tamper** — sign an honest card, then mutate it after signing (grant
  itself the victim's capability and swap the endpoint).  The signature no
  longer covers the card that is registered.

Every attempt is emitted into the trace in a line protocol the
``registry_integrity`` validators parse; after all registrations settle, an
auditor looks up each honest agent's capability and records whether discovery
still resolves to the *authentic* owner.  Under ``registry: verified`` every
attack is rejected with a typed reason and discovery stays authentic; under
``registry: in_memory`` the same scenario runs without crashing, the attacks
are accepted, and the validators fail — the honest demonstration that the
default registry trusts anyone.

Attacks are *capability-gated*: agents attempt registration through whatever
registry instance the factory provisioned and simply report the verdict, so
swapping the ``registry:`` line in the YAML is the only difference between
the passing and failing runs.

Trace line protocol (carried in message bodies, ``:``-delimited ``k=v``):

* ``reg:attempt:actor=<id>:claimed=<id>:attack=<kind>:verdict=<v>:reason=<r>``
  — one registration attempt; ``kind`` is ``honest``/``impersonate``/
  ``unsigned``/``tamper``; ``verdict`` is ``accepted``/``rejected``;
  ``reason`` is ``ok`` or the plugin's typed rejection reason.
* ``reg:lookup:claimed=<id>:present=<0|1>:authentic=<0|1>`` — the auditor's
  post-hoc discovery check for one honest agent: ``present`` means a card
  with that ``agent_id`` is discoverable, ``authentic`` means that card still
  points at the owner's true endpoint.

Example::

    agents = registry_integrity_factory(config, plugins)
"""

from __future__ import annotations

import inspect
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Query

ATTACK_HONEST = "honest"
"""Attempt kind: an agent registering its own, correctly signed card."""

ATTACK_IMPERSONATE = "impersonate"
"""Attempt kind: a signed card claiming another agent's ``agent_id``."""

ATTACK_UNSIGNED = "unsigned"
"""Attempt kind: a card claiming another agent's ``agent_id``, no signature."""

ATTACK_TAMPER = "tamper"
"""Attempt kind: a card mutated after signing (capability forgery)."""

_ATTACK_CYCLE = (ATTACK_IMPERSONATE, ATTACK_UNSIGNED, ATTACK_TAMPER)

AUDIT_PULSE = b"audit:"
"""Self-scheduled payload that triggers the auditor's discovery sweep."""


def _service_capability(agent_id: AgentId) -> str:
    """The capability an agent advertises (and an attacker covets).

    Example::

        cap = _service_capability(AgentId("honest-0"))
    """
    return f"service:{agent_id}"


def _own_endpoint(agent_id: AgentId) -> str:
    """The endpoint only the authentic owner would advertise.

    Example::

        endpoint = _own_endpoint(AgentId("honest-0"))
    """
    return f"self://{agent_id}"


def _attempt_line(actor: AgentId, claimed: AgentId, attack: str, verdict: str, reason: str) -> str:
    """Render one ``reg:attempt:`` trace line.

    Example::

        line = _attempt_line(actor, claimed, "honest", "accepted", "ok")
    """
    return (
        f"reg:attempt:actor={actor}:claimed={claimed}:attack={attack}"
        f":verdict={verdict}:reason={reason}"
    )


async def _attempt_register(ctx: AgentContext, card: AgentCard) -> tuple[str, str]:
    """Try to register ``card``; return ``(verdict, reason)``.

    Rejections are recognised structurally (an exception exposing a string
    ``reason``), so the verdict path works unchanged against any configured
    registry — including ones that never reject.

    Example::

        verdict, reason = await _attempt_register(ctx, card)
    """
    registry = ctx.plugins.get("registry")
    if registry is None:  # pragma: no cover - scenario always configures a registry
        return "rejected", "no_registry"
    try:
        await registry.register(card)
    except Exception as exc:  # verdicts must be recorded, not raised
        reason = getattr(exc, "reason", None)
        return "rejected", reason if isinstance(reason, str) else "error"
    return "accepted", "ok"


class HonestRegistrant(StateMachineAgent):
    """Signs its own card with its own identity and registers it.

    Signing is capability-gated: with an identity plugin available the card
    is signed via the scenario-side canonical encoding (the same one
    ``verified`` checks); without one the card goes out unsigned and the
    verdict line records whatever the registry decides.

    Example::

        agent = HonestRegistrant(AgentId("honest-0"), AgentId("auditor-0"))
    """

    def __init__(self, agent_id: AgentId, auditor: AgentId) -> None:
        self._id = agent_id
        self._auditor = auditor

    async def on_start(self, ctx: AgentContext) -> None:
        """Build, sign, and register this agent's own card; report the verdict.

        Example::

            await agent.on_start(ctx)
        """
        from nest_plugins_reference.registry.verified import sign_card

        card = AgentCard(
            agent_id=self._id,
            name=str(self._id),
            capabilities=[_service_capability(self._id)],
            endpoint=_own_endpoint(self._id),
        )
        ident = ctx.plugins.get("identity")
        if ident is not None:
            card = sign_card(card, ident)
        verdict, reason = await _attempt_register(ctx, card)
        line = _attempt_line(self._id, self._id, ATTACK_HONEST, verdict, reason)
        await ctx.send(self._auditor, line.encode())


class SybilRegistrant(StateMachineAgent):
    """Attempts one registration attack against a victim and reports the verdict.

    The three attacks cover the three distinct trust failures a registration
    gate must refuse: wrong signer (``impersonate``), no signer
    (``unsigned``), and a signature that no longer covers the card
    (``tamper``).  Each maps to exactly one typed rejection reason in the
    ``verified`` plugin, which the validators assert.

    Example::

        agent = SybilRegistrant(
            AgentId("sybil-0"), AgentId("auditor-0"),
            attack="impersonate", victim=AgentId("honest-0"),
        )
    """

    def __init__(self, agent_id: AgentId, auditor: AgentId, attack: str, victim: AgentId) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._attack = attack
        self._victim = victim

    def _build_card(self, ctx: AgentContext) -> tuple[AgentCard, AgentId]:
        """Construct the attack card; return it with the claimed ``agent_id``.

        Example::

            card, claimed = agent._build_card(ctx)
        """
        from nest_plugins_reference.registry.verified import sign_card

        ident = ctx.plugins.get("identity")
        if self._attack == ATTACK_UNSIGNED or ident is None:
            # The victim's identity, no proof at all.
            card = AgentCard(
                agent_id=self._victim,
                name=str(self._victim),
                capabilities=[_service_capability(self._victim)],
                endpoint=f"sybil://{self._id}",
            )
            return card, self._victim

        if self._attack == ATTACK_IMPERSONATE:
            # The victim's identity, signed with the attacker's own key.
            card = AgentCard(
                agent_id=self._victim,
                name=str(self._victim),
                capabilities=[_service_capability(self._victim)],
                endpoint=f"sybil://{self._id}",
            )
            return sign_card(card, ident), self._victim

        # ATTACK_TAMPER: sign an innocuous own card, then mutate it.
        card = AgentCard(
            agent_id=self._id,
            name=str(self._id),
            capabilities=[_service_capability(self._id)],
            endpoint=_own_endpoint(self._id),
        )
        signed = sign_card(card, ident)
        signed.capabilities.append(_service_capability(self._victim))
        signed.endpoint = f"sybil://{self._id}"
        return signed, self._id

    async def on_start(self, ctx: AgentContext) -> None:
        """Run the configured attack once; report the verdict line.

        Example::

            await agent.on_start(ctx)
        """
        card, claimed = self._build_card(ctx)
        verdict, reason = await _attempt_register(ctx, card)
        line = _attempt_line(self._id, claimed, self._attack, verdict, reason)
        await ctx.send(self._auditor, line.encode())


class AuditorAgent(StateMachineAgent):
    """Collects verdict lines and audits discovery after registrations settle.

    All registrations happen in the agents' ``on_start`` at tick 0; the
    auditor schedules a single ``audit:`` pulse one tick later, looks up each
    honest agent's capability, and emits one ``reg:lookup:`` line per honest
    agent recording whether discovery resolves to the authentic owner.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"), honest_ids)
    """

    def __init__(self, agent_id: AgentId, honest_ids: list[AgentId]) -> None:
        self._id = agent_id
        self._honest_ids = honest_ids

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the discovery audit for after all registrations.

        Example::

            await auditor.on_start(ctx)
        """
        await ctx.schedule(1.0, AUDIT_PULSE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the ``audit:`` pulse, check discovery for every honest agent.

        Example::

            await auditor.on_message(ctx, auditor_id, b"audit:")
        """
        if sender != ctx.agent_id or not payload.startswith(AUDIT_PULSE):
            return
        registry = ctx.plugins.get("registry")
        if registry is None:  # pragma: no cover - scenario always configures a registry
            return
        for hid in self._honest_ids:
            cards = await registry.lookup(Query(capabilities=[_service_capability(hid)]))
            owner: AgentCard | None = None
            for card in cards:
                if card.agent_id == hid:
                    owner = card
                    break
            present = owner is not None
            authentic = present and owner is not None and owner.endpoint == _own_endpoint(hid)
            line = f"reg:lookup:claimed={hid}:present={int(present)}:authentic={int(authentic)}"
            await ctx.send(self._id, line.encode())


def _provision_identities(plugins: dict[str, Any], agent_ids: list[AgentId]) -> dict[AgentId, Any]:
    """Instantiate one identity per agent from the configured plugin class.

    Mirrors ``identity_rotation``'s wiring: resolve the class at
    ``plugins["identity"]``, build per-agent instances with deterministic
    seeds, and cross-register peers' public keys (capability-gated).  Returns
    the instances; the caller stashes them under ``plugins["_agent_plugins"]``.

    Example::

        identities = _provision_identities(plugins, agent_ids)
    """
    identity_cls = plugins.get("identity")
    if identity_cls is None or not isinstance(identity_cls, type):
        return {}
    identities: dict[AgentId, Any] = {
        aid: identity_cls(aid, seed=b"registry-integrity:" + str(aid).encode()) for aid in agent_ids
    }
    for aid, ident in identities.items():
        for peer_id, peer_ident in identities.items():
            if peer_id != aid and hasattr(ident, "register_peer"):
                ident.register_peer(peer_id, peer_ident.public_key)
    return identities


def _provision_registry(
    plugins: dict[str, Any],
    identities: dict[AgentId, Any],
) -> Any:
    """Build the single shared registry instance for the scenario.

    If the configured registry class accepts a ``verifier`` parameter (the
    ``verified`` plugin does), it is given a dedicated verifier identity that
    knows every scenario agent's public key.  Plain registries (``in_memory``)
    are instantiated bare — the differential run needs no special wiring.

    Example::

        registry = _provision_registry(plugins, identities)
    """
    registry_cls = plugins.get("registry")
    if registry_cls is None or not isinstance(registry_cls, type):
        return registry_cls

    params = inspect.signature(registry_cls.__init__).parameters
    if "verifier" not in params:
        return registry_cls()

    identity_cls = plugins.get("identity")
    if identity_cls is None or not isinstance(identity_cls, type):
        msg = "registry 'verified' requires an identity plugin class to build its verifier"
        raise ValueError(msg)
    verifier = identity_cls(AgentId("registry-verifier"), seed=b"registry-integrity:verifier")
    for aid, ident in identities.items():
        if hasattr(verifier, "register_peer") and hasattr(ident, "public_key"):
            verifier.register_peer(aid, ident.public_key)
    return registry_cls(verifier=verifier)


def registry_integrity_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create honest registrants, Sybil attackers, and one auditor.

    Role counts come from ``config.agents.roles`` (``honest``/``sybil``,
    defaults 3/3).  Sybil agents cycle through the three attack kinds, all
    targeting ``honest-0``.  Every agent shares one registry instance and
    holds its own identity instance, both injected via the
    ``_agent_plugins`` override channel.

    Example::

        agents = registry_integrity_factory(config, plugins)
    """
    honest_count = 3
    sybil_count = 3
    for role in config.agents.roles:
        if role.name == "honest":
            honest_count = role.count
        elif role.name == "sybil":
            sybil_count = role.count
    if honest_count < 1:
        msg = "registry_integrity needs at least one honest agent (the victim)"
        raise ValueError(msg)

    auditor_id = AgentId("auditor-0")
    honest_ids = [AgentId(f"honest-{i}") for i in range(honest_count)]
    sybil_ids = [AgentId(f"sybil-{i}") for i in range(sybil_count)]
    victim = honest_ids[0]

    identities = _provision_identities(plugins, honest_ids + sybil_ids)
    shared_registry = _provision_registry(plugins, identities)

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    for aid in [*honest_ids, *sybil_ids, auditor_id]:
        overrides = agent_plugins.setdefault(aid, {})
        overrides["registry"] = shared_registry
        ident = identities.get(aid)
        if ident is not None:
            overrides["identity"] = ident
    plugins.pop("identity", None)
    plugins.pop("registry", None)

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in honest_ids:
        agents[aid] = HonestRegistrant(aid, auditor=auditor_id)
    for i, aid in enumerate(sybil_ids):
        agents[aid] = SybilRegistrant(
            aid,
            auditor=auditor_id,
            attack=_ATTACK_CYCLE[i % len(_ATTACK_CYCLE)],
            victim=victim,
        )
    agents[auditor_id] = AuditorAgent(auditor_id, honest_ids=honest_ids)
    return agents
