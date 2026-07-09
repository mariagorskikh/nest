# SPDX-License-Identifier: Apache-2.0
"""Intent-gated datafacts scenario: publish only after a pre-declared intent.

Three honest agents each **register a publish intent** for their dataset and then
publish it; a fourth agent is an **attacker** that skips the intent step and tries
to publish a surprise dataset directly. Every step is reported as a ``|``-delimited
trace message so ``validate_trace(..., "intent_gated_datafacts")`` can read it.

The scenario is a discriminator. Point ``layers.datafacts`` at ``intent_facts``
(the ``IntentGatedFacts`` plugin) and both validators pass: honest publishes are
each preceded by a registered intent, and the attacker's un-declared publish is
blocked. Point it at ``datafacts_v1`` -- which has no intent concept -- and both
flip to FAIL: there is no intent gate, so the attacker's surprise publication
succeeds silently and no publish is backed by a declared intent.

Example::

    agents = intent_gated_datafacts_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DatasetMetadata


class HonestPublisher(StateMachineAgent):
    """Declares a publish intent, then publishes its dataset within the TTL.

    Against a gated plugin the intent is registered first (emitting
    ``intent_registered``) and the publish then consumes it (``publish_ok``).
    Against a plugin with no intent concept the registration is silently
    skipped -- the ``publish_ok`` then has no backing intent, which is exactly
    what the validator catches.

    Example::

        pub = HonestPublisher(AgentId("supplier-0"), name="prices")
    """

    def __init__(self, agent_id: AgentId, name: str) -> None:
        self._id = agent_id
        self._name = name

    async def on_start(self, ctx: AgentContext) -> None:
        """Register intent (if the plugin supports it), then publish the dataset.

        Example::

            await pub.on_start(ctx)
        """
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        register = getattr(facts, "register_publish_intent", None)
        if callable(register):
            register(self._name)
            await ctx.send(self._id, f"intent_registered|honest|{self._name}|{self._id}".encode())
        dataset = DatasetMetadata(name=self._name, owner=self._id)
        try:
            url = await facts.publish(dataset)
        except ValueError as exc:  # IntentError (a ValueError) if the gate blocks it
            await ctx.send(
                self._id, f"publish_blocked|honest|{self._name}|{self._id}|{exc}".encode()
            )
            return
        await ctx.send(self._id, f"publish_ok|honest|{self._name}|{self._id}|{url}".encode())


class AttackerPublisher(StateMachineAgent):
    """Skips the intent step and attempts a surprise publication.

    A gated plugin raises (a ``ValueError``) because no intent was declared, and
    the attempt is reported as ``publish_blocked``. A plugin with no gate lets
    the surprise land as ``publish_ok`` -- the failure the discriminator surfaces.

    Example::

        atk = AttackerPublisher(AgentId("attacker-0"), name="surprise_release")
    """

    def __init__(self, agent_id: AgentId, name: str) -> None:
        self._id = agent_id
        self._name = name

    async def on_start(self, ctx: AgentContext) -> None:
        """Attempt to publish without declaring any intent first.

        Example::

            await atk.on_start(ctx)
        """
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(name=self._name, owner=self._id)
        try:
            url = await facts.publish(dataset)
        except ValueError as exc:  # IntentError (a ValueError) when the gate blocks it
            await ctx.send(
                self._id, f"publish_blocked|attacker|{self._name}|{self._id}|{exc}".encode()
            )
            return
        await ctx.send(self._id, f"publish_ok|attacker|{self._name}|{self._id}|{url}".encode())


def _build_datafacts_handles(
    datafacts_cls: type[Any],
    identities: dict[AgentId, Any],
    all_ids: list[AgentId],
) -> dict[AgentId, Any]:
    """Give each agent its own datafacts handle over shared storage where possible.

    Plugins that take an ``Identity`` plus ``datasets``/``proofs``/``clock``
    keyword arguments (``intent_facts``, ``cid_facts``) get one handle per agent
    over the same dicts and logical clock, so each agent signs and registers
    intents as itself while sharing the published-dataset store. Plugins with a
    no-argument constructor (``datafacts_v1``) get a single shared instance.

    Example::

        handles = _build_datafacts_handles(cls, identities, all_ids)
    """
    shared_datasets: dict[Any, Any] = {}
    shared_proofs: dict[Any, Any] = {}
    shared_clock: Any = None
    shared_instance: Any = None
    handles: dict[AgentId, Any] = {}

    for aid in all_ids:
        try:
            kwargs: dict[str, Any] = {"datasets": shared_datasets, "proofs": shared_proofs}
            if shared_clock is not None:
                kwargs["clock"] = shared_clock
            handle = datafacts_cls(identities[aid], **kwargs)
            shared_clock = getattr(handle, "clock", shared_clock)
            handles[aid] = handle
        except TypeError:
            if shared_instance is None:
                shared_instance = datafacts_cls()
            handles[aid] = shared_instance
    return handles


def intent_gated_datafacts_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create three honest publishers plus one surprise-publishing attacker.

    Instantiates per-agent identities (so each agent registers and signs as
    itself) and wires the resolved ``datafacts`` plugin class into per-agent
    handles via :func:`_build_datafacts_handles`.

    Example::

        agents = intent_gated_datafacts_factory(config, plugins)
    """
    supplier = AgentId("supplier-0")
    manufacturer = AgentId("manufacturer-0")
    retailer = AgentId("retailer-0")
    attacker = AgentId("attacker-0")
    all_ids = [supplier, manufacturer, retailer, attacker]

    identity_cls = plugins.get("identity")
    identities: dict[AgentId, Any] = {}
    if identity_cls is not None and isinstance(identity_cls, type):
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"sim-seed")
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    datafacts_cls = plugins.get("datafacts")
    if datafacts_cls is not None and isinstance(datafacts_cls, type) and identities:
        handles = _build_datafacts_handles(datafacts_cls, identities, all_ids)
        for aid, handle in handles.items():
            agent_plugins.setdefault(aid, {})["datafacts"] = handle
    plugins.pop("datafacts", None)
    plugins.pop("identity", None)

    return {
        supplier: HonestPublisher(supplier, name="raw_materials"),
        manufacturer: HonestPublisher(manufacturer, name="assembled_goods"),
        retailer: HonestPublisher(retailer, name="retail_inventory"),
        attacker: AttackerPublisher(attacker, name="surprise_release"),
    }
