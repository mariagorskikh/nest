# SPDX-License-Identifier: Apache-2.0
"""Content-addressed provenance scenario: a data pipeline, then three attacks.

A 4-stage pipeline mirrors the existing ``supply_chain`` scenario, except each
hop publishes a *dataset* (not a physical good) through ``plugins["datafacts"]``
and the next hop's dataset declares the upstream one as its provenance
parent: ``source -> refine -> aggregate -> verify``.

The final stage plays two roles:

1. **Verifier** — walks the parent chain back to the source via ``fetch``,
   checks the final dataset's freshness, and reports both.
2. **Attacker** — using its own identity (never the source's), attempts the
   three attacks the datafacts problem brief calls out:

   * *Substitution*: publish different content under the source's exact
     ``name`` and see whether it lands on the source's URL.
   * *Forged freshness*: publish identical content claiming the source's
     ``owner`` and see whether the source's freshness now reads as valid
     under someone else's signature.
   * *Broken provenance*: publish a dataset whose declared parent was never
     published, and see whether that is rejected.

Every step is reported as a ``|``-delimited trace message (``:`` collides
with the ``df://`` URL scheme, so this scenario does not use it as a
delimiter the way other validators do). ``validate_trace(..., "provenance_supply_chain")``
reads exactly these messages, so the same scenario YAML demonstrates both
directions: point ``layers.datafacts`` at ``cid_facts`` and every adversarial
validator passes; point it at ``datafacts_v1`` and they fail, because that
reference plugin has no content-addressing, no signed freshness, and no
provenance concept at all.

Example::

    agents = provenance_supply_chain_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DatasetMetadata

_PHANTOM_PARENT = "df://sha256-" + "0" * 64


class SourceAgent(StateMachineAgent):
    """Publishes the root dataset (no provenance parents) and hands off its URL.

    Example::

        source = SourceAgent(AgentId("source-0"), next_stage=AgentId("refine-0"),
                              name="raw_sensor_readings", description="batch-A")
    """

    def __init__(self, agent_id: AgentId, next_stage: AgentId, name: str, description: str) -> None:
        self._id = agent_id
        self._next = next_stage
        self._name = name
        self._description = description

    async def on_start(self, ctx: AgentContext) -> None:
        """Publish the root dataset and hand its URL to the next stage.

        Example::

            await source.on_start(ctx)
        """
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(name=self._name, owner=self._id, description=self._description)
        url = await facts.publish(dataset)
        await ctx.send(self._next, f"lineage|{url}|{self._id}".encode())


class RefineAgent(StateMachineAgent):
    """Publishes a derived dataset whose provenance parent is the upstream URL.

    Example::

        refine = RefineAgent(AgentId("refine-0"), next_stage=AgentId("aggregate-0"),
                              name="cleaned_sensor_readings")
    """

    def __init__(self, agent_id: AgentId, next_stage: AgentId, name: str) -> None:
        self._id = agent_id
        self._next = next_stage
        self._name = name

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Publish a derived dataset parented on the lineage URL just received.

        Example::

            await refine.on_message(ctx, AgentId("source-0"), b"lineage|df://sha256-x|source-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        _, parent_url, _parent_owner = msg.split("|", 2)
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(
            name=self._name,
            owner=self._id,
            metadata={"parents": [parent_url]},
        )
        url = await facts.publish(dataset)
        await ctx.send(self._next, f"lineage|{url}|{self._id}".encode())


class VerifyAndAttackAgent(StateMachineAgent):
    """Verifies the happy-path chain, then attempts three attacks as an outsider.

    Example::

        verify = VerifyAndAttackAgent(AgentId("verify-0"), source_id=AgentId("source-0"),
                                       source_name="raw_sensor_readings")
    """

    def __init__(self, agent_id: AgentId, source_id: AgentId, source_name: str) -> None:
        self._id = agent_id
        self._source_id = source_id
        self._source_name = source_name

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify the received chain's integrity and freshness, then run the three attacks.

        Example::

            await verify.on_message(ctx, AgentId("aggregate-0"), b"lineage|df://sha256-x|aggregate-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        _, final_url, _final_owner = msg.split("|", 2)
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return

        root_url = await self._verify_chain(ctx, facts, final_url)
        await self._verify_freshness(ctx, facts, final_url)
        if root_url is not None:
            await self._attack_substitution(ctx, facts, root_url)
            await self._attack_forged_freshness(ctx, facts)
        await self._attack_provenance(ctx, facts)

    async def _verify_chain(self, ctx: AgentContext, facts: Any, final_url: str) -> str | None:
        """Walk the parent chain back to the root and report depth.

        Returns the root dataset's own URL (the source's published URL), or
        ``None`` if the chain was broken, so the caller can target the
        substitution attack at the *actual* source address rather than the
        terminal (derived) one.
        """
        depth = 0
        url: str = final_url
        try:
            while True:
                meta: DatasetMetadata = await facts.fetch(url)
                depth += 1
                parents: list[str] = meta.metadata.get("parents", [])
                if not parents:
                    break
                url = parents[0]
        except KeyError:
            await ctx.send(self._id, f"chain_broken|{final_url}|{url}".encode())
            return None
        await ctx.send(self._id, f"chain_ok|{final_url}|{depth}".encode())
        return url

    async def _verify_freshness(self, ctx: AgentContext, facts: Any, final_url: str) -> None:
        fresh = await facts.verify_freshness(final_url)
        await ctx.send(self._id, f"freshness|{final_url}|{int(fresh)}".encode())

    async def _attack_substitution(self, ctx: AgentContext, facts: Any, source_url: str) -> None:
        """Try to republish different content under the source's exact name."""
        forged = DatasetMetadata(
            name=self._source_name,
            owner=self._source_id,
            description="tampered-by-attacker",
        )
        attacker_url = await facts.publish(forged)
        collided = int(str(attacker_url) == str(source_url))
        await ctx.send(
            self._id, f"attack_substitution|{source_url}|{attacker_url}|{collided}".encode()
        )

    async def _attack_forged_freshness(self, ctx: AgentContext, facts: Any) -> None:
        """Republish the source's exact content, signed by the attacker, then re-check freshness."""
        forged = DatasetMetadata(name=self._source_name, owner=self._source_id)
        forged_url = await facts.publish(forged)
        fresh = await facts.verify_freshness(forged_url)
        await ctx.send(self._id, f"attack_forged_freshness|{forged_url}|{int(fresh)}".encode())

    async def _attack_provenance(self, ctx: AgentContext, facts: Any) -> None:
        """Try to publish a dataset whose declared parent was never published."""
        phantom = DatasetMetadata(
            name="laundered",
            owner=self._source_id,
            metadata={"parents": [_PHANTOM_PARENT]},
        )
        try:
            await facts.publish(phantom)
            rejected = 0
        except ValueError:
            rejected = 1
        await ctx.send(self._id, f"attack_provenance|{_PHANTOM_PARENT}|{rejected}".encode())


def _build_datafacts_handles(
    datafacts_cls: type[Any],
    identities: dict[AgentId, Any],
    all_ids: list[AgentId],
) -> dict[AgentId, Any]:
    """Instantiate one datafacts handle per agent, sharing state where possible.

    Plugins that take an ``Identity`` and ``datasets``/``proofs``/``clock``
    keyword arguments (e.g. ``cid_facts``) get one handle per agent, all
    backed by the same shared dicts and logical clock -- mirroring how the
    reference ``prepaid_credits`` payments plugin gives every agent its own
    handle over one shared ledger. Plugins with a no-argument constructor
    (e.g. ``datafacts_v1``) get a single shared instance for every agent,
    which is already correct for them since their internal storage is a
    single dict.

    Example::

        handles = _build_datafacts_handles(CidFacts, identities, all_ids)
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


def provenance_supply_chain_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the source/refine/aggregate/verify pipeline.

    Instantiates per-agent identity instances (so each hop signs as itself)
    and wires the resolved ``datafacts`` plugin class into per-agent handles
    via :func:`_build_datafacts_handles`.

    Example::

        agents = provenance_supply_chain_factory(config, plugins)
    """
    source_id = AgentId("source-0")
    refine_id = AgentId("refine-0")
    aggregate_id = AgentId("aggregate-0")
    verify_id = AgentId("verify-0")
    all_ids = [source_id, refine_id, aggregate_id, verify_id]

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

    source_name = "raw_sensor_readings"
    return {
        source_id: SourceAgent(source_id, refine_id, source_name, description="batch-A"),
        refine_id: RefineAgent(refine_id, aggregate_id, "cleaned_sensor_readings"),
        aggregate_id: RefineAgent(aggregate_id, verify_id, "aggregated_report"),
        verify_id: VerifyAndAttackAgent(verify_id, source_id, source_name),
    }
