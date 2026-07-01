# SPDX-License-Identifier: Apache-2.0
"""Content-addressed provenance scenario: a deep *linear* supply chain, then attacks.

Where ``provenance_supply_chain`` (#31) is a **diamond** that stresses lineage
*fan-out* (a join whose ancestry forks back to a shared root), this scenario is a
**linear spine** that stresses lineage *depth* -- the canonical physical
supply-chain shape::

    supplier-0 -> manufacturer-0 -> distributor-0 -> retailer-0 -> auditor-0

Each producer hop publishes a *dataset* through ``plugins["datafacts"]`` and
declares exactly the previous hop's dataset as its single provenance parent, so
the lineage is one unbranched chain four hops long. ``auditor-0``:

1. **Verifies** -- walks the whole parent chain from the retailer's dataset back
   to the supplier's root and reports how many distinct datasets it found. A
   single broken hop anywhere along a deep chain must surface as a break.
2. **Attacks** -- as an *outsider* (signing with its own identity, never the
   supplier's), it runs the three provenance attacks against the root:

   * *Substitution*: republish different content under the supplier's exact
     ``name`` -- does it land on the supplier's URL?
   * *Forged freshness*: republish identical content claiming the supplier as
     ``owner`` -- does the supplier then read as freshly attested under an
     outsider's signature?
   * *Broken provenance*: publish a dataset whose declared parent was never
     published -- is it rejected?

Every step is reported as a ``|``-delimited trace message (``:`` collides with
the ``df://`` URL scheme) using the *same* wire protocol as the diamond
scenario, so the two share one validator set: point ``layers.datafacts`` at
``cid_facts`` and every adversarial validator passes; point it at
``datafacts_v1`` and they fail, because that reference plugin has no
content-addressing, no signed freshness, and no provenance concept at all.

Example::

    agents = provenance_supply_chain_linear_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DatasetMetadata

# The producer hops of the linear chain, upstream-to-downstream. Kept as data so
# the spine is easy to read and to lengthen; the auditor is appended separately.
_CHAIN: tuple[str, ...] = ("supplier", "manufacturer", "distributor", "retailer")
_PHANTOM_PARENT = "df://sha256-" + "0" * 64


def _parents_of(meta: DatasetMetadata) -> list[str]:
    """Read declared provenance parents off a dataset as plain URL strings.

    Example::

        parents = _parents_of(meta)
    """
    raw: object = meta.metadata.get("parents", [])
    if not isinstance(raw, list):
        return []
    return [str(p) for p in cast("list[Any]", raw)]


class SupplierAgent(StateMachineAgent):
    """Publishes the root dataset (no parents) and hands it to the next hop.

    Example::

        supplier = SupplierAgent(AgentId("supplier-0"), downstream=AgentId("manufacturer-0"),
                                 name="raw_materials", description="lot-A")
    """

    def __init__(self, agent_id: AgentId, downstream: AgentId, name: str, description: str) -> None:
        self._id = agent_id
        self._downstream = downstream
        self._name = name
        self._description = description

    async def on_start(self, ctx: AgentContext) -> None:
        """Publish the root dataset and send its URL to the next hop.

        Example::

            await supplier.on_start(ctx)
        """
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(name=self._name, owner=self._id, description=self._description)
        url = await facts.publish(dataset)
        await ctx.send(self._downstream, f"lineage|{url}|{self._id}".encode())


class ChainHopAgent(StateMachineAgent):
    """A middle hop: publishes a dataset parented on the one it received, forwards it.

    Manufacturer, distributor, and retailer are all this same hop with different
    ids -- each declares exactly one parent, keeping the lineage an unbranched
    spine.

    Example::

        hop = ChainHopAgent(AgentId("manufacturer-0"), downstream=AgentId("distributor-0"),
                            name="assembled_goods")
    """

    def __init__(self, agent_id: AgentId, downstream: AgentId, name: str) -> None:
        self._id = agent_id
        self._downstream = downstream
        self._name = name

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Publish a dataset parented on the received URL and forward it downstream.

        Example::

            await hop.on_message(ctx, AgentId("supplier-0"), b"lineage|df://sha256-x|supplier-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        _, parent_url, _owner = msg.split("|", 2)
        dataset = DatasetMetadata(
            name=self._name, owner=self._id, metadata={"parents": [parent_url]}
        )
        url = await facts.publish(dataset)
        await ctx.send(self._downstream, f"lineage|{url}|{self._id}".encode())


class AuditorAgent(StateMachineAgent):
    """Walks the deep linear lineage, then runs three attacks as an outsider.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"), source_id=AgentId("supplier-0"),
                               source_name="raw_materials")
    """

    def __init__(self, agent_id: AgentId, source_id: AgentId, source_name: str) -> None:
        self._id = agent_id
        self._source_id = source_id
        self._source_name = source_name

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Walk the lineage from the received leaf, then attempt the three attacks.

        Example::

            await auditor.on_message(ctx, AgentId("retailer-0"), b"lineage|df://sha256-x|retailer-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        _, leaf_url, _owner = msg.split("|", 2)
        root_url = await self._verify_chain(ctx, facts, leaf_url)
        if root_url is not None:
            await self._attack_substitution(ctx, facts, root_url)
            await self._attack_forged_freshness(ctx, facts)
        await self._attack_provenance(ctx, facts)

    async def _verify_chain(self, ctx: AgentContext, facts: Any, leaf_url: str) -> str | None:
        """Walk the parent chain from the leaf to its root, reporting depth.

        Follows every declared parent (so a mis-wired fork would still be caught)
        and de-dupes, though a correct linear chain visits each hop exactly once.
        Returns the single root (a node with no parents) so the substitution
        attack can target the true supplier. A parent that does not resolve is a
        broken chain.
        """
        seen: set[str] = set()
        roots: list[str] = []
        stack: list[str] = [leaf_url]
        while stack:
            url = stack.pop()
            if url in seen:
                continue
            seen.add(url)
            try:
                meta: DatasetMetadata = await facts.fetch(url)
            except KeyError:
                await ctx.send(self._id, f"chain_broken|{leaf_url}|{url}".encode())
                return None
            parents = _parents_of(meta)
            if parents:
                stack.extend(parents)
            else:
                roots.append(url)
        await ctx.send(self._id, f"chain_ok|{leaf_url}|{len(seen)}".encode())
        return sorted(roots)[0] if roots else None

    async def _attack_substitution(self, ctx: AgentContext, facts: Any, source_url: str) -> None:
        """Try to republish different content under the supplier's exact name."""
        forged = DatasetMetadata(
            name=self._source_name, owner=self._source_id, description="tampered-by-attacker"
        )
        attacker_url = await facts.publish(forged)
        collided = int(str(attacker_url) == str(source_url))
        await ctx.send(
            self._id, f"attack_substitution|{source_url}|{attacker_url}|{collided}".encode()
        )

    async def _attack_forged_freshness(self, ctx: AgentContext, facts: Any) -> None:
        """Republish the supplier's content signed by the attacker, then re-check freshness."""
        forged = DatasetMetadata(name=self._source_name, owner=self._source_id)
        forged_url = await facts.publish(forged)
        fresh = await facts.verify_freshness(forged_url)
        await ctx.send(self._id, f"attack_forged_freshness|{forged_url}|{int(fresh)}".encode())

    async def _attack_provenance(self, ctx: AgentContext, facts: Any) -> None:
        """Try to publish a dataset whose declared parent was never published."""
        phantom = DatasetMetadata(
            name="laundered", owner=self._source_id, metadata={"parents": [_PHANTOM_PARENT]}
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

    Plugins taking an ``Identity`` plus ``datasets``/``proofs``/``clock`` keyword
    arguments (e.g. ``cid_facts``) get one handle per agent over the same shared
    dicts and logical clock -- so substitution resistance is meaningful
    swarm-wide while each agent still signs as itself. Plugins with a no-argument
    constructor (e.g. ``datafacts_v1``) get a single shared instance, already
    correct for them since their storage is one dict.

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


def provenance_supply_chain_linear_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the linear chain: supplier -> manufacturer -> distributor -> retailer -> auditor.

    Instantiates per-agent identity instances (so each hop signs as itself) and
    wires the resolved ``datafacts`` plugin class into per-agent handles via
    :func:`_build_datafacts_handles`.

    Example::

        agents = provenance_supply_chain_linear_factory(config, plugins)
    """
    producer_ids = [AgentId(f"{role}-0") for role in _CHAIN]
    auditor_id = AgentId("auditor-0")
    all_ids = [*producer_ids, auditor_id]

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

    source_id = producer_ids[0]
    source_name = "raw_materials"
    # Each producer's downstream is the next id in the spine; the last forwards
    # to the auditor.
    downstream = {**{producer_ids[i]: producer_ids[i + 1] for i in range(len(producer_ids) - 1)}}
    downstream[producer_ids[-1]] = auditor_id

    agents: dict[AgentId, StateMachineAgent] = {
        source_id: SupplierAgent(
            source_id, downstream=downstream[source_id], name=source_name, description="lot-A"
        )
    }
    for aid in producer_ids[1:]:
        agents[aid] = ChainHopAgent(aid, downstream=downstream[aid], name=f"{aid}_dataset")
    agents[auditor_id] = AuditorAgent(auditor_id, source_id=source_id, source_name=source_name)
    return agents
