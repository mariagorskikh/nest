# SPDX-License-Identifier: Apache-2.0
"""Content-addressed provenance scenario: a diamond data pipeline, then attacks.

The pipeline is a **diamond**, not a line -- the canonical data-lineage shape::

                 source-0
                /        \\
          refine-a      refine-b
                \\        /
               aggregate-0   (join: parents = [refine-a, refine-b])
                    |
                 verify-0

Each hop publishes a *dataset* through ``plugins["datafacts"]`` and declares its
upstream input(s) as provenance parents. ``aggregate-0`` is a join: it waits for
both refiners and lists both as parents, so the final report's lineage fans back
out to a single shared root. A verifier that only followed the first parent would
silently miss half the graph; the walk here is a full breadth-first traversal.

``verify-0`` plays two roles:

1. **Verifier** -- walks the whole provenance DAG back to the root and reports
   how many distinct datasets it found.
2. **Attacker** -- using its own identity (never the source's), it runs three
   attacks:

   * *Substitution*: republish different content under the source's exact
     ``name``; does it land on the source's URL?
   * *Forged freshness*: republish identical content claiming the source's
     ``owner``; does the source then read as freshly attested under an
     outsider's signature?
   * *Broken provenance*: publish a dataset whose declared parent was never
     published; is it rejected?

Every step is reported as a ``|``-delimited trace message (``:`` collides with
the ``df://`` URL scheme). ``validate_trace(..., "provenance_supply_chain")``
reads exactly these messages, so the one scenario YAML demonstrates both
directions: point ``layers.datafacts`` at ``cid_facts`` and every adversarial
validator passes; point it at ``datafacts_v1`` and they fail, because that
reference plugin has no content-addressing, no signed freshness, and no
provenance concept at all.

Example::

    agents = provenance_supply_chain_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DatasetMetadata

_PHANTOM_PARENT = "df://sha256-" + "0" * 64


def _parents_of(meta: DatasetMetadata) -> list[str]:
    """Read declared provenance parents off a dataset as a plain list of URL strings.

    Example::

        parents = _parents_of(meta)
    """
    raw: object = meta.metadata.get("parents", [])
    if not isinstance(raw, list):
        return []
    return [str(p) for p in cast("list[Any]", raw)]


class SourceAgent(StateMachineAgent):
    """Publishes the root dataset (no parents) and fans it out to both refiners.

    Example::

        source = SourceAgent(AgentId("source-0"),
                             refiners=[AgentId("refine-a"), AgentId("refine-b")],
                             name="raw_sensor_readings", description="batch-A")
    """

    def __init__(
        self, agent_id: AgentId, refiners: list[AgentId], name: str, description: str
    ) -> None:
        self._id = agent_id
        self._refiners = refiners
        self._name = name
        self._description = description

    async def on_start(self, ctx: AgentContext) -> None:
        """Publish the root dataset and send its URL to every refiner.

        Example::

            await source.on_start(ctx)
        """
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(name=self._name, owner=self._id, description=self._description)
        url = await facts.publish(dataset)
        for refiner in self._refiners:
            await ctx.send(refiner, f"lineage|{url}|{self._id}".encode())


class RefineAgent(StateMachineAgent):
    """Publishes a derived dataset parented on the source, forwards to the aggregator.

    Example::

        refine = RefineAgent(AgentId("refine-a"), aggregator=AgentId("aggregate-0"),
                             name="cleaned_a")
    """

    def __init__(self, agent_id: AgentId, aggregator: AgentId, name: str) -> None:
        self._id = agent_id
        self._aggregator = aggregator
        self._name = name

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Publish a dataset parented on the source URL and forward it to the aggregator.

        Example::

            await refine.on_message(ctx, AgentId("source-0"), b"lineage|df://sha256-x|source-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        _, parent_url, _owner = msg.split("|", 2)
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(
            name=self._name, owner=self._id, metadata={"parents": [parent_url]}
        )
        url = await facts.publish(dataset)
        await ctx.send(self._aggregator, f"lineage|{url}|{self._id}".encode())


class AggregateAgent(StateMachineAgent):
    """Joins both refiners into one dataset -- the diamond's closure -- and forwards it.

    A join lists *both* upstream datasets as parents, so the report's lineage
    fans back out to the shared root. This is what forces a verifier to walk
    every parent rather than a single spine.

    Example::

        agg = AggregateAgent(AgentId("aggregate-0"), downstream=AgentId("verify-0"),
                             name="aggregated_report", expected_parents=2)
    """

    def __init__(
        self, agent_id: AgentId, downstream: AgentId, name: str, expected_parents: int
    ) -> None:
        self._id = agent_id
        self._downstream = downstream
        self._name = name
        self._expected = expected_parents
        self._parents: list[str] = []

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Collect refiner inputs and, once both arrive, publish + forward the join.

        Example::

            await agg.on_message(ctx, AgentId("refine-a"), b"lineage|df://sha256-a|refine-a")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        _, parent_url, _owner = msg.split("|", 2)
        self._parents.append(parent_url)
        if len(self._parents) == self._expected:
            dataset = DatasetMetadata(
                name=self._name, owner=self._id, metadata={"parents": list(self._parents)}
            )
            url = await facts.publish(dataset)
            await ctx.send(self._downstream, f"lineage|{url}|{self._id}".encode())


class VerifyAndAttackAgent(StateMachineAgent):
    """Walks the provenance DAG, then runs three attacks as an outsider.

    Example::

        verify = VerifyAndAttackAgent(AgentId("verify-0"), source_id=AgentId("source-0"),
                                      source_name="raw_sensor_readings")
    """

    def __init__(self, agent_id: AgentId, source_id: AgentId, source_name: str) -> None:
        self._id = agent_id
        self._source_id = source_id
        self._source_name = source_name

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Walk the lineage from the received leaf, then attempt the three attacks.

        Example::

            await verify.on_message(ctx, AgentId("aggregate-0"), b"lineage|df://sha256-x|aggregate-0")
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
        """Full breadth-first walk of the provenance DAG from the leaf to its root.

        Visits *every* parent of every node (not just ``parents[0]``), de-dupes
        shared ancestors so a diamond is counted once, reports the number of
        distinct datasets in the lineage, and returns the single root (a node
        with no parents) so the substitution attack can target the true source.
        A parent that does not resolve is a broken chain.
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
        """Try to republish different content under the source's exact name."""
        forged = DatasetMetadata(
            name=self._source_name, owner=self._source_id, description="tampered-by-attacker"
        )
        attacker_url = await facts.publish(forged)
        collided = int(str(attacker_url) == str(source_url))
        await ctx.send(
            self._id, f"attack_substitution|{source_url}|{attacker_url}|{collided}".encode()
        )

    async def _attack_forged_freshness(self, ctx: AgentContext, facts: Any) -> None:
        """Republish the source's content signed by the attacker, then re-check freshness."""
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

    Plugins that take an ``Identity`` plus ``datasets``/``proofs``/``clock``
    keyword arguments (e.g. ``cid_facts``) get one handle per agent over the
    same shared dicts and logical clock -- mirroring how the reference
    ``prepaid_credits`` payments plugin gives every agent its own handle over
    one shared ledger. Plugins with a no-argument constructor (e.g.
    ``datafacts_v1``) get a single shared instance, already correct for them
    since their storage is one dict.

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
    """Create the diamond pipeline: source -> {refine-a, refine-b} -> aggregate -> verify.

    Instantiates per-agent identity instances (so each hop signs as itself) and
    wires the resolved ``datafacts`` plugin class into per-agent handles via
    :func:`_build_datafacts_handles`.

    Example::

        agents = provenance_supply_chain_factory(config, plugins)
    """
    source_id = AgentId("source-0")
    refine_a = AgentId("refine-a")
    refine_b = AgentId("refine-b")
    aggregate_id = AgentId("aggregate-0")
    verify_id = AgentId("verify-0")
    all_ids = [source_id, refine_a, refine_b, aggregate_id, verify_id]

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
        source_id: SourceAgent(
            source_id, refiners=[refine_a, refine_b], name=source_name, description="batch-A"
        ),
        refine_a: RefineAgent(refine_a, aggregator=aggregate_id, name="cleaned_a"),
        refine_b: RefineAgent(refine_b, aggregator=aggregate_id, name="cleaned_b"),
        aggregate_id: AggregateAgent(
            aggregate_id, downstream=verify_id, name="aggregated_report", expected_parents=2
        ),
        verify_id: VerifyAndAttackAgent(verify_id, source_id=source_id, source_name=source_name),
    }
