# SPDX-License-Identifier: Apache-2.0
"""Content-addressed provenance scenario: a configurable N×M fan-in pipeline, then attacks.

Topology (configurable via ``task.config`` in the YAML)::

    supplier-0  supplier-1  ...  supplier-(N-1)
         \\            |              /
          \\           |             /
       manufacturer-0  ...  manufacturer-(M-1)
               \\       ...       /
                \\               /
               distributor-0   (join: parents = all manufacturer URLs)
                      |
                 retailer-0

Each supplier publishes a raw dataset.  Every manufacturer waits to receive
*all* supplier inputs (``num_suppliers`` messages), then publishes one derived
dataset whose ``parents`` list every supplier URL, and forwards the result to
the distributor.  The distributor waits for *all* manufacturers (``num_manufacturers``
messages) and publishes a join dataset whose ``parents`` list every manufacturer
URL.  The retailer acts as verifier-and-attacker: it walks the full provenance
DAG and then runs the three canonical attacks.

This gives ``validate_trace(..., "provenance_supply_chain_multi")`` a different
graph shape from the fixed diamond in ``provenance_supply_chain``: fan-width is
configurable from YAML, not hard-coded to 2.

Example (from YAML ``task.config``)::

    task:
      type: provenance_supply_chain_multi
      config:
        num_suppliers: 3
        num_manufacturers: 2

Defaults to ``num_suppliers=2, num_manufacturers=2``.
"""

from __future__ import annotations

from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DatasetMetadata

_PHANTOM_PARENT = "df://sha256-" + "0" * 64

# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------


def _parents_of(meta: DatasetMetadata) -> list[str]:
    """Read declared provenance parents off a dataset as a plain list of URL strings.

    Example::

        parents = _parents_of(meta)
    """
    raw: object = meta.metadata.get("parents", [])
    if not isinstance(raw, list):
        return []
    return [str(p) for p in cast("list[Any]", raw)]


# ---------------------------------------------------------------------------
# Agent classes
# ---------------------------------------------------------------------------


class MultiSupplierAgent(StateMachineAgent):
    """Publishes one root dataset and fans it out to every manufacturer.

    Example::

        supplier = MultiSupplierAgent(
            AgentId("supplier-0"),
            manufacturers=[AgentId("manufacturer-0"), AgentId("manufacturer-1")],
            name="raw_0",
        )
    """

    def __init__(self, agent_id: AgentId, manufacturers: list[AgentId], name: str) -> None:
        self._id = agent_id
        self._manufacturers = manufacturers
        self._name = name

    async def on_start(self, ctx: AgentContext) -> None:
        """Publish the root dataset and notify every manufacturer.

        Example::

            await supplier.on_start(ctx)
        """
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(name=self._name, owner=self._id)
        url = await facts.publish(dataset)
        for mfg in self._manufacturers:
            await ctx.send(mfg, f"lineage|{url}|{self._id}".encode())


class MultiManufacturerAgent(StateMachineAgent):
    """Collects one URL from every supplier, then publishes a derived dataset.

    Waits for ``num_suppliers`` ``lineage|…`` messages.  Once all arrive,
    publishes one dataset listing all supplier URLs as parents and forwards
    to the distributor.

    Example::

        mfg = MultiManufacturerAgent(
            AgentId("manufacturer-0"),
            distributor=AgentId("distributor-0"),
            name="product_0",
            num_suppliers=3,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        distributor: AgentId,
        name: str,
        num_suppliers: int,
    ) -> None:
        self._id = agent_id
        self._distributor = distributor
        self._name = name
        self._num_suppliers = num_suppliers
        self._parent_urls: list[str] = []

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Accumulate supplier URLs; publish + forward when all have arrived.

        Example::

            await mfg.on_message(ctx, AgentId("supplier-0"), b"lineage|df://sha256-x|supplier-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        _, parent_url, _owner = msg.split("|", 2)
        self._parent_urls.append(parent_url)
        if len(self._parent_urls) == self._num_suppliers:
            facts = ctx.plugins.get("datafacts")
            if facts is None:
                return
            dataset = DatasetMetadata(
                name=self._name,
                owner=self._id,
                metadata={"parents": list(self._parent_urls)},
            )
            url = await facts.publish(dataset)
            await ctx.send(self._distributor, f"lineage|{url}|{self._id}".encode())


class MultiDistributorAgent(StateMachineAgent):
    """Joins all manufacturer outputs into one dataset and forwards to the retailer.

    Example::

        dist = MultiDistributorAgent(
            AgentId("distributor-0"),
            retailer=AgentId("retailer-0"),
            name="aggregated",
            num_manufacturers=2,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        retailer: AgentId,
        name: str,
        num_manufacturers: int,
    ) -> None:
        self._id = agent_id
        self._retailer = retailer
        self._name = name
        self._num_manufacturers = num_manufacturers
        self._parent_urls: list[str] = []

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Accumulate manufacturer URLs; publish + forward when all have arrived.

        Example::

            await dist.on_message(ctx, AgentId("manufacturer-0"), b"lineage|df://sha256-y|manufacturer-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        _, parent_url, _owner = msg.split("|", 2)
        self._parent_urls.append(parent_url)
        if len(self._parent_urls) == self._num_manufacturers:
            facts = ctx.plugins.get("datafacts")
            if facts is None:
                return
            dataset = DatasetMetadata(
                name=self._name,
                owner=self._id,
                metadata={"parents": list(self._parent_urls)},
            )
            url = await facts.publish(dataset)
            await ctx.send(self._retailer, f"lineage|{url}|{self._id}".encode())


class MultiRetailerAgent(StateMachineAgent):
    """Walks the provenance DAG from the distributor leaf, then runs three attacks.

    Reuses the same three attack patterns as ``VerifyAndAttackAgent`` in the
    diamond scenario, exercising identical validators via a wider graph.

    Example::

        retailer = MultiRetailerAgent(
            AgentId("retailer-0"),
            first_supplier_id=AgentId("supplier-0"),
            first_supplier_name="raw_0",
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        first_supplier_id: AgentId,
        first_supplier_name: str,
    ) -> None:
        self._id = agent_id
        self._source_id = first_supplier_id
        self._source_name = first_supplier_name

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Walk the lineage, then run substitution, forged-freshness, and provenance attacks.

        Example::

            await retailer.on_message(ctx, AgentId("distributor-0"), b"lineage|df://sha256-z|distributor-0")
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
        """Full breadth-first walk of the provenance DAG from the leaf to its roots.

        Visits every parent of every node, de-dupes shared ancestors, reports
        the number of distinct datasets in the lineage, and returns the
        lexicographically first root (a node with no parents) so the
        substitution attack has a concrete target.
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
        """Try to republish different content under the first supplier's exact name."""
        forged = DatasetMetadata(
            name=self._source_name,
            owner=self._source_id,
            description="tampered-by-attacker",
        )
        attacker_url = await facts.publish(forged)
        collided = int(str(attacker_url) == str(source_url))
        await ctx.send(
            self._id,
            f"attack_substitution|{source_url}|{attacker_url}|{collided}".encode(),
        )

    async def _attack_forged_freshness(self, ctx: AgentContext, facts: Any) -> None:
        """Republish the supplier's content signed by the attacker, then re-check freshness."""
        forged = DatasetMetadata(name=self._source_name, owner=self._source_id)
        forged_url = await facts.publish(forged)
        fresh = await facts.verify_freshness(forged_url)
        await ctx.send(
            self._id,
            f"attack_forged_freshness|{forged_url}|{int(fresh)}".encode(),
        )

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
        await ctx.send(
            self._id,
            f"attack_provenance|{_PHANTOM_PARENT}|{rejected}".encode(),
        )


# ---------------------------------------------------------------------------
# Shared datafacts wiring (mirrors provenance_supply_chain)
# ---------------------------------------------------------------------------


def _build_datafacts_handles(
    datafacts_cls: type[Any],
    identities: dict[AgentId, Any],
    all_ids: list[AgentId],
) -> dict[AgentId, Any]:
    """Instantiate one datafacts handle per agent, sharing state where possible.

    Mirrors the implementation in ``provenance_supply_chain`` exactly: plugins
    accepting ``Identity + datasets/proofs/clock`` kwargs (e.g. ``cid_facts``)
    get per-agent handles over shared dicts; single-instance plugins (e.g.
    ``datafacts_v1``) are shared as-is.

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
            kwargs: dict[str, Any] = {
                "datasets": shared_datasets,
                "proofs": shared_proofs,
            }
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


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def provenance_supply_chain_multi_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the N×M pipeline: suppliers → manufacturers → distributor → retailer.

    Reads ``num_suppliers`` and ``num_manufacturers`` from ``config.task.config``,
    defaulting to 2 and 2 respectively.  Instantiates per-agent identity
    instances and wires the datafacts plugin class into per-agent handles via
    :func:`_build_datafacts_handles`.

    Example::

        agents = provenance_supply_chain_multi_factory(config, plugins)
    """
    task_cfg = config.task.config
    num_suppliers: int = int(task_cfg.get("num_suppliers", 2))
    num_manufacturers: int = int(task_cfg.get("num_manufacturers", 2))

    if num_suppliers < 1:
        msg = "num_suppliers must be >= 1"
        raise ValueError(msg)
    if num_manufacturers < 1:
        msg = "num_manufacturers must be >= 1"
        raise ValueError(msg)

    # Build agent IDs
    supplier_ids = [AgentId(f"supplier-{i}") for i in range(num_suppliers)]
    manufacturer_ids = [AgentId(f"manufacturer-{i}") for i in range(num_manufacturers)]
    distributor_id = AgentId("distributor-0")
    retailer_id = AgentId("retailer-0")
    all_ids = supplier_ids + manufacturer_ids + [distributor_id, retailer_id]

    # Build identities
    identity_cls = plugins.get("identity")
    identities: dict[AgentId, Any] = {}
    if identity_cls is not None and isinstance(identity_cls, type):
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"sim-seed")
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)

    # Wire datafacts handles
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    datafacts_cls = plugins.get("datafacts")
    if datafacts_cls is not None and isinstance(datafacts_cls, type) and identities:
        handles = _build_datafacts_handles(datafacts_cls, identities, all_ids)
        for aid, handle in handles.items():
            agent_plugins.setdefault(aid, {})["datafacts"] = handle
    plugins.pop("datafacts", None)
    plugins.pop("identity", None)

    # Build agents
    agents: dict[AgentId, StateMachineAgent] = {}

    # Suppliers — each sends to all manufacturers
    supplier_names: list[str] = []
    for i, sid in enumerate(supplier_ids):
        name = f"raw_material_{i}"
        supplier_names.append(name)
        agents[sid] = MultiSupplierAgent(sid, manufacturers=manufacturer_ids, name=name)

    # Manufacturers — each waits for all suppliers
    for j, mid in enumerate(manufacturer_ids):
        agents[mid] = MultiManufacturerAgent(
            mid,
            distributor=distributor_id,
            name=f"product_{j}",
            num_suppliers=num_suppliers,
        )

    # Distributor — waits for all manufacturers
    agents[distributor_id] = MultiDistributorAgent(
        distributor_id,
        retailer=retailer_id,
        name="aggregated_batch",
        num_manufacturers=num_manufacturers,
    )

    # Retailer — verifier + attacker, targets the first supplier's root dataset
    agents[retailer_id] = MultiRetailerAgent(
        retailer_id,
        first_supplier_id=supplier_ids[0],
        first_supplier_name=supplier_names[0],
    )

    return agents
