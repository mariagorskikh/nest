# SPDX-License-Identifier: Apache-2.0
"""Provenance supply-chain scenario — content-addressed DataFacts end-to-end.

Each participant in the supply-chain DAG publishes a content-addressed dataset
via the `cid_facts` plugin and emits structured trace events that the
`provenance_supply_chain` validators can inspect:

* ``publish:df://sha256-<hex>:<agent_id>``
* ``freshness_proof:df://sha256-<hex>:<tick>:<sig_hex>``
* ``derived:df://sha256-<child>:df://sha256-<parent1>[,df://sha256-<parent2>]``
* ``provenance_audit:<url>:nodes=<n>:ancestors=<url1>,<url2>,...``

The topology is configurable via ``num_suppliers`` (default 2) and
``num_manufacturers`` (default 2) in the task config block.  Agent IDs are
``supplier-0 … supplier-(N-1)`` and ``manufacturer-0 … manufacturer-(M-1)``.

Flow (default 2×2)::

```
supplier-0 and supplier-1
  └─ each publishes raw-material datasets
  └─ each forwards dataset URLs to all manufacturers

manufacturer-0 and manufacturer-1
  └─ each waits until ALL supplier URLs are received
     for the same round/item
  └─ publishes a manufactured-goods dataset with all supplier URLs as parents
  └─ emits a derived trace event
  └─ forwards the dataset URL to Distributor

Distributor
  └─ waits until ALL manufacturer URLs are received
     for the same round/item
  └─ publishes a shipment dataset with all manufacturer URLs as parents
  └─ emits a derived trace event
  └─ forwards the dataset URL to Retailer

Retailer
  └─ receives distributor dataset URL
  └─ verifies freshness proofs
  └─ walks the complete provenance DAG
  └─ verifies every ancestor dataset
  └─ emits chain-verified or chain-failed events
  └─ emits provenance_audit event with full ancestor list
```

Provenance DAG (default 2×2)::

    supplier-0 ─────┬─► manufacturer-0 ──┐
                    │                     │
                    └─► manufacturer-1 ──┤
                                          │
    supplier-1 ─────┬─► manufacturer-0 ──┤
                    │                     │
                    └─► manufacturer-1 ──┘
                                          │
                                          ▼
                                    distributor-0
                                          │
                                          ▼
                                     retailer-0

This scenario demonstrates a true multi-parent provenance DAG rather than
a simple linear chain. Manufacturer datasets depend on multiple supplier
datasets, and shipment datasets depend on multiple manufacturer datasets.
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_df(agent_id: AgentId, plugins: dict[str, Any]) -> Any:
    """Instantiate a ``CidFacts`` (or ``DataFactsV1``) from the plugin registry.

    ``plugins["datafacts"]`` holds the resolved plugin *class*, not an
    instance.  ``CidFacts`` requires a ``DidKeyIdentity`` argument; this
    helper constructs one keyed to *agent_id* with a deterministic seed.
    Falls back to no-arg construction for ``DataFactsV1``-style classes.
    """
    import hashlib
    import inspect

    datafacts_cls = plugins.get("datafacts")
    if datafacts_cls is None:
        return None

    params = inspect.signature(datafacts_cls.__init__).parameters
    required = [
        p for name, p in params.items() if name != "self" and p.default is inspect.Parameter.empty
    ]
    if not required:
        return datafacts_cls()

    identity_cls = plugins.get("identity")
    if identity_cls is None:
        try:
            return datafacts_cls()
        except TypeError:
            return None

    seed = hashlib.sha256(str(agent_id).encode()).digest()
    identity = identity_cls(agent_id, seed=seed)
    return datafacts_cls(identity)


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


class CidSupplierAgent(StateMachineAgent):
    """Produces a content-addressed raw-materials dataset and forwards the URL."""

    def __init__(
        self,
        agent_id: AgentId,
        next_stages: list[AgentId],
        df: Any,
        items_per_round: int = 2,
        rounds: int = 3,
    ) -> None:
        self._id = agent_id
        self._next_stages = next_stages
        self._df = df
        self._items_per_round = items_per_round
        self._rounds = rounds

    async def on_start(self, ctx: AgentContext) -> None:
        df = self._df

        for rnd in range(1, self._rounds + 1):
            for item in range(self._items_per_round):
                batch_id = f"raw-{self._id}-r{rnd}-i{item}"
                meta = DatasetMetadata(
                    name=batch_id,
                    owner=self._id,
                    description=f"Raw materials batch {batch_id}",
                    tags=["raw", "supplier"],
                    # Bind payload content: store a digest in metadata so the
                    # CID covers actual content, not just structural metadata.
                    metadata={"content_sha256": _fake_content_hash(batch_id)},
                )

                if df is not None:
                    url = await df.publish(meta)
                    proof = (
                        df.get_freshness_proof(url) if hasattr(df, "get_freshness_proof") else None
                    )

                    # Emit structured trace events for validators.
                    sig_hex = proof.signature.value.hex() if proof else "none"
                    tick_str = str(proof.tick) if proof else "0"
                    publisher = str(self._id)
                    for next_stage in self._next_stages:
                        await ctx.send(
                            next_stage,
                            f"publish:{url}:{publisher}".encode(),
                        )
                    for next_stage in self._next_stages:
                        await ctx.send(
                            next_stage,
                            f"freshness_proof:{url}:{tick_str}:{sig_hex}".encode(),
                        )
                    # Forward URL to next stage.
                    for next_stage in self._next_stages:
                        await ctx.send(
                            next_stage,
                            f"cid_url:{rnd}:{item}:{url}".encode(),
                        )
                else:
                    # Fallback: no datafacts plugin — use raw message protocol.
                    for next_stage in self._next_stages:
                        await ctx.send(
                            next_stage,
                            f"material:{rnd}:{batch_id}".encode(),
                        )


class CidManufacturerAgent(StateMachineAgent):
    """Receives supplier URLs, publishes a derived manufactured-goods dataset.

    Waits until ``num_suppliers`` distinct URLs have arrived for the same
    ``(round, item)`` key before publishing, mirroring the N-way fan-in.
    """

    def __init__(
        self,
        agent_id: AgentId,
        next_stage: AgentId,
        df: Any,
        num_suppliers: int = 2,
    ) -> None:
        self._id = agent_id
        self._next = next_stage
        self._counter = 0
        self._df = df
        self._num_suppliers = num_suppliers
        self._supplier_urls: dict[str, list[str]] = {}

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        df = self._df

        # Consume the forwarded supplier URL.
        if msg.startswith("cid_url:"):
            # Format: cid_url:{rnd}:{item}:{url}  — url contains ://  so
            # split with maxsplit=3 to keep the full URL intact.
            parts = msg.split(":", 3)
            if len(parts) < 4:
                return
            rnd, item, supplier_url = parts[1], parts[2], parts[3]

            key = f"{rnd}:{item}"
            urls = self._supplier_urls.setdefault(key, [])

            if supplier_url not in urls:
                urls.append(supplier_url)

            if len(urls) < self._num_suppliers:
                return

            self._counter += 1
            product_id = f"good-{self._id}-r{rnd}-i{item}"

            parents = [DataFactsUrl(url) for url in urls]

            if df is not None:
                meta = DatasetMetadata(
                    name=product_id,
                    owner=self._id,
                    description=f"Manufactured goods {product_id}",
                    tags=["goods", "manufacturer"],
                    metadata={"content_sha256": _fake_content_hash(product_id)},
                    parents=parents,
                )
                url = await df.publish(meta)
                proof = df.get_freshness_proof(url) if hasattr(df, "get_freshness_proof") else None

                sig_hex = proof.signature.value.hex() if proof else "none"
                tick_str = str(proof.tick) if proof else "0"

                # Emit trace events.
                await ctx.send(self._next, f"publish:{url}:{self._id}".encode())
                await ctx.send(
                    self._next,
                    f"freshness_proof:{url}:{tick_str}:{sig_hex}".encode(),
                )
                await ctx.send(
                    self._next,
                    f"derived:{url}:{','.join(str(parent) for parent in parents)}".encode(),
                )
                await ctx.send(
                    self._next,
                    f"cid_url:{rnd}:{item}:{url}".encode(),
                )
            else:
                await ctx.send(
                    self._next,
                    f"product:{rnd}:{product_id}".encode(),
                )


class CidDistributorAgent(StateMachineAgent):
    """Receives manufacturer URLs, publishes a derived shipment dataset.

    Waits until ``num_manufacturers`` distinct URLs have arrived for the same
    ``(round, item)`` key before publishing, mirroring the M-way fan-in.
    """

    def __init__(
        self,
        agent_id: AgentId,
        next_stage: AgentId,
        df: Any,
        num_manufacturers: int = 2,
    ) -> None:
        self._id = agent_id
        self._next = next_stage
        self._counter = 0
        self._df = df
        self._num_manufacturers = num_manufacturers
        self._manufacturer_urls: dict[str, list[str]] = {}

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        df = self._df

        if msg.startswith("cid_url:"):
            # Format: cid_url:{rnd}:{item}:{url}  — split with maxsplit=3.
            parts = msg.split(":", 3)
            if len(parts) < 4:
                return
            rnd, item, mfg_url = parts[1], parts[2], parts[3]
            key = f"{rnd}:{item}"

            urls = self._manufacturer_urls.setdefault(key, [])

            if mfg_url not in urls:
                urls.append(mfg_url)

            if len(urls) < self._num_manufacturers:
                return

            parents = [DataFactsUrl(url) for url in urls]
            self._counter += 1
            shipment_id = f"shipment-{self._id}-r{rnd}-i{item}"

            if df is not None:
                meta = DatasetMetadata(
                    name=shipment_id,
                    owner=self._id,
                    description=f"Shipment {shipment_id}",
                    tags=["shipment", "distributor"],
                    metadata={"content_sha256": _fake_content_hash(shipment_id)},
                    parents=parents,
                )
                url = await df.publish(meta)
                proof = df.get_freshness_proof(url) if hasattr(df, "get_freshness_proof") else None

                sig_hex = proof.signature.value.hex() if proof else "none"
                tick_str = str(proof.tick) if proof else "0"

                await ctx.send(self._next, f"publish:{url}:{self._id}".encode())
                await ctx.send(
                    self._next,
                    f"freshness_proof:{url}:{tick_str}:{sig_hex}".encode(),
                )
                await ctx.send(
                    self._next,
                    f"derived:{url}:{','.join(str(parent) for parent in parents)}".encode(),
                )
                await ctx.send(
                    self._next,
                    f"cid_url:{rnd}:{item}:{url}".encode(),
                )
            else:
                await ctx.send(
                    self._next,
                    f"shipment:{rnd}:{shipment_id}".encode(),
                )


class CidRetailerAgent(StateMachineAgent):
    """Receives distributor URL, verifies freshness + provenance chain end-to-end."""

    def __init__(self, agent_id: AgentId, origin: AgentId, df: Any) -> None:
        self._id = agent_id
        self._origin = origin
        self._received = 0
        self._df = df

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        df = self._df

        if msg.startswith("cid_url:"):
            # Format: cid_url:{rnd}:{item}:{url}  — split with maxsplit=3.
            parts = msg.split(":", 3)
            if len(parts) < 4:
                return
            rnd, item, dist_url = parts[1], parts[2], parts[3]
            self._received += 1

            if df is not None:
                # Verify freshness of the final-hop dataset.
                fresh = await df.verify_freshness(DataFactsUrl(dist_url))

                # Walk provenance chain: fetch dist -> mfg -> supplier.
                chain_valid = await _verify_chain(df, DataFactsUrl(dist_url))

                status = "chain-verified" if (fresh and chain_valid) else "chain-failed"
                await ctx.send(
                    self._origin,
                    f"{status}:{rnd}:{item}:{dist_url}".encode(),
                )
                # Also emit a final delivered event compatible with supply_chain validators.
                await ctx.send(
                    self._origin,
                    f"delivered:{rnd}:{item}".encode(),
                )
                # Emit provenance audit: walk the full DAG and list all ancestors.
                if fresh and chain_valid:
                    ancestors = await _collect_ancestors(df, DataFactsUrl(dist_url))
                    ancestor_list = ",".join(sorted(str(a) for a in ancestors))
                    await ctx.send(
                        self._origin,
                        f"provenance_audit:{dist_url}:nodes={len(ancestors)}:ancestors={ancestor_list}".encode(),
                    )
            else:
                await ctx.send(
                    self._origin,
                    f"delivered:{rnd}:{item}".encode(),
                )


# ---------------------------------------------------------------------------
# Provenance chain walk
# ---------------------------------------------------------------------------


async def _collect_ancestors(df: Any, url: DataFactsUrl) -> set[DataFactsUrl]:
    """Return every ancestor reachable from url by walking the provenance DAG."""
    visited: set[DataFactsUrl] = set()
    ancestors: set[DataFactsUrl] = set()
    stack: list[DataFactsUrl] = [url]

    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)

        try:
            meta = await df.fetch(current)
        except KeyError:
            continue

        for parent_url in meta.parents:
            ancestors.add(parent_url)
            stack.append(parent_url)

    return ancestors


async def _verify_chain(df: Any, url: DataFactsUrl) -> bool:
    """Walk the provenance DAG and verify freshness at every hop.

    Returns ``True`` iff every dataset in the chain has a valid freshness
    proof.  Returns ``False`` on the first broken link or missing dataset.
    """
    visited: set[DataFactsUrl] = set()
    queue: list[DataFactsUrl] = [url]

    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)

        try:
            meta = await df.fetch(current)
        except KeyError:
            return False  # missing dataset in chain

        fresh = await df.verify_freshness(current)
        if not fresh:
            return False

        for parent_url in meta.parents:
            queue.append(parent_url)

    return True


# ---------------------------------------------------------------------------
# Content hash helper (simulation stand-in for actual payload hashing)
# ---------------------------------------------------------------------------


def _fake_content_hash(payload_id: str) -> str:
    """Return a deterministic hex digest representing payload content.

    In a real system this would be sha256(actual_payload_bytes).  In
    simulation we derive it from the payload identifier string so that
    two datasets with different names always get different content hashes.
    """
    import hashlib

    return hashlib.sha256(payload_id.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def provenance_supply_chain_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create a content-addressed provenance supply chain.

    Builds **one shared** ``CidFacts`` instance and passes it to every agent.
    All agents share the same in-memory dataset registry, so the retailer can
    verify freshness proofs for datasets that upstream agents published.

    The ``datafacts`` layer must be set to ``cid_facts`` in the scenario YAML.
    The ``identity`` layer must also be set (e.g. ``did_key``).

    Configuration keys (all optional with defaults shown)::

        task:
          config:
            num_suppliers: 2       # N suppliers: supplier-0 … supplier-(N-1)
            num_manufacturers: 2   # M manufacturers: manufacturer-0 … manufacturer-(M-1)
            items_per_round: 2
            rounds: 3

    Example::

        agents = provenance_supply_chain_factory(config, plugins)
    """
    task_config = config.task.config
    items_per_round = task_config.get("items_per_round", 2)
    rounds = task_config.get("rounds", 3)
    num_suppliers = int(task_config.get("num_suppliers", 2))
    num_manufacturers = int(task_config.get("num_manufacturers", 2))

    retailer_id = AgentId("retailer-0")
    distributor_id = AgentId("distributor-0")

    supplier_ids = [AgentId(f"supplier-{i}") for i in range(num_suppliers)]
    manufacturer_ids = [AgentId(f"manufacturer-{i}") for i in range(num_manufacturers)]

    # Build one shared datafacts instance.  All agents write to and read from
    # the same in-memory registry so the retailer can look up proofs created
    # by upstream agents.  We use the first supplier's identity as the signing
    # key; each agent's datasets are attributed via DatasetMetadata.owner.
    seed_id = supplier_ids[0] if supplier_ids else AgentId("supplier-0")
    shared_df = _make_df(seed_id, plugins)

    agents: dict[AgentId, StateMachineAgent] = {}

    # --- Suppliers: each forwards its URL to every manufacturer ---
    for sup_id in supplier_ids:
        agents[sup_id] = CidSupplierAgent(
            sup_id,
            next_stages=list(manufacturer_ids),
            df=shared_df,
            items_per_round=items_per_round,
            rounds=rounds,
        )

    # --- Manufacturers: each waits for all num_suppliers URLs ---
    for mfg_id in manufacturer_ids:
        agents[mfg_id] = CidManufacturerAgent(
            mfg_id,
            next_stage=distributor_id,
            df=shared_df,
            num_suppliers=num_suppliers,
        )

    # --- Distributor: waits for all num_manufacturers URLs ---
    agents[distributor_id] = CidDistributorAgent(
        distributor_id,
        next_stage=retailer_id,
        df=shared_df,
        num_manufacturers=num_manufacturers,
    )

    # --- Retailer: verifies the full chain ---
    agents[retailer_id] = CidRetailerAgent(retailer_id, origin=seed_id, df=shared_df)

    return agents
