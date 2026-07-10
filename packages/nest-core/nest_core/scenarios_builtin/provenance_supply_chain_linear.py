# SPDX-License-Identifier: Apache-2.0
"""Content-addressed provenance scenario: a deep *linear* supply chain, then attacks.

Where ``provenance_supply_chain`` (#31) is a **diamond** that stresses lineage
*fan-out* (a join whose ancestry forks back to a shared root), this scenario is a
**linear spine** that stresses lineage *depth* -- the canonical physical
supply-chain shape::

    supplier-0 -> manufacturer-0 -> distributor-0 -> retailer-0 -> auditor-0

Each producer hop publishes a *dataset* through ``plugins["datafacts"]`` and
declares exactly the previous hop's dataset as its single provenance parent, so
the lineage is one unbranched chain four hops long. A linear chain is just a
diamond with the fan-out removed, so the producer hops and the shared datafacts
wiring are **reused directly** from ``provenance_supply_chain``: the supplier is
a ``SourceAgent`` fanning out to a single downstream, and each middle hop is a
``RefineAgent``. Only ``AuditorAgent`` is defined here, because it does something
the diamond's verifier does not -- it measures the lineage *depth*.

``auditor-0``:

1. **Verifies** -- walks the whole parent chain from the retailer's dataset back
   to the supplier's root, reporting both the number of distinct datasets
   (``chain_ok``) *and* the longest root-path length (``chain_depth``). The depth
   is what distinguishes this scenario from the diamond: a four-hop spine is
   depth 4, whereas the diamond's longest path is only 3, even though both have
   four distinct nodes. A single broken hop anywhere along a deep chain must
   still surface as a break.
2. **Attacks** -- as an *outsider* (signing with its own identity, never the
   supplier's), it runs the three provenance attacks against the root:
   substitution, forged freshness, and broken provenance.

Every step is reported as a ``|``-delimited trace message (``:`` collides with
the ``df://`` URL scheme) using the *same* wire protocol as the diamond
scenario, so the two share one validator set: point ``layers.datafacts`` at
``cid_facts`` and every adversarial validator passes; point it at
``datafacts_v1`` and they fail. The extra ``chain_depth`` message is ignored by
the shared validators (which match exact prefixes), so validator reuse is
unaffected.

Example::

    agents = provenance_supply_chain_linear_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig

# Reuse the diamond scenario's producer agents and datafacts wiring rather than
# copying them: the two scenarios are twins that share one validator set, so a
# second copy of the emitters could silently drift. These package-internal
# helpers are deliberately reused (see PR #51 review); the ignores keep
# provenance_supply_chain itself untouched instead of widening its public API.
from nest_core.scenarios_builtin.provenance_supply_chain import (
    _PHANTOM_PARENT,  # pyright: ignore[reportPrivateUsage]
    RefineAgent,
    SourceAgent,
    _build_datafacts_handles,  # pyright: ignore[reportPrivateUsage]
    _parents_of,  # pyright: ignore[reportPrivateUsage]
)
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DatasetMetadata

# The producer hops of the linear chain, upstream-to-downstream. Kept as data so
# the spine is easy to read and to lengthen; the auditor is appended separately.
_CHAIN: tuple[str, ...] = ("supplier", "manufacturer", "distributor", "retailer")


class AuditorAgent(StateMachineAgent):
    """Walks the deep linear lineage measuring its depth, then attacks as an outsider.

    Unlike the diamond's verifier, this reports the longest root-path length
    (``chain_depth``) alongside the distinct-node count, so the trace makes the
    scenario's defining property -- lineage *depth* -- verifiable rather than
    indistinguishable from a shallow fan-out.

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
        """Walk the parent chain from the leaf to its root, reporting size and depth.

        Follows every declared parent (so a mis-wired fork would still be caught)
        and de-dupes. Each node is pushed with its distance from the leaf, so the
        longest root-path length can be emitted as ``chain_depth`` -- for an
        unbranched chain this is simply the number of hops (4 here), which is the
        one property that distinguishes this scenario from the diamond (whose
        longest path is 3). Also emits ``chain_ok`` with the distinct-node count.
        Returns the single root (a node with no parents) so the substitution
        attack can target the true supplier. A parent that does not resolve is a
        broken chain.
        """
        seen: set[str] = set()
        roots: list[str] = []
        max_depth = 0
        stack: list[tuple[str, int]] = [(leaf_url, 1)]
        while stack:
            url, dist = stack.pop()
            if url in seen:
                continue
            seen.add(url)
            max_depth = max(max_depth, dist)
            try:
                meta: DatasetMetadata = await facts.fetch(url)
            except KeyError:
                await ctx.send(self._id, f"chain_broken|{leaf_url}|{url}".encode())
                return None
            parents = _parents_of(meta)
            if parents:
                stack.extend((parent, dist + 1) for parent in parents)
            else:
                roots.append(url)
        await ctx.send(self._id, f"chain_ok|{leaf_url}|{len(seen)}".encode())
        await ctx.send(self._id, f"chain_depth|{leaf_url}|{max_depth}".encode())
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


def provenance_supply_chain_linear_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the linear chain: supplier -> manufacturer -> distributor -> retailer -> auditor.

    Reuses ``SourceAgent`` (as the supplier, fanning out to a single downstream)
    and ``RefineAgent`` (as each middle hop) from ``provenance_supply_chain``;
    only the depth-measuring ``AuditorAgent`` is local. Instantiates per-agent
    identity instances so each hop signs as itself, and wires the resolved
    ``datafacts`` plugin class into per-agent handles.

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
    downstream = {producer_ids[i]: producer_ids[i + 1] for i in range(len(producer_ids) - 1)}
    downstream[producer_ids[-1]] = auditor_id

    agents: dict[AgentId, StateMachineAgent] = {
        # A linear supplier is just a SourceAgent that fans out to one downstream.
        source_id: SourceAgent(
            source_id, refiners=[downstream[source_id]], name=source_name, description="lot-A"
        )
    }
    # Middle hops are RefineAgents forwarding to the next id in the spine.
    for aid in producer_ids[1:]:
        agents[aid] = RefineAgent(aid, aggregator=downstream[aid], name=f"{aid}_dataset")
    agents[auditor_id] = AuditorAgent(auditor_id, source_id=source_id, source_name=source_name)
    return agents
