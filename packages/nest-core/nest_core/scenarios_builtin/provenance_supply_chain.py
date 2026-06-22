# SPDX-License-Identifier: Apache-2.0
"""Content-addressed supply-chain provenance scenario with byzantine forgers.

Persona: ``provenance-engineer``. This is the supply-chain scenario re-cast as a
*provenance* test. Four honest hops (supplier -> manufacturer -> distributor ->
retailer) each publish a content-addressed dataset derived from the previous
hop's, building an end-to-end provenance DAG that the retailer verifies. A
fraction of byzantine agents attempt the three attacks the
``content_addressed`` plugin is built to defeat:

* **substitution** — publish *different* content while trying to occupy an
  existing dataset's address;
* **stale-freshness** — claim a dataset is current without re-issuing a signed
  freshness proof;
* **broken provenance** — publish a derived dataset whose ancestry references a
  hash nobody ever published.

Every publish, freshness attestation, verification, and attack is emitted into
the trace in a ``:``-delimited line protocol that the ``provenance_supply_chain``
validators parse (see
``nest_core.validators.validate_datafacts_*``). Behaviour is *capability-gated*
via ``hasattr``: run the same scenario with ``datafacts: datafacts_v1`` and the
hops fall back to name-addressed publishes with no signed proofs and no
provenance checks — the validators then fail, which is the honest demonstration
that ``datafacts_v1`` cannot catch any of the three attacks. Under
``datafacts: content_addressed`` the same scenario passes.

Trace line protocol (carried in message bodies to the auditor):

* ``publish:<agent>:<url>:<parents>:<tick>`` — a publish; ``parents`` is a
  ``|``-joined list of parent URLs or ``-``.
* ``freshness:<agent>:<url>:<proof_tick>:<observed_tick>:<verdict>`` — a
  freshness attestation; ``proof_tick`` is the tick the proof was signed at (or
  ``none`` for an unsigned/keyless plugin); ``verdict`` is ``ok`` (current) or
  ``stale`` (a deliberately non-current claim).
* ``verify:<agent>:<url>:<verdict>`` — the retailer's end-to-end provenance
  check; ``ok``, ``broken``, or ``unverifiable`` (plugin can't verify).
* ``attack:substitution:<agent>:<url1>:<url2>`` — two publishes of *different*
  content; ``url1 == url2`` means substitution succeeded.
* ``attack:broken:<agent>:<ghost_url>:<verdict>`` — a derived publish anchored
  to a never-published parent; ``rejected`` or ``accepted``.

Example::

    agents = provenance_supply_chain_factory(config, plugins)
"""

from __future__ import annotations

import inspect
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata


def _datafacts_of(ctx: AgentContext) -> Any:
    """Return the per-agent datafacts instance from the agent's context.

    Example::

        df = _datafacts_of(ctx)
    """
    return ctx.plugins.get("datafacts")


def _is_content_addressed(df: Any) -> bool:
    """Return whether ``df`` exposes the content-addressed capability surface.

    Example::

        ok = _is_content_addressed(ctx.plugins.get("datafacts"))
    """
    return hasattr(df, "content_id") and hasattr(df, "issue_freshness_proof")


def _tok(url: str) -> str:
    """Render a DataFacts URL as a colon-free trace token (scheme stripped).

    The ``:``-delimited line protocol cannot carry the ``df://`` scheme (it
    contains a colon), so trace tokens use the bare content id — ``sha256-<hex>``
    for the content-addressed plugin, or the bare name for ``datafacts_v1``. The
    presence or absence of the ``sha256-`` prefix is exactly what the
    content-addressing validator keys on.

    Example::

        assert _tok("df://sha256-abc") == "sha256-abc"
    """
    return url.removeprefix("df://")


def _parents_token(parents: list[DataFactsUrl]) -> str:
    """Render a parent-URL list as ``|``-joined colon-free tokens (``-`` when empty).

    Example::

        token = _parents_token([DataFactsUrl("df://sha256-a")])  # "sha256-a"
    """
    return "|".join(_tok(p) for p in parents) if parents else "-"


async def _publish(
    df: Any,
    ctx: AgentContext,
    name: str,
    parents: list[DataFactsUrl],
) -> DataFactsUrl:
    """Publish a dataset at the current tick and return its URL.

    Sets the plugin clock to ``ctx.time`` first so signed proofs bind to the
    simulator's logical tick (Tier 1 determinism).

    Example::

        url = await _publish(df, ctx, "good-0", [])
    """
    if hasattr(df, "set_clock"):
        df.set_clock(ctx.time)
    meta = DatasetMetadata(name=name, owner=ctx.agent_id, parents=list(parents))
    return await df.publish(meta)


class ChainHop(StateMachineAgent):
    """An honest supply-chain hop: publishes a derived dataset and re-attests it.

    The first hop (``is_origin``) publishes a root dataset on start and forwards
    its URL downstream. Each subsequent hop publishes a dataset whose ``parents``
    is the predecessor's URL, extending the provenance DAG, and forwards. On every
    auditor ``tick:`` pulse a hop re-issues a *current* signed freshness proof for
    its own dataset, so honest freshness is always backed by a proof at the
    observed tick. The final hop (``is_terminal``) additionally verifies the full
    provenance chain end-to-end and emits a ``verify:`` line.

    Example::

        hop = ChainHop(AgentId("supplier-0"), AgentId("manufacturer-0"),
                       AgentId("auditor-0"), is_origin=True)
    """

    def __init__(
        self,
        agent_id: AgentId,
        next_stage: AgentId | None,
        auditor: AgentId,
        is_origin: bool = False,
        is_terminal: bool = False,
    ) -> None:
        self._id = agent_id
        self._next = next_stage
        self._auditor = auditor
        self._is_origin = is_origin
        self._is_terminal = is_terminal
        self._url: DataFactsUrl | None = None

    async def _emit_publish(self, ctx: AgentContext, parents: list[DataFactsUrl]) -> None:
        df = _datafacts_of(ctx)
        if df is None:  # pragma: no cover - scenario always configures datafacts
            return
        url = await _publish(df, ctx, f"dataset-{self._id}", parents)
        self._url = url
        await ctx.send(
            self._auditor,
            f"publish:{self._id}:{_tok(url)}:{_parents_token(parents)}:{ctx.time}".encode(),
        )
        await self._emit_freshness(ctx)
        if self._next is not None:
            await ctx.send(self._next, f"derive:{url}".encode())
        if self._is_terminal:
            await self._emit_verify(ctx, url)

    async def _emit_freshness(self, ctx: AgentContext) -> None:
        df = _datafacts_of(ctx)
        if df is None or self._url is None:
            return
        if _is_content_addressed(df):
            df.set_clock(ctx.time)
            proof = df.issue_freshness_proof(self._url)
            proof_tick: str = str(proof.tick)
        else:
            proof_tick = "none"
        await ctx.send(
            self._auditor,
            f"freshness:{self._id}:{_tok(self._url)}:{proof_tick}:{ctx.time}:ok".encode(),
        )

    async def _emit_verify(self, ctx: AgentContext, url: DataFactsUrl) -> None:
        df = _datafacts_of(ctx)
        if df is None:
            return
        if hasattr(df, "verify_provenance"):
            verdict = "ok" if df.verify_provenance(url) else "broken"
        else:
            verdict = "unverifiable"
        await ctx.send(self._auditor, f"verify:{self._id}:{_tok(url)}:{verdict}".encode())

    async def on_start(self, ctx: AgentContext) -> None:
        """Origin hop seeds the chain; other hops wait for an upstream URL.

        Example::

            await hop.on_start(ctx)
        """
        if self._is_origin:
            await self._emit_publish(ctx, parents=[])

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Publish on an upstream ``derive:`` URL; re-attest on auditor ``tick:``.

        Example::

            await hop.on_message(ctx, AgentId("supplier-0"), b"derive:df://sha256-a")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("derive:"):
            parent = DataFactsUrl(msg.split(":", 1)[1])
            await self._emit_publish(ctx, parents=[parent])
        elif msg.startswith("tick:"):
            await self._emit_freshness(ctx)


class ProvenanceByzantine(StateMachineAgent):
    """A byzantine agent that attempts substitution, stale-freshness, and forgery.

    Each attack is self-contained and deterministic. Against ``content_addressed``
    all three are deflected (substitution yields a *different* address, stale
    claims carry a non-current proof tick, broken-provenance publishes raise); the
    emitted lines record the deflection so the validators can confirm it. Against
    ``datafacts_v1`` the same attacks succeed, and the validators fail — which is
    the point.

    Example::

        byz = ProvenanceByzantine(AgentId("byz-0"), AgentId("auditor-0"))
    """

    def __init__(self, agent_id: AgentId, auditor: AgentId) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._url: DataFactsUrl | None = None
        self._published_tick: float = 0.0

    async def _attack_substitution(self, ctx: AgentContext) -> None:
        df = _datafacts_of(ctx)
        if df is None:
            return
        if hasattr(df, "set_clock"):
            df.set_clock(ctx.time)
        # Publish two datasets that share a *name* but differ in content. A
        # content-addressed store gives them different URLs (substitution
        # impossible); a name-addressed store collapses them (substitution).
        url1 = await df.publish(DatasetMetadata(name=f"victim-{self._id}", owner=self._id))
        url2 = await df.publish(
            DatasetMetadata(name=f"victim-{self._id}", owner=self._id, description="tampered")
        )
        self._url = url1
        self._published_tick = ctx.time
        await ctx.send(
            self._auditor,
            f"publish:{self._id}:{_tok(url1)}:-:{ctx.time}".encode(),
        )
        await ctx.send(
            self._auditor,
            f"attack:substitution:{self._id}:{_tok(url1)}:{_tok(url2)}".encode(),
        )

    async def _attack_stale(self, ctx: AgentContext) -> None:
        if self._url is None:
            return
        df = _datafacts_of(ctx)
        if df is None:
            return
        # Claim freshness at the *current* observed tick while pointing at the
        # ORIGINAL proof tick — i.e. no re-issued signature. Content-addressed:
        # proof_tick < observed, detectable. Name-addressed: no proof at all.
        if _is_content_addressed(df):
            proof_tick: str = str(self._published_tick)
        else:
            proof_tick = "none"
        await ctx.send(
            self._auditor,
            f"freshness:{self._id}:{_tok(self._url)}:{proof_tick}:{ctx.time}:stale".encode(),
        )

    async def _attack_broken(self, ctx: AgentContext) -> None:
        df = _datafacts_of(ctx)
        if df is None:
            return
        if hasattr(df, "set_clock"):
            df.set_clock(ctx.time)
        ghost = DataFactsUrl("df://sha256-" + "0" * 64)
        meta = DatasetMetadata(name=f"forged-{self._id}", owner=self._id, parents=[ghost])
        verdict = "accepted"
        try:
            url = await df.publish(meta)
        except Exception:  # noqa: BLE001 - any rejection (BrokenProvenanceError) deflects the attack
            verdict = "rejected"
        else:
            # The publish was accepted; record the orphan so the validator sees it.
            await ctx.send(
                self._auditor,
                f"publish:{self._id}:{_tok(url)}:{_tok(ghost)}:{ctx.time}".encode(),
            )
        await ctx.send(
            self._auditor,
            f"attack:broken:{self._id}:{_tok(ghost)}:{verdict}".encode(),
        )

    async def on_start(self, ctx: AgentContext) -> None:
        """Launch the substitution attack and publish the byzantine's dataset.

        Example::

            await byz.on_start(ctx)
        """
        await self._attack_substitution(ctx)
        await self._attack_broken(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On each auditor ``tick:`` pulse, attempt the stale-freshness attack.

        Example::

            await byz.on_message(ctx, AgentId("auditor-0"), b"tick:2")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("tick:"):
            await self._attack_stale(ctx)


class AuditorAgent(StateMachineAgent):
    """Drives rounds; the trace is the audit log.

    Pulses every hop and byzantine agent once per round (``tick:`` messages) at a
    strictly increasing logical tick, so the observed tick the validators anchor
    freshness to advances deterministically. All verification happens offline in
    the ``provenance_supply_chain`` validators against the emitted trace.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"), members, rounds=4)
    """

    def __init__(self, agent_id: AgentId, members: list[AgentId], rounds: int = 4) -> None:
        self._id = agent_id
        self._members = members
        self._rounds = rounds
        self._round = 1

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the first round pulse one tick ahead so the clock advances.

        Example::

            await auditor.on_start(ctx)
        """
        await self._schedule_next(ctx)

    async def _schedule_next(self, ctx: AgentContext) -> None:
        if self._round >= self._rounds:
            return
        await ctx.schedule(1.0, b"pulse:")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Advance one round on each self-scheduled ``pulse:`` tick.

        Example::

            await auditor.on_message(ctx, AgentId("auditor-0"), b"pulse:")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("pulse:"):
            return
        self._round += 1
        for member in self._members:
            await ctx.send(member, f"tick:{self._round}".encode())
        await self._schedule_next(ctx)


def _provision_datafacts(plugins: dict[str, Any], hop_ids: list[AgentId]) -> None:
    """Give each agent a datafacts instance, sharing one content-addressed store.

    Mirrors ``identity_rotation``'s identity provisioning: resolve the class at
    ``plugins["datafacts"]``, build per-agent instances over a *shared* store
    (so substitution resistance spans the whole swarm), each signing with its own
    deterministic ``did_key`` identity, and stash them under
    ``plugins["_agent_plugins"]``. Capability-gated: a plugin whose constructor
    does not accept ``store`` (e.g. ``datafacts_v1``) is instantiated once and
    shared by reference, so the scenario still runs and the validators expose its
    weaker guarantees.

    Example::

        _provision_datafacts(plugins, [AgentId("supplier-0"), AgentId("byz-0")])
    """
    df_cls = plugins.get("datafacts")
    if not isinstance(df_cls, type):
        return

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    params = inspect.signature(df_cls.__init__).parameters

    if "store" in params and "identity" in params:
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        shared_store: dict[Any, Any] = {}
        identities = {
            aid: DidKeyIdentity(aid, seed=b"provenance:" + str(aid).encode()) for aid in hop_ids
        }
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)
        for aid in hop_ids:
            inst = df_cls(identity=identities[aid], store=shared_store)
            agent_plugins.setdefault(aid, {})["datafacts"] = inst
    else:
        shared = df_cls()
        for aid in hop_ids:
            agent_plugins.setdefault(aid, {})["datafacts"] = shared

    plugins.pop("datafacts", None)


def provenance_supply_chain_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the honest 4-hop chain, byzantine attackers, and one auditor.

    The byzantine count comes from ``failures.byzantine_agents`` (default 0.20)
    or an explicit ``byzantine`` role. Every agent shares one content-addressed
    store provisioned from the configured datafacts plugin, so swapping
    ``datafacts: datafacts_v1`` in the YAML genuinely changes behaviour and the
    validators can tell the plugins apart.

    Example::

        agents = provenance_supply_chain_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 4))
    byzantine_fraction = config.failures.byzantine_agents or task_config.get(
        "byzantine_fraction", 0.20
    )

    byzantine_count = max(1, int(4 * byzantine_fraction))
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "byzantine":
                byzantine_count = role.count

    auditor_id = AgentId("auditor-0")
    supplier_id = AgentId("supplier-0")
    manufacturer_id = AgentId("manufacturer-0")
    distributor_id = AgentId("distributor-0")
    retailer_id = AgentId("retailer-0")
    byzantine_ids = [AgentId(f"byz-{i}") for i in range(byzantine_count)]

    chain_ids = [supplier_id, manufacturer_id, distributor_id, retailer_id]
    members = chain_ids + byzantine_ids
    _provision_datafacts(plugins, members)

    agents: dict[AgentId, StateMachineAgent] = {
        supplier_id: ChainHop(supplier_id, manufacturer_id, auditor_id, is_origin=True),
        manufacturer_id: ChainHop(manufacturer_id, distributor_id, auditor_id),
        distributor_id: ChainHop(distributor_id, retailer_id, auditor_id),
        retailer_id: ChainHop(retailer_id, None, auditor_id, is_terminal=True),
    }
    for aid in byzantine_ids:
        agents[aid] = ProvenanceByzantine(aid, auditor_id)

    agents[auditor_id] = AuditorAgent(auditor_id, members=members, rounds=rounds)
    return agents
