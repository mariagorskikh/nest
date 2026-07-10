# SPDX-License-Identifier: Apache-2.0
"""Serialization-invariance scenario: provenance laundering by re-encoding.

The pipeline is a short audit chain with an attacker in the middle::

    supplier-0  --publishes-->  quarantined dataset
        |
    launder-0   --re-encodes the SAME logical content, republishes under a
        |         new name/checksum, hoping for a fresh, clean address
    audit-0     --tamper-checks a genuinely modified copy, tries a phantom
                  parent, and reports whether the launder attempt forked

The attack this scenario probes is the one *byte-level* content addressing
(``cid_facts``) cannot catch: re-serialize identical content (int -> float,
key reorder, NFC -> NFD unicode) and the byte digest changes, so the copy
arrives with a clean URL -- quarantine flags, parents, and annotations are
severed. Under ``sic_facts`` the re-encoded copy collapses onto the original
address and the laundering fails by construction.

Every step is reported as a ``|``-delimited trace message; the
``serialization_invariance`` validators read exactly these messages. Point
``layers.datafacts`` at ``sic_facts`` and every validator passes; point it at
``cid_facts`` (or ``datafacts_v1``) and the laundering validator fails --
demonstrating a real gap in the currently-merged plugin, not a strawman.

Example::

    agents = serialization_invariance_factory(config, plugins)
"""

from __future__ import annotations

import unicodedata
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.scenarios_builtin.provenance_supply_chain import (
    _build_datafacts_handles,  # pyright: ignore[reportPrivateUsage] -- shared scenario wiring
)
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DatasetMetadata

_PHANTOM_PARENT = "df://sic-" + "0" * 64

# The supplier's structured payload: quarantined shipment records.
_SUPPLIER_CONTENT: dict[str, Any] = {
    "rows": [[1, 2], [3, 4]],
    "unit": "kg",
    "origin": "Z\u00fcrich",  # NFC
    "quarantined": True,
}


def _reencode(content: object) -> object:
    """Produce a byte-different, structurally-identical encoding of ``content``.

    Ints become int-valued floats, strings are renormalized NFC -> NFD, and
    dict insertion order is reversed. Any JSON/byte-level digest of the result
    differs from the original; any *structural* digest must not.

    Example::

        assert _reencode({"v": 1}) == {"v": 1.0}
    """
    if isinstance(value := content, bool):
        return value
    if isinstance(content, int):
        return float(content)
    if isinstance(content, str):
        return unicodedata.normalize("NFD", content)
    if isinstance(content, list):
        return [_reencode(v) for v in cast("list[object]", content)]
    if isinstance(content, dict):
        items = list(cast("dict[str, object]", content).items())
        return {k: _reencode(v) for k, v in reversed(items)}
    return content


def _tamper(content: object) -> object:
    """Produce a genuinely different content (one value changed).

    Example::

        assert _tamper(_SUPPLIER_CONTENT) != _SUPPLIER_CONTENT
    """
    tampered = dict(cast("dict[str, object]", content))
    tampered["quarantined"] = False  # the value an attacker actually wants to flip
    return tampered


class SupplierAgent(StateMachineAgent):
    """Publishes the quarantined root dataset and hands its URL downstream.

    Example::

        supplier = SupplierAgent(AgentId("supplier-0"), downstream=AgentId("launder-0"))
    """

    def __init__(self, agent_id: AgentId, downstream: AgentId) -> None:
        self._id = agent_id
        self._downstream = downstream

    async def on_start(self, ctx: AgentContext) -> None:
        """Publish the root dataset and forward its URL to the launderer.

        Example::

            await supplier.on_start(ctx)
        """
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        dataset = DatasetMetadata(
            name="shipment_records",
            owner=self._id,
            checksum="sha256:original-export",
            size_bytes=100,
            metadata={"content": _SUPPLIER_CONTENT},
        )
        url = await facts.publish(dataset)
        await ctx.send(self._downstream, f"lineage|{url}|{self._id}".encode())


class LaunderAgent(StateMachineAgent):
    """Re-encodes identical content and republishes, hoping for a clean address.

    Reports ``launder_collapsed|<url>`` if the registry collapsed the copy
    onto the original URL (attack neutralized) or ``launder_forked|<a>|<b>``
    if it minted a fresh one (attack succeeded -- history severed).

    Example::

        launder = LaunderAgent(AgentId("launder-0"), downstream=AgentId("audit-0"))
    """

    def __init__(self, agent_id: AgentId, downstream: AgentId) -> None:
        self._id = agent_id
        self._downstream = downstream

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Fetch the original, republish a re-encoded copy, report the outcome.

        Example::

            await launder.on_message(ctx, AgentId("supplier-0"), b"lineage|df://sic-x|supplier-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        _, original_url, _owner = msg.split("|", 2)
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        original = await facts.fetch(original_url)
        content: object = original.metadata.get("content", _SUPPLIER_CONTENT)
        laundered = DatasetMetadata(
            name="shipment_records_clean",  # new label
            owner=original.owner,
            checksum="sha256:reexported-bytes",  # new byte digest
            size_bytes=142,  # new byte size
            metadata={"content": _reencode(content)},  # same logical content
        )
        new_url = await facts.publish(laundered)
        if str(new_url) == original_url:
            await ctx.send(self._id, f"launder_collapsed|{new_url}".encode())
        else:
            await ctx.send(self._id, f"launder_forked|{original_url}|{new_url}".encode())
        await ctx.send(self._downstream, f"lineage|{original_url}|{self._id}".encode())


class AuditAgent(StateMachineAgent):
    """Confirms tampering is still detected and phantom parents still rejected.

    Serialization invariance must not blunt integrity: a *changed* value has
    to change the address (``tamper_detected|``), and provenance must still
    refuse parents that were never published (``phantom_rejected|``).

    Example::

        audit = AuditAgent(AgentId("audit-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Run the tamper and phantom-parent probes against the original URL.

        Example::

            await audit.on_message(ctx, AgentId("launder-0"), b"lineage|df://sic-x|launder-0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("lineage|"):
            return
        _, original_url, _owner = msg.split("|", 2)
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return

        original = await facts.fetch(original_url)
        content: object = original.metadata.get("content", _SUPPLIER_CONTENT)
        tampered = DatasetMetadata(
            name=original.name,
            owner=original.owner,
            checksum=original.checksum,
            size_bytes=original.size_bytes,
            metadata={"content": _tamper(content)},
        )
        tampered_url = await facts.publish(tampered)
        if str(tampered_url) != original_url:
            await ctx.send(self._id, f"tamper_detected|{original_url}|{tampered_url}".encode())
        else:
            await ctx.send(self._id, f"tamper_missed|{original_url}".encode())

        try:
            await facts.publish(
                DatasetMetadata(
                    name="orphan",
                    owner=self._id,
                    metadata={"content": {"v": 99}, "parents": [_PHANTOM_PARENT]},
                )
            )
            await ctx.send(self._id, b"phantom_accepted|orphan")
        except Exception:  # noqa: BLE001 - plugin-specific error types
            await ctx.send(self._id, b"phantom_rejected|orphan")

        # Freshness probe: publish a dataset this agent owns, then verify it.
        # This exercises the owner-signed proof over the SHARED logical clock
        # (per-agent handles must share one tick source via the plugin's
        # ``clock`` property) -- a valid proof at the current tick reads fresh.
        probe_url = await facts.publish(
            DatasetMetadata(
                name="freshness_probe",
                owner=self._id,
                metadata={"content": {"probe": str(self._id)}},
            )
        )
        if await facts.verify_freshness(probe_url):
            await ctx.send(self._id, f"freshness_ok|{probe_url}".encode())
        else:
            await ctx.send(self._id, f"freshness_stale|{probe_url}".encode())


def serialization_invariance_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the supplier -> launderer -> auditor chain with per-agent handles.

    Identity and datafacts wiring mirrors ``provenance_supply_chain_factory``:
    each agent gets its own identity (so proofs are signed as themselves) and
    a per-agent datafacts handle over shared storage and one logical clock.

    Example::

        agents = serialization_invariance_factory(config, plugins)
    """
    del config
    supplier_id = AgentId("supplier-0")
    launder_id = AgentId("launder-0")
    audit_id = AgentId("audit-0")
    all_ids = [supplier_id, launder_id, audit_id]

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
        supplier_id: SupplierAgent(supplier_id, downstream=launder_id),
        launder_id: LaunderAgent(launder_id, downstream=audit_id),
        audit_id: AuditAgent(audit_id),
    }
