# SPDX-License-Identifier: Apache-2.0
"""Counterparty-corroborated receipt-reputation scenario with a collusion ring.

Three populations issue cross-signed receipts of their interactions, all routed
to a single **auditor** that owns one live instance of the configured ``trust:``
plugin (resolved from ``plugins["trust"]``, exactly as the identity-rotation
scenario resolves the identity class). The auditor ``report()``s every receipt
into that one global ledger, then — on a final scheduled pulse, strictly after
all reports are delivered — ``score()``s every agent and emits the score into
the trace. Because the auditor holds one shared instance, the ledger is global,
which is what the whole-graph collusion severance needs.

Populations (classified by agent-id prefix so the validator can tell them apart):

* ``honest-<i>`` — N >= 5 honest agents wired into a **directed cycle**
  (``honest-0 -> honest-1 -> ... -> honest-0``, plus a chord) of valid,
  mutually-cosigned ``purchase`` receipts. They form a single strongly-connected
  component strictly larger than the ring, so they are the honest *anchor*.
* ``ring-<i>`` — a 4-agent **collusion ring** that co-signs *only each other*
  (all-pairs, both directions) and has **no corroborated edge to the honest
  anchor**. Every ring receipt is individually valid and corroborated — the
  attack naive averaging rewards — yet the ring is an isolated dense SCC, so
  ``agent_receipts`` severs it to score 0.
* ``byz-<i>`` — ~10% byzantine agents that issue receipts with a **broken
  co-signature** (a corrupted witness signature). These fail corroboration, so
  they never enter the corroboration graph and cannot accidentally bridge the
  ring to the anchor.

Every reported ``Evidence`` carries **both** ``kind="positive"`` (which drives
the ``score_average`` baseline to reward the ring) **and** ``detail`` = the
JSON receipt (which drives ``agent_receipts`` to sever it). The same scenario
therefore fails the adversarial validator under ``trust: score_average`` and
passes it under ``trust: agent_receipts``.

Trace line protocol (carried in message bodies, ``:``-delimited):

* ``score:<agent>:<score>:<confidence>:<role>`` — the live trust plugin's score
  for ``agent`` after every receipt was reported. ``role`` is ``honest``,
  ``ring``, or ``byz``. Scores are formatted to 6 decimals for determinism.

Example::

    agents = receipt_reputation_factory(config, plugins)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# The auditor instantiates the trust plugin lazily and imports the receipt
# builders from the reference plugin so honest/ring receipts are constructed the
# same way the plugin verifies them. These are scenario-only helpers; importing
# them here keeps the receipt format in exactly one place.
from nest_plugins_reference.trust.agent_receipts import (
    cosign_receipt,
    did_for_pubkey,
    sign_receipt,
)

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Evidence


def _seed_for(agent: AgentId) -> bytes:
    """Deterministic 32-byte Ed25519 seed for an agent (matches the plugin).

    Example::

        seed = _seed_for(AgentId("honest-0"))
    """
    return hashlib.sha256(str(agent).encode()).digest()[:32]


def _did_for(agent: AgentId) -> str:
    """The receipt identity (hex pubkey) for an agent — matches the plugin's map.

    Example::

        did = _did_for(AgentId("honest-0"))
    """
    sk = Ed25519PrivateKey.from_private_bytes(_seed_for(agent))
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return did_for_pubkey(pub)


def _build_receipt(
    issuer: AgentId,
    counterparty: AgentId,
    *,
    receipt_id: str,
    category: str = "purchase",
    valid_cosign: bool = True,
) -> dict[str, Any]:
    """Build a signed receipt of ``issuer``'s interaction with ``counterparty``.

    With ``valid_cosign=True`` the counterparty's genuine co-signature is
    attached (corroborated). With ``valid_cosign=False`` a corrupted witness
    signature is attached instead, so :func:`is_corroborated` rejects it — the
    byzantine case.

    Example::

        r = _build_receipt(AgentId("honest-0"), AgentId("honest-1"), receipt_id="r0")
    """
    receipt: dict[str, Any] = {
        "receipt_id": receipt_id,
        "issuer_did": _did_for(issuer),
        "action": {"category": category, "counterparty_did": _did_for(counterparty)},
    }
    receipt = sign_receipt(receipt, issuer_seed=_seed_for(issuer))
    if valid_cosign:
        return cosign_receipt(receipt, counterparty_seed=_seed_for(counterparty))
    # Byzantine: attach a structurally-present but invalid co-signature.
    receipt.setdefault("evidence", {})["witness_signatures"] = [
        {"witness_did": _did_for(counterparty), "signature": "00" * 64}
    ]
    return receipt


class ReceiptIssuer(StateMachineAgent):
    """An agent that issues cross-signed receipts of its assigned interactions.

    On start it sends each of its pre-computed receipts to the auditor as a
    ``receipt:`` message. The agent does no scoring itself — all reputation is
    computed centrally by the auditor against the configured trust plugin, so
    the scenario behaves identically regardless of which ``trust:`` plugin the
    YAML selects.

    Example::

        agent = ReceiptIssuer(AgentId("honest-0"), auditor, receipts)
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        receipts: list[dict[str, Any]],
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._receipts = receipts

    async def on_start(self, ctx: AgentContext) -> None:
        """Send every assigned receipt to the auditor.

        Example::

            await agent.on_start(ctx)
        """
        for receipt in self._receipts:
            await ctx.send(self._auditor, b"receipt:" + json.dumps(receipt).encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Issuers receive no messages; present for Protocol completeness.

        Example::

            await agent.on_message(ctx, auditor, b"noop")
        """
        return


class AuditorAgent(StateMachineAgent):
    """Owns the single trust instance, reports all receipts, then scores everyone.

    The auditor resolves the configured trust plugin *class* from
    ``ctx.plugins["trust"]`` on first use and instantiates exactly one instance,
    so every receipt lands in one global ledger. It schedules a ``finalize:``
    pulse one tick ahead of the issuers' ``on_start`` so scoring happens strictly
    after every ``receipt:`` has been reported. On finalize it scores every known
    agent and emits a ``score:`` line per agent into the trace; the
    ``receipt_reputation`` validator reads those lines.

    If the trust plugin exposes ``seal_events()`` (e.g. ``CapsuleEmitTrust``),
    the auditor additionally broadcasts one ``seal:<seq>:<subject_digest>:<chain_hash>``
    line per seal after all score lines. The ``receipt_reputation_capsule``
    validator reads those seal lines to verify chain integrity and completeness
    from the trace alone — no filesystem reads required.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"), roster)
    """

    def __init__(self, agent_id: AgentId, roster: dict[AgentId, str]) -> None:
        self._id = agent_id
        # AgentId -> role ("honest" | "ring" | "byz"), the population labels.
        self._roster = roster
        self._trust: Any = None

    async def on_start(self, ctx: AgentContext) -> None:
        """Instantiate the trust plugin and schedule the finalize pulse.

        Example::

            await auditor.on_start(ctx)
        """
        trust_cls = ctx.plugins.get("trust")
        # The runner passes the resolved class; instantiate one shared instance.
        self._trust = trust_cls() if isinstance(trust_cls, type) else trust_cls
        # Finalize after all issuers' on_start receipts are delivered.
        await ctx.schedule(1.0, b"finalize:")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Report each received receipt, then score everyone on finalize.

        Example::

            await auditor.on_message(ctx, issuer, b"receipt:{...}")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("receipt:"):
            await self._report(sender, msg[len("receipt:") :])
            return
        if msg.startswith("finalize:"):
            await self._finalize(ctx)

    async def _report(self, issuer: AgentId, receipt_json: str) -> None:
        """Report one receipt to the trust plugin under its issuer.

        The ``Evidence`` carries ``kind="positive"`` (so ``score_average``
        rewards it) and ``detail`` = the JSON receipt (so ``agent_receipts``
        gates it). ``subject`` is the issuer — the agent the receipt is *about*.
        """
        if self._trust is None:  # pragma: no cover - on_start always runs first
            return
        await self._trust.report(
            issuer,
            Evidence(
                reporter=self._id,
                subject=issuer,
                kind="positive",
                detail=receipt_json,
            ),
        )

    async def _finalize(self, ctx: AgentContext) -> None:
        """Score every agent and emit one ``score:`` trace line per agent.

        If the trust plugin exposes ``seal_events()`` (e.g. ``CapsuleEmitTrust``),
        also broadcasts one ``seal:<seq>:<subject_digest>:<chain_hash>`` line per
        seal after all score lines, so the anchoring validator can grade the trace
        without reading the filesystem.
        """
        if self._trust is None:  # pragma: no cover - on_start always runs first
            return
        for agent in sorted(self._roster, key=str):
            role = self._roster[agent]
            rep = await self._trust.score(agent)
            await ctx.broadcast(
                f"score:{agent}:{rep.score:.6f}:{rep.confidence:.6f}:{role}".encode()
            )
        seal_fn = getattr(self._trust, "seal_events", None)
        if callable(seal_fn):
            seals = cast("list[tuple[int, str, str]]", seal_fn())
            for seq, subject_digest, chain_hash in seals:
                await ctx.broadcast(f"seal:{seq}:{subject_digest}:{chain_hash}".encode())
        # Anchoring evidence: pre-obtained confidential-ledger write receipts,
        # one line per anchored receipt. Only these lines can satisfy the
        # anchored validator — they carry the ledger service-identity signature
        # the participant cannot forge. A plugin without the hook (or with an
        # empty store) emits nothing and the anchored check fails closed.
        ccf_fn = getattr(self._trust, "ccf_receipt_events", None)
        if callable(ccf_fn):
            pairs = cast("list[tuple[str, str]]", ccf_fn())
            for subject_digest, receipt_hex in pairs:
                await ctx.broadcast(f"ccfreceipt:{subject_digest}:{receipt_hex}".encode())


def _partition(
    config: ScenarioConfig,
) -> tuple[list[AgentId], list[AgentId], list[AgentId]]:
    """Split the agent budget into honest (>=5), a 4-agent ring, and ~10% byzantine.

    Honest count is whatever remains after reserving the auditor, the 4 ring
    members, and the byzantine fraction — clamped to a minimum of 5 so the honest
    anchor is always strictly larger than the ring. ``roles:`` in the YAML, if
    present, override the honest/ring/byzantine counts.

    Example::

        honest, ring, byz = _partition(config)
    """
    task_config = config.task.config
    ring_size = int(task_config.get("ring_size", 4))
    byzantine_fraction = config.failures.byzantine_agents or task_config.get(
        "byzantine_fraction", 0.10
    )

    issuer_budget = max(1, config.agents.count - 1)  # minus the auditor
    byz_count = int(issuer_budget * byzantine_fraction)
    honest_count = max(5, issuer_budget - ring_size - byz_count)

    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "honest":
                honest_count = max(5, role.count)
            elif role.name == "ring":
                ring_size = role.count
            elif role.name == "byzantine":
                byz_count = role.count

    honest = [AgentId(f"honest-{i}") for i in range(honest_count)]
    ring = [AgentId(f"ring-{i}") for i in range(ring_size)]
    byz = [AgentId(f"byz-{i}") for i in range(byz_count)]
    return honest, ring, byz


def _honest_receipts(honest: list[AgentId]) -> dict[AgentId, list[dict[str, Any]]]:
    """Assign each honest agent receipts forming a single strongly-connected cycle.

    ``honest-i`` issues a corroborated receipt to ``honest-(i+1)`` and a chord to
    ``honest-(i+2)``, so the honest population is one SCC of size ``len(honest)``.

    Example::

        receipts = _honest_receipts([AgentId("honest-0"), ...])
    """
    n = len(honest)
    out: dict[AgentId, list[dict[str, Any]]] = {a: [] for a in honest}
    for i, issuer in enumerate(honest):
        for k in (1, 2):
            cp = honest[(i + k) % n]
            out[issuer].append(
                _build_receipt(issuer, cp, receipt_id=f"{issuer}->{cp}", valid_cosign=True)
            )
    return out


def _ring_receipts(ring: list[AgentId]) -> dict[AgentId, list[dict[str, Any]]]:
    """Assign the ring all-pairs mutual co-signed receipts (a dense isolated SCC).

    Example::

        receipts = _ring_receipts([AgentId("ring-0"), ...])
    """
    out: dict[AgentId, list[dict[str, Any]]] = {a: [] for a in ring}
    for i, issuer in enumerate(ring):
        for j, cp in enumerate(ring):
            if i == j:
                continue
            out[issuer].append(
                _build_receipt(issuer, cp, receipt_id=f"{issuer}->{cp}", valid_cosign=True)
            )
    return out


def _byzantine_receipts(
    byz: list[AgentId],
    honest: list[AgentId],
) -> dict[AgentId, list[dict[str, Any]]]:
    """Assign byzantine agents receipts with a broken co-signature (uncorroborated).

    Each targets an honest agent but cannot produce a valid co-signature, so the
    receipt is dropped from the corroboration graph and earns nothing under
    ``agent_receipts`` while still being reported as ``kind="positive"``.

    Example::

        receipts = _byzantine_receipts([AgentId("byz-0")], honest)
    """
    out: dict[AgentId, list[dict[str, Any]]] = {a: [] for a in byz}
    for i, issuer in enumerate(byz):
        cp = honest[i % len(honest)] if honest else issuer
        out[issuer].append(
            _build_receipt(issuer, cp, receipt_id=f"{issuer}->{cp}", valid_cosign=False)
        )
    return out


def receipt_reputation_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create honest issuers, a collusion ring, byzantine agents, and one auditor.

    The auditor owns the single configured trust instance and computes every
    agent's reputation centrally, so the same scenario runs unchanged under
    ``trust: score_average`` (ring rewarded → validator FAILs) and
    ``trust: agent_receipts`` (ring severed → validator PASSes).

    Example::

        agents = receipt_reputation_factory(config, plugins)
    """
    honest, ring, byz = _partition(config)

    assignments: dict[AgentId, list[dict[str, Any]]] = {}
    assignments.update(_honest_receipts(honest))
    assignments.update(_ring_receipts(ring))
    assignments.update(_byzantine_receipts(byz, honest))

    roster: dict[AgentId, str] = {}
    for a in honest:
        roster[a] = "honest"
    for a in ring:
        roster[a] = "ring"
    for a in byz:
        roster[a] = "byz"

    auditor_id = AgentId("auditor-0")
    agents: dict[AgentId, StateMachineAgent] = {}
    for agent, receipts in assignments.items():
        agents[agent] = ReceiptIssuer(agent, auditor=auditor_id, receipts=receipts)
    agents[auditor_id] = AuditorAgent(auditor_id, roster=roster)
    return agents
