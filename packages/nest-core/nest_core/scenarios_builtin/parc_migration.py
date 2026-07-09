# SPDX-License-Identifier: Apache-2.0
"""Portable-reputation migration scenario: credentials cross a trust-domain border.

Two trust domains live in one deterministic run. In **domain A**, agents have
earned cross-signed receipts (an honest anchor plus an isolated wash-trading
ring). At a fixed logical tick the population **migrates**: domain A's auditor
exports each agent's reputation as a signed PARC credential, publishes its
community ledger once, and every agent presents its credential at **domain
B**'s admission gate. The gate never saw domain A's run — it decides from the
credential alone (plus the published ledger), by *recomputing* the committed
Merkle root and the ``nanda-rep/0.2`` scores rather than trusting the signed
claims.

The migrating cast covers one attack per adversarial validator:

* ``honest-<i>`` — genuine credentials over corroborated receipts → admitted.
* ``ring-<i>`` — an isolated 3-agent collusion ring. Each member's *inline*
  credential is individually corroborated (a star ledger cannot show a ring),
  so it survives recomputation — and is then denied by whole-graph severance
  over the published ledger (``severed_below_threshold``).
* ``forger-0`` — presents its own credential with a tampered ``proofValue``
  → ``proof_invalid``.
* ``replay-0`` — presents ``honest-1``'s genuine credential as its own
  → ``replay_presenter_mismatch``.
* ``stale-0`` — its credential was signed with auditor A's **rotated-out**
  key (via the identity layer's adversarial ``sign_with``) with ``validFrom``
  after the rotation → ``stale_key``.
* ``inflated-0`` — its credential comes from ``auditor-x``, a *trusted but
  corrupt* issuer that inflated ``reputation_score`` and re-signed. The proof
  verifies; recomputation over the carried receipts catches the lie
  → ``score_mismatch``. This is the headline property: **a valid signature is
  not admission**.

Set ``task.config.naive_gate: true`` and the gate trusts the signed claims
(``require_recomputation=False``): the inflated credential and the whole ring
are admitted, so the corresponding validators FAIL — the differential proof of
what recomputation buys. Under ``trust: score_average`` no credentials exist
at all and every validator fails for want of admissions.

Identity wiring (the cross-layer composition): the factory builds real
``ed25519_rotating`` identities for both auditors and the gate, performs
auditor A's key rotation at logical tick ``_ROTATE_AT``, and replays the
rotation record onto the gate's identity, so admission-time proof checks run
against genuine rotation windows — not scenario-faked ones.

Trace line protocol (``:``-delimited message bodies):

* ``export:<agent>:<root8>:<score6>`` — domain A exported a credential.
* ``admit:<agent>:<granted|denied>:<reason>:<role>`` — the gate's decision;
  the ``parc_migration`` validators read these lines.

Example::

    agents = parc_migration_factory(config, plugins)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# The credential builders and receipt format live in exactly one place — the
# plugins — so the scenario constructs receipts the same way the gate verifies
# them (the receipt_reputation scenario sets this precedent).
from nest_plugins_reference.trust.agent_receipts import (
    cosign_receipt,
    did_for_pubkey,
    sign_receipt,
)
from nest_plugins_reference.trust.parc import (
    AdmissionPolicy,
    attach_proof,
)

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Evidence

# Logical credential timeline (independent of simulator ticks): auditor A
# rotates its signing key at _ROTATE_AT and issues every credential at
# _ISSUE_AT — so a credential signed with the pre-rotation key is stale by
# construction.
_ROTATE_AT = 5.0
_ISSUE_AT = 6.0

_AUDITOR_A = AgentId("auditor-a")
_AUDITOR_X = AgentId("auditor-x")
_GATE = AgentId("gate-0")


def _seed_for(agent: AgentId) -> bytes:
    """Deterministic 32-byte Ed25519 receipt seed for an agent (plugin-matching).

    Example::

        seed = _seed_for(AgentId("honest-0"))
    """
    return hashlib.sha256(str(agent).encode()).digest()[:32]


def _did_for(agent: AgentId) -> str:
    """The trust-layer receipt identity (hex pubkey) for an agent.

    Example::

        did = _did_for(AgentId("honest-0"))
    """
    sk = Ed25519PrivateKey.from_private_bytes(_seed_for(agent))
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return did_for_pubkey(pub)


def _receipt(issuer: AgentId, counterparty: AgentId, *, receipt_id: str) -> dict[str, Any]:
    """A corroborated purchase receipt from ``issuer`` about ``counterparty``.

    Example::

        r = _receipt(AgentId("honest-0"), AgentId("honest-1"), receipt_id="r0")
    """
    receipt: dict[str, Any] = {
        "receipt_id": receipt_id,
        "issuer_did": _did_for(issuer),
        "action": {"category": "purchase", "counterparty_did": _did_for(counterparty)},
    }
    receipt = sign_receipt(receipt, issuer_seed=_seed_for(issuer))
    return cosign_receipt(receipt, counterparty_seed=_seed_for(counterparty))


def _domain_a_ledger(
    honest: list[AgentId],
    ring: list[AgentId],
    extras: list[AgentId],
) -> list[dict[str, Any]]:
    """Domain A's community ledger: honest anchor, isolated ring, honest extras.

    The honest agents form a directed cycle plus chords (one SCC, the anchor,
    strictly larger than the ring). The ring co-signs all-pairs among itself
    only — individually corroborated, collectively isolated. Each extra
    (forger, stale, inflated victims-to-be) issues genuine receipts with
    honest counterparties, so their credentials are real; their attacks happen
    at the border, not in the ledger.

    Example::

        ledger = _domain_a_ledger(honest, ring, extras)
    """
    ledger: list[dict[str, Any]] = []
    n = len(honest)
    for i, issuer in enumerate(honest):
        for k in (1, 2):
            cp = honest[(i + k) % n]
            ledger.append(_receipt(issuer, cp, receipt_id=f"{issuer}->{cp}"))
    for i, issuer in enumerate(ring):
        for j, cp in enumerate(ring):
            if i != j:
                ledger.append(_receipt(issuer, cp, receipt_id=f"{issuer}->{cp}"))
    for idx, issuer in enumerate(extras):
        for k in (0, 1):
            cp = honest[(idx + k) % n]
            ledger.append(_receipt(issuer, cp, receipt_id=f"{issuer}->{cp}"))
    return ledger


class DomainAAuditor(StateMachineAgent):
    """Domain A's honest auditor: reports the ledger, exports, publishes.

    On start it instantiates the configured trust plugin, reports every ledger
    receipt into it, exports one credential per migrant (signing with its
    post-rotation key — except the stale migrant's, deliberately signed with
    the rotated-out key), hands ``replay-0`` a copy of ``honest-1``'s
    credential, and publishes the community ledger to the gate. If the
    configured trust plugin cannot build credentials (e.g. ``score_average``),
    it does nothing — and every admission validator fails for want of
    admissions, which is the point.

    Example::

        auditor = DomainAAuditor(_AUDITOR_A, identity=ident, ledger=ledger,
                                 migrants=migrants, stale=AgentId("stale-0"),
                                 replayer=AgentId("replay-0"),
                                 replay_victim=AgentId("honest-1"),
                                 old_key_id="ab12...")
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        identity: Any,
        ledger: list[dict[str, Any]],
        migrants: list[AgentId],
        stale: AgentId,
        replayer: AgentId,
        replay_victim: AgentId,
        old_key_id: str,
    ) -> None:
        self._id = agent_id
        self._identity = identity
        self._ledger = ledger
        self._migrants = migrants
        self._stale = stale
        self._replayer = replayer
        self._replay_victim = replay_victim
        self._old_key_id = old_key_id

    async def on_start(self, ctx: AgentContext) -> None:
        """Report the ledger, export credentials, publish the community ledger.

        Example::

            await auditor.on_start(ctx)
        """
        trust_cls = ctx.plugins.get("trust")
        trust: Any = trust_cls() if isinstance(trust_cls, type) else trust_cls
        if trust is None or not hasattr(trust, "build_credential"):
            return
        for receipt in self._ledger:
            await trust.report(
                AgentId(str(receipt["issuer_did"])),
                Evidence(
                    reporter=self._id,
                    subject=self._id,
                    kind="positive",
                    detail=json.dumps(receipt),
                ),
            )
        # The plugin maps AgentId -> receipt did via the same sha256 seed
        # derivation the ledger used, so exports find the migrants' receipts.
        credentials: dict[AgentId, dict[str, Any]] = {}
        for migrant in self._migrants:
            key_id = self._old_key_id if migrant == self._stale else None
            credentials[migrant] = await trust.build_credential(
                migrant,
                identity=self._identity,
                valid_from=_ISSUE_AT,
                key_id=key_id,
            )
        await ctx.send(_GATE, b"ledger:" + json.dumps(self._ledger).encode())
        for migrant in self._migrants:
            vc = credentials[migrant]
            await ctx.send(migrant, b"credential:" + json.dumps(vc).encode())
            subject = vc["credentialSubject"]
            root8 = str(subject["behavioral_merkle_root"])[:8]
            await ctx.broadcast(f"export:{migrant}:{root8}:{subject['reputation_score']}".encode())
        # The replayer "stole" a genuine credential; it never earned its own.
        await ctx.send(
            self._replayer,
            b"credential:" + json.dumps(credentials[self._replay_victim]).encode(),
        )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """The auditor receives no messages; present for Protocol completeness.

        Example::

            await auditor.on_message(ctx, sender, b"noop")
        """
        return


class CorruptAuditor(StateMachineAgent):
    """A *trusted but corrupt* issuer: inflates a score and genuinely re-signs.

    Builds a real credential for its client over the client's real receipts,
    then rewrites ``reputation_score`` upward and re-attaches a genuine proof
    under its own (trusted) key. The signature verifies; only recomputation
    over the carried receipts exposes the lie. This is the attack that
    distinguishes a recomputing gate from a signature-checking one.

    Example::

        corrupt = CorruptAuditor(_AUDITOR_X, identity=ident,
                                 client=AgentId("inflated-0"), receipts=[...])
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        identity: Any,
        client: AgentId,
        receipts: list[dict[str, Any]],
    ) -> None:
        self._id = agent_id
        self._identity = identity
        self._client = client
        self._receipts = receipts

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue the inflated-but-genuinely-signed credential to the client.

        Example::

            await corrupt.on_start(ctx)
        """
        trust_cls = ctx.plugins.get("trust")
        trust: Any = trust_cls() if isinstance(trust_cls, type) else trust_cls
        if trust is None or not hasattr(trust, "build_credential"):
            return
        for receipt in self._receipts:
            await trust.report(
                AgentId(str(receipt["issuer_did"])),
                Evidence(
                    reporter=self._id,
                    subject=self._id,
                    kind="positive",
                    detail=json.dumps(receipt),
                ),
            )
        vc = await trust.build_credential(
            self._client, identity=self._identity, valid_from=_ISSUE_AT
        )
        vc.pop("proof", None)
        vc["credentialSubject"]["reputation_score"] = "0.990000"
        vc = attach_proof(vc, identity=self._identity)
        await ctx.send(self._client, b"credential:" + json.dumps(vc).encode())
        subject = vc["credentialSubject"]
        root8 = str(subject["behavioral_merkle_root"])[:8]
        await ctx.broadcast(f"export:{self._client}:{root8}:{subject['reputation_score']}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """The corrupt auditor receives no messages; Protocol completeness.

        Example::

            await corrupt.on_message(ctx, sender, b"noop")
        """
        return


class Migrant(StateMachineAgent):
    """An agent that carries its credential across the border and presents it.

    On receiving its ``credential:`` from an issuer it presents at the gate.
    The ``forged`` role tampers its own credential's ``proofValue`` first (a
    deterministic first-nibble flip); every other role presents what it was
    given — including the replayer, whose theft is the credential itself.

    Example::

        agent = Migrant(AgentId("honest-0"), role="honest")
    """

    def __init__(self, agent_id: AgentId, *, role: str) -> None:
        self._id = agent_id
        self._role = role

    async def on_start(self, ctx: AgentContext) -> None:
        """Migrants act only on receiving their credential.

        Example::

            await agent.on_start(ctx)
        """
        return

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Present the received credential at the gate (tampering if forged).

        Example::

            await agent.on_message(ctx, sender, b"credential:{...}")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("credential:"):
            return
        vc: dict[str, Any] = json.loads(msg[len("credential:") :])
        if self._role == "forged":
            proof = vc.get("proof")
            if isinstance(proof, dict):
                proof_typed = cast("dict[str, Any]", proof)
                value = str(proof_typed.get("proofValue", ""))
                if value:
                    flipped = "0" if value[0] != "0" else "f"
                    proof_typed["proofValue"] = flipped + value[1:]
        envelope = {"role": self._role, "credential": vc}
        await ctx.send(_GATE, b"present:" + json.dumps(envelope).encode())


class BorderGate(StateMachineAgent):
    """Domain B's admission gate: verifies, recomputes, and decides.

    Owns its own instance of the configured trust plugin and an identity-layer
    view of the issuers (including auditor A's replayed key rotation). Ingests
    domain A's published ledger for whole-graph severance, then admits or
    denies each presented credential and broadcasts one ``admit:`` line per
    decision. Falls back to trusting the *claimed* score when the configured
    plugin has no ``admit`` (the naive baseline the validators punish).

    Example::

        gate = BorderGate(_GATE, identity=gate_ident, policy=policy)
    """

    def __init__(self, agent_id: AgentId, *, identity: Any, policy: AdmissionPolicy) -> None:
        self._id = agent_id
        self._identity = identity
        self._policy = policy
        self._trust: Any = None

    async def on_start(self, ctx: AgentContext) -> None:
        """Instantiate the configured trust plugin.

        Example::

            await gate.on_start(ctx)
        """
        trust_cls = ctx.plugins.get("trust")
        self._trust = trust_cls() if isinstance(trust_cls, type) else trust_cls

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ingest the published ledger; decide each presented credential.

        Example::

            await gate.on_message(ctx, migrant, b"present:{...}")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("ledger:"):
            receipts: list[dict[str, Any]] = json.loads(msg[len("ledger:") :])
            if hasattr(self._trust, "ingest_published_ledger"):
                self._trust.ingest_published_ledger(receipts)
            return
        if not msg.startswith("present:"):
            return
        envelope: dict[str, Any] = json.loads(msg[len("present:") :])
        role = str(envelope.get("role", "unknown"))
        vc: dict[str, Any] = envelope.get("credential", {})
        if hasattr(self._trust, "admit"):
            result = await self._trust.admit(
                vc,
                policy=self._policy,
                presenter_did=_did_for(sender),
                identity=self._identity,
                current_tick=_ISSUE_AT,
            )
            admitted, reason = result.admitted, result.reason
        else:
            # Naive baseline: trust whatever the credential claims.
            try:
                claimed = float(str(vc["credentialSubject"]["reputation_score"]))
            except (KeyError, TypeError, ValueError):
                claimed = 0.0
            admitted = claimed >= self._policy.min_reputation_score
            reason = "admitted" if admitted else "below_threshold"
        decision = "granted" if admitted else "denied"
        await ctx.broadcast(f"admit:{sender}:{decision}:{reason}:{role}".encode())


def parc_migration_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the two-domain migration cast with real identity-layer wiring.

    Builds ``ed25519_rotating`` identities for both auditors and the gate,
    performs auditor A's key rotation at ``_ROTATE_AT``, replays the rotation
    record onto the gate (so admission checks run against genuine key
    windows), constructs domain A's ledger, and wires the migrating cast.
    ``task.config`` keys: ``min_reputation_score`` (default ``0.2``) and
    ``naive_gate`` (default ``false`` — set true to make the gate trust
    signed claims, the differential baseline).

    Example::

        agents = parc_migration_factory(config, plugins)
    """
    task_config = config.task.config
    min_score = float(task_config.get("min_reputation_score", 0.2))
    naive_gate = bool(task_config.get("naive_gate", False))

    honest = [AgentId(f"honest-{i}") for i in range(4)]
    ring = [AgentId(f"ring-{i}") for i in range(3)]
    forger = AgentId("forger-0")
    replayer = AgentId("replay-0")
    stale = AgentId("stale-0")
    inflated = AgentId("inflated-0")
    extras = [forger, stale, inflated]

    identity_cls = plugins.get("identity")
    if identity_cls is None or not isinstance(identity_cls, type):
        msg = "parc_migration requires a resolvable identity plugin class"
        raise ValueError(msg)
    a_ident = identity_cls(_AUDITOR_A, seed=b"parc:auditor-a")
    x_ident = identity_cls(_AUDITOR_X, seed=b"parc:auditor-x")
    gate_ident = identity_cls(_GATE, seed=b"parc:gate-0")

    # Gate learns A's key #0 at tick 0, then A rotates at _ROTATE_AT and the
    # gate applies the (old-key-signed) rotation record — after which A's old
    # key window is [0, _ROTATE_AT) on both sides. Credentials are issued at
    # _ISSUE_AT, so anything signed with key #0 is stale by construction.
    old_key_id = str(a_ident.current_key_id)
    if hasattr(gate_ident, "register_peer"):
        gate_ident.register_peer(_AUDITOR_A, a_ident.public_key)
        gate_ident.register_peer(_AUDITOR_X, x_ident.public_key)
    if hasattr(a_ident, "rotate_key") and hasattr(gate_ident, "apply_rotation"):
        a_ident.set_clock(_ROTATE_AT)
        rotation = a_ident.rotate_key(b"parc:auditor-a:rotated")
        gate_ident.set_clock(_ROTATE_AT)
        if not gate_ident.apply_rotation(rotation):  # pragma: no cover - wiring invariant
            msg = "gate failed to apply auditor A's rotation record"
            raise ValueError(msg)
        a_ident.set_clock(_ISSUE_AT)

    ledger = _domain_a_ledger(honest, ring, extras)
    inflated_receipts = [r for r in ledger if str(r["issuer_did"]) == _did_for(inflated)]
    # Auditor A exports for everyone except the corrupt auditor's client.
    a_migrants = [*honest, *ring, forger, stale]

    policy = AdmissionPolicy(
        trusted_issuers={
            f"did:nest:{_AUDITOR_A}",
            f"did:nest:{_AUDITOR_X}",
        },
        min_reputation_score=min_score,
        require_recomputation=not naive_gate,
        require_published_ledger=not naive_gate,
    )

    roles: dict[AgentId, str] = {a: "honest" for a in honest}
    roles.update({a: "ring" for a in ring})
    roles[forger] = "forged"
    roles[replayer] = "replay"
    roles[stale] = "stale"
    roles[inflated] = "inflated"

    agents: dict[AgentId, StateMachineAgent] = {
        migrant: Migrant(migrant, role=roles[migrant]) for migrant in roles
    }
    agents[_AUDITOR_A] = DomainAAuditor(
        _AUDITOR_A,
        identity=a_ident,
        ledger=ledger,
        migrants=a_migrants,
        stale=stale,
        replayer=replayer,
        replay_victim=honest[1],
        old_key_id=old_key_id,
    )
    agents[_AUDITOR_X] = CorruptAuditor(
        _AUDITOR_X,
        identity=x_ident,
        client=inflated,
        receipts=inflated_receipts,
    )
    agents[_GATE] = BorderGate(_GATE, identity=gate_ident, policy=policy)
    return agents
