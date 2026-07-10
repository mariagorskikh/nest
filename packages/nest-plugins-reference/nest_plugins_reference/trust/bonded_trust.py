# SPDX-License-Identifier: Apache-2.0
"""Bonded-trust plugin — a Sybil-resistant *trust root* backed by a scarce ledger.

The default ``score_average`` baseline (and any pure running-mean or
graph-centrality reputation) shares a structural weakness: it trusts
*identities*, and NEST's ``did_key`` mints identities for free. So a Sybil can
spin up ten thousand agents, cross-report ``positive`` evidence about each
other, and ride the reputation they manufacture. EigenTrust's own PR concedes
the boundary: *"if NEST's auth/identity layers fail upstream, no trust layer can
save you."*

``bonded_trust`` relocates the Sybil anchor **out of the identity layer and into
a scarce stake**, so it degrades gracefully when identity authenticates nobody. It
cannot beat Douceur's impossibility result (2002) — and Douceur is precise: the
resource used for Sybil resistance must be *genuinely scarce and verified*, not
self-asserted. So this plugin does **not** trust a self-declared bond. It
reserves every bond through a :class:`StakeLedger` whose supply is finite:

* **Ledger-backed self-bond (defeats free minting).** An identity's trust root
  is pinned at the untrusted floor (``score == 0.0``) until it *reserves* a bond
  via :meth:`stake`. The reservation goes through a :class:`StakeLedger`; if the
  agent cannot afford it, **no bond is recorded**. A Sybil that sends
  ``bond:1000000`` with no credits gets nothing. Total bond across a swarm is
  bounded by the swarm's total credits, so splitting a fixed budget across K
  identities buys the same influence as holding it in one — minting more never
  helps.
* **Reporter-weighting (defeats wash-trading).** A report counts in proportion
  to the *reporter's* bond. Unbonded reporters carry zero weight, so a Sybil
  clique's mutual endorsements move nothing. Self-reports are ignored outright —
  an agent cannot vouch for itself.

**Scarcity is delegated, not faked.** The plugin's contribution is the gating +
weighting *mechanism*; the scarce resource comes from the ledger you inject. The
:mod:`sybil_bond <nest_core.scenarios_builtin.sybil_bond>` scenario backs it
with the **payments layer's** credit balances. The zero-arg default,
:class:`SelfDeclaredLedger`, grants any bond and is therefore **simulation/test
only** — it provides no defense against a *bonding* attacker. This mirrors
``hybrid_x25519``'s ``deterministic=False`` discipline: the weak default is
documented, not hidden.

**Honest boundaries** (stated, not implied):

* An attacker who spends *real* bond (credits, work — whatever the ledger
  meters) gains real influence. Because the score is a bond-weighted mean, a
  reporter holding a bond *majority* can dominate the sign of a score — that is
  the intended "most skin in the game, most say," and it costs the attacker its
  whole budget. The guarantee is that this influence is bounded by *spent bond*,
  independent of identity count.
* A bonded-but-unendorsed agent scores ``0.5`` (staked, unproven) — reachable
  only by spending bond, never for free.

Determinism: pure integer/float arithmetic over insertion-ordered dicts. Same
report/stake sequence → identical scores, preserving Tier-1 replay.

Example::

    trust = BondedTrust()  # SelfDeclaredLedger: fine for unit-testing the math
    await trust.stake(AgentId("a1"), 50)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from nest_core.types import (
    AgentId,
    Attestation,
    Claim,
    Evidence,
    ReputationScore,
    Signature,
)

_UNTRUSTED = 0.0
"""Score pinned on any identity whose trust root is not bonded."""

_NEUTRAL = 0.5
"""Score for a bonded identity with no *external* weighted evidence yet."""


@runtime_checkable
class StakeLedger(Protocol):
    """Source of scarce bond — the pluggable Sybil-resistance anchor.

    This is the extension point: ``bonded_trust`` is agnostic about *what* makes
    a bond scarce, so long as the anchor is finite and non-forgeable. Any of these
    families implements this one method and drops in unchanged (see
    :mod:`nest_plugins_reference.trust.stake_ledgers` for shipped anchors):

    * **payments credits** — a finite ledger balance (``CreditBackedLedger``).
    * **proof-of-work** — CPU spent per bond unit (``ProofOfWorkLedger``).
    * **consensus** — budget granted by a quorum (a ``QuorumLedger`` over
      HotStuff / PBFT votes; not yet shipped).
    * **attestation / proof-of-personhood** — redeemed Privacy-Pass / moltpass
      credentials, one per verified action (an ``AttestationLedger``; not yet
      shipped).

    A new payments/consensus/attestation plugin becomes a bond anchor via a
    ~5-line adapter — no change to ``bonded_trust`` itself.

    Example::

        reserved = ledger.reserve(AgentId("a1"), 100)
    """

    def reserve(self, agent: AgentId, amount: int) -> int:
        """Reserve up to ``amount`` of ``agent``'s balance as bond.

        Returns the amount actually reserved (``0`` if the agent cannot afford
        any). Implementations MUST debit what they return so it cannot be
        reserved twice.

        Example::

            got = ledger.reserve(AgentId("a1"), 100)
        """
        ...


class SelfDeclaredLedger:
    """Insecure default: grants any requested bond. **Simulation/test only.**

    Provides NO Sybil resistance against a *bonding* attacker — every agent may
    self-declare unlimited bond. Inject a scarce, balance-backed ledger (see the
    ``sybil_bond`` scenario) for the real guarantee.

    Example::

        assert SelfDeclaredLedger().reserve(AgentId("a1"), 10) == 10
    """

    def reserve(self, agent: AgentId, amount: int) -> int:
        """Grant the full requested amount unconditionally (no scarcity).

        Example::

            assert SelfDeclaredLedger().reserve(AgentId("a1"), 10) == 10
        """
        return max(0, amount)


def _evidence_value(kind: str) -> float:
    """Map an :class:`~nest_core.types.Evidence` kind to a [0, 1] feedback value.

    Example::

        assert _evidence_value("positive") == 1.0
    """
    if kind == "positive":
        return 1.0
    if kind in ("negative", "byzantine"):
        return 0.0
    return _NEUTRAL


@dataclass(frozen=True)
class _Report:
    """One reported feedback value, tagged with the reporter whose bond weights it."""

    reporter: AgentId
    value: float


class BondedTrust:
    """Ledger-backed stake reputation: a trust root a free-minted identity can't obtain.

    Implements the structural :class:`nest_core.layers.trust.Trust` protocol
    (``score``/``attest``/``report``/``stake``). Bond is reserved per subject via
    :meth:`stake` through the injected :class:`StakeLedger`; reports are weighted
    by the *reporter's* bond in :meth:`score`.

    Args:
        identity: Optional identity plugin used to sign attestations (matches the
            ``score_average`` constructor so existing callers keep working).
        ledger: The scarce bond source. Defaults to :class:`SelfDeclaredLedger`
            (insecure; test only). Inject a credit-backed ledger for real
            Sybil resistance.
        min_bond: Minimum bond an identity must hold for its trust root to leave
            the untrusted floor. Must be ``>= 1``; ``0`` would disable the gate.
        confidence_scale: Total bonded weight at which confidence saturates to 1.

    Example::

        trust = BondedTrust(min_bond=1)
        await trust.stake(AgentId("a1"), 50)
    """

    def __init__(
        self,
        identity: Any = None,
        *,
        ledger: StakeLedger | None = None,
        min_bond: int = 1,
        confidence_scale: float = 100.0,
    ) -> None:
        if min_bond < 1:
            msg = f"min_bond must be >= 1 (min_bond=0 disables the gate); got {min_bond}"
            raise ValueError(msg)
        self._identity = identity
        self._ledger: StakeLedger = ledger if ledger is not None else SelfDeclaredLedger()
        self._min_bond = min_bond
        self._confidence_scale = confidence_scale
        self._bonds: dict[AgentId, int] = {}
        self._reports: dict[AgentId, list[_Report]] = {}

    def _weight(self, reporter: AgentId) -> float:
        """Bonded weight a reporter contributes: its bond, strictly linear.

        Linearity is load-bearing: it is what makes a colluder's influence depend
        on *total* bond, not on how many identities the bond is split across.
        """
        return float(self._bonds.get(reporter, 0))

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation for *agent*: the untrusted floor unless its root is bonded.

        An unbonded identity (bond ``< min_bond``) always scores ``0.0``. A bonded
        identity's score is the bond-weighted mean of feedback reported about it
        by *other* agents; unbonded reporters contribute zero weight and
        self-reports are ignored.

        Example::

            rep = await trust.score(AgentId("a1"))
        """
        reports = self._reports.get(agent, [])
        if self._bonds.get(agent, 0) < self._min_bond:
            return ReputationScore(
                agent_id=agent, score=_UNTRUSTED, confidence=0.0, sample_count=len(reports)
            )

        num = 0.0
        den = 0.0
        counted = 0
        for report in reports:
            if report.reporter == agent:
                continue  # no self-vouching
            weight = self._weight(report.reporter)
            if weight <= 0.0:
                continue
            num += weight * report.value
            den += weight
            counted += 1

        if den <= 0.0:
            return ReputationScore(agent_id=agent, score=_NEUTRAL, confidence=0.0, sample_count=0)
        return ReputationScore(
            agent_id=agent,
            score=num / den,
            confidence=min(1.0, den / self._confidence_scale),
            sample_count=counted,
        )

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Create an attestation about *agent*, signed if an identity was supplied.

        Example::

            att = await trust.attest(AgentId("a1"), claim)
        """
        sig = Signature(signer=AgentId("system"), value=b"attestation", algorithm="none")
        if self._identity is not None:
            sig = self._identity.sign(claim.model_dump_json().encode())
        return Attestation(issuer=AgentId("system"), claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Record feedback about *agent*, tagged with the reporter for bond-weighting.

        Example::

            await trust.report(
                AgentId("a1"),
                Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive"),
            )
        """
        self._reports.setdefault(agent, []).append(
            _Report(reporter=evidence.reporter, value=_evidence_value(evidence.kind))
        )

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Reserve *agent*'s bond through the ledger — the scarce root of its trust.

        Only the amount the ledger actually reserves is bonded, so an agent that
        cannot afford the stake gets no trust root (the free-minting defense).

        Example::

            await trust.stake(AgentId("a1"), 100)
        """
        if amount <= 0:
            return
        reserved = self._ledger.reserve(agent, amount)
        if reserved > 0:
            self._bonds[agent] = self._bonds.get(agent, 0) + reserved
