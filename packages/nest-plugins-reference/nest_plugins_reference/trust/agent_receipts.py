# SPDX-License-Identifier: Apache-2.0
"""Counterparty-corroborated receipt reputation with collusion-ring severance.

This trust plugin derives an agent's reputation from **cross-signed receipts**
of real interactions, not from a running mean of self-asserted feedback (the
``score_average`` reference baseline). The threat it is built to defeat is
**wash-traded reputation**: a Sybil/collusion ring whose members co-sign each
other's receipts to manufacture a glowing history. Naive averaging (and an
undefended EigenTrust seeded uniformly) *rewards* that ring; this plugin
**severs** it.

A receipt only builds reputation if it clears three independent gates:

1. **Valid** — its Ed25519 issuer signature verifies (:func:`_verify_receipt`).
2. **Corroborated** — the *distinct* counterparty named in the receipt
   co-signed the same interaction (:func:`is_corroborated`). One party cannot
   fabricate a corroborated receipt alone; it needs the counterparty's key.
3. **Not collusion-severed** — the receipt does not sit inside a collusion
   component that the corroboration graph isolates from the honest anchor
   (:func:`_severed_dids`, Tarjan strongly-connected components).

Gate 3 is the novel part. Corroboration alone is gameable: a set of
distinct-but-colluding identities can mutually co-sign. So we build the directed
corroboration graph over all agents (issuer -> counterparty, over valid +
corroborated receipts), take its strongly-connected components, and judge every
component — the largest included — by one rule: a component is severed iff it is
(a) **collusion-shaped** (a dense ring of size >= 3 with internal density >=
0.8, or a mutual-only pair) and (b) **externally uncorroborated** (no
cross-edges to any clean, non-collusion-shaped component). Component size is
never evidence of honesty: Sybil identities are free to mint, so a ring grown
larger than the honest core must not buy immunity by becoming the biggest
component (issue #97). The symmetric fail-safe: an isolated dense clique with no
outside trade earns nothing, whatever its size. A severed member's wash-traded
receipts — individually corroborated though they are — contribute nothing, so it
collapses to score 0 / confidence 0, while externally-corroborated honest agents
retain their full score.

This is **self-contained**: it depends only on the standard library and
``cryptography`` (already used by the ``ed25519_rotating`` reference identity).
Receipts are plain ``dict`` documents; canonicalization is sorted-key JSON; an
agent's identity is the lowercase hex of its raw 32-byte Ed25519 public key.

NEST's ``Evidence`` has no receipt field, so a cross-signed receipt rides as
JSON in ``evidence.detail``. Stock scenarios (e.g. the marketplace) pass a
plain-string ``detail``; those fall back to the reference score-average
heuristic so this plugin still works as a drop-in ``trust:`` replacement.

Registered under ``("trust", "agent_receipts")`` in ``nest_core.plugins``.

Example::

    trust = AgentReceiptsTrust()
    await trust.report(
        AgentId("a1"),
        Evidence(reporter=r, subject=s, kind="positive", detail=json.dumps(receipt)),
    )
    rep = await trust.score(AgentId("a1"))
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.types import (
    AgentId,
    Attestation,
    Claim,
    Evidence,
    ReputationScore,
    Signature,
)

logger = logging.getLogger(__name__)

ALGORITHM = "ed25519"

# Per-category weights, published as part of the scoring method. Consequential
# actions count for more than routine ones; administrative categories are
# reputation-neutral; a breached commitment earns nothing. A wash-trading ring
# typically mints high-value categories (purchase/payment), so the severance is
# what stops those weights from accruing.
DEFAULT_CATEGORY_WEIGHTS: dict[str, float] = {
    "purchase": 5.0,
    "payment_sent": 5.0,
    "payment_received": 5.0,
    "commitment_fulfilled": 4.0,
    "commitment_breached": 0.0,
    "attestation_issued": 2.0,
    "data_shared": 2.0,
    "message_sent": 1.0,
    "other": 0.0,
}

# Saturation constant for the unbounded weight sum -> [0, 1] map
# (``1 - exp(-raw/K)``). A single corroborated 'purchase' receipt is raw=5.0,
# which K=10 maps to ~0.39; raw=10 -> 0.63; raw=30 -> 0.95. Keeping the curve
# from saturating too fast preserves ordering between agents with more history.
NORMALIZATION_K = 10.0

# Collusion-ring severance thresholds. A non-anchor component isolated
# from the honest anchor is severed if it is a dense ring or a mutual-only pair.
RING_MIN_SIZE = 3
RING_MIN_DENSITY = 0.8


# ---------------------------------------------------------------------------
# Self-contained Ed25519 + canonicalization helpers
# ---------------------------------------------------------------------------


def did_for_pubkey(pubkey: bytes) -> str:
    """Return the lowercase-hex identity string for a raw 32-byte Ed25519 key.

    A receipt names its issuer and counterparty by this string. Using hex of
    the raw public key (rather than a base58 ``did:key``) keeps the plugin
    dependency-free while remaining a stable, collision-free identity.

    Example::

        did = did_for_pubkey(pubkey_bytes)
    """
    return pubkey.hex()


def _canonical(obj: Any) -> bytes:
    """Deterministically serialize ``obj`` to bytes for signing/verification.

    Sorted keys + compact separators give byte-identical output for equal
    documents across processes and runs, which both the issuer and the
    counterparty rely on so their signatures cover identical bytes.

    Example::

        payload = _canonical({"action": {"category": "purchase"}})
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _issuer_payload(receipt: dict[str, Any]) -> bytes:
    """Canonical bytes the *issuer* signs: the receipt minus its signatures.

    Drops the top-level ``signature`` and ``evidence.witness_signatures`` so the
    signed bytes describe *what happened* (action, parties) independent of any
    signature carrier.

    Example::

        payload = _issuer_payload(receipt)
    """
    core: dict[str, Any] = {k: v for k, v in receipt.items() if k != "signature"}
    evidence = core.get("evidence")
    if isinstance(evidence, dict):
        trimmed: dict[str, Any] = {
            k: v for k, v in cast("dict[str, Any]", evidence).items() if k != "witness_signatures"
        }
        if trimmed:
            core["evidence"] = trimmed
        else:
            core.pop("evidence", None)
    return _canonical(core)


def _corroboration_payload(receipt: dict[str, Any]) -> bytes:
    """Canonical bytes a *counterparty* co-signs.

    Identical to :func:`_issuer_payload`: the counterparty attests the same
    interaction the issuer signed, without depending on the issuer's signature.

    Example::

        payload = _corroboration_payload(receipt)
    """
    return _issuer_payload(receipt)


def _verify_ed25519(pubkey_hex: str, signature_hex: str, payload: bytes) -> bool:
    """Verify a hex Ed25519 signature over ``payload`` under a hex public key.

    Returns ``False`` (never raises) on malformed hex, a wrong-length key, or an
    invalid signature, so a hostile receipt can never crash verification.

    Example::

        ok = _verify_ed25519(pub_hex, sig_hex, b"payload")
    """
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(signature_hex)
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _verify_receipt(receipt: dict[str, Any]) -> bool:
    """Return whether a receipt's issuer signature verifies.

    The issuer is named by ``issuer_did`` (hex pubkey) and signs
    :func:`_issuer_payload`; the signature rides in top-level ``signature``.

    Example::

        ok = _verify_receipt(receipt)
    """
    issuer = receipt.get("issuer_did")
    sig = receipt.get("signature")
    if not isinstance(issuer, str) or not isinstance(sig, str):
        return False
    return _verify_ed25519(issuer, sig, _issuer_payload(receipt))


def _action_field(receipt: dict[str, Any], key: str) -> Any:
    """Return ``receipt["action"][key]`` (or ``None``) with a concrete dict type.

    Centralizes the loosely-typed ``action`` access so the typed call sites stay
    free of partially-unknown ``.get()`` chains.

    Example::

        cat = _action_field(receipt, "category")
    """
    action = receipt.get("action")
    if isinstance(action, dict):
        return cast("dict[str, Any]", action).get(key)
    return None


def _counterparty(receipt: dict[str, Any]) -> str | None:
    """The counterparty did iff present and distinct from the issuer.

    Self-corroboration (issuer == counterparty) is rejected: an agent cannot
    corroborate its own receipt.

    Example::

        cp = _counterparty(receipt)
    """
    cp = _action_field(receipt, "counterparty_did")
    if isinstance(cp, str) and cp and cp != receipt.get("issuer_did"):
        return cp
    return None


def is_corroborated(receipt: dict[str, Any]) -> bool:
    """Return whether a *distinct* counterparty co-signed this receipt.

    There must be a ``evidence.witness_signatures`` entry whose ``witness_did``
    equals the receipt's ``counterparty_did`` and whose signature verifies over
    the corroboration payload. Fully recomputable from the receipt alone.

    Example::

        corroborated = is_corroborated(receipt)
    """
    cp = _counterparty(receipt)
    if cp is None:
        return False
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict):
        return False
    witnesses = cast("dict[str, Any]", evidence).get("witness_signatures")
    if not isinstance(witnesses, list):
        return False
    payload = _corroboration_payload(receipt)
    for entry in cast("list[Any]", witnesses):
        if not isinstance(entry, dict):
            continue
        typed: dict[str, Any] = cast("dict[str, Any]", entry)
        if typed.get("witness_did") != cp:
            continue
        if _verify_ed25519(cp, str(typed.get("signature", "")), payload):
            return True
    return False


# ---------------------------------------------------------------------------
# Collusion severance (Tarjan SCC over the corroboration graph)
# ---------------------------------------------------------------------------


def _corroboration_graph(receipts: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Directed multigraph over valid, corroborated receipts: issuer -> counterparty.

    Example::

        graph = _corroboration_graph(receipts)
    """
    graph: dict[str, dict[str, int]] = {}
    for r in receipts:
        if not _verify_receipt(r) or not is_corroborated(r):
            continue
        a = str(r.get("issuer_did", ""))
        b = _counterparty(r) or ""
        graph.setdefault(a, {})
        graph.setdefault(b, {})
        graph[a][b] = graph[a].get(b, 0) + 1
    return graph


def _sccs(graph: dict[str, dict[str, int]]) -> list[list[str]]:
    """Tarjan strongly-connected components, deterministic; largest first.

    Iterative (explicit stack) so deep graphs cannot blow the recursion limit.
    Components are sorted internally and the result is ordered by descending
    size then lexicographically, so the honest anchor (the largest SCC) is
    always ``result[0]`` for a given graph.

    Example::

        comps = _sccs({"a": {"b": 1}, "b": {"a": 1}})
    """
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    scc_stack: list[str] = []
    comps: list[list[str]] = []
    counter = 0

    for root in sorted(graph):
        if root in index:
            continue
        # work stack holds (vertex, iterator-position over sorted successors)
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            v, i = work[-1]
            if i == 0:
                index[v] = low[v] = counter
                counter += 1
                scc_stack.append(v)
                on_stack.add(v)
            succ = sorted(graph.get(v, {}))
            if i < len(succ):
                work[-1] = (v, i + 1)
                w = succ[i]
                if w not in index:
                    work.append((w, 0))
                elif w in on_stack:
                    low[v] = min(low[v], index[w])
            else:
                if low[v] == index[v]:
                    comp: list[str] = []
                    while True:
                        w = scc_stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    comps.append(sorted(comp))
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[v])

    return sorted(comps, key=lambda c: (-len(c), c))


def _internal_density(graph: dict[str, dict[str, int]], members: set[str]) -> float:
    """Fraction of possible directed intra-component edges that are present.

    Example::

        d = _internal_density(graph, {"a", "b", "c"})
    """
    if len(members) < 2:
        return 0.0
    edges = sum(1 for a in members for b in graph.get(a, {}) if b in members and b != a)
    possible = len(members) * (len(members) - 1)
    return edges / possible if possible else 0.0


def _cross_edges(graph: dict[str, dict[str, int]], comp: set[str], other: set[str]) -> int:
    """Count directed edges crossing between ``comp`` and ``other`` (either way).

    Example::

        n = _cross_edges(graph, ring, anchor)
    """
    out = sum(1 for a in comp for b in graph.get(a, {}) if b in other)
    inc = sum(1 for a in other for b in graph.get(a, {}) if b in comp)
    return out + inc


def _collusion_shaped(graph: dict[str, dict[str, int]], comp: list[str]) -> bool:
    """Whether a component has the shape of a wash-trading structure.

    A component is collusion-shaped iff it is a dense ring (size >=
    ``RING_MIN_SIZE`` with internal density >= ``RING_MIN_DENSITY``) or a
    mutual-only pair. These are exactly the criteria :func:`_severed_dids`
    previously applied only to non-anchor components; extracting them lets
    severance judge *every* component by evidence shape instead of exempting
    the largest one (issue #97).

    Example::

        shaped = _collusion_shaped(graph, ["r0", "r1", "r2"])
    """
    members = set(comp)
    if len(members) >= RING_MIN_SIZE and _internal_density(graph, members) >= RING_MIN_DENSITY:
        return True
    if len(members) == 2:
        a, b = comp
        return b in graph.get(a, {}) and a in graph.get(b, {})
    return False


def _severed_dids(graph: dict[str, dict[str, int]]) -> set[str]:
    """Dids inside collusion-shaped components with no external corroboration.

    Component **size is never evidence of honesty**: every SCC — the largest
    included — is judged by the same two-part rule. A component is severed iff
    it is collusion-shaped (:func:`_collusion_shaped`: dense ring or
    mutual-only pair) **and** it has zero cross-edges to every *clean*
    (non-collusion-shaped) component. A single corroborated trade with any
    clean component exonerates it — an honest agent transacted with it, so it
    is not isolated.

    This closes the majority-Sybil inversion of issue #97: the previous rule
    exempted the largest SCC as the "honest anchor", so a ring grown past the
    honest core kept its wash-traded reputation while the honest minority was
    severed. Sybil identities are free to mint, so size is the one signal the
    attacker fully controls; the shape of the evidence and its external
    corroboration are not. Symmetric fail-safe consequence: an isolated dense
    clique with no external corroboration earns nothing, whatever its size.

    Example::

        severed = _severed_dids(_corroboration_graph(receipts))
    """
    comps = _sccs(graph)
    clean = [set(comp) for comp in comps if not _collusion_shaped(graph, comp)]
    severed: set[str] = set()
    for comp in comps:
        if not _collusion_shaped(graph, comp):
            continue
        members = set(comp)
        if any(_cross_edges(graph, members, other) > 0 for other in clean):
            continue  # an honest agent transacted with it — not isolated
        severed |= members
    return severed


def _effective_receipts(receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Receipts that are valid, corroborated, and not collusion-severed.

    Example::

        eff = _effective_receipts(ledger)
    """
    severed = _severed_dids(_corroboration_graph(receipts))
    out: list[dict[str, Any]] = []
    for r in receipts:
        if not _verify_receipt(r) or not is_corroborated(r):
            continue
        if str(r.get("issuer_did", "")) in severed or _counterparty(r) in severed:
            continue
        out.append(r)
    return out


def _raw_reputation(receipts: list[dict[str, Any]], weights: dict[str, float]) -> float:
    """Sum category weights over the effective receipts (unbounded).

    Example::

        raw = _raw_reputation(eff, DEFAULT_CATEGORY_WEIGHTS)
    """
    return sum(weights.get(str(_action_field(r, "category") or ""), 0.0) for r in receipts)


def _normalize(raw: float) -> float:
    """Map an unbounded non-negative reputation to ``[0, 1]`` via ``1 - exp(-raw/K)``.

    Example::

        s = _normalize(5.0)  # ~0.39 at K=10
    """
    if raw <= 0.0:
        return 0.0
    return 1.0 - math.exp(-raw / NORMALIZATION_K)


# ---------------------------------------------------------------------------
# Receipt construction (used by scenarios and tests)
# ---------------------------------------------------------------------------


def sign_receipt(receipt: dict[str, Any], *, issuer_seed: bytes) -> dict[str, Any]:
    """Return ``receipt`` with the issuer's Ed25519 signature attached.

    ``issuer_seed`` is the issuer's 32-byte private seed; its ``issuer_did`` must
    already be set to the hex of the matching public key. The signature covers
    :func:`_issuer_payload`.

    Example::

        signed = sign_receipt(receipt, issuer_seed=seed)
    """
    sk = Ed25519PrivateKey.from_private_bytes(issuer_seed)
    sig = sk.sign(_issuer_payload(receipt))
    return {**receipt, "signature": sig.hex()}


def cosign_receipt(receipt: dict[str, Any], *, counterparty_seed: bytes) -> dict[str, Any]:
    """Return ``receipt`` with a counterparty co-signature appended.

    Appends ``{"witness_did", "signature"}`` to ``evidence.witness_signatures``,
    where ``witness_did`` is the hex of the counterparty's public key and the
    signature covers :func:`_corroboration_payload`. The signer SHOULD be the
    receipt's ``counterparty_did``.

    Example::

        corroborated = cosign_receipt(signed, counterparty_seed=cp_seed)
    """
    sk = Ed25519PrivateKey.from_private_bytes(counterparty_seed)
    witness_did = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    sig = sk.sign(_corroboration_payload(receipt))
    entry: dict[str, str] = {"witness_did": witness_did, "signature": sig.hex()}
    out: dict[str, Any] = copy.deepcopy(receipt)
    evidence = out.setdefault("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}
        out["evidence"] = evidence
    witnesses = cast("dict[str, Any]", evidence).setdefault("witness_signatures", [])
    if not isinstance(witnesses, list):
        witnesses = []
        cast("dict[str, Any]", evidence)["witness_signatures"] = witnesses
    cast("list[Any]", witnesses).append(entry)
    return out


# ---------------------------------------------------------------------------
# The trust plugin
# ---------------------------------------------------------------------------


class AgentReceiptsTrust:
    """Receipt-based, collusion-resistant reputation implementing the ``Trust`` Protocol.

    The constructor is no-arg-callable — the NEST runner does ``trust_cls()`` — so
    this plugin mints its own deterministic Ed25519 identity (for attestations)
    and holds one global ledger of every reported receipt. Because severance is a
    whole-graph property, scoring any single agent reduces the *whole* ledger to
    its globally-effective subset first.

    Example::

        trust = AgentReceiptsTrust()
        rep = await trust.score(AgentId("a1"))
    """

    _SYSTEM_AGENT = AgentId("trust:agent_receipts")

    def __init__(self, identity: Any = None) -> None:
        # ``identity`` is accepted for parity with ScoreAverageTrust's ctor (the
        # runner calls trust_cls() with no args; some callers pass an identity).
        self._identity = identity
        # Deterministic system seed for signing attestations.
        self._system_seed = hashlib.sha256(b"trust:agent_receipts").digest()[:32]
        # One global ledger of verified-on-report receipts.
        self._ledger: list[dict[str, Any]] = []
        # Plain-string-detail fallback scores (stock-scenario compatibility).
        self._fallback_scores: dict[AgentId, list[float]] = {}
        # Parity-only stake tracking.
        self._stakes: dict[AgentId, int] = {}

    def _did_of(self, agent: AgentId) -> str:
        """Map a NEST ``AgentId`` to its receipt identity (deterministic hex pubkey).

        Example::

            did = trust._did_of(AgentId("a1"))
        """
        seed = hashlib.sha256(str(agent).encode()).digest()[:32]
        pub = (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        return did_for_pubkey(pub)

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation for an agent from its corroborated, non-severed receipts.

        Gathers the agent's receipts (those it issued), applies global collusion
        severance over the whole ledger, keeps only the agent's surviving
        receipts, and scores them. A severed ring member therefore drops to
        ``score == 0.0`` with ``confidence == 0.0`` even though it issued
        receipts (``sample_count > 0``), while honest anchor agents keep their
        full corroborated score. Agents with no receipts fall back to the
        plain-string heuristic, or the reference neutral prior (0.5).

        Example::

            rep = await trust.score(AgentId("a1"))
        """
        did = self._did_of(agent)
        mine = [r for r in self._ledger if str(r.get("issuer_did", "")) == did]
        if mine:
            effective = _effective_receipts(self._ledger)
            mine_eff = [r for r in effective if str(r.get("issuer_did", "")) == did]
            raw = _raw_reputation(mine_eff, DEFAULT_CATEGORY_WEIGHTS)
            confidence = len(mine_eff) / len(mine) if mine else 0.0
            return ReputationScore(
                agent_id=agent,
                score=_normalize(raw),
                confidence=confidence,
                sample_count=len(mine),
            )
        fallback = self._fallback_scores.get(agent)
        if fallback:
            avg = sum(fallback) / len(fallback)
            return ReputationScore(
                agent_id=agent,
                score=avg,
                confidence=min(1.0, len(fallback) / 100.0),
                sample_count=len(fallback),
            )
        return ReputationScore(agent_id=agent, score=0.5, confidence=0.0, sample_count=0)

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Issue an Ed25519-signed attestation about an agent.

        Signs ``claim.model_dump_json()`` with this plugin's own system key,
        mirroring the reference plugin's shape.

        Example::

            att = await trust.attest(AgentId("a1"), claim)
        """
        sk = Ed25519PrivateKey.from_private_bytes(self._system_seed)
        raw = sk.sign(claim.model_dump_json().encode())
        sig = Signature(signer=self._SYSTEM_AGENT, value=raw, algorithm=ALGORITHM)
        return Attestation(issuer=self._SYSTEM_AGENT, claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Report evidence — a cross-signed receipt, or a stock heuristic.

        ``evidence.detail`` is tried as JSON. If it decodes to a dict that passes
        :func:`_verify_receipt`, it enters the global ledger. A decoded dict that
        fails verification is logged (never silently dropped) and falls through
        to the heuristic. A plain-string ``detail`` (stock scenarios) uses the
        reference score-average heuristic so this plugin stays a drop-in.

        Example::

            await trust.report(AgentId("a1"), Evidence(reporter=r, subject=s,
                kind="positive", detail=json.dumps(receipt)))
        """
        try:
            parsed: object = json.loads(evidence.detail)
        except (json.JSONDecodeError, TypeError):
            self._record_fallback(agent, evidence)
            return

        if isinstance(parsed, dict):
            receipt = cast("dict[str, Any]", parsed)
            if _verify_receipt(receipt):
                self._ledger.append(receipt)
                return
            logger.warning(
                "report: detail decoded to a dict but failed receipt verification "
                "for agent=%s; using heuristic fallback",
                agent,
            )

        self._record_fallback(agent, evidence)

    def _record_fallback(self, agent: AgentId, evidence: Evidence) -> None:
        """Apply the reference score-average heuristic for non-receipt evidence.

        Example::

            trust._record_fallback(AgentId("a1"), evidence)
        """
        score_val = 0.5
        if evidence.kind == "positive":
            score_val = 1.0
        elif evidence.kind in ("negative", "byzantine"):
            score_val = 0.0
        self._fallback_scores.setdefault(agent, []).append(score_val)

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake reputation on an agent (parity-only no-op).

        There is no staking primitive in this scheme; the amount is recorded in
        memory purely for Protocol parity with the reference plugin.

        Example::

            await trust.stake(AgentId("a1"), 100)
        """
        self._stakes[agent] = self._stakes.get(agent, 0) + amount
