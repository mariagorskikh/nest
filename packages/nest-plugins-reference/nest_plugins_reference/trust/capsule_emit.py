# SPDX-License-Identifier: Apache-2.0
"""CapsuleEmitTrust — in-process sealed reputation; zero external deps.

Drop-in replacement for ``AgentReceiptsTrust``: every corroborated receipt is
sealed into an in-memory chain of JCS digests instead of writing to a capsule
ledger on disk. The anchoring *evidence*, however, is not the chain — it is
the pre-obtained CCF / Azure Confidential Ledger write receipt per sealed
receipt (see :func:`load_committed_ccf_receipts`), which the auditor
broadcasts as ``ccfreceipt:`` trace events and the
``receipt_reputation_capsule`` validator verifies OFFLINE against the pinned
ledger service identity. The ``seal:`` events are still broadcast as a tamper
trip-wire, but they are a pure function of plaintext trace content and can
never produce a PASS on their own.

Three gates for a receipt to build reputation:

1. **Valid** — Ed25519 issuer signature verifies.
2. **Corroborated** — a distinct counterparty co-signed the same interaction.
3. **Anchored (in-memory)** — the receipt was sealed into the in-process chain;
   the digest stored in ``self._sealed`` must equal ``jcs_digest(receipt)``.

Gate 3 is the additive contribution over ``agent_receipts``: a receipt whose
in-memory representation was mutated after sealing fails the digest check and
is excluded from the score. The seal chain records the order of seals; the
auditor hook broadcasts ``seal:`` events so the validator can replay and verify
the chain from the trace alone.

Plain-string ``evidence.detail`` (stock scenarios with no receipt) falls back
to the ``score_average`` heuristic, so this plugin is a drop-in in any scenario.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
from importlib import resources
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.canonical import (
    SEAL_CHAIN_GENESIS,
    jcs_digest,
    seal_chain,
    verify_receipt_signature,
)
from nest_core.types import AgentId, Attestation, Claim, Evidence, ReputationScore

from nest_plugins_reference.trust.agent_receipts import (
    DEFAULT_CATEGORY_WEIGHTS,
    did_for_pubkey,
    is_corroborated,
)

logger = logging.getLogger(__name__)

ALGORITHM = "ed25519"

#: Name of the committed-fixture directory holding pre-obtained confidential-
#: ledger write receipts, one ``<receipt_jcs_digest>.receipt.json`` per receipt.
_CCF_FIXTURE_DIR = "ccf_receipts"
_CCF_FIXTURE_SUFFIX = ".receipt.json"


def load_committed_ccf_receipts() -> dict[str, bytes]:
    """Load the committed confidential-ledger write-receipt fixtures, if any.

    The fixtures are obtained OUT OF BAND (the operator-gated pre-anchor step
    registers each receipt's JCS digest as a claim with the real Azure
    Confidential Ledger and commits the returned write receipts), keyed by
    receipt digest. This read happens at plugin construction — the *run* side.
    The validator's verdict path never touches the filesystem: it sees only
    what the auditor broadcast onto the trace.

    Returns ``{}`` when no fixtures are committed yet, which fails closed: the
    auditor then emits no ``ccfreceipt:`` lines and the anchored validator
    grades FAIL.

    Example::

        store = load_committed_ccf_receipts()
    """
    out: dict[str, bytes] = {}
    try:
        fixture_dir = resources.files(__package__) / _CCF_FIXTURE_DIR
        for entry in fixture_dir.iterdir():
            if not entry.name.endswith(_CCF_FIXTURE_SUFFIX):
                continue
            digest = entry.name[: -len(_CCF_FIXTURE_SUFFIX)]
            if len(digest) != 64:
                continue
            out[digest] = entry.read_bytes()
    except (OSError, TypeError, ValueError):
        return {}
    return out


# ---------------------------------------------------------------------------
# Self-contained scoring helpers.
#
# The Gate-1/Gate-2 scoring (counterparty extraction, Tarjan collusion
# severance, category weighting, normalization) is defined locally here —
# copied verbatim from ``nest_plugins_reference.trust.agent_receipts`` — so
# this plugin never reaches into another module's private (leading-underscore)
# internals.  The only additive behaviour lives in :meth:`CapsuleEmitTrust.score`.
# ---------------------------------------------------------------------------

# Saturation constant for the unbounded weight sum -> [0, 1] map
# (matches agent_receipts.NORMALIZATION_K).
_NORMALIZATION_K = 10.0
# Collusion-ring severance thresholds (match agent_receipts).
_RING_MIN_SIZE = 3
_RING_MIN_DENSITY = 0.8


def _action_field(receipt: dict[str, Any], key: str) -> Any:
    """Return ``receipt["action"][key]`` (or ``None``)."""
    action = receipt.get("action")
    if isinstance(action, dict):
        return cast("dict[str, Any]", action).get(key)
    return None


def _counterparty(receipt: dict[str, Any]) -> str | None:
    """The counterparty did iff present and distinct from the issuer."""
    cp = _action_field(receipt, "counterparty_did")
    if isinstance(cp, str) and cp and cp != receipt.get("issuer_did"):
        return cp
    return None


def _receipt_key(receipt: dict[str, Any]) -> str:
    """Stable per-receipt key: SHA-256 over the receipt's canonical sorted-key JSON bytes."""
    return hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _corroboration_graph(receipts: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Directed multigraph over valid, corroborated receipts: issuer -> counterparty."""
    graph: dict[str, dict[str, int]] = {}
    for r in receipts:
        if not verify_receipt_signature(r) or not is_corroborated(r):
            continue
        a = str(r.get("issuer_did", ""))
        b = _counterparty(r) or ""
        graph.setdefault(a, {})
        graph.setdefault(b, {})
        graph[a][b] = graph[a].get(b, 0) + 1
    return graph


def _sccs(graph: dict[str, dict[str, int]]) -> list[list[str]]:
    """Tarjan strongly-connected components, deterministic; largest first."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    scc_stack: list[str] = []
    comps: list[list[str]] = []
    counter = 0

    for root in sorted(graph):
        if root in index:
            continue
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
    """Fraction of possible directed intra-component edges that are present."""
    if len(members) < 2:
        return 0.0
    edges = sum(1 for a in members for b in graph.get(a, {}) if b in members and b != a)
    possible = len(members) * (len(members) - 1)
    return edges / possible if possible else 0.0


def _cross_edges(graph: dict[str, dict[str, int]], comp: set[str], other: set[str]) -> int:
    """Count directed edges crossing between ``comp`` and ``other`` (either way)."""
    out = sum(1 for a in comp for b in graph.get(a, {}) if b in other)
    inc = sum(1 for a in other for b in graph.get(a, {}) if b in comp)
    return out + inc


def _severed_dids(graph: dict[str, dict[str, int]]) -> set[str]:
    """Dids in collusion structure isolated from the honest anchor (largest SCC)."""
    comps = _sccs(graph)
    if not comps:
        return set()
    anchor = set(comps[0])
    severed: set[str] = set()
    for comp in comps[1:]:
        members = set(comp)
        if _cross_edges(graph, members, anchor) > 0:
            continue
        if (
            len(members) >= _RING_MIN_SIZE
            and _internal_density(graph, members) >= _RING_MIN_DENSITY
        ):
            severed |= members
        elif len(members) == 2:
            a, b = comp
            if b in graph.get(a, {}) and a in graph.get(b, {}):
                severed |= members
    return severed


def _effective_receipts(receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Receipts that are valid, corroborated, and not collusion-severed."""
    severed = _severed_dids(_corroboration_graph(receipts))
    out: list[dict[str, Any]] = []
    for r in receipts:
        if not verify_receipt_signature(r) or not is_corroborated(r):
            continue
        if str(r.get("issuer_did", "")) in severed or _counterparty(r) in severed:
            continue
        out.append(r)
    return out


def _raw_reputation(receipts: list[dict[str, Any]], weights: dict[str, float]) -> float:
    """Sum category weights over the effective receipts (unbounded)."""
    return sum(weights.get(str(_action_field(r, "category") or ""), 0.0) for r in receipts)


def _normalize(raw: float) -> float:
    """Map an unbounded non-negative reputation to ``[0, 1]`` via ``1 - exp(-raw/K)``."""
    if raw <= 0.0:
        return 0.0
    return 1.0 - math.exp(-raw / _NORMALIZATION_K)


def _did_of(agent: AgentId) -> str:
    """Map a NEST ``AgentId`` to its receipt identity (deterministic hex pubkey)."""
    seed = hashlib.sha256(str(agent).encode()).digest()[:32]
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return did_for_pubkey(pub)


class CapsuleEmitTrust:
    """In-process sealed, collusion-resistant reputation implementing the ``Trust`` Protocol.

    Mirrors ``AgentReceiptsTrust`` with one addition: every receipt that passes
    Gate 1 (valid signature) is sealed into an in-memory JCS digest chain so the
    anchoring property is verifiable from the deterministic trace alone — zero
    filesystem I/O, zero network calls, zero external dependencies beyond what
    ``nest-core`` and ``nest-plugins-reference`` already declare.

    The auditor hook (:meth:`seal_events`) exposes the accumulated seals so the
    ``AuditorAgent._finalize`` method can broadcast them as ``seal:`` trace lines.
    The ``receipt_reputation_capsule`` validator replays those lines to verify
    chain integrity and completeness without touching the filesystem.
    """

    _SYSTEM_AGENT = AgentId("trust:capsule_emit")

    def __init__(
        self,
        identity: Any = None,
        ccf_receipts: Mapping[str, bytes] | None = None,
    ) -> None:
        self._identity = identity
        self._system_seed = hashlib.sha256(b"trust:capsule_emit").digest()[:32]
        self._receipts: list[dict[str, Any]] = []
        # Pre-obtained confidential-ledger write receipts, keyed by receipt JCS
        # digest. Defaults to the committed fixtures (empty until the operator-
        # gated pre-anchor step lands them — fail-closed). Tests inject a store
        # minted by the LOCAL TEST-ONLY confidential ledger.
        self._ccf_receipts: dict[str, bytes] = (
            dict(ccf_receipts) if ccf_receipts is not None else load_committed_ccf_receipts()
        )
        # In-memory sealing state:
        #   _seals: ordered list of (seq, subject_digest, chain_hash) triples
        #   _chain: the running chain hash (starts at SEAL_CHAIN_GENESIS)
        #   _sealed: receipt_key -> jcs_digest for Gate-3 in-memory check
        self._seals: list[tuple[int, str, str]] = []
        self._chain: str = SEAL_CHAIN_GENESIS
        self._sealed: dict[str, str] = {}
        self._seal_failures = 0
        self._fallback_scores: dict[AgentId, list[float]] = {}
        self._stakes: dict[AgentId, int] = {}

    @property
    def receipts(self) -> list[dict[str, Any]]:
        """The in-memory receipts recorded so far (live backing list)."""
        return self._receipts

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Report evidence; seal into the in-memory chain if it's a valid receipt."""
        try:
            parsed: object = json.loads(evidence.detail)
        except (json.JSONDecodeError, TypeError):
            self._record_fallback(agent, evidence)
            return

        if not isinstance(parsed, dict):
            self._record_fallback(agent, evidence)
            return

        receipt = cast("dict[str, Any]", parsed)
        if not verify_receipt_signature(receipt):
            self._record_fallback(agent, evidence)
            return

        self._receipts.append(receipt)
        self._seal(receipt)

    def _seal(self, receipt: dict[str, Any]) -> None:
        """Compute the JCS digest of ``receipt`` and fold it into the seal chain."""
        try:
            digest = jcs_digest(receipt)
        except (ValueError, TypeError) as exc:
            self._seal_failures += 1
            logger.warning(
                "seal failed for receipt (seal_failures=%d): %s",
                self._seal_failures,
                exc,
            )
            return
        key = _receipt_key(receipt)
        seq = len(self._seals)
        self._chain = seal_chain(self._chain, digest)
        self._seals.append((seq, digest, self._chain))
        self._sealed[key] = digest

    def seal_events(self) -> list[tuple[int, str, str]]:
        """Return the accumulated seal triples ``(seq, subject_digest, chain_hash)``.

        The auditor hook broadcasts these as ``seal:<seq>:<subject_digest>:<chain_hash>``
        trace lines after emitting all ``score:`` lines, so the validator can replay
        and verify the chain without touching the filesystem.
        """
        return list(self._seals)

    def ccf_receipt_events(self) -> list[tuple[str, str]]:
        """Return ``(subject_digest, receipt_json_hex)`` pairs — the anchoring evidence.

        One pair per sealed receipt whose digest has a pre-obtained
        confidential-ledger write receipt in the store. The auditor hook
        broadcasts each as a ``ccfreceipt:<subject_digest>:<receipt_json_hex>``
        trace line; the anchored validator verifies the write receipt offline
        against the pinned ledger service identity. A digest with no stored
        receipt yields nothing — the validator then fails that receipt, closed.

        Example::

            pairs = plugin.ccf_receipt_events()
        """
        out: list[tuple[str, str]] = []
        for _seq, digest, _chain in self._seals:
            blob = self._ccf_receipts.get(digest)
            if blob is not None:
                out.append((digest, blob.hex()))
        return out

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation from corroborated, ring-severed, in-memory-anchored receipts.

        Gate 3 (Anchored) is enforced by comparing each effective receipt's
        ``jcs_digest`` against the value stored in ``self._sealed`` at report time.
        A receipt whose in-memory representation was mutated after sealing will
        compute a different digest and be excluded — ``agent_receipts`` cannot
        detect this attack because it has no sealed reference.
        """
        did = _did_of(agent)
        effective = _effective_receipts(self._receipts)
        mine_eff = [r for r in effective if str(r.get("issuer_did", "")) == did]
        mine_all = [r for r in self._receipts if str(r.get("issuer_did", "")) == did]

        # Gate 3: in-memory check — sealed digest must still match receipt content.
        mine_anchored: list[dict[str, Any]] = []
        for r in mine_eff:
            key = _receipt_key(r)
            sealed_digest = self._sealed.get(key)
            if sealed_digest is None:
                continue
            try:
                current_digest = jcs_digest(r)
            except (ValueError, TypeError) as exc:
                logger.warning("Gate-3 digest failed for receipt; excluding it: %s", exc)
                continue
            if sealed_digest == current_digest:
                mine_anchored.append(r)

        if mine_all:
            raw = _raw_reputation(mine_anchored, DEFAULT_CATEGORY_WEIGHTS)
            confidence = len(mine_anchored) / len(mine_all)
            return ReputationScore(
                agent_id=agent,
                score=_normalize(raw),
                confidence=confidence,
                sample_count=len(mine_all),
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
        """Issue an Ed25519-signed attestation (same as agent_receipts)."""
        from nest_core.types import Signature

        sk = Ed25519PrivateKey.from_private_bytes(self._system_seed)
        raw = sk.sign(claim.model_dump_json().encode())
        sig = Signature(signer=self._SYSTEM_AGENT, value=raw, algorithm=ALGORITHM)
        return Attestation(issuer=self._SYSTEM_AGENT, claim=claim, signature=sig)

    async def stake(self, agent: AgentId, amount: int) -> None:
        self._stakes[agent] = self._stakes.get(agent, 0) + amount

    def _record_fallback(self, agent: AgentId, evidence: Evidence) -> None:
        score_val = 0.5
        if evidence.kind == "positive":
            score_val = 1.0
        elif evidence.kind in ("negative", "byzantine"):
            score_val = 0.0
        self._fallback_scores.setdefault(agent, []).append(score_val)
