# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
# (PARC deliberately composes agent_receipts' module-level receipt maths —
# _canonical/_verify_receipt/_raw_reputation/_normalize/_severed_dids/
# _corroboration_graph — so the credential recompute path can never drift
# from the exporter's scoring. See the module docstring.)
"""PARC — a Portable Agent Reputation Credential trust plugin.

Reputation in NEST dies with the run: every trust plugin holds an in-memory
ledger and nothing exports it, carries it, or verifies it in another trust
domain. This plugin makes reputation **portable**. It extends the
``agent_receipts`` reference plugin (cross-signed receipts, corroboration
gates, collusion-ring severance) with three new capabilities:

1. **Export** — :meth:`ParcTrust.build_credential` wraps an agent's receipt
   ledger as a W3C-Verifiable-Credential-shaped document: a
   ``behavioral_merkle_root`` committing to the carried receipts, the
   ``nanda-rep/0.2`` scores recomputable from them, and an Ed25519 proof
   issued **through the identity layer** (``ed25519_rotating``), so the proof
   carries a ``key_id`` and is checkable against the issuer's key-rotation
   windows.
2. **Admission** — :meth:`ParcTrust.admit` consumes a presented credential at
   the border of a new trust domain. The gate **recomputes rather than
   trusts**: it re-derives the Merkle root and the scores from the carried
   receipts and rejects any divergence. *A valid signature is not admission* —
   an issuer-inflated-then-re-signed score passes proof verification and is
   still rejected on recompute divergence.
3. **Selective disclosure** — :meth:`ParcTrust.build_presentation` reveals a
   chosen subset of receipts, each with a **Merkle inclusion proof** against
   the credential's signed ``behavioral_merkle_root``, and
   :meth:`ParcTrust.verify_presentation` confirms every disclosed receipt is
   committed under that root — plus the signed ``receipt_count`` bound on the
   undisclosed remainder — without seeing the rest of the ledger. Disclosure
   proves *which receipts happened*; it never recomputes scores. The
   reputation aggregate is a whole-graph property (collusion severance needs
   every edge), so the signed score stands — recomputing it from a
   hand-picked subset is exactly the cherry-picking attack this split
   forbids. Full-ledger recomputation remains :meth:`ParcTrust.admit`'s job.

An inline credential carries only the subject's own receipts — a star graph —
so it cannot reveal an N-party collusion ring (each ring member's credential
looks individually corroborated). :meth:`ParcTrust.ingest_published_ledger`
closes that hole: the originating domain publishes its community ledger once,
and the gate re-runs the whole-graph collusion severance from
``agent_receipts`` over it, denying severed subjects even though their inline
credentials verify.

Identity conventions (two key namespaces, deliberately distinct):

* **Subjects** are named by the trust-layer receipt identity — the lowercase
  hex pubkey of ``agent_receipts.did_for_pubkey`` — because that is what the
  carried receipts' ``issuer_did`` fields use and what recomputation runs on.
* **Issuers** are named by a stable ``did:nest:<agent-id>`` URI, and the
  proof's ``verificationMethod`` pins the actual signing key as a
  ``did:key:z6Mk...`` (multibase/multicodec Ed25519, encoder vendored below)
  plus the identity layer's ``key_id`` fragment. Verification resolves the
  issuer through the identity layer and enforces the key's validity window
  **as-of the credential's** ``validFrom`` tick, so a credential signed with
  an already-rotated-out key is rejected (``stale_key``).

Determinism: scores are embedded as fixed 6-decimal strings, receipts are
sorted by ``receipt_id``, canonicalization is sorted-key compact JSON, Merkle
leaves are sorted — byte-identical credentials for identical ledgers, with no
wall-clock anywhere (``validFrom`` is a logical tick supplied by the caller).

Registered under ``("trust", "parc")`` in ``nest_core.plugins`` and as the
``parc`` entry point in the ``nest.plugins.trust`` group.

Example::

    trust = ParcTrust()
    await trust.report(subject, evidence)  # receipts, as in agent_receipts
    vc = await trust.build_credential(subject, identity=ident, valid_from=6.0)
    result = await gate.admit(vc, policy=policy, presenter_did=did,
                              identity=gate_ident, current_tick=6.0)
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from nest_core.types import AgentId

# PARC composes the receipt maths of the merged agent_receipts plugin rather
# than re-implementing it: receipt verification, corroboration, and the
# whole-graph collusion severance MUST stay in exactly one place so a
# credential's recomputed score can never drift from the exporter's.
from nest_plugins_reference.trust import agent_receipts as ar

SCORING_METHOD = "nanda-rep/0.2"
CREDENTIAL_TYPE = "ParcReputationCredential"
CREDENTIAL_CONTEXT = "https://www.w3.org/ns/credentials/v2"
PROOF_TYPE = "Ed25519Signature2020"
ISSUER_URI_PREFIX = "did:nest:"

# ---------------------------------------------------------------------------
# Vendored did:key encoding (multibase base58btc + multicodec ed25519-pub)
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Multicodec prefix for ed25519-pub (0xed) as an unsigned varint (0xed 0x01).
_ED25519_MULTICODEC = b"\xed\x01"


def _b58btc_encode(data: bytes) -> str:
    """Base58btc-encode ``data`` (Bitcoin alphabet, leading zeros as ``1``).

    Vendored (~15 lines) so the plugin stays stdlib+cryptography-only, matching
    the dependency posture of the other reference plugins.

    Example::

        s = _b58btc_encode(b"\\x00\\x01")
    """
    num = int.from_bytes(data, "big")
    out: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(_B58_ALPHABET[rem])
    pad = 0
    for byte in data:
        if byte != 0:
            break
        pad += 1
    return "1" * pad + "".join(reversed(out))


def did_key_for_pubkey(pubkey: bytes) -> str:
    """Return the ``did:key`` DID for a raw 32-byte Ed25519 public key.

    ``did:key:z`` + base58btc(multicodec ``ed25519-pub`` prefix + key). Every
    Ed25519 ``did:key`` therefore starts with ``did:key:z6Mk``. This is the
    interop-facing form used in ``proof.verificationMethod``; receipts keep
    the hex namespace of :func:`agent_receipts.did_for_pubkey`.

    Example::

        did = did_key_for_pubkey(pubkey)  # "did:key:z6Mk..."
    """
    return "did:key:z" + _b58btc_encode(_ED25519_MULTICODEC + pubkey)


# ---------------------------------------------------------------------------
# Credential construction helpers
# ---------------------------------------------------------------------------


def _fmt6(value: float) -> str:
    """Format a float as a fixed 6-decimal string for deterministic embedding.

    Scores ride in the signed credential as strings, not floats, so canonical
    JSON bytes never depend on float repr subtleties.

    Example::

        s = _fmt6(0.5)  # "0.500000"
    """
    return f"{value:.6f}"


def merkle_root(receipts: list[dict[str, Any]]) -> str:
    """Deterministic Merkle root (hex) committing to a set of receipts.

    Leaves are ``sha256`` of each receipt's canonical bytes, sorted
    lexicographically so the root is order-independent; odd levels duplicate
    the last node. An empty ledger has the root ``sha256(b"")``.

    Example::

        root = merkle_root(receipts)
    """
    leaves = sorted(hashlib.sha256(ar._canonical(r)).hexdigest() for r in receipts)
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = leaves
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]
        level = [
            hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]


def inclusion_proof(
    receipts: list[dict[str, Any]],
    *,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    """Merkle inclusion proof that ``receipt`` is committed by ``merkle_root(receipts)``.

    Built over the exact tree :func:`merkle_root` computes — hex leaf digests
    sorted lexicographically, parents hashing the *concatenated hex strings*,
    odd levels duplicating the last node — so it verifies against the
    ``behavioral_merkle_root`` a credential signs. Shape::

        {"leaf_index": int, "leaf_count": int,
         "path": [{"sibling": <hex>, "position": "left" | "right"}, ...]}

    ``leaf_count`` is the total number of committed leaves: a verifier checks
    it against the credential's signed ``receipt_count``, so a holder cannot
    misrepresent how much ledger stays undisclosed. Raises ``ValueError`` if
    ``receipt`` is not in ``receipts`` — a proof for an absent leaf does not
    exist.

    Example::

        proof = inclusion_proof(receipts, receipt=receipts[0])
    """
    leaves = sorted(hashlib.sha256(ar._canonical(r)).hexdigest() for r in receipts)
    target = hashlib.sha256(ar._canonical(receipt)).hexdigest()
    try:
        index = leaves.index(target)
    except ValueError as exc:
        raise ValueError("receipt is not present in the ledger") from exc

    path: list[dict[str, str]] = []
    level = leaves
    node_index = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]
        # An even node is the left input of its pair, so its sibling sits on
        # the right — and vice versa.
        position = "right" if node_index % 2 == 0 else "left"
        path.append({"sibling": level[node_index ^ 1], "position": position})
        level = [
            hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest()
            for i in range(0, len(level), 2)
        ]
        node_index //= 2
    return {"leaf_index": index, "leaf_count": len(leaves), "path": path}


def verify_inclusion(receipt: dict[str, Any], proof: dict[str, Any], root: str) -> bool:
    """True iff ``receipt`` folds up ``proof``'s path to ``root``.

    The dual of :meth:`ParcTrust.admit`'s recomputation: instead of rebuilding
    the whole tree from every carried receipt, the verifier recomputes ONE
    leaf and folds it up the authentication path — it never needs the rest of
    the ledger. ``root`` is the bare hex :func:`merkle_root` returns (what
    credentials sign as ``behavioral_merkle_root``). A tampered receipt, a
    tampered sibling, or a foreign root all fold to a different hex and yield
    ``False``; a structurally malformed proof is also ``False``, never an
    exception — proofs arrive from the presenting (adversarial) side.

    Example::

        ok = verify_inclusion(receipt, proof, root)
    """
    steps = proof.get("path")
    if not isinstance(steps, list):
        return False
    node = hashlib.sha256(ar._canonical(receipt)).hexdigest()
    for step in cast("list[Any]", steps):
        if not isinstance(step, dict):
            return False
        step_typed = cast("dict[str, Any]", step)
        sibling = step_typed.get("sibling")
        position = step_typed.get("position")
        if not isinstance(sibling, str) or position not in ("left", "right"):
            return False
        pair = sibling + node if position == "left" else node + sibling
        node = hashlib.sha256(pair.encode()).hexdigest()
    return node == root


def _inline_scores(receipts: list[dict[str, Any]]) -> tuple[float, float, float]:
    """``(reputation_score, validity_rate, corroboration_rate)`` for a subject's ledger.

    Computed over the subject's own receipts exactly as an admission gate can
    recompute them from the carried credential: valid + corroborated receipts
    are weighted and normalized, **without** whole-graph severance — a
    single-subject ledger is a star graph, so severance is structurally a
    no-op there. Ring detection is therefore the published-ledger path's job
    (see :meth:`ParcTrust.ingest_published_ledger`), not the inline score's.

    Example::

        score, validity, corroboration = _inline_scores(receipts)
    """
    if not receipts:
        return 0.0, 0.0, 0.0
    valid = [r for r in receipts if ar._verify_receipt(r)]
    corroborated = [r for r in valid if ar.is_corroborated(r)]
    raw = ar._raw_reputation(corroborated, ar.DEFAULT_CATEGORY_WEIGHTS)
    return (
        ar._normalize(raw),
        len(valid) / len(receipts),
        len(corroborated) / len(receipts),
    )


def credential_payload(credential: dict[str, Any]) -> bytes:
    """Canonical bytes a credential's proof signs: the document minus ``proof``.

    Example::

        payload = credential_payload(vc)
    """
    return ar._canonical({k: v for k, v in credential.items() if k != "proof"})


def attach_proof(
    credential: dict[str, Any],
    *,
    identity: Any,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Return ``credential`` with an identity-layer Ed25519 proof attached.

    Signs :func:`credential_payload` through the identity plugin — ``sign()``
    for the current key, or ``sign_with(key_id)`` to sign with a specific
    (possibly rotated-out) key. The latter mirrors
    ``Ed25519RotatingIdentity.sign_with``'s adversarial purpose: scenarios use
    it to forge post-rotation credentials that the as-of window check must
    reject. ``verificationMethod`` pins the signing key as
    ``did:key:...#<key_id>``.

    Example::

        vc = attach_proof(vc, identity=ident)
    """
    payload = credential_payload(credential)
    if key_id is not None and hasattr(identity, "sign_with"):
        sig = identity.sign_with(payload, key_id)
    else:
        sig = identity.sign(payload)
    pub = _own_pubkey_for_key(identity, str(sig.key_id))
    return {
        **credential,
        "proof": {
            "type": PROOF_TYPE,
            "verificationMethod": f"{did_key_for_pubkey(pub)}#{sig.key_id}",
            "proofValue": sig.value.hex(),
        },
    }


def _own_pubkey_for_key(identity: Any, key_id: str) -> bytes:
    """The raw public key bytes of one of ``identity``'s own keys, by ``key_id``.

    Falls back to the current ``public_key`` when the plugin does not expose a
    key history (e.g. ``did_key``), whose single key is its only key.

    Example::

        pub = _own_pubkey_for_key(ident, str(ident.current_key_id))
    """
    records = getattr(identity, "_records", None)
    if isinstance(records, dict):
        own = cast("dict[Any, Any]", records).get(identity.agent_id, [])
        for record in cast("list[Any]", own):
            if str(record.key_id) == key_id:
                return cast("bytes", record.public_key)
    return cast("bytes", identity.public_key)


# ---------------------------------------------------------------------------
# Admission policy and result
# ---------------------------------------------------------------------------


@dataclass
class AdmissionPolicy:
    """What an admitting trust domain requires of a presented credential.

    ``require_recomputation=False`` is the *naive gate*: it trusts the signed
    claims (proof and freshness still checked) and skips root/score
    recomputation and published-ledger severance. It exists so scenarios can
    demonstrate exactly which attacks recomputation stops — the adversarial
    validators FAIL under the naive gate and PASS under the default.

    Example::

        policy = AdmissionPolicy(trusted_issuers={"did:nest:auditor-a"},
                                 min_reputation_score=0.2)
    """

    trusted_issuers: set[str] = field(default_factory=set[str])
    min_reputation_score: float = 0.0
    max_age_ticks: float | None = None
    max_ledger_receipts: int | None = None
    score_tolerance: float = 1e-6
    require_recomputation: bool = True
    require_published_ledger: bool = False


@dataclass
class AdmissionResult:
    """The outcome of one admission decision: a verdict and a typed reason.

    ``reason`` is ``"admitted"`` on success, else one of the snake_case
    rejection reasons (``schema_invalid``, ``wrong_scoring_method``,
    ``untrusted_issuer``, ``replay_presenter_mismatch``, ``stale_credential``,
    ``proof_invalid``, ``stale_key``, ``ledger_too_large``,
    ``foreign_receipts``, ``root_mismatch``, ``score_mismatch``,
    ``below_threshold``, ``published_ledger_missing``,
    ``severed_below_threshold``). Validators key on these strings.

    Example::

        result = AdmissionResult(admitted=True, reason="admitted")
    """

    admitted: bool
    reason: str
    recomputed_score: float | None = None
    detail: str = ""


@dataclass(frozen=True)
class DisclosureResult:
    """The outcome of verifying one selective-disclosure presentation.

    ``ok`` is True iff the credential's proof verified and every disclosed
    receipt checked out. ``reasons`` is empty on success, else the ordered,
    de-duplicated snake_case failures (``malformed_presentation``,
    ``issuer_mismatch``, ``bad_credential_proof``, ``malformed_proof``,
    ``count_mismatch``, ``not_included``). Frozen — a verification verdict is
    evidence, not a scratchpad.

    Example::

        result = DisclosureResult(ok=True)
    """

    ok: bool
    reasons: tuple[str, ...] = ()
    detail: str = ""


def _disclosed_entry_reasons(entry: Any, *, root: str, receipt_count: int) -> list[str]:
    """The typed failures of one disclosed ``{"receipt", "proof"}`` entry.

    The two substantive checks are evaluated independently rather than
    short-circuited, so a receipt from a foreign ledger still reports
    ``not_included`` even when its ``leaf_count`` also lies.

    Example::

        reasons = _disclosed_entry_reasons(entry, root=root, receipt_count=2)
    """
    if not isinstance(entry, dict):
        return ["malformed_presentation"]
    entry_typed = cast("dict[str, Any]", entry)
    receipt = entry_typed.get("receipt")
    proof = entry_typed.get("proof")
    if not isinstance(receipt, dict) or not isinstance(proof, dict):
        return ["malformed_presentation"]
    receipt_typed = cast("dict[str, Any]", receipt)
    proof_typed = cast("dict[str, Any]", proof)
    leaf_index = proof_typed.get("leaf_index")
    leaf_count = proof_typed.get("leaf_count")
    if (
        not isinstance(leaf_index, int)
        or not isinstance(leaf_count, int)
        or not isinstance(proof_typed.get("path"), list)
        or not 0 <= leaf_index < leaf_count
    ):
        return ["malformed_proof"]
    reasons: list[str] = []
    if leaf_count != receipt_count:
        reasons.append("count_mismatch")
    if not verify_inclusion(receipt_typed, proof_typed, root):
        reasons.append("not_included")
    return reasons


# ---------------------------------------------------------------------------
# The trust plugin
# ---------------------------------------------------------------------------


class ParcTrust(ar.AgentReceiptsTrust):
    """Portable-reputation trust plugin implementing the ``Trust`` Protocol.

    Inherits the full receipt-reputation behavior of ``agent_receipts``
    (``report``/``score``/``attest``/``stake``, corroboration gates, collusion
    severance) and adds the portability surface: credential export, admission
    with recomputation, and published-ledger severance. The constructor stays
    no-arg-callable for the NEST runner.

    Example::

        trust = ParcTrust()
        vc = await trust.build_credential(subject, identity=ident, valid_from=6.0)
    """

    def __init__(self, identity: Any = None) -> None:
        super().__init__(identity)
        # The originating domain's community ledger, if one was published to
        # this gate. Whole-graph severance for admissions runs over this.
        self._published_ledger: list[dict[str, Any]] = []

    # -- export ------------------------------------------------------------

    async def build_credential(
        self,
        subject: AgentId,
        *,
        identity: Any,
        valid_from: float,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """Export ``subject``'s reputation as a signed, portable credential.

        Collects the subject's receipts from this plugin's ledger (sorted by
        ``receipt_id`` for determinism), commits to them with a Merkle root,
        embeds the inline-recomputable ``nanda-rep/0.2`` scores as fixed
        6-decimal strings, and signs the canonical document through the
        identity layer. ``valid_from`` is the logical tick the credential is
        anchored to — verifiers enforce the signing key's rotation window
        as-of this tick. ``key_id`` selects a specific (possibly rotated-out)
        signing key and exists for adversarial scenarios, mirroring
        ``Ed25519RotatingIdentity.sign_with``.

        Example::

            vc = await trust.build_credential(AgentId("a1"), identity=ident,
                                              valid_from=6.0)
        """
        did = self._did_of(subject)
        receipts = sorted(
            (r for r in self._ledger if str(r.get("issuer_did", "")) == did),
            key=lambda r: str(r.get("receipt_id", "")),
        )
        score, validity_rate, corroboration_rate = _inline_scores(receipts)
        credential: dict[str, Any] = {
            "@context": [CREDENTIAL_CONTEXT],
            "type": ["VerifiableCredential", CREDENTIAL_TYPE],
            "issuer": f"{ISSUER_URI_PREFIX}{identity.agent_id}",
            "validFrom": valid_from,
            "credentialSubject": {
                "id": did,
                "behavioral_merkle_root": merkle_root(receipts),
                "scoring_method": SCORING_METHOD,
                "reputation_score": _fmt6(score),
                "validity_rate": _fmt6(validity_rate),
                "corroboration_rate": _fmt6(corroboration_rate),
                "receipt_count": len(receipts),
                "as_of": valid_from,
                "receipts": receipts,
            },
        }
        return attach_proof(credential, identity=identity, key_id=key_id)

    # -- published-ledger ingestion -----------------------------------------

    def ingest_published_ledger(self, receipts: list[dict[str, Any]]) -> int:
        """Ingest an originating domain's published community ledger.

        Stores the receipts for whole-graph collusion severance at admission
        time. Only receipts that verify enter (a hostile publisher cannot
        smuggle unverifiable edges into the severance graph). Replaces any
        previously published ledger; returns the number retained.

        Example::

            kept = gate.ingest_published_ledger(ledger)
        """
        self._published_ledger = [r for r in receipts if ar._verify_receipt(r)]
        return len(self._published_ledger)

    # -- admission -----------------------------------------------------------

    async def admit(
        self,
        credential: dict[str, Any],
        *,
        policy: AdmissionPolicy,
        presenter_did: str,
        identity: Any,
        current_tick: float,
    ) -> AdmissionResult:
        """Decide admission for a presented credential under ``policy``.

        Gates run in order, each with a typed rejection reason: schema →
        scoring method → trusted issuer → presenter binding (the presenter
        must *be* the credential subject — anyone else replaying a stolen
        credential is rejected) → freshness → proof (Ed25519 under the
        issuer's identity-layer key, with the key's rotation window enforced
        **as-of** ``validFrom``) → ledger size → subject binding of carried
        receipts → Merkle-root recomputation → score recomputation →
        threshold → published-ledger severance. The proof gate distinguishes
        ``proof_invalid`` (bad bytes/unknown key) from ``stale_key`` (genuine
        signature, but the key's validity window does not contain
        ``validFrom``).

        Example::

            result = await gate.admit(vc, policy=policy, presenter_did=did,
                                      identity=gate_ident, current_tick=6.0)
        """
        parsed = _parse_credential(credential)
        if parsed is None:
            return AdmissionResult(False, "schema_invalid")
        issuer, valid_from, subject = parsed

        if subject.get("scoring_method") != SCORING_METHOD:
            return AdmissionResult(
                False,
                "wrong_scoring_method",
                detail=str(subject.get("scoring_method")),
            )
        if issuer not in policy.trusted_issuers:
            return AdmissionResult(False, "untrusted_issuer", detail=issuer)
        subject_did = str(subject["id"])
        if subject_did != presenter_did:
            return AdmissionResult(False, "replay_presenter_mismatch")
        if policy.max_age_ticks is not None and current_tick - valid_from > policy.max_age_ticks:
            return AdmissionResult(False, "stale_credential")

        proof_reason = await self._verify_proof(credential, issuer, valid_from, identity)
        if proof_reason is not None:
            return AdmissionResult(False, proof_reason)

        receipts = cast("list[dict[str, Any]]", subject["receipts"])
        if policy.max_ledger_receipts is not None and len(receipts) > policy.max_ledger_receipts:
            return AdmissionResult(False, "ledger_too_large")

        claimed_score = float(str(subject["reputation_score"]))
        score = claimed_score
        if policy.require_recomputation:
            if any(str(r.get("issuer_did", "")) != subject_did for r in receipts):
                return AdmissionResult(False, "foreign_receipts")
            if merkle_root(receipts) != subject["behavioral_merkle_root"]:
                return AdmissionResult(False, "root_mismatch")
            recomputed, validity_rate, corroboration_rate = _inline_scores(receipts)
            mismatches = [
                name
                for name, claimed_raw, actual in (
                    ("reputation_score", subject["reputation_score"], recomputed),
                    ("validity_rate", subject["validity_rate"], validity_rate),
                    ("corroboration_rate", subject["corroboration_rate"], corroboration_rate),
                )
                if abs(float(str(claimed_raw)) - actual) > policy.score_tolerance
            ]
            if int(subject["receipt_count"]) != len(receipts):
                mismatches.append("receipt_count")
            if mismatches:
                return AdmissionResult(
                    False,
                    "score_mismatch",
                    recomputed_score=recomputed,
                    detail=",".join(mismatches),
                )
            score = recomputed

        if score < policy.min_reputation_score:
            return AdmissionResult(False, "below_threshold", recomputed_score=score)

        if policy.require_recomputation and policy.require_published_ledger:
            if not self._published_ledger:
                return AdmissionResult(False, "published_ledger_missing")
            severed = ar._severed_dids(ar._corroboration_graph(self._published_ledger))
            if subject_did in severed:
                return AdmissionResult(
                    False,
                    "severed_below_threshold",
                    recomputed_score=0.0,
                    detail="subject severed by whole-graph collusion analysis",
                )

        return AdmissionResult(True, "admitted", recomputed_score=score)

    async def _verify_proof(
        self,
        credential: dict[str, Any],
        issuer: str,
        valid_from: float,
        identity: Any,
    ) -> str | None:
        """Verify the credential proof; ``None`` on success, else a reason.

        Resolves the issuer through the identity layer, binds the proof to the
        exact key named by its ``verificationMethod`` fragment, cross-checks
        the embedded ``did:key`` against that key's actual bytes, verifies the
        Ed25519 signature, and finally enforces the key's rotation window
        as-of ``validFrom``. Window data comes from
        ``AgentIdentity.metadata["keys"]`` (the ``ed25519_rotating`` history);
        an identity plugin without key history degrades to a single
        always-valid key.

        Example::

            reason = await gate._verify_proof(vc, issuer, 6.0, gate_ident)
        """
        proof = credential.get("proof")
        if not isinstance(proof, dict):
            return "proof_invalid"
        proof_typed = cast("dict[str, Any]", proof)
        method = str(proof_typed.get("verificationMethod", ""))
        did_part, _, key_id = method.partition("#")
        if not did_part or not key_id:
            return "proof_invalid"

        issuer_agent = AgentId(issuer.removeprefix(ISSUER_URI_PREFIX))
        resolved = await identity.resolve(issuer_agent)
        keys = resolved.metadata.get("keys")
        if not isinstance(keys, list):
            keys = [
                {
                    "key_id": hashlib.sha256(resolved.public_key).hexdigest(),
                    "public_key": resolved.public_key.hex(),
                    "issued_at": 0.0,
                    "rotated_out": None,
                }
            ]
        record = next(
            (
                cast("dict[str, Any]", k)
                for k in cast("list[Any]", keys)
                if isinstance(k, dict) and str(cast("dict[str, Any]", k).get("key_id")) == key_id
            ),
            None,
        )
        if record is None:
            return "proof_invalid"
        pub = bytes.fromhex(str(record["public_key"]))
        if did_key_for_pubkey(pub) != did_part:
            return "proof_invalid"
        try:
            sig = bytes.fromhex(str(proof_typed.get("proofValue", "")))
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, credential_payload(credential))
        except (InvalidSignature, ValueError, TypeError):
            return "proof_invalid"

        issued_at = float(record.get("issued_at", 0.0))
        rotated_out_raw = record.get("rotated_out")
        rotated_out = float("inf") if rotated_out_raw is None else float(str(rotated_out_raw))
        if not (issued_at <= valid_from < rotated_out):
            return "stale_key"
        return None

    # -- selective disclosure -------------------------------------------------

    def build_presentation(
        self,
        credential: dict[str, Any],
        receipts: list[dict[str, Any]],
        *,
        disclose: Iterable[str],
    ) -> dict[str, Any]:
        """Package ``credential`` plus inclusion proofs for the chosen receipts.

        ``disclose`` names receipts by ``receipt_id``; ``receipts`` is the
        holder's full ledger — the one the credential's
        ``behavioral_merkle_root`` commits to. The prover needs every leaf to
        build a path; the verifier needs none of them. Disclosed entries are
        sorted by ``receipt_id``, so identical inputs yield a byte-identical
        presentation. Raises ``ValueError`` for a ``receipt_id`` not in
        ``receipts`` (see :func:`inclusion_proof`).

        Example::

            pres = trust.build_presentation(vc, receipts, disclose=["r1", "r7"])
        """
        by_id = {str(r.get("receipt_id", "")): r for r in receipts}
        disclosed: list[dict[str, Any]] = []
        for receipt_id in sorted(set(disclose)):
            receipt = by_id.get(receipt_id)
            if receipt is None:
                raise ValueError(f"receipt {receipt_id!r} is not present in the ledger")
            disclosed.append(
                {"receipt": receipt, "proof": inclusion_proof(receipts, receipt=receipt)}
            )
        return {"credential": credential, "disclosed": disclosed}

    async def verify_presentation(
        self,
        presentation: dict[str, Any],
        *,
        identity: Any,
        expected_issuer: str | None = None,
    ) -> DisclosureResult:
        """Verify a selective-disclosure presentation; no score is recomputed.

        Gates, each with a typed reason: the presentation and its credential
        parse (``malformed_presentation``) → the issuer matches
        ``expected_issuer`` when one is required (``issuer_mismatch``) → the
        credential's Ed25519 proof verifies through the SAME identity-layer
        path as :meth:`admit`, key-rotation window enforced as-of
        ``validFrom`` — a forged signature or a rotated-out signing key fails
        here exactly as it would at admission (``bad_credential_proof``, the
        underlying ``proof_invalid``/``stale_key`` in ``detail``). Then, per
        disclosed receipt (failures accumulated across entries): the proof is
        well-formed (``malformed_proof``), its ``leaf_count`` equals the
        signed ``receipt_count`` — the signed bound on the undisclosed
        remainder (``count_mismatch``) — and the receipt folds to the signed
        ``behavioral_merkle_root`` (``not_included``).

        Deliberately absent: score recomputation. Disclosure proves *which
        receipts happened* under the signed commitment; the reputation
        aggregate is a whole-graph property, so the signed score stands and a
        disclosed subset is never grounds to re-derive or adjust it. That is
        :meth:`admit`'s job, with the full ledger.

        Example::

            result = await gate.verify_presentation(pres, identity=gate_ident)
        """
        credential = presentation.get("credential")
        disclosed = presentation.get("disclosed")
        if not isinstance(credential, dict) or not isinstance(disclosed, list):
            return DisclosureResult(False, ("malformed_presentation",))
        credential_typed = cast("dict[str, Any]", credential)
        parsed = _parse_credential(credential_typed)
        if parsed is None:
            return DisclosureResult(
                False, ("malformed_presentation",), detail="credential failed to parse"
            )
        issuer, valid_from, subject = parsed
        if expected_issuer is not None and issuer != expected_issuer:
            return DisclosureResult(False, ("issuer_mismatch",), detail=issuer)
        if not isinstance(subject["receipt_count"], int):
            return DisclosureResult(
                False, ("malformed_presentation",), detail="receipt_count not an int"
            )

        proof_reason = await self._verify_proof(credential_typed, issuer, valid_from, identity)
        if proof_reason is not None:
            return DisclosureResult(False, ("bad_credential_proof",), detail=proof_reason)

        root = str(subject["behavioral_merkle_root"])
        receipt_count = int(subject["receipt_count"])
        reasons: list[str] = []
        for entry in cast("list[Any]", disclosed):
            for reason in _disclosed_entry_reasons(entry, root=root, receipt_count=receipt_count):
                if reason not in reasons:
                    reasons.append(reason)
        if reasons:
            return DisclosureResult(False, tuple(reasons))
        return DisclosureResult(True)


def _parse_credential(
    credential: dict[str, Any],
) -> tuple[str, float, dict[str, Any]] | None:
    """Extract ``(issuer, validFrom, credentialSubject)``; ``None`` if malformed.

    Checks the structural shape only — types of the required fields and the
    ``ParcReputationCredential`` type marker. Cryptographic and semantic gates
    run afterwards in :meth:`ParcTrust.admit`.

    Example::

        parsed = _parse_credential(vc)
    """
    types = credential.get("type")
    if not isinstance(types, list) or CREDENTIAL_TYPE not in cast("list[Any]", types):
        return None
    issuer = credential.get("issuer")
    valid_from = credential.get("validFrom")
    subject = credential.get("credentialSubject")
    if not isinstance(issuer, str) or not issuer.startswith(ISSUER_URI_PREFIX):
        return None
    if not isinstance(valid_from, int | float):
        return None
    if not isinstance(subject, dict):
        return None
    subject_typed = cast("dict[str, Any]", subject)
    required = (
        "id",
        "behavioral_merkle_root",
        "scoring_method",
        "reputation_score",
        "validity_rate",
        "corroboration_rate",
        "receipt_count",
        "receipts",
    )
    if any(key not in subject_typed for key in required):
        return None
    if not isinstance(subject_typed["receipts"], list):
        return None
    return str(issuer), float(valid_from), subject_typed
