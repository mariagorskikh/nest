# SPDX-License-Identifier: Apache-2.0
"""Interview-evaluation DataFacts: content addressing + audience ACLs + pre-hash PII redaction.

This plugin is written by an **interview-integrity engineer**. It models the
delivery pipeline of a technical-*screening* service that sits at the front of a
client's hiring funnel: a human interviewer conducts a recorded screening
interview off-protocol, then publishes a signed *evaluation* — a ``PASSED`` /
``FAILED`` verdict plus a detailed report drawn from the interview recording —
that the service delivers to the company that posted the job. The service only
filters; candidates who pass go on to the client's own rounds. Every verdict is
bound to the recording it came from, so nothing is fabricated.

It builds *on top of* the already-merged content-addressed plugin
(:class:`~nest_plugins_reference.datafacts.cid_facts.CidFacts`) rather than
re-implementing it. ``CidFacts`` already gives us the three properties Problem 08
asks for — content-addressed URLs, a ``parents`` provenance DAG, and
identity-signed freshness proofs. Re-deriving those would be duplicate work.
Instead :class:`OghaFacts` **subclasses** it and adds the two things an
evaluation-delivery pipeline needs that content-addressing alone does not
provide, both explicitly called out as unclaimed on the ``datafacts`` layer
wishlist (*"fine-grained ACLs"*, redaction):

1. **Fine-grained, audience-scoped ACLs.** ``CidFacts.request_access`` is
   binary: the owner (or ``access_tier == "public"``) gets ``read``, everyone
   else is hard-denied with ``PermissionError``. That is wrong for an
   evaluation: the interview verdict is *private*, but it legitimately has more
   than one authorized reader — the interviewer who wrote it, the service that
   brokered it, the **company that posted the job**, and the **candidate**
   themselves. Every *other* company must be able to see that a record exists
   (metadata, provenance) without ever reading the verdict. :meth:`OghaFacts.request_access`
   therefore returns a ``read`` grant to the audience listed in the dataset's
   content-bound ACL and a ``metadata``-tier grant (never a hard denial) to
   anyone else — fail-*closed* on content, fail-*open* on existence.

2. **Pre-hash PII redaction.** A content hash is permanent: once a candidate's
   home address, SSN, salary history, or date of birth is folded into the hash
   and the URL is handed out, it can never be unpublished without breaking every
   provenance link that points at it. So redaction has to happen **before**
   hashing, not after. :meth:`OghaFacts.publish` scrubs the free-text fields of
   every dataset through :func:`redact_pii` *before* delegating to
   ``CidFacts.publish``, so raw PII is never what gets content-addressed. This
   mirrors the production ``PiiDetectionGuardrail`` the author already runs in
   front of their candidate-facing agents, re-expressed as pure-Python regexes so
   Tier 1 stays deterministic.

It also tightens one inherited behaviour: :meth:`OghaFacts.verify_freshness`
anchors signature verification **as-of the tick the proof was signed at**, not
the current clock. That is what lets a verdict signed by an interviewer whose
key has since *rotated* (they left the panel; the key was cycled) still verify,
while a post-rotation forgery with the stale key does not — composing the
as-of semantics of
:class:`~nest_plugins_reference.identity.ed25519_rotating.Ed25519RotatingIdentity`.
Against a non-rotating identity (``did_key``) it degrades to the inherited
behaviour.

Example::

    from nest_plugins_reference.identity.did_key import DidKeyIdentity

    interviewer = DidKeyIdentity(AgentId("interviewer-7"), seed=b"sim-seed")
    facts = OghaFacts(interviewer)
    recording = await facts.publish(DatasetMetadata(name="rec", owner=AgentId("interviewer-7")))
    ds = evaluation_dataset(
        interviewer=AgentId("interviewer-7"),
        candidate_id="cand_a", job_id="job_42",
        company_id="acme", ogha_id="ogha",
        verdict=VERDICT_PASSED,
        report="Cleared system design. Reachable at cand@example.com, SSN 123-45-6789.",
        interview_recording=recording,
    )
    url = await facts.publish(ds)                 # e-mail + SSN scrubbed pre-hash
    grant = await facts.request_access(url, AgentId("acme"))   # tier == "read"
    leak = await facts.request_access(url, AgentId("rival"))   # tier == "metadata"
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, cast

from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata

from nest_plugins_reference.datafacts.cid_facts import (
    CidFacts,
    FreshnessProof,
    SharedClock,
)

if TYPE_CHECKING:
    from nest_core.layers.identity import Identity


def _freshness_payload(url: DataFactsUrl, tick: float) -> bytes:
    """Canonical bytes a freshness proof signs — must match ``cid_facts`` exactly.

    Re-declared here (rather than importing the parent's private helper) so the
    signed payload stays byte-identical to what ``CidFacts.publish`` produced,
    while :meth:`OghaFacts._verify_as_of` can re-anchor the verification tick.

    Example::

        payload = _freshness_payload(DataFactsUrl("df://sha256-x"), 3.0)
    """
    return json.dumps(
        {"url": str(url), "tick": tick}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------

VERDICT_PASSED = "PASSED"
"""The candidate cleared the screening interview and advances to the client's rounds.

Example::

    assert VERDICT_PASSED in VERDICTS
"""

VERDICT_FAILED = "FAILED"
"""The candidate did not clear the screening interview.

Example::

    assert VERDICT_FAILED in VERDICTS
"""

VERDICTS = frozenset({VERDICT_PASSED, VERDICT_FAILED})
"""The only two verdicts a screening evaluation may carry.

OGHA is the *screening* interface at the front of the funnel — it filters
candidates, it does not make hiring decisions (that is the client's call in
later rounds). So the verdict is strictly binary: ``PASSED`` or ``FAILED``.
A verdict outside this set is not a valid screening result; see
:func:`evaluation_dataset`, which refuses to build one.

Example::

    assert VERDICTS == {"PASSED", "FAILED"}
"""


# ---------------------------------------------------------------------------
# PII redaction (ported from the production PiiDetectionGuardrail)
# ---------------------------------------------------------------------------

# Ordered longest/most-specific first so a broad pattern (phone) never eats a
# more specific one (SSN) that shares its digit shape. Each match is replaced
# with a stable ``[REDACTED-<CATEGORY>]`` token, so redacting already-redacted
# text is a no-op (keeps :meth:`OghaFacts.publish` idempotent on clean input).
_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CARD", re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("SALARY", re.compile(r"\$\s?\d{1,3}(?:,\d{3})+(?:\.\d{2})?\b|\$\s?\d+[kK]\b")),
    ("DOB", re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/(?:19|20)\d{2}\b")),
)


def scan_pii(text: str) -> dict[str, int]:
    """Count personally-identifying tokens in ``text`` by category, without mutating it.

    Returns a mapping such as ``{"SSN": 1, "EMAIL": 2}`` containing only the
    categories that actually matched. An empty dict means "no PII found". The
    scan is deterministic (pure regex; no RNG, no clock), so a validator can
    read the count out of a trace and reproduce it exactly.

    Example::

        assert scan_pii("call 555-123-4567 or a@b.com") == {"PHONE": 1, "EMAIL": 1}
        assert scan_pii("clean text") == {}
    """
    counts: dict[str, int] = {}
    for category, pattern in _PII_PATTERNS:
        n = len(pattern.findall(text))
        if n:
            counts[category] = n
    return counts


def redact_pii(text: str) -> tuple[str, dict[str, int]]:
    """Return ``(redacted_text, counts)`` with every PII token replaced by a marker.

    Applies the full :data:`_PII_PATTERNS` set repeatedly until a whole pass
    makes no replacement (a fixpoint). One pass is not enough in the worst case:
    two tokens jammed together with no separator (``"...6789123-45-6789"``) only
    become boundary-visible after the first is removed. Iterating guarantees the
    post-condition ``scan_pii(redact_pii(t)[0]) == {}`` — nothing the scanner can
    see survives — which is exactly what must hold before content-hashing. The
    ``[REDACTED-*]`` markers contain no PII, so the loop is monotone and
    terminates; on already-clean text it is a no-op.

    Example::

        red, counts = redact_pii("SSN 123-45-6789")
        assert red == "SSN [REDACTED-SSN]" and counts == {"SSN": 1}
    """
    counts: dict[str, int] = {}
    out = text
    changed = True
    while changed:
        changed = False
        for category, pattern in _PII_PATTERNS:
            out, n = pattern.subn(f"[REDACTED-{category}]", out)
            if n:
                counts[category] = counts.get(category, 0) + n
                changed = True
    return out, counts


# Free-text fields of a :class:`DatasetMetadata` that may carry candidate PII.
_REDACTED_TEXT_KEYS = ("report", "notes")


def _redact_dataset(dataset: DatasetMetadata) -> tuple[DatasetMetadata, dict[str, int]]:
    """Redact PII from a dataset's ``description`` and free-text ``metadata`` fields.

    Returns a *copy* with the scrubbed fields plus the aggregate redaction
    counts. The original object is never mutated. Only string metadata values
    under :data:`_REDACTED_TEXT_KEYS` are touched — structured fields
    (``scores``, ``acl``, ``parents``) are left alone.

    Example::

        clean, counts = _redact_dataset(raw_eval_dataset)
    """
    total: dict[str, int] = {}

    def _accumulate(part: dict[str, int]) -> None:
        for k, v in part.items():
            total[k] = total.get(k, 0) + v

    new_description, dcounts = redact_pii(dataset.description)
    _accumulate(dcounts)

    new_metadata = dict(dataset.metadata)
    for key in _REDACTED_TEXT_KEYS:
        value = new_metadata.get(key)
        if isinstance(value, str):
            redacted, counts = redact_pii(value)
            new_metadata[key] = redacted
            _accumulate(counts)

    scrubbed = dataset.model_copy(update={"description": new_description, "metadata": new_metadata})
    return scrubbed, total


# ---------------------------------------------------------------------------
# Evaluation dataset construction
# ---------------------------------------------------------------------------


def evaluation_dataset(
    *,
    interviewer: AgentId,
    candidate_id: str,
    job_id: str,
    company_id: str,
    ogha_id: str,
    verdict: str,
    report: str,
    interview_recording: DataFactsUrl,
    scores: dict[str, int] | None = None,
) -> DatasetMetadata:
    """Build the :class:`DatasetMetadata` for one screening evaluation.

    Every field a client relies on — the ``verdict`` (``PASSED``/``FAILED``),
    the interviewer's ``report``, the competency ``scores``, and the reference
    to the ``interview_recording`` the report is drawn from — is placed in
    ``metadata`` so it is covered by the content hash; a single byte changing
    the verdict changes the URL.

    Two invariants enforce *"nothing is fabricated"*:

    * The verdict must be a member of :data:`VERDICTS`; anything else raises
      ``ValueError`` (a screening result is ``PASSED`` or ``FAILED``, never a
      free-form claim).
    * ``interview_recording`` is recorded **and** listed as the sole provenance
      parent, so the evaluation is cryptographically bound to the recorded
      interview it derives from. :meth:`OghaFacts.publish` refuses to publish an
      evaluation whose recording was never itself published — there is no
      verdict without a real interview behind it.

    The ``acl`` (interviewer, service, posting company, candidate) is part of
    the hashed content, so *who may read a verdict* cannot change without minting
    a new URL. ``access_tier`` is ``"restricted"``, which makes
    :meth:`OghaFacts.request_access` enforce that ACL.

    Example::

        ds = evaluation_dataset(
            interviewer=AgentId("iv-1"), candidate_id="cand_a", job_id="job_42",
            company_id="acme", ogha_id="ogha", verdict=VERDICT_PASSED,
            report="Cleared system design.", interview_recording=recording_url)
        assert ds.metadata["verdict"] == "PASSED"
    """
    if verdict not in VERDICTS:
        msg = f"verdict must be one of {sorted(VERDICTS)}, not {verdict!r}"
        raise ValueError(msg)
    metadata: dict[str, Any] = {
        "kind": "screening_evaluation",
        "candidate_id": candidate_id,
        "job_id": job_id,
        "company_id": company_id,
        "verdict": verdict,
        "report": report,
        "interview_recording": str(interview_recording),
        "scores": dict(scores) if scores else {},
        "acl": sorted({str(interviewer), ogha_id, company_id, candidate_id}),
        "parents": [str(interview_recording)],
    }
    return DatasetMetadata(
        name=f"eval-{candidate_id}-{job_id}",
        owner=interviewer,
        description=f"Screening evaluation for {candidate_id} on {job_id}",
        access_tier="restricted",
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class OghaFacts(CidFacts):
    """Content-addressed DataFacts with audience ACLs and pre-hash PII redaction.

    Drop-in for the ``datafacts`` layer. Inherits content addressing, the
    ``parents`` provenance DAG, and signed freshness from
    :class:`~nest_plugins_reference.datafacts.cid_facts.CidFacts`; overrides
    :meth:`publish` (redact first), :meth:`request_access` (audience ACL), and
    :meth:`verify_freshness` (as-of verification).

    Example::

        facts = OghaFacts(DidKeyIdentity(AgentId("iv-1"), seed=b"s"))
        rec = await facts.publish(DatasetMetadata(name="rec", owner=AgentId("iv-1")))
        url = await facts.publish(evaluation_dataset(
            interviewer=AgentId("iv-1"), candidate_id="c", job_id="j",
            company_id="acme", ogha_id="ogha", verdict=VERDICT_PASSED,
            report="ok", interview_recording=rec))
    """

    def __init__(
        self,
        identity: Identity,
        *,
        datasets: dict[DataFactsUrl, DatasetMetadata] | None = None,
        proofs: dict[DataFactsUrl, FreshnessProof] | None = None,
        clock: SharedClock | None = None,
        freshness_window: float = 1.0,
    ) -> None:
        super().__init__(
            identity,
            datasets=datasets,
            proofs=proofs,
            clock=clock,
            freshness_window=freshness_window,
        )

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Redact PII, then content-address and sign like :class:`CidFacts`.

        Redaction runs *before* the content hash is computed, so raw PII is
        never what the permanent URL commits to. Because redaction is
        idempotent, republishing byte-identical raw input is still idempotent
        (same URL). Provenance and freshness behave exactly as inherited —
        a phantom ``parents`` entry still raises
        :class:`~nest_plugins_reference.datafacts.cid_facts.ProvenanceError`.

        Example::

            url = await facts.publish(raw_eval_with_pii)   # stored copy is scrubbed
        """
        scrubbed, _counts = _redact_dataset(dataset)
        return await super().publish(scrubbed)

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        """Grant ``read`` to the dataset's audience, ``metadata`` to everyone else.

        Unlike the inherited binary owner-or-public check (which raises
        ``PermissionError`` for outsiders), this fails *closed on content* but
        *open on existence*: an unauthorized requester still receives a valid
        grant, at ``tier="metadata"``, so they can audit that a record exists
        and trace its provenance without ever reading the private verdict. A
        ``public`` dataset grants ``read`` to all; the owner always gets
        ``read``.

        Example::

            assert (await facts.request_access(url, poster)).tier == "read"
            assert (await facts.request_access(url, rival)).tier == "metadata"
        """
        meta = await self.fetch(url)
        tier = "read" if self._is_authorized(meta, requester) else "metadata"
        grant = AccessGrant(url=url, grantee=requester, tier=tier)
        self._grants.setdefault(url, []).append(grant)
        return grant

    @staticmethod
    def _is_authorized(meta: DatasetMetadata, requester: AgentId) -> bool:
        """Whether ``requester`` may read ``meta``'s content (owner, public, or ACL)."""
        if meta.access_tier == "public":
            return True
        if requester == meta.owner:
            return True
        acl = meta.metadata.get("acl", [])
        if not isinstance(acl, list):
            return False
        return str(requester) in {str(entry) for entry in cast("list[Any]", acl)}

    def access_tier_for(self, meta: DatasetMetadata, requester: AgentId) -> str:
        """Return the tier (``"read"``/``"metadata"``) ``requester`` would receive.

        A pure, side-effect-free view of the ACL decision (no grant is
        recorded), handy for scenario agents that want to report the decision
        into the trace.

        Example::

            tier = facts.access_tier_for(meta, AgentId("rival"))
        """
        return "read" if self._is_authorized(meta, requester) else "metadata"

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """Verify the freshness proof *as-of the tick it was signed at*.

        Fails closed exactly like the parent (no proof, wrong signer, or a proof
        older than the freshness window is not fresh). The one difference:
        signature verification is anchored to ``proof.tick`` rather than the
        current clock. Against a rotating identity that means a verdict signed
        by a key that has *since* rotated still verifies (the key was valid when
        it signed), while a post-rotation forgery with the retired key fails its
        as-of window check. Against a non-rotating identity whose ``verify`` has
        no ``as_of`` parameter, this transparently falls back to the inherited
        behaviour.

        Example::

            assert await facts.verify_freshness(url) is True
        """
        meta = self._datasets.get(url)
        proof = self._proofs.get(url)
        if meta is None or proof is None:
            return False
        if proof.signature.signer != meta.owner:
            return False
        if not self._verify_as_of(proof, meta.owner):
            return False
        return (self._clock.tick - proof.tick) <= self._freshness_window

    def _verify_as_of(self, proof: FreshnessProof, owner: AgentId) -> bool:
        """Verify ``proof``'s signature anchored to ``proof.tick`` when supported."""
        payload = _freshness_payload(proof.url, proof.tick)
        try:
            return bool(
                self._identity.verify(payload, proof.signature, owner, as_of=proof.tick)  # type: ignore[call-arg]
            )
        except TypeError:
            return bool(self._identity.verify(payload, proof.signature, owner))
