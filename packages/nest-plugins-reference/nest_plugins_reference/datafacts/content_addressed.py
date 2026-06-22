# SPDX-License-Identifier: Apache-2.0
"""Content-addressed DataFacts plugin with provenance chains and signed freshness proofs.

Persona: ``provenance-engineer``. This plugin replaces the default
``datafacts_v1`` registry — which addresses datasets by *publisher-chosen name*
(``df://<name>``), grants access to anyone, and "proves" freshness with a bare
``time.time()`` comparison — with a design where **the address is the content**
and **every freshness claim is a signature, not a timestamp**.

Three classes of provenance attack that are silently undetectable under
``datafacts_v1`` become *impossible by construction* or *cryptographically
caught* here:

* **Substitution** — republishing different bytes under an existing address.
  Impossible: the URL is ``df://sha256-<hex>`` derived from the canonical
  content, so different content is a different URL. You cannot overwrite.
* **Stale-freshness** — claiming a dataset is current by re-touching a clock
  without re-publishing. Caught: freshness is a :class:`FreshnessProof` signed
  by the publisher's identity-layer key binding *(content-hash, tick, signer)*.
  A publisher who issues no fresh signature has no valid proof.
* **Broken provenance** — a derived dataset whose ancestry references a hash
  that was never published. Caught: ``parents`` are folded into the child's
  content hash (a Merkle-DAG), and :meth:`verify_provenance` rejects any
  dangling parent.

The plugin implements the :class:`~nest_core.layers.datafacts.DataFacts`
protocol exactly (``publish`` / ``fetch`` / ``request_access`` /
``verify_freshness``). The signed-proof machinery is exposed through *additional*
methods (:meth:`issue_freshness_proof`, :meth:`verify_freshness_proof`,
:meth:`content_id`, :meth:`verify_provenance`) so the base protocol surface is
unchanged and drop-in compatible.

Determinism: content hashing is pure ``sha256`` over canonical JSON, and the
logical "now" is the simulator tick set via :meth:`set_clock` — never wall
time — so the same seed yields byte-identical URLs and proofs.

Example::

    from nest_plugins_reference.identity.did_key import DidKeyIdentity
    from nest_core.types import AgentId, DatasetMetadata

    ident = DidKeyIdentity(AgentId("a1"), seed=b"seed")
    df = ContentAddressedDataFacts(identity=ident)
    url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
    assert url.startswith("df://sha256-")
    assert await df.verify_freshness(url)  # a signed proof was issued on publish
"""

from __future__ import annotations

import hashlib
import json
from typing import Protocol, runtime_checkable

from nest_core.types import (
    AccessGrant,
    AgentId,
    DataFactsUrl,
    DatasetMetadata,
    Signature,
)
from pydantic import BaseModel

# Fields excluded from the content hash. ``created_at`` / ``updated_at`` are
# wall-clock-ish and would break the "same content -> same address" invariant;
# ``parents`` is hashed separately (see ``_content_digest``) so the Merkle
# structure is explicit rather than buried in a dict ordering.
_VOLATILE_FIELDS = frozenset({"created_at", "updated_at"})

_HASH_PREFIX = "sha256-"
_URL_SCHEME = "df://"


@runtime_checkable
class SigningIdentity(Protocol):
    """Structural type for the identity-layer instance the plugin signs with.

    Any object exposing the reference identity surface (``did_key``,
    ``ed25519_rotating``) satisfies this without an explicit import, so the
    datafacts plugin stays decoupled from a concrete identity implementation.

    Example::

        ident: SigningIdentity = DidKeyIdentity(AgentId("a1"))
    """

    def sign(self, payload: bytes) -> Signature:
        """Sign ``payload`` and return a :class:`~nest_core.types.Signature`.

        Example::

            sig = ident.sign(b"content")
        """
        ...

    def verify(self, payload: bytes, sig: Signature, agent: AgentId) -> bool:
        """Verify ``sig`` over ``payload`` was produced by ``agent``.

        Example::

            ok = ident.verify(b"content", sig, AgentId("a1"))
        """
        ...


class FreshnessProof(BaseModel):
    """A publisher's signed attestation that a content hash was current at a tick.

    The proof binds three things the verifier cares about — the content address
    (``cid``), the logical ``tick`` the publisher attested at, and the
    ``signer`` — under a single signature. A verifier validates it *without*
    trusting any wall clock: the signature either covers exactly
    ``<cid>|<tick>|<signer>`` or it does not. ``signature`` is ``None`` only when
    the plugin was constructed without an identity (freshness then cannot be
    proven, which the validators treat as a stale claim).

    Example::

        proof = df.issue_freshness_proof(url)
        assert df.verify_freshness_proof(proof)
    """

    url: DataFactsUrl
    cid: str
    tick: float
    signer: AgentId
    signature: Signature | None = None

    def signed_bytes(self) -> bytes:
        """Return the canonical payload the signature is computed over.

        Example::

            payload = proof.signed_bytes()
        """
        return _canonical_bytes({"cid": self.cid, "tick": self.tick, "signer": str(self.signer)})


class _Record(BaseModel):
    """Internal store entry: the immutable content plus its provenance and proofs."""

    cid: str
    metadata: DatasetMetadata
    content_digest: str
    parents: list[DataFactsUrl]
    published_tick: float
    publisher: AgentId
    proofs: list[FreshnessProof]


def _canonical_bytes(obj: object) -> bytes:
    """Serialize ``obj`` to canonical (sorted-key, tight) JSON bytes.

    Example::

        raw = _canonical_bytes({"b": 1, "a": 2})  # b'{"a":2,"b":1}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class ContentAddressedDataFacts:
    """Content-addressed dataset registry with provenance DAG and signed freshness.

    Instances may share a ``store`` dict so a whole swarm publishes into one
    content-addressed namespace (substitution resistance is only meaningful when
    the namespace is shared), while each instance signs freshness proofs with its
    own ``identity``. Pass ``store`` to join an existing namespace; omit it for an
    isolated one.

    Example::

        shared: dict[DataFactsUrl, object] = {}
        a = ContentAddressedDataFacts(identity=id_a, store=shared)
        b = ContentAddressedDataFacts(identity=id_b, store=shared)
        url = await a.publish(meta)
        meta_back = await b.fetch(url)  # b sees a's publish through the shared store
    """

    def __init__(
        self,
        identity: SigningIdentity | None = None,
        store: dict[DataFactsUrl, _Record] | None = None,
    ) -> None:
        self._identity = identity
        self._store: dict[DataFactsUrl, _Record] = store if store is not None else {}
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._clock: float = 0.0

    # -- determinism -------------------------------------------------------

    def set_clock(self, tick: float) -> None:
        """Set the logical "now" used to stamp freshness proofs.

        Mirrors ``ed25519_rotating.set_clock``: scenarios call this with
        ``ctx.time`` so proofs bind to the simulator's logical tick, never wall
        time, keeping Tier 1 byte-deterministic.

        Example::

            df.set_clock(7.0)
        """
        self._clock = tick

    # -- content addressing ------------------------------------------------

    def _content_digest(self, dataset: DatasetMetadata) -> str:
        """Hash the canonical, volatile-free content view *including* parents.

        Folding ``parents`` in makes this a Merkle-DAG node: tampering with any
        ancestor's bytes changes its hash, which changes this child's hash, which
        propagates to every descendant.

        Example::

            digest = df._content_digest(DatasetMetadata(name="x", owner=AgentId("a1")))
        """
        view = dataset.model_dump(mode="json", exclude=set(_VOLATILE_FIELDS))
        return hashlib.sha256(_canonical_bytes(view)).hexdigest()

    def content_id(self, dataset: DatasetMetadata) -> str:
        """Return the content identifier (``sha256-<hex>``) for ``dataset``.

        Pure and deterministic: identical content always yields the identical id,
        and any change to any content-bearing field yields a different one.

        Example::

            cid = df.content_id(DatasetMetadata(name="x", owner=AgentId("a1")))
            assert cid.startswith("sha256-")
        """
        return f"{_HASH_PREFIX}{self._content_digest(dataset)}"

    def url_for(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Return the content-addressed URL (``df://sha256-<hex>``) for ``dataset``.

        Example::

            url = df.url_for(DatasetMetadata(name="x", owner=AgentId("a1")))
        """
        return DataFactsUrl(f"{_URL_SCHEME}{self.content_id(dataset)}")

    # -- DataFacts protocol ------------------------------------------------

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish ``dataset`` at its content address and issue a freshness proof.

        Republishing identical content is idempotent (same URL, refreshed proof).
        Every ``parents`` entry must already exist in the store, or
        :class:`BrokenProvenanceError` is raised — you cannot anchor provenance to
        a hash nobody published.

        Example::

            url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
        """
        for parent in dataset.parents:
            if parent not in self._store:
                msg = f"parent not found in content store: {parent}"
                raise BrokenProvenanceError(msg)

        url = self.url_for(dataset)
        digest = self._content_digest(dataset)
        record = self._store.get(url)
        if record is None:
            record = _Record(
                cid=self.content_id(dataset),
                metadata=dataset,
                content_digest=digest,
                parents=list(dataset.parents),
                published_tick=self._clock,
                publisher=dataset.owner,
                proofs=[],
            )
            self._store[url] = record
        # Whether new or idempotent re-publish, attest freshness *now*.
        record.proofs.append(self._make_proof(url, record.cid, dataset.owner))
        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        """Fetch metadata for a content-addressed URL.

        Example::

            meta = await df.fetch(DataFactsUrl("df://sha256-abc123"))
        """
        record = self._store.get(url)
        if record is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        return record.metadata

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        """Grant access, keyed by the *content hash* and the dataset's access tier.

        Unlike ``datafacts_v1`` (which grants unconditionally), a non-public
        dataset only grants to its owner. The grant is recorded against the
        content address, so it cannot be transferred to a substituted dataset.

        Example::

            grant = await df.request_access(url, AgentId("a2"))
        """
        record = self._store.get(url)
        if record is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        if record.metadata.access_tier != "public" and requester != record.publisher:
            msg = f"access denied for {requester} on {url}"
            raise PermissionError(msg)
        grant = AccessGrant(url=url, grantee=requester, tier="read")
        self._grants.setdefault(url, []).append(grant)
        return grant

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """Return whether ``url`` has a cryptographically valid freshness proof.

        Protocol-exact (``-> bool``). True iff the most recent proof for ``url``
        is signed and verifies against the publisher's key and binds the stored
        content hash. Returns False for unsigned/keyless plugins — which is why
        ``datafacts_v1`` (no proofs at all) fails the freshness validator. The
        *staleness-by-tick* judgment is left to the validator, which anchors it to
        externally observed trace ticks rather than publisher-claimed ones.

        Example::

            fresh = await df.verify_freshness(url)
        """
        record = self._store.get(url)
        if record is None or not record.proofs:
            return False
        return self.verify_freshness_proof(record.proofs[-1])

    # -- signed freshness proofs ------------------------------------------

    def _make_proof(self, url: DataFactsUrl, cid: str, signer: AgentId) -> FreshnessProof:
        payload = _canonical_bytes({"cid": cid, "tick": self._clock, "signer": str(signer)})
        signature = self._identity.sign(payload) if self._identity is not None else None
        return FreshnessProof(
            url=url, cid=cid, tick=self._clock, signer=signer, signature=signature
        )

    def issue_freshness_proof(self, url: DataFactsUrl) -> FreshnessProof:
        """Issue (and store) a fresh signed proof for an already-published ``url``.

        This is how an honest publisher *re-attests* currency at a later tick.
        A stale publisher who skips this keeps only its old proof — exactly the
        signal the freshness validator looks for.

        Example::

            df.set_clock(9.0)
            proof = df.issue_freshness_proof(url)
        """
        record = self._store.get(url)
        if record is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        proof = self._make_proof(url, record.cid, record.publisher)
        record.proofs.append(proof)
        return proof

    def verify_freshness_proof(self, proof: FreshnessProof) -> bool:
        """Verify a freshness proof's signature and content binding.

        Fails if the proof is unsigned, if the signature does not verify against
        the claimed signer's key, or if the bound ``cid`` does not match the
        content actually stored at ``proof.url`` (a tampered/forged proof).

        Example::

            ok = df.verify_freshness_proof(proof)
        """
        if proof.signature is None or self._identity is None:
            return False
        record = self._store.get(proof.url)
        if record is None or record.cid != proof.cid:
            return False
        return self._identity.verify(proof.signed_bytes(), proof.signature, proof.signer)

    # -- provenance --------------------------------------------------------

    def verify_provenance(self, url: DataFactsUrl) -> bool:
        """Return whether every ancestor of ``url`` is present in the store.

        Walks the transitive ``parents`` DAG; any dangling reference (a parent
        hash nobody published) makes the chain unverifiable and returns False.

        Example::

            ok = df.verify_provenance(url)
        """
        seen: set[DataFactsUrl] = set()
        frontier: list[DataFactsUrl] = [url]
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            seen.add(current)
            record = self._store.get(current)
            if record is None:
                return False
            frontier.extend(record.parents)
        return True


class BrokenProvenanceError(ValueError):
    """Raised when a publish references a parent hash absent from the store.

    Example::

        try:
            await df.publish(DatasetMetadata(name="x", owner=a, parents=[ghost]))
        except BrokenProvenanceError:
            ...
    """
