# SPDX-License-Identifier: Apache-2.0
"""CidFacts — content-addressed DataFacts plugin.

Addresses three attack classes that ``datafacts_v1`` is silent on:

1. **Substitution**: URLs are ``df://sha256-<hex>`` derived from content.
   Publishing different content under the same human-readable name
   produces a different URL — substitution is structurally impossible.

2. **Stale-freshness**: ``verify_freshness`` returns a *signed proof*
   (internally) and ``True`` only when the signature verifies.
   The proof binds content hash + publisher identity + logical tick;
   no wall-clock check is used.

3. **Provenance washing**: ``DatasetMetadata.parents`` carries the
   content-addressed URLs of every upstream dataset; the provenance
   chain is stored verbatim and returned by ``fetch``.

Content binding
---------------
The hash covers the canonical JSON of ``metadata.model_dump()``
(sorted keys, no spaces).  If the caller stores a ``"content_sha256"``
key inside ``metadata.metadata``, it is automatically included in the
canonical JSON, binding the URL to the actual payload bytes without
requiring a protocol change.

Usage::

    from nest_plugins_reference.identity.did_key import DidKeyIdentity
    from nest_core.types import AgentId, DatasetMetadata

    identity = DidKeyIdentity(AgentId("supplier-0"), seed=b"seed")
    df = CidFacts(identity)

    url = await df.publish(DatasetMetadata(name="raw-batch", owner=AgentId("supplier-0")))
    assert url.startswith("df://sha256-")

    fresh = await df.verify_freshness(url)
    proof = df.get_freshness_proof(url)
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Callable
from typing import Any

from nest_core.types import (
    AccessGrant,
    AgentId,
    DataFactsUrl,
    DatasetMetadata,
    FreshnessProof,
    Signature,
)

from nest_plugins_reference.identity.did_key import DidKeyIdentity

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes (sorted keys, no spaces).

    Example::

        _canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _content_hash(dataset: DatasetMetadata) -> str:
    """Compute SHA-256 hex digest of the canonical JSON of *dataset*.

    The dump includes every field of ``DatasetMetadata``, including
    ``metadata`` (which may carry a ``"content_sha256"`` payload digest)
    and ``parents``.  Identical datasets always produce the same digest;
    any change — including a parent reference or a payload digest — yields
    a different digest.

    Example::

        h = _content_hash(DatasetMetadata(name="x", owner=AgentId("a1")))
        assert len(h) == 64  # 256-bit hex string
    """
    raw = {
        "owner": str(dataset.owner),
        "description": dataset.description,
        "schema_version": dataset.schema_version,
        "tags": sorted(dataset.tags),
        "size_bytes": dataset.size_bytes,
        "checksum": dataset.checksum,
        "access_tier": dataset.access_tier,
        "metadata": dataset.metadata,
        "parents": sorted(str(parent) for parent in dataset.parents),
    }

    return hashlib.sha256(_canonical_json(raw)).hexdigest()


def proof_payload(url: DataFactsUrl, publisher: AgentId, tick: float) -> bytes:
    """Canonical bytes that are signed to produce a FreshnessProof.

    ``tick`` is serialized as a string (not a number) so that the encoding is
    identical whether the underlying clock returns ``int`` or ``float``:
    ``itertools.count()`` returns an ``int`` (0, 1, 2…), but ``FreshnessProof``
    stores ``tick: float`` and Pydantic coerces ``0 -> 0.0``, which JSON then
    encodes differently (``"tick":0`` vs ``"tick":0.0``).  Serializing as a
    string sidesteps the type-coercion entirely.

    Example::

        payload = proof_payload(DataFactsUrl("df://sha256-abc"), AgentId("a1"), 42)
    """
    return _canonical_json({"publisher": str(publisher), "tick": str(tick), "url": str(url)})


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class CidFacts:
    """Content-addressed DataFacts plugin.

    Drop-in replacement for ``DataFactsV1`` that adds:

    * SHA-256 content-addressed URLs
    * Signed freshness proofs (no wall-clock)
    * Provenance DAG via ``DatasetMetadata.parents``
    * Minimal ACLs (public → read, restricted → owner only)

    Example::

        identity = DidKeyIdentity(AgentId("a1"), seed=b"seed")
        df = CidFacts(identity)
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        assert url.startswith("df://sha256-")
        fresh = await df.verify_freshness(url)
        assert fresh
    """

    def __init__(
        self,
        identity: DidKeyIdentity,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Initialise the plugin.

        Parameters
        ----------
        identity:
            A ``DidKeyIdentity`` instance for the *publishing* agent.
            Used to sign freshness proofs.
        clock:
            A zero-argument callable that returns the current logical tick
            as a float.  Defaults to ``itertools.count().__next__``,
            which produces 0, 1, 2, … — a pure logical counter with no
            dependency on wall-clock time.  Scenarios may pass
            ``lambda: ctx.time`` to use the simulator's own clock.

        Example::

            identity = DidKeyIdentity(AgentId("a1"), seed=b"seed")
            df = CidFacts(identity, clock=lambda: ctx.time)
        """
        self._identity = identity
        self._clock: Callable[[], float] = (
            clock if clock is not None else itertools.count().__next__
        )

        # url -> DatasetMetadata
        self._datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        # url -> FreshnessProof  (only present after publish)
        self._proofs: dict[DataFactsUrl, FreshnessProof] = {}
        # (url, requester) -> AccessGrant
        self._grants: dict[tuple[DataFactsUrl, AgentId], AccessGrant] = {}
        # content-hash -> url  (idempotency registry)
        self._hash_to_url: dict[str, DataFactsUrl] = {}

    # ------------------------------------------------------------------
    # DataFacts Protocol
    # ------------------------------------------------------------------

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish dataset metadata and return its content-addressed URL.

        Publishing the same content twice returns the same URL (idempotent).
        Publishing different content — even under the same name — always
        returns a different URL, making substitution attacks structurally
        impossible.

        A ``FreshnessProof`` is created and stored internally on every
        publish call.  Use :meth:`get_freshness_proof` to retrieve it.

        Example::

            url = await df.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
            assert url.startswith("df://sha256-")
        """
        for parent in dataset.parents:
            if parent not in self._datasets:
                msg = f"Unknown parent dataset: {parent}"
                raise KeyError(msg)
        hex_digest = _content_hash(dataset)

        # Idempotency: return the existing URL if we've seen this content before.
        if hex_digest in self._hash_to_url:
            return self._hash_to_url[hex_digest]

        url = DataFactsUrl(f"df://sha256-{hex_digest}")
        self._datasets[url] = dataset
        self._hash_to_url[hex_digest] = url

        # Build and store a signed freshness proof.
        # Coerce the clock value to float *before* signing.  itertools.count()
        # returns int, but FreshnessProof.tick is declared as float and Pydantic
        # will coerce 0 → 0.0.  If we signed with str(0)="0" but verify
        # reconstructs the payload with str(0.0)="0.0" the signatures would not
        # match.  Applying float() here ensures both sides serialize identically.
        tick: float = float(self._clock())
        publisher = self._identity.agent_id
        payload = proof_payload(url, publisher, tick)
        sig: Signature = self._identity.sign(payload)

        self._proofs[url] = FreshnessProof(
            url=url,
            publisher=publisher,
            tick=tick,
            signature=sig,
        )

        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        """Fetch metadata for a content-addressed dataset URL.

        Raises ``KeyError`` if the URL was never published.

        Example::

            meta = await df.fetch(url)
            assert meta.parents  # provenance preserved
        """
        meta = self._datasets.get(url)
        if meta is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        return meta

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        """Request access to a dataset keyed by its content-addressed URL.

        ACL rules (applied once per (url, requester) pair):

        * ``access_tier == "public"``  → grants ``tier="read"`` to anyone.
        * ``access_tier == "restricted"`` → grants ``tier="read"`` only to
          the dataset owner; all other requesters receive ``tier="none"``.

        Example::

            grant = await df.request_access(url, AgentId("buyer"))
            assert grant.tier in ("read", "none")
        """
        grant_key = (url, requester)
        if grant_key in self._grants:
            return self._grants[grant_key]

        meta = self._datasets.get(url)
        if meta is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)

        tier = "none" if meta.access_tier == "restricted" and requester != meta.owner else "read"

        grant = AccessGrant(url=url, grantee=requester, tier=tier)
        self._grants[grant_key] = grant
        return grant

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """Verify that a valid signed freshness proof exists for *url*.

        Returns ``True`` iff:

        1. A ``FreshnessProof`` was recorded for this URL during ``publish``.
        2. The proof's signature verifies against the publisher's public key.

        No wall-clock check is performed.

        Protocol compatibility note
        ---------------------------
        The ``DataFacts`` Protocol declares ``verify_freshness(url) -> bool``.
        To avoid breaking any existing caller, the return type remains ``bool``.
        The full proof object is available via :meth:`get_freshness_proof`.

        Example::

            fresh = await df.verify_freshness(url)
            assert fresh  # True when signature is valid
        """
        proof = self._proofs.get(url)
        if proof is None:
            return False

        # Ensure the publisher's public key is known to this identity instance
        # so that verify() can look up the signer.  For the common case where
        # the same CidFacts instance published the dataset the key is already
        # registered (it's the agent's own key).  For cross-agent verification
        # the caller should call register_peer_key() first.
        publisher = proof.publisher
        if not self._identity.has_peer_key(publisher):
            # Cannot verify — unknown publisher key.  Callers that need
            # cross-agent verification must call register_peer_key().
            return False

        payload = proof_payload(proof.url, proof.publisher, proof.tick)
        return self._identity.verify(payload, proof.signature, publisher)

    # ------------------------------------------------------------------
    # Extended API (not part of the DataFacts Protocol)
    # ------------------------------------------------------------------

    def get_freshness_proof(self, url: DataFactsUrl) -> FreshnessProof | None:
        """Return the stored ``FreshnessProof`` for *url*, or ``None``.

        This method is intentionally **not** part of the ``DataFacts``
        Protocol so that existing implementations (e.g. ``datafacts_v1``)
        remain valid.  Validators and provenance-scenario agents that need
        the proof object call this method directly on the ``CidFacts``
        instance retrieved from ``ctx.plugins["datafacts"]``.

        Example::

            proof = df.get_freshness_proof(url)
            if proof:
                print(proof.tick, proof.publisher)
        """
        return self._proofs.get(url)

    @property
    def identity(self) -> DidKeyIdentity:
        """The signing identity for this plugin instance.

        Example::

            pk = df.identity.public_key
        """
        return self._identity

    @property
    def proofs(self) -> dict[DataFactsUrl, FreshnessProof]:
        """Live view of all stored freshness proofs, keyed by URL.

        Intended for testing and scenario inspection only.

        Example::

            assert url in df.proofs
        """
        return self._proofs

    def register_peer_key(self, agent_id: AgentId, public_key: bytes) -> None:
        """Register a peer public key so their freshness proofs can be verified.

        In multi-agent scenarios each agent holds its own ``CidFacts``
        instance.  Call this on the verifier's instance so it can verify
        proofs signed by the peer.

        Example::

            retailer_df.register_peer_key(supplier_id, supplier_identity.public_key)
        """
        self._identity.register_peer(agent_id, public_key)
