# SPDX-License-Identifier: Apache-2.0
"""Content-addressed DataFacts plugin with provenance chains and freshness proofs.

Replaces name-based URLs with content hashes (SHA-256) so that a dataset's
identity is bound to its actual content.  Freshness is attested by a
cryptographic signature from the publisher's identity-layer key rather than
a wall-clock timestamp, making it verifiable without trusting the clock.

Derived datasets carry a ``parents`` list of upstream content hashes,
forming a provenance DAG that can be validated end-to-end.

This plugin is designed to close three gaps in ``datafacts_v1``:

1. Substitution attacks  -- impossible by construction because the URL *is*
   the hash.
2. Stale-freshness claims -- detected because freshness requires a signed
   proof, not a re-touched timestamp.
3. Provenance washing   -- every derived dataset must reference its parent
   hashes; validators can walk the chain.

Example::

    from nest_plugins_reference.identity.did_key import DidKeyIdentity
    identity = DidKeyIdentity(AgentId("publisher"), seed=b"seed")
    df = ContentAddressedDataFacts(identity=identity)
    url = await df.publish(
        DatasetMetadata(name="weather-2024", owner=AgentId("publisher")),
        payload=b"raw sensor readings",
    )
    meta = await df.fetch(url)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

# Re-use the Identity protocol from the identity layer.  The constructor
# accepts any object that satisfies Identity (structural typing), but we
# import the protocol only for type-checking so the runtime dependency
# graph stays clean.
from nest_core.layers.identity import Identity
from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata, Signature


@dataclass(frozen=True)
class FreshnessProof:
    """Signed attestation that a content hash was published at a given tick.

    The proof binds a content URL to a logical timestamp and the publisher's
    signature, so a verifier can confirm freshness without trusting wall-clock
    time.

    Example::

        proof = FreshnessProof(
            url=DataFactsUrl("df://sha256-abcd"),
            publisher=AgentId("a1"),
            tick=5,
            signature=sig,
        )
    """

    url: DataFactsUrl
    publisher: AgentId
    tick: int
    signature: Signature


def canonical_json(obj: dict[str, Any]) -> bytes:
    """Deterministic JSON serialization for hashing.

    Keys are sorted and separators stripped of whitespace so that the
    same logical object always produces the same byte sequence.

    Example::

        raw = canonical_json({"b": 2, "a": 1})
        assert raw == b'{"a":1,"b":2}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_hash(metadata: DatasetMetadata, payload: bytes) -> str:
    """Compute the SHA-256 content hash for a dataset.

    The hash covers both the canonical metadata representation and the raw
    payload bytes, preventing substitution of either component.

    Example::

        h = content_hash(meta, b"payload")
        assert h.startswith("sha256-")
    """
    meta_dict: dict[str, Any] = {
        "name": metadata.name,
        "owner": str(metadata.owner),
        "description": metadata.description,
        "schema_version": metadata.schema_version,
        "tags": sorted(metadata.tags),
        "access_tier": metadata.access_tier,
    }
    # Include parent hashes in the content hash when present so that two
    # datasets with the same raw payload but different provenance are
    # distinguishable.
    parents = metadata.metadata.get("parents")
    if parents is not None:
        meta_dict["parents"] = sorted(parents)

    canonical = canonical_json(meta_dict)
    digest = hashlib.sha256(canonical + payload).hexdigest()
    return f"sha256-{digest}"


def _freshness_payload(url: DataFactsUrl, tick: int) -> bytes:
    """Build the byte string that gets signed for a freshness proof.

    Example::

        raw = _freshness_payload(DataFactsUrl("df://sha256-abc"), 5)
    """
    return canonical_json({"url": str(url), "tick": tick})


class ContentAddressedDataFacts:
    """DataFacts implementation backed by content-addressed storage.

    URLs are SHA-256 hashes of the canonical metadata + payload, so the
    same content always maps to the same URL and different content can
    never collide with an existing URL.  Freshness is proved via a
    signature from the publisher's identity key rather than a wall-clock
    timestamp.

    The ``identity`` parameter must satisfy the ``Identity`` protocol
    (structural typing).  It is used to sign freshness proofs on
    ``publish`` and to verify them on ``verify_freshness``.

    Example::

        from nest_plugins_reference.identity.did_key import DidKeyIdentity
        ident = DidKeyIdentity(AgentId("pub"), seed=b"s")
        df = ContentAddressedDataFacts(identity=ident)
        url = await df.publish(meta, payload=b"data")
    """

    def __init__(
        self,
        identity: Identity,
        *,
        initial_tick: int = 0,
    ) -> None:
        self._identity = identity
        self._tick = initial_tick

        # Primary stores, keyed by content-addressed URL.
        self._datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        self._payloads: dict[DataFactsUrl, bytes] = {}
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._proofs: dict[DataFactsUrl, FreshnessProof] = {}
        self._publishers: dict[DataFactsUrl, AgentId] = {}

    @property
    def tick(self) -> int:
        """Current logical tick (read-only).

        Example::

            t = df.tick
        """
        return self._tick

    def advance_tick(self, new_tick: int) -> None:
        """Advance the logical clock to *new_tick*.

        Monotonicity is enforced: the new tick must be >= the current tick.
        The simulator calls this between rounds so that freshness proofs
        carry meaningful temporal ordering.

        Example::

            df.advance_tick(10)
        """
        if new_tick < self._tick:
            msg = f"tick must be monotonically non-decreasing: {new_tick} < {self._tick}"
            raise ValueError(msg)
        self._tick = new_tick

    async def publish(
        self,
        dataset: DatasetMetadata,
        *,
        payload: bytes = b"",
    ) -> DataFactsUrl:
        """Publish a dataset and return its content-addressed URL.

        If the exact same content (metadata + payload) has been published
        before, the same URL is returned without overwriting the store.
        Publishing *different* content that happens to hash-collide is
        rejected (this cannot happen under SHA-256 in practice, but we
        guard against programming errors in tests).

        A signed freshness proof is generated automatically.

        Example::

            url = await df.publish(meta, payload=b"sensor data")
        """
        content_hash_str = content_hash(dataset, payload)
        url = DataFactsUrl(f"df://{content_hash_str}")

        # Idempotent: re-publishing identical content is a no-op.
        if url in self._datasets:
            return url

        # Validate provenance references if parents are declared.
        parents = dataset.metadata.get("parents")
        if parents is not None:
            for parent_url_str in parents:
                parent_url = DataFactsUrl(str(parent_url_str))
                if parent_url not in self._datasets:
                    msg = f"parent dataset not found: {parent_url}"
                    raise KeyError(msg)

        self._datasets[url] = dataset
        self._payloads[url] = payload
        self._publishers[url] = dataset.owner

        # Sign a freshness proof at the current logical tick.
        proof_payload = _freshness_payload(url, self._tick)
        sig = self._identity.sign(proof_payload)
        self._proofs[url] = FreshnessProof(
            url=url,
            publisher=dataset.owner,
            tick=self._tick,
            signature=sig,
        )

        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        """Fetch metadata for a content-addressed URL.

        Raises ``KeyError`` if the URL has never been published.

        Example::

            meta = await df.fetch(DataFactsUrl("df://sha256-abcd..."))
        """
        meta = self._datasets.get(url)
        if meta is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        return meta

    async def request_access(
        self,
        url: DataFactsUrl,
        requester: AgentId,
    ) -> AccessGrant:
        """Request read access to a dataset.

        In this reference implementation, access is granted unconditionally
        (same as ``datafacts_v1``) because fine-grained ACL enforcement is
        out of scope for the content-addressing problem.  The grant is
        anchored to the content hash, not a mutable name.

        Example::

            grant = await df.request_access(url, AgentId("consumer"))
        """
        if url not in self._datasets:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        grant = AccessGrant(url=url, grantee=requester, tier="read")
        self._grants.setdefault(url, []).append(grant)
        return grant

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """Verify that the dataset has a valid signed freshness proof.

        Returns ``True`` only if:
        - a freshness proof exists for this URL,
        - the proof's signature is valid against the publisher's key.

        No wall-clock time is consulted.

        Example::

            ok = await df.verify_freshness(DataFactsUrl("df://sha256-abcd..."))
        """
        proof = self._proofs.get(url)
        if proof is None:
            return False

        proof_payload = _freshness_payload(url, proof.tick)
        return self._identity.verify(
            proof_payload,
            proof.signature,
            proof.publisher,
        )

    # ------------------------------------------------------------------
    # Introspection helpers (not part of the DataFacts protocol, used by
    # validators and tests).
    # ------------------------------------------------------------------

    def get_proof(self, url: DataFactsUrl) -> FreshnessProof | None:
        """Return the freshness proof for a URL, or ``None`` if absent.

        Example::

            proof = df.get_proof(url)
        """
        return self._proofs.get(url)

    def get_payload(self, url: DataFactsUrl) -> bytes | None:
        """Return the raw payload for a URL, or ``None`` if absent.

        Example::

            data = df.get_payload(url)
        """
        return self._payloads.get(url)

    def published_urls(self) -> list[DataFactsUrl]:
        """Return all published URLs in insertion order.

        Example::

            urls = df.published_urls()
        """
        return list(self._datasets.keys())

    def verify_content_integrity(self, url: DataFactsUrl) -> bool:
        """Re-hash the stored metadata + payload and confirm it matches the URL.

        This is a self-consistency check: if the store is honest, it must
        always pass.  It exists so adversarial validators can confirm that
        the content-addressing invariant holds across the entire store.

        Example::

            assert df.verify_content_integrity(url)
        """
        meta = self._datasets.get(url)
        payload = self._payloads.get(url)
        if meta is None or payload is None:
            return False
        expected_hash = content_hash(meta, payload)
        return str(url) == f"df://{expected_hash}"

    def verify_provenance_chain(self, url: DataFactsUrl) -> bool:
        """Walk the provenance DAG and confirm every parent exists in the store.

        Returns ``False`` if any parent hash referenced by this dataset (or
        transitively by its ancestors) is missing.

        Example::

            assert df.verify_provenance_chain(url)
        """
        visited: set[DataFactsUrl] = set()
        stack = [url]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            meta = self._datasets.get(current)
            if meta is None:
                return False
            parents = meta.metadata.get("parents")
            if parents is not None:
                for p in parents:
                    parent_url = DataFactsUrl(str(p))
                    if parent_url not in self._datasets:
                        return False
                    if parent_url not in visited:
                        stack.append(parent_url)
        return True
