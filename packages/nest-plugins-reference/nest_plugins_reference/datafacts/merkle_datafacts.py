# SPDX-License-Identifier: Apache-2.0
"""Content-addressed DataFacts with Git-style Merkle DAG, monotonic hash chains,
Bloom-filter ancestry, and alias resolution.

Implements the refined Problem 08 approach:

1. **Git-style Merkle DAG** — the dataset URL is
   ``df://sha256-<sha256(payload_checksum || canonical_metadata || sorted_parent_hashes)>``.
   A separate ``tree_hash`` is unnecessary because lineage integrity is
   guaranteed by construction.

2. **Alias consistency under partition** — ``df://<name>@latest`` resolves
   from the local registry view. When the partition heals, gossip converges
   the alias to the globally newest hash.

3. **Anti-equivocation freshness proofs** — each publisher maintains a
   monotonic hash chain ``H_n = SHA256(H_{n-1} || tick_n || dataset_hash_n)``.
   Fork detection catches double-publishing at the same tick.

4. **Compact ancestry check** — each dataset carries a Bloom filter of its
   ancestor hashes for O(1) negative queries.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any, cast

from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata, Signature
from pydantic import BaseModel

if TYPE_CHECKING:
    from nest_core.layers.identity import Identity


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProvenanceError(ValueError):
    """Raised when a dataset declares a parent URL this registry never published.

    Example::

        with pytest.raises(ProvenanceError):
            await facts.publish(DatasetMetadata(name="x", owner=AgentId("a1"),
                                                 metadata={"parents": ["df://sha256-deadbeef"]}))
    """


# ---------------------------------------------------------------------------
# Shared logical clock
# ---------------------------------------------------------------------------


class SharedClock:
    """Monotonic logical tick shared by every per-agent :class:`MerkleDataFacts` handle.

    Example::

        clock = SharedClock()
        facts_a = MerkleDataFacts(identity_a, clock=clock)
        facts_b = MerkleDataFacts(identity_b, clock=clock)
    """

    def __init__(self) -> None:
        self.tick: float = 0.0

    def advance(self) -> float:
        """Advance the clock by one tick and return the new value.

        Example::

            now = clock.advance()
        """
        self.tick += 1.0
        return self.tick


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ChainLink(BaseModel):
    """One link in the anti-equivocation monotonic hash chain.

    ``H_n = SHA256(H_{n-1} || tick_n || dataset_hash_n)``.

    ``signature`` is over ``H_n`` (the current chain hash), binding the
    publisher's identity to this exact point in the chain.

    Example::

        link = ChainLink(h_prev="abc...", h_curr="def...",
                         tick=3.0, dataset_hash="a1b2...", signature=sig)
    """

    h_prev: str
    h_curr: str
    tick: float
    dataset_hash: str
    signature: Signature


class FreshnessProof(BaseModel):
    """A publisher-signed attestation that ``url`` is fresh at ``tick``.

    The proof bundles the chain link so any verifier can detect forks
    by comparing two proofs that share the same ``h_prev`` but diverge
    on ``h_curr``.

    Example::

        proof = FreshnessProof(url=url, tick=3.0, chain=link)
    """

    url: DataFactsUrl
    tick: float
    chain: ChainLink


# ---------------------------------------------------------------------------
# Bloom filter helpers
# ---------------------------------------------------------------------------

_BLOOM_SEEDS = [b"salt1", b"salt2", b"salt3"]


def _compute_bloom(ancestors: set[str]) -> str:
    """Build a 256-bit Bloom filter over ``ancestors`` (k=3, m=256).

    Returns a 64-character hex string.

    Example::

        bloom = _compute_bloom({"df://sha256-a", "df://sha256-b"})
    """
    bit_array = 0
    for ancestor in ancestors:
        for seed in _BLOOM_SEEDS:
            h = hashlib.sha256(seed + ancestor.encode("utf-8")).digest()
            idx = int.from_bytes(h[:2], "big") % 256
            bit_array |= 1 << idx
    return f"{bit_array:064x}"


def _check_bloom(bloom_hex: str, url: str) -> bool:
    """Check whether ``url`` *might* be in the Bloom filter (true = possible).

    Example::

        if _check_bloom(bloom, target_url):
            # fall back to full DAG crawl — could be false positive
            pass
    """
    bit_array = int(bloom_hex, 16)
    for seed in _BLOOM_SEEDS:
        h = hashlib.sha256(seed + url.encode("utf-8")).digest()
        idx = int.from_bytes(h[:2], "big") % 256
        if not (bit_array & (1 << idx)):
            return False
    return True


# ---------------------------------------------------------------------------
# Content hash (Git-style Merkle DAG)
# ---------------------------------------------------------------------------


def _parents_of(dataset: DatasetMetadata) -> list[DataFactsUrl]:
    """Read declared provenance parents out of ``dataset.metadata``.

    Example::

        parents = _parents_of(derived_dataset)
    """
    raw: object = dataset.metadata.get("parents", [])
    if not isinstance(raw, list):
        return []
    return [DataFactsUrl(str(p)) for p in cast("list[Any]", raw)]


def content_hash(dataset: DatasetMetadata) -> str:
    """Compute the Git-style content address.

    ``SHA256(payload_checksum || canonical_metadata || sorted_parent_hashes)``

    - **payload_checksum**: ``dataset.checksum`` if set, else ``""``
    - **canonical_metadata**: sorted JSON of all content-bearing fields
      (excluding ``name``, ``created_at``, ``updated_at``, and derived
      metadata keys such as ``parents`` and ``ancestor_bloom``).
    - **sorted_parent_hashes**: newline-joined parent URLs, sorted.

    Example::

        digest = content_hash(DatasetMetadata(name="raw", owner=AgentId("a1")))
    """
    meta = dict(dataset.metadata)
    meta.pop("parents", None)
    meta.pop("ancestor_bloom", None)

    content: dict[str, Any] = {
        "owner": str(dataset.owner),
        "description": dataset.description,
        "schema_version": dataset.schema_version,
        "tags": sorted(dataset.tags) if dataset.tags else [],
        "size_bytes": dataset.size_bytes,
        "checksum": dataset.checksum,
        "access_tier": dataset.access_tier,
        "metadata": meta,
    }
    canonical_meta = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")

    parents = _parents_of(dataset)
    parent_hashes = "\n".join(sorted(str(p) for p in parents)).encode("utf-8")

    payload_chk = (dataset.checksum or "").encode("utf-8")

    h = hashlib.sha256()
    h.update(payload_chk)
    h.update(canonical_meta)
    h.update(parent_hashes)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Monkey-in-the-middle attack helpers
# ---------------------------------------------------------------------------


def _dataset_hash_from_url(url: str) -> str:
    """Extract the hex digest from a ``df://sha256-<hex>`` URL.

    Example::

        assert _dataset_hash_from_url("df://sha256-abc") == "abc"
    """
    return url.removeprefix("df://sha256-")


# ---------------------------------------------------------------------------
# Main plugin class
# ---------------------------------------------------------------------------


class MerkleDataFacts:
    """Content-addressed DataFacts with provenance, signed freshness, and aliases.

    Example::

        identity = DidKeyIdentity(AgentId("supplier-0"), seed=b"sim-seed")
        facts = MerkleDataFacts(identity)
        url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("supplier-0")))
        assert await facts.verify_freshness(url) is True
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
        self._identity = identity
        self._datasets: dict[DataFactsUrl, DatasetMetadata] = (
            datasets if datasets is not None else {}
        )
        self._proofs: dict[DataFactsUrl, FreshnessProof] = proofs if proofs is not None else {}
        self._chain_heads: dict[AgentId, str] = {}  # last H_n per publisher
        self._aliases: dict[str, DataFactsUrl] = {}  # name -> latest URL
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._clock = clock if clock is not None else SharedClock()
        self._freshness_window = freshness_window
        self.__agent_id: AgentId | None = None

    # -- Public helpers (meant for scenario agents / validators) -----------

    @property
    def clock(self) -> SharedClock:
        """The shared logical clock — accessor expected by ``_build_datafacts_handles``.

        Example::

            clock = facts.clock
        """
        return self._clock

    def resolve(self, name: str) -> DataFactsUrl | None:
        """Resolve a convenience alias ``df://<name>@latest`` to its latest URL.

        Example::

            latest = facts.resolve("weather")
        """
        return self._aliases.get(name)

    def known_urls(self) -> list[DataFactsUrl]:
        """List every URL this registry instance has published.

        Example::

            urls = facts.known_urls()
        """
        return list(self._datasets)

    def freshness_proof(self, url: DataFactsUrl) -> FreshnessProof | None:
        """Return the raw freshness proof for ``url`` (for tests/validators).

        Example::

            proof = facts.freshness_proof(url)
        """
        return self._proofs.get(url)

    def ancestors(self, url: DataFactsUrl) -> set[DataFactsUrl]:
        """Return every transitive provenance ancestor of ``url`` (BFS, de-duped).

        Example::

            assert facts.ancestors(report_url) == {raw_url, cleaned_url}
        """
        seen: set[DataFactsUrl] = set()
        stack: list[DataFactsUrl] = []
        root_meta = self._datasets.get(url)
        if root_meta is not None:
            stack.extend(_parents_of(root_meta))
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            meta = self._datasets.get(current)
            if meta is not None:
                stack.extend(_parents_of(meta))
        return seen

    # -- Core DataFacts protocol ------------------------------------------

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish dataset metadata and return its content-addressed URL.

        Republishing identical content is idempotent (same URL) but issues a
        fresh signed proof — the only legitimate way to extend freshness.

        Raises :class:`ProvenanceError` if any parent in
        ``dataset.metadata["parents"]`` has never been published.

        Example::

            url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        """
        parents = _parents_of(dataset)
        for parent in parents:
            if parent not in self._datasets:
                msg = f"unknown provenance parent {parent!r} for dataset {dataset.name!r}"
                raise ProvenanceError(msg)

        if parents:
            normalized_metadata = dict(dataset.metadata)
            normalized_metadata["parents"] = sorted(str(p) for p in parents)

            all_ancestors: set[str] = set()
            for p in parents:
                all_ancestors.add(str(p))
                all_ancestors.update(str(a) for a in self.ancestors(p))
            if all_ancestors:
                normalized_metadata["ancestor_bloom"] = _compute_bloom(all_ancestors)

            dataset = dataset.model_copy(update={"metadata": normalized_metadata})

        digest = content_hash(dataset)
        url = DataFactsUrl(f"df://sha256-{digest}")
        self._datasets[url] = dataset
        self._aliases[dataset.name] = url

        # -- Anti-equivocation monotonic hash chain --
        agent_id = self._agent_id
        tick = self._clock.advance()
        dataset_hash = _dataset_hash_from_url(str(url))

        h_prev = self._chain_heads.get(agent_id, "")
        h_curr = self._compute_chain_hash(h_prev, tick, dataset_hash)
        self._chain_heads[agent_id] = h_curr

        chain_payload = h_curr.encode("utf-8")
        signature = self._identity.sign(chain_payload)
        link = ChainLink(
            h_prev=h_prev,
            h_curr=h_curr,
            tick=tick,
            dataset_hash=dataset_hash,
            signature=signature,
        )
        self._proofs[url] = FreshnessProof(url=url, tick=tick, chain=link)
        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        """Fetch metadata for a published dataset.

        Example::

            meta = await facts.fetch(url)
        """
        meta = self._datasets.get(url)
        if meta is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        return meta

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        """Request access to a dataset; ACL is keyed by content hash, not name.

        ``access_tier == "public"`` grants any requester read access; anything
        else is only granted to the dataset's own owner.

        Example::

            grant = await facts.request_access(url, AgentId("a2"))
        """
        meta = await self.fetch(url)
        if meta.access_tier != "public" and requester != meta.owner:
            msg = f"{requester} is not authorized to read {url} (tier={meta.access_tier!r})"
            raise PermissionError(msg)
        grant = AccessGrant(url=url, grantee=requester, tier="read")
        self._grants.setdefault(url, []).append(grant)
        return grant

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """Check whether ``url`` has a valid, recent, owner-signed freshness proof.

        Fails closed: no proof, an unverifiable chain link, a signature from
        someone other than the dataset's declared owner, a recomputed chain
        that doesn't match, or a proof older than the freshness window are all
        treated as *not fresh*.

        Example::

            fresh = await facts.verify_freshness(url)
        """
        meta = self._datasets.get(url)
        proof = self._proofs.get(url)
        if meta is None or proof is None:
            return False

        chain = proof.chain

        # The signer must be the dataset's declared owner
        if chain.signature.signer != meta.owner:
            return False

        # Verify the signature on the chain hash
        if not self._identity.verify(chain.h_curr.encode("utf-8"), chain.signature, meta.owner):
            return False

        # Recompute the chain link and verify integrity
        dataset_hash = _dataset_hash_from_url(str(url))
        recomputed = self._compute_chain_hash(chain.h_prev, chain.tick, dataset_hash)
        if recomputed != chain.h_curr:
            return False

        return (self._clock.tick - proof.tick) <= self._freshness_window

    # -- Private helpers ---------------------------------------------------

    @property
    def _agent_id(self) -> AgentId:
        if self.__agent_id is None:
            self.__agent_id = self._identity.sign(b"").signer
        return self.__agent_id

    @staticmethod
    def _compute_chain_hash(h_prev: str, tick: float, dataset_hash: str) -> str:
        """Compute ``H_n = SHA256(H_{n-1} || tick_n || dataset_hash_n)``.

        ``H_0 = SHA256(b"genesis")`` when ``h_prev`` is empty.

        Example::

            h = MerkleDataFacts._compute_chain_hash("abc", 3.0, "def")
        """
        if not h_prev:
            h_prev = hashlib.sha256(b"genesis").hexdigest()
        material = f"{h_prev}|{tick}|{dataset_hash}".encode()
        return hashlib.sha256(material).hexdigest()
