# SPDX-License-Identifier: Apache-2.0
"""Content-addressed DataFacts plugin with provenance and signed freshness.

The reference plugin (:class:`~nest_plugins_reference.datafacts.datafacts_v1.DataFactsV1`)
addresses datasets by the publisher's *chosen name* and checks freshness with an
unauthenticated wall-clock read. Both are silently exploitable:

* **Substitution** — republish different content under the same name; nothing
  rejects it, every existing holder of the URL is now pointed at new bytes.
* **Stale-claim** — "freshness" only means *some* publish touched this name
  recently, by anyone, with no proof the content was actually re-validated.
* **Provenance washing** — there is no field linking a derived dataset back to
  the dataset(s) it was built from, so a contamination trail vanishes at the
  first hop.

This plugin fixes all three by construction:

* The URL **is** ``df://sha256-<hex>``, a hash of the dataset's content-bearing
  fields. Two different contents cannot collide on one URL; the same content
  always resolves to the same URL (republishing is idempotent).
* A derived dataset lists its lineage in ``dataset.metadata["parents"]`` (a
  list of parent URLs); :meth:`CidFacts.publish` rejects any parent hash it has
  not itself seen published.
* Every successful publish issues a :class:`FreshnessProof`: the publisher's
  identity-layer key signs ``(url, tick)`` over a logical tick counter (never
  ``time.time()``, so Tier 1 stays deterministic). :meth:`verify_freshness`
  only accepts a proof whose signature both verifies *and* was produced by the
  dataset's declared owner — an outsider re-publishing identical bytes under
  someone else's name cannot manufacture a valid freshness claim for them.

Example::

    identity = DidKeyIdentity(AgentId("supplier-0"), seed=b"sim-seed")
    facts = CidFacts(identity)
    url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("supplier-0")))
    assert await facts.verify_freshness(url) is True
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any, cast

from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata, Signature
from pydantic import BaseModel

if TYPE_CHECKING:
    from nest_core.layers.identity import Identity


class ProvenanceError(ValueError):
    """Raised when a dataset declares a parent URL this registry never published.

    Example::

        with pytest.raises(ProvenanceError):
            await facts.publish(DatasetMetadata(name="x", owner=AgentId("a1"),
                                                 metadata={"parents": ["df://sha256-deadbeef"]}))
    """


class SharedClock:
    """A monotonic logical tick shared by every per-agent :class:`CidFacts` handle.

    Tier 1 must stay deterministic, so freshness is measured in "ticks since
    this clock was created" rather than wall-clock time. Pass one instance to
    every per-agent plugin handle in a scenario so they share one notion of
    "now" (mirrors how the ``prepaid_credits`` payments plugin shares one
    ``balances`` dict across per-agent handles).

    Example::

        clock = SharedClock()
        facts_a = CidFacts(identity_a, clock=clock)
        facts_b = CidFacts(identity_b, clock=clock)
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


class FreshnessProof(BaseModel):
    """A publisher-signed attestation that ``url`` was (re)published at ``tick``.

    The signed payload is ``canonical_json({"url": url, "tick": tick})`` --
    binding the proof to the content hash itself (not just to a name), per the
    anti-pattern warning that a freshness proof must bind to *content*.

    Example::

        proof = FreshnessProof(url=url, tick=3.0, signature=sig)
    """

    url: DataFactsUrl
    tick: float
    signature: Signature


def _freshness_payload(url: DataFactsUrl, tick: float) -> bytes:
    return json.dumps(
        {"url": str(url), "tick": tick}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def content_hash(dataset: DatasetMetadata) -> str:
    """Compute the content-address (hex sha256) of a dataset's content fields.

    Excludes ``name`` (a label, not content) and the wall-clock timestamps
    ``created_at``/``updated_at`` (so republishing byte-identical content
    later does not change its address). Includes ``metadata`` -- which is
    where lineage (``parents``) and any payload digest the caller wants to
    bind in (e.g. ``checksum``) live -- so two datasets with the same name and
    description but different parents necessarily hash differently.

    Example::

        h = content_hash(DatasetMetadata(name="raw", owner=AgentId("a1")))
    """
    content: dict[str, Any] = {
        "owner": str(dataset.owner),
        "description": dataset.description,
        "schema_version": dataset.schema_version,
        "tags": sorted(dataset.tags),
        "size_bytes": dataset.size_bytes,
        "checksum": dataset.checksum,
        "access_tier": dataset.access_tier,
        "metadata": dataset.metadata,
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def parents_of(dataset: DatasetMetadata) -> list[DataFactsUrl]:
    """Read the declared provenance parents out of ``dataset.metadata``.

    Example::

        parents = parents_of(derived_dataset)
    """
    raw: object = dataset.metadata.get("parents", [])
    if not isinstance(raw, list):
        return []
    return [DataFactsUrl(str(p)) for p in cast("list[Any]", raw)]


class CidFacts:
    """Content-addressed DataFacts registry with provenance and signed freshness.

    Example::

        facts = CidFacts(DidKeyIdentity(AgentId("a1"), seed=b"s"))
        url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        meta = await facts.fetch(url)
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
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._clock = clock if clock is not None else SharedClock()
        self._freshness_window = freshness_window

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish dataset metadata and return its content-addressed URL.

        Republishing identical content is idempotent (same URL) but still
        issues a fresh signed proof -- that is the only legitimate way to
        extend a dataset's freshness window. Raises :class:`ProvenanceError`
        if ``dataset.metadata["parents"]`` names a URL this registry has not
        itself published.

        Provenance is a DAG, not a tree -- a dataset can declare more than
        one parent (e.g. a join of two upstream datasets). Parent order is
        not semantically meaningful, so it is normalized (sorted) before
        hashing and storing: declaring the same two parents in either order
        produces the same address.

        Example::

            url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        """
        parents = parents_of(dataset)
        for parent in parents:
            if parent not in self._datasets:
                msg = f"unknown provenance parent {parent!r} for dataset {dataset.name!r}"
                raise ProvenanceError(msg)

        if parents:
            normalized_metadata = dict(dataset.metadata)
            normalized_metadata["parents"] = sorted(str(p) for p in parents)
            dataset = dataset.model_copy(update={"metadata": normalized_metadata})

        digest = content_hash(dataset)
        url = DataFactsUrl(f"df://sha256-{digest}")
        self._datasets[url] = dataset

        tick = self._clock.advance()
        signature = self._identity.sign(_freshness_payload(url, tick))
        self._proofs[url] = FreshnessProof(url=url, tick=tick, signature=signature)
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
        return meta.model_copy(deep=True)

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

        Fails closed: no proof, an unverifiable signature, a signature from
        someone other than the dataset's declared owner, or a proof older
        than the freshness window are all treated as *not fresh*. This is
        what makes a forged claim ("I attest your dataset is fresh" from an
        agent that isn't the owner) unable to pass, unlike the wall-clock
        ``datafacts_v1`` check which trusts whoever last touched the name.

        Example::

            fresh = await facts.verify_freshness(url)
        """
        meta = self._datasets.get(url)
        proof = self._proofs.get(url)
        if meta is None or proof is None:
            return False
        if proof.signature.signer != meta.owner:
            return False
        if not self._identity.verify(
            _freshness_payload(url, proof.tick), proof.signature, meta.owner
        ):
            return False
        return (self._clock.tick - proof.tick) <= self._freshness_window

    def ancestors(self, url: DataFactsUrl) -> set[DataFactsUrl]:
        """Return every transitive provenance ancestor of ``url`` (excluding itself).

        Walks all parents, not just the first, so it is correct on a diamond
        (``A -> B``, ``A -> C``, ``{B, C} -> D``): ``D``'s ancestors are
        ``{A, B, C}`` with ``A`` counted once. Unknown parents are simply not
        expanded (an unpublishable dataset never reached this registry).

        Example::

            assert facts.ancestors(report_url) == {raw_url, cleaned_url}
        """
        seen: set[DataFactsUrl] = set()
        stack: list[DataFactsUrl] = []
        root_meta = self._datasets.get(url)
        if root_meta is not None:
            stack.extend(parents_of(root_meta))
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            meta = self._datasets.get(current)
            if meta is not None:
                stack.extend(parents_of(meta))
        return seen

    def freshness_proof(self, url: DataFactsUrl) -> FreshnessProof | None:
        """Return the raw freshness proof for ``url``, for tests/validators.

        Example::

            proof = facts.freshness_proof(url)
        """
        return self._proofs.get(url)

    def known_urls(self) -> list[DataFactsUrl]:
        """List every URL this registry instance has published.

        Example::

            urls = facts.known_urls()
        """
        return list(self._datasets)

    @property
    def clock(self) -> SharedClock:
        """This instance's logical clock, so callers can share it with peers.

        Scenario factories that don't import ``cid_facts`` directly can still
        wire up a shared clock with ``getattr(handle, "clock", None)`` --
        duck typing, the same way the rest of Nanda Town treats layers as
        structural ``Protocol``\\ s.

        Example::

            clock = facts.clock
            peer = CidFacts(peer_identity, clock=clock)
        """
        return self._clock
