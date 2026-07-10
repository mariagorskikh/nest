# SPDX-License-Identifier: Apache-2.0
"""Serialization-invariant content-addressed DataFacts with provenance & freshness.

Prior work on Problem 08 (:mod:`~nest_plugins_reference.datafacts.cid_facts`,
PR #35 and follow-ups) fixed the *name*-substitution attack: URLs became content
hashes, so republishing different content under an old URL is impossible by
construction. This plugin closes the attack that byte-level content addressing
still permits: **encoding substitution / provenance laundering**.

``cid_facts`` binds payloads through ``dataset.checksum`` -- a digest of raw
bytes -- and hashes the metadata dict via ``json.dumps``. Byte-level addressing
means the *same logical dataset*, re-serialized, gets a *new* address:

* re-order CSV columns, re-gzip, or re-export JSON with different whitespace
  -> new ``checksum`` -> new ``df://`` URL;
* write ``{"v": 1.0}`` instead of ``{"v": 1}``, or the same string in unicode
  NFD instead of NFC -> ``json.dumps`` differs -> new URL.

The consequences are silent and nasty: a dataset flagged as poisoned can be
"laundered" by re-encoding -- the re-encoded copy arrives with a clean, fresh
address, no parents, and no link back to the flagged original. Provenance
chains fork, dedup fails, and no validator in the trace can connect the two.

``SicFacts`` addresses datasets by a **canonical structural digest** of their
content, not their bytes. Any two encodings of the same logical content
collapse to one URL (``df://sic-<hex>``), so:

* re-encoding is *idempotent republish* -- history, parents, ACL state, and any
  quarantine flags stay attached;
* actual content changes still produce a new address (tamper still detected);
* provenance parents are resolved at the structural level, so citing a
  re-encoded alias of a parent is citing *the parent itself*.

Everything else Problem 08 requires is kept: provenance is a DAG validated at
publish time, every publish issues a :class:`FreshnessProof` signed by the
publisher's identity-layer key over a logical tick (never wall-clock), and
ACLs key off the content address.

Two scope decisions, stated plainly:

* **Content-less datasets fall back to byte identity.** Structural invariance
  is guaranteed only when ``metadata["content"]`` is present. Without it, the
  address binds ``checksum``/``description`` so distinct datasets keep
  distinct identities -- but that path is byte-sensitive by construction (see
  :func:`content_address`).
* **Ownership is part of the address.** A launderer who re-encodes a dataset
  and reassigns ``owner`` to themselves does mint a fresh URL. This is
  deliberate: the address answers "is this the same content, from the same
  owner", and an ownership change is an attributable signed act, not a silent
  re-serialization. Addressing content independent of owner would make the
  URL a pure content hash and drop the ACL binding -- a different plugin.

Example::

    identity = DidKeyIdentity(AgentId("supplier-0"), seed=b"sim-seed")
    facts = SicFacts(identity)
    a = await facts.publish(DatasetMetadata(
        name="raw", owner=AgentId("supplier-0"),
        metadata={"content": {"rows": [[1, 2], [3, 4]], "unit": "kg"}}))
    b = await facts.publish(DatasetMetadata(
        name="raw-reencoded", owner=AgentId("supplier-0"),
        metadata={"content": {"unit": "kg", "rows": [[1.0, 2.0], [3.0, 4.0]]}}))
    assert a == b  # same logical content, one address
"""

from __future__ import annotations

import hashlib
import math
import unicodedata
from typing import TYPE_CHECKING, Any, cast

from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata, Signature
from pydantic import BaseModel

if TYPE_CHECKING:
    from nest_core.layers.identity import Identity


class ProvenanceError(ValueError):
    """Raised when a dataset declares a parent URL this registry never published.

    Example::

        with pytest.raises(ProvenanceError):
            await facts.publish(DatasetMetadata(
                name="x", owner=AgentId("a1"),
                metadata={"parents": ["df://sic-" + "0" * 64]}))
    """


class CanonicalizationError(ValueError):
    """Raised when content contains values with no canonical form (NaN, inf, non-JSON types).

    Example::

        with pytest.raises(CanonicalizationError):
            structural_digest({"v": float("nan")})
    """


class SharedClock:
    """A monotonic logical tick shared by every per-agent :class:`SicFacts` handle.

    Tier 1 must stay deterministic, so freshness is measured in ticks, never
    ``time.time()``. Pass one instance to every per-agent handle in a scenario
    (mirrors ``cid_facts.SharedClock`` and the shared-``balances`` pattern in
    the ``prepaid_credits`` payments plugin).

    Example::

        clock = SharedClock()
        facts_a = SicFacts(identity_a, clock=clock)
        facts_b = SicFacts(identity_b, clock=clock)
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

    The signed payload binds to the structural content address itself, so a
    proof cannot be transplanted onto a different dataset -- and because
    re-encodings share one address, re-encoding cannot mint a "new" dataset
    to attach a proof to.

    Example::

        proof = FreshnessProof(url=url, tick=3.0, signature=sig)
    """

    url: DataFactsUrl
    tick: float
    signature: Signature


def _freshness_payload(url: DataFactsUrl, tick: float) -> bytes:
    return f'{{"tick":{tick!r},"url":"{url}"}}'.encode()


# ---------------------------------------------------------------------------
# Canonical structural encoding
#
# An injective, type-tagged, length-prefixed byte encoding of JSON-compatible
# structures. Injectivity (distinct canonical values -> distinct byte strings)
# is what makes the digest safe to use as an address: no delimiter ambiguity,
# no "1"/1/True collisions, no nesting confusion.
# ---------------------------------------------------------------------------

_INT_SAFE_FLOAT = 2**53  # beyond this, float(int(x)) is lossy


def _canon_number(value: float) -> bytes:
    """Canonical bytes for a number; int-valued floats normalize to ints.

    ``1`` and ``1.0`` denote the same quantity; serializers disagree about
    which to emit, so the canonical form must not. Non-finite floats have no
    canonical form and are rejected.

    Invariance between int and int-valued float holds only up to
    ``_INT_SAFE_FLOAT`` (2**53). Beyond it, ``float(int(x))`` is lossy, so
    ``{"v": 2**53 + 2}`` and its float re-encoding digest differently.
    Injectivity is preserved in preference to invariance at that boundary.

    Example::

        assert _canon_number(2.0) == _canon_number(2)
    """
    if isinstance(value, float):
        if not math.isfinite(value):
            msg = f"non-finite float has no canonical form: {value!r}"
            raise CanonicalizationError(msg)
        if value.is_integer() and abs(value) <= _INT_SAFE_FLOAT:
            iv = int(value)
            return b"I" + str(iv).encode("ascii")
        return b"F" + repr(value).encode("ascii")
    return b"I" + str(value).encode("ascii")


def _canon(value: object) -> bytes:
    """Encode a JSON-compatible value into canonical, injective bytes.

    Rules: dict keys are NFC-normalized and sorted bytewise; list order is
    significant; strings are NFC-normalized; bools and None are type-tagged
    (so ``True != 1 != "1"``); numbers via :func:`_canon_number`. Every
    variable-length element is length-prefixed, so no delimiter can be forged
    by content.

    Example::

        assert _canon({"a": 1}) == _canon({"a": 1.0})
    """
    if value is None:
        return b"N"
    if isinstance(value, bool):
        return b"T" if value else b"Z"
    if isinstance(value, (int, float)):
        num = _canon_number(value)
        return b"#" + str(len(num)).encode("ascii") + b":" + num
    if isinstance(value, str):
        raw = unicodedata.normalize("NFC", value).encode("utf-8")
        return b"S" + str(len(raw)).encode("ascii") + b":" + raw
    if isinstance(value, list):
        items = [_canon(v) for v in cast("list[object]", value)]
        body = b"".join(items)
        return b"L" + str(len(items)).encode("ascii") + b":" + body
    if isinstance(value, dict):
        entries: list[tuple[bytes, bytes]] = []
        for k, v in cast("dict[object, object]", value).items():
            if not isinstance(k, str):
                msg = f"dict keys must be strings, got {type(k).__name__}"
                raise CanonicalizationError(msg)
            key_raw = unicodedata.normalize("NFC", k).encode("utf-8")
            entries.append((key_raw, _canon(v)))
        entries.sort(key=lambda kv: kv[0])
        body = b"".join(b"K" + str(len(k)).encode("ascii") + b":" + k + v for k, v in entries)
        return b"D" + str(len(entries)).encode("ascii") + b":" + body
    msg = f"type has no canonical form: {type(value).__name__}"
    raise CanonicalizationError(msg)


def structural_digest(content: object) -> str:
    """Hex sha256 of the canonical structural encoding of ``content``.

    This is the serialization-invariant core: any two byte encodings of the
    same logical structure digest identically, and any structural difference
    digests differently.

    Example::

        assert structural_digest({"v": 1}) == structural_digest({"v": 1.0})
        assert structural_digest({"v": 1}) != structural_digest({"v": 2})
    """
    return hashlib.sha256(_canon(content)).hexdigest()


def parents_of(dataset: DatasetMetadata) -> list[DataFactsUrl]:
    """Read the declared provenance parents out of ``dataset.metadata``.

    Example::

        parents = parents_of(derived_dataset)
    """
    raw: object = dataset.metadata.get("parents", [])
    if not isinstance(raw, list):
        return []
    return [DataFactsUrl(str(p)) for p in cast("list[Any]", raw)]


def content_address(dataset: DatasetMetadata) -> str:
    """Compute the serialization-invariant address (hex sha256) of a dataset.

    The address covers the *content-bearing* structure only:

    * ``metadata["content"]`` -- the dataset's structured payload, digested
      via :func:`structural_digest` (the invariance core);
    * declared ``parents`` (sorted -- provenance is order-insensitive);
    * ``owner``, ``schema_version``, ``access_tier`` -- identity-bearing
      fields that legitimately distinguish datasets.

    Deliberately **excluded**: ``name`` (a label), ``description`` (prose),
    ``created_at``/``updated_at`` (wall-clock), and -- unlike ``cid_facts`` --
    ``checksum`` and ``size_bytes``, because both are *encoding artifacts*:
    they change when identical content is re-serialized, which is exactly the
    laundering channel this plugin closes.

    **Checksum fallback.** When ``metadata["content"]`` is absent the dataset
    has no structural identity, so the address binds ``checksum`` and
    ``description`` instead (drop-in compatible with content-less publishers
    such as ``provenance_supply_chain``). Serialization invariance does NOT
    hold on that path -- a re-export gets a new checksum, hence a new address,
    exactly as under ``cid_facts``.

    Example::

        addr = content_address(dataset)
    """
    content: object = dataset.metadata.get("content")
    if content is not None:
        content_binding: object = structural_digest(content)
    else:
        # Checksum fallback: a dataset with no structural content has no
        # structural identity, so bind the byte-level fields instead --
        # otherwise every content-less dataset from one owner/tier collapses
        # onto a single URL (the collision the review surfaced). Invariance
        # does NOT hold on this path: ``checksum`` and ``description`` are
        # encoding artifacts, so a re-export mints a new address, exactly as
        # ``cid_facts`` behaves. Structural invariance is guaranteed only for
        # content-bearing datasets.
        content_binding = {
            "fallback_checksum": dataset.checksum,
            "fallback_description": dataset.description,
        }
    structure = {
        "access_tier": dataset.access_tier,
        "content": content_binding,
        "owner": str(dataset.owner),
        "parents": sorted(str(p) for p in parents_of(dataset)),
        "schema_version": dataset.schema_version,
    }
    return hashlib.sha256(_canon(structure)).hexdigest()


class SicFacts:
    """Serialization-invariant content-addressed DataFacts registry.

    Implements the full :class:`~nest_core.layers.datafacts.DataFacts`
    protocol: publish/fetch by structural content address, provenance-DAG
    validation, identity-signed freshness proofs over logical ticks, and
    hash-keyed ACLs.

    Example::

        facts = SicFacts(DidKeyIdentity(AgentId("a1"), seed=b"s"))
        url = await facts.publish(DatasetMetadata(
            name="raw", owner=AgentId("a1"),
            metadata={"content": {"rows": [1, 2, 3]}}))
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

    @property
    def clock(self) -> SharedClock:
        """This instance's logical clock, so callers can share it with peers.

        Scenario factories that don't import ``sic_facts`` directly wire up a
        shared tick source via ``getattr(handle, "clock", None)`` -- duck
        typing, mirroring ``cid_facts``. Without this property every per-agent
        handle silently builds its own :class:`SharedClock` and cross-agent
        freshness windows are meaningless.

        Example::

            facts_b = SicFacts(identity_b, clock=facts_a.clock)
            assert facts_a.clock is facts_b.clock
        """
        return self._clock

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish dataset metadata; return its serialization-invariant URL.

        Republishing the same *logical* content -- under any encoding, any
        ``name``, any ``checksum`` -- is idempotent: it lands on the existing
        URL and merely extends freshness. The first-published metadata record
        is kept, so quarantine flags or annotations attached to the original
        cannot be shed by a re-encoded copy. Raises :class:`ProvenanceError`
        for parents this registry has never published.

        Example::

            url = await facts.publish(dataset)
        """
        for parent in parents_of(dataset):
            if parent not in self._datasets:
                msg = f"unknown provenance parent {parent!r} for dataset {dataset.name!r}"
                raise ProvenanceError(msg)

        digest = content_address(dataset)
        url = DataFactsUrl(f"df://sic-{digest}")
        if url not in self._datasets:
            self._datasets[url] = dataset

        # A republish only refreshes the stored proof when the publisher IS the
        # kept record's owner. Structural addressing makes every re-encoding
        # land on the same URL, so without this guard any peer could clobber
        # the owner's proof (griefing their freshness) just by republishing.
        # The signer is read off the signature itself -- the Identity protocol
        # exposes no "who am I", but every signature names its signer.
        tick = self._clock.advance()
        signature = self._identity.sign(_freshness_payload(url, tick))
        kept = self._datasets[url]
        if self._proofs.get(url) is None or signature.signer == kept.owner:
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
        return meta

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        """Request access; ACL keys off the structural content address.

        Because re-encodings share one address, an ACL denial cannot be
        bypassed by re-serializing the dataset and asking again under a
        "different" URL. ``access_tier == "public"`` grants any requester
        read access; anything else only the owner.

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
        """Check for a valid, recent, owner-signed freshness proof for ``url``.

        Fails closed: no proof, a bad signature, a signer other than the
        dataset's declared owner, or a proof older than the freshness window
        all read as *not fresh*.

        Example::

            fresh = await facts.verify_freshness(url)
        """
        meta = self._datasets.get(url)
        proof = self._proofs.get(url)
        if meta is None or proof is None:
            return False
        if proof.signature.signer != meta.owner:
            return False
        payload = _freshness_payload(proof.url, proof.tick)
        if not self._identity.verify(payload, proof.signature, meta.owner):
            return False
        return (self._clock.tick - proof.tick) <= self._freshness_window

    def ancestors(self, url: DataFactsUrl) -> set[DataFactsUrl]:
        """Return every transitive provenance ancestor of ``url`` (excluding itself).

        Full DAG walk (diamonds handled; shared roots counted once). Because
        addresses are serialization-invariant, an ancestor cited via a
        re-encoded alias resolves to the ancestor itself -- the chain cannot
        be forked by re-serialization.

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
        """List every URL this registry instance has published, sorted.

        Example::

            urls = facts.known_urls()
        """
        return sorted(self._datasets)
