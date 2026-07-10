# SPDX-License-Identifier: Apache-2.0
"""Tests for the serialization-invariant DataFacts plugin (``sic_facts``).

Three layers of coverage:

1. Canonicalization unit tests -- invariance where required, sensitivity
   where required, injectivity of the type tags.
2. Base Problem-08 criteria -- content-addressed URLs, provenance DAG,
   signed freshness over logical ticks, hash-keyed ACLs.
3. Adversarial contrast -- the encoding-substitution / provenance-laundering
   attack succeeds against byte-level ``cid_facts`` and is neutralized by
   ``sic_facts``, mirroring how the Problem-08 validators contrast against
   ``datafacts_v1``.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.cid_facts import CidFacts
from nest_plugins_reference.datafacts.sic_facts import (
    CanonicalizationError,
    FreshnessProof,
    ProvenanceError,
    SharedClock,
    SicFacts,
    structural_digest,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity

OWNER = AgentId("supplier-0")
OUTSIDER = AgentId("mallory-0")

# The same logical table, exported by two different serializers:
# ints vs int-valued floats, different key order, NFD vs NFC unicode.
CONTENT_A = {"rows": [[1, 2], [3, 4]], "unit": "kg", "city": "Z\u00fcrich"}
CONTENT_B = {"unit": "kg", "city": "Zu\u0308rich", "rows": [[1.0, 2.0], [3.0, 4.0]]}


def _identity(agent: AgentId = OWNER) -> DidKeyIdentity:
    return DidKeyIdentity(agent, seed=b"sic-test-seed")


def _meta(
    content: object,
    *,
    name: str = "raw",
    checksum: str | None = None,
    size: int | None = None,
    parents: list[str] | None = None,
) -> DatasetMetadata:
    md: dict[str, object] = {"content": content}
    if parents is not None:
        md["parents"] = parents
    return DatasetMetadata(name=name, owner=OWNER, checksum=checksum, size_bytes=size, metadata=md)


# ---------------------------------------------------------------------------
# 1. Canonicalization
# ---------------------------------------------------------------------------


def test_digest_invariant_under_reencoding() -> None:
    """Key order, int/float, and unicode normalization must not change the digest."""
    assert structural_digest(CONTENT_A) == structural_digest(CONTENT_B)


def test_digest_sensitive_to_content_change() -> None:
    """A single changed value must change the digest (tamper detection survives)."""
    tampered = {"rows": [[1, 2], [3, 5]], "unit": "kg", "city": "Z\u00fcrich"}
    assert structural_digest(CONTENT_A) != structural_digest(tampered)


def test_type_tags_are_injective() -> None:
    """1, 1.0 collapse; True, "1", [1], {"": 1}, None all stay distinct."""
    values: list[object] = [1, True, "1", [1], {"": 1}, None]
    digests = {structural_digest(v) for v in values}
    assert len(digests) == len(values)
    assert structural_digest(1) == structural_digest(1.0)


def test_list_order_is_significant_dict_order_is_not() -> None:
    assert structural_digest([1, 2]) != structural_digest([2, 1])
    assert structural_digest({"a": 1, "b": 2}) == structural_digest({"b": 2, "a": 1})


def test_non_canonical_values_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        structural_digest(float("nan"))
    with pytest.raises(CanonicalizationError):
        structural_digest({1: "non-string-key"})


# ---------------------------------------------------------------------------
# 2. Base Problem-08 criteria
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_is_idempotent_across_encodings() -> None:
    facts = SicFacts(_identity())
    url_a = await facts.publish(_meta(CONTENT_A, checksum="sha256:aaaa", size=100))
    url_b = await facts.publish(
        _meta(CONTENT_B, name="raw-export-2", checksum="sha256:bbbb", size=142)
    )
    assert url_a == url_b
    assert str(url_a).startswith("df://sic-")
    assert len(facts.known_urls()) == 1


@pytest.mark.asyncio
async def test_provenance_dag_and_unknown_parent_rejected() -> None:
    facts = SicFacts(_identity())
    root = await facts.publish(_meta({"v": 1}, name="root"))
    left = await facts.publish(_meta({"v": 2}, name="left", parents=[str(root)]))
    right = await facts.publish(_meta({"v": 3}, name="right", parents=[str(root)]))
    join = await facts.publish(_meta({"v": 4}, name="join", parents=[str(left), str(right)]))
    assert facts.ancestors(join) == {root, left, right}
    with pytest.raises(ProvenanceError):
        await facts.publish(_meta({"v": 9}, name="orphan", parents=["df://sic-" + "0" * 64]))


@pytest.mark.asyncio
async def test_freshness_signed_over_logical_ticks() -> None:
    clock = SharedClock()
    facts = SicFacts(_identity(), clock=clock, freshness_window=1.0)
    url = await facts.publish(_meta(CONTENT_A))
    assert await facts.verify_freshness(url) is True
    clock.advance()
    clock.advance()
    assert await facts.verify_freshness(url) is False  # window elapsed
    await facts.publish(_meta(CONTENT_B))  # legitimate re-publish renews
    assert await facts.verify_freshness(url) is True


@pytest.mark.asyncio
async def test_forged_freshness_by_outsider_cannot_clobber() -> None:
    """An outsider republishing identical content cannot replace the owner's
    freshness proof -- publish keeps the stored proof unless the new signer
    matches the kept record's owner, so Mallory's republish is a no-op on
    freshness and the owner's dataset stays fresh."""
    clock = SharedClock()
    store: dict[DataFactsUrl, DatasetMetadata] = {}
    proofs: dict[DataFactsUrl, FreshnessProof] = {}
    owner_facts = SicFacts(_identity(OWNER), datasets=store, proofs=proofs, clock=clock)
    mallory_facts = SicFacts(
        DidKeyIdentity(OUTSIDER, seed=b"mallory"), datasets=store, proofs=proofs, clock=clock
    )
    url = await owner_facts.publish(_meta(CONTENT_A))
    owner_proof = proofs[url]
    await mallory_facts.publish(_meta(CONTENT_B))  # same URL; must NOT clobber the proof
    assert proofs[url] == owner_proof
    assert proofs[url].signature.signer == OWNER
    assert await owner_facts.verify_freshness(url) is True


@pytest.mark.asyncio
async def test_acl_keyed_by_content_address() -> None:
    facts = SicFacts(_identity())
    private = DatasetMetadata(
        name="secret", owner=OWNER, access_tier="restricted", metadata={"content": {"v": 7}}
    )
    url = await facts.publish(private)
    with pytest.raises(PermissionError):
        await facts.request_access(url, OUTSIDER)
    grant = await facts.request_access(url, OWNER)
    assert grant.grantee == OWNER


# ---------------------------------------------------------------------------
# 3. Adversarial contrast: laundering succeeds vs cid_facts, fails vs sic_facts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_laundering_attack_succeeds_against_cid_facts() -> None:
    """Byte-level addressing forks the same logical content into two URLs:
    the re-encoded copy arrives with a clean identity and no provenance link."""
    facts = CidFacts(_identity())
    url_orig = await facts.publish(_meta(CONTENT_A, checksum="sha256:aaaa", size=100))
    url_laundered = await facts.publish(
        _meta(CONTENT_B, name="raw-clean", checksum="sha256:bbbb", size=142)
    )
    assert url_orig != url_laundered  # the attack: history severed


@pytest.mark.asyncio
async def test_laundering_attack_neutralized_by_sic_facts() -> None:
    """Under structural addressing the re-encoded copy lands on the original
    URL: annotations, parents, and quarantine state stay attached."""
    facts = SicFacts(_identity())
    url_orig = await facts.publish(_meta(CONTENT_A, checksum="sha256:aaaa", size=100))
    url_laundered = await facts.publish(
        _meta(CONTENT_B, name="raw-clean", checksum="sha256:bbbb", size=142)
    )
    assert url_orig == url_laundered
    kept = await facts.fetch(url_orig)
    assert kept.name == "raw"  # first-published record retained


@pytest.mark.asyncio
async def test_provenance_fork_via_alias_neutralized() -> None:
    """Citing a re-encoded alias of a parent is citing the parent itself."""
    facts = SicFacts(_identity())
    parent_v1 = await facts.publish(_meta(CONTENT_A, name="parent"))
    parent_v2 = await facts.publish(_meta(CONTENT_B, name="parent-alias"))
    child = await facts.publish(_meta({"v": 10}, name="child", parents=[str(parent_v2)]))
    assert parent_v1 == parent_v2
    assert facts.ancestors(child) == {parent_v1}


# ---------------------------------------------------------------------------
# 4. Checksum fallback for content-less datasets
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_content_less_datasets_do_not_collide() -> None:
    """Regression (review point 1): two content-less datasets from one owner
    must keep distinct identities via the checksum/description fallback."""
    facts = SicFacts(_identity())
    a = await facts.publish(
        DatasetMetadata(name="raw-a", owner=OWNER, checksum="sha256:aaaa", description="lot A")
    )
    b = await facts.publish(
        DatasetMetadata(name="raw-b", owner=OWNER, checksum="sha256:bbbb", description="lot B")
    )
    assert a != b


@pytest.mark.asyncio
async def test_content_less_substitution_still_detected() -> None:
    """The provenance_supply_chain attack shape: a forged republish with a
    different description (same owner, no content) must mint a different URL."""
    facts = SicFacts(_identity())
    original = await facts.publish(
        DatasetMetadata(name="field-x", owner=OWNER, description="genuine readings")
    )
    forged = await facts.publish(
        DatasetMetadata(name="field-x", owner=OWNER, description="tampered-by-attacker")
    )
    assert original != forged


@pytest.mark.asyncio
async def test_content_less_fallback_is_byte_sensitive() -> None:
    """Documented limitation: invariance does NOT hold on the fallback path.
    A re-export (new checksum, same meaning) mints a new address -- exactly
    the cid_facts behavior, confined to datasets without structural content."""
    facts = SicFacts(_identity())
    a = await facts.publish(DatasetMetadata(name="x", owner=OWNER, checksum="sha256:v1"))
    b = await facts.publish(DatasetMetadata(name="x", owner=OWNER, checksum="sha256:v2"))
    assert a != b


# ---------------------------------------------------------------------------
# 5. Property-based canonicalization tests (hypothesis)
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from nest_plugins_reference.datafacts.sic_facts import _canon  # noqa: E402

# ASCII-only keys: canonically-equivalent unicode keys (NFC vs NFD of the same
# text) inside ONE dict would merge under re-encoding and fail spuriously.
_ascii_key = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=8
)

json_value = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53), max_value=2**53)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=12),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(_ascii_key, children, max_size=4)
    ),
    max_leaves=12,
)


def _reencode(value: object) -> object:
    """Preserve structure, change bytes: key order, int->float, NFC->NFD."""
    import unicodedata

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and abs(value) <= 2**53:
        return float(value)
    if isinstance(value, str):
        return unicodedata.normalize("NFD", value)
    if isinstance(value, list):
        return [_reencode(v) for v in value]
    if isinstance(value, dict):
        return {k: _reencode(v) for k, v in reversed(list(value.items()))}
    return value


_SENTINEL = "\x00mutated\x00"


def _mutate(value: object) -> object:
    """Change exactly one leaf to a canonically-distinct value."""
    if isinstance(value, dict):
        if value:
            k = next(iter(value))
            return {**value, k: _mutate(value[k])}
        return {_SENTINEL: 1}
    if isinstance(value, list):
        if value:
            return [_mutate(value[0]), *value[1:]]
        return [_SENTINEL]
    return _SENTINEL if value != _SENTINEL else _SENTINEL + "x"


@settings(max_examples=200)
@given(json_value)
def test_property_digest_invariant_under_reencoding(value: object) -> None:
    """structural_digest(v) == structural_digest(reencode(v)) for arbitrary
    JSON-ish structures under key-shuffle, int->float, and NFC->NFD."""
    assert structural_digest(value) == structural_digest(_reencode(value))


@settings(max_examples=200)
@given(json_value)
def test_property_digest_sensitive_to_mutation(value: object) -> None:
    """Changing one leaf must change the digest (no over-normalization)."""
    assert structural_digest(value) != structural_digest(_mutate(value))


@settings(max_examples=200)
@given(json_value, json_value)
def test_property_digest_collision_free_modulo_canon(a: object, b: object) -> None:
    """Digests agree exactly when canonical encodings agree (injectivity
    spot-check: the digest adds no collisions beyond canonical equality)."""
    assert (structural_digest(a) == structural_digest(b)) == (_canon(a) == _canon(b))


def test_int_float_invariance_stops_at_2_53() -> None:
    """The documented boundary: beyond _INT_SAFE_FLOAT, float(int(x)) is lossy,
    so the int and its float re-encoding digest DIFFERENTLY (injectivity is
    preserved in preference to invariance)."""
    big = 2**53 + 2
    assert structural_digest({"v": big}) != structural_digest({"v": float(big)})
    safe = 2**53
    assert structural_digest({"v": safe}) == structural_digest({"v": float(safe)})
