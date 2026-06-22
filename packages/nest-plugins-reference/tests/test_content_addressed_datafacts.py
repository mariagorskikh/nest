# SPDX-License-Identifier: Apache-2.0
"""Tests for the content-addressed DataFacts plugin.

Covers protocol conformance, content-addressing invariants, substitution
resistance, signed freshness proofs, provenance chain validation,
adversarial validators (which must fail for ``datafacts_v1`` and pass for
``content_addressed``), determinism, and plugin registry wiring.
"""

from __future__ import annotations

import pytest
from nest_core.layers.datafacts import DataFacts
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.content_addressed import (
    ContentAddressedDataFacts,
    FreshnessProof,
    canonical_json,
    content_hash,
)
from nest_plugins_reference.datafacts.datafacts_v1 import DataFactsV1
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.validators.datafacts_validators import (
    check_no_stale_freshness,
    check_no_substitution,
    check_provenance_chain_intact,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_identity(agent_id: str = "publisher") -> DidKeyIdentity:
    """Build a deterministic identity for testing."""
    aid = AgentId(agent_id)
    return DidKeyIdentity(aid, seed=b"test-seed")


def _make_plugin(agent_id: str = "publisher") -> ContentAddressedDataFacts:
    """Build a content-addressed DataFacts instance for testing."""
    ident = _make_identity(agent_id)
    return ContentAddressedDataFacts(identity=ident)


def _meta(
    name: str = "test-dataset",
    owner: str = "publisher",
    *,
    description: str = "",
    parents: list[str] | None = None,
) -> DatasetMetadata:
    """Shorthand for building DatasetMetadata in tests."""
    metadata: dict[str, object] = {}
    if parents is not None:
        metadata["parents"] = parents
    return DatasetMetadata(
        name=name,
        owner=AgentId(owner),
        description=description,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_datafacts(self) -> None:
        assert isinstance(_make_plugin(), DataFacts)

    @pytest.mark.asyncio
    async def test_publish_returns_datafacts_url(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"data")
        assert isinstance(url, str)
        assert str(url).startswith("df://sha256-")

    @pytest.mark.asyncio
    async def test_fetch_returns_metadata(self) -> None:
        df = _make_plugin()
        original = _meta(description="test description")
        url = await df.publish(original, payload=b"data")
        fetched = await df.fetch(url)
        assert fetched.name == original.name
        assert fetched.description == original.description

    @pytest.mark.asyncio
    async def test_fetch_missing_raises_key_error(self) -> None:
        df = _make_plugin()
        with pytest.raises(KeyError):
            await df.fetch(DataFactsUrl("df://sha256-nonexistent"))

    @pytest.mark.asyncio
    async def test_request_access_grants_read(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"data")
        grant = await df.request_access(url, AgentId("consumer"))
        assert grant.tier == "read"
        assert grant.grantee == AgentId("consumer")

    @pytest.mark.asyncio
    async def test_request_access_missing_raises_key_error(self) -> None:
        df = _make_plugin()
        with pytest.raises(KeyError):
            await df.request_access(DataFactsUrl("df://sha256-missing"), AgentId("a"))

    @pytest.mark.asyncio
    async def test_verify_freshness_returns_bool(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"data")
        result = await df.verify_freshness(url)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Content addressing invariants
# ---------------------------------------------------------------------------


class TestContentAddressing:
    @pytest.mark.asyncio
    async def test_same_content_same_url(self) -> None:
        df = _make_plugin()
        meta = _meta(description="stable")
        url_a = await df.publish(meta, payload=b"identical")
        url_b = await df.publish(meta, payload=b"identical")
        assert url_a == url_b

    @pytest.mark.asyncio
    async def test_different_content_different_url(self) -> None:
        df = _make_plugin()
        url_a = await df.publish(_meta(description="v1"), payload=b"A")
        url_b = await df.publish(_meta(description="v2"), payload=b"B")
        assert url_a != url_b

    @pytest.mark.asyncio
    async def test_different_payload_different_url(self) -> None:
        df = _make_plugin()
        meta = _meta()
        url_a = await df.publish(meta, payload=b"payload-1")
        url_b = await df.publish(meta, payload=b"payload-2")
        assert url_a != url_b

    @pytest.mark.asyncio
    async def test_url_starts_with_hash_prefix(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"x")
        assert str(url).startswith("df://sha256-")

    @pytest.mark.asyncio
    async def test_content_integrity_self_check(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"data")
        assert df.verify_content_integrity(url) is True

    @pytest.mark.asyncio
    async def test_content_integrity_missing_returns_false(self) -> None:
        df = _make_plugin()
        assert df.verify_content_integrity(DataFactsUrl("df://sha256-bogus")) is False


# ---------------------------------------------------------------------------
# Freshness proofs
# ---------------------------------------------------------------------------


class TestFreshnessProofs:
    @pytest.mark.asyncio
    async def test_publish_creates_proof(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"data")
        proof = df.get_proof(url)
        assert proof is not None
        assert isinstance(proof, FreshnessProof)

    @pytest.mark.asyncio
    async def test_proof_signature_is_valid(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"data")
        result = await df.verify_freshness(url)
        assert result is True

    @pytest.mark.asyncio
    async def test_unpublished_url_has_no_freshness(self) -> None:
        df = _make_plugin()
        result = await df.verify_freshness(DataFactsUrl("df://sha256-never"))
        assert result is False

    @pytest.mark.asyncio
    async def test_proof_records_publisher(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(owner="alice"), payload=b"data")
        proof = df.get_proof(url)
        assert proof is not None
        assert proof.publisher == AgentId("alice")

    @pytest.mark.asyncio
    async def test_proof_records_tick(self) -> None:
        df = _make_plugin()
        df.advance_tick(7)
        url = await df.publish(_meta(), payload=b"data")
        proof = df.get_proof(url)
        assert proof is not None
        assert proof.tick == 7


# ---------------------------------------------------------------------------
# Logical clock
# ---------------------------------------------------------------------------


class TestLogicalClock:
    def test_initial_tick_is_zero(self) -> None:
        df = _make_plugin()
        assert df.tick == 0

    def test_advance_tick(self) -> None:
        df = _make_plugin()
        df.advance_tick(10)
        assert df.tick == 10

    def test_advance_same_tick_is_allowed(self) -> None:
        df = _make_plugin()
        df.advance_tick(5)
        df.advance_tick(5)
        assert df.tick == 5

    def test_rewind_raises(self) -> None:
        df = _make_plugin()
        df.advance_tick(10)
        with pytest.raises(ValueError, match="monotonically"):
            df.advance_tick(5)


# ---------------------------------------------------------------------------
# Provenance chain
# ---------------------------------------------------------------------------


class TestProvenanceChain:
    @pytest.mark.asyncio
    async def test_root_dataset_has_no_parents(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"root")
        assert df.verify_provenance_chain(url) is True

    @pytest.mark.asyncio
    async def test_child_references_parent(self) -> None:
        df = _make_plugin()
        root_url = await df.publish(_meta(name="root"), payload=b"root")
        child_url = await df.publish(
            _meta(name="child", parents=[str(root_url)]),
            payload=b"derived",
        )
        assert df.verify_provenance_chain(child_url) is True

    @pytest.mark.asyncio
    async def test_three_level_chain(self) -> None:
        df = _make_plugin()
        l1 = await df.publish(_meta(name="level-1"), payload=b"l1")
        l2 = await df.publish(
            _meta(name="level-2", parents=[str(l1)]),
            payload=b"l2",
        )
        l3 = await df.publish(
            _meta(name="level-3", parents=[str(l2)]),
            payload=b"l3",
        )
        assert df.verify_provenance_chain(l3) is True

    @pytest.mark.asyncio
    async def test_multiple_parents_dag(self) -> None:
        df = _make_plugin()
        p1 = await df.publish(_meta(name="parent-1"), payload=b"p1")
        p2 = await df.publish(_meta(name="parent-2"), payload=b"p2")
        child = await df.publish(
            _meta(name="merged", parents=[str(p1), str(p2)]),
            payload=b"merged",
        )
        assert df.verify_provenance_chain(child) is True

    @pytest.mark.asyncio
    async def test_publish_with_missing_parent_raises(self) -> None:
        df = _make_plugin()
        with pytest.raises(KeyError, match="parent dataset not found"):
            await df.publish(
                _meta(name="orphan", parents=["df://sha256-nonexistent"]),
                payload=b"data",
            )

    @pytest.mark.asyncio
    async def test_broken_chain_returns_false(self) -> None:
        df = _make_plugin()
        # Directly check that verify_provenance_chain rejects a missing URL.
        assert df.verify_provenance_chain(DataFactsUrl("df://sha256-missing")) is False

    @pytest.mark.asyncio
    async def test_published_urls_returns_insertion_order(self) -> None:
        df = _make_plugin()
        url1 = await df.publish(_meta(name="first"), payload=b"1")
        url2 = await df.publish(_meta(name="second"), payload=b"2")
        assert df.published_urls() == [url1, url2]


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_input_same_hash(self) -> None:
        meta = _meta(name="det-test", description="fixed")
        payload = b"deterministic-payload"

        df_a = _make_plugin()
        df_b = _make_plugin()

        url_a = await df_a.publish(meta, payload=payload)
        url_b = await df_b.publish(meta, payload=payload)
        assert url_a == url_b

    def test_canonical_json_is_stable(self) -> None:
        d1 = {"z": 1, "a": 2, "m": 3}
        d2 = {"a": 2, "m": 3, "z": 1}
        assert canonical_json(d1) == canonical_json(d2)

    def test_content_hash_is_deterministic(self) -> None:
        meta = _meta(name="hash-test")
        h1 = content_hash(meta, b"payload")
        h2 = content_hash(meta, b"payload")
        assert h1 == h2


# ---------------------------------------------------------------------------
# Adversarial validators: content_addressed must pass, datafacts_v1 must fail
# ---------------------------------------------------------------------------


class TestAdversarialValidators:
    @pytest.mark.asyncio
    async def test_substitution_passes_content_addressed(self) -> None:
        ident = _make_identity()
        df = ContentAddressedDataFacts(identity=ident)
        # Register publisher's peer key for cross-verification.
        ident.register_peer(AgentId("validator-pub"), ident.public_key)
        report = await check_no_substitution(df)
        assert report.passed, report.detail

    @pytest.mark.asyncio
    async def test_substitution_fails_datafacts_v1(self) -> None:
        df = DataFactsV1()
        report = await check_no_substitution(df)
        assert not report.passed, "datafacts_v1 should fail the substitution check"

    @pytest.mark.asyncio
    async def test_stale_freshness_passes_content_addressed(self) -> None:
        ident = _make_identity()
        df = ContentAddressedDataFacts(identity=ident)
        ident.register_peer(AgentId("validator-pub"), ident.public_key)
        report = await check_no_stale_freshness(df)
        assert report.passed, report.detail

    @pytest.mark.asyncio
    async def test_stale_freshness_fails_datafacts_v1(self) -> None:
        df = DataFactsV1()
        report = await check_no_stale_freshness(df)
        assert not report.passed, "datafacts_v1 should fail the stale freshness check"

    @pytest.mark.asyncio
    async def test_provenance_passes_content_addressed(self) -> None:
        ident = _make_identity()
        df = ContentAddressedDataFacts(identity=ident)
        ident.register_peer(AgentId("validator-pub"), ident.public_key)
        report = await check_provenance_chain_intact(df)
        assert report.passed, report.detail

    @pytest.mark.asyncio
    async def test_provenance_fails_datafacts_v1(self) -> None:
        df = DataFactsV1()
        report = await check_provenance_chain_intact(df)
        assert not report.passed, "datafacts_v1 should fail the provenance check"


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("datafacts", "content_addressed")
        assert cls is ContentAddressedDataFacts

    def test_listed_for_datafacts_layer(self) -> None:
        plugins = PluginRegistry().list_plugins("datafacts")
        assert ("datafacts", "content_addressed") in plugins

    def test_original_v1_still_resolves(self) -> None:
        cls = PluginRegistry().resolve("datafacts", "datafacts_v1")
        assert cls is DataFactsV1


# ---------------------------------------------------------------------------
# Payload retrieval
# ---------------------------------------------------------------------------


class TestPayloadRetrieval:
    @pytest.mark.asyncio
    async def test_get_payload_returns_stored_bytes(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"binary-blob")
        assert df.get_payload(url) == b"binary-blob"

    @pytest.mark.asyncio
    async def test_get_payload_missing_returns_none(self) -> None:
        df = _make_plugin()
        assert df.get_payload(DataFactsUrl("df://sha256-nope")) is None

    @pytest.mark.asyncio
    async def test_empty_payload_is_valid(self) -> None:
        df = _make_plugin()
        url = await df.publish(_meta(), payload=b"")
        assert df.get_payload(url) == b""
        assert df.verify_content_integrity(url) is True
