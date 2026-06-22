# SPDX-License-Identifier: Apache-2.0
"""Tests for the content-addressed DataFacts plugin.

Covers protocol conformance, content-addressing (idempotent republish,
distinct content -> distinct URL), provenance-parent enforcement, signed
freshness (happy path and the forged-claim rejection), ACL enforcement, and
registry wiring.
"""

from __future__ import annotations

import pytest
from nest_core.layers.datafacts import DataFacts
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.cid_facts import (
    CidFacts,
    FreshnessProof,
    ProvenanceError,
    SharedClock,
    content_hash,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity


def _peered_identities(*agent_ids: str) -> dict[str, DidKeyIdentity]:
    idents = {aid: DidKeyIdentity(AgentId(aid), seed=f"seed-{aid}".encode()) for aid in agent_ids}
    for aid, ident in idents.items():
        for peer_id, peer_ident in idents.items():
            if peer_id != aid:
                ident.register_peer(AgentId(peer_id), peer_ident.public_key)
    return idents


# ---------------------------------------------------------------------------
# Protocol conformance and content addressing
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_datafacts(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        assert isinstance(CidFacts(ident), DataFacts)

    @pytest.mark.asyncio
    async def test_publish_returns_content_addressed_url(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        dataset = DatasetMetadata(name="raw", owner=AgentId("a1"))
        url = await facts.publish(dataset)
        assert str(url) == f"df://sha256-{content_hash(dataset)}"

    @pytest.mark.asyncio
    async def test_republish_identical_content_is_idempotent(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        dataset = DatasetMetadata(name="raw", owner=AgentId("a1"))
        url1 = await facts.publish(dataset)
        url2 = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        assert url1 == url2

    @pytest.mark.asyncio
    async def test_different_content_same_name_gets_different_url(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        url1 = await facts.publish(
            DatasetMetadata(name="raw", owner=AgentId("a1"), description="A")
        )
        url2 = await facts.publish(
            DatasetMetadata(name="raw", owner=AgentId("a1"), description="B")
        )
        assert url1 != url2

    @pytest.mark.asyncio
    async def test_fetch_roundtrip(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        dataset = DatasetMetadata(name="raw", owner=AgentId("a1"), description="x")
        url = await facts.publish(dataset)
        fetched = await facts.fetch(url)
        assert fetched == dataset

    @pytest.mark.asyncio
    async def test_fetch_missing_raises_keyerror(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        with pytest.raises(KeyError):
            await facts.fetch("df://sha256-doesnotexist")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


class TestProvenance:
    @pytest.mark.asyncio
    async def test_publish_with_unknown_parent_raises(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        derived = DatasetMetadata(
            name="derived",
            owner=AgentId("a1"),
            metadata={"parents": ["df://sha256-" + "0" * 64]},
        )
        with pytest.raises(ProvenanceError):
            await facts.publish(derived)

    @pytest.mark.asyncio
    async def test_publish_with_known_parent_succeeds(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        parent_url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        derived = DatasetMetadata(
            name="derived", owner=AgentId("a1"), metadata={"parents": [str(parent_url)]}
        )
        url = await facts.publish(derived)
        fetched = await facts.fetch(url)
        assert fetched.metadata["parents"] == [str(parent_url)]

    @pytest.mark.asyncio
    async def test_multi_hop_chain_walkable(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        root = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        mid = await facts.publish(
            DatasetMetadata(name="cleaned", owner=AgentId("a1"), metadata={"parents": [str(root)]})
        )
        leaf = await facts.publish(
            DatasetMetadata(name="report", owner=AgentId("a1"), metadata={"parents": [str(mid)]})
        )
        url = leaf
        depth = 0
        while True:
            meta = await facts.fetch(url)
            depth += 1
            parents = meta.metadata.get("parents", [])
            if not parents:
                break
            url = parents[0]
        assert depth == 3
        assert url == root


# ---------------------------------------------------------------------------
# Signed freshness, including the forged-claim rejection
# ---------------------------------------------------------------------------


class TestFreshness:
    @pytest.mark.asyncio
    async def test_fresh_immediately_after_publish(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        assert await facts.verify_freshness(url) is True

    @pytest.mark.asyncio
    async def test_unpublished_url_is_not_fresh(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        assert await facts.verify_freshness("df://sha256-" + "0" * 64) is False  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_stale_after_window_elapses(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident, freshness_window=0.0)
        url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        # A second, genuinely different publish (distinct content -> distinct
        # URL) advances the shared clock past the window for the first URL.
        await facts.publish(
            DatasetMetadata(name="other", owner=AgentId("a1"), description="distinct")
        )
        assert await facts.verify_freshness(url) is False

    @pytest.mark.asyncio
    async def test_forged_freshness_claim_is_rejected(self) -> None:
        """Republishing the owner's exact content cannot pass off as a genuine freshness claim."""
        idents = _peered_identities("owner", "attacker")
        clock = SharedClock()
        shared_datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        shared_proofs: dict[DataFactsUrl, FreshnessProof] = {}
        owner_facts = CidFacts(
            idents["owner"], datasets=shared_datasets, proofs=shared_proofs, clock=clock
        )
        attacker_facts = CidFacts(
            idents["attacker"], datasets=shared_datasets, proofs=shared_proofs, clock=clock
        )

        dataset = DatasetMetadata(name="weather", owner=AgentId("owner"))
        url = await owner_facts.publish(dataset)
        assert await owner_facts.verify_freshness(url) is True

        forged = DatasetMetadata(name="weather", owner=AgentId("owner"))
        forged_url = await attacker_facts.publish(forged)
        assert forged_url == url
        assert await owner_facts.verify_freshness(url) is False

    @pytest.mark.asyncio
    async def test_genuine_republish_by_owner_stays_fresh(self) -> None:
        idents = _peered_identities("owner", "other")
        clock = SharedClock()
        shared_datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        shared_proofs: dict[DataFactsUrl, FreshnessProof] = {}
        owner_facts = CidFacts(
            idents["owner"], datasets=shared_datasets, proofs=shared_proofs, clock=clock
        )
        url = await owner_facts.publish(DatasetMetadata(name="weather", owner=AgentId("owner")))
        # Owner re-affirms by republishing the identical content again.
        url2 = await owner_facts.publish(DatasetMetadata(name="weather", owner=AgentId("owner")))
        assert url == url2
        assert await owner_facts.verify_freshness(url) is True


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


class TestAccessControl:
    @pytest.mark.asyncio
    async def test_public_dataset_grants_anyone(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        url = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        grant = await facts.request_access(url, AgentId("anyone"))
        assert grant.tier == "read"

    @pytest.mark.asyncio
    async def test_private_dataset_denies_non_owner(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        url = await facts.publish(
            DatasetMetadata(name="secret", owner=AgentId("a1"), access_tier="private")
        )
        with pytest.raises(PermissionError):
            await facts.request_access(url, AgentId("intruder"))

    @pytest.mark.asyncio
    async def test_private_dataset_grants_owner(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        url = await facts.publish(
            DatasetMetadata(name="secret", owner=AgentId("a1"), access_tier="private")
        )
        grant = await facts.request_access(url, AgentId("a1"))
        assert grant.tier == "read"


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("datafacts", "cid_facts")
        assert cls is CidFacts

    def test_listed_for_datafacts_layer(self) -> None:
        assert ("datafacts", "cid_facts") in PluginRegistry().list_plugins("datafacts")
