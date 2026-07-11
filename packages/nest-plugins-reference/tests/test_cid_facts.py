# SPDX-License-Identifier: Apache-2.0
"""Tests for the content-addressed DataFacts plugin.

Covers protocol conformance, content-addressing (idempotent republish,
distinct content -> distinct URL), provenance-parent enforcement, signed
freshness (happy path and the forged-claim rejection), ACL enforcement, and
registry wiring.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
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

    @pytest.mark.asyncio
    async def test_fetch_returns_defensive_copy(self) -> None:
        """Mutating a fetched dataset must not mutate the registry."""

        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)

        dataset = DatasetMetadata(
            name="raw",
            owner=AgentId("a1"),
            description="original",
            metadata={"key": "value"},
        )

        url = await facts.publish(dataset)

        fetched = await facts.fetch(url)

        # Attempt to mutate the returned object.
        fetched.description = "tampered"
        fetched.metadata["key"] = "changed"

        fetched_again = await facts.fetch(url)

        assert fetched_again.description == "original"
        assert fetched_again.metadata["key"] == "value"


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

    @pytest.mark.asyncio
    async def test_join_of_two_parents_succeeds(self) -> None:
        """Provenance is a DAG: a dataset may declare more than one parent."""
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        left = await facts.publish(DatasetMetadata(name="orders", owner=AgentId("a1")))
        right = await facts.publish(
            DatasetMetadata(name="customers", owner=AgentId("a1"), description="x")
        )
        joined = DatasetMetadata(
            name="orders_with_customers",
            owner=AgentId("a1"),
            metadata={"parents": [str(left), str(right)]},
        )
        url = await facts.publish(joined)
        fetched = await facts.fetch(url)
        assert set(fetched.metadata["parents"]) == {str(left), str(right)}

    @pytest.mark.asyncio
    async def test_join_is_rejected_if_either_parent_is_unknown(self) -> None:
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        known = await facts.publish(DatasetMetadata(name="orders", owner=AgentId("a1")))
        phantom = "df://sha256-" + "f" * 64
        joined = DatasetMetadata(
            name="orders_with_customers",
            owner=AgentId("a1"),
            metadata={"parents": [str(known), phantom]},
        )
        with pytest.raises(ProvenanceError):
            await facts.publish(joined)
        # The rejected join must not have been partially registered.
        assert phantom not in [str(u) for u in facts.known_urls()]

    @pytest.mark.asyncio
    async def test_join_address_is_independent_of_parent_declaration_order(self) -> None:
        """The same join declared as [A, B] or [B, A] must resolve to one URL.

        Parent order is an artifact of how the publishing agent happened to
        build the list, not part of the dataset's identity -- two joins over
        the same inputs should be the same address regardless of which side
        was listed first.
        """
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        left = await facts.publish(DatasetMetadata(name="orders", owner=AgentId("a1")))
        right = await facts.publish(
            DatasetMetadata(name="customers", owner=AgentId("a1"), description="x")
        )

        forward = DatasetMetadata(
            name="joined", owner=AgentId("a1"), metadata={"parents": [str(left), str(right)]}
        )
        backward = DatasetMetadata(
            name="joined", owner=AgentId("a1"), metadata={"parents": [str(right), str(left)]}
        )
        url_forward = await facts.publish(forward)
        url_backward = await facts.publish(backward)
        assert url_forward == url_backward


# ---------------------------------------------------------------------------
# DAG shape: diamond ancestry, acyclicity, and Merkle tamper-evidence
# ---------------------------------------------------------------------------


class TestDagProperties:
    @pytest.mark.asyncio
    async def test_diamond_ancestor_set_counts_shared_root_once(self) -> None:
        """A -> B, A -> C, {B, C} -> D: D's ancestors are {A, B, C}, A once."""
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        a = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        b = await facts.publish(
            DatasetMetadata(name="b", owner=AgentId("a1"), metadata={"parents": [str(a)]})
        )
        c = await facts.publish(
            DatasetMetadata(name="c", owner=AgentId("a1"), metadata={"parents": [str(a)]})
        )
        d = await facts.publish(
            DatasetMetadata(name="d", owner=AgentId("a1"), metadata={"parents": [str(b), str(c)]})
        )
        assert facts.ancestors(d) == {a, b, c}

    @pytest.mark.asyncio
    async def test_self_reference_is_impossible(self) -> None:
        """A dataset cannot list its own (future) URL as a parent.

        Its URL is the hash of its content *including* parents, so the URL
        isn't known until after the parents are fixed -- you can't close the
        loop. Listing the URL a no-parent version would have produces a
        *different* (and unpublished) URL, so publish rejects it.
        """
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        would_be = content_hash(DatasetMetadata(name="x", owner=AgentId("a1")))
        self_ref = DatasetMetadata(
            name="x", owner=AgentId("a1"), metadata={"parents": [f"df://sha256-{would_be}"]}
        )
        with pytest.raises(ProvenanceError):
            await facts.publish(self_ref)

    @pytest.mark.asyncio
    async def test_no_cycle_can_be_formed(self) -> None:
        """B parents on A; a new A' parenting on B is a *different* node, so A<->B is no cycle."""
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        a = await facts.publish(DatasetMetadata(name="a", owner=AgentId("a1")))
        b = await facts.publish(
            DatasetMetadata(name="b", owner=AgentId("a1"), metadata={"parents": [str(a)]})
        )
        a_prime = await facts.publish(
            DatasetMetadata(name="a", owner=AgentId("a1"), metadata={"parents": [str(b)]})
        )
        # a_prime is a distinct address; the original a does not point back at b.
        assert a_prime != a
        assert facts.ancestors(a) == set()
        assert b not in facts.ancestors(a)

    @pytest.mark.asyncio
    async def test_altering_an_ancestor_re_addresses_every_descendant(self) -> None:
        """Merkle property: tamper with deep history and all downstream URLs change."""
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        facts = CidFacts(ident)
        root = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
        child = await facts.publish(
            DatasetMetadata(name="c", owner=AgentId("a1"), metadata={"parents": [str(root)]})
        )

        tampered_root = await facts.publish(
            DatasetMetadata(name="raw", owner=AgentId("a1"), description="tampered")
        )
        tampered_child = await facts.publish(
            DatasetMetadata(
                name="c", owner=AgentId("a1"), metadata={"parents": [str(tampered_root)]}
            )
        )
        assert tampered_root != root
        assert tampered_child != child


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
# content_hash properties (the substitution defense rests on these holding)
# ---------------------------------------------------------------------------

_descriptions = st.text(max_size=20)
_owners = st.sampled_from(["a1", "a2", "owner", "attacker"])
_schema_versions = st.sampled_from(["1.0", "1.1", "2.0"])


class TestContentHashProperties:
    @settings(max_examples=50)
    @given(owner=_owners, description=_descriptions, schema_version=_schema_versions)
    def test_deterministic_for_identical_fields(
        self, owner: str, description: str, schema_version: str
    ) -> None:
        """Same content fields, hashed twice, must agree -- republishing depends on this."""
        a = DatasetMetadata(
            name="raw", owner=AgentId(owner), description=description, schema_version=schema_version
        )
        b = DatasetMetadata(
            name="raw", owner=AgentId(owner), description=description, schema_version=schema_version
        )
        assert content_hash(a) == content_hash(b)

    @settings(max_examples=50)
    @given(owner=_owners, description=_descriptions)
    def test_name_does_not_affect_address(self, owner: str, description: str) -> None:
        """The label is not content -- renaming a dataset must not change its address."""
        a = DatasetMetadata(name="raw", owner=AgentId(owner), description=description)
        b = DatasetMetadata(name="renamed", owner=AgentId(owner), description=description)
        assert content_hash(a) == content_hash(b)

    @settings(max_examples=50)
    @given(schema_version=_schema_versions)
    def test_schema_version_bump_changes_address(self, schema_version: str) -> None:
        """A schema bump changes content; pinned consumers must not silently see new data."""
        baseline = DatasetMetadata(name="raw", owner=AgentId("a1"), schema_version="1.0")
        if schema_version == "1.0":
            return
        bumped = DatasetMetadata(name="raw", owner=AgentId("a1"), schema_version=schema_version)
        assert content_hash(baseline) != content_hash(bumped)

    def test_owner_change_changes_address(self) -> None:
        """Re-attributing the same bytes to a new owner is a different claim -- new address."""
        a = DatasetMetadata(name="raw", owner=AgentId("a1"))
        b = DatasetMetadata(name="raw", owner=AgentId("a2"))
        assert content_hash(a) != content_hash(b)


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("datafacts", "cid_facts")
        assert cls is CidFacts

    def test_listed_for_datafacts_layer(self) -> None:
        assert ("datafacts", "cid_facts") in PluginRegistry().list_plugins("datafacts")
