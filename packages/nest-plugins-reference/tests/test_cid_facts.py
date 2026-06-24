# SPDX-License-Identifier: Apache-2.0
"""Tests for the CidFacts content-addressed DataFacts plugin.

Coverage
--------
* URL format is always ``df://sha256-<64-hex-chars>``
* Same content → same URL (idempotent publish)
* Different content → different URL (substitution impossible)
* Freshness proof creation and signature verification
* Tamper detection (proof with wrong payload does not verify)
* Stale-freshness detection (missing proof fails verify_freshness)
* Provenance DAG: parents stored and returned verbatim
* Multiple-parent DAG (provenance is not just a tree)
* Restricted ACL: owner reads, stranger denied
* Public ACL: anyone reads
* Validator cross-checks:
  - FAIL on datafacts_v1 traces (name-based URLs, no proof events)
  - PASS on cid_facts-style synthetic traces
* Scenario-level: provenance_supply_chain factory returns 4 agents
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_identity(agent_id: str, seed: bytes = b"seed"):
    from nest_plugins_reference.identity.did_key import DidKeyIdentity

    return DidKeyIdentity(AgentId(agent_id), seed=seed)


def _make_df(agent_id: str = "a1", seed: bytes = b"seed"):
    from nest_plugins_reference.datafacts.cid_facts import CidFacts

    return CidFacts(_make_identity(agent_id, seed))


# ---------------------------------------------------------------------------
# 1. URL format
# ---------------------------------------------------------------------------


class TestUrlFormat:
    @pytest.mark.asyncio
    async def test_url_is_sha256_prefixed(self) -> None:
        df = _make_df()
        meta = DatasetMetadata(name="weather", owner=AgentId("a1"))
        url = await df.publish(meta)
        assert url.startswith("df://sha256-"), f"unexpected URL: {url}"

    @pytest.mark.asyncio
    async def test_url_hex_is_64_chars(self) -> None:
        df = _make_df()
        meta = DatasetMetadata(name="weather", owner=AgentId("a1"))
        url = await df.publish(meta)
        hex_part = url.removeprefix("df://sha256-")
        assert len(hex_part) == 64, f"hex part length: {len(hex_part)}"
        assert all(c in "0123456789abcdef" for c in hex_part)

    @pytest.mark.asyncio
    async def test_url_not_name_based(self) -> None:
        df = _make_df()
        meta = DatasetMetadata(name="my-dataset", owner=AgentId("a1"))
        url = await df.publish(meta)
        assert "my-dataset" not in url, "URL must not contain the dataset name"


# ---------------------------------------------------------------------------
# 2. Content addressing — idempotency and substitution resistance
# ---------------------------------------------------------------------------


class TestContentAddressing:
    @pytest.mark.asyncio
    async def test_same_content_same_url(self) -> None:
        """Identical content published twice must yield the same URL."""
        df = _make_df()
        meta_a = DatasetMetadata(name="ds", owner=AgentId("a1"), description="same")
        meta_b = DatasetMetadata(name="ds", owner=AgentId("a1"), description="same")
        url_a = await df.publish(meta_a)
        url_b = await df.publish(meta_b)
        assert url_a == url_b

    @pytest.mark.asyncio
    async def test_different_content_different_url(self) -> None:
        """Different content must produce distinct URLs."""
        df = _make_df()
        url_a = await df.publish(
            DatasetMetadata(
                name="ds-A",
                owner=AgentId("a1"),
                description="version A",
            )
        )
        url_b = await df.publish(
            DatasetMetadata(
                name="ds-B",
                owner=AgentId("a1"),
                description="version B",
            )
        )
        assert url_a != url_b

    @pytest.mark.asyncio
    async def test_name_does_not_affect_url(self) -> None:
        """Changing only the human-readable name must not change the content URL."""
        df = _make_df()

        url_a = await df.publish(
            DatasetMetadata(
                name="label-a",
                owner=AgentId("a1"),
                description="same content",
            )
        )
        url_b = await df.publish(
            DatasetMetadata(
                name="label-b",
                owner=AgentId("a1"),
                description="same content",
            )
        )

        assert url_a == url_b

    @pytest.mark.asyncio
    async def test_tag_order_does_not_affect_url(self) -> None:
        df = _make_df()

        first = DatasetMetadata(
            name="a",
            owner=AgentId("a1"),
            tags=["steel", "raw"],
        )

        second = DatasetMetadata(
            name="b",
            owner=AgentId("a1"),
            tags=["raw", "steel"],
        )

        assert await df.publish(first) == await df.publish(second)

    @pytest.mark.asyncio
    async def test_republish_same_name_different_description_is_different_url(self) -> None:
        """Changing any field changes the URL — substitution is impossible."""
        df = _make_df()
        url_v1 = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1"), description="v1"))
        url_v2 = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1"), description="v2"))
        assert url_v1 != url_v2, "same name, different description must not share a URL"

    @pytest.mark.asyncio
    async def test_content_hash_covers_payload_digest(self) -> None:
        """Including a content_sha256 in metadata changes the URL."""
        df = _make_df()
        meta_no_payload = DatasetMetadata(name="ds", owner=AgentId("a1"))
        meta_with_payload = DatasetMetadata(
            name="ds",
            owner=AgentId("a1"),
            metadata={"content_sha256": "abc123"},
        )
        url_a = await df.publish(meta_no_payload)
        url_b = await df.publish(meta_with_payload)
        assert url_a != url_b

    @pytest.mark.asyncio
    async def test_timestamps_do_not_affect_url(self) -> None:
        """Changing timestamps must not change the content-addressed URL."""
        df = _make_df()

        first = DatasetMetadata(
            name="label-a",
            owner=AgentId("a1"),
            description="same content",
            created_at=datetime(2024, 1, 1),
            updated_at=datetime(2024, 1, 2),
        )

        second = DatasetMetadata(
            name="label-b",
            owner=AgentId("a1"),
            description="same content",
            created_at=datetime(2025, 1, 1),
            updated_at=datetime(2025, 1, 2),
        )

        assert await df.publish(first) == await df.publish(second)

    @pytest.mark.asyncio
    async def test_parents_change_url(self) -> None:
        """Adding a parent reference changes the content hash."""
        df = _make_df()
        url_root = await df.publish(DatasetMetadata(name="root", owner=AgentId("a1")))
        url_derived = await df.publish(
            DatasetMetadata(
                name="root",
                owner=AgentId("a1"),
                parents=[url_root],
            )
        )
        assert url_root != url_derived


# ---------------------------------------------------------------------------
# 3. Fetch
# ---------------------------------------------------------------------------


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_returns_original_metadata(self) -> None:
        df = _make_df()
        meta = DatasetMetadata(name="weather", owner=AgentId("a1"), tags=["hot"])
        url = await df.publish(meta)
        fetched = await df.fetch(url)
        assert fetched.name == "weather"
        assert fetched.tags == ["hot"]

    @pytest.mark.asyncio
    async def test_fetch_missing_raises_key_error(self) -> None:
        df = _make_df()
        with pytest.raises(KeyError):
            await df.fetch(DataFactsUrl("df://sha256-" + "0" * 64))

    @pytest.mark.asyncio
    async def test_fetch_preserves_parents(self) -> None:
        df = _make_df()
        parent_url = await df.publish(DatasetMetadata(name="parent", owner=AgentId("a1")))
        child_url = await df.publish(
            DatasetMetadata(
                name="child",
                owner=AgentId("a1"),
                parents=[parent_url],
            )
        )
        fetched = await df.fetch(child_url)
        assert fetched.parents == [parent_url]


# ---------------------------------------------------------------------------
# 4. Freshness proofs
# ---------------------------------------------------------------------------


class TestFreshnessProofs:
    @pytest.mark.asyncio
    async def test_verify_freshness_true_after_publish(self) -> None:
        df = _make_df()
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        assert await df.verify_freshness(url) is True

    @pytest.mark.asyncio
    async def test_verify_freshness_false_unknown_url(self) -> None:
        df = _make_df()
        assert await df.verify_freshness(DataFactsUrl("df://sha256-" + "0" * 64)) is False

    @pytest.mark.asyncio
    async def test_get_freshness_proof_not_none(self) -> None:
        df = _make_df()
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        proof = df.get_freshness_proof(url)
        assert proof is not None

    @pytest.mark.asyncio
    async def test_proof_url_matches(self) -> None:
        df = _make_df()
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        proof = df.get_freshness_proof(url)
        assert proof is not None
        assert proof.url == url

    @pytest.mark.asyncio
    async def test_proof_publisher_matches_agent(self) -> None:
        df = _make_df("supplier-0")
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("supplier-0")))
        proof = df.get_freshness_proof(url)
        assert proof is not None
        assert proof.publisher == AgentId("supplier-0")

    @pytest.mark.asyncio
    async def test_proof_tick_is_float(self) -> None:
        df = _make_df()
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        proof = df.get_freshness_proof(url)
        assert proof is not None
        assert isinstance(proof.tick, float)

    @pytest.mark.asyncio
    async def test_proof_signature_has_bytes(self) -> None:
        df = _make_df()
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        proof = df.get_freshness_proof(url)
        assert proof is not None
        assert len(proof.signature.value) > 0

    @pytest.mark.asyncio
    async def test_proof_no_wall_clock(self) -> None:
        """Logical clock must not use time.time(); tick starts at 0."""
        ticks: list[float] = []
        df = _make_df()

        for i in range(3):
            url = await df.publish(DatasetMetadata(name=f"ds-{i}", owner=AgentId("a1")))
            proof = df.get_freshness_proof(url)
            assert proof is not None
            ticks.append(proof.tick)

        # With itertools.count() the ticks should be 0, 1, 2
        # (or whatever the count is at — they must be monotonically increasing
        # and small, not a Unix timestamp > 1e9).
        for tick in ticks:
            assert tick < 1_000_000, f"tick looks like a wall-clock timestamp: {tick}"
        assert ticks == sorted(ticks), "ticks must be monotonically non-decreasing"


# ---------------------------------------------------------------------------
# 5. Tamper detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    @pytest.mark.asyncio
    async def test_tampered_signature_fails_verify(self) -> None:
        """Manually corrupting the signature bytes must make verify_freshness False."""
        from nest_core.types import Signature

        df = _make_df()
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        proof = df.get_freshness_proof(url)
        assert proof is not None

        # Replace stored proof with a tampered version.
        bad_sig = Signature(
            signer=proof.signature.signer,
            value=bytes(b ^ 0xFF for b in proof.signature.value),
            algorithm=proof.signature.algorithm,
        )
        from nest_core.types import FreshnessProof

        bad_proof = FreshnessProof(
            url=proof.url,
            publisher=proof.publisher,
            tick=proof.tick,
            signature=bad_sig,
        )
        df.proofs[url] = bad_proof  # inject tampered proof
        assert await df.verify_freshness(url) is False

    @pytest.mark.asyncio
    async def test_missing_proof_fails_verify(self) -> None:
        """Removing the proof record must make verify_freshness return False."""
        df = _make_df()
        url = await df.publish(DatasetMetadata(name="ds", owner=AgentId("a1")))
        del df.proofs[url]
        assert await df.verify_freshness(url) is False


# ---------------------------------------------------------------------------
# 6. Provenance DAG
# ---------------------------------------------------------------------------


class TestProvenanceDAG:
    @pytest.mark.asyncio
    async def test_single_parent_stored(self) -> None:
        df = _make_df()
        parent_url = await df.publish(DatasetMetadata(name="p", owner=AgentId("a1")))
        child = DatasetMetadata(name="c", owner=AgentId("a1"), parents=[parent_url])
        child_url = await df.publish(child)
        fetched = await df.fetch(child_url)
        assert fetched.parents == [parent_url]

    @pytest.mark.asyncio
    async def test_multiple_parents_dag(self) -> None:
        """Provenance is a DAG — multiple parents are supported."""
        df = _make_df()
        p1 = await df.publish(DatasetMetadata(name="p1", owner=AgentId("a1")))
        p2 = await df.publish(DatasetMetadata(name="p2", owner=AgentId("a1")))
        child = DatasetMetadata(name="c", owner=AgentId("a1"), parents=[p1, p2])
        child_url = await df.publish(child)
        fetched = await df.fetch(child_url)
        assert set(fetched.parents) == {p1, p2}

    @pytest.mark.asyncio
    async def test_parent_order_does_not_affect_url(self) -> None:
        """Parent order is canonicalized for multi-parent DAG joins."""
        df = _make_df()

        p1 = await df.publish(DatasetMetadata(name="p1", owner=AgentId("a1")))
        p2 = await df.publish(DatasetMetadata(name="p2", owner=AgentId("a1")))

        first = DatasetMetadata(
            name="child-a",
            owner=AgentId("a1"),
            parents=[p1, p2],
        )
        second = DatasetMetadata(
            name="child-b",
            owner=AgentId("a1"),
            parents=[p2, p1],
        )

        assert await df.publish(first) == await df.publish(second)

    @pytest.mark.asyncio
    async def test_unknown_parent_rejected(self) -> None:
        df = _make_df()

        child = DatasetMetadata(
            name="child",
            owner=AgentId("a1"),
            parents=[DataFactsUrl("df://sha256-" + "0" * 64)],
        )

        with pytest.raises(KeyError):
            await df.publish(child)

    @pytest.mark.asyncio
    async def test_no_parents_for_root(self) -> None:
        df = _make_df()
        url = await df.publish(DatasetMetadata(name="root", owner=AgentId("a1")))
        fetched = await df.fetch(url)
        assert fetched.parents == []

    @pytest.mark.asyncio
    async def test_collect_ancestors_walks_full_dag_once(self) -> None:
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            _collect_ancestors,  # pyright: ignore[reportPrivateUsage]
        )

        df = _make_df()

        supplier_a = await df.publish(DatasetMetadata(name="supplier-a", owner=AgentId("s-a")))
        supplier_b = await df.publish(DatasetMetadata(name="supplier-b", owner=AgentId("s-b")))

        manufacturer_a = await df.publish(
            DatasetMetadata(
                name="manufacturer-a",
                owner=AgentId("m-a"),
                parents=[supplier_a, supplier_b],
            )
        )
        manufacturer_b = await df.publish(
            DatasetMetadata(
                name="manufacturer-b",
                owner=AgentId("m-b"),
                parents=[supplier_a, supplier_b],
            )
        )

        distributor = await df.publish(
            DatasetMetadata(
                name="distributor",
                owner=AgentId("d"),
                parents=[manufacturer_a, manufacturer_b],
            )
        )

        ancestors = await _collect_ancestors(df, distributor)

        assert ancestors == {
            supplier_a,
            supplier_b,
            manufacturer_a,
            manufacturer_b,
        }
        assert len(ancestors) == 4

    @pytest.mark.asyncio
    async def test_three_hop_chain(self) -> None:
        """Supplier → manufacturer → distributor provenance chain."""
        df = _make_df()
        supplier_url = await df.publish(DatasetMetadata(name="raw", owner=AgentId("supplier")))
        mfg_url = await df.publish(
            DatasetMetadata(
                name="goods",
                owner=AgentId("mfg"),
                parents=[supplier_url],
            )
        )
        dist_url = await df.publish(
            DatasetMetadata(
                name="shipment",
                owner=AgentId("dist"),
                parents=[mfg_url],
            )
        )

        # Walk chain from distributor back to supplier.
        dist_meta = await df.fetch(dist_url)
        assert dist_meta.parents == [mfg_url]

        mfg_meta = await df.fetch(mfg_url)
        assert mfg_meta.parents == [supplier_url]

        sup_meta = await df.fetch(supplier_url)
        assert sup_meta.parents == []


# ---------------------------------------------------------------------------
# 7. Access control
# ---------------------------------------------------------------------------


class TestAccessControl:
    @pytest.mark.asyncio
    async def test_public_dataset_grants_read_to_anyone(self) -> None:
        df = _make_df("owner")
        url = await df.publish(
            DatasetMetadata(name="pub", owner=AgentId("owner"), access_tier="public")
        )
        grant = await df.request_access(url, AgentId("stranger"))
        assert grant.tier == "read"

    @pytest.mark.asyncio
    async def test_restricted_dataset_grants_owner_read(self) -> None:
        df = _make_df("owner")
        url = await df.publish(
            DatasetMetadata(
                name="priv",
                owner=AgentId("owner"),
                access_tier="restricted",
            )
        )
        grant = await df.request_access(url, AgentId("owner"))
        assert grant.tier == "read"

    @pytest.mark.asyncio
    async def test_restricted_dataset_denies_stranger(self) -> None:
        df = _make_df("owner")
        url = await df.publish(
            DatasetMetadata(
                name="priv",
                owner=AgentId("owner"),
                access_tier="restricted",
            )
        )
        grant = await df.request_access(url, AgentId("stranger"))
        assert grant.tier == "none"

    @pytest.mark.asyncio
    async def test_access_grant_is_idempotent(self) -> None:
        df = _make_df("owner")
        url = await df.publish(
            DatasetMetadata(name="pub", owner=AgentId("owner"), access_tier="public")
        )
        grant1 = await df.request_access(url, AgentId("buyer"))
        grant2 = await df.request_access(url, AgentId("buyer"))
        assert grant1.tier == grant2.tier

    @pytest.mark.asyncio
    async def test_access_unknown_url_raises(self) -> None:
        df = _make_df()
        with pytest.raises(KeyError):
            await df.request_access(DataFactsUrl("df://sha256-" + "0" * 64), AgentId("a2"))


# ---------------------------------------------------------------------------
# 8. Peer key registration
# ---------------------------------------------------------------------------


class TestPeerKeyRegistration:
    @pytest.mark.asyncio
    async def test_verify_peer_proof_after_register_key(self) -> None:
        """A verifier can validate a proof created by a different agent."""
        from nest_plugins_reference.datafacts.cid_facts import CidFacts, proof_payload

        publisher_id = AgentId("publisher")
        verifier_id = AgentId("verifier")

        publisher_identity = _make_identity(publisher_id, seed=b"pub-seed")
        verifier_identity = _make_identity(verifier_id, seed=b"ver-seed")

        publisher_df = CidFacts(publisher_identity)
        verifier_df = CidFacts(verifier_identity)

        # Register publisher's public key with verifier.
        verifier_df.register_peer_key(publisher_id, publisher_identity.public_key)

        url = await publisher_df.publish(DatasetMetadata(name="ds", owner=publisher_id))
        proof = publisher_df.get_freshness_proof(url)
        assert proof is not None

        # Verifier can manually re-verify the proof using the registered key.
        payload = proof_payload(proof.url, proof.publisher, proof.tick)
        ok = verifier_df.identity.verify(payload, proof.signature, publisher_id)
        assert ok is True


# ---------------------------------------------------------------------------
# 9. Validator tests — FAIL on v1-style traces, PASS on CID-style traces
# ---------------------------------------------------------------------------


def _make_send_event(agent: str, to: str, msg: str) -> dict[str, Any]:
    """Minimal trace event compatible with the validator's ``_message_body`` helper."""
    return {"kind": "send", "agent": agent, "to": to, "msg": msg}


class TestValidatorNoSubstitution:
    def test_fails_on_name_based_urls(self) -> None:
        from nest_core.validators import validate_cid_no_substitution

        events = [
            _make_send_event(
                "supplier-0", "manufacturer-0", "publish:df://raw-materials:supplier-0"
            ),
        ]
        results = validate_cid_no_substitution(events)
        assert any(not r.passed for r in results), "should FAIL on name-based URLs"

    def test_passes_on_sha256_urls(self) -> None:
        from nest_core.validators import validate_cid_no_substitution

        sha_url = "df://sha256-" + "a" * 64
        events = [
            _make_send_event("supplier-0", "mfg-0", f"publish:{sha_url}:supplier-0"),
        ]
        results = validate_cid_no_substitution(events)
        assert all(r.passed for r in results), [r.detail for r in results]

    def test_fails_when_no_publish_events(self) -> None:
        from nest_core.validators import validate_cid_no_substitution

        results = validate_cid_no_substitution([])
        assert any(not r.passed for r in results)


class TestValidatorFreshnessProofs:
    def test_fails_when_no_proof_events(self) -> None:
        from nest_core.validators import validate_cid_freshness_proofs

        sha_url = "df://sha256-" + "b" * 64
        events = [
            _make_send_event("supplier-0", "mfg-0", f"publish:{sha_url}:supplier-0"),
            # No freshness_proof: event
        ]
        results = validate_cid_freshness_proofs(events)
        assert any(not r.passed for r in results), "should FAIL — no proof event"

    def test_passes_when_proof_matches_publish(self) -> None:
        from nest_core.validators import validate_cid_freshness_proofs

        sha_url = "df://sha256-" + "c" * 64
        events = [
            _make_send_event("supplier-0", "mfg-0", f"publish:{sha_url}:supplier-0"),
            _make_send_event("supplier-0", "mfg-0", f"freshness_proof:{sha_url}:0:deadbeef"),
        ]
        results = validate_cid_freshness_proofs(events)
        assert all(r.passed for r in results), [r.detail for r in results]

    def test_fails_on_datafacts_v1_trace(self) -> None:
        """datafacts_v1 never emits freshness_proof events → FAIL."""
        from nest_core.validators import validate_cid_freshness_proofs

        # datafacts_v1 trace: only name-based publish events, no proofs.
        events = [
            _make_send_event("supplier-0", "mfg-0", "publish:df://raw-materials:supplier-0"),
        ]
        results = validate_cid_freshness_proofs(events)
        assert any(not r.passed for r in results)


class TestValidatorProvenanceChain:
    def test_fails_when_no_derived_events(self) -> None:
        from nest_core.validators import validate_cid_provenance_chain

        sha_url = "df://sha256-" + "d" * 64
        events = [
            _make_send_event("supplier-0", "mfg-0", f"publish:{sha_url}:supplier-0"),
            # No derived: event
        ]
        results = validate_cid_provenance_chain(events)
        assert any(not r.passed for r in results)

    def test_fails_when_parent_not_published(self) -> None:
        from nest_core.validators import validate_cid_provenance_chain

        child_url = "df://sha256-" + "e" * 64
        ghost_parent = "df://sha256-" + "f" * 64  # never published

        events = [
            _make_send_event("mfg-0", "dist-0", f"publish:{child_url}:mfg-0"),
            _make_send_event("mfg-0", "dist-0", f"derived:{child_url}:{ghost_parent}"),
        ]
        results = validate_cid_provenance_chain(events)
        assert any(not r.passed for r in results), "should FAIL — parent not published"

    def test_passes_when_chain_is_complete(self) -> None:
        from nest_core.validators import validate_cid_provenance_chain

        parent_url = "df://sha256-" + "1" * 64
        child_url = "df://sha256-" + "2" * 64

        events = [
            _make_send_event("supplier-0", "mfg-0", f"publish:{parent_url}:supplier-0"),
            _make_send_event("mfg-0", "dist-0", f"publish:{child_url}:mfg-0"),
            _make_send_event("mfg-0", "dist-0", f"derived:{child_url}:{parent_url}"),
        ]
        results = validate_cid_provenance_chain(events)
        assert all(r.passed for r in results), [r.detail for r in results]

    def test_passes_multi_parent_dag(self) -> None:
        from nest_core.validators import validate_cid_provenance_chain

        p1 = "df://sha256-" + "a" * 64
        p2 = "df://sha256-" + "b" * 64
        child = "df://sha256-" + "c" * 64

        events = [
            _make_send_event("s1", "m", f"publish:{p1}:s1"),
            _make_send_event("s2", "m", f"publish:{p2}:s2"),
            _make_send_event("m", "d", f"publish:{child}:m"),
            # Comma-separated parents
            _make_send_event("m", "d", f"derived:{child}:{p1},{p2}"),
        ]
        results = validate_cid_provenance_chain(events)
        assert all(r.passed for r in results), [r.detail for r in results]


# ---------------------------------------------------------------------------
# 10. Scenario factory
# ---------------------------------------------------------------------------


class TestProvenanceSupplyChainFactory:
    def test_factory_returns_six_agents(self) -> None:
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            provenance_supply_chain_factory,
        )

        config = ScenarioConfig.from_dict(
            {
                "name": "test",
                "tier": 1,
                "task": {
                    "type": "provenance_supply_chain",
                    "config": {"items_per_round": 1, "rounds": 1},
                },
            }
        )
        agents = provenance_supply_chain_factory(config, {})
        assert len(agents) == 6

    def test_factory_agent_ids(self) -> None:
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            provenance_supply_chain_factory,
        )

        config = ScenarioConfig.from_dict({"name": "test", "tier": 1})
        agents = provenance_supply_chain_factory(config, {})
        ids = {str(k) for k in agents}
        assert "supplier-0" in ids
        assert "supplier-1" in ids
        assert "manufacturer-0" in ids
        assert "manufacturer-1" in ids
        assert "distributor-0" in ids
        assert "retailer-0" in ids

    def test_factory_uses_multi_layer_dag(self) -> None:
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            CidDistributorAgent,
            CidManufacturerAgent,
            CidSupplierAgent,
            provenance_supply_chain_factory,
        )

        config = ScenarioConfig.from_dict({"name": "test", "tier": 1})
        agents = provenance_supply_chain_factory(config, {})

        assert isinstance(agents[AgentId("supplier-0")], CidSupplierAgent)
        assert isinstance(agents[AgentId("supplier-1")], CidSupplierAgent)
        assert isinstance(agents[AgentId("manufacturer-0")], CidManufacturerAgent)
        assert isinstance(agents[AgentId("manufacturer-1")], CidManufacturerAgent)
        assert isinstance(agents[AgentId("distributor-0")], CidDistributorAgent)


# ---------------------------------------------------------------------------
# 11. N-way DAG generalization
# ---------------------------------------------------------------------------


class TestNWayDAG:
    def test_factory_custom_counts(self) -> None:
        """Factory respects num_suppliers and num_manufacturers config keys."""
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            provenance_supply_chain_factory,
        )

        config = ScenarioConfig.from_dict(
            {
                "name": "test",
                "tier": 1,
                "task": {
                    "type": "provenance_supply_chain",
                    "config": {"num_suppliers": 3, "num_manufacturers": 3},
                },
            }
        )
        agents = provenance_supply_chain_factory(config, {})
        # 3 suppliers + 3 manufacturers + 1 distributor + 1 retailer = 8
        assert len(agents) == 8
        ids = {str(k) for k in agents}
        for i in range(3):
            assert f"supplier-{i}" in ids
            assert f"manufacturer-{i}" in ids

    def test_factory_defaults_give_six_agents(self) -> None:
        """Default config (num_suppliers=2, num_manufacturers=2) gives 6 agents."""
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            provenance_supply_chain_factory,
        )

        config = ScenarioConfig.from_dict({"name": "test", "tier": 1})
        agents = provenance_supply_chain_factory(config, {})
        assert len(agents) == 6

    def test_manufacturer_threshold_respected(self) -> None:
        """CidManufacturerAgent with num_suppliers=3 waits for 3 URLs."""
        from nest_core.scenarios_builtin.provenance_supply_chain import CidManufacturerAgent

        agent = CidManufacturerAgent(
            AgentId("mfg-0"),
            next_stage=AgentId("dist-0"),
            df=None,
            num_suppliers=3,
        )
        assert agent._num_suppliers == 3  # pyright: ignore[reportPrivateUsage]

    def test_distributor_threshold_respected(self) -> None:
        """CidDistributorAgent with num_manufacturers=3 waits for 3 URLs."""
        from nest_core.scenarios_builtin.provenance_supply_chain import CidDistributorAgent

        agent = CidDistributorAgent(
            AgentId("dist-0"),
            next_stage=AgentId("retailer-0"),
            df=None,
            num_manufacturers=3,
        )
        assert agent._num_manufacturers == 3  # pyright: ignore[reportPrivateUsage]

    def test_factory_single_supplier_single_manufacturer(self) -> None:
        """Edge case: num_suppliers=1, num_manufacturers=1 gives 4 agents."""
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios_builtin.provenance_supply_chain import (
            provenance_supply_chain_factory,
        )

        config = ScenarioConfig.from_dict(
            {
                "name": "test",
                "tier": 1,
                "task": {
                    "type": "provenance_supply_chain",
                    "config": {"num_suppliers": 1, "num_manufacturers": 1},
                },
            }
        )
        agents = provenance_supply_chain_factory(config, {})
        assert len(agents) == 4  # 1 supplier + 1 manufacturer + distributor + retailer
        assert AgentId("supplier-0") in agents
        assert AgentId("manufacturer-0") in agents


# ---------------------------------------------------------------------------
# 12. Provenance audit event
# ---------------------------------------------------------------------------


class TestProvenanceAuditEvent:
    @pytest.mark.asyncio
    async def test_retailer_emits_provenance_audit(self) -> None:
        """CidRetailerAgent emits a provenance_audit: event after successful verification.

        We drive the retailer directly: publish a 3-node DAG (supplier ->
        manufacturer -> distributor) into a shared CidFacts instance, then
        call on_message with a synthetic cid_url payload and verify that the
        resulting outbound messages include a provenance_audit: event.
        """
        from nest_core.scenarios_builtin.provenance_supply_chain import CidRetailerAgent

        df = _make_df("test-agent")

        # Build a minimal 3-hop DAG.
        supplier_url = await df.publish(DatasetMetadata(name="raw", owner=AgentId("supplier-0")))
        mfg_url = await df.publish(
            DatasetMetadata(
                name="goods",
                owner=AgentId("manufacturer-0"),
                parents=[supplier_url],
            )
        )
        dist_url = await df.publish(
            DatasetMetadata(
                name="shipment",
                owner=AgentId("distributor-0"),
                parents=[mfg_url],
            )
        )

        # Capture outbound messages via a simple mock context.
        sent: list[tuple[AgentId, str]] = []

        class _MockCtx:
            async def send(self, to: AgentId, payload: bytes) -> None:
                sent.append((to, payload.decode("utf-8", errors="replace")))

        origin = AgentId("supplier-0")
        retailer = CidRetailerAgent(AgentId("retailer-0"), origin=origin, df=df)

        # Deliver the distributor URL to the retailer.
        cid_msg = f"cid_url:1:0:{dist_url}".encode()
        await retailer.on_message(_MockCtx(), AgentId("distributor-0"), cid_msg)  # pyright: ignore[reportArgumentType]

        msgs = [m for _, m in sent]
        audit_events = [m for m in msgs if m.startswith("provenance_audit:")]
        assert audit_events, f"no provenance_audit event emitted; got: {msgs}"

    @pytest.mark.asyncio
    async def test_provenance_audit_format(self) -> None:
        """provenance_audit event exposes nodes count and sorted ancestor URLs."""
        from nest_core.scenarios_builtin.provenance_supply_chain import CidRetailerAgent

        df = _make_df("test-agent")

        supplier_url = await df.publish(DatasetMetadata(name="raw", owner=AgentId("supplier-0")))
        mfg_url = await df.publish(
            DatasetMetadata(
                name="goods",
                owner=AgentId("manufacturer-0"),
                parents=[supplier_url],
            )
        )
        dist_url = await df.publish(
            DatasetMetadata(
                name="shipment",
                owner=AgentId("distributor-0"),
                parents=[mfg_url],
            )
        )

        sent: list[str] = []

        class _MockCtx:
            async def send(self, to: AgentId, payload: bytes) -> None:
                sent.append(payload.decode("utf-8", errors="replace"))

        retailer = CidRetailerAgent(AgentId("retailer-0"), origin=AgentId("supplier-0"), df=df)
        await retailer.on_message(
            _MockCtx(),  # pyright: ignore[reportArgumentType]
            AgentId("distributor-0"),
            f"cid_url:1:0:{dist_url}".encode(),
        )

        audit = next((m for m in sent if m.startswith("provenance_audit:")), None)
        assert audit is not None

        # Format: provenance_audit:{url}:nodes={n}:ancestors={csv}
        assert f"provenance_audit:{dist_url}" in audit
        assert "nodes=2" in audit, f"expected nodes=2 (mfg + supplier), got: {audit}"
        assert "ancestors=" in audit
        # Both ancestors must appear.
        assert str(supplier_url) in audit
        assert str(mfg_url) in audit

    @pytest.mark.asyncio
    async def test_provenance_audit_multi_parent_dag(self) -> None:
        """provenance_audit correctly counts deduplicated ancestors in a multi-parent DAG."""
        from nest_core.scenarios_builtin.provenance_supply_chain import CidRetailerAgent

        df = _make_df("test-agent")

        # DAG: 2 suppliers -> 1 manufacturer -> distributor (4 ancestors total).
        sup_a = await df.publish(DatasetMetadata(name="s-a", owner=AgentId("s-a")))
        sup_b = await df.publish(DatasetMetadata(name="s-b", owner=AgentId("s-b")))
        mfg = await df.publish(
            DatasetMetadata(
                name="mfg",
                owner=AgentId("mfg-0"),
                parents=[sup_a, sup_b],
            )
        )
        dist_url = await df.publish(
            DatasetMetadata(
                name="shipment",
                owner=AgentId("dist-0"),
                parents=[mfg],
            )
        )

        sent: list[str] = []

        class _MockCtx:
            async def send(self, to: AgentId, payload: bytes) -> None:
                sent.append(payload.decode("utf-8", errors="replace"))

        retailer = CidRetailerAgent(AgentId("retailer-0"), origin=AgentId("s-a"), df=df)
        await retailer.on_message(
            _MockCtx(),  # pyright: ignore[reportArgumentType]
            AgentId("dist-0"),
            f"cid_url:1:0:{dist_url}".encode(),
        )

        audit = next((m for m in sent if m.startswith("provenance_audit:")), None)
        assert audit is not None
        # 3 ancestors: sup_a, sup_b, mfg
        assert "nodes=3" in audit, f"expected nodes=3, got: {audit}"
