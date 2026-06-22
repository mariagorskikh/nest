# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the content-addressed DataFacts plugin.

Covers the protocol contract and the three provenance-integrity guarantees the
``provenance-engineer`` persona cares about: content addressing (substitution
resistance), signed freshness proofs, and a tamper-evident provenance DAG.
"""

from __future__ import annotations

import pytest
from nest_core.layers.datafacts import DataFacts
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.content_addressed import (
    BrokenProvenanceError,
    ContentAddressedDataFacts,
    FreshnessProof,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity


def _plugin(
    store: dict[DataFactsUrl, object] | None = None,
    agent: str = "pub-0",
) -> tuple[AgentId, ContentAddressedDataFacts]:
    aid = AgentId(agent)
    ident = DidKeyIdentity(aid, seed=b"test:" + agent.encode())
    return aid, ContentAddressedDataFacts(identity=ident, store=store)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_implements_datafacts_protocol() -> None:
    _aid, df = _plugin()
    assert isinstance(df, DataFacts)


async def test_fetch_missing_raises_keyerror() -> None:
    _aid, df = _plugin()
    with pytest.raises(KeyError):
        await df.fetch(DataFactsUrl("df://sha256-deadbeef"))


# ---------------------------------------------------------------------------
# Content addressing — substitution resistance
# ---------------------------------------------------------------------------


async def test_url_is_content_addressed() -> None:
    aid, df = _plugin()
    url = await df.publish(DatasetMetadata(name="weather", owner=aid))
    assert url.startswith("df://sha256-")


async def test_identical_content_yields_same_url() -> None:
    aid, df = _plugin()
    u1 = await df.publish(DatasetMetadata(name="weather", owner=aid))
    u2 = await df.publish(DatasetMetadata(name="weather", owner=aid))
    assert u1 == u2


@pytest.mark.parametrize(
    "mutate",
    [
        {"description": "changed"},
        {"schema_version": "2.0"},
        {"tags": ["x"]},
        {"size_bytes": 99},
        {"checksum": "abc"},
        {"access_tier": "private"},
        {"metadata": {"payload_hex": "ff"}},
    ],
)
async def test_any_content_change_changes_url(mutate: dict[str, object]) -> None:
    aid, df = _plugin()
    base = DatasetMetadata(name="weather", owner=aid)
    tampered = base.model_copy(update=mutate)
    assert df.url_for(base) != df.url_for(tampered)


async def test_substitution_is_impossible() -> None:
    """Different content under the same name cannot occupy the same address."""
    aid, df = _plugin()
    original = await df.publish(DatasetMetadata(name="prices", owner=aid))
    substitute = await df.publish(DatasetMetadata(name="prices", owner=aid, description="forged"))
    assert original != substitute
    # The original is still intact at its address — not overwritten.
    assert (await df.fetch(original)).description == ""


# ---------------------------------------------------------------------------
# Signed freshness proofs
# ---------------------------------------------------------------------------


async def test_publish_issues_verifiable_freshness_proof() -> None:
    aid, df = _plugin()
    url = await df.publish(DatasetMetadata(name="weather", owner=aid))
    assert await df.verify_freshness(url) is True


async def test_freshness_proof_binds_content_hash() -> None:
    aid, df = _plugin()
    url = await df.publish(DatasetMetadata(name="weather", owner=aid))
    proof = df.issue_freshness_proof(url)
    forged = proof.model_copy(update={"cid": "sha256-forged"})
    assert df.verify_freshness_proof(forged) is False


async def test_freshness_proof_tick_advances_with_clock() -> None:
    aid, df = _plugin()
    df.set_clock(0.0)
    url = await df.publish(DatasetMetadata(name="weather", owner=aid))
    df.set_clock(5.0)
    proof = df.issue_freshness_proof(url)
    assert proof.tick == 5.0
    assert df.verify_freshness_proof(proof) is True


async def test_keyless_plugin_cannot_prove_freshness() -> None:
    """Without an identity there is no signature, so freshness cannot be proven."""
    df = ContentAddressedDataFacts()  # no identity
    url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
    assert await df.verify_freshness(url) is False


def test_unsigned_proof_rejected() -> None:
    df = ContentAddressedDataFacts()
    proof = FreshnessProof(
        url=DataFactsUrl("df://sha256-x"), cid="sha256-x", tick=0.0, signer=AgentId("a1")
    )
    assert df.verify_freshness_proof(proof) is False


# ---------------------------------------------------------------------------
# Provenance DAG
# ---------------------------------------------------------------------------


async def test_parents_fold_into_child_hash() -> None:
    """A child's address depends on its parent's content (Merkle-DAG property)."""
    aid, df = _plugin()
    p1 = await df.publish(DatasetMetadata(name="raw", owner=aid))
    p2 = await df.publish(DatasetMetadata(name="raw", owner=aid, description="different"))
    child_of_p1 = df.url_for(DatasetMetadata(name="clean", owner=aid, parents=[p1]))
    child_of_p2 = df.url_for(DatasetMetadata(name="clean", owner=aid, parents=[p2]))
    assert child_of_p1 != child_of_p2


async def test_broken_provenance_is_rejected() -> None:
    aid, df = _plugin()
    ghost = DataFactsUrl("df://sha256-" + "0" * 64)
    with pytest.raises(BrokenProvenanceError):
        await df.publish(DatasetMetadata(name="forged", owner=aid, parents=[ghost]))


async def test_verify_provenance_walks_full_chain() -> None:
    aid, df = _plugin()
    p0 = await df.publish(DatasetMetadata(name="d0", owner=aid))
    p1 = await df.publish(DatasetMetadata(name="d1", owner=aid, parents=[p0]))
    p2 = await df.publish(DatasetMetadata(name="d2", owner=aid, parents=[p1]))
    assert df.verify_provenance(p2) is True


async def test_verify_provenance_fails_on_unresolvable_url() -> None:
    """A URL whose record is absent (forged or never published) does not resolve."""
    _aid, df = _plugin()
    assert df.verify_provenance(DataFactsUrl("df://sha256-" + "0" * 64)) is False


# ---------------------------------------------------------------------------
# Access control + shared store
# ---------------------------------------------------------------------------


async def test_public_access_granted_to_anyone() -> None:
    aid, df = _plugin()
    url = await df.publish(DatasetMetadata(name="open", owner=aid, access_tier="public"))
    grant = await df.request_access(url, AgentId("stranger"))
    assert grant.tier == "read"


async def test_private_access_denied_to_non_owner() -> None:
    aid, df = _plugin()
    url = await df.publish(DatasetMetadata(name="secret", owner=aid, access_tier="private"))
    with pytest.raises(PermissionError):
        await df.request_access(url, AgentId("stranger"))


async def test_shared_store_is_visible_across_instances() -> None:
    store: dict[DataFactsUrl, object] = {}
    a_id, a = _plugin(store=store, agent="a")
    _b_id, b = _plugin(store=store, agent="b")
    url = await a.publish(DatasetMetadata(name="shared", owner=a_id))
    # b sees a's publish through the shared content-addressed namespace.
    assert (await b.fetch(url)).name == "shared"
