# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the content-addressed DataFacts plugin.

Hypothesis drives the invariants the persona stakes the design on:

* content addressing is a deterministic, injective function of *content*;
* volatile timestamps are excluded, so re-publishing identical content is stable;
* canonical serialization is order-independent;
* parents fold into the child hash (Merkle-DAG);
* freshness signatures bind to exactly their payload (no cross-payload forgery).
"""

from __future__ import annotations

from datetime import datetime

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.content_addressed import ContentAddressedDataFacts
from nest_plugins_reference.identity.did_key import DidKeyIdentity

_text = st.text(min_size=0, max_size=24)
_df = ContentAddressedDataFacts()  # content_id is identity-independent and pure
# Build the signing identity once: deriving the simulation RSA keypair (Miller-Rabin
# primality) is expensive, so doing it per Hypothesis example would trip the deadline.
_SIGNER = AgentId("signer-0")
_signer_ident = DidKeyIdentity(_SIGNER, seed=b"prop")


@given(name=_text, desc=_text)
def test_content_id_is_deterministic(name: str, desc: str) -> None:
    meta = DatasetMetadata(name=name, owner=AgentId("a1"), description=desc)
    other = ContentAddressedDataFacts()
    assert _df.content_id(meta) == other.content_id(meta)
    assert _df.content_id(meta).startswith("sha256-")


@given(name1=_text, name2=_text)
def test_distinct_names_yield_distinct_addresses(name1: str, name2: str) -> None:
    a = DatasetMetadata(name=name1, owner=AgentId("a1"))
    b = DatasetMetadata(name=name2, owner=AgentId("a1"))
    assert (_df.content_id(a) == _df.content_id(b)) == (name1 == name2)


@given(t1=st.datetimes(), t2=st.datetimes(), name=_text)
def test_volatile_timestamps_excluded_from_address(t1: datetime, t2: datetime, name: str) -> None:
    """Re-publishing identical content with a new timestamp is the same address."""
    a = DatasetMetadata(name=name, owner=AgentId("a1"), created_at=t1, updated_at=t1)
    b = DatasetMetadata(name=name, owner=AgentId("a1"), created_at=t2, updated_at=t2)
    assert _df.content_id(a) == _df.content_id(b)


@given(
    items=st.dictionaries(
        st.text(min_size=1, max_size=8), st.text(max_size=8), min_size=0, max_size=5
    )
)
def test_metadata_dict_order_irrelevant(items: dict[str, str]) -> None:
    forward = DatasetMetadata(name="x", owner=AgentId("a1"), metadata=dict(items))
    reversed_items = dict(reversed(list(items.items())))
    backward = DatasetMetadata(name="x", owner=AgentId("a1"), metadata=reversed_items)
    assert _df.content_id(forward) == _df.content_id(backward)


@given(p1=_text, p2=_text)
def test_parents_fold_into_child_address(p1: str, p2: str) -> None:
    parent_a = DataFactsUrl(f"df://sha256-{p1}")
    parent_b = DataFactsUrl(f"df://sha256-{p2}")
    child_a = DatasetMetadata(name="c", owner=AgentId("a1"), parents=[parent_a])
    child_b = DatasetMetadata(name="c", owner=AgentId("a1"), parents=[parent_b])
    assert (_df.content_id(child_a) == _df.content_id(child_b)) == (p1 == p2)


@settings(deadline=None)
@given(payload=st.binary(max_size=64), other=st.binary(max_size=64))
def test_signature_binds_to_its_payload(payload: bytes, other: bytes) -> None:
    """A freshness signature verifies its own payload and rejects any other."""
    sig = _signer_ident.sign(payload)
    assert _signer_ident.verify(payload, sig, _SIGNER) is True
    assert _signer_ident.verify(other, sig, _SIGNER) == (other == payload)
