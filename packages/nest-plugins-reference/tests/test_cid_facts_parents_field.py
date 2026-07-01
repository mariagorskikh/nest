# SPDX-License-Identifier: Apache-2.0
"""Tests for the first-class ``DatasetMetadata.parents`` lineage field.

``cid_facts`` originally read provenance parents only from the free-form
``metadata["parents"]`` dict entry. These tests cover the typed ``parents``
field added to :class:`~nest_core.types.DatasetMetadata`: it is preferred when
present, the legacy dict entry still works (backward compatibility), and both
spellings content-address to the *same* URL so lineage is unambiguous.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.cid_facts import (
    CidFacts,
    ProvenanceError,
    parents_of,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity

_PHANTOM = DataFactsUrl("df://sha256-" + "0" * 64)


def _facts(owner: str = "a1") -> CidFacts:
    return CidFacts(DidKeyIdentity(AgentId(owner), seed=b"sim-seed"))


def test_default_parents_is_empty() -> None:
    """A root dataset has no lineage: the field defaults to an empty list."""
    meta = DatasetMetadata(name="raw", owner=AgentId("a1"))
    assert meta.parents == []
    assert parents_of(meta) == []


@pytest.mark.asyncio
async def test_typed_parents_field_is_read() -> None:
    """``parents_of`` and the ancestry walk honour the typed ``parents`` field."""
    facts = _facts()
    root = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
    child = DatasetMetadata(name="clean", owner=AgentId("a1"), parents=[root])
    child_url = await facts.publish(child)
    assert parents_of(child) == [root]
    assert facts.ancestors(child_url) == {root}


@pytest.mark.asyncio
async def test_legacy_dict_parents_still_supported() -> None:
    """The pre-existing ``metadata['parents']`` dict spelling keeps working."""
    facts = _facts()
    root = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
    child = DatasetMetadata(name="clean", owner=AgentId("a1"), metadata={"parents": [str(root)]})
    child_url = await facts.publish(child)
    assert parents_of(child) == [root]
    assert facts.ancestors(child_url) == {root}


@pytest.mark.asyncio
async def test_typed_and_dict_parents_content_address_identically() -> None:
    """Declaring the same parent via the typed field or the dict yields one URL."""
    facts = _facts()
    root = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
    via_field = await facts.publish(
        DatasetMetadata(name="clean", owner=AgentId("a1"), parents=[root])
    )
    via_dict = await facts.publish(
        DatasetMetadata(name="clean", owner=AgentId("a1"), metadata={"parents": [str(root)]})
    )
    assert str(via_field) == str(via_dict)


@pytest.mark.asyncio
async def test_typed_parents_take_precedence_over_dict() -> None:
    """When both are set, the typed field wins — the stray dict parent is ignored."""
    facts = _facts()
    root = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))
    # metadata names a never-published phantom; the typed field names the real root.
    child = DatasetMetadata(
        name="clean",
        owner=AgentId("a1"),
        parents=[root],
        metadata={"parents": [str(_PHANTOM)]},
    )
    child_url = await facts.publish(child)  # must NOT raise on the phantom
    assert facts.ancestors(child_url) == {root}


@pytest.mark.asyncio
async def test_typed_phantom_parent_rejected_at_publish() -> None:
    """A typed parent that was never published is rejected, like the dict form."""
    facts = _facts()
    orphan = DatasetMetadata(name="laundered", owner=AgentId("a1"), parents=[_PHANTOM])
    with pytest.raises(ProvenanceError):
        await facts.publish(orphan)
