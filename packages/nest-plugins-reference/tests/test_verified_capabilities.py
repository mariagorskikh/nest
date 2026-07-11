# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the capability-conformance registry gate.

``VerifiedCapabilitiesRegistry`` wraps an inner registry and filters
``lookup`` results per ``(agent_id, capability)`` pair based on observed
fulfillment/defection evidence, not the agent's self-asserted card alone.
These tests exercise the gate directly, without a scenario, so they pin
the exclusion/re-admission semantics before any scenario-level proof is
built on top of them.

Example::

    reg = VerifiedCapabilitiesRegistry()
    await reg.register(AgentCard(agent_id=AgentId("a1"), name="a1", capabilities=["sell"]))
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.registry.verified_capabilities import (
    VerifiedCapabilitiesRegistry,
)


def _card(agent_id: str, capabilities: list[str]) -> AgentCard:
    return AgentCard(agent_id=AgentId(agent_id), name=agent_id, capabilities=capabilities)


@pytest.mark.asyncio
async def test_bootstrap_first_contact_is_discoverable() -> None:
    """A never-reported agent is discoverable — no evidence yet is not a strike."""
    reg = VerifiedCapabilitiesRegistry()
    await reg.register(_card("seller-0", ["sell"]))

    results = await reg.lookup(Query(capabilities=["sell"]))

    assert [c.agent_id for c in results] == [AgentId("seller-0")]


@pytest.mark.asyncio
async def test_defection_excludes_from_lookup_after_threshold() -> None:
    """After enough observed defections on a capability, the agent stops appearing."""
    reg = VerifiedCapabilitiesRegistry(defection_threshold=1)
    await reg.register(_card("spoofer-0", ["sell"]))

    reg.report_defection(AgentId("spoofer-0"), "sell")
    results = await reg.lookup(Query(capabilities=["sell"]))

    assert results == []


@pytest.mark.asyncio
async def test_defection_on_one_capability_does_not_affect_another() -> None:
    """Exclusion is per-capability: a defection on 'sell' must not hide 'deliver'."""
    reg = VerifiedCapabilitiesRegistry(defection_threshold=1)
    await reg.register(_card("agent-0", ["sell", "deliver"]))

    reg.report_defection(AgentId("agent-0"), "sell")

    sell_results = await reg.lookup(Query(capabilities=["sell"]))
    deliver_results = await reg.lookup(Query(capabilities=["deliver"]))

    assert sell_results == []
    assert [c.agent_id for c in deliver_results] == [AgentId("agent-0")]


@pytest.mark.asyncio
async def test_fulfillment_re_admits_after_defection() -> None:
    """Exclusion is not a permanent blacklist: a later fulfillment clears it."""
    reg = VerifiedCapabilitiesRegistry(defection_threshold=1)
    await reg.register(_card("agent-0", ["sell"]))

    reg.report_defection(AgentId("agent-0"), "sell")
    assert await reg.lookup(Query(capabilities=["sell"])) == []

    reg.report_fulfillment(AgentId("agent-0"), "sell")
    results = await reg.lookup(Query(capabilities=["sell"]))

    assert [c.agent_id for c in results] == [AgentId("agent-0")]


@pytest.mark.asyncio
async def test_defections_below_threshold_do_not_exclude() -> None:
    """A single defection under a higher threshold is tolerated, not punished."""
    reg = VerifiedCapabilitiesRegistry(defection_threshold=2)
    await reg.register(_card("agent-0", ["sell"]))

    reg.report_defection(AgentId("agent-0"), "sell")
    results = await reg.lookup(Query(capabilities=["sell"]))

    assert [c.agent_id for c in results] == [AgentId("agent-0")]


@pytest.mark.asyncio
async def test_honest_agent_never_reported_remains_discoverable() -> None:
    """An agent with no defections ever reported against it is unaffected."""
    reg = VerifiedCapabilitiesRegistry(defection_threshold=1)
    await reg.register(_card("honest-0", ["sell"]))
    await reg.register(_card("spoofer-0", ["sell"]))

    reg.report_defection(AgentId("spoofer-0"), "sell")
    results = await reg.lookup(Query(capabilities=["sell"]))

    assert [c.agent_id for c in results] == [AgentId("honest-0")]


@pytest.mark.asyncio
async def test_deregister_delegates_to_inner_registry() -> None:
    """deregister removes the card from lookups, same as the inner registry."""
    reg = VerifiedCapabilitiesRegistry()
    await reg.register(_card("agent-0", ["sell"]))

    await reg.deregister(AgentId("agent-0"))
    results = await reg.lookup(Query(capabilities=["sell"]))

    assert results == []
