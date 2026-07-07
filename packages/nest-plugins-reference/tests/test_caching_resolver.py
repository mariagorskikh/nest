# SPDX-License-Identifier: Apache-2.0
"""Tests for the caching resolver registry: TTL expiry, negative caching, liveness.

Mixes unit tests, a Hypothesis property test for the TTL invariant, and the charter's
adversarial discrimination: the resolver validators FAIL against the default
``in_memory`` registry and PASS against the ``resolver``.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given
from hypothesis import strategies as st
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.registry.caching_resolver import CachingResolverRegistry
from nest_plugins_reference.registry.in_memory import InMemoryRegistry
from nest_plugins_reference.validators.resolver_validators import run_all_resolver_checks

_CAP = "resolve-me"


def _card(agent_id: str, ttl: float) -> AgentCard:
    return AgentCard(
        agent_id=AgentId(agent_id), name=agent_id, capabilities=[_CAP], metadata={"ttl": ttl}
    )


class TestResolver:
    @pytest.mark.asyncio
    async def test_live_record_resolves(self) -> None:
        reg = CachingResolverRegistry(clock=0.0)
        await reg.register(_card("a", ttl=100.0))
        found = await reg.lookup(Query(capabilities=[_CAP]))
        assert [str(c.agent_id) for c in found] == ["a"]

    @pytest.mark.asyncio
    async def test_expired_record_self_evicts(self) -> None:
        reg = CachingResolverRegistry(clock=0.0)
        await reg.register(_card("ghost", ttl=10.0))
        reg.set_clock(50.0)
        assert await reg.lookup(Query(capabilities=[_CAP])) == []
        assert AgentId("ghost") not in reg.live_agents()

    @pytest.mark.asyncio
    async def test_heartbeat_extends_life(self) -> None:
        reg = CachingResolverRegistry(clock=0.0)
        await reg.register(_card("beat", ttl=10.0))  # expires at 10
        reg.set_clock(5.0)
        await reg.register(_card("beat", ttl=10.0))  # heartbeat -> expires at 15
        reg.set_clock(12.0)
        assert [str(c.agent_id) for c in await reg.lookup(Query(capabilities=[_CAP]))] == ["beat"]

    @pytest.mark.asyncio
    async def test_negative_cache_invalidated_on_register(self) -> None:
        reg = CachingResolverRegistry(clock=0.0)
        assert await reg.lookup(Query(capabilities=[_CAP])) == []  # miss, negatively cached
        await reg.register(_card("late", ttl=100.0))
        found = await reg.lookup(Query(capabilities=[_CAP]))
        assert [str(c.agent_id) for c in found] == ["late"]

    @pytest.mark.asyncio
    async def test_default_ttl_when_metadata_absent(self) -> None:
        reg = CachingResolverRegistry(default_ttl=20.0, clock=0.0)
        await reg.register(AgentCard(agent_id=AgentId("d"), name="d", capabilities=[_CAP]))
        reg.set_clock(30.0)
        assert await reg.lookup(Query(capabilities=[_CAP])) == []

    @pytest.mark.asyncio
    async def test_deregister_removes_before_ttl(self) -> None:
        reg = CachingResolverRegistry(clock=0.0)
        await reg.register(_card("x", ttl=1000.0))
        await reg.deregister(AgentId("x"))
        assert await reg.lookup(Query(capabilities=[_CAP])) == []

    def test_registry_resolves_resolver(self) -> None:
        cls = PluginRegistry().resolve("registry", "resolver")
        assert cls is CachingResolverRegistry


class TestAdversarialDiscrimination:
    """The charter's bar: validators fail the reference registry, pass the new one."""

    @pytest.mark.asyncio
    async def test_in_memory_fails_liveness_checks(self) -> None:
        report = await run_all_resolver_checks(InMemoryRegistry())
        assert not report.passed

    @pytest.mark.asyncio
    async def test_resolver_passes_liveness_checks(self) -> None:
        report = await run_all_resolver_checks(CachingResolverRegistry(clock=0.0))
        assert report.passed


class TestTtlProperty:
    @given(
        ttl=st.floats(min_value=1.0, max_value=1000.0),
        advance=st.floats(min_value=0.0, max_value=2000.0),
    )
    def test_resolvable_iff_within_ttl(self, ttl: float, advance: float) -> None:
        async def run() -> None:
            reg = CachingResolverRegistry(clock=0.0)
            await reg.register(_card("x", ttl=ttl))
            reg.set_clock(advance)
            live = await reg.lookup(Query(capabilities=[_CAP]))
            resolvable = any(str(c.agent_id) == "x" for c in live)
            assert resolvable == (advance < ttl)

        asyncio.run(run())
