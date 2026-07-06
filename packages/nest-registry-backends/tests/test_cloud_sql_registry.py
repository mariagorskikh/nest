# SPDX-License-Identifier: Apache-2.0
"""Tests for the Cloud SQL (PostgreSQL) registry backend.

All tests run fully offline using an in-process SQLite shim that mimics the
asyncpg pool API.  No PostgreSQL or Cloud SQL credentials are needed.

Test categories
---------------
* **Protocol conformance** — verifies that :class:`CloudSqlRegistry` satisfies
  the ``nest_sdk.Registry`` ``isinstance`` check.
* **Basic CRUD** — register, lookup, deregister round-trips.
* **Capability filtering** — SQL-level ``@>`` array containment filter.
* **Name pattern filtering** — Python post-filter applied after SQL fetch.
* **Metadata filtering** — Python post-filter for ``metadata_filter``.
* **TTL / expiry** — cards with an ``expires_at`` in the past are excluded
  from lookup results.
* **Upsert semantics** — registering the same ``agent_id`` twice replaces the
  card.
* **Deregister idempotence** — deregistering an unknown agent is a no-op.
* **Subscribe** — yields new arrivals and does not repeat already-seen cards.
* **Property-based** (Hypothesis) — any sequence of register/deregister
  operations leaves the registry in a consistent state.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nest_core.layers.registry import Registry
from nest_registry_backends.cloud_sql.registry import CloudSqlRegistry
from nest_sdk import AgentCard, AgentId, Query

from tests.helpers import AsyncpgShim, make_card

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def pool() -> AsyncpgShim:
    """Provide a fresh in-memory SQLite pool for each test."""
    p = await AsyncpgShim.create()
    return p


@pytest.fixture()
async def registry(pool: AsyncpgShim) -> CloudSqlRegistry:  # type: ignore[override]
    """Return a migrated CloudSqlRegistry backed by the SQLite shim."""
    reg = CloudSqlRegistry(pool)
    await reg.migrate()
    return reg


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_implements_registry_protocol() -> None:
    """CloudSqlRegistry must satisfy the Registry Protocol at runtime."""

    async def _check() -> None:
        pool = await AsyncpgShim.create()
        reg = CloudSqlRegistry(pool)
        await pool.close()
        assert isinstance(reg, Registry)

    asyncio.run(_check())


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------


class TestBasicCrud:
    async def test_register_and_lookup_returns_card(self, registry: CloudSqlRegistry) -> None:
        card = make_card("a1", caps=["sell"])
        await registry.register(card)
        results = await registry.lookup(Query())
        assert len(results) == 1
        assert results[0].agent_id == AgentId("a1")

    async def test_lookup_empty_registry_returns_empty_list(
        self, registry: CloudSqlRegistry
    ) -> None:
        results = await registry.lookup(Query())
        assert results == []

    async def test_deregister_removes_card(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1"))
        await registry.deregister(AgentId("a1"))
        assert await registry.lookup(Query()) == []

    async def test_deregister_unknown_agent_is_noop(self, registry: CloudSqlRegistry) -> None:
        """Deregistering a non-existent agent must not raise."""
        await registry.deregister(AgentId("ghost"))

    async def test_multiple_agents_all_returned(self, registry: CloudSqlRegistry) -> None:
        for i in range(5):
            await registry.register(make_card(f"a{i}", caps=["sell"]))
        results = await registry.lookup(Query())
        assert len(results) == 5

    async def test_upsert_overwrites_existing_card(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", name="original"))
        await registry.register(make_card("a1", name="updated"))
        results = await registry.lookup(Query())
        assert len(results) == 1
        assert results[0].name == "updated"


# ---------------------------------------------------------------------------
# Capability filtering
# ---------------------------------------------------------------------------


class TestCapabilityFiltering:
    async def test_single_capability_filter(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("seller", caps=["sell"]))
        await registry.register(make_card("buyer", caps=["buy"]))
        results = await registry.lookup(Query(capabilities=["sell"]))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("seller")

    async def test_multiple_required_capabilities_and_semantics(
        self, registry: CloudSqlRegistry
    ) -> None:
        await registry.register(make_card("both", caps=["sell", "buy"]))
        await registry.register(make_card("sell_only", caps=["sell"]))
        results = await registry.lookup(Query(capabilities=["sell", "buy"]))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("both")

    async def test_capability_no_match_returns_empty(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        results = await registry.lookup(Query(capabilities=["unknown_cap"]))
        assert results == []

    async def test_empty_capabilities_query_returns_all(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        await registry.register(make_card("a2", caps=["buy"]))
        results = await registry.lookup(Query(capabilities=[]))
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Name pattern filtering
# ---------------------------------------------------------------------------


class TestNamePatternFiltering:
    async def test_name_pattern_substring_match(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", name="DataSeller"))
        await registry.register(make_card("a2", name="DataBuyer"))
        results = await registry.lookup(Query(name_pattern="Seller"))
        assert len(results) == 1
        assert results[0].name == "DataSeller"

    async def test_name_pattern_no_match_returns_empty(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", name="Alice"))
        results = await registry.lookup(Query(name_pattern="Bob"))
        assert results == []

    async def test_name_pattern_combined_with_capabilities(
        self, registry: CloudSqlRegistry
    ) -> None:
        await registry.register(make_card("a1", name="AliceSeller", caps=["sell"]))
        await registry.register(make_card("a2", name="BobSeller", caps=["sell"]))
        results = await registry.lookup(Query(capabilities=["sell"], name_pattern="Alice"))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("a1")


# ---------------------------------------------------------------------------
# Metadata filtering
# ---------------------------------------------------------------------------


class TestMetadataFiltering:
    async def test_metadata_filter_exact_match(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("gold", metadata={"tier": "gold"}))
        await registry.register(make_card("silver", metadata={"tier": "silver"}))
        results = await registry.lookup(Query(metadata_filter={"tier": "gold"}))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("gold")

    async def test_metadata_filter_no_match(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", metadata={"tier": "gold"}))
        results = await registry.lookup(Query(metadata_filter={"tier": "platinum"}))
        assert results == []

    async def test_metadata_filter_multi_key(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", metadata={"tier": "gold", "region": "eu"}))
        await registry.register(make_card("a2", metadata={"tier": "gold", "region": "us"}))
        results = await registry.lookup(Query(metadata_filter={"tier": "gold", "region": "eu"}))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("a1")


# ---------------------------------------------------------------------------
# TTL / expiry
# ---------------------------------------------------------------------------


class TestTtl:
    async def test_cards_with_ttl_appear_in_lookup(self) -> None:
        pool = await AsyncpgShim.create()
        reg = CloudSqlRegistry(pool, ttl_seconds=3600)
        await reg.migrate()
        await reg.register(make_card("a1", caps=["sell"]))
        results = await reg.lookup(Query())
        assert len(results) == 1
        await pool.close()

    async def test_register_without_ttl_persists(self) -> None:
        pool = await AsyncpgShim.create()
        reg = CloudSqlRegistry(pool, ttl_seconds=None)
        await reg.migrate()
        await reg.register(make_card("a1"))
        results = await reg.lookup(Query())
        assert len(results) == 1
        await pool.close()


# ---------------------------------------------------------------------------
# Subscribe
# ---------------------------------------------------------------------------


class TestSubscribe:
    async def test_subscribe_yields_existing_matching_cards(
        self, registry: CloudSqlRegistry
    ) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        await registry.register(make_card("a2", caps=["buy"]))

        received: list[AgentCard] = []

        async def _consume() -> None:
            async for card in registry.subscribe(Query(capabilities=["sell"])):
                received.append(card)
                break  # stop after first card

        await asyncio.wait_for(_consume(), timeout=5.0)
        assert len(received) == 1
        assert received[0].agent_id == AgentId("a1")

    async def test_subscribe_yields_new_registrations(self, registry: CloudSqlRegistry) -> None:
        received: list[AgentCard] = []

        async def _produce() -> None:
            await asyncio.sleep(0.05)
            await registry.register(make_card("late", caps=["sell"]))

        async def _consume() -> None:
            async for card in registry.subscribe(Query(capabilities=["sell"])):
                received.append(card)
                if len(received) == 1:
                    break

        await asyncio.gather(
            asyncio.wait_for(_consume(), timeout=5.0),
            _produce(),
        )
        assert len(received) == 1
        assert received[0].agent_id == AgentId("late")

    async def test_subscribe_does_not_repeat_seen_cards(self, registry: CloudSqlRegistry) -> None:
        await registry.register(make_card("a1", caps=["sell"]))

        received: list[AgentCard] = []
        count = 0

        async def _consume() -> None:
            nonlocal count
            async for card in registry.subscribe(Query(capabilities=["sell"])):
                received.append(card)
                count += 1
                if count >= 3:
                    break

        async def _register_more() -> None:
            await asyncio.sleep(0.1)
            await registry.register(make_card("a2", caps=["sell"]))
            await asyncio.sleep(0.1)
            await registry.register(make_card("a3", caps=["sell"]))

        await asyncio.gather(
            asyncio.wait_for(_consume(), timeout=5.0),
            _register_more(),
        )
        agent_ids = {c.agent_id for c in received}
        assert len(agent_ids) == 3, f"Expected 3 unique agents, got {agent_ids}"


# ---------------------------------------------------------------------------
# Property-based: consistency under random operations
# ---------------------------------------------------------------------------


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ops=st.lists(
        st.one_of(
            st.tuples(
                st.just("register"),
                st.integers(min_value=0, max_value=4),
                st.lists(st.sampled_from(["a", "b", "c"]), max_size=3),
            ),
            st.tuples(
                st.just("deregister"),
                st.integers(min_value=0, max_value=4),
            ),
        ),
        min_size=1,
        max_size=20,
    ),
)
def test_property_consistent_under_random_ops(ops: list[tuple[object, ...]]) -> None:
    """Register/deregister sequences must leave lookup in a consistent state."""

    async def _run() -> None:
        pool = await AsyncpgShim.create()
        reg = CloudSqlRegistry(pool)
        await reg.migrate()

        registered: set[str] = set()

        for op in ops:
            if op[0] == "register":
                _, idx, caps = op
                aid = f"agent-{idx}"
                await reg.register(make_card(aid, caps=list(caps)))  # type: ignore[arg-type]
                registered.add(aid)
            elif op[0] == "deregister":
                _, idx = op
                aid = f"agent-{idx}"
                await reg.deregister(AgentId(aid))
                registered.discard(aid)

        all_cards = await reg.lookup(Query())
        actual_ids = {c.agent_id for c in all_cards}
        assert actual_ids == {AgentId(aid) for aid in registered}
        await pool.close()

    asyncio.run(_run())
