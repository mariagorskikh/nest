# SPDX-License-Identifier: Apache-2.0
"""Tests for the Redis / Memorystore registry backend.

All tests run fully offline using ``fakeredis.aioredis.FakeRedis`` — an
in-memory Redis emulator that mirrors the ``redis.asyncio`` API.  No Redis
server or GCP credentials are needed.

Test categories
---------------
* **Protocol conformance** — verifies that :class:`RedisRegistry` satisfies
  the ``nest_sdk.Registry`` ``isinstance`` check.
* **Basic CRUD** — register, lookup, deregister round-trips.
* **Capability index** — SINTER-based filtering, multi-capability AND semantics.
* **Name pattern filtering** — Python post-filter.
* **Metadata filtering** — Python post-filter for ``metadata_filter``.
* **TTL / expiry** — ensure the TTL is set on agent keys.
* **Upsert semantics** — re-registering the same agent replaces its card and
  refreshes the capability index.
* **Deregister idempotence** — deregistering a non-existent agent is a no-op.
* **Capability index cleanup on deregister** — removed agent disappears from
  capability sets.
* **Capability index cleanup on re-register** — stale capabilities are removed
  when a card's capabilities change.
* **Subscribe** — new-arrival detection and no-repeat guarantee.
* **Property-based** (Hypothesis) — any sequence of register/deregister
  operations leaves the registry in a consistent state.
"""

from __future__ import annotations

import asyncio
from typing import Any

import nest_registry_backends.redis.registry as _redis_mod
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nest_core.layers.registry import Registry
from nest_registry_backends.redis.registry import RedisRegistry
from nest_sdk import AgentCard, AgentId, Query

from tests.helpers import make_card

# Access private key-builder functions for whitebox TTL assertions.
_agent_key = _redis_mod._agent_key  # pyright: ignore[reportPrivateUsage]
_cap_key = _redis_mod._cap_key  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_fake_redis() -> Any:
    """Return a ``FakeRedis`` instance (importable check deferred to call time)."""
    import fakeredis  # type: ignore[import-untyped]
    import fakeredis.aioredis  # type: ignore[import-untyped]

    return fakeredis.aioredis.FakeRedis(decode_responses=False)


@pytest.fixture()
def fake_redis() -> Any:
    return _make_fake_redis()


@pytest.fixture()
def registry(fake_redis: Any) -> RedisRegistry:
    return RedisRegistry(fake_redis, poll_interval_s=0.02)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_implements_registry_protocol(fake_redis: Any) -> None:
    """RedisRegistry must satisfy the Registry Protocol at runtime."""
    reg = RedisRegistry(fake_redis)
    assert isinstance(reg, Registry)


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------


class TestBasicCrud:
    async def test_register_and_lookup_returns_card(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        results = await registry.lookup(Query())
        assert len(results) == 1
        assert results[0].agent_id == AgentId("a1")

    async def test_lookup_empty_registry_returns_empty_list(self, registry: RedisRegistry) -> None:
        results = await registry.lookup(Query())
        assert results == []

    async def test_deregister_removes_card(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1"))
        await registry.deregister(AgentId("a1"))
        results = await registry.lookup(Query())
        assert results == []

    async def test_deregister_unknown_agent_is_noop(self, registry: RedisRegistry) -> None:
        """Deregistering an agent that was never registered must not raise."""
        await registry.deregister(AgentId("ghost"))

    async def test_multiple_agents_all_returned(self, registry: RedisRegistry) -> None:
        for i in range(5):
            await registry.register(make_card(f"a{i}", caps=["sell"]))
        results = await registry.lookup(Query())
        assert len(results) == 5

    async def test_upsert_overwrites_existing_card(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", name="original"))
        await registry.register(make_card("a1", name="updated"))
        results = await registry.lookup(Query())
        assert len(results) == 1
        assert results[0].name == "updated"

    async def test_card_data_round_trips_correctly(self, registry: RedisRegistry) -> None:
        card = make_card(
            "a1",
            name="DataSeller",
            caps=["sell", "negotiate"],
            endpoint="https://example.com/agent",
            metadata={"region": "eu", "tier": "gold"},
        )
        await registry.register(card)
        results = await registry.lookup(Query())
        assert len(results) == 1
        fetched = results[0]
        assert fetched.agent_id == card.agent_id
        assert fetched.name == card.name
        assert set(fetched.capabilities) == set(card.capabilities)
        assert fetched.endpoint == card.endpoint
        assert fetched.metadata == card.metadata


# ---------------------------------------------------------------------------
# Capability index
# ---------------------------------------------------------------------------


class TestCapabilityIndex:
    async def test_single_capability_filter(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("seller", caps=["sell"]))
        await registry.register(make_card("buyer", caps=["buy"]))
        results = await registry.lookup(Query(capabilities=["sell"]))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("seller")

    async def test_multi_capability_and_semantics(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("both", caps=["sell", "buy"]))
        await registry.register(make_card("sell_only", caps=["sell"]))
        results = await registry.lookup(Query(capabilities=["sell", "buy"]))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("both")

    async def test_capability_no_match_returns_empty(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        results = await registry.lookup(Query(capabilities=["unknown_cap"]))
        assert results == []

    async def test_empty_capabilities_query_returns_all(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        await registry.register(make_card("a2", caps=["buy"]))
        results = await registry.lookup(Query())
        assert len(results) == 2

    async def test_deregister_cleans_capability_index(
        self, registry: RedisRegistry, fake_redis: Any
    ) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        await registry.deregister(AgentId("a1"))
        members = await fake_redis.smembers(_cap_key("sell"))
        assert b"a1" not in members and "a1" not in members

    async def test_upsert_removes_stale_capabilities(
        self, registry: RedisRegistry, fake_redis: Any
    ) -> None:
        """When a card loses a capability on re-register, its ID is removed from that set."""
        await registry.register(make_card("a1", caps=["sell", "negotiate"]))
        await registry.register(make_card("a1", caps=["sell"]))
        members = await fake_redis.smembers(_cap_key("negotiate"))
        assert b"a1" not in members and "a1" not in members
        sell_members = await fake_redis.smembers(_cap_key("sell"))
        assert b"a1" in sell_members or "a1" in sell_members


# ---------------------------------------------------------------------------
# Name pattern filtering
# ---------------------------------------------------------------------------


class TestNamePatternFiltering:
    async def test_name_pattern_substring_match(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", name="DataSeller"))
        await registry.register(make_card("a2", name="DataBuyer"))
        results = await registry.lookup(Query(name_pattern="Seller"))
        assert len(results) == 1
        assert results[0].name == "DataSeller"

    async def test_name_pattern_no_match_returns_empty(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", name="Alice"))
        results = await registry.lookup(Query(name_pattern="Bob"))
        assert results == []

    async def test_name_pattern_combined_with_capabilities(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", name="AliceSeller", caps=["sell"]))
        await registry.register(make_card("a2", name="BobSeller", caps=["sell"]))
        results = await registry.lookup(Query(capabilities=["sell"], name_pattern="Alice"))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("a1")


# ---------------------------------------------------------------------------
# Metadata filtering
# ---------------------------------------------------------------------------


class TestMetadataFiltering:
    async def test_metadata_filter_exact_match(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("gold", metadata={"tier": "gold"}))
        await registry.register(make_card("silver", metadata={"tier": "silver"}))
        results = await registry.lookup(Query(metadata_filter={"tier": "gold"}))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("gold")

    async def test_metadata_filter_no_match(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", metadata={"tier": "gold"}))
        results = await registry.lookup(Query(metadata_filter={"tier": "platinum"}))
        assert results == []


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------


class TestTtl:
    async def test_ttl_is_applied_to_agent_key(self, fake_redis: Any) -> None:
        reg = RedisRegistry(fake_redis, ttl_seconds=3600)
        await reg.register(make_card("a1", caps=["sell"]))
        ttl = await fake_redis.ttl(_agent_key(AgentId("a1")))
        # fakeredis returns -1 for no TTL; positive value means TTL was set.
        assert ttl > 0

    async def test_no_ttl_key_persists_indefinitely(self, fake_redis: Any) -> None:
        reg = RedisRegistry(fake_redis, ttl_seconds=None)
        await reg.register(make_card("a1"))
        ttl = await fake_redis.ttl(_agent_key(AgentId("a1")))
        assert ttl == -1  # -1 means no expiry in Redis

    async def test_re_register_refreshes_ttl(self, fake_redis: Any) -> None:
        reg = RedisRegistry(fake_redis, ttl_seconds=3600)
        await reg.register(make_card("a1"))
        await reg.register(make_card("a1", name="v2"))
        ttl = await fake_redis.ttl(_agent_key(AgentId("a1")))
        assert ttl > 0


# ---------------------------------------------------------------------------
# Subscribe
# ---------------------------------------------------------------------------


class TestSubscribe:
    async def test_subscribe_yields_existing_matching_cards(self, registry: RedisRegistry) -> None:
        await registry.register(make_card("a1", caps=["sell"]))
        await registry.register(make_card("a2", caps=["buy"]))

        received: list[AgentCard] = []

        async def _consume() -> None:
            async for card in registry.subscribe(Query(capabilities=["sell"])):
                received.append(card)
                break

        await asyncio.wait_for(_consume(), timeout=5.0)
        assert len(received) == 1
        assert received[0].agent_id == AgentId("a1")

    async def test_subscribe_yields_new_registrations(self, registry: RedisRegistry) -> None:
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

    async def test_subscribe_does_not_repeat_seen_cards(self, registry: RedisRegistry) -> None:
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

    async def test_subscribe_skips_non_matching_cards(self, registry: RedisRegistry) -> None:
        received: list[AgentCard] = []

        async def _produce() -> None:
            await asyncio.sleep(0.03)
            await registry.register(make_card("buyer", caps=["buy"]))
            await asyncio.sleep(0.05)
            await registry.register(make_card("seller", caps=["sell"]))

        async def _consume() -> None:
            async for card in registry.subscribe(Query(capabilities=["sell"])):
                received.append(card)
                break

        await asyncio.gather(
            asyncio.wait_for(_consume(), timeout=5.0),
            _produce(),
        )
        assert len(received) == 1
        assert received[0].agent_id == AgentId("seller")


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
    """Any register/deregister sequence must leave lookup in a consistent state."""

    async def _run() -> None:
        r = _make_fake_redis()
        reg = RedisRegistry(r)
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

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Capability index correctness — property-based
# ---------------------------------------------------------------------------


@settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    caps_a=st.lists(st.sampled_from(["x", "y", "z"]), min_size=1, max_size=3, unique=True),
    caps_b=st.lists(st.sampled_from(["x", "y", "z"]), min_size=1, max_size=3, unique=True),
)
def test_property_capability_index_matches_lookup(caps_a: list[str], caps_b: list[str]) -> None:
    """Lookup by capability always returns the correct set of agent IDs."""

    async def _run() -> None:
        r = _make_fake_redis()
        reg = RedisRegistry(r)
        await reg.register(make_card("agent-a", caps=caps_a))
        await reg.register(make_card("agent-b", caps=caps_b))

        for cap in ["x", "y", "z"]:
            results = await reg.lookup(Query(capabilities=[cap]))
            result_ids = {c.agent_id for c in results}
            expected_ids: set[AgentId] = set()
            if cap in caps_a:
                expected_ids.add(AgentId("agent-a"))
            if cap in caps_b:
                expected_ids.add(AgentId("agent-b"))
            assert result_ids == expected_ids, (
                f"capability={cap!r} → expected {expected_ids}, got {result_ids}"
            )

    asyncio.run(_run())
