# SPDX-License-Identifier: Apache-2.0

"""Tests for the intent-gated DataFacts plugin.

Covers:
- Protocol conformance (IntentGatedFacts is a DataFacts)
- Happy-path: register intent -> publish -> fetch -> verify
- IntentError on publish without intent
- IntentError on expired intent
- One-time-use: second publish on same name requires new intent
- Provenance chains still enforce parent validation (inherited from CidFacts)
- Freshness signing still works (inherited from CidFacts)
- Adversarial validator: surprise-publication attack blocked, passes against
  IntentGatedFacts, fails against datafacts_v1 (documented below)
"""

from __future__ import annotations

import contextlib

import pytest
from nest_core.layers.datafacts import DataFacts
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, DatasetMetadata
from nest_plugins_reference.datafacts.cid_facts import SharedClock
from nest_plugins_reference.datafacts.intent_facts import IntentError, IntentGatedFacts
from nest_plugins_reference.identity.did_key import DidKeyIdentity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_facts(
    agent_id: str = "a1",
    intent_ttl: float = 10.0,
    clock: SharedClock | None = None,
) -> IntentGatedFacts:
    ident = DidKeyIdentity(AgentId(agent_id), seed=f"seed-{agent_id}".encode())
    return IntentGatedFacts(ident, intent_ttl=intent_ttl, clock=clock)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------

class TestProtocolConformance:
    def test_isinstance_datafacts(self) -> None:
        assert isinstance(_make_facts(), DataFacts)

    def test_resolves_from_plugin_registry(self) -> None:
        cls = PluginRegistry().resolve("datafacts", "intent_facts")
        assert cls is IntentGatedFacts

    def test_listed_in_datafacts_layer(self) -> None:
        assert ("datafacts", "intent_facts") in PluginRegistry().list_plugins("datafacts")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestHappyPath:
    @pytest.mark.asyncio
    async def test_register_then_publish_succeeds(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("weather")
        url = await facts.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
        assert str(url).startswith("df://sha256-")

    @pytest.mark.asyncio
    async def test_fetch_after_publish(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("prices")
        dataset = DatasetMetadata(name="prices", owner=AgentId("a1"), description="raw")
        url = await facts.publish(dataset)
        fetched = await facts.fetch(url)
        assert fetched.description == "raw"

    @pytest.mark.asyncio
    async def test_verify_freshness_after_publish(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("prices")
        url = await facts.publish(DatasetMetadata(name="prices", owner=AgentId("a1")))
        assert await facts.verify_freshness(url) is True

    @pytest.mark.asyncio
    async def test_intent_consumed_on_publish(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("weather")
        await facts.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
        assert not facts.has_live_intent("weather")

    @pytest.mark.asyncio
    async def test_intent_log_records_fulfilled_status(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("weather")
        await facts.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
        log = facts.intent_log()
        assert len(log) == 1
        assert log[0].status == "fulfilled"
        assert log[0].fulfilled_at is not None

    @pytest.mark.asyncio
    async def test_second_publish_after_re_registering_intent(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("sensor")
        await facts.publish(DatasetMetadata(name="sensor", owner=AgentId("a1")))
        # Must register again for the second publish
        facts.register_publish_intent("sensor")
        url2 = await facts.publish(
            DatasetMetadata(name="sensor", owner=AgentId("a1"), description="v2")
        )
        assert str(url2).startswith("df://sha256-")

    def test_has_live_intent_true_before_publish(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("data")
        assert facts.has_live_intent("data") is True

    def test_has_live_intent_false_for_unknown_name(self) -> None:
        facts = _make_facts()
        assert facts.has_live_intent("nonexistent") is False


# ---------------------------------------------------------------------------
# Surprise-publication attack — the core adversarial scenario
# ---------------------------------------------------------------------------

class TestSurprisePublicationAttack:
    @pytest.mark.asyncio
    async def test_publish_without_intent_raises_intent_error(self) -> None:
        """Core adversarial check: no prior intent -> publish must fail."""
        facts = _make_facts()
        with pytest.raises(IntentError, match="no registered intent"):
            await facts.publish(DatasetMetadata(name="prices", owner=AgentId("a1")))

    @pytest.mark.asyncio
    async def test_publish_wrong_name_raises_intent_error(self) -> None:
        """Intent for 'weather' does not cover publishing 'prices'."""
        facts = _make_facts()
        facts.register_publish_intent("weather")
        with pytest.raises(IntentError):
            await facts.publish(DatasetMetadata(name="prices", owner=AgentId("a1")))

    @pytest.mark.asyncio
    async def test_intent_is_one_time_use(self) -> None:
        """Second publish without re-registering must fail."""
        facts = _make_facts()
        facts.register_publish_intent("data")
        await facts.publish(DatasetMetadata(name="data", owner=AgentId("a1")))
        with pytest.raises(IntentError, match="no registered intent"):
            await facts.publish(
                DatasetMetadata(name="data", owner=AgentId("a1"), description="v2")
            )


# ---------------------------------------------------------------------------
# Expired-intent replay attack
# ---------------------------------------------------------------------------

class TestExpiredIntentAttack:
    @pytest.mark.asyncio
    async def test_expired_intent_raises_intent_error(self) -> None:
        """Intents that elapse before publish() is called are rejected."""
        clock = SharedClock()
        facts = _make_facts(clock=clock, intent_ttl=2.0)

        facts.register_publish_intent("sensor")
        # Advance clock past intent TTL
        clock.tick += 5.0

        with pytest.raises(IntentError, match="expired"):
            await facts.publish(DatasetMetadata(name="sensor", owner=AgentId("a1")))

    @pytest.mark.asyncio
    async def test_expired_intent_marked_in_log(self) -> None:
        clock = SharedClock()
        facts = _make_facts(clock=clock, intent_ttl=2.0)
        facts.register_publish_intent("sensor")
        clock.tick += 5.0
        with pytest.raises(IntentError):
            await facts.publish(DatasetMetadata(name="sensor", owner=AgentId("a1")))
        log = facts.intent_log()
        assert log[0].status == "expired"

    @pytest.mark.asyncio
    async def test_intent_within_ttl_still_accepted(self) -> None:
        clock = SharedClock()
        facts = _make_facts(clock=clock, intent_ttl=10.0)
        facts.register_publish_intent("sensor")
        # Advance clock to just before expiry
        clock.tick += 9.0
        url = await facts.publish(DatasetMetadata(name="sensor", owner=AgentId("a1")))
        assert str(url).startswith("df://sha256-")


# ---------------------------------------------------------------------------
# Intent-hijack across separate instances (shared clock, shared state)
# ---------------------------------------------------------------------------

class TestIntentHijackAttack:
    @pytest.mark.asyncio
    async def test_agent_b_cannot_use_agent_a_intent(self) -> None:
        """Agent B registers intent but tries to publish a dataset owned by A.

        The intent is tied to the *instance's* identity, not dataset.owner.
        Agent B's intent for 'weather' only covers B publishing 'weather',
        not A publishing 'weather'.
        """
        clock = SharedClock()
        ident_a = DidKeyIdentity(AgentId("a1"), seed=b"seed-a")
        ident_b = DidKeyIdentity(AgentId("b1"), seed=b"seed-b")

        facts_a = IntentGatedFacts(ident_a, clock=clock)
        facts_b = IntentGatedFacts(ident_b, clock=clock)

        # Only B registers an intent; A has none
        facts_b.register_publish_intent("weather")

        # A tries to publish — no intent registered on A's instance
        with pytest.raises(IntentError, match="no registered intent"):
            await facts_a.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))


# ---------------------------------------------------------------------------
# Inherited CidFacts behaviour still works
# ---------------------------------------------------------------------------

class TestInheritedCidFacts:
    @pytest.mark.asyncio
    async def test_provenance_parent_still_enforced(self) -> None:
        """Provenance validation from CidFacts is preserved."""
        facts = _make_facts()
        facts.register_publish_intent("derived")
        from nest_plugins_reference.datafacts.cid_facts import ProvenanceError

        with pytest.raises(ProvenanceError):
            await facts.publish(
                DatasetMetadata(
                    name="derived",
                    owner=AgentId("a1"),
                    metadata={"parents": ["df://sha256-" + "0" * 64]},
                )
            )

    @pytest.mark.asyncio
    async def test_content_addressing_is_deterministic(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("data")
        url1 = await facts.publish(DatasetMetadata(name="data", owner=AgentId("a1")))
        facts.register_publish_intent("data")
        url2 = await facts.publish(DatasetMetadata(name="data", owner=AgentId("a1")))
        assert url1 == url2

    @pytest.mark.asyncio
    async def test_different_content_gives_different_url(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("data")
        url1 = await facts.publish(
            DatasetMetadata(name="data", owner=AgentId("a1"), description="v1")
        )
        facts.register_publish_intent("data")
        url2 = await facts.publish(
            DatasetMetadata(name="data", owner=AgentId("a1"), description="v2")
        )
        assert url1 != url2

    @pytest.mark.asyncio
    async def test_freshness_stale_after_window(self) -> None:
        clock = SharedClock()
        ident = DidKeyIdentity(AgentId("a1"), seed=b"s")
        # freshness_window=0 means only fresh at the exact publish tick
        facts = IntentGatedFacts(ident, clock=clock, freshness_window=0.0)
        facts.register_publish_intent("data")
        url = await facts.publish(DatasetMetadata(name="data", owner=AgentId("a1")))
        # Advance clock by one tick — now (clock.tick - proof.tick) == 1 > 0 window
        clock.advance()
        assert await facts.verify_freshness(url) is False

    @pytest.mark.asyncio
    async def test_ancestors_traversal_still_correct(self) -> None:
        facts = _make_facts()
        facts.register_publish_intent("raw")
        root = await facts.publish(DatasetMetadata(name="raw", owner=AgentId("a1")))

        facts.register_publish_intent("derived")
        leaf = await facts.publish(
            DatasetMetadata(
                name="derived",
                owner=AgentId("a1"),
                metadata={"parents": [str(root)]},
            )
        )
        assert facts.ancestors(leaf) == {root}


# ---------------------------------------------------------------------------
# Adversarial validator: trace-level check
#
# The validator function below is what a judge would use in automated scoring.
# It returns True if NO surprise publication appears in the intent_log,
# i.e. every fulfilled intent has status == "fulfilled" (not missing from log).
#
# Against datafacts_v1: there is no intent_log; the validator would catch this
# by the absence of the audit trail itself, or via a wrapper that simulates
# the attack and checks the publish does NOT raise.
# ---------------------------------------------------------------------------

class TestAdversarialValidator:
    @pytest.mark.asyncio
    async def test_validator_passes_clean_trace(self) -> None:
        """All publishes preceded by register_intent -> log only has fulfilled."""
        facts = _make_facts()
        facts.register_publish_intent("A")
        await facts.publish(DatasetMetadata(name="A", owner=AgentId("a1")))
        facts.register_publish_intent("B")
        await facts.publish(DatasetMetadata(name="B", owner=AgentId("a1"), description="x"))

        log = facts.intent_log()
        assert all(r.status == "fulfilled" for r in log)
        assert _no_surprise_publications(log, published_names=["A", "B"])

    @pytest.mark.asyncio
    async def test_validator_catches_missing_intent_attempt(self) -> None:
        """Attack attempt is visible: IntentError raised, log shows no fulfilled entry."""
        facts = _make_facts()
        with contextlib.suppress(IntentError):
            await facts.publish(DatasetMetadata(name="secret", owner=AgentId("a1")))

        log = facts.intent_log()
        # No intent was ever registered, so log is empty -> surprise detected
        assert _no_surprise_publications(log, published_names=["secret"]) is False

    @pytest.mark.asyncio
    async def test_datafacts_v1_has_no_intent_gate(self) -> None:
        """Demonstrate that datafacts_v1 allows surprise publication (the gap we fix)."""
        from nest_plugins_reference.datafacts.datafacts_v1 import DataFactsV1

        v1 = DataFactsV1()
        # No intent registered — publish succeeds silently in v1
        url = await v1.publish(DatasetMetadata(name="surprise", owner=AgentId("attacker")))
        assert str(url) == "df://surprise"  # name-based URL, no content hash


def _no_surprise_publications(
    intent_log: list,
    *,
    published_names: list[str],
) -> bool:
    """Return False if any published name lacks a fulfilled intent log entry."""
    fulfilled_names = {r.dataset_name for r in intent_log if r.status == "fulfilled"}
    return all(name in fulfilled_names for name in published_names)
