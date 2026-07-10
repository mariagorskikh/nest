# SPDX-License-Identifier: Apache-2.0
"""Tests for the embx-backed semantic memory plugin.

Covers protocol conformance, the standard read/write/cas/subscribe surface,
the semantic-lookup capability (the thing blackboard cannot do), the
adversarial contrast against blackboard (semantic recall fails on the default
plugin, passes on this one), determinism of the fallback path, registry
wiring, and an end-to-end scenario run.

The semantic tests force the deterministic hash-embedding fallback by clearing
``EMBX_BASE_URL`` so they run offline and byte-reproducibly -- the live embx
path (https://embx.net) is exercised in production, not in CI.
"""

from __future__ import annotations

# pyright: reportPrivateUsage=false, reportUnusedFunction=false
import asyncio

import pytest
from nest_core.layers.memory import Memory
from nest_core.plugins import PluginRegistry
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.embx_semantic import (
    DEFAULT_EMBX_BASE_URL,
    EMBEDDING_DIM,
    EmbxSemanticMemory,
    _cosine,
    _hash_embedding,
    _tokenize,
)


@pytest.fixture(autouse=True)
def _force_deterministic_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear EMBX_BASE_URL so every test uses the hash-embedding fallback.

    This is the reproducible path; the live embx path is a production concern.
    """
    monkeypatch.delenv("EMBX_BASE_URL", raising=False)
    monkeypatch.delenv("EMBX_API_KEY", raising=False)


# ---------------------------------------------------------------------------
# Protocol conformance and base Memory surface
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_memory(self) -> None:
        assert isinstance(EmbxSemanticMemory("a"), Memory)

    @pytest.mark.asyncio
    async def test_read_missing_is_none(self) -> None:
        mem = EmbxSemanticMemory("a")
        assert await mem.read("missing") is None

    @pytest.mark.asyncio
    async def test_write_read_roundtrip(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("k", b"value")
        assert await mem.read("k") == b"value"

    @pytest.mark.asyncio
    async def test_overwrite_keeps_latest(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("k", b"old")
        await mem.write("k", b"new")
        assert await mem.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_success(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("k", b"old")
        assert await mem.cas("k", b"old", b"new") is True
        assert await mem.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_failure_leaves_value(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("k", b"current")
        assert await mem.cas("k", b"wrong", b"new") is False
        assert await mem.read("k") == b"current"

    @pytest.mark.asyncio
    async def test_cas_on_missing_key(self) -> None:
        mem = EmbxSemanticMemory("a")
        assert await mem.cas("k", b"expected", b"new") is False

    @pytest.mark.asyncio
    async def test_binary_payload(self) -> None:
        mem = EmbxSemanticMemory("a")
        blob = bytes(range(256))
        await mem.write("k", blob)
        assert await mem.read("k") == blob

    @pytest.mark.asyncio
    async def test_subscribe_receives_writes(self) -> None:
        mem = EmbxSemanticMemory("a")
        sub = mem.subscribe("k")
        fut = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)  # let the generator register its queue
        await mem.write("k", b"first")
        assert await asyncio.wait_for(fut, 5) == b"first"
        fut2 = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)
        await mem.write("k", b"second")
        assert await asyncio.wait_for(fut2, 5) == b"second"


# ---------------------------------------------------------------------------
# Semantic recall -- the headline capability
# ---------------------------------------------------------------------------


class TestSemanticLookup:
    @pytest.mark.asyncio
    async def test_finds_value_under_related_key(self) -> None:
        """semantic_lookup finds a stored value via a different, related key.

        This is the property blackboard cannot satisfy: read under a key that
        is not stored but shares meaning (here, shared surface tokens). The
        deterministic fallback ranks shared-token keys above the floor.
        """
        mem = EmbxSemanticMemory("a")
        await mem.write("airport-departure-gate", b"A23")
        hit = await mem.semantic_lookup("departure-gate-airport")
        assert hit is not None
        assert hit[0] == "airport-departure-gate"
        assert hit[1] == b"A23"

    @pytest.mark.asyncio
    async def test_finds_best_of_several(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("flight-boarding-pass", b"BP-1")
        await mem.write("gate-departure-time", b"09:30")
        # Query shares tokens with the gate entry, not the boarding pass.
        hit = await mem.semantic_lookup("departure-gate")
        assert hit is not None
        assert hit[0] == "gate-departure-time"

    @pytest.mark.asyncio
    async def test_returns_none_when_nothing_related(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("kennel-vet-records", b"dog")
        # Disjoint token set -> similarity below the floor -> no false hit.
        assert await mem.semantic_lookup("airport-runway-taxiway") is None

    @pytest.mark.asyncio
    async def test_returns_none_on_empty_store(self) -> None:
        assert await EmbxSemanticMemory("a").semantic_lookup("anything") is None

    @pytest.mark.asyncio
    async def test_rank_returns_shortlist_descending(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("gate-departure", b"v1")
        await mem.write("gate-arrival", b"v2")
        await mem.write("kennel-vet", b"v3")
        ranked = await mem.semantic_rank("gate-departure", limit=5)
        assert len(ranked) >= 2
        # Highest similarity first.
        assert ranked[0][0] == "gate-departure"
        # Disjoint-token entry does not make the cut.
        keys = [k for k, _v, _s in ranked]
        assert "kennel-vet" not in keys
        # Scores are descending.
        scores = [s for _k, _v, s in ranked]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Adversarial contrast: blackboard cannot do semantic recall; this plugin can
# ---------------------------------------------------------------------------


class TestSemanticContrastWithBlackboard:
    """The test that fails without this plugin and passes with it.

    Blackboard has no semantic_lookup at all, so the contrast is structural:
    the default plugin cannot answer a recall-by-meaning question, this one
    can. Asserting both halves proves the plugin adds a real capability rather
    than re-exposing exact-match.
    """

    @pytest.mark.asyncio
    async def test_blackboard_cannot_recall_by_related_key(self) -> None:
        bb = Blackboard()
        await bb.write("airport-departure-gate", b"A23")
        # Blackboard only knows exact keys. A related-but-different key misses.
        assert await bb.read("departure-gate-airport") is None
        # And it has no semantic_lookup method to fall back on.
        assert not hasattr(bb, "semantic_lookup")

    @pytest.mark.asyncio
    async def test_embx_recalls_by_related_key(self) -> None:
        mem = EmbxSemanticMemory("a")
        await mem.write("airport-departure-gate", b"A23")
        hit = await mem.semantic_lookup("departure-gate-airport")
        assert hit is not None
        assert hit[1] == b"A23"


# ---------------------------------------------------------------------------
# Determinism and fallback internals
# ---------------------------------------------------------------------------


class TestDeterministicFallback:
    def test_tokenize_lowercases_and_splits(self) -> None:
        assert _tokenize("Flight-Boarding_Gate!") == ["flight", "boarding", "gate"]

    def test_tokenize_empty_string(self) -> None:
        assert _tokenize("") == []

    def test_hash_embedding_fixed_dimension(self) -> None:
        assert len(_hash_embedding("anything")) == EMBEDDING_DIM

    def test_hash_embedding_is_deterministic(self) -> None:
        # Same bytes in -> same vector out, every run. This is the property
        # that keeps the fallback CI-safe.
        assert _hash_embedding("departure gate") == _hash_embedding("departure gate")

    def test_hash_embedding_shared_tokens_score_higher(self) -> None:
        a = _hash_embedding("airport-departure-gate")
        b = _hash_embedding("departure-gate-airport")
        unrelated = _hash_embedding("kennel-vet-records")
        # Shared tokens -> high cosine; disjoint tokens -> near zero.
        assert _cosine(a, b) > _cosine(a, unrelated)

    def test_cosine_self_is_one(self) -> None:
        v = _hash_embedding("gate")
        assert _cosine(v, v) == pytest.approx(1.0, abs=1e-9)

    def test_cosine_mismatched_length_is_zero(self) -> None:
        assert _cosine([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0

    def test_default_base_url_is_live_embx(self) -> None:
        # The production default points at the live service.
        assert DEFAULT_EMBX_BASE_URL == "https://embx.net"

    def test_unsetting_base_url_forces_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("EMBX_BASE_URL", raising=False)
        mem = EmbxSemanticMemory("a")
        # No EMBX_BASE_URL -> plugin will not attempt live calls.
        assert mem.using_embx is False

    def test_empty_base_url_forces_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMBX_BASE_URL", "   ")
        assert EmbxSemanticMemory("a").using_embx is False

    def test_set_base_url_attempts_embx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMBX_BASE_URL", "https://embx.example.test")
        assert EmbxSemanticMemory("a").using_embx is True

    @pytest.mark.asyncio
    async def test_embx_failure_falls_back_without_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Point at a bogus host so the HTTP call fails fast; the plugin must
        # fall back to the deterministic embedding and keep working.
        monkeypatch.setenv("EMBX_BASE_URL", "http://127.0.0.1:1")
        monkeypatch.setenv("EMBX_TIMEOUT_S", "0.2")
        mem = EmbxSemanticMemory("a")
        assert mem.using_embx is True
        # write embeds via the (failing) embx path, then trips the fallback.
        await mem.write("airport-departure-gate", b"A23")
        # After a failure the replica stops retrying the network.
        assert mem.using_embx is False
        # And semantic recall still works via the fallback.
        hit = await mem.semantic_lookup("departure-gate-airport")
        assert hit is not None
        assert hit[1] == b"A23"


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("memory", "embx_semantic")
        assert cls is EmbxSemanticMemory

    def test_listed_for_memory_layer(self) -> None:
        assert ("memory", "embx_semantic") in PluginRegistry().list_plugins("memory")


# ---------------------------------------------------------------------------
# Determinism of the full plugin: same writes -> same recall, every run.
# (The concurrent-writers scenario is CRDT-specific -- it calls export/merge --
#  so it does not apply to a non-CRDT memory plugin. Determinism here is proven
#  at the plugin level: the fallback embedding is a pure function of the key,
#  so replaying the same writes yields the same semantic rankings.)
# ---------------------------------------------------------------------------


class TestScenarioDeterminism:
    @pytest.mark.asyncio
    async def test_same_writes_same_recall(self) -> None:
        async def build_and_recall() -> tuple[str, bytes] | None:
            mem = EmbxSemanticMemory("a")
            await mem.write("airport-departure-gate", b"A23")
            await mem.write("gate-boarding-zone", b"B12")
            await mem.write("kennel-vet-records", b"dog")
            return await mem.semantic_lookup("departure-gate")

        assert await build_and_recall() == await build_and_recall()

    @pytest.mark.asyncio
    async def test_recall_stable_across_independent_instances(self) -> None:
        # Two separate replicas, same writes, must agree on the best semantic
        # match -- the deterministic fallback makes the ranking a pure function
        # of the stored keys.
        async def build() -> EmbxSemanticMemory:
            mem = EmbxSemanticMemory("a")
            await mem.write("flight-boarding-pass", b"BP-1")
            await mem.write("gate-departure-time", b"09:30")
            return mem

        a = await build()
        b = await build()
        query = "departure-gate"
        assert await a.semantic_lookup(query) == await b.semantic_lookup(query)
