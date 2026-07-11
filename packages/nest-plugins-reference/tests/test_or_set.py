# SPDX-License-Identifier: Apache-2.0
"""Tests for the OR-Set CRDT memory plugin.

Covers protocol conformance, the standard read/write/cas/subscribe surface,
the export/merge replication channel, the three CRDT algebraic laws
(commutativity, associativity, idempotence), convergence under arbitrary
delivery order via the adversarial validator (which must fail for
``blackboard`` and pass for the OR-Set), the defining OR-Set property that
concurrent adds all survive (which ``lww_register`` cannot provide),
determinism of the canonical encoding, malformed-input handling, and
registry wiring.
"""

from __future__ import annotations

import asyncio
import base64
import json

import pytest
from nest_core.layers.memory import Memory
from nest_core.plugins import PluginRegistry
from nest_core.validators import validate_crdt_convergence
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.lww_register import LwwRegisterMemory
from nest_plugins_reference.memory.or_set import (
    CRDT_KIND,
    CrdtStateError,
    OrSet,
    OrSetMemory,
)

# ---------------------------------------------------------------------------
# Protocol conformance and base Memory surface
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_memory(self) -> None:
        assert isinstance(OrSetMemory("a"), Memory)

    @pytest.mark.asyncio
    async def test_read_missing_is_none(self) -> None:
        mem = OrSetMemory("a")
        assert await mem.read("missing") is None

    @pytest.mark.asyncio
    async def test_write_read_roundtrip(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"value")
        assert await mem.read("k") == b"value"

    @pytest.mark.asyncio
    async def test_overwrite_keeps_latest(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"old")
        await mem.write("k", b"new")
        assert await mem.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_success(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"old")
        assert await mem.cas("k", b"old", b"new") is True
        assert await mem.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_failure_leaves_value(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"current")
        assert await mem.cas("k", b"wrong", b"new") is False
        assert await mem.read("k") == b"current"

    @pytest.mark.asyncio
    async def test_cas_on_missing_key(self) -> None:
        mem = OrSetMemory("a")
        assert await mem.cas("k", b"expected", b"new") is False

    @pytest.mark.asyncio
    async def test_subscribe_sees_local_write(self) -> None:
        mem = OrSetMemory("a")
        agen = mem.subscribe("k")
        task = asyncio.ensure_future(agen.__anext__())
        await asyncio.sleep(0)
        await mem.write("k", b"ping")
        assert await asyncio.wait_for(task, timeout=1) == b"ping"
        await agen.aclose()


# ---------------------------------------------------------------------------
# CRDT algebraic laws on the pure state
# ---------------------------------------------------------------------------


class TestAlgebraicLaws:
    def _states(self) -> tuple[OrSet, OrSet, OrSet]:
        s1 = OrSet(adds={"a:1": b"x"}, removes=set())
        s2 = OrSet(adds={"b:1": b"y"}, removes={"a:1"})
        s3 = OrSet(adds={"c:1": b"z", "a:1": b"x"}, removes={"b:1"})
        return s1, s2, s3

    def test_join_commutative(self) -> None:
        s1, s2, _ = self._states()
        assert s1.join(s2).encode() == s2.join(s1).encode()

    def test_join_associative(self) -> None:
        s1, s2, s3 = self._states()
        left = s1.join(s2).join(s3)
        right = s1.join(s2.join(s3))
        assert left.encode() == right.encode()

    def test_join_idempotent(self) -> None:
        s1, _, _ = self._states()
        assert s1.join(s1).encode() == s1.encode()

    def test_observed_remove_only_covers_observed_tags(self) -> None:
        # A remove for tag a:1 must not affect a concurrent add under b:1.
        removed = OrSet(adds={"a:1": b"x"}, removes={"a:1"})
        concurrent = OrSet(adds={"b:1": b"y"}, removes=set())
        assert removed.join(concurrent).live() == {b"y"}


# ---------------------------------------------------------------------------
# The defining OR-Set property: concurrent adds survive
# ---------------------------------------------------------------------------


class TestConcurrentAddsSurvive:
    @pytest.mark.asyncio
    async def test_or_set_keeps_both_concurrent_writes(self) -> None:
        a, b = OrSetMemory("a"), OrSetMemory("b")
        await a.write("catalogue", b"from-a")
        await b.write("catalogue", b"from-b")
        await b.merge("catalogue", a.export("catalogue"))
        await a.merge("catalogue", b.export("catalogue"))
        merged = await a.read("catalogue")
        assert merged == await b.read("catalogue")
        assert merged is not None
        elements = {base64.b64decode(e) for e in json.loads(merged)}
        assert elements == {b"from-a", b"from-b"}

    @pytest.mark.asyncio
    async def test_lww_register_loses_a_concurrent_write(self) -> None:
        # The gap this plugin closes: the LWW register converges but keeps
        # only one of two concurrent writes, silently dropping the other.
        a, b = LwwRegisterMemory("a"), LwwRegisterMemory("b")
        await a.write("catalogue", b"from-a")
        await b.write("catalogue", b"from-b")
        await b.merge("catalogue", a.export("catalogue"))
        await a.merge("catalogue", b.export("catalogue"))
        winner = await a.read("catalogue")
        assert winner == await b.read("catalogue")
        assert winner in (b"from-a", b"from-b")  # exactly one survives

    @pytest.mark.asyncio
    async def test_local_rewrite_after_merge_replaces_all_observed(self) -> None:
        a, b = OrSetMemory("a"), OrSetMemory("b")
        await a.write("k", b"one")
        await b.write("k", b"two")
        await a.merge("k", b.export("k"))
        await a.write("k", b"final")  # observes both, removes both, adds one
        await b.merge("k", a.export("k"))
        assert await a.read("k") == b"final"
        assert await b.read("k") == b"final"


# ---------------------------------------------------------------------------
# Adversarial convergence validator: FAIL blackboard, PASS or_set
# ---------------------------------------------------------------------------


WRITES = [(0, b"alpha"), (1, b"bravo"), (2, b"charlie"), (0, b"delta")]
ORDERS = [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2]]


class TestConvergenceValidator:
    @pytest.mark.asyncio
    async def test_blackboard_fails_convergence(self) -> None:
        results = await validate_crdt_convergence(
            lambda _node: Blackboard(), writes=WRITES, delivery_orders=ORDERS
        )
        assert not all(r.passed for r in results)

    @pytest.mark.asyncio
    async def test_or_set_passes_convergence(self) -> None:
        results = await validate_crdt_convergence(
            OrSetMemory, writes=WRITES, delivery_orders=ORDERS
        )
        assert all(r.passed for r in results), [r.detail for r in results]

    @pytest.mark.asyncio
    async def test_or_set_converges_under_duplicated_gossip(self) -> None:
        # Idempotence end-to-end: delivering the same state twice is a no-op.
        a, b = OrSetMemory("a"), OrSetMemory("b")
        await a.write("k", b"x")
        state = a.export("k")
        await b.merge("k", state)
        await b.merge("k", state)
        assert await b.read("k") == await a.read("k")


# ---------------------------------------------------------------------------
# Determinism of the canonical encoding
# ---------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_ops_same_bytes(self) -> None:
        def build() -> OrSetMemory:
            return OrSetMemory("fixed-node")

        async def run(mem: OrSetMemory) -> bytes | None:
            await mem.write("k", b"one")
            await mem.write("k", b"two")
            return mem.export("k")

        assert await run(build()) == await run(build())

    @pytest.mark.asyncio
    async def test_merge_order_does_not_change_bytes(self) -> None:
        a, b, c = OrSetMemory("a"), OrSetMemory("b"), OrSetMemory("c")
        for mem, payload in ((a, b"pa"), (b, b"pb"), (c, b"pc")):
            await mem.write("k", payload)
        sa, sb, sc = a.export("k"), b.export("k"), c.export("k")

        one = OrSetMemory("x")
        for raw in (sa, sb, sc):
            await one.merge("k", raw)
        other = OrSetMemory("y")
        for raw in (sc, sa, sb):
            await other.merge("k", raw)
        assert one.export("k") == other.export("k")
        assert await one.read("k") == await other.read("k")


# ---------------------------------------------------------------------------
# Malformed input and registry wiring
# ---------------------------------------------------------------------------


class TestMalformedInput:
    def test_decode_rejects_non_json(self) -> None:
        with pytest.raises(CrdtStateError):
            OrSet.decode(b"\xff\xfenope")

    def test_decode_rejects_wrong_schema_tag(self) -> None:
        raw = json.dumps({"crdt": "lww_register", "adds": {}, "removes": []}).encode()
        with pytest.raises(CrdtStateError):
            OrSet.decode(raw)

    def test_decode_rejects_bad_shapes(self) -> None:
        raw = json.dumps({"crdt": CRDT_KIND, "adds": [], "removes": {}}).encode()
        with pytest.raises(CrdtStateError):
            OrSet.decode(raw)

    def test_decode_rejects_bad_base64(self) -> None:
        raw = json.dumps(
            {"crdt": CRDT_KIND, "adds": {"a:1": "!!not-base64!!"}, "removes": []}
        ).encode()
        with pytest.raises(CrdtStateError):
            OrSet.decode(raw)

    def test_crdt_state_error_is_value_error(self) -> None:
        assert issubclass(CrdtStateError, ValueError)


class TestRegistryWiring:
    def test_resolves_from_plugin_registry(self) -> None:
        cls = PluginRegistry().resolve("memory", "or_set")
        assert cls is OrSetMemory

    @pytest.mark.asyncio
    async def test_resolved_instance_satisfies_memory(self) -> None:
        cls = PluginRegistry().resolve("memory", "or_set")
        mem = cls("agent-0")
        assert isinstance(mem, Memory)
        await mem.write("k", b"v")
        assert await mem.read("k") == b"v"
