# SPDX-License-Identifier: Apache-2.0
"""Tests for the OR-Set CRDT memory plugin.

Covers protocol conformance, the set-semantic read/write/add/remove/cas/
subscribe surface, the export/merge replication channel, the three CRDT
algebraic laws (commutativity, associativity, idempotence), convergence under
arbitrary delivery order via the shared adversarial validator, the defining
add-wins property (concurrent add survives a concurrent remove) and the
concrete contrast with LWW-Register (which loses concurrent adds), determinism,
malformed-input handling, and registry wiring.
"""

from __future__ import annotations

import asyncio
import base64
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.memory import Memory
from nest_core.plugins import PluginRegistry
from nest_core.validators import validate_crdt_convergence
from nest_plugins_reference.memory.lww_register import LwwRegisterMemory
from nest_plugins_reference.memory.or_set import (
    CRDT_KIND,
    CrdtStateError,
    OrSet,
    OrSetMemory,
)

# ---------------------------------------------------------------------------
# Protocol conformance and base Memory surface (set semantics)
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_memory(self) -> None:
        assert isinstance(OrSetMemory("a"), Memory)

    @pytest.mark.asyncio
    async def test_read_missing_is_none(self) -> None:
        mem = OrSetMemory("a")
        assert await mem.read("missing") is None

    @pytest.mark.asyncio
    async def test_write_adds_element(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"value")
        assert await mem.elements("k") == [b"value"]

    @pytest.mark.asyncio
    async def test_writes_accumulate(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"one")
        await mem.write("k", b"two")
        assert await mem.elements("k") == [b"one", b"two"]

    @pytest.mark.asyncio
    async def test_read_returns_canonical_member_list(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"b")
        await mem.write("k", b"a")
        expected = json.dumps(
            [base64.b64encode(b"a").decode(), base64.b64encode(b"b").decode()]
        ).encode()
        assert await mem.read("k") == expected

    @pytest.mark.asyncio
    async def test_remove_present_element(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"x")
        assert await mem.remove("k", b"x") is True
        assert await mem.contains("k", b"x") is False

    @pytest.mark.asyncio
    async def test_remove_absent_element_returns_false(self) -> None:
        mem = OrSetMemory("a")
        assert await mem.remove("k", b"missing") is False

    @pytest.mark.asyncio
    async def test_removed_key_reads_empty_not_none(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"x")
        await mem.remove("k", b"x")
        assert await mem.read("k") == b"[]"

    @pytest.mark.asyncio
    async def test_readd_after_remove_is_present(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"x")
        await mem.remove("k", b"x")
        await mem.write("k", b"x")  # fresh tag, not tombstoned
        assert await mem.contains("k", b"x") is True

    @pytest.mark.asyncio
    async def test_binary_payload(self) -> None:
        mem = OrSetMemory("a")
        blob = bytes(range(256))
        await mem.write("k", blob)
        assert await mem.elements("k") == [blob]

    @pytest.mark.asyncio
    async def test_cas_success_adds(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"one")
        snapshot = await mem.read("k")
        assert snapshot is not None
        assert await mem.cas("k", snapshot, b"two") is True
        assert await mem.elements("k") == [b"one", b"two"]

    @pytest.mark.asyncio
    async def test_cas_failure_leaves_set(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k", b"one")
        assert await mem.cas("k", b"wrong", b"two") is False
        assert await mem.elements("k") == [b"one"]

    @pytest.mark.asyncio
    async def test_subscribe_receives_writes(self) -> None:
        mem = OrSetMemory("a")
        sub = mem.subscribe("k")

        await asyncio.sleep(0)  # let the generator register its queue
        task = asyncio.ensure_future(sub.__anext__())
        await asyncio.sleep(0)
        await mem.write("k", b"v")
        received = await asyncio.wait_for(task, timeout=1)
        assert received == await mem.read("k")


# ---------------------------------------------------------------------------
# Replication channel: export / merge / *_all
# ---------------------------------------------------------------------------


class TestReplication:
    @pytest.mark.asyncio
    async def test_export_none_for_missing_key(self) -> None:
        assert OrSetMemory("a").export("missing") is None

    @pytest.mark.asyncio
    async def test_merge_is_idempotent(self) -> None:
        a = OrSetMemory("a")
        await a.write("k", b"x")
        state = a.export("k")
        assert state is not None
        b = OrSetMemory("b")
        assert await b.merge("k", state) is True
        assert await b.merge("k", state) is False
        assert await b.elements("k") == [b"x"]

    @pytest.mark.asyncio
    async def test_concurrent_adds_union(self) -> None:
        a = OrSetMemory("a")
        b = OrSetMemory("b")
        await a.write("k", b"from-a")
        await b.write("k", b"from-b")
        a_state = a.export("k")
        b_state = b.export("k")
        assert a_state is not None and b_state is not None
        await b.merge("k", a_state)
        await a.merge("k", b_state)
        assert await a.elements("k") == [b"from-a", b"from-b"]
        assert await a.read("k") == await b.read("k")

    @pytest.mark.asyncio
    async def test_export_all_merge_all_roundtrip(self) -> None:
        a = OrSetMemory("a")
        await a.write("k1", b"v1")
        await a.write("k2", b"v2")
        b = OrSetMemory("b")
        changed = await b.merge_all(a.export_all())
        assert changed == ["k1", "k2"]
        assert await b.elements("k1") == [b"v1"]
        assert await b.elements("k2") == [b"v2"]


# ---------------------------------------------------------------------------
# The defining OR-Set property: add-wins, and the contrast with LWW
# ---------------------------------------------------------------------------


class TestAddWins:
    @pytest.mark.asyncio
    async def test_concurrent_add_survives_remove(self) -> None:
        # a adds and removes x; b concurrently adds x. After merge, x survives
        # because b's add-tag was never observed by a's remove.
        a = OrSetMemory("a")
        b = OrSetMemory("b")
        await a.write("k", b"x")
        await b.write("k", b"x")
        b_state_add = b.export("k")
        assert b_state_add is not None
        await a.remove("k", b"x")  # only tombstones a's own tag
        await a.merge("k", b_state_add)
        assert await a.contains("k", b"x") is True

    @pytest.mark.asyncio
    async def test_or_set_preserves_concurrent_adds_lww_does_not(self) -> None:
        # Same concurrent scenario on both plugins: two replicas each add a
        # distinct value to one key, then exchange state.
        # OR-Set: both values retained (the union).
        oa, ob = OrSetMemory("a"), OrSetMemory("b")
        await oa.write("k", b"alpha")
        await ob.write("k", b"beta")
        oa_state, ob_state = oa.export("k"), ob.export("k")
        assert oa_state is not None and ob_state is not None
        await oa.merge("k", ob_state)
        await ob.merge("k", oa_state)
        assert await oa.elements("k") == [b"alpha", b"beta"]

        # LWW-Register: exactly one value survives; the other is lost.
        la, lb = LwwRegisterMemory("a"), LwwRegisterMemory("b")
        await la.write("k", b"alpha")
        await lb.write("k", b"beta")
        la_state, lb_state = la.export("k"), lb.export("k")
        assert la_state is not None and lb_state is not None
        await la.merge("k", lb_state)
        await lb.merge("k", la_state)
        survivor = await la.read("k")
        assert survivor in (b"alpha", b"beta")
        assert await la.read("k") == await lb.read("k")  # converged, but to one value


# ---------------------------------------------------------------------------
# Malformed input handling
# ---------------------------------------------------------------------------


class TestMalformedState:
    @pytest.mark.asyncio
    async def test_merge_rejects_non_json(self) -> None:
        with pytest.raises(CrdtStateError):
            await OrSetMemory("a").merge("k", b"\xff\xfenot json")

    @pytest.mark.asyncio
    async def test_merge_rejects_wrong_kind(self) -> None:
        with pytest.raises(CrdtStateError):
            await OrSetMemory("a").merge("k", b'{"crdt": "other"}')

    @pytest.mark.asyncio
    async def test_merge_rejects_malformed_add_row(self) -> None:
        with pytest.raises(CrdtStateError):
            await OrSetMemory("a").merge(
                "k", b'{"crdt": "or_set", "adds": [["bad-row"]], "removes": []}'
            )

    def test_crdt_state_error_is_value_error(self) -> None:
        assert issubclass(CrdtStateError, ValueError)


# ---------------------------------------------------------------------------
# CRDT algebraic laws (property-based) on the OrSet join
# ---------------------------------------------------------------------------

_element = st.binary(min_size=0, max_size=4)
_node = st.text(alphabet="abcdef", min_size=1, max_size=3)
_counter = st.integers(min_value=0, max_value=8)
_tag = st.tuples(_node, _counter)
_pair = st.tuples(_element, _tag)


@st.composite
def _or_sets(draw: st.DrawFn) -> OrSet:
    adds = draw(st.frozensets(_pair, max_size=6))
    # removes drawn from the tags that appear in adds, plus some free tags
    add_tags = [tag for (_el, tag) in adds]
    remove_pool = add_tags + draw(st.lists(_tag, max_size=3))
    removes = draw(st.frozensets(st.sampled_from(remove_pool) if remove_pool else _tag, max_size=4))
    return OrSet(adds, removes)


class TestCrdtLaws:
    @settings(max_examples=80, deadline=None)
    @given(a=_or_sets(), b=_or_sets())
    def test_join_is_commutative(self, a: OrSet, b: OrSet) -> None:
        assert a.join(b).value() == b.join(a).value()

    @settings(max_examples=80, deadline=None)
    @given(a=_or_sets(), b=_or_sets(), c=_or_sets())
    def test_join_is_associative(self, a: OrSet, b: OrSet, c: OrSet) -> None:
        assert a.join(b).join(c) == a.join(b.join(c))

    @settings(max_examples=80, deadline=None)
    @given(a=_or_sets())
    def test_join_is_idempotent(self, a: OrSet) -> None:
        assert a.join(a) == a

    @settings(max_examples=80, deadline=None)
    @given(a=_or_sets())
    def test_encode_decode_roundtrip(self, a: OrSet) -> None:
        assert OrSet.decode(a.encode()).value() == a.value()


# ---------------------------------------------------------------------------
# Convergence under arbitrary delivery order (shared adversarial validator)
# ---------------------------------------------------------------------------


class TestConvergence:
    @settings(max_examples=40, deadline=None)
    @given(data=st.data())
    @pytest.mark.asyncio
    async def test_replicas_converge_for_any_order(self, data: st.DataObject) -> None:
        n_writes = data.draw(st.integers(min_value=2, max_value=6))
        replicas = data.draw(st.integers(min_value=2, max_value=5))
        writes = [
            (data.draw(st.integers(min_value=0, max_value=replicas - 1)), f"v{i}".encode())
            for i in range(n_writes)
        ]
        orders = [data.draw(st.permutations(list(range(n_writes)))) for _ in range(replicas)]
        results = await validate_crdt_convergence(OrSetMemory, writes, orders)
        assert all(r.passed for r in results), results[0].detail

    @pytest.mark.asyncio
    async def test_determinism_same_ops_same_state(self) -> None:
        async def build() -> bytes:
            mem = OrSetMemory("a")
            await mem.write("k", b"one")
            await mem.merge("k", OrSet().add(b"two", ("b", 3)).encode())
            await mem.write("k", b"three")
            return mem.export_all()

        assert await build() == await build()


# ---------------------------------------------------------------------------
# Adversarial validator: blackboard fails, OR-Set passes
# ---------------------------------------------------------------------------


class TestConvergenceValidator:
    _writes = [(0, b"A"), (1, b"B"), (2, b"C")]
    _orders = [[0, 1, 2], [2, 1, 0], [1, 0, 2]]

    @pytest.mark.asyncio
    async def test_or_set_passes(self) -> None:
        results = await validate_crdt_convergence(OrSetMemory, self._writes, self._orders)
        assert all(r.passed for r in results)


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("memory", "or_set")
        assert cls is OrSetMemory

    def test_listed_for_memory_layer(self) -> None:
        assert ("memory", "or_set") in PluginRegistry().list_plugins("memory")

    def test_crdt_kind_tag(self) -> None:
        assert CRDT_KIND == "or_set"
