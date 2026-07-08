# SPDX-License-Identifier: Apache-2.0
"""Tests for the PN-Counter CRDT memory plugin."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.memory import Memory
from nest_core.plugins import PluginRegistry
from nest_core.validators import validate_crdt_convergence
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.lww_register import LwwRegisterMemory
from nest_plugins_reference.memory.pn_counter import (
    CounterState,
    PnCounterMemory,
    PnCounterStateError,
)


class TestProtocolSurface:
    def test_isinstance_memory(self) -> None:
        assert isinstance(PnCounterMemory("a"), Memory)

    @pytest.mark.asyncio
    async def test_read_missing_is_none(self) -> None:
        assert await PnCounterMemory("a").read("score") is None

    @pytest.mark.asyncio
    async def test_write_json_deltas(self) -> None:
        mem = PnCounterMemory("a")
        await mem.write("score", b'{"op":"inc","amount":5}')
        await mem.write("score", b'{"op":"dec","amount":2}')
        assert await mem.read("score") == b"3"

    @pytest.mark.asyncio
    async def test_write_plain_integer_delta(self) -> None:
        mem = PnCounterMemory("a")
        await mem.write("score", b"4")
        await mem.write("score", b"-6")
        assert await mem.read("score") == b"-2"

    @pytest.mark.asyncio
    async def test_cas_sets_absolute_total(self) -> None:
        mem = PnCounterMemory("a")
        await mem.write("score", b"4")
        assert await mem.cas("score", b"4", b"9") is True
        assert await mem.read("score") == b"9"
        assert await mem.cas("score", b"4", b"0") is False
        assert await mem.read("score") == b"9"

    @pytest.mark.asyncio
    async def test_subscribe_receives_totals(self) -> None:
        mem = PnCounterMemory("a")
        sub = mem.subscribe("score")
        fut = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)
        await mem.write("score", b"2")
        assert await asyncio.wait_for(fut, 5) == b"2"


class TestMerge:
    @pytest.mark.asyncio
    async def test_merge_preserves_signed_deltas(self) -> None:
        a = PnCounterMemory("a")
        b = PnCounterMemory("b")
        await a.write("score", b'{"op":"inc","amount":3}')
        await b.write("score", b'{"op":"dec","amount":2}')
        a_state = a.export("score")
        b_state = b.export("score")
        assert a_state is not None
        assert b_state is not None
        await a.merge("score", b_state)
        await b.merge("score", a_state)
        assert await a.read("score") == await b.read("score") == b"1"

    @pytest.mark.asyncio
    async def test_duplicate_merge_does_not_double_count(self) -> None:
        a = PnCounterMemory("a")
        b = PnCounterMemory("b")
        await a.write("score", b"5")
        state = a.export("score")
        assert state is not None
        assert await b.merge("score", state) is True
        assert await b.merge("score", state) is False
        assert await b.read("score") == b"5"

    @pytest.mark.asyncio
    async def test_export_all_merge_all(self) -> None:
        a = PnCounterMemory("a")
        await a.write("score-a", b"1")
        await a.write("score-b", b"-2")
        b = PnCounterMemory("b")
        assert await b.merge_all(a.export_all()) == ["score-a", "score-b"]
        assert await b.read("score-a") == b"1"
        assert await b.read("score-b") == b"-2"


_node_map = st.dictionaries(
    st.text(alphabet="abc", min_size=1, max_size=3),
    st.integers(min_value=0, max_value=20),
    max_size=4,
)
_counter_state = st.builds(CounterState, positive=_node_map, negative=_node_map)


class TestCrdtLaws:
    @settings(max_examples=60, deadline=None)
    @given(a=_counter_state, b=_counter_state)
    def test_join_commutative(self, a: CounterState, b: CounterState) -> None:
        assert a.join(b) == b.join(a)

    @settings(max_examples=60, deadline=None)
    @given(a=_counter_state, b=_counter_state, c=_counter_state)
    def test_join_associative(self, a: CounterState, b: CounterState, c: CounterState) -> None:
        assert a.join(b).join(c) == a.join(b.join(c))

    @settings(max_examples=60, deadline=None)
    @given(a=_counter_state)
    def test_join_idempotent(self, a: CounterState) -> None:
        assert a.join(a) == a


async def _deliver_deltas(
    factory: Callable[[str], Any],
    deltas: list[tuple[int, int]],
    orders: list[list[int]],
) -> list[bytes | None]:
    replicas = [factory(f"node-{idx}") for idx in range(len(orders))]
    has_crdt = all(hasattr(r, "export") and hasattr(r, "merge") for r in replicas)
    gossip: list[bytes] = []
    for origin, delta in deltas:
        await replicas[origin].write("score", str(delta).encode("ascii"))
        if has_crdt:
            state = replicas[origin].export("score")
            assert state is not None
            gossip.append(state)
        else:
            gossip.append(str(delta).encode("ascii"))

    for replica_idx, order in enumerate(orders):
        for write_idx in order:
            if deltas[write_idx][0] == replica_idx:
                continue
            if has_crdt:
                await replicas[replica_idx].merge("score", gossip[write_idx])
            else:
                await replicas[replica_idx].write("score", gossip[write_idx])
    return [await r.read("score") for r in replicas]


class TestAdversarialDeltaPreservation:
    _deltas = [(0, 3), (1, -2), (2, 5), (3, -1)]
    _orders = [
        [0, 1, 2, 3],
        [3, 2, 1, 0],
        [1, 3, 0, 2],
        [2, 0, 3, 1],
    ]

    @pytest.mark.asyncio
    async def test_pn_counter_converges_and_preserves_sum(self) -> None:
        finals = await _deliver_deltas(PnCounterMemory, self._deltas, self._orders)
        assert len(set(finals)) == 1
        assert finals == [b"5", b"5", b"5", b"5"]

    @pytest.mark.asyncio
    async def test_lww_register_converges_but_loses_deltas(self) -> None:
        results = await validate_crdt_convergence(
            LwwRegisterMemory,
            [(origin, str(delta).encode("ascii")) for origin, delta in self._deltas],
            self._orders,
            key="score",
        )
        assert all(r.passed for r in results)
        finals = await _deliver_deltas(LwwRegisterMemory, self._deltas, self._orders)
        assert len(set(finals)) == 1
        assert finals[0] != b"5"

    @pytest.mark.asyncio
    async def test_blackboard_does_not_preserve_sum(self) -> None:
        finals = await _deliver_deltas(lambda _node: Blackboard(), self._deltas, self._orders)
        assert b"5" not in finals


class TestMalformedState:
    @pytest.mark.asyncio
    async def test_merge_rejects_non_json(self) -> None:
        with pytest.raises(PnCounterStateError):
            await PnCounterMemory("a").merge("score", b"not-json")

    @pytest.mark.asyncio
    async def test_write_rejects_bad_op(self) -> None:
        with pytest.raises(PnCounterStateError):
            await PnCounterMemory("a").write("score", b'{"op":"mul","amount":2}')

    @pytest.mark.asyncio
    async def test_copypasta_payload_rejected_without_state_corruption(self) -> None:
        mem = PnCounterMemory("builder")
        await mem.write("calculator:ready_score", b'{"op":"inc","amount":3}')
        noisy_payload = (
            b"r/copypasta noise: unsolicited wall of meme text that is not "
            b"a signed evidence delta for the calculator project"
        )
        with pytest.raises(PnCounterStateError):
            await mem.write("calculator:ready_score", noisy_payload)
        assert await mem.read("calculator:ready_score") == b"3"


class TestCalculatorNoiseScenario:
    @pytest.mark.asyncio
    async def test_calculator_project_survives_copypasta_noise(self) -> None:
        builder = PnCounterMemory("builder")
        tester = PnCounterMemory("tester")
        noisy = PnCounterMemory("copypasta")

        await builder.write("calculator:ready_score", b'{"op":"inc","amount":2}')
        await tester.write("calculator:ready_score", b'{"op":"inc","amount":2}')
        await noisy.write("calculator:ready_score", b'{"op":"dec","amount":1}')

        states = [
            builder.export("calculator:ready_score"),
            tester.export("calculator:ready_score"),
            noisy.export("calculator:ready_score"),
        ]
        assert all(state is not None for state in states)
        for replica in (builder, tester, noisy):
            for state in states:
                assert state is not None
                await replica.merge("calculator:ready_score", state)

        assert await builder.read("calculator:ready_score") == b"3"
        assert await tester.read("calculator:ready_score") == b"3"
        assert await noisy.read("calculator:ready_score") == b"3"


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        assert PluginRegistry().resolve("memory", "pn_counter") is PnCounterMemory

    def test_listed_for_memory_layer(self) -> None:
        assert ("memory", "pn_counter") in PluginRegistry().list_plugins("memory")
