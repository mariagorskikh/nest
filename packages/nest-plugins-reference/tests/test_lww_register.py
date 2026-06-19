# SPDX-License-Identifier: Apache-2.0
"""Tests for the LWW-Register CRDT memory plugin.

Covers protocol conformance, the standard read/write/cas/subscribe surface,
the export/merge replication channel, the three CRDT algebraic laws
(commutativity, associativity, idempotence), convergence under arbitrary
delivery order, determinism, malformed-input handling, registry wiring, the
adversarial convergence validator (which must fail for ``blackboard`` and pass
for the CRDT), and an end-to-end scenario run under message loss.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.memory import Memory
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_crdt_convergence, validate_trace
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.lww_register import (
    CRDT_KIND,
    CrdtStateError,
    LwwRegisterMemory,
    Register,
)

# ---------------------------------------------------------------------------
# Protocol conformance and base Memory surface
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_memory(self) -> None:
        assert isinstance(LwwRegisterMemory("a"), Memory)

    @pytest.mark.asyncio
    async def test_read_missing_is_none(self) -> None:
        mem = LwwRegisterMemory("a")
        assert await mem.read("missing") is None

    @pytest.mark.asyncio
    async def test_write_read_roundtrip(self) -> None:
        mem = LwwRegisterMemory("a")
        await mem.write("k", b"value")
        assert await mem.read("k") == b"value"

    @pytest.mark.asyncio
    async def test_overwrite_keeps_latest(self) -> None:
        mem = LwwRegisterMemory("a")
        await mem.write("k", b"old")
        await mem.write("k", b"new")
        assert await mem.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_success(self) -> None:
        mem = LwwRegisterMemory("a")
        await mem.write("k", b"old")
        assert await mem.cas("k", b"old", b"new") is True
        assert await mem.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_failure_leaves_value(self) -> None:
        mem = LwwRegisterMemory("a")
        await mem.write("k", b"current")
        assert await mem.cas("k", b"wrong", b"new") is False
        assert await mem.read("k") == b"current"

    @pytest.mark.asyncio
    async def test_cas_on_missing_key(self) -> None:
        mem = LwwRegisterMemory("a")
        assert await mem.cas("k", b"expected", b"new") is False

    @pytest.mark.asyncio
    async def test_binary_payload(self) -> None:
        mem = LwwRegisterMemory("a")
        blob = bytes(range(256))
        await mem.write("k", blob)
        assert await mem.read("k") == blob

    @pytest.mark.asyncio
    async def test_subscribe_receives_writes(self) -> None:
        mem = LwwRegisterMemory("a")
        sub = mem.subscribe("k")
        fut = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)  # let the generator register its queue
        await mem.write("k", b"first")
        assert await asyncio.wait_for(fut, 5) == b"first"
        fut2 = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)
        await mem.write("k", b"second")
        assert await asyncio.wait_for(fut2, 5) == b"second"

    @pytest.mark.asyncio
    async def test_subscribe_receives_merges(self) -> None:
        a = LwwRegisterMemory("a")
        b = LwwRegisterMemory("b")
        await a.write("k", b"v")
        sub = b.subscribe("k")
        fut = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)  # let the generator register its queue
        state = a.export("k")
        assert state is not None
        await b.merge("k", state)
        assert await asyncio.wait_for(fut, 5) == b"v"


# ---------------------------------------------------------------------------
# Export / merge replication channel
# ---------------------------------------------------------------------------


class TestExportMerge:
    @pytest.mark.asyncio
    async def test_export_missing_is_none(self) -> None:
        assert LwwRegisterMemory("a").export("k") is None

    @pytest.mark.asyncio
    async def test_export_is_grep_able_json(self) -> None:
        mem = LwwRegisterMemory("a")
        await mem.write("k", b"hi")
        raw = mem.export("k")
        assert raw is not None
        assert CRDT_KIND.encode() in raw

    @pytest.mark.asyncio
    async def test_merge_into_empty_adopts_value(self) -> None:
        a = LwwRegisterMemory("a")
        b = LwwRegisterMemory("b")
        await a.write("k", b"from-a")
        state = a.export("k")
        assert state is not None
        changed = await b.merge("k", state)
        assert changed is True
        assert await b.read("k") == b"from-a"

    @pytest.mark.asyncio
    async def test_merge_is_idempotent(self) -> None:
        a = LwwRegisterMemory("a")
        b = LwwRegisterMemory("b")
        await a.write("k", b"x")
        state = a.export("k")
        assert state is not None
        assert await b.merge("k", state) is True
        assert await b.merge("k", state) is False
        assert await b.read("k") == b"x"

    @pytest.mark.asyncio
    async def test_higher_lamport_wins(self) -> None:
        b = LwwRegisterMemory("b")
        await b.write("k", b"local")  # lamport 1
        loser = Register(b"older", lamport=0, node="z").encode()
        winner = Register(b"newer", lamport=5, node="a").encode()
        await b.merge("k", loser)
        assert await b.read("k") == b"local"
        await b.merge("k", winner)
        assert await b.read("k") == b"newer"

    @pytest.mark.asyncio
    async def test_merge_advances_lamport_clock(self) -> None:
        b = LwwRegisterMemory("b")
        await b.merge("k", Register(b"x", lamport=9, node="a").encode())
        await b.write("k", b"local")
        # The local write must dominate the merged value (clock advanced past 9).
        assert b.lamport > 9
        assert await b.read("k") == b"local"

    @pytest.mark.asyncio
    async def test_export_all_merge_all_roundtrip(self) -> None:
        a = LwwRegisterMemory("a")
        await a.write("k1", b"v1")
        await a.write("k2", b"v2")
        b = LwwRegisterMemory("b")
        changed = await b.merge_all(a.export_all())
        assert changed == ["k1", "k2"]
        assert await b.read("k1") == b"v1"
        assert await b.read("k2") == b"v2"


# ---------------------------------------------------------------------------
# Malformed input handling
# ---------------------------------------------------------------------------


class TestMalformedState:
    @pytest.mark.asyncio
    async def test_merge_rejects_non_json(self) -> None:
        with pytest.raises(CrdtStateError):
            await LwwRegisterMemory("a").merge("k", b"\xff\xfenot json")

    @pytest.mark.asyncio
    async def test_merge_rejects_wrong_kind(self) -> None:
        with pytest.raises(CrdtStateError):
            await LwwRegisterMemory("a").merge("k", b'{"crdt": "other", "x": 1}')

    @pytest.mark.asyncio
    async def test_merge_rejects_missing_fields(self) -> None:
        with pytest.raises(CrdtStateError):
            await LwwRegisterMemory("a").merge("k", b'{"crdt": "lww_register"}')

    def test_crdt_state_error_is_value_error(self) -> None:
        assert issubclass(CrdtStateError, ValueError)


# ---------------------------------------------------------------------------
# CRDT algebraic laws (property-based)
# ---------------------------------------------------------------------------

_node = st.text(alphabet="abcdef", min_size=1, max_size=3)
_payload = st.binary(min_size=0, max_size=8)
_lamport = st.integers(min_value=0, max_value=20)
_register = st.builds(Register, payload=_payload, lamport=_lamport, node=_node)


async def _merged_state(states: list[bytes]) -> bytes | None:
    replica = LwwRegisterMemory("merger")
    for s in states:
        await replica.merge("k", s)
    return replica.export("k")


class TestCrdtLaws:
    @settings(max_examples=60, deadline=None)
    @given(r1=_register, r2=_register)
    @pytest.mark.asyncio
    async def test_merge_is_commutative(self, r1: Register, r2: Register) -> None:
        forward = await _merged_state([r1.encode(), r2.encode()])
        backward = await _merged_state([r2.encode(), r1.encode()])
        assert forward == backward

    @settings(max_examples=60, deadline=None)
    @given(r1=_register, r2=_register, r3=_register)
    @pytest.mark.asyncio
    async def test_merge_is_associative(self, r1: Register, r2: Register, r3: Register) -> None:
        left = await _merged_state([r1.encode(), r2.encode(), r3.encode()])
        right = await _merged_state([r3.encode(), r2.encode(), r1.encode()])
        assert left == right

    @settings(max_examples=60, deadline=None)
    @given(r1=_register)
    @pytest.mark.asyncio
    async def test_merge_is_idempotent(self, r1: Register) -> None:
        once = await _merged_state([r1.encode()])
        twice = await _merged_state([r1.encode(), r1.encode()])
        assert once == twice


# ---------------------------------------------------------------------------
# Convergence under arbitrary delivery order (the headline property)
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
        results = await validate_crdt_convergence(LwwRegisterMemory, writes, orders)
        assert all(r.passed for r in results), results[0].detail

    @pytest.mark.asyncio
    async def test_determinism_same_ops_same_state(self) -> None:
        async def build() -> bytes:
            mem = LwwRegisterMemory("a")
            await mem.write("k", b"one")
            await mem.merge("k", Register(b"two", 3, "b").encode())
            await mem.write("k", b"three")
            return mem.export_all()

        assert await build() == await build()


# ---------------------------------------------------------------------------
# Adversarial validator: blackboard must fail, CRDT must pass
# ---------------------------------------------------------------------------


class TestConvergenceValidator:
    _writes = [(0, b"A"), (1, b"B"), (2, b"C")]
    _orders = [[0, 1, 2], [2, 1, 0], [1, 0, 2]]

    @pytest.mark.asyncio
    async def test_crdt_passes(self) -> None:
        results = await validate_crdt_convergence(LwwRegisterMemory, self._writes, self._orders)
        assert all(r.passed for r in results)

    @pytest.mark.asyncio
    async def test_blackboard_fails(self) -> None:
        results = await validate_crdt_convergence(
            lambda _node: Blackboard(), self._writes, self._orders
        )
        assert not any(r.passed for r in results)


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("memory", "lww_register")
        assert cls is LwwRegisterMemory

    def test_listed_for_memory_layer(self) -> None:
        assert ("memory", "lww_register") in PluginRegistry().list_plugins("memory")


# ---------------------------------------------------------------------------
# End-to-end scenario: convergence under loss, deterministic across seeds
# ---------------------------------------------------------------------------


class TestScenario:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [42, 7, 1337])
    async def test_scenario_converges_and_is_deterministic(self, seed: int) -> None:
        traces: list[bytes] = []
        with tempfile.TemporaryDirectory() as tmp:
            for run in range(2):
                config = ScenarioConfig.from_yaml("scenarios/memory_concurrent_writers.yaml")
                config.seed = seed
                out = Path(tmp) / f"run-{run}.jsonl"
                config.output.trace = str(out)
                trace_path = await ScenarioRunner(config).run()
                traces.append(trace_path.read_bytes())
                if run == 0:
                    results = validate_trace(trace_path, "memory_concurrent_writers")
                    assert results, "validator produced no results"
                    assert all(r.passed for r in results), [r.detail for r in results]
        assert traces[0] == traces[1], "trace not byte-identical under same seed"
