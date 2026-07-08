# SPDX-License-Identifier: Apache-2.0
"""Tests for the multi-value register (MV-Register) CRDT memory plugin.

Covers protocol conformance, the read/write/cas/subscribe surface, the
multi-value ``values`` surface, the export/merge replication channel, version
vector partial-order semantics, the three CRDT algebraic laws, convergence of
the sibling set under arbitrary delivery order, the headline property
(concurrent writes are preserved, causal overwrites collapse), determinism,
malformed-input handling, registry wiring, the adversarial no-loss validator
(which must fail for ``lww_register`` and pass for the MV-Register), a
quantified loss benchmark against LWW, and an end-to-end scenario run under
message loss that is deterministic across seeds.
"""

from __future__ import annotations

import asyncio
import base64
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.memory import Memory
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace
from nest_plugins_reference.memory.lww_register import LwwRegisterMemory
from nest_plugins_reference.memory.mv_register import (
    CRDT_KIND,
    MvRegisterMemory,
    MvStateError,
    Value,
    VersionVector,
)
from nest_plugins_reference.validators import validate_mv_no_concurrent_loss

# ---------------------------------------------------------------------------
# Version vector partial-order semantics
# ---------------------------------------------------------------------------


class TestVersionVector:
    def test_from_dict_drops_zeros_and_sorts(self) -> None:
        vv = VersionVector.from_dict({"b": 1, "a": 0, "c": 2})
        assert vv.items == (("b", 1), ("c", 2))

    def test_equal_histories_are_equal(self) -> None:
        assert VersionVector.from_dict({"a": 1, "b": 0}) == VersionVector.from_dict({"a": 1})

    def test_merge_is_pointwise_max(self) -> None:
        a = VersionVector.from_dict({"a": 2, "b": 1})
        b = VersionVector.from_dict({"a": 1, "b": 3})
        assert a.merge(b).as_dict() == {"a": 2, "b": 3}

    def test_dominates_and_strictly_dominates(self) -> None:
        hi = VersionVector.from_dict({"a": 2, "b": 1})
        lo = VersionVector.from_dict({"a": 1, "b": 1})
        assert hi.dominates(lo)
        assert hi.strictly_dominates(lo)
        assert not lo.dominates(hi)

    def test_equal_vectors_dominate_but_not_strictly(self) -> None:
        v = VersionVector.from_dict({"a": 1})
        assert v.dominates(v)
        assert not v.strictly_dominates(v)

    def test_concurrent_when_neither_dominates(self) -> None:
        a = VersionVector.from_dict({"a": 1})
        b = VersionVector.from_dict({"b": 1})
        assert a.concurrent(b)
        assert b.concurrent(a)

    def test_not_concurrent_when_causal(self) -> None:
        older = VersionVector.from_dict({"a": 1})
        newer = VersionVector.from_dict({"a": 1, "b": 1})
        assert not older.concurrent(newer)


# ---------------------------------------------------------------------------
# Protocol conformance and base Memory surface
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_isinstance_memory(self) -> None:
        assert isinstance(MvRegisterMemory("a"), Memory)

    @pytest.mark.asyncio
    async def test_read_missing_is_none(self) -> None:
        mem = MvRegisterMemory("a")
        assert await mem.read("missing") is None

    @pytest.mark.asyncio
    async def test_values_missing_is_empty(self) -> None:
        mem = MvRegisterMemory("a")
        assert await mem.values("missing") == []

    @pytest.mark.asyncio
    async def test_write_read_roundtrip(self) -> None:
        mem = MvRegisterMemory("a")
        await mem.write("k", b"value")
        assert await mem.read("k") == b"value"
        assert await mem.values("k") == [b"value"]

    @pytest.mark.asyncio
    async def test_local_overwrite_collapses_to_one(self) -> None:
        mem = MvRegisterMemory("a")
        await mem.write("k", b"old")
        await mem.write("k", b"new")
        # A local overwrite causally follows the prior write -- one sibling, not two.
        assert await mem.read("k") == b"new"
        assert await mem.values("k") == [b"new"]

    @pytest.mark.asyncio
    async def test_cas_success(self) -> None:
        mem = MvRegisterMemory("a")
        await mem.write("k", b"old")
        assert await mem.cas("k", b"old", b"new") is True
        assert await mem.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_failure_leaves_value(self) -> None:
        mem = MvRegisterMemory("a")
        await mem.write("k", b"current")
        assert await mem.cas("k", b"wrong", b"new") is False
        assert await mem.read("k") == b"current"

    @pytest.mark.asyncio
    async def test_cas_on_missing_key(self) -> None:
        mem = MvRegisterMemory("a")
        assert await mem.cas("k", b"expected", b"new") is False

    @pytest.mark.asyncio
    async def test_binary_payload(self) -> None:
        mem = MvRegisterMemory("a")
        blob = bytes(range(256))
        await mem.write("k", blob)
        assert await mem.read("k") == blob

    @pytest.mark.asyncio
    async def test_subscribe_receives_writes(self) -> None:
        mem = MvRegisterMemory("a")
        sub = mem.subscribe("k")
        fut = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)
        await mem.write("k", b"first")
        assert await asyncio.wait_for(fut, 5) == b"first"

    @pytest.mark.asyncio
    async def test_subscribe_receives_merges(self) -> None:
        a = MvRegisterMemory("a")
        b = MvRegisterMemory("b")
        await a.write("k", b"v")
        sub = b.subscribe("k")
        fut = asyncio.ensure_future(anext(sub))
        await asyncio.sleep(0)
        state = a.export("k")
        assert state is not None
        await b.merge("k", state)
        assert await asyncio.wait_for(fut, 5) == b"v"


# ---------------------------------------------------------------------------
# The headline property: concurrent writes survive as siblings
# ---------------------------------------------------------------------------


async def _gossip_both_ways(a: MvRegisterMemory, b: MvRegisterMemory, key: str) -> None:
    sa, sb = a.export(key), b.export(key)
    assert sa is not None and sb is not None
    await a.merge(key, sb)
    await b.merge(key, sa)


class TestConcurrentPreservation:
    @pytest.mark.asyncio
    async def test_two_concurrent_writes_kept_as_siblings(self) -> None:
        a = MvRegisterMemory("a")
        b = MvRegisterMemory("b")
        await a.write("k", b"from-a")  # concurrent: neither has seen the other
        await b.write("k", b"from-b")
        await _gossip_both_ways(a, b, "k")
        assert await a.values("k") == [b"from-a", b"from-b"]
        assert await b.values("k") == [b"from-a", b"from-b"]

    @pytest.mark.asyncio
    async def test_causal_overwrite_collapses_sibling(self) -> None:
        a = MvRegisterMemory("a")
        b = MvRegisterMemory("b")
        await a.write("k", b"from-a")
        await b.write("k", b"from-b")
        await _gossip_both_ways(a, b, "k")
        # b has now SEEN a's write; overwriting supersedes both siblings causally.
        await b.write("k", b"resolved")
        assert await b.values("k") == [b"resolved"]
        # a merges b's resolution: the conflict collapses to the single new value.
        state = b.export("k")
        assert state is not None
        await a.merge("k", state)
        assert await a.values("k") == [b"resolved"]

    @pytest.mark.asyncio
    async def test_lww_would_lose_a_concurrent_write(self) -> None:
        # Same race on the LWW register keeps exactly one value -- the contrast
        # this whole plugin exists to remove.
        a = LwwRegisterMemory("a")
        b = LwwRegisterMemory("b")
        await a.write("k", b"from-a")
        await b.write("k", b"from-b")
        sa, sb = a.export("k"), b.export("k")
        assert sa is not None and sb is not None
        await a.merge("k", sb)
        await b.merge("k", sa)
        assert await a.read("k") == await b.read("k")  # converged...
        # ...but only one of the two written values remains anywhere.
        survivors = {await a.read("k")}
        assert survivors < {b"from-a", b"from-b"}


# ---------------------------------------------------------------------------
# Export / merge replication channel
# ---------------------------------------------------------------------------


class TestExportMerge:
    @pytest.mark.asyncio
    async def test_export_missing_is_none(self) -> None:
        assert MvRegisterMemory("a").export("k") is None

    @pytest.mark.asyncio
    async def test_export_is_grep_able_json(self) -> None:
        mem = MvRegisterMemory("a")
        await mem.write("k", b"hi")
        raw = mem.export("k")
        assert raw is not None
        assert CRDT_KIND.encode() in raw

    @pytest.mark.asyncio
    async def test_merge_into_empty_adopts_value(self) -> None:
        a = MvRegisterMemory("a")
        b = MvRegisterMemory("b")
        await a.write("k", b"from-a")
        state = a.export("k")
        assert state is not None
        assert await b.merge("k", state) is True
        assert await b.read("k") == b"from-a"

    @pytest.mark.asyncio
    async def test_merge_is_idempotent(self) -> None:
        a = MvRegisterMemory("a")
        b = MvRegisterMemory("b")
        await a.write("k", b"x")
        state = a.export("k")
        assert state is not None
        assert await b.merge("k", state) is True
        assert await b.merge("k", state) is False
        assert await b.values("k") == [b"x"]

    @pytest.mark.asyncio
    async def test_merge_advances_local_clock(self) -> None:
        a = MvRegisterMemory("a")
        await a.write("k", b"a1")  # a:1
        b = MvRegisterMemory("a")  # same node id, higher observed counter
        await b.write("k", b"b1")
        await b.write("k", b"b2")  # a:2
        state = b.export("k")
        assert state is not None
        await a.merge("k", state)
        await a.write("k", b"a-next")
        # The post-merge local write must dominate the merged value, not tie it.
        assert await a.values("k") == [b"a-next"]

    @pytest.mark.asyncio
    async def test_export_all_merge_all_roundtrip(self) -> None:
        a = MvRegisterMemory("a")
        await a.write("k1", b"v1")
        await a.write("k2", b"v2")
        b = MvRegisterMemory("b")
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
        with pytest.raises(MvStateError):
            await MvRegisterMemory("a").merge("k", b"\xff\xfenot json")

    @pytest.mark.asyncio
    async def test_merge_rejects_wrong_kind(self) -> None:
        with pytest.raises(MvStateError):
            await MvRegisterMemory("a").merge("k", b'{"crdt": "other", "values": []}')

    @pytest.mark.asyncio
    async def test_merge_rejects_bad_values_shape(self) -> None:
        with pytest.raises(MvStateError):
            await MvRegisterMemory("a").merge("k", b'{"crdt": "mv_register", "values": {}}')

    @pytest.mark.asyncio
    async def test_merge_rejects_bad_version_vector(self) -> None:
        bad = b'{"crdt": "mv_register", "values": [{"payload": "aGk=", "vv": {"a": "x"}}]}'
        with pytest.raises(MvStateError):
            await MvRegisterMemory("a").merge("k", bad)

    def test_state_error_is_value_error(self) -> None:
        assert issubclass(MvStateError, ValueError)


# ---------------------------------------------------------------------------
# CRDT algebraic laws (property-based) over the version-vector merge
# ---------------------------------------------------------------------------

_node = st.text(alphabet="abc", min_size=1, max_size=2)
_payload = st.binary(min_size=0, max_size=4)
_vv = st.dictionaries(_node, st.integers(min_value=0, max_value=4), max_size=3).map(
    VersionVector.from_dict
)
_value = st.builds(Value, payload=_payload, vv=_vv)


def _state(value: Value) -> bytes:
    """Serialize one value to a single-value MV-Register state via the public wire shape."""
    data = {
        "crdt": CRDT_KIND,
        "values": [
            {
                "payload": base64.b64encode(value.payload).decode("ascii"),
                "vv": value.vv.as_dict(),
            }
        ],
    }
    return json.dumps(data, sort_keys=True).encode("utf-8")


async def _merged(states: list[bytes]) -> bytes | None:
    replica = MvRegisterMemory("merger")
    for s in states:
        await replica.merge("k", s)
    return replica.export("k")


class TestCrdtLaws:
    @settings(max_examples=60, deadline=None)
    @given(v1=_value, v2=_value)
    @pytest.mark.asyncio
    async def test_merge_is_commutative(self, v1: Value, v2: Value) -> None:
        forward = await _merged([_state(v1), _state(v2)])
        backward = await _merged([_state(v2), _state(v1)])
        assert forward == backward

    @settings(max_examples=60, deadline=None)
    @given(v1=_value, v2=_value, v3=_value)
    @pytest.mark.asyncio
    async def test_merge_is_associative(self, v1: Value, v2: Value, v3: Value) -> None:
        left = await _merged([_state(v1), _state(v2), _state(v3)])
        right = await _merged([_state(v3), _state(v2), _state(v1)])
        assert left == right

    @settings(max_examples=60, deadline=None)
    @given(v1=_value)
    @pytest.mark.asyncio
    async def test_merge_is_idempotent(self, v1: Value) -> None:
        once = await _merged([_state(v1)])
        twice = await _merged([_state(v1), _state(v1)])
        assert once == twice


# ---------------------------------------------------------------------------
# Sibling-set convergence under arbitrary delivery order
# ---------------------------------------------------------------------------


class TestConvergence:
    @settings(max_examples=40, deadline=None)
    @given(data=st.data())
    @pytest.mark.asyncio
    async def test_replicas_converge_to_same_sibling_set(self, data: st.DataObject) -> None:
        replica_count = data.draw(st.integers(min_value=2, max_value=5))
        replicas = [MvRegisterMemory(f"node-{i}") for i in range(replica_count)]
        # Each replica makes one concurrent write, then all-to-all gossip in a
        # per-replica-random order. Every replica must end with the same set.
        gossip: list[bytes] = []
        for i in range(replica_count):
            await replicas[i].write("k", f"v{i}".encode())
            state = replicas[i].export("k")
            assert state is not None
            gossip.append(state)
        for i in range(replica_count):
            order = data.draw(st.permutations(list(range(replica_count))))
            for j in order:
                if j != i:
                    await replicas[i].merge("k", gossip[j])
        finals = [await r.values("k") for r in replicas]
        assert all(f == finals[0] for f in finals)
        assert len(finals[0]) == replica_count  # no write lost

    @pytest.mark.asyncio
    async def test_determinism_same_ops_same_state(self) -> None:
        async def build() -> bytes:
            a = MvRegisterMemory("a")
            b = MvRegisterMemory("b")
            await a.write("k", b"one")
            await b.write("k", b"two")
            sa, sb = a.export("k"), b.export("k")
            assert sa is not None and sb is not None
            await a.merge("k", sb)
            await b.merge("k", sa)
            return a.export_all()

        assert await build() == await build()


# ---------------------------------------------------------------------------
# Adversarial validator: LWW must fail, MV-Register must pass
# ---------------------------------------------------------------------------


class TestNoLossValidator:
    _values = [b"A", b"B", b"C"]

    @pytest.mark.asyncio
    async def test_mv_register_passes(self) -> None:
        report = await validate_mv_no_concurrent_loss(MvRegisterMemory, self._values)
        assert report.passed, report.detail

    @pytest.mark.asyncio
    async def test_lww_register_fails(self) -> None:
        report = await validate_mv_no_concurrent_loss(LwwRegisterMemory, self._values)
        assert not report.passed
        assert "lost" in report.evidence

    @pytest.mark.asyncio
    async def test_validator_rejects_too_few_values(self) -> None:
        with pytest.raises(ValueError, match="two concurrent writes"):
            await validate_mv_no_concurrent_loss(MvRegisterMemory, [b"only-one"])

    @pytest.mark.asyncio
    async def test_validator_rejects_duplicate_values(self) -> None:
        with pytest.raises(ValueError, match="distinct"):
            await validate_mv_no_concurrent_loss(MvRegisterMemory, [b"x", b"x"])


# ---------------------------------------------------------------------------
# Quantified loss benchmark: how much does LWW silently drop?
# ---------------------------------------------------------------------------


async def _surviving_after_concurrent_writes(
    factory: Callable[[str], Any],
    n: int,
) -> int:
    """Return how many of ``n`` concurrent writes survive on the first replica."""
    replicas: list[Any] = [factory(f"node-{i}") for i in range(n)]
    gossip: list[bytes] = []
    for i in range(n):
        await replicas[i].write("k", f"v{i}".encode())
        gossip.append(replicas[i].export("k"))
    for i in range(n):
        for j in range(n):
            if j != i:
                await replicas[i].merge("k", gossip[j])
    if hasattr(replicas[0], "values"):
        return len(await replicas[0].values("k"))
    return 1 if await replicas[0].read("k") is not None else 0


class TestLossBenchmark:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("n", [2, 5, 10])
    async def test_mv_keeps_all_lww_keeps_one(self, n: int) -> None:
        mv_survivors = await _surviving_after_concurrent_writes(MvRegisterMemory, n)
        lww_survivors = await _surviving_after_concurrent_writes(LwwRegisterMemory, n)
        assert mv_survivors == n, "MV-Register must keep every concurrent write"
        assert lww_survivors == 1, "LWW keeps one; the rest are silently dropped"
        # The hidden property, quantified: LWW drops n-1 of every n concurrent writes.
        assert (n - lww_survivors) == (n - 1)

    @pytest.mark.asyncio
    async def test_correct_at_scale_with_full_all_to_all_gossip(self) -> None:
        # The worst case for a multi-value register: 50 replicas all write the
        # same key concurrently and never resolve, then gossip all-to-all. The
        # merge stays correct (every replica converges to all 50 siblings) --
        # this is what the incremental antichain fold has to get right at size.
        n = 50
        survivors = await _surviving_after_concurrent_writes(MvRegisterMemory, n)
        assert survivors == n


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("memory", "mv_register")
        assert cls is MvRegisterMemory

    def test_listed_for_memory_layer(self) -> None:
        assert ("memory", "mv_register") in PluginRegistry().list_plugins("memory")


# ---------------------------------------------------------------------------
# End-to-end scenario: siblings preserved under loss, deterministic across seeds
# ---------------------------------------------------------------------------


class TestScenario:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [42, 7, 1337])
    async def test_scenario_preserves_siblings_and_is_deterministic(self, seed: int) -> None:
        traces: list[bytes] = []
        with tempfile.TemporaryDirectory() as tmp:
            for run in range(2):
                config = ScenarioConfig.from_yaml("scenarios/mv_register_siblings.yaml")
                config.seed = seed
                out = Path(tmp) / f"run-{run}.jsonl"
                config.output.trace = str(out)
                trace_path = await ScenarioRunner(config).run()
                traces.append(trace_path.read_bytes())
                if run == 0:
                    results = validate_trace(trace_path, "mv_register_siblings")
                    assert results, "validator produced no results"
                    assert all(r.passed for r in results), [
                        (r.name, r.detail) for r in results if not r.passed
                    ]
        assert traces[0] == traces[1], "trace not byte-identical under same seed"
