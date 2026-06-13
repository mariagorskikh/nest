# SPDX-License-Identifier: Apache-2.0
"""Tests for the LWW-Register CRDT memory plugin.

Includes an adversarial convergence validator that drives N concurrent writers
against the same key under deterministic but reordered delivery. The same
workload must DIVERGE on the blackboard plugin and CONVERGE on the CRDT plugin,
with byte-identical state across replicas and across repeated seeded runs.
"""

from __future__ import annotations

import asyncio
import random

import pytest
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.lww_crdt import LWWRegister

# ---------------------------------------------------------------------------
# Conformance: the Memory protocol surface
# ---------------------------------------------------------------------------


class TestLWWRegisterConformance:
    @pytest.mark.asyncio
    async def test_read_write(self) -> None:
        reg = LWWRegister(node_id="a")
        assert await reg.read("k") is None
        await reg.write("k", b"value")
        assert await reg.read("k") == b"value"

    @pytest.mark.asyncio
    async def test_later_write_wins(self) -> None:
        reg = LWWRegister(node_id="a")
        await reg.write("k", b"old")
        await reg.write("k", b"new")
        assert await reg.read("k") == b"new"

    @pytest.mark.asyncio
    async def test_cas_success(self) -> None:
        reg = LWWRegister(node_id="a")
        await reg.write("x", b"old")
        assert await reg.cas("x", b"old", b"new") is True
        assert await reg.read("x") == b"new"

    @pytest.mark.asyncio
    async def test_cas_failure(self) -> None:
        reg = LWWRegister(node_id="a")
        await reg.write("x", b"current")
        assert await reg.cas("x", b"wrong", b"new") is False
        assert await reg.read("x") == b"current"

    @pytest.mark.asyncio
    async def test_subscribe_receives_updates(self) -> None:
        reg = LWWRegister(node_id="a")
        stream = reg.subscribe("k")

        async def _first() -> bytes:
            return await anext(stream)

        # Prime the subscriber on a background task, then write so it unblocks.
        first = asyncio.ensure_future(_first())
        await asyncio.sleep(0)
        await reg.write("k", b"first")
        assert await asyncio.wait_for(first, timeout=1.0) == b"first"


# ---------------------------------------------------------------------------
# Adversarial convergence validator
# ---------------------------------------------------------------------------


def _make_workload(
    seed: int, n_writers: int, n_keys: int, ops_per_writer: int
) -> dict[str, list[tuple[str, bytes]]]:
    """Generate a deterministic set of concurrent writes, one list per writer."""
    rng = random.Random(seed)
    workload: dict[str, list[tuple[str, bytes]]] = {}
    for w in range(n_writers):
        node = f"w{w}"
        ops: list[tuple[str, bytes]] = []
        for i in range(ops_per_writer):
            key = f"k{rng.randint(0, n_keys - 1)}"
            value = f"{node}:{i}:{rng.randint(0, 999)}".encode()
            ops.append((key, value))
        workload[node] = ops
    return workload


async def _writer_replicas(
    workload: dict[str, list[tuple[str, bytes]]],
) -> list[LWWRegister]:
    """Each writer applies its own ops to its own replica, in isolation."""
    replicas: list[LWWRegister] = []
    for node, ops in workload.items():
        reg = LWWRegister(node_id=node)
        for key, value in ops:
            await reg.write(key, value)
        replicas.append(reg)
    return replicas


def _merge_in_order(replicas: list[LWWRegister], order_seed: int) -> bytes:
    """Gossip every replica's state into one merger in a shuffled order."""
    order = list(replicas)
    random.Random(order_seed).shuffle(order)
    merged = LWWRegister(node_id="merger")
    for reg in order:
        merged.merge_state(reg.export_state())
    return merged.export_state()


class TestConvergence:
    @pytest.mark.asyncio
    async def test_converges_regardless_of_merge_order(self) -> None:
        workload = _make_workload(seed=42, n_writers=8, n_keys=4, ops_per_writer=12)
        replicas = await _writer_replicas(workload)

        finals = [_merge_in_order(replicas, order_seed) for order_seed in range(10)]
        assert all(state == finals[0] for state in finals)
        # A non-trivial state actually converged (not just empty agreement).
        assert finals[0] != b"{}"

    @pytest.mark.asyncio
    async def test_merge_is_idempotent(self) -> None:
        workload = _make_workload(seed=7, n_writers=5, n_keys=3, ops_per_writer=8)
        replicas = await _writer_replicas(workload)

        merged = LWWRegister(node_id="m")
        for reg in replicas:
            merged.merge(reg)
        once = merged.export_state()
        # Re-merging the same states changes nothing.
        for reg in replicas:
            merged.merge(reg)
        assert merged.export_state() == once

    @pytest.mark.asyncio
    async def test_deterministic_across_runs(self) -> None:
        results: list[bytes] = []
        for _ in range(2):
            workload = _make_workload(seed=99, n_writers=8, n_keys=4, ops_per_writer=12)
            replicas = await _writer_replicas(workload)
            results.append(_merge_in_order(replicas, order_seed=0))
        assert results[0] == results[1]

    @pytest.mark.asyncio
    async def test_blackboard_diverges_lww_converges(self) -> None:
        """The same concurrent updates: blackboard diverges, CRDT converges."""
        updates = [b"alice", b"bob", b"carol"]

        # Blackboard keeps only the last arrival, so order changes the outcome.
        bb_forward = Blackboard()
        bb_reverse = Blackboard()
        for value in updates:
            await bb_forward.write("x", value)
        for value in reversed(updates):
            await bb_reverse.write("x", value)
        assert await bb_forward.read("x") != await bb_reverse.read("x")

        # CRDT: each update comes from a distinct writer; merging in any order
        # yields byte-identical state.
        writers: list[LWWRegister] = []
        for i, value in enumerate(updates):
            reg = LWWRegister(node_id=f"n{i}")
            await reg.write("x", value)
            writers.append(reg)

        forward = LWWRegister(node_id="A")
        reverse = LWWRegister(node_id="B")
        for reg in writers:
            forward.merge(reg)
        for reg in reversed(writers):
            reverse.merge(reg)
        assert forward.export_state() == reverse.export_state()
        assert await forward.read("x") == await reverse.read("x")
