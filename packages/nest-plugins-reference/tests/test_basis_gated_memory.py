# SPDX-License-Identifier: Apache-2.0
"""Tests for the basis-gated memory wrapper plugin."""

from __future__ import annotations

import pytest
from nest_core.layers.memory import Memory
from nest_core.plugins import PluginRegistry
from nest_plugins_reference.memory.basis_gated_memory import BasisGatedMemory

_KEY = "calculator:ready_score"


def _report(node: str, basis: str) -> bytes:
    return f'{{"node":"{node}","basis":"{basis}","claim":"x"}}'.encode()


class TestProtocolSurface:
    def test_isinstance_memory(self) -> None:
        assert isinstance(BasisGatedMemory("n"), Memory)

    def test_registry_resolves(self) -> None:
        assert PluginRegistry().resolve("memory", "basis_gated") is BasisGatedMemory

    def test_listed_for_memory_layer(self) -> None:
        assert ("memory", "basis_gated") in PluginRegistry().list_plugins("memory")


class TestFusionGate:
    @pytest.mark.asyncio
    async def test_declared_basis_fuses_and_writes(self) -> None:
        mem = BasisGatedMemory("c", bases={"calculator": {"add", "divide"}})
        outcome = await mem.fuse(_KEY, _report("calculator", "add"))
        assert outcome.accepted
        assert outcome.reason == "fused"
        assert outcome.basis == "add"
        assert await mem.read(_KEY) == b"1"
        assert mem.fused_basis("calculator") == frozenset({"add"})
        assert mem.ignored == 0

    @pytest.mark.asyncio
    async def test_outside_basis_is_ignored(self) -> None:
        mem = BasisGatedMemory("c", bases={"calculator": {"add"}})
        outcome = await mem.fuse(_KEY, _report("calculator", "horoscope"))
        assert not outcome.accepted
        assert outcome.reason == "outside-basis"
        assert await mem.read(_KEY) is None
        assert mem.ignored == 1

    @pytest.mark.asyncio
    async def test_undeclared_node_has_no_overlap(self) -> None:
        mem = BasisGatedMemory("c", bases={"calculator": {"add"}})
        outcome = await mem.fuse(_KEY, _report("weather", "add"))
        assert not outcome.accepted
        assert outcome.reason == "no-overlap"

    @pytest.mark.asyncio
    async def test_natural_language_saturation_is_not_json(self) -> None:
        mem = BasisGatedMemory("c", bases={"calculator": {"add"}})
        outcome = await mem.fuse(_KEY, b"Alice was beginning to get very tired of sitting")
        assert not outcome.accepted
        assert outcome.reason == "not-json"

    @pytest.mark.asyncio
    async def test_json_non_object_is_rejected(self) -> None:
        mem = BasisGatedMemory("c", bases={"calculator": {"add"}})
        outcome = await mem.fuse(_KEY, b"[1, 2, 3]")
        assert not outcome.accepted
        assert outcome.reason == "not-object"

    @pytest.mark.asyncio
    async def test_each_basis_dimension_fuses_at_most_once(self) -> None:
        mem = BasisGatedMemory("c", bases={"calculator": {"add"}})
        first = await mem.fuse(_KEY, _report("calculator", "add"))
        second = await mem.fuse(_KEY, _report("calculator", "add"))
        assert first.accepted
        assert not second.accepted
        assert second.reason == "duplicate"
        assert await mem.read(_KEY) == b"1"

    @pytest.mark.asyncio
    async def test_write_protocol_path_also_gates(self) -> None:
        mem = BasisGatedMemory("c", bases={"calculator": {"add"}})
        await mem.write(_KEY, _report("calculator", "add"))
        await mem.write(_KEY, b"unstructured noise that has no basis")
        assert await mem.read(_KEY) == b"1"
        assert mem.ignored == 1

    def test_declare_extends_basis(self) -> None:
        mem = BasisGatedMemory("c")
        mem.declare("calculator", {"add"})
        mem.declare("calculator", {"subtract"})
        assert mem.declared_basis("calculator") == frozenset({"add", "subtract"})


class TestGossipDelegation:
    @pytest.mark.asyncio
    async def test_export_and_merge_converge_like_pn_counter(self) -> None:
        a = BasisGatedMemory("a", bases={"calculator": {"add"}})
        b = BasisGatedMemory("b", bases={"calculator": {"add"}})
        await a.fuse(_KEY, _report("calculator", "add"))
        state = a.export(_KEY)
        assert state is not None
        assert await b.merge(_KEY, state) is True
        assert await b.read(_KEY) == b"1"

    @pytest.mark.asyncio
    async def test_export_all_and_merge_all(self) -> None:
        a = BasisGatedMemory("a", bases={"calculator": {"add", "subtract"}})
        await a.fuse(_KEY, _report("calculator", "add"))
        await a.fuse(_KEY, _report("calculator", "subtract"))
        b = BasisGatedMemory("b")
        assert await b.merge_all(a.export_all()) == [_KEY]
        assert await b.read(_KEY) == b"2"
