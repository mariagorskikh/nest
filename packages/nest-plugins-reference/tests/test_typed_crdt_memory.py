# SPDX-License-Identifier: Apache-2.0
"""Tests for typed CRDT memory."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Protocol

import pytest
from nest_core.layers.memory import Memory
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.typed_crdt import TypedCrdtMemory


class ReadWriteMemory(Protocol):
    async def read(self, key: str) -> bytes | None: ...

    async def write(self, key: str, value: bytes) -> None: ...


def encode(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


async def apply_updates(memory: ReadWriteMemory, key: str, updates: list[bytes]) -> bytes:
    for update in updates:
        await memory.write(key, update)

    result = await memory.read(key)
    assert result is not None
    return result


def test_typed_crdt_satisfies_memory_protocol():
    assert isinstance(TypedCrdtMemory(), Memory)


def test_blackboard_is_order_dependent_for_concurrent_set_writes():
    async def run_test():
        updates = [
            encode({"type": "set", "writer": f"agent_{i}", "value": f"fact_{i}"})
            for i in range(1, 9)
        ]

        forward = await apply_updates(Blackboard(), "facts", updates)
        reverse = await apply_updates(Blackboard(), "facts", list(reversed(updates)))

        assert forward != reverse

    asyncio.run(run_test())


def test_set_memory_converges_across_write_orders():
    async def run_test():
        updates = [
            encode({"type": "set", "writer": f"agent_{i}", "value": f"fact_{i}"})
            for i in range(1, 9)
        ]

        forward = await apply_updates(TypedCrdtMemory(), "facts", updates)
        reverse = await apply_updates(TypedCrdtMemory(), "facts", list(reversed(updates)))

        assert forward == reverse

        decoded = json.loads(forward.decode("utf-8"))
        assert decoded["type"] == "set"
        assert decoded["values"] == [f"fact_{i}" for i in range(1, 9)]
        assert len(decoded["items"]) == 8

    asyncio.run(run_test())


def test_counter_memory_converges_and_avoids_duplicate_delivery():
    async def run_test():
        updates = [
            encode({"type": "counter", "writer": f"agent_{i}", "count": 1}) for i in range(1, 9)
        ]

        duplicate = encode({"type": "counter", "writer": "agent_1", "count": 1})
        later_higher_count = encode({"type": "counter", "writer": "agent_1", "count": 2})

        forward = await apply_updates(
            TypedCrdtMemory(),
            "count",
            updates + [duplicate, later_higher_count],
        )
        reverse = await apply_updates(
            TypedCrdtMemory(),
            "count",
            list(reversed(updates)) + [duplicate, later_higher_count],
        )

        assert forward == reverse

        decoded = json.loads(forward.decode("utf-8"))
        assert decoded["type"] == "counter"
        assert decoded["counts"]["agent_1"] == 2
        assert decoded["total"] == 9

    asyncio.run(run_test())


def test_vote_memory_preserves_ballots_and_derives_majority():
    async def run_test():
        votes = [
            "approve",
            "approve",
            "approve",
            "approve",
            "approve",
            "approve",
            "approve",
            "reject",
        ]

        updates = [
            encode({"type": "vote", "writer": f"agent_{i}", "value": votes[i - 1]})
            for i in range(1, 9)
        ]

        forward = await apply_updates(TypedCrdtMemory(), "decision", updates)
        reverse = await apply_updates(TypedCrdtMemory(), "decision", list(reversed(updates)))

        assert forward == reverse

        decoded = json.loads(forward.decode("utf-8"))
        assert decoded["type"] == "vote"
        assert len(decoded["ballots"]) == 8
        assert decoded["result"]["winner"] == "approve"
        assert decoded["result"]["counts"] == {"approve": 7, "reject": 1}
        assert decoded["result"]["confidence"] == 0.875

    asyncio.run(run_test())


def test_type_mismatch_is_rejected():
    async def run_test():
        mem = TypedCrdtMemory()

        await mem.write(
            "shared",
            encode({"type": "set", "writer": "agent_1", "value": "fact"}),
        )

        with pytest.raises(ValueError, match="Cannot merge different memory types"):
            await mem.write(
                "shared",
                encode({"type": "vote", "writer": "agent_2", "value": "approve"}),
            )

    asyncio.run(run_test())
