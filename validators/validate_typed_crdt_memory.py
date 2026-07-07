# SPDX-License-Identifier: Apache-2.0
"""Validator for typed_crdt memory.

This validator demonstrates the problem with last-writer-wins blackboard
memory and checks that TypedCrdtMemory converges under interleaved writes.

Expected behavior:
- Blackboard does not converge because the final value depends on delivery order.
- TypedCrdtMemory converges because it merges by memory type.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from typing import Any

from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.typed_crdt import TypedCrdtMemory


Update = tuple[str, bytes]


def encode(obj: dict[str, Any]) -> bytes:
    """Encode JSON deterministically for test inputs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


async def apply_updates(memory: Any, key: str, updates: Iterable[Update]) -> bytes:
    """Apply writes to a memory plugin and return the final bytes."""
    for _, value in updates:
        await memory.write(key, value)

    final = await memory.read(key)
    if final is None:
        raise AssertionError(f"Expected final value for key {key!r}, got None")

    return final


def make_set_updates() -> list[Update]:
    return [
        (
            f"agent_{i}",
            encode({
                "type": "set",
                "writer": f"agent_{i}",
                "value": f"fact_{i}",
            }),
        )
        for i in range(1, 9)
    ]


def make_counter_updates() -> list[Update]:
    return [
        (
            f"agent_{i}",
            encode({
                "type": "counter",
                "writer": f"agent_{i}",
                "count": 1,
            }),
        )
        for i in range(1, 9)
    ]


def make_vote_updates() -> list[Update]:
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

    return [
        (
            f"agent_{i}",
            encode({
                "type": "vote",
                "writer": f"agent_{i}",
                "value": votes[i - 1],
            }),
        )
        for i in range(1, 9)
    ]


async def validate_blackboard_fails() -> None:
    """Show that Blackboard final state depends on write order."""
    updates = make_set_updates()

    forward = await apply_updates(Blackboard(), "shared_facts", updates)
    reverse = await apply_updates(Blackboard(), "shared_facts", reversed(updates))

    if forward == reverse:
        raise AssertionError(
            "Expected Blackboard to fail convergence, but forward and reverse matched"
        )

    print("Blackboard expected failure:")
    print(f"  forward final value: {forward.decode('utf-8')}")
    print(f"  reverse final value: {reverse.decode('utf-8')}")
    print("  result: FAILS convergence, as expected")


async def validate_typed_crdt_set() -> None:
    updates = make_set_updates()

    forward = await apply_updates(TypedCrdtMemory(), "shared_facts", updates)
    reverse = await apply_updates(TypedCrdtMemory(), "shared_facts", reversed(updates))

    if forward != reverse:
        raise AssertionError("TypedCrdtMemory set did not converge")

    decoded = json.loads(forward.decode("utf-8"))

    expected_values = [f"fact_{i}" for i in range(1, 9)]
    if decoded["type"] != "set":
        raise AssertionError("Expected set memory type")
    if decoded["values"] != expected_values:
        raise AssertionError(f"Expected {expected_values}, got {decoded['values']}")
    if len(decoded["items"]) != 8:
        raise AssertionError("Expected 8 set items")

    print("TypedCrdtMemory set: PASS")


async def validate_typed_crdt_counter() -> None:
    updates = make_counter_updates()

    forward = await apply_updates(TypedCrdtMemory(), "vote_count", updates)
    reverse = await apply_updates(TypedCrdtMemory(), "vote_count", reversed(updates))

    if forward != reverse:
        raise AssertionError("TypedCrdtMemory counter did not converge")

    decoded = json.loads(forward.decode("utf-8"))

    expected_counts = {f"agent_{i}": 1 for i in range(1, 9)}
    if decoded["type"] != "counter":
        raise AssertionError("Expected counter memory type")
    if decoded["counts"] != expected_counts:
        raise AssertionError(f"Expected {expected_counts}, got {decoded['counts']}")
    if decoded["total"] != 8:
        raise AssertionError(f"Expected total 8, got {decoded['total']}")

    print("TypedCrdtMemory counter: PASS")


async def validate_typed_crdt_vote() -> None:
    updates = make_vote_updates()

    forward = await apply_updates(TypedCrdtMemory(), "decision", updates)
    reverse = await apply_updates(TypedCrdtMemory(), "decision", reversed(updates))

    if forward != reverse:
        raise AssertionError("TypedCrdtMemory vote did not converge")

    decoded = json.loads(forward.decode("utf-8"))

    if decoded["type"] != "vote":
        raise AssertionError("Expected vote memory type")
    if len(decoded["ballots"]) != 8:
        raise AssertionError("Expected 8 ballots")
    if decoded["result"]["winner"] != "approve":
        raise AssertionError(f"Expected approve winner, got {decoded['result']['winner']}")
    if decoded["result"]["counts"] != {"approve": 7, "reject": 1}:
        raise AssertionError(f"Unexpected vote counts: {decoded['result']['counts']}")
    if decoded["result"]["confidence"] != 0.875:
        raise AssertionError(f"Expected confidence 0.875, got {decoded['result']['confidence']}")

    print("TypedCrdtMemory vote: PASS")


async def main() -> None:
    await validate_blackboard_fails()
    await validate_typed_crdt_set()
    await validate_typed_crdt_counter()
    await validate_typed_crdt_vote()
    print("All typed CRDT memory validators passed.")


if __name__ == "__main__":
    asyncio.run(main())