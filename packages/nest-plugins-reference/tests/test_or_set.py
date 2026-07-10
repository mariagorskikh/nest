from __future__ import annotations

import random
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_crdt_convergence, validate_trace
from nest_plugins_reference.memory.or_set import OrSetMemory


@pytest.mark.asyncio
async def test_add_and_read() -> None:
    mem = OrSetMemory("a")
    await mem.write("k", b"apple")
    assert await mem.read("k") == b"apple"


@pytest.mark.asyncio
async def test_remove_and_read_absent() -> None:
    mem = OrSetMemory("a")
    await mem.write("k", b"apple")
    assert await mem.remove("k", b"apple") is True
    assert await mem.read("k") is None


@pytest.mark.asyncio
async def test_re_add_after_remove() -> None:
    mem = OrSetMemory("a")
    await mem.write("k", b"apple")
    await mem.remove("k", b"apple")
    await mem.write("k", b"apple")  # new tag
    assert await mem.read("k") == b"apple"


@pytest.mark.asyncio
async def test_export_merge_converge() -> None:
    a = OrSetMemory("a")
    b = OrSetMemory("b")
    await a.write("k", b"x")
    await b.write("k", b"y")
    a_export = a.export("k")
    assert a_export is not None
    await b.merge("k", a_export)
    b_export = b.export("k")
    assert b_export is not None
    await a.merge("k", b_export)
    assert await a.read("k") == await b.read("k")
    # either "x" or "y" is fine as long as they agree; in practice both are present.
    assert await a.read("k") in (b"x", b"y")


@pytest.mark.asyncio
async def test_merge_is_idempotent() -> None:
    a = OrSetMemory("a")
    await a.write("k", b"v")
    state = a.export("k")
    assert state is not None
    await a.merge("k", state)
    await a.merge("k", state)
    assert a.export("k") == state


@pytest.mark.asyncio
async def test_merge_is_commutative() -> None:
    a = OrSetMemory("a")
    b = OrSetMemory("b")
    await a.write("k", b"v")
    await b.write("k", b"w")
    ab = a.export("k")
    ba = b.export("k")

    a2 = OrSetMemory("a")
    b2 = OrSetMemory("b")
    assert ba is not None
    assert ab is not None
    await a2.merge("k", ba)
    await a2.merge("k", ab)  # order reversed
    await b2.merge("k", ab)
    await b2.merge("k", ba)
    assert a2.export("k") == b2.export("k")


@pytest.mark.asyncio
async def test_or_set_convergence_under_reordered_deliveries() -> None:
    writes = [
        (0, b"a"),
        (1, b"b"),
        (2, b"c"),
        (0, b"d"),
        (1, b"e"),
        (2, b"f"),
    ]
    # Different delivery orders per replica (permutes).
    delivery_orders = [
        [0, 1, 2, 3, 4, 5],
        [5, 4, 3, 2, 1, 0],
        [2, 0, 4, 1, 5, 3],
    ]
    results = await validate_crdt_convergence(
        OrSetMemory,
        writes=writes,
        delivery_orders=delivery_orders,
        key="k",
    )
    for r in results:
        assert r.passed, r.detail


@pytest.mark.asyncio
async def test_concurrent_removes_converge_under_reordered_merge() -> None:
    """Two replicas observe the same removes in different orders.
    Their exported canonical state must be byte-identical.
    """
    # Agent A writes and removes "x"
    a = OrSetMemory("a")
    await a.write("k", b"x")
    await a.remove("k", b"x")

    # Agent B writes and removes "y"
    b = OrSetMemory("b")
    await b.write("k", b"y")
    await b.remove("k", b"y")

    # Replica 1 merges A then B
    r1 = OrSetMemory("r1")
    a_export = a.export("k")
    b_export = b.export("k")
    assert a_export is not None
    assert b_export is not None
    await r1.merge("k", a_export)
    await r1.merge("k", b_export)

    # Replica 2 merges B then A (reversed order)
    r2 = OrSetMemory("r2")
    await r2.merge("k", b_export)
    await r2.merge("k", a_export)

    # Must be byte-identical despite different merge orders
    assert r1.export("k") == r2.export("k"), "Tombstone ordering is not canonical"


@pytest.mark.asyncio
async def test_write_overwrites_are_readable() -> None:
    """Later write() calls must be visible via read().

    Before the fix, read() sorted tags ascending so the first write
    (smallest tag) always won -- the key was effectively write-once.
    After the fix, read() sorts descending so the latest write wins.
    """
    mem = OrSetMemory("a")
    await mem.write("k", b"apple")
    await mem.write("k", b"banana")
    # Latest write must win, not the first-ever write.
    assert await mem.read("k") == b"banana"


@pytest.mark.asyncio
async def test_sorting_ignores_lexicographical_node_priority() -> None:
    """Verify that a node with lexicographically greater name does not override clocks.

    'writer-1:0' has a lexicographically greater string tag than 'writer-0:100'.
    However, the tick 100 is higher, so it must win the read() resolution.
    """
    a = OrSetMemory("writer-1")
    b = OrSetMemory("writer-0")

    await a.write("k", b"apple")  # Tag: writer-1:0
    for _ in range(101):
        await b.write("k", b"banana")  # Tag: writer-0:100 (after 101 writes)

    # Now merge both states into a single replica
    merged = OrSetMemory("merged")
    a_state = a.export("k")
    b_state = b.export("k")
    assert a_state is not None
    assert b_state is not None
    await merged.merge("k", a_state)
    await merged.merge("k", b_state)

    # The latest write (banana, tick 100) must win, despite 'writer-1' > 'writer-0'
    assert await merged.read("k") == b"banana"


@pytest.mark.asyncio
async def test_tick_synchronization_on_merge() -> None:
    """Replica local _tick counter must sync to max incoming tick from same node.

    This avoids collisions on restarts.
    """
    a = OrSetMemory("node-a")
    await a.write("k", b"v1")  # tick = 0
    await a.write("k", b"v2")  # tick = 1

    # Create a fresh replica with same node_id (e.g. after a restart)
    b = OrSetMemory("node-a")
    assert b.tick == 0

    # Merge state from a (which contains node-a:0 and node-a:1)
    a_state = a.export("k")
    assert a_state is not None
    await b.merge("k", a_state)

    # Local tick of b must have advanced beyond 1 to avoid tag collisions on subsequent writes
    assert b.tick >= 2
    await b.write("k", b"v3")  # This should be node-a:2

    # Verify we can read it and it's not tombstoned or collided
    assert await b.read("k") == b"v3"


@pytest.mark.asyncio
async def test_defensive_schema_checks() -> None:
    """Verify that merge() and cas() don't crash the program on malformed schema inputs."""
    mem = OrSetMemory("a")

    # 1. merge() with invalid JSON
    assert await mem.merge("k", b"invalid-json") is False

    # 2. merge() with wrong CRDT kind
    assert await mem.merge("k", b'{"crdt": "other", "elements": {}}') is False

    # 3. merge() with missing fields
    assert await mem.merge("k", b'{"crdt": "or_set"}') is False

    # 4. cas() with invalid expected/new type
    from typing import Any, cast

    assert await mem.cas("k", cast("Any", "not-bytes"), b"new") is False
    assert await mem.cas("k", b"old", cast("Any", "not-bytes")) is False


@pytest.mark.asyncio
async def test_cas_operates_on_raw_payload() -> None:
    """cas() must compare raw user payloads, not CRDT JSON envelopes.

    Before the fix, cas() compared expected against the full exported
    JSON state (b'{"crdt": "or_set", ...}'), making standard calls
    like mem.cas("k", b"apple", b"banana") always fail.
    """
    mem = OrSetMemory("a")
    await mem.write("k", b"apple")
    # Standard protocol: compare raw bytes, swap to new raw bytes.
    ok = await mem.cas("k", b"apple", b"banana")
    assert ok is True
    assert await mem.read("k") == b"banana"

    # Wrong expected: must fail cleanly without crashing.
    ok2 = await mem.cas("k", b"apple", b"cherry")
    assert ok2 is False
    assert await mem.read("k") == b"banana"


@pytest.mark.asyncio
async def test_subscribe_yields_raw_payload_not_crdt_envelope() -> None:
    """subscribe() must emit raw payload bytes, not CRDT JSON.

    Before the fix, subscribers received the full JSON envelope
    (e.g. b'{"crdt": "or_set", "elements": {...}, "tombstones": []}').
    After the fix, they receive the same bytes that read() returns,
    matching the lww_register contract.
    """
    import asyncio
    import contextlib

    mem = OrSetMemory("a")
    received: list[bytes] = []

    async def drain() -> None:
        async for val in mem.subscribe("k"):
            received.append(val)
            break  # only capture the first notification

    task = asyncio.create_task(drain())
    await asyncio.sleep(0)  # yield to let subscriber register
    await mem.write("k", b"hello")
    await asyncio.sleep(0)  # yield to let subscriber receive
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    assert len(received) == 1
    assert received[0] == b"hello", (
        f"Expected raw payload b'hello', got {received[0]!r}. "
        "subscribe() must not leak CRDT envelopes."
    )


@pytest.mark.asyncio
async def test_merge_no_notification_when_no_change() -> None:
    """merge() must not fire subscriber notifications when state is unchanged.

    Before the fix, merge() unconditionally called _notify(), which would
    cause infinite broadcast cascades in gossip protocols.
    """
    import asyncio
    import contextlib

    mem = OrSetMemory("a")
    await mem.write("k", b"v")
    state = mem.export("k")
    assert state is not None

    notification_count = 0

    async def count_notifications() -> None:
        nonlocal notification_count
        async for _ in mem.subscribe("k"):
            notification_count += 1

    task = asyncio.create_task(count_notifications())
    await asyncio.sleep(0)

    # Merge the same state twice -- idempotent, no new info.
    await mem.merge("k", state)
    await mem.merge("k", state)
    await asyncio.sleep(0)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    assert notification_count == 0, (
        f"Expected 0 notifications for no-op merges, got {notification_count}. "
        "merge() must not fire on unchanged state."
    )


@given(
    values=st.lists(st.binary(min_size=1, max_size=10), min_size=2, max_size=5),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
)
@settings(max_examples=50, deadline=None)
@pytest.mark.asyncio
async def test_merge_converges_for_any_operation_sequence(values: list[bytes], seed: int) -> None:
    """Property: for any sequence of adds/removes across two replicas,
    bilateral merge always produces identical canonical state.
    """
    rng = random.Random(seed)

    a = OrSetMemory("a")
    b = OrSetMemory("b")

    # Apply random operations to each replica
    for _ in range(20):
        val = rng.choice(values)
        if rng.random() < 0.7:
            await a.write("k", val)
        else:
            await a.remove("k", val)

        val = rng.choice(values)
        if rng.random() < 0.7:
            await b.write("k", val)
        else:
            await b.remove("k", val)

    # Full bilateral merge
    a_export = a.export("k")
    b_export = b.export("k")
    if a_export is not None:
        await b.merge("k", a_export)
    if b_export is not None:
        await a.merge("k", b_export)

    b_export2 = b.export("k")
    if b_export2 is not None:
        await a.merge("k", b_export2)  # quiesce

    assert a.export("k") == b.export("k"), "OR-Set failed to converge"


@pytest.mark.asyncio
async def test_read_your_writes_after_merge() -> None:
    """merge() must advance local tick past ALL incoming tags (Lamport's rule).
    Otherwise, a local write following a merge might be assigned a stale tick,
    causing it to lose read() resolution to older remote values.
    """
    a = OrSetMemory("a")
    for _ in range(50):
        await a.write("k", b"old")  # tags up to a:49
    b = OrSetMemory("b")
    a_export = a.export("k")
    assert a_export is not None
    await b.merge("k", a_export)  # b._tick must advance to at least 50
    await b.write("k", b"new")  # tag b:50
    assert await b.read("k") == b"new"  # must win against a:49


@pytest.mark.asyncio
async def test_add_wins_concurrent() -> None:
    """Add-wins: if replica A removes x while replica B concurrently re-adds it,
    post-merge both read it as present because B's fresh tag is not tombstoned.
    """
    a = OrSetMemory("a")
    b = OrSetMemory("b")

    # Common base state
    await a.write("k", b"x")
    base_state = a.export("k")
    assert base_state is not None
    await a.merge("k", base_state)
    await b.merge("k", base_state)

    # A removes x
    await a.remove("k", b"x")
    assert await a.read("k") is None

    # B concurrently re-adds x
    await b.write("k", b"x")
    assert await b.read("k") == b"x"

    # Merge and verify add-wins
    a_state = a.export("k")
    b_state = b.export("k")
    assert a_state is not None
    assert b_state is not None

    await a.merge("k", b_state)
    await b.merge("k", a_state)

    # Both must resolve to present
    assert await a.read("k") == b"x"
    assert await b.read("k") == b"x"


class TestScenario:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [42, 7, 1337])
    async def test_scenario_converges_and_is_deterministic(self, seed: int) -> None:
        traces: list[bytes] = []
        with tempfile.TemporaryDirectory() as tmp:
            for run in range(2):
                config = ScenarioConfig.from_yaml("scenarios/memory_or_set.yaml")
                config.seed = seed
                out = Path(tmp) / f"run-{run}.jsonl"
                config.output.trace = str(out)
                trace_path = await ScenarioRunner(config).run()
                traces.append(trace_path.read_bytes())
                if run == 0:
                    results = validate_trace(trace_path, "memory_or_set_writers")
                    assert results, "validator produced no results"
                    assert all(r.passed for r in results), [r.detail for r in results]
        assert traces[0] == traces[1], "trace not byte-identical under same seed"
