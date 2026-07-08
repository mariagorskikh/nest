# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for the OR-Set memory plugin.

Pins the algebraic laws that make a state-based OR-Set a CvRDT (Shapiro,
Preguica, Baquero & Zawirski, 2011): merge is commutative, associative, and
idempotent, so any merge order yields byte-identical state (strong eventual
consistency). Also pins the two semantic guarantees the plugin sells: add-wins
resolution survives arbitrary preceding interleavings, and observed-context CAS
never loses a concurrent update -- unlike a racing blackboard.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.or_set import OrSetMemory

_KEY = "k"
_EMPTY = b'{"crdt": "or_set", "adds": {}, "removed": []}'
_ELEMENTS = st.sampled_from(["a", "b", "c", "d", "e"])
_OP = st.tuples(st.sampled_from(["add", "remove"]), _ELEMENTS)
_OPS = st.lists(_OP, max_size=12)


def _add(element: str) -> bytes:
    return json.dumps({"op": "add", "element": element}, sort_keys=True).encode()


def _remove(element: str) -> bytes:
    return json.dumps({"op": "remove", "element": element}, sort_keys=True).encode()


def _require(state: bytes | None) -> bytes:
    assert state is not None
    return state


async def _source(node_id: str, ops: list[tuple[str, str]]) -> OrSetMemory:
    """Build a replica by applying an op sequence locally."""
    mem = OrSetMemory(node_id)
    for op, element in ops:
        await mem.write(_KEY, _add(element) if op == "add" else _remove(element))
    return mem


async def _merge_all(target: OrSetMemory, states: list[bytes]) -> bytes:
    for state in states:
        await target.merge(_KEY, state)
    export = target.export(_KEY)
    return export if export is not None else b""


@given(ops_a=_OPS, ops_b=_OPS)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_merge_is_commutative(
    ops_a: list[tuple[str, str]], ops_b: list[tuple[str, str]]
) -> None:
    """A then B merges to the same state as B then A."""
    a = await _source("sa", ops_a)
    b = await _source("sb", ops_b)
    state_a = a.export(_KEY) or _EMPTY
    state_b = b.export(_KEY) or _EMPTY
    left = await _merge_all(OrSetMemory("t1"), [state_a, state_b])
    right = await _merge_all(OrSetMemory("t2"), [state_b, state_a])
    assert left == right


@given(ops_a=_OPS, ops_b=_OPS, ops_c=_OPS)
@settings(max_examples=80, deadline=None)
@pytest.mark.asyncio
async def test_merge_is_associative(
    ops_a: list[tuple[str, str]],
    ops_b: list[tuple[str, str]],
    ops_c: list[tuple[str, str]],
) -> None:
    """((A merge B) merge C) equals (A merge (B merge C))."""
    a = await _source("sa", ops_a)
    b = await _source("sb", ops_b)
    c = await _source("sc", ops_c)
    state_a = a.export(_KEY) or _EMPTY
    state_b = b.export(_KEY) or _EMPTY
    state_c = c.export(_KEY) or _EMPTY

    # left = (A merge B) merge C
    ab = OrSetMemory("ab")
    await ab.merge(_KEY, state_a)
    await ab.merge(_KEY, state_b)
    left_target = OrSetMemory("left")
    await left_target.merge(_KEY, _require(ab.export(_KEY)))
    await left_target.merge(_KEY, state_c)

    # right = A merge (B merge C)
    bc = OrSetMemory("bc")
    await bc.merge(_KEY, state_b)
    await bc.merge(_KEY, state_c)
    right_target = OrSetMemory("right")
    await right_target.merge(_KEY, state_a)
    await right_target.merge(_KEY, _require(bc.export(_KEY)))

    assert left_target.export(_KEY) == right_target.export(_KEY)


@given(ops=_OPS)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_merge_is_idempotent(ops: list[tuple[str, str]]) -> None:
    """Merging the same state twice equals merging it once, and reports no change."""
    src = await _source("s", ops)
    state = src.export(_KEY)
    if state is None:
        return
    target = OrSetMemory("t")
    await target.merge(_KEY, state)
    once = target.export(_KEY)
    changed_again = await target.merge(_KEY, state)
    twice = target.export(_KEY)
    assert once == twice
    assert changed_again is False


@given(ops_a=_OPS, ops_b=_OPS, ops_c=_OPS, perm=st.permutations([0, 1, 2]))
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_permutation_invariance(
    ops_a: list[tuple[str, str]],
    ops_b: list[tuple[str, str]],
    ops_c: list[tuple[str, str]],
    perm: list[int],
) -> None:
    """Any order of merging the same three replica states yields identical bytes."""
    sources = [
        await _source("sa", ops_a),
        await _source("sb", ops_b),
        await _source("sc", ops_c),
    ]
    states = [_require(s.export(_KEY)) for s in sources if s.export(_KEY) is not None]
    baseline = await _merge_all(OrSetMemory("base"), states)
    reordered_states = [
        _require(sources[i].export(_KEY)) for i in perm if sources[i].export(_KEY) is not None
    ]
    permuted = await _merge_all(OrSetMemory("perm"), reordered_states)
    assert baseline == permuted


@given(churn=_OPS, element=_ELEMENTS)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_add_wins_under_arbitrary_interleaving(
    churn: list[tuple[str, str]], element: str
) -> None:
    """A fresh add of an element, concurrent with all prior removes, always wins.

    Arbitrary add/remove churn happens first across several replicas. Then a new
    replica observes the whole mess and adds ``element`` once more -- minting a
    tag no remover could have tombstoned. At convergence ``element`` is present.
    """
    churners = [await _source(f"c{i}", churn) for i in range(3)]
    states = [_require(c.export(_KEY)) for c in churners if c.export(_KEY) is not None]

    adder = OrSetMemory("adder")
    for state in states:
        await adder.merge(_KEY, state)
    await adder.write(_KEY, _add(element))  # fresh, unobservable-by-removers tag

    converged = OrSetMemory("conv")
    for state in [*states, _require(adder.export(_KEY))]:
        await converged.merge(_KEY, state)
    present = json.loads(_require(await converged.read(_KEY)))
    assert element in present


@given(x=_ELEMENTS, y=_ELEMENTS)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_observed_context_cas_never_loses_update(x: str, y: str) -> None:
    """Two racing observed-context CAS adds both survive the merge (no lost update).

    Both replicas start from a shared base, each captures that context, and each
    CAS-adds a distinct element concurrently. Because merge unions add-tags,
    neither update is lost -- the lost-update-freedom an OR-Set guarantees.
    """
    if x == y:
        return
    base = OrSetMemory("base")
    await base.write(_KEY, _add("seed"))
    base_state = _require(base.export(_KEY))

    a = OrSetMemory("a")
    b = OrSetMemory("b")
    await a.merge(_KEY, base_state)
    await b.merge(_KEY, base_state)
    ctx_a = _require(a.export(_KEY))
    ctx_b = _require(b.export(_KEY))

    assert await a.cas(_KEY, ctx_a, _add(x)) is True
    assert await b.cas(_KEY, ctx_b, _add(y)) is True

    await a.merge(_KEY, _require(b.export(_KEY)))
    await b.merge(_KEY, _require(a.export(_KEY)))
    present_a = set(json.loads(_require(await a.read(_KEY))))
    assert {x, y} <= present_a
    assert (await a.read(_KEY)) == (await b.read(_KEY))


@given(x=_ELEMENTS, y=_ELEMENTS)
@settings(max_examples=50, deadline=None)
@pytest.mark.asyncio
async def test_blackboard_races_and_loses_an_update(x: str, y: str) -> None:
    """Contrast: a blackboard under the same concurrent CAS pattern loses an update.

    The same two distinct writes, applied to one shared blackboard as racing
    compare-and-swaps and then serialized, cannot both survive -- exactly the
    lost update an OR-Set's union merge prevents.
    """
    if x == y:
        return
    bb = Blackboard()
    await bb.write(_KEY, b"seed")
    # Two racers each swap from the same observed value; the second clobbers.
    assert await bb.cas(_KEY, b"seed", x.encode()) is True
    assert await bb.cas(_KEY, b"seed", y.encode()) is False
    final = await bb.read(_KEY)
    # Only one of the two updates survives; there is no set to hold both.
    assert final == x.encode()
    assert final != y.encode()
