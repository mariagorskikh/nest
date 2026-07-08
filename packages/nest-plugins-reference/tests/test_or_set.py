# SPDX-License-Identifier: Apache-2.0
"""Example-based tests for the OR-Set (observed-remove set) memory plugin.

Covers the observed-remove semantics of Shapiro, Preguica, Baquero & Zawirski
(2011), Section 3.3.5: empty and single-element sets, the add/remove/re-add
lifecycle, add-wins under concurrent add||remove, idempotent self-merge,
cross-key isolation, structured-op parsing with the documented plain-bytes
fallback, observed-context CAS, and rejection of malformed merge payloads
without state corruption.
"""

from __future__ import annotations

import json

import pytest
from nest_plugins_reference.memory.or_set import (
    CRDT_KIND,
    OrSetMemory,
    OrSetStateError,
)


def _add(element: object) -> bytes:
    return json.dumps({"op": "add", "element": element}, sort_keys=True).encode()


def _remove(element: object) -> bytes:
    return json.dumps({"op": "remove", "element": element}, sort_keys=True).encode()


def _present(raw: bytes | None) -> list[object]:
    assert raw is not None
    return list(json.loads(raw))


class TestReadWrite:
    async def test_unset_key_reads_none(self) -> None:
        mem = OrSetMemory("a")
        assert await mem.read("missing") is None

    async def test_single_element_present(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        assert await mem.read("held") == b'["slot-1"]'

    async def test_empty_after_add_then_remove(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        await mem.write("held", _remove("slot-1"))
        assert await mem.read("held") == b"[]"

    async def test_add_remove_re_add(self) -> None:
        # Re-adding after a remove mints a FRESH tag not covered by the old
        # tombstone, so the element comes back -- the OR-Set's defining behavior.
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        await mem.write("held", _remove("slot-1"))
        assert await mem.read("held") == b"[]"
        await mem.write("held", _add("slot-1"))
        assert await mem.read("held") == b'["slot-1"]'

    async def test_read_is_sorted_and_canonical(self) -> None:
        mem = OrSetMemory("a")
        for element in ("slot-3", "slot-1", "slot-2"):
            await mem.write("held", _add(element))
        # Present list is sorted by canonical element key -> byte-deterministic.
        assert await mem.read("held") == b'["slot-1","slot-2","slot-3"]'

    async def test_duplicate_add_is_idempotent_read(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        await mem.write("held", _add("slot-1"))
        assert await mem.read("held") == b'["slot-1"]'


class TestOpParsing:
    async def test_plain_bytes_fallback_is_add(self) -> None:
        # Documented decision: a non-op byte payload is treated as add of the
        # UTF-8 string, keeping the plugin drop-in for opaque-byte callers.
        mem = OrSetMemory("a")
        await mem.write("held", b"slot-9")
        assert await mem.read("held") == b'["slot-9"]'

    async def test_non_string_element_supported(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("held", _add({"host": "h1", "port": 22}))
        present = _present(await mem.read("held"))
        assert present == [{"host": "h1", "port": 22}]

    async def test_remove_requires_explicit_op(self) -> None:
        # A raw byte string that happens to read like "remove" is still an add;
        # only the structured op form can delete, so nothing deletes by accident.
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        await mem.write("held", b"remove")
        present = _present(await mem.read("held"))
        assert set(present) == {"slot-1", "remove"}

    async def test_malformed_op_object_falls_back_to_add(self) -> None:
        mem = OrSetMemory("a")
        # Valid JSON, but not an op object -> treated as add of the raw text.
        await mem.write("held", b'{"not":"an-op"}')
        present = _present(await mem.read("held"))
        assert present == ['{"not":"an-op"}']


class TestCrossKeyIsolation:
    async def test_keys_are_independent(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("k1", _add("x"))
        await mem.write("k2", _add("y"))
        assert await mem.read("k1") == b'["x"]'
        assert await mem.read("k2") == b'["y"]'
        await mem.write("k1", _remove("x"))
        assert await mem.read("k1") == b"[]"
        assert await mem.read("k2") == b'["y"]'


class TestMergeGossip:
    async def test_merge_unions_disjoint_adds(self) -> None:
        a = OrSetMemory("a")
        b = OrSetMemory("b")
        await a.write("held", _add("slot-1"))
        await b.write("held", _add("slot-2"))
        await a.merge("held", _require(b.export("held")))
        await b.merge("held", _require(a.export("held")))
        assert await a.read("held") == await b.read("held")
        assert _present(await a.read("held")) == ["slot-1", "slot-2"]

    async def test_self_merge_is_noop(self) -> None:
        a = OrSetMemory("a")
        await a.write("held", _add("slot-1"))
        changed = await a.merge("held", _require(a.export("held")))
        assert changed is False
        assert await a.read("held") == b'["slot-1"]'

    async def test_merge_is_idempotent(self) -> None:
        a = OrSetMemory("a")
        b = OrSetMemory("b")
        await b.write("held", _add("slot-2"))
        state = _require(b.export("held"))
        assert await a.merge("held", state) is True
        assert await a.merge("held", state) is False

    async def test_merge_returns_false_when_present_unchanged(self) -> None:
        # Merging an add whose element is already present (via another tag) does
        # not change the present set, so merge reports no change.
        a = OrSetMemory("a")
        b = OrSetMemory("b")
        await a.write("held", _add("slot-1"))
        await b.write("held", _add("slot-1"))
        assert await a.merge("held", _require(b.export("held"))) is False

    async def test_export_all_merge_all_roundtrip(self) -> None:
        a = OrSetMemory("a")
        b = OrSetMemory("b")
        await a.write("k1", _add("x"))
        await a.write("k2", _add("y"))
        changed = await b.merge_all(a.export_all())
        assert sorted(changed) == ["k1", "k2"]
        assert await b.read("k1") == b'["x"]'
        assert await b.read("k2") == b'["y"]'

    async def test_export_unset_key_is_none(self) -> None:
        assert OrSetMemory("a").export("missing") is None


class TestAddWins:
    async def test_concurrent_add_beats_remove(self) -> None:
        # r1 adds x; r2 observes x then removes it; concurrently r1 re-adds x
        # with a fresh tag r2 never saw. After merge, x is present (add-wins).
        r1 = OrSetMemory("r1")
        r2 = OrSetMemory("r2")
        await r1.write("k", _add("x"))
        await r2.merge("k", _require(r1.export("k")))
        await r2.write("k", _remove("x"))
        await r1.write("k", _add("x"))  # concurrent, unobserved by r2
        await r1.merge("k", _require(r2.export("k")))
        await r2.merge("k", _require(r1.export("k")))
        assert await r1.read("k") == await r2.read("k")
        assert await r1.read("k") == b'["x"]'


class TestObservedContextCas:
    async def test_cas_applies_on_current_context(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        ctx = _require(mem.export("held"))
        ok = await mem.cas("held", ctx, _add("slot-2"))
        assert ok is True
        assert _present(await mem.read("held")) == ["slot-1", "slot-2"]

    async def test_cas_rejects_stale_context(self) -> None:
        # Capture context, then let a concurrent add land via merge; the stale
        # context no longer covers the live tag-set, so the CAS is rejected.
        a = OrSetMemory("a")
        b = OrSetMemory("b")
        await a.write("held", _add("slot-1"))
        stale = _require(a.export("held"))
        await b.write("held", _add("slot-2"))
        await a.merge("held", _require(b.export("held")))
        ok = await a.cas("held", stale, _add("slot-3"))
        assert ok is False
        assert "slot-3" not in _present(await a.read("held"))

    async def test_cas_on_fresh_key_with_empty_context(self) -> None:
        mem = OrSetMemory("a")
        ok = await mem.cas("held", b'{"crdt": "or_set", "adds": {}, "removed": []}', _add("slot-1"))
        assert ok is True
        assert await mem.read("held") == b'["slot-1"]'

    async def test_cas_on_malformed_context_returns_false(self) -> None:
        mem = OrSetMemory("a")
        assert await mem.cas("held", b"not json", _add("slot-1")) is False


class TestMalformedRejected:
    async def test_merge_rejects_non_json(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        before = await mem.read("held")
        with pytest.raises(OrSetStateError):
            await mem.merge("held", b"not json")
        assert await mem.read("held") == before

    async def test_merge_rejects_wrong_crdt_tag(self) -> None:
        mem = OrSetMemory("a")
        payload = json.dumps({"crdt": "lww_register", "adds": {}, "removed": []}).encode()
        with pytest.raises(OrSetStateError):
            await mem.merge("held", payload)

    async def test_merge_rejects_malformed_tag(self) -> None:
        mem = OrSetMemory("a")
        await mem.write("held", _add("slot-1"))
        before = await mem.read("held")
        bad = json.dumps(
            {"crdt": CRDT_KIND, "adds": {'"x"': [["node", "not-an-int"]]}, "removed": []}
        ).encode()
        with pytest.raises(OrSetStateError):
            await mem.merge("held", bad)
        # State untouched by the rejected merge.
        assert await mem.read("held") == before

    async def test_merge_rejects_non_pair_tag(self) -> None:
        mem = OrSetMemory("a")
        bad = json.dumps(
            {"crdt": CRDT_KIND, "adds": {'"x"': [["only-one"]]}, "removed": []}
        ).encode()
        with pytest.raises(OrSetStateError):
            await mem.merge("held", bad)

    async def test_merge_rejects_bool_counter(self) -> None:
        # A JSON bool would int()-coerce to 0/1; reject it so a forged bool tag
        # cannot alias a real integer-counter tag.
        mem = OrSetMemory("a")
        bad = json.dumps(
            {"crdt": CRDT_KIND, "adds": {'"x"': [["node", True]]}, "removed": []}
        ).encode()
        with pytest.raises(OrSetStateError):
            await mem.merge("held", bad)


class TestProperties:
    async def test_node_id_and_counter_exposed(self) -> None:
        mem = OrSetMemory("agent-0")
        assert mem.node_id == "agent-0"
        assert mem.counter == 0
        await mem.write("held", _add("slot-1"))
        assert mem.counter == 1

    async def test_counter_advances_past_merged_self_tags(self) -> None:
        # After merging back a state echoing this replica's own high-counter tag,
        # a fresh local add must not re-mint a colliding (already-tombstoned) tag.
        a = OrSetMemory("a")
        forged_self = json.dumps(
            {"crdt": CRDT_KIND, "adds": {'"x"': [["a", 100]]}, "removed": []}
        ).encode()
        await a.merge("held", forged_self)
        await a.write("held", _add("y"))
        assert a.counter > 100


def _require(state: bytes | None) -> bytes:
    assert state is not None
    return state
