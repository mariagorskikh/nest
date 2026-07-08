# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests: the honest-write-liveness red-team of the memory plugins.

These tests run the two factory-based CRDT validators against three memory
plugins and assert the discrimination matrix the charter asks for:

* ``validate_memory_honest_write_liveness`` -- a Byzantine replica forges state,
  an honest replica writes before observing it, both gossip to convergence:

    - ``lww_register``  FAILS  (a register forged with ``lamport = 2**60`` wins
      the ``max(clock, incoming)`` merge at ``lww_register.py:305`` and silently
      suppresses the honest write),
    - ``blackboard``    FAILS  (the later Byzantine value clobbers the honest one),
    - ``or_set``        PASSES (a Byzantine replica cannot tombstone an add-tag
      it never observed, so the honest claim survives).

* ``validate_crdt_add_wins_convergence`` -- concurrent add||remove on one element:

    - ``blackboard``    FAILS  (no set to converge, no add-wins),
    - ``or_set``        PASSES (byte-identical convergence + add-wins).

The point of this file: it ships a validator that FAILS a plugin already merged
into ``main`` (``lww_register``), which is exactly the "make the host catch
something it currently wouldn't" the charter demands.
"""

from __future__ import annotations

import base64
import json
from typing import Any, cast

from nest_core.validators import (
    validate_crdt_add_wins_convergence,
    validate_memory_honest_write_liveness,
)
from nest_plugins_reference.memory.blackboard import Blackboard
from nest_plugins_reference.memory.lww_register import LwwRegisterMemory
from nest_plugins_reference.memory.or_set import CRDT_KIND, OrSetMemory

_HONEST = "honest-claim"


def _element_key(element: str) -> str:
    """Canonical OR-Set element key, mirroring the plugin's internal encoding."""
    return json.dumps(element, sort_keys=True, separators=(",", ":"))


# -- forge functions: how each plugin's Byzantine replica fabricates state ----


def _forge_lww(_byz: Any) -> bytes:
    """A register forged with an astronomically large Lamport clock."""
    return json.dumps(
        {
            "crdt": "lww_register",
            "payload": base64.b64encode(b"BYZANTINE").decode("ascii"),
            "lamport": 2**60,
            "node": "node-0",
        },
        sort_keys=True,
    ).encode()


def _forge_orset(_byz: Any) -> bytes:
    """An OR-Set forged with an inflated counter and a fabricated honest tombstone.

    The inflated counter only mints a Byzantine-owned tag; the fabricated
    tombstone ``(node-1, 2**60)`` targets an honest node but with a counter no
    honest add ever used, so it removes nothing real.
    """
    return json.dumps(
        {
            "crdt": CRDT_KIND,
            "adds": {_element_key("BYZANTINE"): [["node-0", 2**60]]},
            "removed": [["node-1", 2**60]],
        },
        sort_keys=True,
    ).encode()


def _forge_blackboard(_byz: Any) -> bytes:
    """No CvRDT channel: the Byzantine value is delivered as a raw later write."""
    return b"BYZANTINE-JUNK"


def _bb_factory(_node_id: str) -> Blackboard:
    """Blackboard ignores the node id (it is not a replica-aware CRDT)."""
    return Blackboard()


# -- add/remove op adapters (identical ops for or_set and blackboard) ---------


def _add_op(element: str) -> bytes:
    return json.dumps({"op": "add", "element": element}, sort_keys=True).encode()


def _remove_op(element: str) -> bytes:
    return json.dumps({"op": "remove", "element": element}, sort_keys=True).encode()


def _present(raw: bytes | None) -> set[str]:
    if not raw:
        return set()
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return set()
    if not isinstance(parsed, list):
        return set()
    return {str(element) for element in cast("list[Any]", parsed)}


def _passed(results: list[Any]) -> bool:
    return bool(results) and all(r.passed for r in results)


class TestHonestWriteLiveness:
    async def test_lww_register_fails(self) -> None:
        results = await validate_memory_honest_write_liveness(
            LwwRegisterMemory,
            forge=_forge_lww,
            honest_op=_HONEST.encode(),
            is_visible=lambda v: v == _HONEST.encode(),
        )
        assert not _passed(results)
        assert "suppressed" in results[0].detail

    async def test_blackboard_fails(self) -> None:
        results = await validate_memory_honest_write_liveness(
            _bb_factory,
            forge=_forge_blackboard,
            honest_op=_HONEST.encode(),
            is_visible=lambda v: v == _HONEST.encode(),
        )
        assert not _passed(results)

    async def test_or_set_passes(self) -> None:
        results = await validate_memory_honest_write_liveness(
            OrSetMemory,
            forge=_forge_orset,
            honest_op=_add_op(_HONEST),
            is_visible=lambda v: v is not None and _HONEST in json.loads(v),
        )
        assert _passed(results)


class TestAddWinsConvergence:
    async def test_or_set_passes(self) -> None:
        results = await validate_crdt_add_wins_convergence(
            OrSetMemory,
            add_op=_add_op,
            remove_op=_remove_op,
            present=_present,
        )
        assert _passed(results)
        names = {r.name for r in results}
        assert {"crdt_add_wins_converged", "crdt_add_wins_resolution"} <= names

    async def test_blackboard_fails(self) -> None:
        results = await validate_crdt_add_wins_convergence(
            _bb_factory,
            add_op=_add_op,
            remove_op=_remove_op,
            present=_present,
        )
        assert not _passed(results)


class TestVerifiedVulnerabilityRepro:
    async def test_lww_register_silently_suppresses_honest_write(self) -> None:
        """Direct repro of the lww_register.py:305 finding, independent of the validator.

        An honest replica commits a legitimate write, then merges a register a
        Byzantine peer forged with ``lamport = 2**60``. The honest write is
        silently discarded -- the write-suppression this submission red-teams.
        """
        honest = LwwRegisterMemory("honest")
        await honest.write("slot", b"honest-claim")
        assert await honest.read("slot") == b"honest-claim"
        forged = _forge_lww(None)
        await honest.merge("slot", forged)
        assert await honest.read("slot") == b"BYZANTINE"  # honest write lost

    async def test_or_set_preserves_honest_write_under_same_attack(self) -> None:
        """The same attack against the OR-Set leaves the honest claim intact."""
        honest = OrSetMemory("honest")
        await honest.write("slot", _add_op("honest-claim"))
        await honest.merge("slot", _forge_orset(None))
        present = json.loads(await honest.read("slot") or b"[]")
        assert "honest-claim" in present
