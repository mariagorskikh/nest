# SPDX-License-Identifier: Apache-2.0
"""Basis-gated memory: only fuse evidence that restricts onto a declared basis.

``PnCounterMemory`` answers "how do concurrent signed deltas converge without
loss". It does not answer "which reports are *allowed* to become deltas". That
second question -- basis-restricted fusion -- used to live inside a bespoke
scenario coordinator, which meant the reusable artifact was "a PN-Counter plus
some scenario glue" rather than "memory that only fuses legal evidence".

``BasisGatedMemory`` lifts that gate to the memory layer. It wraps an inner
``Memory`` (a ``PnCounterMemory`` by default) and, on every ``write``/``fuse``,
validates the payload against a declared per-node basis before any delta reaches
the inner counter:

* the payload must be a JSON object (else ``not-json`` / ``not-object``),
* its ``node`` must be a declared node (else ``no-overlap``),
* its ``basis`` must be one of that node's declared dimensions (else
  ``outside-basis``),
* and each ``(node, basis)`` pair fuses at most once (else ``duplicate``).

Only a payload that clears all four gates is written to the inner counter as a
signed increment. Context saturation -- a wall of natural-language or
code-shaped text -- has no ``node``/``basis`` that restricts onto the task, so
it is ignored rather than absorbed, no matter how large or plausible it looks.

Read/subscribe/cas and the CRDT gossip helpers (``export``/``merge``/...) all
delegate to the inner memory, so a basis-gated counter still converges across
replicas exactly like a plain ``PnCounterMemory``.

Example::

    mem = BasisGatedMemory("coordinator", bases={"calculator": {"add", "divide"}})
    outcome = await mem.fuse("calculator:ready_score", b'{"node":"calculator","basis":"add"}')
    assert outcome.accepted
    assert await mem.read("calculator:ready_score") == b"1"
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from nest_plugins_reference.memory.pn_counter import PnCounterMemory

# Ignore reasons emitted for non-fusable payloads. These strings are part of the
# scenario trace contract consumed by validate_basis_fusion_calculator_action.
REASON_FUSED = "fused"
REASON_NOT_JSON = "not-json"
REASON_NOT_OBJECT = "not-object"
REASON_NO_OVERLAP = "no-overlap"
REASON_OUTSIDE_BASIS = "outside-basis"
REASON_DUPLICATE = "duplicate"


@dataclass(frozen=True)
class FusionOutcome:
    """Result of evaluating one report against the declared basis.

    Example::

        outcome = FusionOutcome(accepted=True, reason="fused", node="calculator", basis="add")
    """

    accepted: bool
    reason: str
    node: str | None = None
    basis: str | None = None


class BasisGatedMemory:
    """A ``Memory`` that only fuses reports restricting onto a declared basis.

    Example::

        mem = BasisGatedMemory("node", bases={"calculator": {"add"}})
    """

    def __init__(
        self,
        node_id: str = "node",
        *,
        bases: Mapping[str, Iterable[str]] | None = None,
        inner: PnCounterMemory | None = None,
    ) -> None:
        """Create a gate over ``inner`` (a fresh ``PnCounterMemory`` by default).

        Example::

            mem = BasisGatedMemory("coordinator", bases={"calculator": {"add"}})
        """
        self._node_id = str(node_id)
        self._inner = inner if inner is not None else PnCounterMemory(node_id)
        self._bases: dict[str, frozenset[str]] = {}
        for node, dims in (bases or {}).items():
            self.declare(node, dims)
        self._fused: set[tuple[str, str]] = set()
        self._ignored = 0

    def declare(self, node: str, dimensions: Iterable[str]) -> None:
        """Declare (or extend) the basis dimensions a node can fuse on.

        Example::

            mem.declare("calculator", {"add", "subtract"})
        """
        current = self._bases.get(str(node), frozenset())
        self._bases[str(node)] = current | frozenset(str(d) for d in dimensions)

    def declared_basis(self, node: str) -> frozenset[str]:
        """Return the declared basis dimensions for ``node``.

        Example::

            assert "add" in mem.declared_basis("calculator")
        """
        return self._bases.get(str(node), frozenset())

    def fused_basis(self, node: str) -> frozenset[str]:
        """Return the basis dimensions that have actually fused for ``node``.

        Example::

            assert mem.fused_basis("calculator") <= mem.declared_basis("calculator")
        """
        return frozenset(basis for (n, basis) in self._fused if n == str(node))

    @property
    def ignored(self) -> int:
        """Count of reports rejected by the basis gate.

        Example::

            assert BasisGatedMemory("n").ignored == 0
        """
        return self._ignored

    async def fuse(self, key: str, report: bytes) -> FusionOutcome:
        """Fuse ``report`` into the ``key`` counter iff it clears the basis gate.

        Returns the decision so a caller can trace accepts and ignores. A
        rejected report leaves the inner counter untouched.

        Example::

            outcome = await mem.fuse("calculator:ready_score", report)
        """
        outcome = self._evaluate(report)
        if not outcome.accepted:
            self._ignored += 1
            return outcome
        assert outcome.node is not None
        assert outcome.basis is not None
        self._fused.add((outcome.node, outcome.basis))
        await self._inner.write(key, b'{"op":"inc","amount":1}')
        return outcome

    def _evaluate(self, report: bytes) -> FusionOutcome:
        try:
            obj = json.loads(report)
        except (ValueError, TypeError):
            return FusionOutcome(False, REASON_NOT_JSON)
        if not isinstance(obj, dict):
            return FusionOutcome(False, REASON_NOT_OBJECT)
        data = cast("dict[str, Any]", obj)
        node = data.get("node")
        basis = data.get("basis")
        if not isinstance(node, str) or node not in self._bases or not isinstance(basis, str):
            return FusionOutcome(False, REASON_NO_OVERLAP)
        if basis not in self._bases[node]:
            return FusionOutcome(False, REASON_OUTSIDE_BASIS, node=node)
        if (node, basis) in self._fused:
            return FusionOutcome(False, REASON_DUPLICATE, node=node, basis=basis)
        return FusionOutcome(True, REASON_FUSED, node=node, basis=basis)

    # -- Memory protocol -----------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read the fused signed total for ``key`` from the inner counter.

        Example::

            value = await mem.read("calculator:ready_score")
        """
        return await self._inner.read(key)

    async def write(self, key: str, value: bytes) -> None:
        """Fuse ``value`` through the basis gate (protocol-facing form of ``fuse``).

        Example::

            await mem.write("calculator:ready_score", report_bytes)
        """
        await self.fuse(key, value)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Subscribe to fused-total changes on the inner counter.

        Example::

            async for value in mem.subscribe("calculator:ready_score"):
                print(value)
        """
        async for value in self._inner.subscribe(key):
            yield value

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Delegate compare-and-swap to the inner counter.

        Example::

            ok = await mem.cas("calculator:ready_score", b"3", b"4")
        """
        return await self._inner.cas(key, expected, new)

    # -- CRDT gossip helpers (delegated) -------------------------------------

    def export(self, key: str) -> bytes | None:
        """Serialize one inner counter state for gossip.

        Example::

            state = mem.export("calculator:ready_score")
        """
        return self._inner.export(key)

    def export_all(self) -> bytes:
        """Serialize the full inner counter snapshot.

        Example::

            snapshot = mem.export_all()
        """
        return self._inner.export_all()

    async def merge(self, key: str, state: bytes) -> bool:
        """Join a remote counter state into the inner counter.

        Example::

            changed = await mem.merge("calculator:ready_score", other.export(...))
        """
        return await self._inner.merge(key, state)

    async def merge_all(self, state: bytes) -> list[str]:
        """Join a full-state snapshot into the inner counter.

        Example::

            changed = await mem.merge_all(other.export_all())
        """
        return await self._inner.merge_all(state)
