# SPDX-License-Identifier: Apache-2.0
"""LWW-Register CRDT memory plugin -- conflict-free shared state.

This module implements a **state-based, last-writer-wins register**
(an LWW-Register CvRDT) for the Nanda Town memory layer. Unlike the default
``blackboard`` plugin, which resolves concurrent writes by wall-arrival
order and silently diverges when two replicas apply the same writes in a
different order, this plugin tags every write with a Lamport timestamp and a
stable node identifier so that the *merge* of any set of replica states is
**commutative, associative, and idempotent**. Those three algebraic laws are
exactly what guarantees *strong eventual consistency*: replicas that have
observed the same set of writes converge to byte-identical state regardless
of delivery order, duplication, or loss.

The register state for a single key is encoded as inspectable JSON so it
stays grep-able inside a JSONL trace::

    {"crdt": "lww_register", "payload": "<base64>", "lamport": 3, "node": "agent-2"}

The total order used to pick a winner is the lexicographic pair
``(lamport, node)``. Because a node's Lamport clock strictly increases on
every local write and the node component breaks ties, the pair is globally
unique across writes -- so the join (least-upper-bound) is well defined and
deterministic.

Example::

    a = LwwRegisterMemory("a")
    b = LwwRegisterMemory("b")
    await a.write("k", b"from-a")
    await b.write("k", b"from-b")
    # Gossip both ways; order does not matter.
    await b.merge("k", a.export("k"))
    await a.merge("k", b.export("k"))
    assert await a.read("k") == await b.read("k")
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast

CRDT_KIND = "lww_register"
"""Schema tag stamped into every serialized register, used to detect and
validate CRDT state when it is read back from a trace or the wire."""


class CrdtStateError(ValueError):
    """Raised when a byte string is not a valid serialized LWW-Register.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    keep working while callers that care can catch the specific type.

    Example::

        try:
            LwwRegisterMemory._decode(b"not json")
        except CrdtStateError:
            ...
    """


@dataclass(frozen=True)
class Register:
    """A single last-writer-wins register value with its causal tag.

    The ordering is the lexicographic triple ``(lamport, node, payload)``: a
    higher Lamport clock wins; the stable ``node`` id breaks clock ties; and
    the payload bytes break the (rare) remaining tie. Including the payload
    makes the order **total over every possible register**, so the join is a
    genuine semilattice join -- commutative, associative, and idempotent -- even
    if two replicas were misconfigured to share a node id. In normal operation
    ``(lamport, node)`` is already unique per write and the payload tiebreak
    never fires.

    Example::

        r1 = Register(b"x", 1, "a")
        r2 = Register(b"y", 2, "b")
        assert r2.dominates(r1)
    """

    payload: bytes
    lamport: int
    node: str

    def dominates(self, other: Register) -> bool:
        """Return True if this register wins the join against ``other``.

        Example::

            assert Register(b"y", 2, "b").dominates(Register(b"x", 1, "a"))
        """
        return (self.lamport, self.node, self.payload) > (
            other.lamport,
            other.node,
            other.payload,
        )

    def join(self, other: Register) -> Register:
        """Least-upper-bound merge of two registers (commutative, idempotent).

        Example::

            winner = r1.join(r2)
        """
        return self if self.dominates(other) else other

    def encode(self) -> bytes:
        """Serialize to canonical, grep-able JSON bytes.

        Example::

            raw = Register(b"hi", 1, "a").encode()
        """
        data = {
            "crdt": CRDT_KIND,
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "lamport": self.lamport,
            "node": self.node,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")


class LwwRegisterMemory:
    """A last-writer-wins register CRDT implementing the ``Memory`` protocol.

    Each instance is an independent **replica**. Local writes are tagged with
    a monotonically increasing Lamport clock and this replica's ``node_id``;
    replicas exchange state with :meth:`export` / :meth:`merge` (typically
    gossiped over the transport layer). The merge is conflict-free, so any
    set of replicas that have seen the same writes read back identical values
    no matter what order the writes and merges arrived in.

    The standard :class:`~nest_core.layers.memory.Memory` surface
    (``read`` / ``write`` / ``cas`` / ``subscribe``) treats values as opaque
    user payloads; the CRDT machinery is internal. The extra
    :meth:`export` / :meth:`merge` / :meth:`export_all` / :meth:`merge_all`
    methods are the replication channel and are additive -- a caller that only
    speaks the base protocol never has to know the values are CRDT registers.

    Example::

        mem = LwwRegisterMemory("agent-0")
        await mem.write("counter", b"42")
        assert await mem.read("counter") == b"42"
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a replica with a stable, unique ``node_id``.

        The ``node_id`` must be stable for the lifetime of the replica and
        unique across replicas, since it is the deterministic tie-breaker in
        the register total order. Two replicas sharing a ``node_id`` would
        break the convergence guarantee.

        Example::

            mem = LwwRegisterMemory("agent-0")
        """
        self._node_id = str(node_id)
        self._store: dict[str, Register] = {}
        self._clock: int = 0
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    @property
    def node_id(self) -> str:
        """The stable node identifier used to break ties in the total order.

        Example::

            assert LwwRegisterMemory("agent-0").node_id == "agent-0"
        """
        return self._node_id

    @property
    def lamport(self) -> int:
        """The current Lamport clock value of this replica.

        Example::

            mem = LwwRegisterMemory("a")
            assert mem.lamport == 0
        """
        return self._clock

    # -- Memory protocol -------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read the winning payload for ``key`` or ``None`` if unset.

        Example::

            val = await mem.read("counter")
        """
        reg = self._store.get(key)
        return reg.payload if reg is not None else None

    async def write(self, key: str, value: bytes) -> None:
        """Locally write ``value`` for ``key``, tagging it with a fresh clock.

        The write is stamped with ``(lamport + 1, node_id)``, which always
        dominates this replica's current value for the key, and subscribers
        are notified -- matching the ``blackboard`` contract that every local
        write is observable.

        Example::

            await mem.write("counter", b"42")
        """
        self._clock += 1
        reg = Register(payload=value, lamport=self._clock, node=self._node_id)
        self._store[key] = reg
        await self._notify(key, reg.payload)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Yield the winning payload for ``key`` each time it advances.

        Example::

            async for val in mem.subscribe("counter"):
                print(val)
        """
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Compare-and-swap on the local replica's winning payload.

        Succeeds iff the current winning payload equals ``expected``, in which
        case it performs a normal tagged :meth:`write` of ``new``. This is a
        linearizable operation *on this replica*; across replicas the CRDT
        merge -- not CAS -- is the conflict resolver, so a swap that lost a
        concurrent race elsewhere is reconciled at the next :meth:`merge`.

        Example::

            ok = await mem.cas("counter", b"42", b"43")
        """
        current = self._store.get(key)
        current_payload = current.payload if current is not None else None
        if current_payload == expected:
            await self.write(key, new)
            return True
        return False

    # -- CRDT replication channel ---------------------------------------

    def export(self, key: str) -> bytes | None:
        """Serialize the winning register for ``key`` for gossip.

        Returns ``None`` if the key is unset. The result is valid input to
        another replica's :meth:`merge`.

        Example::

            state = mem.export("counter")
        """
        reg = self._store.get(key)
        return reg.encode() if reg is not None else None

    def export_all(self) -> bytes:
        """Serialize this replica's full state for a full-state anti-entropy push.

        Example::

            snapshot = mem.export_all()
        """
        data = {
            "crdt": CRDT_KIND,
            "registers": {
                key: {
                    "payload": base64.b64encode(reg.payload).decode("ascii"),
                    "lamport": reg.lamport,
                    "node": reg.node,
                }
                for key, reg in sorted(self._store.items())
            },
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    async def merge(self, key: str, state: bytes) -> bool:
        """Merge a remote register for ``key`` into the local replica.

        Joins the incoming register by least-upper-bound and advances this
        replica's Lamport clock to at least the observed value (Lamport's
        rule). Returns ``True`` if the local winning payload changed, in which
        case subscribers are notified. Idempotent: merging the same state
        twice is a no-op.

        Example::

            changed = await mem.merge("counter", other.export("counter"))
        """
        incoming = self._decode(state)
        self._clock = max(self._clock, incoming.lamport)
        current = self._store.get(key)
        if current is None:
            self._store[key] = incoming
            await self._notify(key, incoming.payload)
            return True
        winner = current.join(incoming)
        if winner is current or winner == current:
            return False
        self._store[key] = winner
        if winner.payload != current.payload:
            await self._notify(key, winner.payload)
            return True
        return False

    async def merge_all(self, state: bytes) -> list[str]:
        """Merge a full-state snapshot, returning the keys whose value changed.

        Example::

            changed_keys = await mem.merge_all(other.export_all())
        """
        registers = self._decode_all(state)
        changed: list[str] = []
        for key in sorted(registers):
            if await self.merge(key, registers[key].encode()):
                changed.append(key)
        return changed

    # -- internals -------------------------------------------------------

    async def _notify(self, key: str, payload: bytes) -> None:
        for q in self._subscribers.get(key, []):
            await q.put(payload)

    @staticmethod
    def _loads_object(state: bytes) -> object:
        try:
            return json.loads(state)
        except (ValueError, TypeError) as exc:
            msg = "state is not valid JSON"
            raise CrdtStateError(msg) from exc

    @staticmethod
    def _decode(state: bytes) -> Register:
        obj = LwwRegisterMemory._loads_object(state)
        if not isinstance(obj, dict):
            msg = f"not an {CRDT_KIND} register: {obj!r}"
            raise CrdtStateError(msg)
        data = cast("dict[str, Any]", obj)
        if data.get("crdt") != CRDT_KIND:
            msg = f"not an {CRDT_KIND} register: {data!r}"
            raise CrdtStateError(msg)
        return LwwRegisterMemory._register_from_fields(data)

    @staticmethod
    def _decode_all(state: bytes) -> dict[str, Register]:
        obj = LwwRegisterMemory._loads_object(state)
        if not isinstance(obj, dict):
            msg = f"not an {CRDT_KIND} snapshot: {obj!r}"
            raise CrdtStateError(msg)
        data = cast("dict[str, Any]", obj)
        if data.get("crdt") != CRDT_KIND:
            msg = f"not an {CRDT_KIND} snapshot: {data!r}"
            raise CrdtStateError(msg)
        raw = data.get("registers", {})
        if not isinstance(raw, dict):
            msg = "snapshot 'registers' must be an object"
            raise CrdtStateError(msg)
        raw_registers = cast("dict[str, Any]", raw)
        result: dict[str, Register] = {}
        for key, fields in raw_registers.items():
            if not isinstance(fields, dict):
                msg = f"register for {key!r} must be an object"
                raise CrdtStateError(msg)
            result[str(key)] = LwwRegisterMemory._register_from_fields(
                cast("dict[str, Any]", fields)
            )
        return result

    @staticmethod
    def _register_from_fields(fields: dict[str, Any]) -> Register:
        try:
            payload = base64.b64decode(fields["payload"])
            lamport = int(fields["lamport"])
            node = str(fields["node"])
        except (KeyError, ValueError, TypeError) as exc:
            msg = f"malformed register fields: {fields!r}"
            raise CrdtStateError(msg) from exc
        return Register(payload=payload, lamport=lamport, node=node)
