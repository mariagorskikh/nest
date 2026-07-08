# SPDX-License-Identifier: Apache-2.0
"""PN-Counter CRDT memory plugin for signed evidence aggregation.

The default blackboard and the merged ``lww_register`` can make replicas
converge, but a converged register still keeps only one writer's payload. That
is the wrong mathematical object for tallies, reputation reports, and other
signed evidence where every concurrent delta should survive exactly once.

``PnCounterMemory`` represents each key as two grow-only maps:

``positive[node]`` counts increments observed from ``node`` and
``negative[node]`` counts decrements observed from ``node``. The value is
``sum(positive) - sum(negative)`` and the merge is pointwise maximum on both
maps. That join is commutative, associative, and idempotent, so replicas that
have seen the same deltas converge to the same total regardless of delivery
order, duplication, or reordering.

Example::

    a = PnCounterMemory("a")
    b = PnCounterMemory("b")
    await a.write("score", b'{"op":"inc","amount":2}')
    await b.write("score", b'{"op":"dec","amount":1}')
    await a.merge("score", b.export("score"))
    await b.merge("score", a.export("score"))
    assert await a.read("score") == await b.read("score") == b"1"
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast

CRDT_KIND = "pn_counter"
"""Schema tag stamped into serialized counter state."""


class PnCounterStateError(ValueError):
    """Raised when serialized PN-Counter state or operations are malformed.

    Example::

        try:
            PnCounterMemory._decode(b"not json")
        except PnCounterStateError:
            ...
    """


@dataclass(frozen=True)
class CounterState:
    """A state-based PN-Counter value.

    Example::

        state = CounterState({"a": 2}, {"b": 1})
        assert state.value == 1
    """

    positive: dict[str, int]
    negative: dict[str, int]

    @property
    def value(self) -> int:
        """Return ``sum(positive) - sum(negative)``.

        Example::

            assert CounterState({"a": 3}, {"b": 2}).value == 1
        """
        return sum(self.positive.values()) - sum(self.negative.values())

    def join(self, other: CounterState) -> CounterState:
        """Pointwise-max least upper bound for two counter states.

        Example::

            joined = CounterState({"a": 1}, {}).join(CounterState({"a": 3}, {}))
            assert joined.positive["a"] == 3
        """
        return CounterState(
            positive=_pointwise_max(self.positive, other.positive),
            negative=_pointwise_max(self.negative, other.negative),
        )

    def encode(self) -> bytes:
        """Serialize to canonical, grep-able JSON bytes.

        Example::

            raw = CounterState({"a": 1}, {}).encode()
        """
        data = {
            "crdt": CRDT_KIND,
            "positive": self.positive,
            "negative": self.negative,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class PnCounterMemory:
    """A PN-Counter CvRDT implementing the ``Memory`` protocol.

    ``write`` accepts signed deltas as either canonical JSON
    (``{"op":"inc","amount":2}``, ``{"op":"dec","amount":1}``,
    ``{"delta":-3}``) or a plain integer byte string such as ``b"4"``. ``read``
    returns the current total as ASCII integer bytes. ``cas`` treats ``new`` as
    an absolute target total and applies the local delta needed to reach it if
    the observed total still equals ``expected``.

    Example::

        mem = PnCounterMemory("agent-0")
        await mem.write("score", b'{"delta": 3}')
        assert await mem.read("score") == b"3"
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a replica with a stable node id.

        Example::

            mem = PnCounterMemory("observer-0")
        """
        self._node_id = str(node_id)
        self._store: dict[str, CounterState] = {}
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

    @property
    def node_id(self) -> str:
        """Stable node identifier used as this replica's counter coordinate.

        Example::

            assert PnCounterMemory("a").node_id == "a"
        """
        return self._node_id

    async def read(self, key: str) -> bytes | None:
        """Read the current signed total for ``key``.

        Example::

            value = await mem.read("score")
        """
        state = self._store.get(key)
        return str(state.value).encode("ascii") if state is not None else None

    async def write(self, key: str, value: bytes) -> None:
        """Apply a signed delta to this replica's coordinate.

        Example::

            await mem.write("score", b'{"op":"dec","amount":2}')
        """
        delta = _parse_delta(value)
        if delta == 0:
            return
        current = self._store.get(key, CounterState({}, {}))
        positive = dict(current.positive)
        negative = dict(current.negative)
        if delta > 0:
            positive[self._node_id] = positive.get(self._node_id, 0) + delta
        else:
            negative[self._node_id] = negative.get(self._node_id, 0) + abs(delta)
        self._store[key] = CounterState(positive=positive, negative=negative)
        await self._notify(key)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Yield the signed total each time it changes.

        Example::

            async for value in mem.subscribe("score"):
                print(value)
        """
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Set the total to ``new`` if the current total equals ``expected``.

        Example::

            ok = await mem.cas("score", b"3", b"5")
        """
        current_bytes = await self.read(key)
        if current_bytes != expected:
            return False
        current = int(current_bytes or b"0")
        target = _parse_int(new)
        await self.write(key, str(target - current).encode("ascii"))
        return True

    def export(self, key: str) -> bytes | None:
        """Serialize one counter state for gossip.

        Example::

            state = mem.export("score")
        """
        state = self._store.get(key)
        return state.encode() if state is not None else None

    def export_all(self) -> bytes:
        """Serialize every key in this replica.

        Example::

            snapshot = mem.export_all()
        """
        data = {
            "crdt": CRDT_KIND,
            "counters": {
                key: {
                    "positive": state.positive,
                    "negative": state.negative,
                }
                for key, state in sorted(self._store.items())
            },
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    async def merge(self, key: str, state: bytes) -> bool:
        """Join a remote counter state into this replica.

        Example::

            changed = await mem.merge("score", other.export("score"))
        """
        incoming = self._decode(state)
        current = self._store.get(key)
        if current is None:
            self._store[key] = incoming
            await self._notify(key)
            return True
        joined = current.join(incoming)
        if joined == current:
            return False
        old_value = current.value
        self._store[key] = joined
        if joined.value != old_value:
            await self._notify(key)
        return True

    async def merge_all(self, state: bytes) -> list[str]:
        """Join a full-state snapshot, returning keys whose state changed.

        Example::

            changed = await mem.merge_all(other.export_all())
        """
        counters = self._decode_all(state)
        changed: list[str] = []
        for key in sorted(counters):
            if await self.merge(key, counters[key].encode()):
                changed.append(key)
        return changed

    async def _notify(self, key: str) -> None:
        value = await self.read(key)
        if value is None:
            return
        for q in self._subscribers.get(key, []):
            await q.put(value)

    @staticmethod
    def _decode(state: bytes) -> CounterState:
        obj = _loads_object(state)
        data = _expect_kind(obj, "counter")
        return _state_from_fields(data)

    @staticmethod
    def _decode_all(state: bytes) -> dict[str, CounterState]:
        obj = _loads_object(state)
        data = _expect_kind(obj, "snapshot")
        raw = data.get("counters", {})
        if not isinstance(raw, dict):
            msg = "snapshot 'counters' must be an object"
            raise PnCounterStateError(msg)
        result: dict[str, CounterState] = {}
        for key, fields in cast("dict[str, Any]", raw).items():
            if not isinstance(fields, dict):
                msg = f"counter for {key!r} must be an object"
                raise PnCounterStateError(msg)
            result[str(key)] = _state_from_fields(cast("dict[str, Any]", fields))
        return result


def _pointwise_max(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    keys = set(left) | set(right)
    return {key: max(left.get(key, 0), right.get(key, 0)) for key in sorted(keys)}


def _loads_object(state: bytes) -> object:
    try:
        return json.loads(state)
    except (ValueError, TypeError) as exc:
        msg = "state is not valid JSON"
        raise PnCounterStateError(msg) from exc


def _expect_kind(obj: object, label: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        msg = f"not a {CRDT_KIND} {label}: {obj!r}"
        raise PnCounterStateError(msg)
    data = cast("dict[str, Any]", obj)
    if data.get("crdt") != CRDT_KIND:
        msg = f"not a {CRDT_KIND} {label}: {data!r}"
        raise PnCounterStateError(msg)
    return data


def _state_from_fields(fields: dict[str, Any]) -> CounterState:
    positive = _clean_counter_map(fields.get("positive", {}), "positive")
    negative = _clean_counter_map(fields.get("negative", {}), "negative")
    return CounterState(positive=positive, negative=negative)


def _clean_counter_map(raw: object, label: str) -> dict[str, int]:
    if not isinstance(raw, dict):
        msg = f"{label} must be an object"
        raise PnCounterStateError(msg)
    clean: dict[str, int] = {}
    for key, value in cast("dict[str, Any]", raw).items():
        if isinstance(value, bool):
            msg = f"{label}[{key!r}] must be a non-negative integer"
            raise PnCounterStateError(msg)
        amount = int(value)
        if amount < 0:
            msg = f"{label}[{key!r}] must be non-negative"
            raise PnCounterStateError(msg)
        if amount:
            clean[str(key)] = amount
    return clean


def _parse_delta(value: bytes) -> int:
    text = value.decode("utf-8")
    try:
        obj = json.loads(text)
    except ValueError:
        return _parse_int(value)
    if isinstance(obj, dict):
        data = cast("dict[str, Any]", obj)
        if "delta" in data:
            return _parse_int_like(data["delta"])
        op = data.get("op")
        amount = _parse_int_like(data.get("amount", 1))
        if amount < 0:
            msg = "amount must be non-negative"
            raise PnCounterStateError(msg)
        if op == "inc":
            return amount
        if op == "dec":
            return -amount
    if isinstance(obj, int) and not isinstance(obj, bool):
        return obj
    msg = f"unsupported PN-Counter write payload: {text!r}"
    raise PnCounterStateError(msg)


def _parse_int(value: bytes) -> int:
    try:
        return int(value.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        msg = f"expected integer bytes, got {value!r}"
        raise PnCounterStateError(msg) from exc


def _parse_int_like(value: object) -> int:
    if isinstance(value, bool):
        msg = f"expected integer, got {value!r}"
        raise PnCounterStateError(msg)
    try:
        return int(cast("Any", value))
    except (TypeError, ValueError) as exc:
        msg = f"expected integer, got {value!r}"
        raise PnCounterStateError(msg) from exc
