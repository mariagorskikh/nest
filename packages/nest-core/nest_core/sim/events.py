# SPDX-License-Identifier: Apache-2.0
"""Event types and priority queue for the discrete-event simulator.
Example::
    q = EventQueue()
    q.push(Event(time=1.0, kind="send", agent_id=AgentId("a1")))
    ev = q.pop()
"""

from __future__ import annotations
import heapq
from dataclasses import dataclass, field
from typing import Any
from nest_core.types import AgentId, CorrelationId


@dataclass(order=True)
class Event:
    """A single simulation event, ordered by (time, sequence).
    Example::
        ev = Event(time=1.0, kind="send", agent_id=AgentId("a1"))
    """

    time: float
    sequence: int = field(compare=True, default=0)
    kind: str = field(compare=False, default="")
    agent_id: AgentId = field(compare=False, default=AgentId(""))
    target_id: AgentId = field(compare=False, default=AgentId(""))
    payload: bytes = field(compare=False, default=b"")
    correlation_id: CorrelationId | None = field(compare=False, default=None)
    metadata: dict[str, Any] = field(compare=False, default_factory=lambda: dict[str, Any]())

    @property
    def recipient_id(self) -> AgentId:
        """Agent receiving this event (``agent_id`` in deliver events)."""
        return self.agent_id

    @property
    def sender_id(self) -> AgentId:
        """Peer that originated the message (``target_id`` in deliver events)."""
        return self.target_id


class EventQueue:
    """Min-heap priority queue of simulation events.
    Events are ordered by (time, sequence) for deterministic FIFO within
    the same timestamp.
    Example::
        q = EventQueue()
        q.push(Event(time=2.0, kind="send", agent_id=AgentId("a1")))
        q.push(Event(time=1.0, kind="recv", agent_id=AgentId("a2")))
        assert q.pop().time == 1.0
    """

    __slots__ = ("_heap", "_counter")

    def __init__(self) -> None:
        self._heap: list[Event] = []
        self._counter: int = 0

    def push(self, event: Event) -> None:
        """Push an event, auto-assigning a sequence number for FIFO ordering.
        Example::
            q.push(Event(time=5.0, kind="tick", agent_id=AgentId("a1")))
        """
        event.sequence = self._counter
        self._counter += 1
        heapq.heappush(self._heap, event)

    def pop(self) -> Event:
        """Pop the next event (earliest time, then FIFO).
        Example::
            ev = q.pop()
        """
        return heapq.heappop(self._heap)

    def peek(self) -> Event:
        """Peek at the next event without removing it.
        Example::
            ev = q.peek()
        """
        return self._heap[0]

    def __len__(self) -> int:
        return len(self._heap)

    def __bool__(self) -> bool:
        return bool(self._heap)
