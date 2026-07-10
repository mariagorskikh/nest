# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for Nanda Town core modules.

Covers: simulator determinism, clock monotonicity, event queue ordering,
metric consistency, scenario config round-trip, and message drop rate bounds.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.metrics import compute_metrics
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.clock import VirtualClock
from nest_core.sim.events import Event, EventQueue
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId

# ---------------------------------------------------------------------------
# Helper agent for simulator property tests
# ---------------------------------------------------------------------------


class RingPingAgent(StateMachineAgent):
    """Sends pings around a ring topology for a fixed number of rounds."""

    def __init__(self, target: AgentId, rounds: int = 5) -> None:
        self._target = target
        self._rounds = rounds
        self._round = 0

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.send(self._target, f"ping-{self._round}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self._round += 1
        if self._round < self._rounds:
            await ctx.send(sender, f"ping-{self._round}".encode())


class RetryPingAgent(StateMachineAgent):
    """Sends pings and schedules periodic retries to ensure traffic even under drops."""

    def __init__(self, target: AgentId, rounds: int = 10) -> None:
        self._target = target
        self._rounds = rounds
        self._round = 0

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.send(self._target, f"ping-{self._round}".encode())
        # Schedule periodic retries so messages keep flowing even if some are dropped
        await ctx.schedule(1.0, b"retry")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if payload == b"retry":
            # Retry: send another ping
            if self._round < self._rounds:
                await ctx.send(self._target, f"ping-{self._round}".encode())
                await ctx.schedule(1.0, b"retry")
        else:
            self._round += 1
            if self._round < self._rounds:
                await ctx.send(sender, f"ping-{self._round}".encode())


# ---------------------------------------------------------------------------
# 1. Simulator determinism
# ---------------------------------------------------------------------------


class TestSimulatorDeterminism:
    @settings(max_examples=10, deadline=None)
    @given(
        seed=st.integers(min_value=0, max_value=10000),
        agent_count=st.integers(min_value=2, max_value=15),
    )
    @pytest.mark.asyncio
    async def test_same_seed_produces_identical_traces(self, seed: int, agent_count: int) -> None:
        """For any seed and agent count, running the same scenario twice
        produces identical traces."""
        traces: list[str] = []
        for _run_idx in range(2):
            with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as f:
                trace_path = Path(f.name)

            sim = Simulator(seed=seed, trace_path=trace_path)
            agent_ids = [AgentId(f"a{i}") for i in range(agent_count)]
            for i, aid in enumerate(agent_ids):
                target = agent_ids[(i + 1) % agent_count]
                sim.add_agent(aid, RingPingAgent(target, rounds=3))

            await sim.run(max_ticks=5000)
            traces.append(trace_path.read_text())
            trace_path.unlink(missing_ok=True)

        assert traces[0] == traces[1], "Traces diverged for same seed"
        assert len(traces[0]) > 0, "Trace should not be empty"


# ---------------------------------------------------------------------------
# 2. Clock monotonicity
# ---------------------------------------------------------------------------


class TestClockMonotonicity:
    @settings(max_examples=25)
    @given(
        deltas=st.lists(
            st.floats(min_value=0.001, max_value=1000.0, allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=50,
        ),
    )
    def test_advance_always_increases_time(self, deltas: list[float]) -> None:
        """VirtualClock.advance_to() always increases time and now is never negative."""
        clock = VirtualClock()
        assert clock.now >= 0.0

        current = 0.0
        for delta in deltas:
            current += delta
            clock.advance_to(current)
            assert clock.now == current
            assert clock.now >= 0.0

    @settings(max_examples=25)
    @given(
        times=st.lists(
            st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
            min_size=2,
            max_size=50,
        ),
    )
    def test_sorted_advances_are_monotonic(self, times: list[float]) -> None:
        """Advancing through sorted times always succeeds and is monotonic."""
        clock = VirtualClock()
        sorted_times = sorted(times)
        prev = 0.0
        for t in sorted_times:
            clock.advance_to(t)
            assert clock.now >= prev
            assert clock.now >= 0.0
            prev = clock.now


# ---------------------------------------------------------------------------
# 3. EventQueue ordering
# ---------------------------------------------------------------------------


class TestEventQueueOrdering:
    @settings(max_examples=25)
    @given(
        times=st.lists(
            st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=100,
        ),
    )
    def test_events_come_out_in_time_order(self, times: list[float]) -> None:
        """Push N events with random times, pop them all, verify sorted by time."""
        q = EventQueue()
        for t in times:
            q.push(Event(time=t, kind="test", agent_id=AgentId("a")))

        popped_times: list[float] = []
        while q:
            popped_times.append(q.pop().time)

        for i in range(1, len(popped_times)):
            assert popped_times[i] >= popped_times[i - 1], (
                f"Events out of order: {popped_times[i - 1]} > {popped_times[i]}"
            )

    @settings(max_examples=25)
    @given(
        times=st.lists(
            st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=100,
        ),
    )
    def test_queue_length_matches_push_count(self, times: list[float]) -> None:
        """Queue length after N pushes equals N."""
        q = EventQueue()
        for t in times:
            q.push(Event(time=t, kind="test", agent_id=AgentId("a")))

        assert len(q) == len(times)

        for _ in range(len(times)):
            q.pop()

        assert len(q) == 0
        assert not q


# ---------------------------------------------------------------------------
# 4. Metrics consistency
# ---------------------------------------------------------------------------

# Strategy that generates valid JSONL trace events
_agent_ids_st = st.sampled_from(["a1", "a2", "a3", "a4", "a5"])
_ts_st = st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False)


def _make_send_event(ts: float, agent: str, to: str, size: int, corr: str) -> dict[str, Any]:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "size": size, "corr": corr}


def _make_receive_event(ts: float, agent: str, frm: str, size: int, corr: str) -> dict[str, Any]:
    return {"ts": ts, "agent": agent, "kind": "receive", "from": frm, "size": size, "corr": corr}


def _make_dropped_event(ts: float, agent: str, frm: str, size: int) -> dict[str, Any]:
    return {"ts": ts, "agent": agent, "kind": "dropped", "from": frm, "size": size}


def _make_start_event(ts: float, agent: str) -> dict[str, Any]:
    return {"ts": ts, "agent": agent, "kind": "start"}


def _make_stop_event(ts: float, agent: str) -> dict[str, Any]:
    return {"ts": ts, "agent": agent, "kind": "stop"}


def _trace_events_strategy() -> st.SearchStrategy[list[dict[str, Any]]]:
    """Generate a list of valid trace events with proper structure."""
    return st.lists(
        st.one_of(
            st.builds(
                _make_send_event,
                ts=_ts_st,
                agent=_agent_ids_st,
                to=_agent_ids_st,
                size=st.integers(min_value=1, max_value=1000),
                corr=st.from_regex(r"c-[0-9]{1,4}", fullmatch=True),
            ),
            st.builds(
                _make_receive_event,
                ts=_ts_st,
                agent=_agent_ids_st,
                frm=_agent_ids_st,
                size=st.integers(min_value=1, max_value=1000),
                corr=st.from_regex(r"c-[0-9]{1,4}", fullmatch=True),
            ),
            st.builds(
                _make_dropped_event,
                ts=_ts_st,
                agent=_agent_ids_st,
                frm=_agent_ids_st,
                size=st.integers(min_value=1, max_value=1000),
            ),
            st.builds(
                _make_start_event,
                ts=_ts_st,
                agent=_agent_ids_st,
            ),
            st.builds(
                _make_stop_event,
                ts=_ts_st,
                agent=_agent_ids_st,
            ),
        ),
        min_size=0,
        max_size=50,
    )


def _write_trace_events(events: list[dict[str, Any]]) -> Path:
    """Write events to a temporary JSONL file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
        return Path(f.name)


class TestMetricsConsistency:
    @settings(max_examples=25)
    @given(events=_trace_events_strategy())
    def test_success_rate_bounded(self, events: list[dict[str, Any]]) -> None:
        """success_rate is always a proper fraction in [0.0, 1.0]."""
        trace = _write_trace_events(events)
        try:
            results = compute_metrics(str(trace), ["success_rate"])
            rate = results["success_rate"]
            # success_rate = receives / (receives + dropped). The denominator
            # can never be smaller than the numerator, so for any trace -- unicast
            # or broadcast-heavy -- the rate stays within [0.0, 1.0].
            assert 0.0 <= rate <= 1.0
        finally:
            trace.unlink(missing_ok=True)

    @settings(max_examples=25)
    @given(events=_trace_events_strategy())
    def test_message_count_non_negative(self, events: list[dict[str, Any]]) -> None:
        """message_count >= 0."""
        trace = _write_trace_events(events)
        try:
            results = compute_metrics(str(trace), ["message_count"])
            assert results["message_count"] >= 0
        finally:
            trace.unlink(missing_ok=True)

    @settings(max_examples=25)
    @given(events=_trace_events_strategy())
    def test_dropped_count_non_negative(self, events: list[dict[str, Any]]) -> None:
        """dropped_count >= 0."""
        trace = _write_trace_events(events)
        try:
            results = compute_metrics(str(trace), ["dropped_count"])
            assert results["dropped_count"] >= 0
        finally:
            trace.unlink(missing_ok=True)

    @settings(max_examples=25)
    @given(events=_trace_events_strategy())
    def test_agent_count_non_negative(self, events: list[dict[str, Any]]) -> None:
        """agent_count >= 0."""
        trace = _write_trace_events(events)
        try:
            results = compute_metrics(str(trace), ["agent_count"])
            assert results["agent_count"] >= 0
        finally:
            trace.unlink(missing_ok=True)

    @settings(max_examples=25)
    @given(events=_trace_events_strategy())
    def test_duration_non_negative(self, events: list[dict[str, Any]]) -> None:
        """duration >= 0."""
        trace = _write_trace_events(events)
        try:
            results = compute_metrics(str(trace), ["duration"])
            assert results["duration"] >= 0
        finally:
            trace.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 5. ScenarioConfig round-trip
# ---------------------------------------------------------------------------

_valid_scenario_dicts = st.fixed_dictionaries(
    {
        "name": st.from_regex(r"[a-z][a-z0-9_-]{0,20}", fullmatch=True),
        "tier": st.just(1),
        "seed": st.integers(min_value=0, max_value=100000),
        "description": st.text(min_size=0, max_size=50),
        "duration": st.integers(min_value=1, max_value=99999).map(lambda n: f"ticks: {n}"),
    },
)


class TestScenarioConfigRoundTrip:
    @settings(max_examples=25)
    @given(data=_valid_scenario_dicts)
    def test_from_dict_round_trip(self, data: dict[str, Any]) -> None:
        """Any valid config dict can be serialized and deserialized without loss."""
        config = ScenarioConfig.from_dict(data)
        dumped = config.model_dump()
        restored = ScenarioConfig.from_dict(dumped)
        assert config == restored

    @settings(max_examples=25)
    @given(data=_valid_scenario_dicts)
    def test_model_dump_preserves_name(self, data: dict[str, Any]) -> None:
        """The name field survives round-trip."""
        config = ScenarioConfig.from_dict(data)
        dumped = config.model_dump()
        assert dumped["name"] == data["name"]

    @settings(max_examples=25)
    @given(data=_valid_scenario_dicts)
    def test_model_dump_preserves_seed(self, data: dict[str, Any]) -> None:
        """The seed field survives round-trip."""
        config = ScenarioConfig.from_dict(data)
        dumped = config.model_dump()
        assert dumped["seed"] == data["seed"]


# ---------------------------------------------------------------------------
# 6. Message drop rate bounds
# ---------------------------------------------------------------------------


class TestMessageDropRateBounds:
    @settings(max_examples=10, deadline=None)
    @given(seed=st.integers(min_value=0, max_value=10000))
    @pytest.mark.asyncio
    async def test_zero_drop_rate_means_no_drops(self, seed: int) -> None:
        """With drop_rate=0.0, dropped_count == 0."""
        sim = Simulator(seed=seed, message_drop_rate=0.0)
        agent_ids = [AgentId(f"a{i}") for i in range(5)]
        for i, aid in enumerate(agent_ids):
            target = agent_ids[(i + 1) % 5]
            sim.add_agent(aid, RingPingAgent(target, rounds=5))
        await sim.run(max_ticks=5000)

        assert sim.dropped_count == 0
        assert sim.message_count > 0

    @settings(max_examples=10, deadline=None)
    @given(seed=st.integers(min_value=0, max_value=10000))
    @pytest.mark.asyncio
    async def test_full_drop_rate_means_no_deliveries(self, seed: int) -> None:
        """With drop_rate=1.0, message_count == 0 (no deliveries)."""
        sim = Simulator(seed=seed, message_drop_rate=1.0)
        agent_ids = [AgentId(f"a{i}") for i in range(5)]
        for i, aid in enumerate(agent_ids):
            target = agent_ids[(i + 1) % 5]
            sim.add_agent(aid, RingPingAgent(target, rounds=5))
        await sim.run(max_ticks=5000)

        assert sim.message_count == 0
        assert sim.dropped_count > 0

    @settings(max_examples=10, deadline=None)
    @given(
        seed=st.integers(min_value=0, max_value=10000),
        drop_rate=st.floats(min_value=0.1, max_value=0.5, allow_nan=False, allow_infinity=False),
    )
    @pytest.mark.asyncio
    async def test_partial_drop_rate_has_both(self, seed: int, drop_rate: float) -> None:
        """With 0 < drop_rate < 1, both messages and drops occur
        given enough agents and rounds (using retry agents to avoid starvation)."""
        sim = Simulator(seed=seed, message_drop_rate=drop_rate)
        agent_ids = [AgentId(f"a{i}") for i in range(10)]
        for i, aid in enumerate(agent_ids):
            target = agent_ids[(i + 1) % 10]
            sim.add_agent(aid, RetryPingAgent(target, rounds=40))
        await sim.run(max_ticks=50000)

        # RetryPingAgent schedules periodic retries, so even with high drop rates
        # there will eventually be both deliveries and drops
        assert sim.message_count > 0, f"Expected some deliveries with drop_rate={drop_rate}"
        assert sim.dropped_count > 0, f"Expected some drops with drop_rate={drop_rate}"
