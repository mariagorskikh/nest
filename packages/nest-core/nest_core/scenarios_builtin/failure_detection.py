# SPDX-License-Identifier: Apache-2.0
"""Failure-detection scenario — silence that heals, with a ground-truth oracle.

Topology (see ``scenarios/failure_detection.yaml``):

* ``observer-0`` runs a :class:`~nest_core.layers.failure_detector.FailureDetector`
  instance (injected per-agent via the ``_agent_plugins`` override channel) and
  periodically reports, for every watched peer, whether it is currently
  *suspected* of having failed.
* ``target-0`` is a heartbeat emitter that goes **silent** for a long, bounded
  window ``[silent_from, silent_until)`` and then resumes — a transient crash
  that later heals.
* ``peer-0`` is a heartbeat emitter that is **never** silent.  It is the
  always-alive control: a correct detector must never suspect it.

Every emitter heartbeats on a *jittered* interval ``uniform(hb_min, hb_max)``.
That jitter is the whole point of the scenario.  A naive fixed-timeout detector
set just above the mean interval will mistake the upper tail of normal jitter
for a crash and raise a **false** suspicion against a peer that is provably
alive; an adaptive phi-accrual detector learns the inter-arrival distribution
and stays quiet through the jitter while still catching the genuine outage.
The accuracy validator in :mod:`nest_core.validators` is tuned to separate the
two: the baseline fails it, phi-accrual passes.

Ground truth is not inferred — the emitters broadcast ``fd:phase`` marker events
at start and on every reachability transition, so the validators know exactly
which intervals were truly reachable versus truly down.  Heartbeats and status
reports are plain broadcasts at ``failures.message_drop == 0``, so no redundancy
is needed and the run is fully deterministic for a fixed seed.

Example::

    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig

    config = ScenarioConfig.from_yaml("scenarios/failure_detection.yaml")
    runner = ScenarioRunner(config)
    await runner.run()
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_core.layers.failure_detector import FailureDetector
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

HB_TICK = b"FD_HB_TICK"
"""Payload tag for an emitter's periodic self-message that triggers a heartbeat."""

EVAL_TICK = b"FD_EVAL_TICK"
"""Payload tag for the observer's periodic self-message that triggers an evaluation."""

_HB_PREFIX = "FDHB|"
"""Marker prefix identifying a heartbeat broadcast; the suffix is the sender id."""

DEFAULT_HB_MIN = 10.0
"""Default lower bound on the jittered heartbeat interval, in logical time units."""

DEFAULT_HB_MAX = 20.0
"""Default upper bound on the jittered heartbeat interval, in logical time units."""

DEFAULT_EVAL_INTERVAL = 3.0
"""Default logical-time gap between consecutive observer evaluations."""

DEFAULT_SILENT_FROM = 200.0
"""Default logical time at which ``target-0`` begins its silence window."""

DEFAULT_SILENT_UNTIL = 320.0
"""Default logical time at which ``target-0`` resumes heartbeating."""

DEFAULT_FD_PLUGIN = "phi_accrual"
"""Default failure-detector plugin name used by the observer."""


def _hb_payload(agent_id: AgentId) -> bytes:
    """Return the heartbeat broadcast payload for *agent_id*.

    Example::

        payload = _hb_payload(AgentId("peer-0"))
    """
    return f"{_HB_PREFIX}{agent_id}".encode()


def _parse_hb(payload: bytes) -> AgentId | None:
    """Return the sender id if *payload* is a heartbeat broadcast, else ``None``.

    Example::

        peer = _parse_hb(b"FDHB|peer-0")
    """
    text = payload.decode("utf-8", "replace")
    if not text.startswith(_HB_PREFIX):
        return None
    return AgentId(text[len(_HB_PREFIX) :])


def _phase_payload(peer: AgentId, reachable: bool, now: float) -> bytes:
    """Return a ground-truth ``fd:phase`` marker payload.

    Example::

        payload = _phase_payload(AgentId("target-0"), reachable=False, now=205.0)
    """
    obj: dict[str, Any] = {
        "fd": "phase",
        "peer": str(peer),
        "reachable": reachable,
        "ts": round(now, 6),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class HeartbeatEmitterAgent(StateMachineAgent):
    """Broadcast jittered heartbeats, going silent for one bounded window.

    The agent emits a ``fd:phase`` marker at start and on every transition
    between reachable and unreachable, so the trace carries ground truth that
    the validators can check the detector against.  During the silence window
    ``[silent_from, silent_until)`` heartbeats are suppressed but the agent
    keeps re-arming its tick chain, so emission resumes cleanly afterwards.

    A non-silent emitter is configured with ``silent_from == silent_until``
    (an empty window), so it never goes silent and only ever emits the initial
    reachable marker.

    Example::

        agent = HeartbeatEmitterAgent(
            AgentId("target-0"), hb_min=10.0, hb_max=20.0,
            silent_from=200.0, silent_until=320.0,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        hb_min: float = DEFAULT_HB_MIN,
        hb_max: float = DEFAULT_HB_MAX,
        silent_from: float = 0.0,
        silent_until: float = 0.0,
    ) -> None:
        self._id = agent_id
        self._hb_min = hb_min
        self._hb_max = hb_max
        self._silent_from = silent_from
        self._silent_until = silent_until
        self._reachable = True

    def _is_reachable(self, now: float) -> bool:
        return not (self._silent_from <= now < self._silent_until)

    async def _arm_next(self, ctx: AgentContext) -> None:
        await ctx.schedule(ctx.rng.uniform(self._hb_min, self._hb_max), HB_TICK)

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit the initial reachability marker and arm the first heartbeat.

        Example::

            await agent.on_start(ctx)
        """
        self._reachable = self._is_reachable(ctx.time)
        await ctx.broadcast(_phase_payload(self._id, self._reachable, ctx.time))
        await self._arm_next(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On a self heartbeat tick: emit any transition marker, beat, re-arm.

        All non-self messages (other emitters' heartbeats, the observer's
        status reports) are ignored — this agent is a pure source.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        if sender != ctx.agent_id or payload != HB_TICK:
            return
        reachable = self._is_reachable(ctx.time)
        if reachable != self._reachable:
            self._reachable = reachable
            await ctx.broadcast(_phase_payload(self._id, reachable, ctx.time))
        if reachable:
            await ctx.broadcast(_hb_payload(self._id))
        await self._arm_next(ctx)


class FailureMonitorAgent(StateMachineAgent):
    """Drive one failure detector and periodically publish suspicion verdicts.

    The detector is injected as the per-agent ``failure_detector`` plugin.  On
    each heartbeat broadcast the agent feeds the detector; on each evaluation
    self-tick it reports, for every watched peer, a ``fd:status`` broadcast
    carrying the boolean verdict plus the current ``phi`` and elapsed silence
    (the latter two are informational — the validators key off the verdict and
    the broadcast's own timestamp).

    Example::

        agent = FailureMonitorAgent(
            watched=[AgentId("target-0"), AgentId("peer-0")], eval_interval=3.0,
        )
    """

    def __init__(
        self, watched: list[AgentId], eval_interval: float = DEFAULT_EVAL_INTERVAL
    ) -> None:
        self._watched = watched
        self._eval_interval = eval_interval

    async def on_start(self, ctx: AgentContext) -> None:
        """Arm the first evaluation tick.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.schedule(self._eval_interval, EVAL_TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Feed heartbeats into the detector; on eval ticks publish verdicts.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        fd: FailureDetector | None = ctx.plugins.get("failure_detector")
        if fd is None:
            return
        if sender == ctx.agent_id and payload == EVAL_TICK:
            now = ctx.time
            for peer in self._watched:
                snap = await fd.report(peer, now=now)
                last_hb = snap.last_heartbeat
                elapsed = round(now - last_hb, 6) if last_hb is not None else None
                obj: dict[str, Any] = {
                    "fd": "status",
                    "peer": str(peer),
                    "suspected": snap.suspected,
                    "phi": round(snap.phi, 6),
                    "elapsed": elapsed,
                    "ts": round(now, 6),
                }
                body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
                await ctx.broadcast(body)
            await ctx.schedule(self._eval_interval, EVAL_TICK)
            return
        hb_peer = _parse_hb(payload)
        if hb_peer is not None and hb_peer != ctx.agent_id:
            await fd.heartbeat(hb_peer, now=ctx.time)


def failure_detection_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build the agent fleet for the failure-detection scenario.

    Roles are read from ``config.agents.roles``: an ``observer`` role becomes a
    :class:`FailureMonitorAgent` (each gets its own freshly-built detector), a
    ``target`` role becomes a silence-then-heal :class:`HeartbeatEmitterAgent`,
    and any other emitter role (e.g. ``peer``) becomes a never-silent emitter.
    The detector kind and its parameters come from ``task.config`` so the same
    scenario can be re-run with the baseline or the accrual detector.

    Example::

        agents = failure_detection_factory(config, plugins)
    """
    from nest_plugins_reference.failure_detection.heartbeat import (
        DEFAULT_TIMEOUT,
        HeartbeatFailureDetector,
    )
    from nest_plugins_reference.failure_detection.phi_accrual import (
        DEFAULT_MIN_SAMPLES,
        DEFAULT_MIN_STD,
        DEFAULT_THRESHOLD,
        DEFAULT_WINDOW_SIZE,
        PhiAccrualFailureDetector,
    )

    task_cfg = config.task.config or {}
    hb_min = float(task_cfg.get("hb_min", DEFAULT_HB_MIN))
    hb_max = float(task_cfg.get("hb_max", DEFAULT_HB_MAX))
    eval_interval = float(task_cfg.get("eval_interval", DEFAULT_EVAL_INTERVAL))
    silent_from = float(task_cfg.get("silent_from", DEFAULT_SILENT_FROM))
    silent_until = float(task_cfg.get("silent_until", DEFAULT_SILENT_UNTIL))
    fd_plugin = str(task_cfg.get("fd_plugin", DEFAULT_FD_PLUGIN))
    raw_fd_params = task_cfg.get("fd_params", {})
    fd_params: dict[str, Any] = (
        cast("dict[str, Any]", raw_fd_params) if isinstance(raw_fd_params, dict) else {}
    )

    emitter_ids: list[AgentId] = []
    observer_ids: list[AgentId] = []
    emitter_silence: dict[AgentId, tuple[float, float]] = {}
    for role in config.agents.roles:
        for i in range(role.count):
            aid = AgentId(f"{role.name}-{i}")
            if role.name == "observer":
                observer_ids.append(aid)
            else:
                emitter_ids.append(aid)
                if role.name == "target":
                    emitter_silence[aid] = (silent_from, silent_until)
                else:
                    emitter_silence[aid] = (0.0, 0.0)

    def _make_detector() -> Any:
        if fd_plugin == "heartbeat":
            return HeartbeatFailureDetector(
                timeout=float(fd_params.get("timeout", DEFAULT_TIMEOUT)),
            )
        return PhiAccrualFailureDetector(
            window_size=int(fd_params.get("window_size", DEFAULT_WINDOW_SIZE)),
            min_samples=int(fd_params.get("min_samples", DEFAULT_MIN_SAMPLES)),
            min_std=float(fd_params.get("min_std", DEFAULT_MIN_STD)),
            threshold=float(fd_params.get("threshold", DEFAULT_THRESHOLD)),
        )

    detectors: dict[AgentId, Any] = {oid: _make_detector() for oid in observer_ids}
    overrides: dict[AgentId, dict[str, Any]] = {
        oid: {"failure_detector": det} for oid, det in detectors.items()
    }
    plugins["_agent_plugins"] = overrides
    plugins["_fd_detectors"] = detectors
    plugins["_fd_watched"] = list(emitter_ids)

    agents: dict[AgentId, Any] = {}
    for oid in observer_ids:
        agents[oid] = FailureMonitorAgent(watched=list(emitter_ids), eval_interval=eval_interval)
    for eid in emitter_ids:
        sfrom, suntil = emitter_silence[eid]
        agents[eid] = HeartbeatEmitterAgent(
            agent_id=eid,
            hb_min=hb_min,
            hb_max=hb_max,
            silent_from=sfrom,
            silent_until=suntil,
        )
    return agents
