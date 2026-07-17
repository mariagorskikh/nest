# SPDX-License-Identifier: Apache-2.0
"""Failure-detection scenarios — silence that heals, plus a Byzantine forger.

Topology of the base scenario (see ``scenarios/failure_detection.yaml``):

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

**Authenticated heartbeats.**  Every heartbeat is signed with the emitter's
identity plugin and carries its emission timestamp:
``FDHB|<id>|<ts>|<sig-hex>``.  The observer verifies the signature against the
claimed peer's registered public key and requires the signed timestamp to be
strictly newer than the last accepted one from that peer (and not from the
future), so both fabricated and replayed heartbeats are rejected.  Verification
lives in the observing agent, not in the detector: the
:class:`~nest_core.layers.failure_detector.FailureDetector` contract stays a
pure liveness oracle over *accepted* observations.

The forgery scenario (``scenarios/failure_detection_forgery.yaml``, task type
``failure_detection_forgery``) adds a Byzantine ``forger`` role that mounts the
keep-alive attack: while the victim is genuinely down, the forger keeps
broadcasting heartbeats that *claim* to be the victim — both fabricated
payloads signed with the forger's own key and byte-exact replays of captured
genuine beats.  With ``verify_heartbeats: true`` (the default) the observer
rejects every forgery and the outage is detected; with the trusting mode
(``verify_heartbeats: false``, the foil) the forged liveness masks the crash
and the ``failure_detection_no_forged_liveness`` validator fails.  This is the
same discriminator pattern the base scenario uses against the fixed-timeout
baseline, applied to an attack class instead of an implementation mistake.

Ground truth is not inferred — the emitters broadcast ``fd:phase`` marker events
at start and on every reachability transition, and the observer broadcasts one
``fd:config`` marker carrying the scenario's heartbeat bounds, so the
validators derive their thresholds from the trace instead of hardcoding the
scenario configuration.  Heartbeats and status reports are plain broadcasts at
``failures.message_drop == 0``, so no redundancy is needed and the run is fully
deterministic for a fixed seed.

Example::

    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig

    config = ScenarioConfig.from_yaml("scenarios/failure_detection.yaml")
    runner = ScenarioRunner(config)
    await runner.run()
"""

from __future__ import annotations

import json
import math
from typing import Any, cast

from nest_core.layers.failure_detector import FailureDetector
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Signature

HB_TICK = b"FD_HB_TICK"
"""Payload tag for an emitter's periodic self-message that triggers a heartbeat."""

EVAL_TICK = b"FD_EVAL_TICK"
"""Payload tag for the observer's periodic self-message that triggers an evaluation."""

FORGE_TICK = b"FD_FORGE_TICK"
"""Payload tag for the forger's periodic self-message that triggers an attack round."""

_HB_PREFIX = "FDHB|"
"""Marker prefix identifying a heartbeat broadcast."""

_HB_ALGORITHM = "sim-rsa-sha256"
"""Algorithm tag stamped on reconstructed heartbeat signatures.

The reference identity plugins verify by key material and ignore this field;
it is carried for trace forensics only.
"""

IDENTITY_SEED = b"fd-heartbeat-v1"
"""Deterministic key-derivation seed shared by every agent's identity instance."""

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

DEFAULT_VERIFY_HEARTBEATS = True
"""Default authentication mode: observers verify heartbeat signatures."""

DEFAULT_FORGERY_VICTIM = "target-0"
"""Default peer the forger impersonates in the forgery scenario."""


def heartbeat_payload(identity: Any, agent_id: AgentId, now: float) -> bytes:
    """Return a signed heartbeat payload ``FDHB|<id>|<ts>|<sig-hex>``.

    The signature covers ``FDHB|<id>|<ts>`` exactly as serialized, so a
    verifier can rebuild the signed bytes from the wire text without float
    round-tripping.  When *identity* is ``None`` the unsigned prefix form is
    emitted (usable only by a trusting observer).

    Example::

        payload = heartbeat_payload(identity, AgentId("peer-0"), 12.5)
    """
    base = f"{_HB_PREFIX}{agent_id}|{round(now, 6)}"
    if identity is None:
        return base.encode()
    sig = identity.sign(base.encode())
    return f"{base}|{sig.value.hex()}".encode()


def claimed_peer(payload: bytes) -> AgentId | None:
    """Return the peer id a heartbeat payload *claims*, with no authentication.

    This is the trusting parse: it believes whatever id the payload names,
    which is exactly the spoofable behavior the forgery scenario attacks.

    Example::

        peer = claimed_peer(b"FDHB|peer-0|12.5|abcd")
    """
    text = payload.decode("utf-8", "replace")
    if not text.startswith(_HB_PREFIX):
        return None
    claimed = text[len(_HB_PREFIX) :].split("|", 1)[0]
    if not claimed:
        return None
    return AgentId(claimed)


def verify_heartbeat(
    identity: Any,
    payload: bytes,
    last_ts: dict[AgentId, float],
    now: float,
) -> tuple[AgentId, float] | None:
    """Return ``(peer, ts)`` if *payload* is an authentic, fresh heartbeat.

    Rejects the payload unless every check passes:

    * well-formed ``FDHB|<id>|<ts>|<sig-hex>`` wire format;
    * the signed timestamp is not from the future and is strictly newer than
      the last accepted heartbeat from that peer (defeats replay);
    * the signature verifies against the *claimed* peer's registered public
      key (defeats fabrication — a forger signing with its own key fails).

    Verification does not consult transport metadata, so it holds even on a
    transport whose sender field cannot be trusted.

    Example::

        accepted = verify_heartbeat(identity, payload, last_ts={}, now=12.5)
    """
    text = payload.decode("utf-8", "replace")
    if not text.startswith(_HB_PREFIX):
        return None
    fields = text[len(_HB_PREFIX) :].split("|")
    if len(fields) != 3:
        return None
    claimed, ts_text, sig_hex = fields
    if not claimed:
        return None
    try:
        ts = float(ts_text)
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return None
    # A non-finite timestamp (nan/inf) would slip the IEEE-754 comparisons
    # below, so reject it outright.  Genuine beats always carry ``round(now, 6)``.
    if not math.isfinite(ts):
        return None
    peer = AgentId(claimed)
    # The signed ts is quantized to 6 dp, so it can round a hair above the
    # observer's exact ``now`` on the same zero-latency tick; compare against
    # the same quantum rather than raw ``now`` so genuine beats are not read as
    # future-dated.  Replays are still caught by the strict freshness check.
    if ts > round(now, 6) or ts <= last_ts.get(peer, float("-inf")):
        return None
    if identity is None:
        return None
    base = f"{_HB_PREFIX}{claimed}|{ts_text}"
    sig = Signature(signer=peer, value=sig_bytes, algorithm=_HB_ALGORITHM)
    if not identity.verify(base.encode(), sig, peer):
        return None
    return peer, ts


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


def _config_payload(hb_max: float, verify: bool, now: float) -> bytes:
    """Return the ``fd:config`` marker carrying the scenario's heartbeat bound.

    The validators derive the longest silence a live peer can plausibly
    produce from this marker instead of hardcoding the scenario's ``hb_max``.

    Example::

        payload = _config_payload(20.0, verify=True, now=0.0)
    """
    obj: dict[str, Any] = {
        "fd": "config",
        "hb_max": round(hb_max, 6),
        "verify": verify,
        "ts": round(now, 6),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _build_identities(
    identity_cls: Any, agent_ids: list[AgentId], seed: bytes
) -> dict[AgentId, Any]:
    """Build one identity instance per agent, cross-registering every public key.

    Structural copy of the wiring block used by ``gossip_byzantine`` and
    ``bft_hotstuff`` (private helpers are not imported across scenario module
    boundaries).  Identities are built for every agent, forger included: the
    forger needs a real keypair so its impersonation attempt is the strongest
    available — a genuine signature by the *wrong* key, not malformed bytes.

    Example::

        identities = _build_identities(DidKeyIdentity, [AgentId("a")], b"seed")
    """
    identities: dict[AgentId, Any] = {aid: identity_cls(aid, seed=seed) for aid in agent_ids}
    for aid, ident in identities.items():
        if not hasattr(ident, "register_peer"):
            continue
        for peer_id, peer_ident in identities.items():
            if peer_id != aid:
                ident.register_peer(peer_id, peer_ident.public_key)
    return identities


class HeartbeatEmitterAgent(StateMachineAgent):
    """Broadcast signed jittered heartbeats, going silent for one bounded window.

    The agent emits a ``fd:phase`` marker at start and on every transition
    between reachable and unreachable, so the trace carries ground truth that
    the validators can check the detector against.  During the silence window
    ``[silent_from, silent_until)`` heartbeats are suppressed but the agent
    keeps re-arming its tick chain, so emission resumes cleanly afterwards.
    Heartbeats are signed with the agent's injected ``identity`` plugin.

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
            identity = ctx.plugins.get("identity")
            await ctx.broadcast(heartbeat_payload(identity, self._id, ctx.time))
        await self._arm_next(ctx)


class ByzantineForgerAgent(StateMachineAgent):
    """Impersonate *victim* with fabricated and replayed heartbeats.

    Two attacks per jittered tick, running for the whole scenario:

    * **Fabrication** — build a fresh heartbeat that *claims* the victim's id
      but is signed with the forger's own (real) key.  Fools any observer that
      trusts the claimed id; fails signature verification against the victim's
      public key.
    * **Replay** — rebroadcast, byte for byte, the most recent genuine signed
      heartbeat captured from the victim.  The signature verifies, so only the
      freshness check (signed timestamp strictly newer than the last accepted
      one) rejects it.

    The point of the attack is *keep-alive forgery*: while the victim is truly
    silent, forged liveness keeps arriving, and a spoofable observer will never
    suspect the dead peer.

    Example::

        agent = ByzantineForgerAgent(
            AgentId("forger-0"), victim=AgentId("target-0"),
            hb_min=10.0, hb_max=20.0,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        victim: AgentId,
        hb_min: float = DEFAULT_HB_MIN,
        hb_max: float = DEFAULT_HB_MAX,
    ) -> None:
        self._id = agent_id
        self._victim = victim
        self._hb_min = hb_min
        self._hb_max = hb_max
        self._captured: bytes | None = None

    async def _arm_next(self, ctx: AgentContext) -> None:
        await ctx.schedule(ctx.rng.uniform(self._hb_min, self._hb_max), FORGE_TICK)

    async def on_start(self, ctx: AgentContext) -> None:
        """Arm the first attack tick.

        Example::

            await agent.on_start(ctx)
        """
        await self._arm_next(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Capture the victim's genuine beats; on attack ticks, forge and replay.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        if sender == self._victim:
            if claimed_peer(payload) == self._victim:
                self._captured = payload
            return
        if sender != ctx.agent_id or payload != FORGE_TICK:
            return
        identity = ctx.plugins.get("identity")
        await ctx.broadcast(heartbeat_payload(identity, self._victim, ctx.time))
        if self._captured is not None:
            await ctx.broadcast(self._captured)
        await self._arm_next(ctx)


class FailureMonitorAgent(StateMachineAgent):
    """Drive one failure detector and periodically publish suspicion verdicts.

    The detector is injected as the per-agent ``failure_detector`` plugin and
    the observer's identity (with every peer's public key registered) as the
    ``identity`` plugin.  In the default verifying mode, a heartbeat is fed to
    the detector only after its signature and freshness pass
    :func:`verify_heartbeat`; in the trusting mode (``verify=False``, the forgery
    scenario's foil) the claimed peer id is believed outright.  On each
    evaluation self-tick the agent reports, for every watched peer, a
    ``fd:status`` broadcast carrying the boolean verdict plus the current
    ``phi`` and elapsed silence (the latter two are informational — the
    validators key off the verdict and the broadcast's own timestamp).

    Example::

        agent = FailureMonitorAgent(
            watched=[AgentId("target-0"), AgentId("peer-0")], eval_interval=3.0,
        )
    """

    def __init__(
        self,
        watched: list[AgentId],
        eval_interval: float = DEFAULT_EVAL_INTERVAL,
        hb_max: float = DEFAULT_HB_MAX,
        verify: bool = DEFAULT_VERIFY_HEARTBEATS,
    ) -> None:
        self._watched = watched
        self._eval_interval = eval_interval
        self._hb_max = hb_max
        self._verify = verify
        self._last_hb_ts: dict[AgentId, float] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Broadcast the ``fd:config`` marker and arm the first evaluation tick.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.broadcast(_config_payload(self._hb_max, self._verify, ctx.time))
        await ctx.schedule(self._eval_interval, EVAL_TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Feed authenticated heartbeats into the detector; publish verdicts.

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
        if self._verify:
            accepted = verify_heartbeat(
                ctx.plugins.get("identity"), payload, self._last_hb_ts, ctx.time
            )
            if accepted is None:
                return
            hb_peer, hb_ts = accepted
            if hb_peer == ctx.agent_id:
                return
            self._last_hb_ts[hb_peer] = hb_ts
            await fd.heartbeat(hb_peer, now=ctx.time)
            return
        hb_peer = claimed_peer(payload)
        if hb_peer is not None and hb_peer != ctx.agent_id:
            await fd.heartbeat(hb_peer, now=ctx.time)


def failure_detection_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build the agent fleet for the failure-detection scenarios.

    Roles are read from ``config.agents.roles``: an ``observer`` role becomes a
    :class:`FailureMonitorAgent` (each gets its own freshly-built detector and
    identity), a ``target`` role becomes a silence-then-heal
    :class:`HeartbeatEmitterAgent`, a ``forger`` role becomes a
    :class:`ByzantineForgerAgent` impersonating ``forgery_victim``, and any
    other emitter role (e.g. ``peer``) becomes a never-silent emitter.  The
    detector kind, its parameters, and the ``verify_heartbeats`` mode come from
    ``task.config`` so the same scenario can be re-run with the baseline or the
    accrual detector, and with or without heartbeat authentication.  The same
    factory serves both the ``failure_detection`` and
    ``failure_detection_forgery`` task types; the difference is purely which
    roles the YAML declares.

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
    verify_heartbeats = bool(task_cfg.get("verify_heartbeats", DEFAULT_VERIFY_HEARTBEATS))
    forgery_victim = AgentId(str(task_cfg.get("forgery_victim", DEFAULT_FORGERY_VICTIM)))
    raw_fd_params = task_cfg.get("fd_params", {})
    fd_params: dict[str, Any] = (
        cast("dict[str, Any]", raw_fd_params) if isinstance(raw_fd_params, dict) else {}
    )

    emitter_ids: list[AgentId] = []
    observer_ids: list[AgentId] = []
    forger_ids: list[AgentId] = []
    emitter_silence: dict[AgentId, tuple[float, float]] = {}
    for role in config.agents.roles:
        for i in range(role.count):
            aid = AgentId(f"{role.name}-{i}")
            if role.name == "observer":
                observer_ids.append(aid)
            elif role.name == "forger":
                forger_ids.append(aid)
            else:
                emitter_ids.append(aid)
                if role.name == "target":
                    emitter_silence[aid] = (silent_from, silent_until)
                else:
                    emitter_silence[aid] = (0.0, 0.0)

    identity_cls = plugins.get("identity")
    if identity_cls is None:
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        identity_cls = DidKeyIdentity
    all_ids = observer_ids + emitter_ids + forger_ids
    identities = _build_identities(identity_cls, all_ids, IDENTITY_SEED)

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
        aid: {"identity": identities[aid]} for aid in all_ids
    }
    for oid, det in detectors.items():
        overrides[oid]["failure_detector"] = det
    plugins["_agent_plugins"] = overrides
    plugins["_fd_detectors"] = detectors
    plugins["_fd_watched"] = list(emitter_ids)
    plugins["_fd_identities"] = identities

    agents: dict[AgentId, Any] = {}
    for oid in observer_ids:
        agents[oid] = FailureMonitorAgent(
            watched=list(emitter_ids),
            eval_interval=eval_interval,
            hb_max=hb_max,
            verify=verify_heartbeats,
        )
    for eid in emitter_ids:
        sfrom, suntil = emitter_silence[eid]
        agents[eid] = HeartbeatEmitterAgent(
            agent_id=eid,
            hb_min=hb_min,
            hb_max=hb_max,
            silent_from=sfrom,
            silent_until=suntil,
        )
    for fid in forger_ids:
        agents[fid] = ByzantineForgerAgent(
            agent_id=fid,
            victim=forgery_victim,
            hb_min=hb_min,
            hb_max=hb_max,
        )
    return agents
