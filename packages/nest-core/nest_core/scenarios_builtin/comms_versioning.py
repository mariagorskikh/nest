# SPDX-License-Identifier: Apache-2.0
"""Comms schema-versioning scenario — mixed-version agents on one wire.

A swarm mid-rolling-upgrade: half the peers speak the old wire format and half
speak a newer one. Each peer sends to a single ``auditor`` that decodes every
envelope with the configured ``comms`` plugin and reports, in an ``ack``, what
it did with it. The trace this produces is what
``validate_trace(..., "comms_versioning")`` inspects.

The peers build raw envelopes *directly* (not through any comms plugin) so the
injected traffic is byte-identical regardless of which comms layer the auditor
runs. That is what lets the same scenario demonstrate both directions:

* with ``comms: versioned`` the auditor preserves unknown fields and rejects the
  breaking major bump -> the adversarial validators pass;
* with ``comms: nest_native`` the auditor silently drops the unknown field and
  accepts the breaking major as if it were v1 -> the validators fail.

Three envelope shapes are injected:

* ``1.0`` — an old-format peer (no unknown fields);
* ``1.1`` — a newer-*minor* peer carrying an unknown ``x-trace-id`` field
  (forward compat: must be preserved);
* ``2.0`` — a newer-*major* "future" peer (breaking: must be rejected).

Example::

    agents = comms_versioning_factory(config, plugins)
"""

from __future__ import annotations

import base64
import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


def _envelope(
    *,
    version: str,
    kind: str,
    mid: str,
    sender: str,
    receiver: str,
    payload: bytes,
    extra: dict[str, Any] | None = None,
) -> bytes:
    """Build a canonical (sorted-key) JSON envelope as raw wire bytes.

    ``extra`` injects top-level fields a newer peer would add; they are unknown
    to an older reader. Output is deterministic for Tier 1 replay.

    Example::

        raw = _envelope(version="1.1", kind="offer", mid="m-1", sender="a",
                        receiver="b", payload=b"x", extra={"x-trace-id": "t1"})
    """
    env: dict[str, Any] = {
        "schema_version": version,
        "kind": kind,
        "id": mid,
        "sender": sender,
        "receiver": receiver,
        "payload": base64.b64encode(payload).decode("ascii"),
        "correlation_id": None,
        "timestamp": None,
        "metadata": {},
    }
    if extra:
        env.update(extra)
    return json.dumps(env, sort_keys=True).encode("utf-8")


def _best_effort_id(raw: bytes) -> str:
    """Pull the ``id`` out of a possibly-undecodable envelope for ack labelling.

    Example::

        assert _best_effort_id(b'{"id": "m-1"}') == "m-1"
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return "unknown"
    if isinstance(data, dict):
        return str(cast("dict[str, Any]", data).get("id", "unknown"))
    return "unknown"


class PeerAgent(StateMachineAgent):
    """Sends versioned envelopes to the auditor at start.

    A ``v1`` peer sends one ``1.0`` envelope; a ``v2`` peer sends a ``1.1``
    envelope with an unknown field *and* a breaking ``2.0`` envelope.

    Example::

        peer = PeerAgent(AgentId("peer-1"), index=1, is_v2=True,
                         auditor=AgentId("auditor-0"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        index: int,
        is_v2: bool,
        auditor: AgentId,
    ) -> None:
        self._id = agent_id
        self._index = index
        self._is_v2 = is_v2
        self._auditor = auditor

    async def on_start(self, ctx: AgentContext) -> None:
        """Arm a self-timer so this peer emits on its own tick.

        The default transport is zero-latency, so without staggering every
        event lands at ``t=0``. Scheduling each peer onto tick ``index + 1``
        gives the trace real virtual time (a rolling upgrade unfolding over
        ticks) while keeping the run deterministic.

        Example::

            await peer.on_start(ctx)
        """
        await ctx.schedule(float(self._index + 1), b"emit")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Emit envelopes when our timer fires; ignore the auditor's ack.

        Example::

            await peer.on_message(ctx, AgentId("peer-1"), b"emit")
        """
        if payload != b"emit":
            return
        me, to = str(self._id), str(self._auditor)
        if not self._is_v2:
            await ctx.send(
                self._auditor,
                _envelope(
                    version="1.0",
                    kind="offer",
                    mid=f"m-{self._index}-base",
                    sender=me,
                    receiver=to,
                    payload=b"v1-offer",
                ),
            )
            return
        # Forward-compatible minor bump: carries a field older readers don't know.
        await ctx.send(
            self._auditor,
            _envelope(
                version="1.1",
                kind="offer",
                mid=f"m-{self._index}-minor",
                sender=me,
                receiver=to,
                payload=b"v2-offer",
                extra={"x-trace-id": f"trace-{self._index}"},
            ),
        )
        # Breaking major bump from a hypothetical future build: must be rejected.
        await ctx.send(
            self._auditor,
            _envelope(
                version="2.0",
                kind="offer",
                mid=f"m-{self._index}-major",
                sender=me,
                receiver=to,
                payload=b"v_future-offer",
            ),
        )


class AuditorAgent(StateMachineAgent):
    """Decodes every envelope with the configured comms plugin and acks the outcome.

    The ack format is ``ack:<id>:<status>:<preserved fields>`` where status is
    ``accepted`` (with the comma-separated unknown fields the decoder preserved)
    or ``rejected_major`` (decode refused). This is the evidence the comms
    validators score.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"), comms=VersionedComms(...))
    """

    def __init__(self, agent_id: AgentId, comms: Any) -> None:
        self._id = agent_id
        self._comms = comms

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Decode one envelope and report what happened back to the sender.

        Example::

            await auditor.on_message(ctx, AgentId("peer-1"), raw)
        """
        try:
            msg = self._comms.deserialize(payload)
        except (ValueError, KeyError):
            # UnsupportedSchemaError (a ValueError) or a structurally invalid
            # envelope: the decoder refused, which is the correct behaviour for
            # an unknown major.
            mid = _best_effort_id(payload)
            await ctx.send(sender, f"ack:{mid}:rejected_major:".encode())
            return
        preserved = sorted(cast("dict[str, Any]", msg.metadata.get("_unknown") or {}))
        await ctx.send(
            sender,
            f"ack:{msg.id}:accepted:{','.join(preserved)}".encode(),
        )


def comms_versioning_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create one auditor and a mix of v1/v2 peer agents.

    The auditor decodes with ``plugins["comms"]`` so the scenario exercises
    whichever comms plugin the YAML selected. Peer count comes from the
    ``peer`` role (default: all agents but the auditor); even indices speak v1,
    odd indices speak v2.

    Example::

        agents = comms_versioning_factory(config, plugins)
    """
    peer_count = 0
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "peer":
                peer_count = role.count
    if peer_count == 0:
        peer_count = max(2, config.agents.count - 1)

    auditor_id = AgentId("auditor-0")
    comms_cls = plugins["comms"]
    auditor_comms = comms_cls(auditor_id)

    agents: dict[AgentId, StateMachineAgent] = {
        auditor_id: AuditorAgent(auditor_id, comms=auditor_comms),
    }
    for i in range(peer_count):
        aid = AgentId(f"peer-{i}")
        agents[aid] = PeerAgent(aid, index=i, is_v2=bool(i % 2), auditor=auditor_id)
    return agents
