# SPDX-License-Identifier: Apache-2.0
"""Comms replay-attack scenario — an on-path relay re-sends a captured envelope.

A swarm where every honest peer sends two envelopes to the ``auditor``: one
that is delivered exactly once (the control), and one that a relay captures
and re-sends verbatim a second time (the replay). Both envelopes are
genuinely tagged by :class:`~nest_plugins_reference.comms.authenticated.AuthenticatedComms`
-- the replay is *not* tampered in any way, it is a byte-for-byte duplicate --
so the same scenario demonstrates both directions:

* with ``comms: replay_safe`` the auditor remembers it already accepted the
  replayed id from this sender and rejects the second delivery -> the replay
  validator passes;
* with ``comms: authenticated`` (or ``versioned``/``nest_native``) the auditor
  has no replay memory and the tag on the duplicate verifies just as well as
  the original -> it is accepted twice -> the validator fails.

Two envelope shapes per peer, keyed by id suffix for readability (the
validator does not trust the suffix -- it counts actual wire deliveries):

* ``m-<i>-solo``     -- sent once, must be accepted (no false positives);
* ``m-<i>-replayed`` -- sent twice, byte-identical; the first delivery must
  be accepted, the second must be rejected.

Example::

    agents = comms_replay_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Message, MessageId


def _honest_bytes(mid: str, sender: str, receiver: str) -> bytes:
    """Serialize a genuine, correctly-tagged ``1.1`` envelope via the real plugin.

    Built with :class:`~nest_plugins_reference.comms.authenticated.AuthenticatedComms`
    so the bytes -- and their tag -- are exactly what an honest sender would
    emit. Deterministic (no clock, no RNG).

    Example::

        raw = _honest_bytes("m-0-solo", "peer-0", "auditor-0")
    """
    from nest_plugins_reference.comms.authenticated import AuthenticatedComms

    comms = AuthenticatedComms(AgentId(sender))
    msg = Message(
        id=MessageId(mid),
        sender=AgentId(sender),
        receiver=AgentId(receiver),
        payload=b"v1.1-offer",
        metadata={"schema_version": "1.1", "kind": "offer"},
    )
    return comms.serialize(msg)


def _best_effort_id(raw: bytes) -> str:
    """Pull the ``id`` from a possibly-undecodable envelope for ack labelling.

    Example::

        assert _best_effort_id(b'{"id": "m-0-solo"}') == "m-0-solo"
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return "unknown"
    if isinstance(data, dict):
        return str(cast("dict[str, Any]", data).get("id", "unknown"))
    return "unknown"


class ReplayPeerAgent(StateMachineAgent):
    """Emits a solo envelope plus a second envelope a relay replays verbatim.

    Example::

        peer = ReplayPeerAgent(AgentId("peer-0"), index=0, auditor=AgentId("auditor-0"))
    """

    def __init__(self, agent_id: AgentId, index: int, auditor: AgentId) -> None:
        self._id = agent_id
        self._index = index
        self._auditor = auditor

    async def on_start(self, ctx: AgentContext) -> None:
        """Stagger emissions onto distinct ticks for real virtual time.

        Example::

            await peer.on_start(ctx)
        """
        await ctx.schedule(float(self._index + 1), b"emit")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the self-timer, send the solo envelope, then the replayed one twice.

        Example::

            await peer.on_message(ctx, AgentId("peer-0"), b"emit")
        """
        if payload != b"emit":
            return
        me, to = str(self._id), str(self._auditor)

        solo = _honest_bytes(f"m-{self._index}-solo", me, to)
        await ctx.send(self._auditor, solo)

        # The relay captures this exact envelope and re-sends it verbatim --
        # not a re-serialization, the identical bytes -- so its tag is still
        # perfectly valid. Only replay memory (not tamper-evidence) can catch it.
        genuine = _honest_bytes(f"m-{self._index}-replayed", me, to)
        await ctx.send(self._auditor, genuine)
        await ctx.send(self._auditor, genuine)


class ReplayAuditorAgent(StateMachineAgent):
    """Decodes each envelope with the configured comms plugin and acks the outcome.

    Ack format is ``ack:<id>:<status>`` where status is ``accepted``,
    ``rejected_replay`` (a :class:`ReplayError` -- duplicate id from this
    sender), ``rejected_tampered`` (a :class:`DowngradeError`), or
    ``rejected_major`` (any other decode refusal). This is the evidence the
    replay validator scores.

    Example::

        auditor = ReplayAuditorAgent(AgentId("auditor-0"), comms=ReplaySafeComms(...))
    """

    def __init__(self, agent_id: AgentId, comms: Any) -> None:
        self._id = agent_id
        self._comms = comms

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Decode one envelope and report the outcome back to the sender.

        Example::

            await auditor.on_message(ctx, AgentId("peer-0"), raw)
        """
        # Imported lazily so the scenario stays importable without the reference
        # package present. ReplayError is a DowngradeError subclass, so it must
        # be checked first or the broader except would mislabel it.
        from nest_plugins_reference.comms.authenticated import DowngradeError
        from nest_plugins_reference.comms.replay_safe import ReplayError

        try:
            msg = self._comms.deserialize(payload)
        except ReplayError:
            mid = _best_effort_id(payload)
            await ctx.send(sender, f"ack:{mid}:rejected_replay:".encode())
            return
        except DowngradeError:
            mid = _best_effort_id(payload)
            await ctx.send(sender, f"ack:{mid}:rejected_tampered:".encode())
            return
        except (ValueError, KeyError):
            mid = _best_effort_id(payload)
            await ctx.send(sender, f"ack:{mid}:rejected_major:".encode())
            return
        await ctx.send(sender, f"ack:{msg.id}:accepted:".encode())


def comms_replay_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create one auditor and a set of honest peers, one of whose messages is replayed.

    The auditor decodes with ``plugins["comms"]`` so the scenario exercises
    whichever comms plugin the YAML selected. Peer count comes from the
    ``peer`` role (default: all agents but the auditor).

    Example::

        agents = comms_replay_factory(config, plugins)
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
        auditor_id: ReplayAuditorAgent(auditor_id, comms=auditor_comms),
    }
    for i in range(peer_count):
        aid = AgentId(f"peer-{i}")
        agents[aid] = ReplayPeerAgent(aid, index=i, auditor=auditor_id)
    return agents
