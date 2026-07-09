# SPDX-License-Identifier: Apache-2.0
"""Comms downgrade-attack scenario — an on-path adversary rewrites authentic bytes.

A swarm where every honest peer authenticates its envelopes with an ``auth_tag``
(see :mod:`nest_plugins_reference.comms.authenticated`), but a man-in-the-middle
sits on the wire and tampers with a copy before it reaches the ``auditor``. Each
peer injects three envelopes at the auditor, all byte-identical regardless of which
comms plugin the auditor runs (the tampering is baked into the bytes, not produced
by a plugin), so the same scenario demonstrates both directions:

* with ``comms: authenticated`` the auditor recomputes the tag, sees it no longer
  covers the rewritten bytes, and rejects the tampered copies -> the downgrade
  validator passes;
* with ``comms: versioned`` (or ``nest_native``) the auditor has no tag concept and
  accepts the rolled-back / stripped copies as if authentic -> the validator fails.

Three envelope shapes per peer, keyed by id suffix for readability (the validator
does *not* trust the suffix — it recomputes the tag as ground truth):

* ``m-<i>-honest``   — a genuine ``1.1`` envelope with a valid tag (must be accepted);
* ``m-<i>-rollback`` — the same envelope with ``schema_version`` rewritten to ``1.0``
  and the stale tag left in place (version rollback: must be rejected);
* ``m-<i>-strip``    — the same envelope with the newer peer's ``x-trace-id`` field
  deleted and the stale tag left in place (field stripping: must be rejected).

Example::

    agents = comms_downgrade_factory(config, plugins)
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
    so the tag is exactly what an honest sender would emit; the attacker then
    mutates a copy of these bytes. Deterministic (no clock, no RNG).

    Example::

        raw = _honest_bytes("m-0-honest", "peer-0", "auditor-0")
    """
    from nest_plugins_reference.comms.authenticated import AuthenticatedComms

    comms = AuthenticatedComms(AgentId(sender))
    msg = Message(
        id=MessageId(mid),
        sender=AgentId(sender),
        receiver=AgentId(receiver),
        payload=b"v1.1-offer",
        metadata={"schema_version": "1.1", "kind": "offer", "_unknown": {"x-trace-id": mid}},
    )
    return comms.serialize(msg)


def _tamper(raw: bytes, *, rewrite_version: str | None, drop_field: str | None) -> bytes:
    """Rewrite an authentic envelope's bytes while leaving its stale tag intact.

    Models the on-path attacker: it can edit any cleartext field but cannot
    recompute the HMAC tag (it lacks the channel key), so the tag no longer
    covers the bytes. Re-canonicalizes so the result is well-formed JSON an
    honest reader would happily parse.

    Example::

        rolled = _tamper(raw, rewrite_version="1.0", drop_field=None)
    """
    env = cast("dict[str, Any]", json.loads(raw))
    if rewrite_version is not None:
        env["schema_version"] = rewrite_version
    if drop_field is not None:
        env.pop(drop_field, None)
    return json.dumps(env, sort_keys=True).encode("utf-8")


def _best_effort_id(raw: bytes) -> str:
    """Pull the ``id`` from a possibly-undecodable envelope for ack labelling.

    Example::

        assert _best_effort_id(b'{"id": "m-0-honest"}') == "m-0-honest"
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return "unknown"
    if isinstance(data, dict):
        return str(cast("dict[str, Any]", data).get("id", "unknown"))
    return "unknown"


class DowngradePeerAgent(StateMachineAgent):
    """Emits an honest envelope plus the attacker's rolled-back and stripped copies.

    Example::

        peer = DowngradePeerAgent(AgentId("peer-0"), index=0, auditor=AgentId("auditor-0"))
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
        """On the self-timer, inject the honest envelope and both tampered copies.

        Example::

            await peer.on_message(ctx, AgentId("peer-0"), b"emit")
        """
        if payload != b"emit":
            return
        me, to = str(self._id), str(self._auditor)
        honest = _honest_bytes(f"m-{self._index}-honest", me, to)
        await ctx.send(self._auditor, honest)

        rollback_src = _honest_bytes(f"m-{self._index}-rollback", me, to)
        await ctx.send(
            self._auditor,
            _tamper(rollback_src, rewrite_version="1.0", drop_field=None),
        )

        strip_src = _honest_bytes(f"m-{self._index}-strip", me, to)
        await ctx.send(
            self._auditor,
            _tamper(strip_src, rewrite_version=None, drop_field="x-trace-id"),
        )


class DowngradeAuditorAgent(StateMachineAgent):
    """Decodes each envelope with the configured comms plugin and acks the outcome.

    Ack format is ``ack:<id>:<status>`` where status is ``accepted``,
    ``rejected_tampered`` (a :class:`DowngradeError` — tag failed), or
    ``rejected_major`` (any other decode refusal). This is the evidence the
    downgrade validator scores.

    Example::

        auditor = DowngradeAuditorAgent(AgentId("auditor-0"), comms=AuthenticatedComms(...))
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
        # package present; the DowngradeError subclass drives the ack label.
        from nest_plugins_reference.comms.authenticated import DowngradeError

        try:
            msg = self._comms.deserialize(payload)
        except DowngradeError:
            mid = _best_effort_id(payload)
            await ctx.send(sender, f"ack:{mid}:rejected_tampered:".encode())
            return
        except (ValueError, KeyError):
            mid = _best_effort_id(payload)
            await ctx.send(sender, f"ack:{mid}:rejected_major:".encode())
            return
        await ctx.send(sender, f"ack:{msg.id}:accepted:".encode())


def comms_downgrade_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create one auditor and a set of honest peers whose traffic is tampered in flight.

    The auditor decodes with ``plugins["comms"]`` so the scenario exercises
    whichever comms plugin the YAML selected. Peer count comes from the ``peer``
    role (default: all agents but the auditor).

    Example::

        agents = comms_downgrade_factory(config, plugins)
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
        auditor_id: DowngradeAuditorAgent(auditor_id, comms=auditor_comms),
    }
    for i in range(peer_count):
        aid = AgentId(f"peer-{i}")
        agents[aid] = DowngradePeerAgent(aid, index=i, auditor=auditor_id)
    return agents
