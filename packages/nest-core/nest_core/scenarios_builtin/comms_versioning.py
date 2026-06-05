# SPDX-License-Identifier: Apache-2.0
"""Comms schema-versioning scenario.

Mixed-version agents exchange envelopes through the configured comms plugin to
exercise cross-version interop. A v1 sender emits a legacy envelope (no schema
version); a v2 sender emits a v2.1 envelope carrying an unknown ``priority``
field plus an unsupported-major v3 envelope. A forwarder round-trips each
message through the comms plugin (deserialize -> reserialize) and forwards what
it accepts to a sink.

Because the round-tripped envelopes land in the JSONL trace, the
``comms_versioning`` validators can check that the wire format survived:

- under ``versioned``: schema versions and unknown fields are preserved, and the
  unsupported-major message is rejected (validators PASS);
- under ``nest_native``: the version/unknown fields are silently dropped and the
  v3 message is blindly forwarded (validators FAIL).

Example::

    agents = comms_versioning_factory(config, plugins)
"""

from __future__ import annotations

import base64
import json
from typing import Any

from nest_plugins_reference.comms.versioned import UnsupportedSchemaError

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


def _raw_envelope(
    *,
    sender: AgentId,
    receiver: AgentId,
    payload: bytes,
    version: str | None = None,
    kind: str | None = None,
    extra: dict[str, Any] | None = None,
) -> bytes:
    """Build a raw JSON envelope on the wire (independent of any comms plugin).

    Used to inject specific versions/fields regardless of which comms plugin the
    agents use to read them.

    Example::

        raw = _raw_envelope(sender=AgentId("a"), receiver=AgentId("b"), payload=b"hi")
    """
    data: dict[str, Any] = {
        "id": f"msg-{sender}-{kind or 'legacy'}",
        "sender": str(sender),
        "receiver": str(receiver),
        "payload": base64.b64encode(payload).decode("ascii"),
        "correlation_id": None,
        "timestamp": 0,
        "metadata": {},
    }
    if version is not None:
        data["schema_version"] = version
    if kind is not None:
        data["kind"] = kind
    if extra:
        data.update(extra)
    return json.dumps(data, sort_keys=True).encode("utf-8")


class V1SenderAgent(StateMachineAgent):
    """Emits a legacy (no schema_version) envelope to the forwarder."""

    def __init__(self, agent_id: AgentId, forwarder: AgentId) -> None:
        self._id = agent_id
        self._forwarder = forwarder

    async def on_start(self, ctx: AgentContext) -> None:
        """Send one legacy envelope.

        Example::

            await agent.on_start(ctx)
        """
        raw = _raw_envelope(sender=self._id, receiver=self._forwarder, payload=b"greeting-v1")
        await ctx.send(self._forwarder, raw)


class V2SenderAgent(StateMachineAgent):
    """Emits a v2.1 envelope (with an unknown field) and an unsupported v3 envelope."""

    def __init__(self, agent_id: AgentId, forwarder: AgentId) -> None:
        self._id = agent_id
        self._forwarder = forwarder

    async def on_start(self, ctx: AgentContext) -> None:
        """Send a forward-compatible v2.1 message and an unsupported-major v3 message.

        Example::

            await agent.on_start(ctx)
        """
        v2 = _raw_envelope(
            sender=self._id,
            receiver=self._forwarder,
            payload=b"greeting-v2",
            version="2.1",
            kind="greeting",
            extra={"priority": "high"},
        )
        await ctx.send(self._forwarder, v2)

        v3 = _raw_envelope(
            sender=self._id,
            receiver=self._forwarder,
            payload=b"probe-v3",
            version="3.0",
            kind="probe",
        )
        await ctx.send(self._forwarder, v3)


class ForwarderAgent(StateMachineAgent):
    """Round-trips each envelope through the comms plugin and forwards accepted ones."""

    def __init__(self, agent_id: AgentId, sink: AgentId) -> None:
        self._id = agent_id
        self._sink = sink

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Deserialize then re-serialize via comms; forward unless the major is unsupported.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        comms = ctx.plugins["comms"]
        try:
            msg = comms.deserialize(payload)
        except UnsupportedSchemaError:
            return  # reject unsupported-major messages instead of forwarding
        out = comms.serialize(msg)
        await ctx.send(self._sink, out)


class SinkAgent(StateMachineAgent):
    """Terminal agent; records nothing beyond the trace it receives."""

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """No-op sink.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        return


def comms_versioning_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create mixed-version sender agents, a forwarder, and a sink.

    Instantiates the configured comms plugin (versioned or nest_native) as a
    shared serializer the agents use for the deserialize -> reserialize round trip.

    Example::

        agents = comms_versioning_factory(config, plugins)
    """
    _instantiate_comms(plugins)

    forwarder_id = AgentId("forwarder-0")
    sink_id = AgentId("sink-0")
    v1_sender = AgentId("v1sender-0")
    v2_sender = AgentId("v2sender-0")

    return {
        v1_sender: V1SenderAgent(v1_sender, forwarder=forwarder_id),
        v2_sender: V2SenderAgent(v2_sender, forwarder=forwarder_id),
        forwarder_id: ForwarderAgent(forwarder_id, sink=sink_id),
        sink_id: SinkAgent(sink_id),
    }


def _instantiate_comms(plugins: dict[str, Any]) -> None:
    """Instantiate the comms plugin class into a shared serializer instance, in place.

    Example::

        _instantiate_comms(plugins)
    """
    comms_cls = plugins.get("comms")
    if isinstance(comms_cls, type):
        plugins["comms"] = comms_cls(AgentId("comms-helper"))
