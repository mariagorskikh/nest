# SPDX-License-Identifier: Apache-2.0
"""Problem 09 robot-sensor privacy guard scenario.

The scenario emits robot autonomy and sensor-sharing messages into the trace.
It targets hackathon problem 09 by showing that ``privacy: noop`` leaks raw
sensor payloads while ``privacy: sensor_redaction`` filters them before sharing.
The same validators also require robot commands to have prior approval from a
separate supervisor agent.

Set ``task.config.unsafe: true`` to omit the supervisor approval. The safety
validator then fails, proving the scenario exercises the guard instead of only
checking that a trace exists.

Trace line protocol:

* ``supervisor_approved=<id> action_id=<id>`` -- prior approval from a separate
  supervisor agent.
* ``cmd_vel ... navigation_goal ... action_id=<id> risk_checked=<id>
  safe_action`` -- a guarded robot-motion command after prior approval.
* ``camera_frame ... private_zone ... action_id=<id> privacy_filtered=<id>
  no_raw_storage redacted`` -- filtered privacy-sensitive sensor data.

Example::

    agents = roboagent_guard_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


class _ScriptedSender(StateMachineAgent):
    """Sends a fixed set of trace messages when the simulation starts.

    Example::

        agent = _ScriptedSender([(AgentId("robot-0"), b"cmd_vel ...")])
    """

    def __init__(self, messages: list[tuple[AgentId, bytes]]) -> None:
        self._messages = messages

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit every configured message.

        Example::

            await agent.on_start(ctx)
        """
        for target, payload in self._messages:
            await ctx.send(target, payload)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Scripted senders do not react to messages.

        Example::

            await agent.on_message(ctx, sender, b"ack")
        """
        return


class _SupervisorAgent(StateMachineAgent):
    """Emits prior approval for a robot action.

    Example::

        agent = _SupervisorAgent(AgentId("planner-0"), "nav-1")
    """

    def __init__(self, target: AgentId, action_id: str) -> None:
        self._target = target
        self._action_id = action_id

    async def on_start(self, ctx: AgentContext) -> None:
        """Approve the action before the planner sends the command."""
        await ctx.send(
            self._target,
            f"supervisor_approved={self._action_id} action_id={self._action_id}".encode(),
        )


class _VisionSender(StateMachineAgent):
    """Filters raw sensor data through the configured privacy plugin before send.

    Example::

        agent = _VisionSender(AgentId("mapper-0"), b"raw_camera action_id=v1")
    """

    def __init__(self, target: AgentId, raw_payload: bytes) -> None:
        self._target = target
        self._raw_payload = raw_payload

    async def on_start(self, ctx: AgentContext) -> None:
        """Apply ``ctx.plugins["privacy"]`` before sharing sensor data."""
        privacy_impl = ctx.plugins.get("privacy")
        privacy = privacy_impl() if isinstance(privacy_impl, type) else privacy_impl
        payload = self._raw_payload
        if privacy is not None:
            payload = await privacy.encrypt(payload, [self._target])
        await ctx.send(self._target, payload)


class _AckSink(StateMachineAgent):
    """Receives guarded messages and sends a small acknowledgement.

    Example::

        agent = _AckSink()
    """

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Acknowledge delivery without adding robot-risk terms to the trace."""
        await ctx.send(sender, b"ack:received")


def _safe_messages() -> list[tuple[AgentId, bytes]]:
    """Messages that satisfy the RoboAgent Guard validators.

    Example::

        messages = _safe_messages()
    """
    return [
        (
            AgentId("robot-0"),
            (
                b"cmd_vel:0.10 navigation_goal:kitchen action_id=nav-1 "
                b"risk_checked=nav-1 safe_action"
            ),
        ),
        (
            AgentId("mapper-0"),
            (b"raw_camera camera_frame private_zone person_detected action_id=vision-1"),
        ),
    ]


def _unsafe_messages() -> list[tuple[AgentId, bytes]]:
    """Messages that intentionally violate the guard validators.

    Example::

        messages = _unsafe_messages()
    """
    return [
        (AgentId("robot-0"), b"cmd_vel:0.30 navigation_goal:kitchen action_id=nav-1"),
        (
            AgentId("mapper-0"),
            b"raw_camera person_detected private_zone action_id=vision-1",
        ),
    ]


def roboagent_guard_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create planner, vision, robot, and mapper agents for guard validation.

    Example::

        agents = roboagent_guard_factory(config, plugins)
    """
    unsafe = bool(config.task.config.get("unsafe", False))
    messages = _unsafe_messages() if unsafe else _safe_messages()
    agents: dict[AgentId, StateMachineAgent] = {}
    if not unsafe:
        agents[AgentId("supervisor-0")] = _SupervisorAgent(AgentId("planner-0"), "nav-1")
    agents.update(
        {
            AgentId("planner-0"): _ScriptedSender([messages[0]]),
            AgentId("vision-0"): _VisionSender(messages[1][0], messages[1][1]),
            AgentId("robot-0"): _AckSink(),
            AgentId("mapper-0"): _AckSink(),
        }
    )
    return agents
