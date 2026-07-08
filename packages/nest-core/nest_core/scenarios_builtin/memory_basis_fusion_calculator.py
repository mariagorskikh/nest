# SPDX-License-Identifier: Apache-2.0
"""Basis-fusion memory scenario -- act only on fusable calculator evidence.

This scenario exercises a more applied memory rule than "store every byte":
local reports are fused into a calculator project node only when they restrict
onto an existing basis dimension. A large copypasta-like payload has no
``node`` and no valid ``basis`` field, so it cannot glue to the calculator node
and cannot change the decision.

The coordinator writes accepted evidence into ``pn_counter`` memory and ships
the calculator only after all required basis dimensions have fused.

Example::

    agents = memory_basis_fusion_calculator_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_CHECK = b"check"
_REPORT_PREFIX = "fusion_report|"
_ACCEPT_PREFIX = "fusion_accept|"
_IGNORE_PREFIX = "fusion_ignore|"
_DELTA_PREFIX = "pn_delta|"
_DECISION_PREFIX = "decision|"
_FINAL_PREFIX = "final:"


class FusionReporterAgent(StateMachineAgent):
    """Send one report to the fusion coordinator.

    Example::

        agent = FusionReporterAgent(AgentId("impl-add"), AgentId("coordinator-0"), b"{}")
    """

    def __init__(self, agent_id: AgentId, coordinator: AgentId, report: bytes) -> None:
        self._id = agent_id
        self._coordinator = coordinator
        self._report = report

    async def on_start(self, ctx: AgentContext) -> None:
        """Send the report to the coordinator.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.send(self._coordinator, _REPORT_PREFIX.encode() + self._report)


class FusionCoordinatorAgent(StateMachineAgent):
    """Fuse reports that match the calculator node's declared basis.

    Example::

        coordinator = FusionCoordinatorAgent(AgentId("coordinator-0"), ["add"], 1)
    """

    def __init__(
        self,
        agent_id: AgentId,
        required_basis: list[str],
        threshold: int,
    ) -> None:
        self._id = agent_id
        self._required_basis = set(required_basis)
        self._threshold = threshold
        self._accepted_basis: set[str] = set()
        self._accepted_reports: set[tuple[str, str]] = set()
        self._ignored = 0
        self._shipped = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule deterministic decision checks.

        Example::

            await coordinator.on_start(ctx)
        """
        for tick in range(1, 12):
            await ctx.schedule(float(tick), _CHECK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle reports and decision ticks.

        Example::

            await coordinator.on_message(ctx, AgentId("impl-add"), b"fusion_report|{}")
        """
        if payload == _CHECK:
            await self._maybe_ship(ctx)
            return

        text = payload.decode("utf-8", errors="replace")
        if not text.startswith(_REPORT_PREFIX):
            return
        body = text[len(_REPORT_PREFIX) :]
        try:
            report_obj = json.loads(body)
        except ValueError:
            await self._ignore(ctx, sender, "not-json")
            return
        if not isinstance(report_obj, dict):
            await self._ignore(ctx, sender, "not-object")
            return
        report = cast("dict[str, object]", report_obj)
        node = report.get("node")
        basis = report.get("basis")
        if node != "calculator" or not isinstance(basis, str):
            await self._ignore(ctx, sender, "no-overlap")
            return
        if basis not in self._required_basis:
            await self._ignore(ctx, sender, "outside-basis")
            return

        report_key = (str(sender), basis)
        if report_key in self._accepted_reports:
            await self._ignore(ctx, sender, "duplicate")
            return
        self._accepted_reports.add(report_key)
        self._accepted_basis.add(basis)
        mem = ctx.plugins["memory"]
        await mem.write("calculator:ready_score", b'{"op":"inc","amount":1}')
        await ctx.broadcast(f"{_ACCEPT_PREFIX}calculator|{basis}|{sender}".encode())
        await ctx.broadcast(b"pn_delta|calculator:ready_score|1")

    async def on_stop(self, ctx: AgentContext) -> None:
        """Broadcast final fused counter state for validators.

        Example::

            await coordinator.on_stop(ctx)
        """
        mem = ctx.plugins["memory"]
        state = mem.export("calculator:ready_score")
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)

    async def _ignore(self, ctx: AgentContext, sender: AgentId, reason: str) -> None:
        self._ignored += 1
        await ctx.broadcast(f"{_IGNORE_PREFIX}{sender}|{reason}".encode())

    async def _maybe_ship(self, ctx: AgentContext) -> None:
        if self._shipped:
            return
        mem = ctx.plugins["memory"]
        raw = await mem.read("calculator:ready_score")
        score = int(raw or b"0")
        if self._accepted_basis == self._required_basis and score >= self._threshold:
            self._shipped = True
            await ctx.broadcast(
                f"{_DECISION_PREFIX}calculator|ship|score={score}|ignored={self._ignored}".encode()
            )


def _report(node: str, basis: str, claim: str) -> bytes:
    return json.dumps(
        {"node": node, "basis": basis, "claim": claim},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def memory_basis_fusion_calculator_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create calculator reporters plus a copypasta saturation reporter.

    Example::

        agents = memory_basis_fusion_calculator_factory(config, plugins)
    """
    task_config = config.task.config
    required_basis = [
        str(item)
        for item in task_config.get(
            "required_basis",
            ["add", "subtract", "multiply", "divide"],
        )
    ]
    threshold = int(task_config.get("threshold", len(required_basis)))
    coordinator = AgentId("coordinator-0")
    copypasta = ("r/copypasta saturation " * 500).encode("utf-8")

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator: FusionCoordinatorAgent(coordinator, required_basis, threshold)
    }
    reports = [
        ("impl-add", _report("calculator", "add", "addition implemented")),
        ("impl-subtract", _report("calculator", "subtract", "subtraction implemented")),
        ("test-multiply", _report("calculator", "multiply", "multiplication tested")),
        ("test-divide", _report("calculator", "divide", "division tested")),
        ("off-basis", _report("calculator", "horoscope", "irrelevant basis")),
        ("copypasta", copypasta),
    ]
    for name, payload in reports:
        aid = AgentId(name)
        agents[aid] = FusionReporterAgent(aid, coordinator, payload)

    memory_cls = plugins["memory"]
    plugins["_agent_plugins"] = {coordinator: {"memory": memory_cls(str(coordinator))}}
    return agents
