# SPDX-License-Identifier: Apache-2.0
"""Basis-fusion memory scenario -- act only on fusable calculator evidence.

This scenario exercises a more applied memory rule than "store every byte":
local reports are fused into a calculator project node only when they restrict
onto an existing basis dimension. A public-domain context-saturation payload
has no ``node`` and no valid ``basis`` field, so it cannot glue to the
calculator node and cannot change the decision.

The basis gate itself lives in the memory layer: the coordinator's memory is a
``basis_gated`` plugin (``BasisGatedMemory``) wrapping a ``pn_counter``. The
coordinator forwards each raw report to ``memory.fuse`` and merely traces the
accept/ignore decision the memory returns; the memory is what validates
fusability and writes the signed delta into the underlying counter. It ships the
calculator only after all required basis dimensions have fused.

Example::

    agents = memory_basis_fusion_calculator_factory(config, plugins)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

if TYPE_CHECKING:
    from nest_plugins_reference.memory.basis_gated_memory import BasisGatedMemory

_CHECK = b"check"
_REPORT_PREFIX = "fusion_report|"
_ACCEPT_PREFIX = "fusion_accept|"
_IGNORE_PREFIX = "fusion_ignore|"
_BASIS_DECL_PREFIX = "basis_decl|"
_DELTA_PREFIX = "pn_delta|"
_DECISION_PREFIX = "decision|"
_FINAL_PREFIX = "final:"
_FIXTURE_DIR = Path(__file__).with_name("fixtures")
_DEFAULT_SATURATION_FIXTURE = "context_saturation_payload.txt"


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
        self._required_basis = frozenset(required_basis)
        self._threshold = threshold
        self._shipped = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule deterministic decision checks.

        Example::

            await coordinator.on_start(ctx)
        """
        declared = "|".join(sorted(self._required_basis))
        await ctx.broadcast(
            f"{_BASIS_DECL_PREFIX}calculator|{declared}|threshold={self._threshold}".encode()
        )
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

        prefix = _REPORT_PREFIX.encode()
        if not payload.startswith(prefix):
            return
        body = payload[len(prefix) :]
        mem = cast("BasisGatedMemory", ctx.plugins["memory"])
        outcome = await mem.fuse("calculator:ready_score", body)
        if outcome.accepted:
            await ctx.broadcast(f"{_ACCEPT_PREFIX}calculator|{outcome.basis}|{sender}".encode())
            await ctx.broadcast(b"pn_delta|calculator:ready_score|1")
        else:
            await ctx.broadcast(f"{_IGNORE_PREFIX}{sender}|{outcome.reason}".encode())

    async def on_stop(self, ctx: AgentContext) -> None:
        """Broadcast final fused counter state for validators.

        Example::

            await coordinator.on_stop(ctx)
        """
        mem = ctx.plugins["memory"]
        state = mem.export("calculator:ready_score")
        if state is not None:
            await ctx.broadcast(_FINAL_PREFIX.encode() + state)

    async def _maybe_ship(self, ctx: AgentContext) -> None:
        if self._shipped:
            return
        mem = cast("BasisGatedMemory", ctx.plugins["memory"])
        raw = await mem.read("calculator:ready_score")
        score = int(raw or b"0")
        if mem.fused_basis("calculator") == self._required_basis and score >= self._threshold:
            self._shipped = True
            await ctx.broadcast(
                f"{_DECISION_PREFIX}calculator|ship|score={score}|ignored={mem.ignored}".encode()
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
    """Create calculator reporters plus a context-saturation reporter.

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
    saturation_fixture = str(task_config.get("saturation_fixture", _DEFAULT_SATURATION_FIXTURE))
    coordinator = AgentId("coordinator-0")
    saturation_payload = (_FIXTURE_DIR / saturation_fixture).read_bytes()

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator: FusionCoordinatorAgent(coordinator, required_basis, threshold)
    }
    reports = [
        ("impl-add", _report("calculator", "add", "addition implemented")),
        ("impl-subtract", _report("calculator", "subtract", "subtraction implemented")),
        ("test-multiply", _report("calculator", "multiply", "multiplication tested")),
        ("test-divide", _report("calculator", "divide", "division tested")),
        ("off-basis", _report("calculator", "horoscope", "irrelevant basis")),
        ("context-saturation", saturation_payload),
    ]
    for name, payload in reports:
        aid = AgentId(name)
        agents[aid] = FusionReporterAgent(aid, coordinator, payload)

    from nest_plugins_reference.memory.basis_gated_memory import BasisGatedMemory

    memory_cls = plugins["memory"]
    gated = BasisGatedMemory(
        str(coordinator),
        bases={"calculator": set(required_basis)},
        inner=memory_cls(str(coordinator)),
    )
    plugins["_agent_plugins"] = {coordinator: {"memory": gated}}
    return agents
