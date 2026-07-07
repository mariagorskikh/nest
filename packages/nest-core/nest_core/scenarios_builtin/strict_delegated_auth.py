# SPDX-License-Identifier: Apache-2.0
"""Strict delegated-auth scenario -- coordinator, intermediaries, and leaves.

The factory builds the exact problem-04 topology: one coordinator mints
strict child capabilities for three intermediaries, each intermediary mints
four narrower leaf capabilities, and leaves verify their audience-bound
tokens before acknowledging the coordinator.  The coordinator also runs the
three adversarial checks from the problem statement so the trace proves the
scenario exercised the auth plugin instead of merely booting.

Example::

    agents = strict_delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

_ROOT_SCOPES = [
    "orders:read",
    "orders:write",
    "orders:approve",
    "orders:audit",
    "orders:export",
]
_INTERMEDIARY_SCOPES = [
    ["orders:read", "orders:write", "orders:audit"],
    ["orders:read", "orders:approve", "orders:audit"],
    ["orders:read", "orders:export", "orders:audit"],
]
_LEAF_SCOPES = ["orders:read"]


class _DelegationState:
    """Shared in-memory grant table used by the deterministic scenario.

    Example::

        state = _DelegationState()
        state.tokens[AgentId("worker")] = token
    """

    def __init__(self) -> None:
        self.tokens: dict[AgentId, Token] = {}


class CoordinatorAgent(StateMachineAgent):
    """Root capability holder that delegates to intermediaries.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator"), intermediaries, leaves, state)
    """

    def __init__(
        self,
        agent_id: AgentId,
        intermediaries: list[AgentId],
        leaves_by_intermediary: dict[AgentId, list[AgentId]],
        state: _DelegationState,
    ) -> None:
        self._id = agent_id
        self._intermediaries = intermediaries
        self._leaves_by_intermediary = leaves_by_intermediary
        self._state = state

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue a root token, delegate intermediary grants, and run attacks.

        Example::

            await agent.on_start(ctx)
        """
        auth = ctx.plugins["auth"]
        root = await auth.issue(self._id, list(_ROOT_SCOPES))
        self._state.tokens[self._id] = root

        await self._run_attack_suite(ctx, auth)

        for idx, intermediary in enumerate(self._intermediaries):
            grant = await auth.delegate(
                root,
                intermediary,
                list(_INTERMEDIARY_SCOPES[idx]),
                ttl=300.0,
            )
            self._state.tokens[intermediary] = grant
            leaves = ",".join(str(leaf) for leaf in self._leaves_by_intermediary[intermediary])
            await ctx.send(
                intermediary,
                f"grant:intermediary:{intermediary}:leaves={leaves}".encode(),
            )

    async def _run_attack_suite(self, ctx: AgentContext, auth: Any) -> None:
        """Emit trace-visible attack-check outcomes.

        Example::

            await agent._run_attack_suite(ctx, auth)
        """
        parent = await auth.issue(AgentId("attack-coordinator"), ["read", "write"])
        try:
            await auth.delegate(parent, AgentId("attacker"), ["read", "admin"], ttl=60.0)
        except Exception:
            await ctx.send(self._intermediaries[0], b"attack:scope_escalation:blocked")
        else:
            await ctx.send(self._intermediaries[0], b"attack:scope_escalation:allowed")

        stale_parent = await auth.issue(AgentId("stale-coordinator"), ["docs:read", "docs:write"])
        stale_child = await auth.delegate(
            stale_parent, AgentId("stale-worker"), ["docs:read"], 60.0
        )
        await auth.revoke(stale_parent)
        try:
            await auth.verify(stale_child)
        except Exception:
            await ctx.send(self._intermediaries[1], b"attack:stale_parent:blocked")
        else:
            await ctx.send(self._intermediaries[1], b"attack:stale_parent:allowed")

        audience_parent = await auth.issue(
            AgentId("aud-coordinator"), ["files:read", "files:write"]
        )
        audience_child = await auth.delegate(
            audience_parent,
            AgentId("aud-worker"),
            ["files:read"],
            60.0,
        )
        try:
            await auth.verify_for(audience_child, AgentId("wrong-worker"))
        except Exception:
            await ctx.send(self._intermediaries[2], b"attack:audience_confusion:blocked")
        else:
            await ctx.send(self._intermediaries[2], b"attack:audience_confusion:allowed")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Receive leaf acknowledgements for trace completeness.

        Example::

            await agent.on_message(ctx, AgentId("leaf-0"), b"ack")
        """
        if payload.startswith(b"leaf:verified:"):
            await ctx.send(sender, b"coordinator:ack")


class IntermediaryAgent(StateMachineAgent):
    """Intermediate capability holder that delegates to four leaves.

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), leaves, state)
    """

    def __init__(self, agent_id: AgentId, leaves: list[AgentId], state: _DelegationState) -> None:
        self._id = agent_id
        self._leaves = leaves
        self._state = state

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Delegate leaf grants after the coordinator grant arrives.

        Example::

            await agent.on_message(ctx, AgentId("coordinator"), b"grant")
        """
        if not payload.startswith(b"grant:intermediary:"):
            return
        auth = ctx.plugins["auth"]
        parent = self._state.tokens[self._id]
        for leaf in self._leaves:
            grant = await auth.delegate(parent, leaf, list(_LEAF_SCOPES), ttl=120.0)
            self._state.tokens[leaf] = grant
            await ctx.send(leaf, f"grant:leaf:{leaf}:from={self._id}".encode())
        await ctx.send(
            sender, f"intermediary:delegated:{self._id}:count={len(self._leaves)}".encode()
        )


class LeafAgent(StateMachineAgent):
    """Leaf agent that verifies its audience-bound child capability.

    Example::

        agent = LeafAgent(AgentId("leaf-0"), AgentId("coordinator"), state)
    """

    def __init__(self, agent_id: AgentId, coordinator: AgentId, state: _DelegationState) -> None:
        self._id = agent_id
        self._coordinator = coordinator
        self._state = state

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify the received grant and acknowledge the coordinator.

        Example::

            await agent.on_message(ctx, AgentId("intermediary-0"), b"grant")
        """
        if not payload.startswith(b"grant:leaf:"):
            return
        auth = ctx.plugins["auth"]
        token = self._state.tokens[self._id]
        ctx_auth = await auth.verify_for(token, self._id)
        scopes = ",".join(ctx_auth.scopes)
        await ctx.send(
            self._coordinator,
            f"leaf:verified:{self._id}:via={sender}:scopes={scopes}".encode(),
        )


def strict_delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the problem-04 delegated-auth scenario agents.

    Example::

        agents = strict_delegated_auth_factory(config, plugins)
    """
    auth_cls = plugins.get("auth")
    if isinstance(auth_cls, type):
        try:
            plugins["auth"] = auth_cls(clock=0.0)
        except TypeError:
            plugins["auth"] = auth_cls()

    coordinator = AgentId("coordinator")
    intermediary_count, leaf_count = _role_counts(config)
    intermediaries = [AgentId(f"intermediary-{idx}") for idx in range(intermediary_count)]
    leaves = [AgentId(f"leaf-{idx}") for idx in range(leaf_count)]
    leaves_by_intermediary = {
        intermediary: leaves[idx * 4 : (idx + 1) * 4]
        for idx, intermediary in enumerate(intermediaries)
    }
    state = _DelegationState()

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator: CoordinatorAgent(coordinator, intermediaries, leaves_by_intermediary, state),
    }
    for intermediary in intermediaries:
        agents[intermediary] = IntermediaryAgent(
            intermediary,
            leaves_by_intermediary[intermediary],
            state,
        )
    for leaf in leaves:
        agents[leaf] = LeafAgent(leaf, coordinator, state)
    return agents


def _role_counts(config: ScenarioConfig) -> tuple[int, int]:
    counts = {role.name: role.count for role in config.agents.roles}
    intermediary_count = counts.get("intermediary", 3)
    leaf_count = counts.get("leaf", 12)
    if counts.get("coordinator", 1) != 1:
        msg = "strict_delegated_auth scenario requires exactly one coordinator"
        raise ValueError(msg)
    if intermediary_count != 3 or leaf_count != 12:
        msg = "strict_delegated_auth scenario requires 3 intermediaries and 12 leaves"
        raise ValueError(msg)
    return intermediary_count, leaf_count
