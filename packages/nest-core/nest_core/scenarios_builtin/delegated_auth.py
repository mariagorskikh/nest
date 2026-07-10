# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario — HMAC capability tokens flow through a trust hierarchy.

A coordinator issues a root token and delegates scoped child tokens to three
intermediaries.  Each intermediary re-delegates narrower tokens to its four
leaf agents.  Leaves verify their tokens and report success back to the
coordinator.  The scenario validates the delegation chain, scope narrowing,
and audience binding end-to-end.

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

_COORD = AgentId("coordinator-0")
_NUM_INTER = 3
_LEAVES_PER_INTER = 4

_INTER_IDS = [AgentId(f"inter-{i}") for i in range(_NUM_INTER)]
_LEAF_IDS = [AgentId(f"leaf-{i}-{j}") for i in range(_NUM_INTER) for j in range(_LEAVES_PER_INTER)]


class CoordinatorAgent(StateMachineAgent):
    """Issues a root capability token and delegates to every intermediary.

    On start the coordinator issues a root token with scopes
    ``["admin", "exec", "read", "write"]`` and forwards a scoped child token
    (``["exec", "read", "write"]``) to each intermediary.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._verified_count = 0

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue root token and delegate to intermediaries.

        Example::

            await agent.on_start(ctx)
        """
        auth = ctx.plugins.get("auth")
        if auth is None:
            return

        root: Token = await auth.issue(self._id, ["admin", "exec", "read", "write"], ttl=3600.0)
        for inter_id in _INTER_IDS:
            child: Token = await auth.delegate(
                root, inter_id, ["exec", "read", "write"], ttl=1800.0
            )
            await ctx.send(inter_id, child.encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Count verified confirmations from leaves.

        Example::

            await agent.on_message(ctx, sender, b"verified")
        """
        if payload == b"verified":
            self._verified_count += 1

    async def on_stop(self, ctx: AgentContext) -> None:
        """Log final verified count.

        Example::

            await agent.on_stop(ctx)
        """


class IntermediaryAgent(StateMachineAgent):
    """Receives a delegated token and re-delegates narrower tokens to leaves.

    The intermediary holds scopes ``["exec", "read", "write"]`` and delegates
    ``["read"]`` to each of its leaf agents.

    Example::

        agent = IntermediaryAgent(AgentId("inter-0"), leaf_ids=[...])
    """

    def __init__(self, agent_id: AgentId, leaf_ids: list[AgentId]) -> None:
        self._id = agent_id
        self._leaf_ids = leaf_ids
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On receipt of the coordinator's delegation, re-delegate to leaves.

        Example::

            await agent.on_message(ctx, sender, b"<token_bytes>")
        """
        if sender == _COORD and self._token is None:
            auth = ctx.plugins.get("auth")
            if auth is None:
                return

            self._token = Token(payload.decode())
            for leaf_id in self._leaf_ids:
                leaf_token: Token = await auth.delegate(
                    self._token, leaf_id, ["read"], ttl=600.0, caller=self._id
                )
                await ctx.send(leaf_id, leaf_token.encode())


class LeafAgent(StateMachineAgent):
    """Verifies its delegated capability token and confirms to the coordinator.

    The leaf expects a ``["read"]`` token issued to itself as audience.  It
    verifies with ``caller=self._id`` to exercise the audience-confusion guard.

    Example::

        agent = LeafAgent(AgentId("leaf-0-0"), inter_id=AgentId("inter-0"))
    """

    def __init__(self, agent_id: AgentId, inter_id: AgentId) -> None:
        self._id = agent_id
        self._inter_id = inter_id

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify the received token and report back to the coordinator.

        Example::

            await agent.on_message(ctx, sender, b"<token_bytes>")
        """
        if sender != self._inter_id:
            return

        auth = ctx.plugins.get("auth")
        if auth is None:
            return

        token = Token(payload.decode())
        try:
            await auth.verify(token, caller=self._id)
        except Exception:
            return

        await ctx.send(_COORD, b"verified")


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create a coordinator, 3 intermediaries, and 12 leaf agents.

    The agent topology forms a two-level delegation tree: coordinator →
    intermediaries → leaves.  Expects ``layers.auth: delegatable`` in the
    scenario YAML.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    # runner.py._resolve_plugins() returns classes, not instances — instantiate
    # auth here with a fixed clock (0.0) so token iat/exp are deterministic and
    # traces are byte-identical across runs with the same seed (Tier 1 requirement).
    auth_cls = plugins.get("auth")
    if auth_cls is not None and isinstance(auth_cls, type):
        plugins["auth"] = auth_cls(clock=0.0)

    agents: dict[AgentId, StateMachineAgent] = {}

    agents[_COORD] = CoordinatorAgent(_COORD)

    for i, inter_id in enumerate(_INTER_IDS):
        leaves = [AgentId(f"leaf-{i}-{j}") for j in range(_LEAVES_PER_INTER)]
        agents[inter_id] = IntermediaryAgent(inter_id, leaf_ids=leaves)

    for leaf_id in _LEAF_IDS:
        inter_idx = int(str(leaf_id).split("-")[1])
        agents[leaf_id] = LeafAgent(leaf_id, inter_id=_INTER_IDS[inter_idx])

    return agents
