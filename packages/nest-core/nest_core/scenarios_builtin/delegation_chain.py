# SPDX-License-Identifier: Apache-2.0
"""Delegation chain scenario — testing auth capabilities.

Tests 3-hop delegation, cascading revocation, scope bounds, and audience checking.
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


class CoordinatorAgent(StateMachineAgent):
    def __init__(self, agent_id: AgentId, num_intermediaries: int) -> None:
        self._id = agent_id
        self._num_intermediaries = num_intermediaries
        self._root_token = None
        self._round = 0

    async def on_start(self, ctx: AgentContext) -> None:
        auth = ctx.plugins.get("auth")
        if not auth:
            return

        # Issue root token
        self._root_token = await auth.issue(self._id, ["read", "write", "delegate"])

        # Delegate to intermediaries
        for i in range(self._num_intermediaries):
            intermediary_id = AgentId(f"intermediary-{i}")
            child_token = await auth.delegate(
                self._root_token, intermediary_id, ["read", "write"], ttl=3600.0
            )
            await ctx.send(intermediary_id, f"token:{child_token}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        self._round += 1

        # Revoke the root token midway to trigger cascading revocation
        if self._round == 15 and self._root_token:
            auth = ctx.plugins.get("auth")
            if auth:
                await auth.revoke(self._root_token)
                await ctx.send(self._id, b"root_revoked")

        if msg.startswith("verify:"):
            token_str = msg.split(":", 1)[1]
            from nest_core.types import Token

            auth = ctx.plugins.get("auth")
            if auth:
                from nest_plugins_reference.auth.delegatable import (
                    AudienceError,
                    RevokedAncestorError,
                )

                try:
                    await auth.verify(Token(token_str), presenter=sender)
                    await ctx.send(sender, b"verified")
                except AudienceError:
                    await ctx.send(self._id, b"adversarial:audience_confusion_rejected")
                except RevokedAncestorError:
                    await ctx.send(self._id, b"adversarial:stale_parent_rejected")
                except Exception:
                    pass


class IntermediaryAgent(StateMachineAgent):
    def __init__(self, agent_id: AgentId, leaf_start: int, leaf_end: int) -> None:
        self._id = agent_id
        self._leaf_start = leaf_start
        self._leaf_end = leaf_end
        self._my_token = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("token:"):
            token_str = msg.split(":", 1)[1]
            from nest_core.types import Token

            self._my_token = Token(token_str)

            auth = ctx.plugins.get("auth")
            if not auth:
                return

            # Test 1: Scope Escalation (Adversarial)
            if self._id == AgentId("intermediary-0"):
                from nest_plugins_reference.auth.delegatable import ScopeEscalationError

                try:
                    await auth.delegate(self._my_token, AgentId("leaf-0"), ["admin"], ttl=60.0)
                except ScopeEscalationError:
                    await ctx.send(self._id, b"adversarial:scope_escalation_rejected")
                except Exception:
                    pass

            # Delegate valid tokens to leaves
            for i in range(self._leaf_start, self._leaf_end):
                leaf_id = AgentId(f"leaf-{i}")
                try:
                    leaf_token = await auth.delegate(self._my_token, leaf_id, ["read"], ttl=3600.0)
                    await ctx.send(leaf_id, f"token:{leaf_token}".encode())
                except Exception:
                    pass


class LeafAgent(StateMachineAgent):
    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._my_token = None
        self._round = 0

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")

        if msg.startswith("token:"):
            self._my_token = msg.split(":", 1)[1]
            # Verify immediately
            await ctx.send(AgentId("coordinator-0"), f"verify:{self._my_token}".encode())

            # Test 2: Audience Confusion (Adversarial)
            # Give our token to someone else to present (send multiple times to beat packet drop)
            if self._id == AgentId("leaf-0"):
                for _ in range(5):
                    await ctx.send(AgentId("leaf-1"), f"steal:{self._my_token}".encode())

        elif msg.startswith("steal:"):
            stolen_token = msg.split(":", 1)[1]
            # Try to present the stolen token as ourselves (which should trigger AudienceError)
            await ctx.send(AgentId("coordinator-0"), f"verify:{stolen_token}".encode())

        elif msg == "verified":
            self._round += 1
            # Periodically re-verify to eventually hit the RevokedAncestorError
            if self._my_token:
                await ctx.send(AgentId("coordinator-0"), f"verify:{self._my_token}".encode())


def delegation_chain_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    agents: dict[AgentId, StateMachineAgent] = {}

    auth_cls = plugins.get("auth")
    if auth_cls and isinstance(auth_cls, type):
        plugins["auth"] = auth_cls(secret=b"delegation-chain-secret")

    # Roles: 1 coordinator, 3 intermediaries, 12 leaves
    coord_id = AgentId("coordinator-0")
    agents[coord_id] = CoordinatorAgent(coord_id, num_intermediaries=3)

    for i in range(3):
        int_id = AgentId(f"intermediary-{i}")
        leaf_start = i * 4
        leaf_end = (i + 1) * 4
        agents[int_id] = IntermediaryAgent(int_id, leaf_start, leaf_end)

    for i in range(12):
        leaf_id = AgentId(f"leaf-{i}")
        agents[leaf_id] = LeafAgent(leaf_id)

    return agents
