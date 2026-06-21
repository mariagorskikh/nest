# SPDX-License-Identifier: Apache-2.0
"""Delegated capability tokens scenario factory.

Wires up 1 coordinator, 3 intermediaries, and 12 leaf agents.
Runs honest delegation and validation, scope escalation attacks,
stale parent cascading revocation attacks, and audience confusion attacks.

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token


class CoordinatorAgent(StateMachineAgent):
    """Coordinator agent that issues root tokens and verifies all requests."""

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._root_token: Token | None = None
        self._child_tokens: dict[AgentId, Token] = {}
        self._honest_replies_count = 0
        self._phase2_replies_count = 0

    async def _verify(self, auth: Any, token: Token, presenter: AgentId) -> None:
        if not hasattr(auth, "verify"):
            return
        import inspect

        sig = inspect.signature(auth.verify)
        if "presenter" in sig.parameters:
            await auth.verify(token, presenter=presenter)
        else:
            await auth.verify(token)

    async def on_start(self, ctx: AgentContext) -> None:
        auth = ctx.plugins.get("auth")
        if auth is None:
            return

        # Hook dynamic virtual clock
        if hasattr(auth, "set_clock"):
            auth.set_clock(lambda: ctx.time)

        # 1. Issue root token
        self._root_token = await auth.issue(self._id, ["read", "write", "admin"])

        # 2. Delegate to 3 intermediaries
        intermediaries = [
            (AgentId("intermediary-0"), ["read", "write"]),
            (AgentId("intermediary-1"), ["read"]),
            (AgentId("intermediary-2"), ["write"]),
        ]

        for inter_id, scopes in intermediaries:
            # Fallback to issue if delegation is unsupported (e.g. JWT auth)
            if hasattr(auth, "delegate"):
                child_token = await auth.delegate(self._root_token, inter_id, scopes, ttl=100.0)
            else:
                child_token = await auth.issue(inter_id, scopes)

            self._child_tokens[inter_id] = child_token
            # Send child token to the intermediary
            await ctx.send(inter_id, f"delegate:{child_token}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        auth = ctx.plugins.get("auth")
        if auth is None:
            return

        if hasattr(auth, "set_clock"):
            auth.set_clock(lambda: ctx.time)

        msg = payload.decode("utf-8", errors="replace")

        if msg.startswith("honest_request:"):
            parts = msg.split(":", 2)
            action, token_str = parts[1], parts[2]
            token = Token(token_str)

            try:
                # verify using auth context
                await self._verify(auth, token, sender)
                await ctx.send(sender, b"success:honest")
                # Log success
                await ctx.send(
                    self._id,
                    f"verify_success:{sender}:coordinator-0:{action}:honest".encode(),
                )
            except Exception as e:
                reason = type(e).__name__
                await ctx.send(sender, f"error:honest:{reason}".encode())
                # Log failure
                await ctx.send(
                    self._id,
                    f"verify_failed:{sender}:{reason}:honest".encode(),
                )

            self._honest_replies_count += 1
            # Once all 12 leaves have sent their honest requests
            if self._honest_replies_count >= 12:
                await self._trigger_phase2(ctx, auth)

        elif msg.startswith("escalation_blocked"):
            # Intermediary reported that scope escalation delegation failed (which is correct)
            # Log verify failed for leaf-4 escalated
            await ctx.send(
                self._id,
                b"verify_failed:leaf-4:ValueError:escalated",
            )

        elif msg.startswith("escalated_request:"):
            parts = msg.split(":", 2)
            action, token_str = parts[1], parts[2]
            token = Token(token_str)

            try:
                await self._verify(auth, token, sender)
                # Log success (under jwt auth, this will succeed)
                await ctx.send(
                    self._id,
                    f"verify_success:{sender}:coordinator-0:{action}:escalated".encode(),
                )
            except Exception as e:
                reason = type(e).__name__
                # Log failure (under delegatable, if it somehow reached here)
                await ctx.send(
                    self._id,
                    f"verify_failed:{sender}:{reason}:escalated".encode(),
                )

        elif msg.startswith("stale_request:"):
            parts = msg.split(":", 2)
            action, token_str = parts[1], parts[2]
            token = Token(token_str)

            try:
                await self._verify(auth, token, sender)
                # Log success (under jwt auth, this will succeed)
                await ctx.send(
                    self._id,
                    f"verify_success:{sender}:coordinator-0:{action}:stale".encode(),
                )
            except Exception as e:
                reason = type(e).__name__
                # Log failure (under delegatable, this will fail with RevokedAncestorError)
                await ctx.send(
                    self._id,
                    f"verify_failed:{sender}:{reason}:stale".encode(),
                )

        elif msg.startswith("confused_request:"):
            parts = msg.split(":", 2)
            action, token_str = parts[1], parts[2]
            token = Token(token_str)

            try:
                await self._verify(auth, token, sender)
                # Log success (under jwt auth, this will succeed)
                await ctx.send(
                    self._id,
                    f"verify_success:{sender}:coordinator-0:{action}:confused".encode(),
                )
            except Exception as e:
                reason = type(e).__name__
                # Log failure (under delegatable, this will fail due to audience mismatch)
                await ctx.send(
                    self._id,
                    f"verify_failed:{sender}:{reason}:confused".encode(),
                )

    async def _trigger_phase2(self, ctx: AgentContext, auth: Any) -> None:
        # Revoke intermediary-0's token
        inter0_token = self._child_tokens.get(AgentId("intermediary-0"))
        if inter0_token is not None:
            await auth.revoke(inter0_token)

        # Trigger stale parent request on leaf-0
        await ctx.send(AgentId("leaf-0"), b"trigger_stale_parent")

        # Trigger audience confusion: ask leaf-1 to send its token to leaf-2
        await ctx.send(AgentId("leaf-1"), b"share_token_with_leaf_2")


class IntermediaryAgent(StateMachineAgent):
    """Intermediary agent that delegates grandchild tokens to leaf agents."""

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._child_token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        auth = ctx.plugins.get("auth")
        if auth is None:
            return

        if hasattr(auth, "set_clock"):
            auth.set_clock(lambda: ctx.time)

        msg = payload.decode("utf-8", errors="replace")

        if msg.startswith("delegate:"):
            token_str = msg.split(":", 1)[1]
            self._child_token = Token(token_str)

            # Determine leaf agents and scopes
            # intermediary-0 has leaf-0 to leaf-3
            # intermediary-1 has leaf-4 to leaf-7
            # intermediary-2 has leaf-8 to leaf-11
            idx = int(str(self._id).split("-")[1])
            leaves = [AgentId(f"leaf-{idx * 4 + i}") for i in range(4)]

            for leaf_id in leaves:
                # Assign subset scopes
                if idx == 0:
                    scopes = ["read"] if int(str(leaf_id).split("-")[1]) < 2 else ["write"]
                elif idx == 1:
                    scopes = ["read"]
                else:
                    scopes = ["write"]

                if hasattr(auth, "delegate"):
                    grandchild = await auth.delegate(self._child_token, leaf_id, scopes, ttl=50.0)
                else:
                    grandchild = await auth.issue(leaf_id, scopes)

                await ctx.send(leaf_id, f"leaf_delegate:{grandchild}:{','.join(scopes)}".encode())

            # Attempt scope escalation for leaf-4
            if idx == 1:
                escalated_scopes = ["read", "admin"]
                try:
                    if hasattr(auth, "delegate"):
                        # Should fail under delegatable
                        escalated = await auth.delegate(
                            self._child_token,
                            AgentId("leaf-4"),
                            escalated_scopes,
                            ttl=50.0,
                        )
                        # Trigger escalated request if it succeeds
                        await ctx.send(
                            AgentId("leaf-4"),
                            f"escalation_succeeded:{escalated}".encode(),
                        )
                    else:
                        # Simulate fallback under JWT
                        escalated = await auth.issue(AgentId("leaf-4"), escalated_scopes)
                        await ctx.send(
                            AgentId("leaf-4"),
                            f"escalation_succeeded:{escalated}".encode(),
                        )
                except Exception:
                    # Notify coordinator that escalation failed
                    await ctx.send(AgentId("coordinator-0"), b"escalation_blocked")


class LeafAgent(StateMachineAgent):
    """Leaf agent that stores grandchild tokens and performs actions."""

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._token: Token | None = None
        self._scopes: list[str] = []
        self._leaf_1_token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")

        if msg.startswith("leaf_delegate:"):
            parts = msg.split(":", 2)
            token_str, scopes_str = parts[1], parts[2]
            self._token = Token(token_str)
            self._scopes = scopes_str.split(",")

            # Send honest request to Coordinator
            action = self._scopes[0]
            await ctx.send(
                AgentId("coordinator-0"),
                f"honest_request:{action}:{self._token}".encode(),
            )

        elif msg.startswith("escalation_succeeded:"):
            escalated_token_str = msg.split(":", 1)[1]
            # Send escalated request
            await ctx.send(
                AgentId("coordinator-0"),
                f"escalated_request:admin:{escalated_token_str}".encode(),
            )

        elif msg == "share_token_with_leaf_2":
            # Send token to leaf-2 for audience confusion test
            await ctx.send(AgentId("leaf-2"), f"confused_token:{self._token}".encode())

        elif msg.startswith("confused_token:"):
            self._leaf_1_token = Token(msg.split(":", 1)[1])
            # Triggered in phase 2
            await ctx.send(self._id, b"trigger_audience_confusion")

        elif msg == "trigger_stale_parent":
            # Leaf-0 sends request under revoked parent
            if self._token is not None:
                await ctx.send(
                    AgentId("coordinator-0"),
                    f"stale_request:read:{self._token}".encode(),
                )

        elif msg == "trigger_audience_confusion":
            # Leaf-2 sends Leaf-1's token to Coordinator claiming to be Leaf-2
            if self._leaf_1_token is not None:
                await ctx.send(
                    AgentId("coordinator-0"),
                    f"confused_request:read:{self._leaf_1_token}".encode(),
                )


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the agent fleet for the delegated_auth scenario.

    Roles:
    - 1 coordinator (coordinator-0)
    - 3 intermediaries (intermediary-0, intermediary-1, intermediary-2)
    - 12 leaves (leaf-0 to leaf-11)

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    auth_cls = plugins.get("auth")
    if auth_cls is not None and isinstance(auth_cls, type):
        plugins["auth"] = auth_cls()

    agents: dict[AgentId, StateMachineAgent] = {}

    coordinator_id = AgentId("coordinator-0")
    agents[coordinator_id] = CoordinatorAgent(coordinator_id)

    for i in range(3):
        aid = AgentId(f"intermediary-{i}")
        agents[aid] = IntermediaryAgent(aid)

    for i in range(12):
        aid = AgentId(f"leaf-{i}")
        agents[aid] = LeafAgent(aid)

    return agents
