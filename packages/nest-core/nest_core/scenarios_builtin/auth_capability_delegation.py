# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability token scenario — coordinator delegates to intermediaries, who
delegate further to leaf agents, and cascading revocation invalidates the whole subtree.

The scenario builds a three-tier delegation tree:

     coordinator  (depth 0, max_depth=2)
       ┌──┼──┐
     int-0 int-1 int-2   (depth 1)
      ─┬─  ─┬─  ─┬─
     l0 l1 l2 l3 l4 ...   (depth 2, 12 total leaves)

Honest agents propagate capability tokens down the tree. At the end the coordinator's
root token is revoked and every leaf agent must be unable to verify its token.

Example::

    agents = auth_capability_delegation_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

NUM_COORDINATORS = 1
NUM_INTERMEDIARIES = 3
NUM_LEAVES = 12

ROOT_SCOPES = frozenset({"read", "write", "admin"})
INT_SCOPES = frozenset({"read", "write"})
LEAF_SCOPES = frozenset({"read"})


# ── Agent classes ───────────────────────────────────────────────────────────


class CoordinatorAgent(StateMachineAgent):
    """Root of the delegation tree. Issues root tokens and delegates to intermediaries."""

    def __init__(self, agent_id: AgentId, num_intermediaries: int) -> None:
        self._id = agent_id
        self._num_intermediaries = num_intermediaries
        self._phase = 0

    async def on_start(self, ctx: AgentContext) -> None:
        auth = ctx.plugins["auth"]
        root_token_str = auth.issue_root(
            subject=str(self._id),
            audience="nandatown",
            scopes=ROOT_SCOPES,
            ttl_seconds=3600.0,
            max_depth=2,
        )

        # Delegate to each intermediary with restricted scopes
        for i in range(self._num_intermediaries):
            child_id = AgentId(f"int-{i}")
            child_token = auth.delegate(
                root_token_str,
                subject=str(child_id),
                audience="nandatown",
                scopes=INT_SCOPES,
                ttl_seconds=300.0,
            )
            await ctx.send(child_id, f"token:{child_token}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        pass


class IntermediaryAgent(StateMachineAgent):
    """Mid-tier agent that receives a capability token from the coordinator and
    delegates it further to its leaf agents."""

    def __init__(self, agent_id: AgentId, num_leaves_per: int, start_index: int) -> None:
        self._id = agent_id
        self._num_leaves_per = num_leaves_per
        self._start_index = start_index
        self._parent_token: str | None = None
        self._phase = 0

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode()
        if msg.startswith("token:") and self._parent_token is None:
            auth = ctx.plugins["auth"]
            self._parent_token = msg[6:]

            # Verify first
            _ = auth.verify_capability(self._parent_token)

            # Delegate to leaf agents
            for i in range(self._num_leaves_per):
                leaf_idx = self._start_index + i
                child_id = AgentId(f"leaf-{leaf_idx}")
                try:
                    child_token = auth.delegate(
                        self._parent_token,
                        subject=str(child_id),
                        audience="nandatown",
                        scopes=LEAF_SCOPES,
                        ttl_seconds=60.0,
                    )
                    await ctx.send(child_id, f"token:{child_token}".encode())
                except Exception:
                    pass

            await ctx.send(sender, b"ack:1")


class LeafAgent(StateMachineAgent):
    """Leaf agent that receives a capability token from its intermediary and
    reports its verification result."""

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._my_token: str | None = None
        self._verified = False

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode()
        if msg.startswith("token:") and self._my_token is None:
            auth = ctx.plugins["auth"]
            self._my_token = msg[6:]
            try:
                _ = auth.verify_capability(self._my_token)
                self._verified = True

            except Exception:
                self._verified = False
            await ctx.send(sender, b"ack:2")

    @property
    def verified(self) -> bool:
        return self._verified


# ── Factory ─────────────────────────────────────────────────────────────────


def auth_capability_delegation_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the delegation tree agent set.

    Instantiates a single shared ``DelegatableAuth`` so all agents operate
    on the same token store — required for cascading revocation.

    Returns a dict of ``{AgentId: agent}`` for 1 coordinator, 3 intermediaries,
    and 12 leaf agents.

    Example::

        agents = auth_capability_delegation_factory(config, plugins)
    """
    coordinator = CoordinatorAgent(AgentId("coordinator-0"), NUM_INTERMEDIARIES)

    agents: dict[AgentId, StateMachineAgent] = {AgentId("coordinator-0"): coordinator}

    for i in range(NUM_INTERMEDIARIES):
        aid = AgentId(f"int-{i}")
        leaves_per = NUM_LEAVES // NUM_INTERMEDIARIES  # 4 each
        start_idx = i * leaves_per
        agents[aid] = IntermediaryAgent(aid, leaves_per, start_idx)

    for i in range(NUM_LEAVES):
        aid = AgentId(f"leaf-{i}")
        agents[aid] = LeafAgent(aid)

    # Instantiate a shared auth instance so all agents operate on the same
    # token / revocation store — matches the escrow_marketplace pattern.
    auth_cls = plugins["auth"]
    shared_auth = auth_cls()
    agent_plugins: dict[AgentId, dict[str, Any]] = {}
    for aid in agents:
        agent_plugins[aid] = {"auth": shared_auth}
    plugins["_agent_plugins"] = agent_plugins

    return agents
