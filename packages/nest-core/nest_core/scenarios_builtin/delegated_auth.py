# SPDX-License-Identifier: Apache-2.0
"""Delegated auth scenario — capability delegation chain with cascading revocation.

Topology:

* ``coordinator-0`` issues a root token with full scopes and delegates
  narrowing sub-capabilities to three ``intermediary-*`` agents.
* Each intermediary further delegates a subset to four ``leaf-*`` agents
  (12 leaves total, 16 agents in all).
* Mid-run, the coordinator revokes **one** intermediary's token; the
  downstream 4 leaves must fail verification — demonstrated by emitting
  ``auth:verify:FAIL`` events that the ``delegated_auth`` validators check.

Trace line protocol (carried in message bodies, ``:``-delimited):

* ``auth:issue:<agent>:<scopes>`` — root token issued
* ``auth:delegate:<parent_agent>:<child_agent>:<scopes>`` — delegation step
* ``auth:verify:OK:<agent>:<scopes>`` — successful verification
* ``auth:verify:FAIL:<agent>:<error>`` — failed verification (expected post-revoke)
* ``auth:revoke:<agent>`` — token revoked by coordinator

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

# Sentinel payloads for inter-agent signalling
_MSG_TOKEN = b"TOKEN:"
_MSG_REVOKE = b"REVOKE"
_MSG_VERIFY = b"VERIFY"


class CoordinatorAgent(StateMachineAgent):
    """Issues the root token, delegates to intermediaries, and revokes one.

    Example::

        agent = CoordinatorAgent(
            agent_id=AgentId("coordinator-0"),
            root_scopes=["read", "write", "exec", "admin"],
            intermediary_ids=[AgentId("intermediary-0"), ...],
            revoke_intermediary=1,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        root_scopes: list[str],
        intermediary_ids: list[AgentId],
        revoke_intermediary: int = 1,
        delegate_ttl: float = 1800.0,
    ) -> None:
        self._id = agent_id
        self._root_scopes = root_scopes
        self._intermediary_ids = intermediary_ids
        self._revoke_intermediary = revoke_intermediary
        self._delegate_ttl = delegate_ttl
        # token held per intermediary (set during on_start)
        self._child_tokens: dict[AgentId, Token] = {}
        self._revoked = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue root token and delegate to each intermediary.

        Example::

            await agent.on_start(ctx)
        """
        auth = ctx.plugins.get("auth")
        if auth is None or not hasattr(auth, "issue"):
            return

        root_token = await auth.issue(self._id, self._root_scopes)
        await ctx.broadcast(f"auth:issue:{self._id}:{','.join(sorted(self._root_scopes))}".encode())

        delegate_scopes = [s for s in self._root_scopes if s != "admin"]
        for interm_id in self._intermediary_ids:
            if hasattr(auth, "delegate"):
                child_token = await auth.delegate(
                    parent_token=root_token,
                    audience=interm_id,
                    scopes_subset=delegate_scopes,
                    ttl=self._delegate_ttl,
                )
                self._child_tokens[interm_id] = child_token
                await ctx.broadcast(
                    f"auth:delegate:{self._id}:{interm_id}:{','.join(sorted(delegate_scopes))}".encode()
                )
                # Send the token to the intermediary
                payload = _MSG_TOKEN + str(child_token).encode()
                await ctx.send(interm_id, payload)

        # Schedule revocation of one intermediary mid-run
        await ctx.schedule(500.0, _MSG_REVOKE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle scheduled revocation.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        if sender == ctx.agent_id and payload == _MSG_REVOKE and not self._revoked:
            self._revoked = True
            auth = ctx.plugins.get("auth")
            if auth is None:
                return
            # Revoke the designated intermediary's token
            interm_ids = list(self._child_tokens.keys())
            if self._revoke_intermediary < len(interm_ids):
                target = interm_ids[self._revoke_intermediary]
                token_to_revoke = self._child_tokens[target]
                await auth.revoke(token_to_revoke)
                await ctx.broadcast(f"auth:revoke:{target}".encode())


class IntermediaryAgent(StateMachineAgent):
    """Receives a delegated token and further sub-delegates to leaves.

    Example::

        agent = IntermediaryAgent(
            agent_id=AgentId("intermediary-0"),
            leaf_ids=[AgentId("leaf-0"), AgentId("leaf-1"), ...],
            leaf_scopes=["read", "exec"],
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        leaf_ids: list[AgentId],
        leaf_scopes: list[str],
        leaf_ttl: float = 900.0,
    ) -> None:
        self._id = agent_id
        self._leaf_ids = leaf_ids
        self._leaf_scopes = leaf_scopes
        self._leaf_ttl = leaf_ttl
        self._my_token: Token | None = None

    async def on_start(self, ctx: AgentContext) -> None:
        """Nothing to do until coordinator sends the token."""

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Receive token from coordinator; sub-delegate to leaves.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        if payload.startswith(_MSG_TOKEN):
            token_str = payload[len(_MSG_TOKEN) :].decode()
            self._my_token = Token(token_str)
            await self._delegate_to_leaves(ctx)

        elif payload == _MSG_VERIFY:
            await self._verify_own_token(ctx)

    async def _delegate_to_leaves(self, ctx: AgentContext) -> None:
        auth = ctx.plugins.get("auth")
        if auth is None or self._my_token is None:
            return
        for leaf_id in self._leaf_ids:
            if hasattr(auth, "delegate"):
                try:
                    leaf_token = await auth.delegate(
                        parent_token=self._my_token,
                        audience=leaf_id,
                        scopes_subset=self._leaf_scopes,
                        ttl=self._leaf_ttl,
                    )
                    await ctx.broadcast(
                        f"auth:delegate:{self._id}:{leaf_id}:{','.join(sorted(self._leaf_scopes))}".encode()
                    )
                    payload = _MSG_TOKEN + str(leaf_token).encode()
                    await ctx.send(leaf_id, payload)
                except Exception as exc:
                    await ctx.broadcast(f"auth:delegate:FAIL:{self._id}:{leaf_id}:{exc!r}".encode())

    async def _verify_own_token(self, ctx: AgentContext) -> None:
        auth = ctx.plugins.get("auth")
        if auth is None or self._my_token is None:
            return
        try:
            result = await auth.verify(self._my_token, presenter=self._id)
            await ctx.broadcast(f"auth:verify:OK:{self._id}:{','.join(sorted(result.scopes))}".encode())
        except Exception as exc:
            await ctx.broadcast(f"auth:verify:FAIL:{self._id}:{type(exc).__name__}".encode())


class LeafAgent(StateMachineAgent):
    """Receives a leaf token and periodically verifies it.

    Example::

        agent = LeafAgent(agent_id=AgentId("leaf-0"))
    """

    def __init__(self, agent_id: AgentId, verify_interval: float = 200.0) -> None:
        self._id = agent_id
        self._verify_interval = verify_interval
        self._my_token: Token | None = None
        self._did_audience_confusion = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Arm periodic verification ticks."""
        await ctx.schedule(self._verify_interval, _MSG_VERIFY)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Receive token from intermediary; verify on each tick.

        Example::

            await agent.on_message(ctx, sender, payload)
        """
        if payload.startswith(_MSG_TOKEN):
            token_str = payload[len(_MSG_TOKEN) :].decode()
            self._my_token = Token(token_str)
            # Immediately verify upon receipt
            await self._do_verify(ctx)

        elif sender == ctx.agent_id and payload == _MSG_VERIFY:
            await self._do_verify(ctx)
            await ctx.schedule(self._verify_interval, _MSG_VERIFY)

    async def _do_verify(self, ctx: AgentContext) -> None:
        auth = ctx.plugins.get("auth")
        if auth is None or self._my_token is None:
            return
        try:
            if not self._did_audience_confusion:
                self._did_audience_confusion = True
                try:
                    await auth.verify(self._my_token, presenter=AgentId("wrong-audience"))
                except Exception as exc:
                    await ctx.broadcast(f"auth:verify:FAIL:{self._id}:{type(exc).__name__}".encode())

            result = await auth.verify(self._my_token, presenter=self._id)
            await ctx.broadcast(f"auth:verify:OK:{self._id}:{','.join(sorted(result.scopes))}".encode())
        except Exception as exc:
            await ctx.broadcast(f"auth:verify:FAIL:{self._id}:{type(exc).__name__}".encode())


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def delegated_auth_factory(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> dict[AgentId, Any]:
    """Build the 16-agent delegation-tree fleet.

    Role layout from the YAML:
    * 1 coordinator
    * 3 intermediaries (each gets 4 leaves)
    * 12 leaves

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    task_cfg = config.task.config or {}
    revoke_intermediary = int(task_cfg.get("revoke_intermediary", 1))

    auth_cls = plugins.get("auth")
    if auth_cls is not None and isinstance(auth_cls, type):
        plugins["auth"] = auth_cls()

    # Collect IDs by role
    coord_ids: list[AgentId] = []
    interm_ids: list[AgentId] = []
    leaf_ids: list[AgentId] = []

    for role in config.agents.roles:
        for i in range(role.count):
            aid = AgentId(f"{role.name}-{i}")
            if role.name == "coordinator":
                coord_ids.append(aid)
            elif role.name == "intermediary":
                interm_ids.append(aid)
            elif role.name == "leaf":
                leaf_ids.append(aid)

    # Distribute leaves evenly across intermediaries
    n_interm = len(interm_ids)
    leaves_per_interm: dict[AgentId, list[AgentId]] = {iid: [] for iid in interm_ids}
    for idx, leaf_id in enumerate(leaf_ids):
        bucket = interm_ids[idx % n_interm] if n_interm else None
        if bucket:
            leaves_per_interm[bucket].append(leaf_id)

    root_scopes = ["read", "write", "exec", "admin"]
    leaf_scopes = ["read", "exec"]

    agents: dict[AgentId, Any] = {}

    # Coordinator
    for coord_id in coord_ids:
        agents[coord_id] = CoordinatorAgent(
            agent_id=coord_id,
            root_scopes=root_scopes,
            intermediary_ids=interm_ids,
            revoke_intermediary=revoke_intermediary,
        )

    # Intermediaries
    for iid in interm_ids:
        agents[iid] = IntermediaryAgent(
            agent_id=iid,
            leaf_ids=leaves_per_interm[iid],
            leaf_scopes=leaf_scopes,
        )

    # Leaves
    for lid in leaf_ids:
        agents[lid] = LeafAgent(agent_id=lid)

    return agents
