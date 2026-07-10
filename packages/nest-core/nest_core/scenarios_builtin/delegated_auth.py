# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario: a capability tree under adversarial use.

A coordinator self-issues a root capability and delegates attenuated
tokens to three intermediaries; each intermediary sub-delegates to four
leaf agents, which then present their tokens back to the coordinator to
access a resource.  Three adversarial behaviours are baked in:

1. one intermediary requests a *broader* scope for its first leaf
   (scope escalation);
2. the coordinator revokes one intermediary's grant mid-run, after
   which that subtree keeps presenting (stale ancestor);
3. one leaf shares its token with a sibling, which presents it
   (audience confusion).

Every delegate / revoke / verify emits a ``delegation_audit`` event so
the validators in
``nest_plugins_reference.validators.delegation_validators`` can replay
the trace.  Under ``auth: delegatable`` all three attacks are refused;
under ``auth: jwt`` they succeed and the validators fail.

The scenario is deliberately **seed-invariant**: agents draw nothing
from ``ctx.rng``, so the trace is byte-identical across seeds.  The
adversarial behaviours are structural (fixed roles, fixed ticks), not
sampled — determinism here is a property under test, not an accident.

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

ROOT_SCOPES: list[str] = ["read", "write", "pay"]
MID_SCOPES: list[str] = ["read", "write"]
LEAF_SCOPES: list[str] = ["read"]
ESCALATED_SCOPES: list[str] = ["read", "admin"]


def _json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _load(payload: bytes) -> dict[str, Any]:
    try:
        data: object = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return {}
    return cast("dict[str, Any]", data) if isinstance(data, dict) else {}


def _tid(token: Token) -> str:
    """Correlation id for a token, uniform across auth plugins.

    Example::

        tid = _tid(token)
    """
    return hashlib.sha256(str(token).encode()).hexdigest()[:16]


async def _audit(ctx: AgentContext, data: dict[str, Any]) -> None:
    event = {"type": "delegation_audit", "tick": int(ctx.time), **data}
    await ctx.send(ctx.agent_id, _json(event))


def _pin_clock(auth: Any, now: float) -> None:
    set_clock = getattr(auth, "set_clock", None)
    if callable(set_clock):
        set_clock(now)


async def _delegate(
    auth: Any,
    parent_token: Token,
    audience: AgentId,
    scopes: list[str],
    ttl: float,
) -> Token | None:
    """Delegate via the plugin if it can, else fall back to re-issuance.

    The fallback is deliberately the vulnerable pattern the default
    ``jwt`` plugin forces: a "child" is a brand-new root with whatever
    scopes were requested and no link to its parent.

    Example::

        child = await _delegate(auth, root, AgentId("leaf-0"), ["read"], 300.0)
    """
    delegate = getattr(auth, "delegate", None)
    if callable(delegate):
        try:
            pending = cast("Awaitable[Token]", delegate(parent_token, audience, scopes, ttl))
            return await pending
        except ValueError:
            return None
    return cast("Token", await auth.issue(audience, scopes))


async def _verify(auth: Any, token: Token, presenter: AgentId) -> bool:
    """Verify a presented token, audience-bound when the plugin can.

    Example::

        ok = await _verify(auth, token, AgentId("leaf-0"))
    """
    verify_presented = getattr(auth, "verify_presented", None)
    try:
        if callable(verify_presented):
            await cast("Awaitable[object]", verify_presented(token, presenter))
        else:
            await auth.verify(token)
    except ValueError:
        return False
    return True


class CoordinatorAgent(StateMachineAgent):
    """Root of the delegation tree; grants, revokes, and gates access.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"), auth=auth,
                                 intermediaries=[AgentId("intermediary-0")],
                                 revoke_tick=20, revoke_target=0)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auth: Any,
        intermediaries: list[AgentId],
        revoke_tick: int,
        revoke_target: int,
    ) -> None:
        self._id = agent_id
        self._auth = auth
        self._intermediaries = intermediaries
        self._revoke_tick = revoke_tick
        self._revoke_target = revoke_target
        self._grants: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(1.0, _json({"type": "bootstrap"}))
        await ctx.schedule(float(self._revoke_tick), _json({"type": "revoke"}))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        data = _load(payload)
        kind = data.get("type")
        _pin_clock(self._auth, ctx.time)
        if kind == "bootstrap" and sender == ctx.agent_id:
            root = cast("Token", await self._auth.issue(ctx.agent_id, ROOT_SCOPES))
            for mid in self._intermediaries:
                token = await _delegate(self._auth, root, mid, MID_SCOPES, ttl=600.0)
                granted = token is not None
                await _audit(
                    ctx,
                    {
                        "op": "delegate",
                        "delegator": str(ctx.agent_id),
                        "audience": str(mid),
                        "parent_scopes": ROOT_SCOPES,
                        "child_scopes": MID_SCOPES,
                        "granted": granted,
                    },
                )
                if token is None:
                    continue
                self._grants[mid] = token
                lineage = [_tid(root), _tid(token)]
                grant = {"type": "grant", "token": str(token), "lineage": lineage}
                await ctx.send(mid, _json(grant))
        elif kind == "revoke" and sender == ctx.agent_id:
            target = self._intermediaries[self._revoke_target]
            token = self._grants.get(target)
            if token is None:
                return
            await self._auth.revoke(token)
            await _audit(ctx, {"op": "revoke", "tid": _tid(token), "target": str(target)})
        elif kind == "access_request":
            token = Token(str(data.get("token", "")))
            lineage = [str(t) for t in cast("list[Any]", data.get("lineage", []))]
            audience = str(data.get("audience", ""))
            verified = await _verify(self._auth, token, sender)
            await _audit(
                ctx,
                {
                    "op": "verify",
                    "presenter": str(sender),
                    "audience": audience,
                    "chain_tids": [*lineage, _tid(token)],
                    "verified": verified,
                },
            )


class IntermediaryAgent(StateMachineAgent):
    """Sub-delegates its grant to a block of leaf agents.

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), auth=auth,
                                  leaves=[AgentId("leaf-0")], escalate=False)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auth: Any,
        leaves: list[AgentId],
        escalate: bool,
    ) -> None:
        self._id = agent_id
        self._auth = auth
        self._leaves = leaves
        self._escalate = escalate

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        data = _load(payload)
        if data.get("type") != "grant":
            return
        _pin_clock(self._auth, ctx.time)
        parent = Token(str(data.get("token", "")))
        lineage = [str(t) for t in cast("list[Any]", data.get("lineage", []))]
        for index, leaf in enumerate(self._leaves):
            scopes = ESCALATED_SCOPES if self._escalate and index == 0 else LEAF_SCOPES
            token = await _delegate(self._auth, parent, leaf, scopes, ttl=300.0)
            granted = token is not None
            await _audit(
                ctx,
                {
                    "op": "delegate",
                    "delegator": str(ctx.agent_id),
                    "audience": str(leaf),
                    "parent_scopes": MID_SCOPES,
                    "child_scopes": scopes,
                    "granted": granted,
                },
            )
            if token is None:
                continue
            await ctx.send(
                leaf,
                _json(
                    {
                        "type": "grant",
                        "token": str(token),
                        "lineage": [*lineage, _tid(token)],
                    }
                ),
            )


class LeafAgent(StateMachineAgent):
    """Presents its token to the coordinator; may leak it to a sibling.

    Example::

        agent = LeafAgent(AgentId("leaf-0"), coordinator=AgentId("coordinator-0"),
                          share_with=None, presents=4, interval=10)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        coordinator: AgentId,
        share_with: AgentId | None,
        presents: int,
        interval: int,
    ) -> None:
        self._id = agent_id
        self._coordinator = coordinator
        self._share_with = share_with
        self._presents = presents
        self._interval = interval
        self._token: str | None = None
        self._lineage: list[str] = []
        self._audience: str = str(agent_id)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        data = _load(payload)
        kind = data.get("type")
        if kind == "grant" or kind == "share":
            self._token = str(data.get("token", ""))
            self._lineage = [str(t) for t in cast("list[Any]", data.get("lineage", []))]
            if kind == "share":
                self._audience = str(data.get("audience", ""))
            if kind == "grant" and self._share_with is not None:
                await ctx.send(
                    self._share_with,
                    _json(
                        {
                            "type": "share",
                            "token": self._token,
                            "lineage": self._lineage,
                            "audience": str(ctx.agent_id),
                        }
                    ),
                )
            for step in range(self._presents):
                await ctx.schedule(2.0 + step * self._interval, _json({"type": "present"}))
        elif kind == "present" and sender == ctx.agent_id and self._token is not None:
            await ctx.send(
                self._coordinator,
                _json(
                    {
                        "type": "access_request",
                        "token": self._token,
                        "lineage": self._lineage,
                        "audience": self._audience,
                    }
                ),
            )


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the coordinator, intermediaries, and leaf agents.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    task_config = config.task.config
    mid_count = 3
    leaf_count = 12
    for role in config.agents.roles:
        if role.name == "intermediary":
            mid_count = role.count
        elif role.name == "leaf":
            leaf_count = role.count
    revoke_tick = int(cast("int", task_config.get("revoke_tick", 20)))
    presents = int(cast("int", task_config.get("presents", 4)))
    interval = int(cast("int", task_config.get("present_interval", 10)))

    auth_cls = cast("Any", plugins.get("auth"))
    auth: Any = auth_cls(secret=b"delegated-auth-scenario", clock=0.0)

    coordinator_id = AgentId("coordinator-0")
    intermediary_ids = [AgentId(f"intermediary-{i}") for i in range(mid_count)]
    leaf_ids = [AgentId(f"leaf-{i}") for i in range(leaf_count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    agents[coordinator_id] = CoordinatorAgent(
        coordinator_id,
        auth=auth,
        intermediaries=intermediary_ids,
        revoke_tick=revoke_tick,
        revoke_target=min(1, mid_count - 1),
    )
    per_block = max(1, leaf_count // max(1, mid_count))
    for index, mid in enumerate(intermediary_ids):
        block = leaf_ids[index * per_block : (index + 1) * per_block]
        agents[mid] = IntermediaryAgent(
            mid,
            auth=auth,
            leaves=block,
            escalate=index == min(2, mid_count - 1),
        )
    for index, leaf in enumerate(leaf_ids):
        share_with = leaf_ids[1] if index == 0 and leaf_count > 1 else None
        agents[leaf] = LeafAgent(
            leaf,
            coordinator=coordinator_id,
            share_with=share_with,
            presents=presents,
            interval=interval,
        )
    return agents
