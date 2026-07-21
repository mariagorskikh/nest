# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth partition scenario: revocation during a network split.

The ``delegated_auth`` scenario proves capability *semantics* (attenuation,
cascade, audience binding) with every agent sharing one auth instance. This
scenario proves capability *distribution*: every verifier owns its own auth
replica, and revocation knowledge travels only by gossip.

A coordinator delegates to two intermediaries, which sub-delegate to three
leaves each. Leaves present their tokens to two independent verifiers -- the
coordinator and a gateway -- on a fixed cadence. The mesh then splits into
two groups (coordinator + intermediary-0's subtree vs gateway +
intermediary-1's subtree), and *during* the split the coordinator revokes
intermediary-1's grant:

- the gateway, cut off from the revoker, keeps accepting that subtree's
  tokens -- honest partition behavior (availability), asserted by
  ``check_partition_liveness``;
- once the partition heals, gossiped revocation state converges and the
  revoked subtree is denied by **every** verifier within a bounded number
  of gossip rounds, asserted by ``check_revocation_converges``.

Under ``auth: mesh_revocable`` both properties hold. Under per-replica
``auth: delegatable`` the gossip channel does not exist, the gateway never
learns of the revocation, and convergence fails -- that is the gap this
scenario exists to expose.

Every delegate / revoke / verify emits a ``delegation_audit`` event using
the same vocabulary as ``delegated_auth`` (plus a ``verifier`` field and a
``gossip_merge`` op), so the escalation and audience validators from
``nest_plugins_reference.validators.delegation_validators`` run green on
this trace too.

The scenario is deliberately **seed-invariant**: agents draw nothing from
``ctx.rng``; all behavior is structural (fixed roles, fixed ticks).

Example::

    agents = delegated_auth_partition_factory(config, plugins)
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


def _json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _load(payload: bytes) -> dict[str, Any]:
    try:
        data: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
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


class _GossipMixin(StateMachineAgent):
    """Shared gossip behavior for every agent that owns an auth replica.

    On each self-scheduled ``rvk_tick`` the replica's revocation state is
    broadcast (duck-typed: a plugin without ``export_revocations`` -- e.g.
    plain ``delegatable`` -- simply never gossips, which *is* the baseline
    under test). Incoming states are merged defensively.

    Example::

        class MyAgent(_GossipMixin): ...
    """

    _auth: Any

    def _schedule_gossip(self) -> list[tuple[float, bytes]]:
        return [
            (float(t), _json({"type": "rvk_tick"}))
            for t in range(self._gossip_interval, self._gossip_until, self._gossip_interval)
        ]

    def __init__(self, *, gossip_interval: int, gossip_until: int) -> None:
        self._gossip_interval = gossip_interval
        self._gossip_until = gossip_until

    async def _handle_gossip(
        self, ctx: AgentContext, sender: AgentId, data: dict[str, Any]
    ) -> bool:
        kind = data.get("type")
        if kind == "rvk_tick" and sender == ctx.agent_id:
            export = getattr(self._auth, "export_revocations", None)
            if callable(export):
                state = cast("bytes", export())
                await ctx.broadcast(_json({"type": "rvk_state", "state": state.decode("utf-8")}))
            return True
        if kind == "rvk_state":
            merge = getattr(self._auth, "merge_revocations", None)
            if callable(merge):
                try:
                    changed = bool(merge(str(data.get("state", "")).encode("utf-8")))
                except ValueError:
                    return True
                if changed:
                    await _audit(ctx, {"op": "gossip_merge", "source": str(sender)})
            return True
        return False


class CoordinatorAgent(_GossipMixin):
    """Issues the root, delegates, revokes mid-partition, and verifies.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"), auth=auth,
                                 intermediaries=[AgentId("intermediary-0")],
                                 revoke_tick=20, revoke_target=1,
                                 gossip_interval=5, gossip_until=95)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auth: Any,
        intermediaries: list[AgentId],
        revoke_tick: int,
        revoke_target: int,
        gossip_interval: int,
        gossip_until: int,
    ) -> None:
        super().__init__(gossip_interval=gossip_interval, gossip_until=gossip_until)
        self._id = agent_id
        self._auth = auth
        self._intermediaries = intermediaries
        self._revoke_tick = revoke_tick
        self._revoke_target = revoke_target
        self._grants: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the bootstrap grant, the revocation, and gossip rounds.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.schedule(1.0, _json({"type": "bootstrap"}))
        await ctx.schedule(float(self._revoke_tick), _json({"type": "revoke"}))
        for when, payload in self._schedule_gossip():
            await ctx.schedule(when, payload)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle gossip, the bootstrap/revoke ticks, and access requests.

        Example::

            await agent.on_message(ctx, sender, b'{"type": "access_request"}')
        """
        data = _load(payload)
        _pin_clock(self._auth, ctx.time)
        if await self._handle_gossip(ctx, sender, data):
            return
        kind = data.get("type")
        if kind == "bootstrap" and sender == ctx.agent_id:
            root = cast("Token", await self._auth.issue(ctx.agent_id, ROOT_SCOPES))
            for mid in self._intermediaries:
                token = await _delegate(self._auth, root, mid, MID_SCOPES, ttl=6000.0)
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
            await _audit(
                ctx,
                {
                    "op": "revoke",
                    "tid": _tid(token),
                    "target": str(target),
                    "revoker": str(ctx.agent_id),
                },
            )
        elif kind == "access_request":
            await self._gate(ctx, sender, data)

    async def _gate(self, ctx: AgentContext, sender: AgentId, data: dict[str, Any]) -> None:
        token = Token(str(data.get("token", "")))
        lineage = [str(t) for t in cast("list[Any]", data.get("lineage", []))]
        verified = await _verify(self._auth, token, sender)
        await _audit(
            ctx,
            {
                "op": "verify",
                "verifier": str(ctx.agent_id),
                "presenter": str(sender),
                "audience": str(data.get("audience", "")),
                "chain_tids": [*lineage, _tid(token)],
                "verified": verified,
            },
        )


class GatewayAgent(_GossipMixin):
    """A second, independent verifier with its own auth replica.

    Its whole purpose is to sit on the far side of the partition from the
    revoker: its verify audits are the evidence for both partition
    liveness and post-heal convergence.

    Example::

        agent = GatewayAgent(AgentId("gateway-0"), auth=auth,
                             gossip_interval=5, gossip_until=95)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auth: Any,
        gossip_interval: int,
        gossip_until: int,
    ) -> None:
        super().__init__(gossip_interval=gossip_interval, gossip_until=gossip_until)
        self._id = agent_id
        self._auth = auth

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule this replica's gossip rounds.

        Example::

            await agent.on_start(ctx)
        """
        for when, payload in self._schedule_gossip():
            await ctx.schedule(when, payload)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Merge incoming gossip, or gate an access request against this replica.

        Example::

            await agent.on_message(ctx, sender, b'{"type": "access_request"}')
        """
        data = _load(payload)
        _pin_clock(self._auth, ctx.time)
        if await self._handle_gossip(ctx, sender, data):
            return
        if data.get("type") != "access_request":
            return
        token = Token(str(data.get("token", "")))
        lineage = [str(t) for t in cast("list[Any]", data.get("lineage", []))]
        verified = await _verify(self._auth, token, sender)
        await _audit(
            ctx,
            {
                "op": "verify",
                "verifier": str(ctx.agent_id),
                "presenter": str(sender),
                "audience": str(data.get("audience", "")),
                "chain_tids": [*lineage, _tid(token)],
                "verified": verified,
            },
        )


class IntermediaryAgent(_GossipMixin):
    """Sub-delegates its grant to a block of leaf agents; carries a replica.

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), auth=auth,
                                  leaves=[AgentId("leaf-0")],
                                  gossip_interval=5, gossip_until=95)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auth: Any,
        leaves: list[AgentId],
        gossip_interval: int,
        gossip_until: int,
    ) -> None:
        super().__init__(gossip_interval=gossip_interval, gossip_until=gossip_until)
        self._id = agent_id
        self._auth = auth
        self._leaves = leaves

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule this replica's gossip rounds.

        Example::

            await agent.on_start(ctx)
        """
        for when, payload in self._schedule_gossip():
            await ctx.schedule(when, payload)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Merge incoming gossip, or attenuate a received grant for each leaf.

        Example::

            await agent.on_message(ctx, coordinator, b'{"type": "grant", ...}')
        """
        data = _load(payload)
        _pin_clock(self._auth, ctx.time)
        if await self._handle_gossip(ctx, sender, data):
            return
        if data.get("type") != "grant":
            return
        parent = Token(str(data.get("token", "")))
        lineage = [str(t) for t in cast("list[Any]", data.get("lineage", []))]
        for leaf in self._leaves:
            token = await _delegate(self._auth, parent, leaf, LEAF_SCOPES, ttl=3000.0)
            granted = token is not None
            await _audit(
                ctx,
                {
                    "op": "delegate",
                    "delegator": str(ctx.agent_id),
                    "audience": str(leaf),
                    "parent_scopes": MID_SCOPES,
                    "child_scopes": LEAF_SCOPES,
                    "granted": granted,
                },
            )
            if token is None:
                continue
            await ctx.send(
                leaf,
                _json({"type": "grant", "token": str(token), "lineage": [*lineage, _tid(token)]}),
            )


class LeafAgent(StateMachineAgent):
    """Presents its token to both verifiers on a fixed cadence.

    Example::

        agent = LeafAgent(AgentId("leaf-0"),
                          verifiers=[AgentId("coordinator-0"), AgentId("gateway-0")],
                          presents=15, interval=6)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        verifiers: list[AgentId],
        presents: int,
        interval: int,
    ) -> None:
        self._id = agent_id
        self._verifiers = verifiers
        self._presents = presents
        self._interval = interval
        self._token: str | None = None
        self._lineage: list[str] = []

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Store a received grant, then present it to every verifier on cadence.

        Example::

            await agent.on_message(ctx, intermediary, b'{"type": "grant", ...}')
        """
        data = _load(payload)
        kind = data.get("type")
        if kind == "grant":
            self._token = str(data.get("token", ""))
            self._lineage = [str(t) for t in cast("list[Any]", data.get("lineage", []))]
            for step in range(self._presents):
                await ctx.schedule(2.0 + step * self._interval, _json({"type": "present"}))
        elif kind == "present" and sender == ctx.agent_id and self._token is not None:
            request = {
                "type": "access_request",
                "token": self._token,
                "lineage": self._lineage,
                "audience": str(ctx.agent_id),
            }
            for verifier in self._verifiers:
                await ctx.send(verifier, _json(request))


def delegated_auth_partition_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the partitioned delegation mesh with per-agent auth replicas.

    Unlike ``delegated_auth_factory``, every verifier and delegator gets its
    **own** instance of the configured auth plugin (same secret, so tokens
    verify everywhere) -- the deployment shape a real network forces. Leaves
    hold only token strings.

    Example::

        agents = delegated_auth_partition_factory(config, plugins)
    """
    task_config = config.task.config
    revoke_tick = int(cast("int", task_config.get("revoke_tick", 20)))
    gossip_interval = int(cast("int", task_config.get("gossip_interval", 5)))
    gossip_until = int(cast("int", task_config.get("gossip_until", 95)))
    presents = int(cast("int", task_config.get("presents", 15)))
    interval = int(cast("int", task_config.get("present_interval", 6)))

    auth_cls = cast("Any", plugins.get("auth"))

    def _new_replica() -> Any:
        return auth_cls(secret=b"delegated-auth-partition", clock=0.0)

    coordinator_id = AgentId("coordinator-0")
    gateway_id = AgentId("gateway-0")
    intermediary_ids = [AgentId("intermediary-0"), AgentId("intermediary-1")]
    leaf_ids = [AgentId(f"leaf-{i}") for i in range(6)]

    agents: dict[AgentId, StateMachineAgent] = {}
    agents[coordinator_id] = CoordinatorAgent(
        coordinator_id,
        auth=_new_replica(),
        intermediaries=intermediary_ids,
        revoke_tick=revoke_tick,
        revoke_target=1,  # intermediary-1: the subtree on the far side of the split
        gossip_interval=gossip_interval,
        gossip_until=gossip_until,
    )
    agents[gateway_id] = GatewayAgent(
        gateway_id,
        auth=_new_replica(),
        gossip_interval=gossip_interval,
        gossip_until=gossip_until,
    )
    for index, mid in enumerate(intermediary_ids):
        block = leaf_ids[index * 3 : (index + 1) * 3]
        agents[mid] = IntermediaryAgent(
            mid,
            auth=_new_replica(),
            leaves=block,
            gossip_interval=gossip_interval,
            gossip_until=gossip_until,
        )
    for leaf in leaf_ids:
        agents[leaf] = LeafAgent(
            leaf,
            verifiers=[coordinator_id, gateway_id],
            presents=presents,
            interval=interval,
        )
    return agents
