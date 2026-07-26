# SPDX-License-Identifier: Apache-2.0
"""Bounded-delegation scenario: a capability tree that tries to grow forever.

A coordinator issues a root capability and hands attenuated tokens down a
deliberately over-long chain, while a churn agent revokes short-lived
tokens on a fixed cadence. Two resource attacks are baked in, neither of
which breaks any cryptographic invariant:

1. **Chain inflation.** A relay agent re-delegates its token to the next
   relay, repeatedly, past whatever depth the auth plugin allows. Under
   ``auth: bounded_delegation`` the mint is refused once the bound is
   reached; under ``delegatable`` or ``mesh_revocable`` it succeeds
   indefinitely, and every verifier downstream pays to walk the chain.

2. **Revocation-set growth.** The churn agent issues and revokes
   short-TTL tokens every few ticks, then time passes. Under
   ``bounded_delegation`` the expired entries are pruned and the gossip
   payload stops growing; under the merged plugins the G-Set retains
   every entry forever.

Every delegate / revoke / verify / gossip emits a
``bounded_delegation_audit`` event, so the validators in
``nest_plugins_reference.validators.bounded_delegation_validators`` can
replay the trace.

Like ``delegated_auth``, this scenario is **seed-invariant**: no agent
draws from ``ctx.rng``, so the trace is byte-identical across seeds. The
adversarial behaviours are structural — fixed roles, fixed ticks — which
makes determinism a property under test rather than an accident.

Example::

    agents = bounded_delegation_factory(config, plugins)
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
RELAY_SCOPES: list[str] = ["read"]
CHURN_SCOPES: list[str] = ["read"]

DEFAULT_RELAY_HOPS = 12
"""Re-delegations the relay chain attempts, chosen to exceed any sane bound."""

DEFAULT_CHURN_TTL = 5.0
"""Seconds a churn token lives, short enough to expire well inside the run."""


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
    event = {"type": "bounded_delegation_audit", "tick": int(ctx.time), **data}
    await ctx.send(ctx.agent_id, _json(event))


def _pin_clock(auth: Any, now: float) -> None:
    """Pin a fixed-clock replica to simulation time, if it supports it."""
    for name in ("advance_to", "set_clock"):
        setter = getattr(auth, name, None)
        if callable(setter):
            setter(now)
            return


def _depth_of(auth: Any, token: Token) -> int:
    """Report a token's chain depth, or 1 for plugins without chains.

    ``jwt`` has no chain at all, so every token is depth 1; that is the
    honest answer rather than a failure.

    Example::

        depth = _depth_of(auth, token)
    """
    summary = getattr(auth, "chain_summary", None)
    if callable(summary):
        return int(cast("dict[str, Any]", summary(token))["depth"])
    decode = getattr(auth, "_decode", None)
    if callable(decode):
        try:
            return len(cast("list[Any]", decode(token)))
        except ValueError:
            return 1
    return 1


def _max_depth_of(auth: Any) -> int:
    """Report the plugin's declared bound, or a sentinel when it has none.

    A plugin with no bound reports 0, which no depth can be within — so
    an unbounded plugin fails ``check_chain_depth_bounded`` by
    construction rather than by a special case in the validator.

    Example::

        bound = _max_depth_of(auth)
    """
    return int(getattr(auth, "max_depth", 0))


async def _delegate(
    auth: Any,
    parent_token: Token,
    audience: AgentId,
    scopes: list[str],
    ttl: float,
) -> tuple[Token | None, str]:
    """Delegate via the plugin, reporting why a refusal happened.

    Returns ``(token, reason)``. The reason is ``"depth"`` when the
    plugin refused for chain length, ``"other"`` for any other refusal,
    and ``""`` on success — which is what lets
    ``check_depth_attack_refused`` tell a depth defence from a scope one.

    Example::

        token, reason = await _delegate(auth, root, AgentId("r1"), ["read"], 60.0)
    """
    delegate = getattr(auth, "delegate", None)
    if not callable(delegate):
        return cast("Token", await auth.issue(audience, scopes)), ""
    try:
        pending = cast("Awaitable[Token]", delegate(parent_token, audience, scopes, ttl))
        return await pending, ""
    except ValueError as err:
        reason = "depth" if "max_depth" in str(err) else "other"
        return None, reason


async def _verify(auth: Any, token: Token, presenter: AgentId) -> bool:
    """Verify a presented token, audience-bound when the plugin can.

    Example::

        ok = await _verify(auth, token, AgentId("relay-3"))
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
    """Roots the delegation tree and starts the relay chain.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"), auth=auth,
                                 first_relay=AgentId("relay-0"))
    """

    def __init__(self, agent_id: AgentId, *, auth: Any, first_relay: AgentId) -> None:
        self._id = agent_id
        self._auth = auth
        self._first_relay = first_relay

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(1.0, _json({"type": "bootstrap"}))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        data = _load(payload)
        if data.get("type") != "bootstrap" or sender != ctx.agent_id:
            return
        _pin_clock(self._auth, ctx.time)
        root = cast("Token", await self._auth.issue(ctx.agent_id, ROOT_SCOPES))
        token, reason = await _delegate(
            self._auth, root, self._first_relay, RELAY_SCOPES, ttl=600.0
        )
        await _audit(
            ctx,
            {
                "action": "delegate",
                "delegator": str(ctx.agent_id),
                "audience": str(self._first_relay),
                "granted": token is not None,
                "reason": reason,
                "depth": _depth_of(self._auth, token) if token else 0,
                "max_depth": _max_depth_of(self._auth),
            },
        )
        if token is None:
            return
        await ctx.send(
            self._first_relay,
            _json({"type": "relay_grant", "token": str(token), "hop": 0}),
        )


class RelayAgent(StateMachineAgent):
    """Re-delegates its token onward, inflating the chain until refused.

    Each relay verifies what it received, audits the depth, then tries to
    hand a narrower token to the next relay. On an unbounded plugin the
    chain grows to ``hops``; on a bounded one it stops at the bound.

    Example::

        agent = RelayAgent(AgentId("relay-0"), auth=auth,
                           successors=[AgentId("relay-1")], hops=12)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auth: Any,
        successors: list[AgentId],
        hops: int,
    ) -> None:
        self._id = agent_id
        self._auth = auth
        self._successors = successors
        self._hops = hops

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        data = _load(payload)
        if data.get("type") != "relay_grant":
            return
        _pin_clock(self._auth, ctx.time)

        token = Token(str(data.get("token", "")))
        hop = int(cast("int", data.get("hop", 0)))
        verified = await _verify(self._auth, token, ctx.agent_id)
        await _audit(
            ctx,
            {
                "action": "verify",
                "presenter": str(ctx.agent_id),
                "verified": verified,
                "depth": _depth_of(self._auth, token),
                "max_depth": _max_depth_of(self._auth),
                "hop": hop,
            },
        )
        if not verified or hop >= self._hops or not self._successors:
            return

        successor = self._successors[hop % len(self._successors)]
        child, reason = await _delegate(self._auth, token, successor, RELAY_SCOPES, ttl=300.0)
        await _audit(
            ctx,
            {
                "action": "delegate",
                "delegator": str(ctx.agent_id),
                "audience": str(successor),
                "granted": child is not None,
                "reason": reason,
                "depth": _depth_of(self._auth, child) if child else 0,
                "max_depth": _max_depth_of(self._auth),
                "hop": hop + 1,
            },
        )
        if child is None:
            return
        await ctx.send(
            successor,
            _json({"type": "relay_grant", "token": str(child), "hop": hop + 1}),
        )


class ChurnAgent(StateMachineAgent):
    """Issues and revokes short-lived tokens, growing the revocation set.

    After the churn window closes it waits for every token to expire,
    then reports revocation-set size. A plugin that prunes reports zero
    prunable entries; a G-Set that never forgets reports all of them.

    Example::

        agent = ChurnAgent(AgentId("churn-0"), auth=auth, rounds=8,
                           interval=3, report_tick=90)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auth: Any,
        rounds: int,
        interval: int,
        report_tick: int,
    ) -> None:
        self._id = agent_id
        self._auth = auth
        self._rounds = rounds
        self._interval = interval
        self._report_tick = report_tick

    async def on_start(self, ctx: AgentContext) -> None:
        for round_index in range(self._rounds):
            when = float(2 + round_index * self._interval)
            await ctx.schedule(when, _json({"type": "churn", "round": round_index}))
        await ctx.schedule(float(self._report_tick), _json({"type": "report"}))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        data = _load(payload)
        kind = data.get("type")
        if sender != ctx.agent_id:
            return
        _pin_clock(self._auth, ctx.time)

        if kind == "churn":
            token = cast("Token", await self._auth.issue(ctx.agent_id, CHURN_SCOPES))
            await self._auth.revoke(token)
            await _audit(
                ctx,
                {
                    "action": "revoke",
                    "tid": _tid(token),
                    "round": int(cast("int", data.get("round", 0))),
                },
            )
        elif kind == "report":
            stats = getattr(self._auth, "revocation_stats", None)
            if callable(stats):
                report = cast("dict[str, int]", stats())
            else:
                # A plugin with no pruning notion: every revocation is
                # retained, and all of them are past expiry by now.
                empty: set[str] = set()
                revoked = cast("set[str]", getattr(self._auth, "_revoked", empty))
                report = {
                    "retained": len(revoked),
                    "prunable": len(revoked),
                    "unknown_expiry": 0,
                }
            await _audit(ctx, {"action": "gossip", **report})


def bounded_delegation_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the coordinator, relay chain, and churn agent.

    Every agent shares one auth replica, so the relay chain and the churn
    agent exercise the same revocation state — which is what makes the
    gossip report at the end meaningful.

    Example::

        agents = bounded_delegation_factory(config, plugins)
    """
    task_config = config.task.config or {}
    hops = int(cast("int", task_config.get("relay_hops", DEFAULT_RELAY_HOPS)))
    rounds = int(cast("int", task_config.get("churn_rounds", 8)))
    interval = int(cast("int", task_config.get("churn_interval", 3)))
    report_tick = int(cast("int", task_config.get("report_tick", 90)))

    auth_cls = cast("Any", plugins.get("auth"))
    auth: Any = auth_cls(secret=b"bounded-delegation-scenario", clock=0.0)

    relay_count = max(2, hops)
    relays = [AgentId(f"relay-{i}") for i in range(relay_count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    coordinator_id = AgentId("coordinator-0")
    agents[coordinator_id] = CoordinatorAgent(coordinator_id, auth=auth, first_relay=relays[0])
    for index, relay_id in enumerate(relays):
        successors = [relays[(index + 1) % relay_count]]
        agents[relay_id] = RelayAgent(relay_id, auth=auth, successors=successors, hops=hops)
    churn_id = AgentId("churn-0")
    agents[churn_id] = ChurnAgent(
        churn_id,
        auth=auth,
        rounds=rounds,
        interval=interval,
        report_tick=report_tick,
    )
    return agents
