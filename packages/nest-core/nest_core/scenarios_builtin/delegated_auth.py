# SPDX-License-Identifier: Apache-2.0
"""Delegated auth scenario — coordinator delegates scoped tokens through a tree.

A coordinator issues a root capability token, delegates subsets to three
intermediaries, and each intermediary delegates read-only tokens to four leaf
agents. The trace also exercises adversarial paths: scope escalation, TTL
violation, parent revocation, audience confusion, and transitive revocation.

With ``auth: delegatable`` every attack is blocked or rejected and validators
PASS. With ``auth: jwt`` the same script falls back to naive re-issuance with
no parent chain or audience binding, so validators FAIL.

Trace-line protocol (auditor ``send`` bodies, ``:``-delimited)::

    auth_issue:<agent>:<tok_id>:<scopes>
    auth_delegate:<parent>:<audience>:<tok_id>:<scopes>:<ttl>:<outcome>[:<detail>]
    auth_verify:<presenter>:<tok_id>:<outcome>:<detail>
    auth_revoke:<agent>:<tok_id>
    auth_attack:<attack_type>

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

_AUDITOR = AgentId("auditor-0")


class _TokenStore:
    """Shared token state across all agents in the delegation tree."""

    def __init__(self) -> None:
        self.by_agent: dict[str, Token] = {}
        self.by_id: dict[str, Token] = {}


def _scopes_str(scopes: list[str]) -> str:
    return ",".join(sorted(scopes))


def _instantiate_auth(auth_cls: Any, config: ScenarioConfig) -> Any:
    if not isinstance(auth_cls, type):
        return auth_cls
    if hasattr(auth_cls, "set_clock"):
        return auth_cls(clock=0.0)
    return auth_cls()


class AuditorAgent(StateMachineAgent):
    """Passive evidence collector for auth trace lines."""

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Accept auth evidence messages (recorded by the simulator trace)."""


class DelegatedAuthAgent(StateMachineAgent):
    """Runs one agent's scripted delegation steps at deterministic ticks."""

    def __init__(
        self,
        agent_id: AgentId,
        turns: list[tuple[float, str]],
        auth: Any,
        store: _TokenStore,
    ) -> None:
        self._id = agent_id
        self._turns = turns
        self._auth = auth
        self._store = store
        self._has_delegate = hasattr(auth, "delegate")

    async def on_start(self, ctx: AgentContext) -> None:
        for index, (tick, _action) in enumerate(self._turns):
            await ctx.schedule(tick, f"act:{index}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("act:"):
            return
        try:
            index = int(msg[len("act:") :])
        except ValueError:
            return
        if not 0 <= index < len(self._turns):
            return
        _tick, action = self._turns[index]
        if hasattr(self._auth, "set_clock"):
            self._auth.set_clock(ctx.time)
        await self._run_action(ctx, action)

    async def _run_action(self, ctx: AgentContext, action: str) -> None:
        me = str(self._id)
        if action == "issue_root":
            await self._issue_root(ctx, me)
        elif action.startswith("delegate:"):
            await self._delegate(ctx, me, action)
        elif action.startswith("verify:"):
            await self._verify(ctx, me, action)
        elif action.startswith("revoke:"):
            await self._revoke(ctx, me, action)
        elif action.startswith("attack:"):
            await self._attack(ctx, me, action)

    async def _emit(self, ctx: AgentContext, line: str) -> None:
        await ctx.send(_AUDITOR, line.encode())

    async def _issue_root(self, ctx: AgentContext, me: str) -> None:
        scopes = ["delegate", "read", "write"]
        token = await self._auth.issue(AgentId(me), scopes)
        tok_id = self._tok_id(token)
        self._store.by_agent[me] = token
        self._store.by_id[tok_id] = token
        await self._emit(ctx, f"auth_issue:{me}:{tok_id}:{_scopes_str(scopes)}")

    async def _delegate(self, ctx: AgentContext, me: str, action: str) -> None:
        _, audience, scopes_raw, ttl_raw = action.split(":", 3)
        scopes = scopes_raw.split(",") if scopes_raw else []
        ttl = float(ttl_raw)
        parent = self._store.by_agent.get(me)
        if parent is None:
            await self._emit(
                ctx,
                f"auth_delegate:{me}:{audience}:none:{scopes_raw}:{ttl_raw}:blocked:no_parent",
            )
            return
        try:
            if self._has_delegate:
                child = await self._auth.delegate(parent, AgentId(audience), scopes, ttl)
                outcome, detail = "ok", ""
            else:
                child = await self._auth.issue(AgentId(audience), scopes)
                outcome, detail = "ok", "naive_reissue"
        except Exception as exc:  # noqa: BLE001 — trace records adversarial failures
            await self._emit(ctx, f"auth_attack:delegate_failure:{type(exc).__name__}")
            await self._emit(
                ctx,
                f"auth_delegate:{me}:{audience}:none:{scopes_raw}:{ttl_raw}:blocked:{type(exc).__name__}",
            )
            return
        tok_id = self._tok_id(child)
        self._store.by_agent[audience] = child
        self._store.by_id[tok_id] = child
        await self._emit(
            ctx,
            f"auth_delegate:{me}:{audience}:{tok_id}:{scopes_raw}:{ttl_raw}:{outcome}:{detail}",
        )

    async def _verify(self, ctx: AgentContext, me: str, action: str) -> None:
        _, tok_holder = action.split(":", 1)
        token = self._store.by_agent.get(tok_holder)
        if token is None:
            await self._emit(ctx, f"auth_verify:{me}:none:rejected:missing_token")
            return
        tok_id = self._tok_id(token)
        try:
            if self._has_delegate:
                await self._auth.verify(token, presenter=AgentId(me))
            else:
                await self._auth.verify(token)
            outcome, detail = "accepted", ""
        except Exception as exc:  # noqa: BLE001
            outcome = "rejected"
            detail = type(exc).__name__
        await self._emit(ctx, f"auth_verify:{me}:{tok_id}:{outcome}:{detail}")

    async def _revoke(self, ctx: AgentContext, me: str, action: str) -> None:
        _, holder = action.split(":", 1)
        token = self._store.by_agent.get(holder)
        if token is None:
            return
        await self._auth.revoke(token)
        tok_id = self._tok_id(token)
        await self._emit(ctx, f"auth_revoke:{me}:{tok_id}")

    async def _attack(self, ctx: AgentContext, me: str, action: str) -> None:
        attack_type = action.split(":", 1)[1]
        await self._emit(ctx, f"auth_attack:{attack_type}")
        if attack_type == "scope_escalation":
            await self._delegate(ctx, me, "delegate:leaf-99:read,admin:100")
        elif attack_type == "ttl_violation":
            await self._delegate(ctx, me, "delegate:leaf-99:read:5000")
        elif attack_type == "audience_confusion":
            await self._verify(ctx, "leaf-1", "verify:leaf-0")
        elif attack_type in ("stale_parent", "transitive_revocation"):
            await self._verify(ctx, "leaf-0", "verify:leaf-0")

    def _tok_id(self, token: Token) -> str:
        if hasattr(self._auth, "tok_id"):
            return str(self._auth.tok_id(token))
        return str(token)[:16]


def _build_schedule() -> dict[AgentId, list[tuple[float, str]]]:
    """Fixed deterministic schedule for 16 agents."""
    schedule: dict[AgentId, list[tuple[float, str]]] = {}
    tick = 1.0

    coord: list[tuple[float, str]] = []
    coord.append((tick, "issue_root"))
    tick += 1
    for i in range(3):
        coord.append((tick, f"delegate:intermediary-{i}:read,delegate:800"))
        tick += 1

    for i in range(3):
        agent = AgentId(f"intermediary-{i}")
        turns: list[tuple[float, str]] = []
        for j in range(4):
            leaf = i * 4 + j
            turns.append((tick, f"delegate:leaf-{leaf}:read:400"))
            tick += 1
        schedule[agent] = turns

    for i in range(12):
        agent = AgentId(f"leaf-{i}")
        schedule[agent] = [(tick, f"verify:leaf-{i}")]
        tick += 1

    coord.extend(
        [
            (tick, "attack:scope_escalation"),
            (tick + 1, "attack:ttl_violation"),
            (tick + 2, "attack:audience_confusion"),
            (tick + 3, "revoke:coordinator-0"),
            (tick + 4, "attack:stale_parent"),
            (tick + 5, "attack:transitive_revocation"),
        ]
    )
    schedule[AgentId("coordinator-0")] = coord
    return schedule


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create coordinator, intermediaries, and leaves sharing one auth instance.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    auth_cls = plugins.get("auth")
    auth = _instantiate_auth(auth_cls, config)
    store = _TokenStore()
    schedule = _build_schedule()
    agents: dict[AgentId, StateMachineAgent] = {_AUDITOR: AuditorAgent()}
    for agent_id, turns in schedule.items():
        agents[agent_id] = DelegatedAuthAgent(agent_id, turns, auth, store)
    return agents
