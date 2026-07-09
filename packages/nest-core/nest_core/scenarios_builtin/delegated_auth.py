# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario -- a coordinator, 3 intermediaries, 12 leaf agents.

Drives the ``delegatable`` auth plugin through a real delegation tree and three
adversarial probes, emitting one structured ``authz:<kind>:<fields>`` broadcast
per lifecycle event. The three ``delegated_auth`` validators (see
:mod:`nest_core.validators`) read those broadcasts and confirm:

* every delegated token's scopes are a subset of its parent's (attenuation);
* no token verifies OK once an ancestor has been revoked (cascading revocation);
* no token verifies OK when presented by an agent that is not its audience
  (audience binding).

Flow (all timings are logical sim ticks; the auth clock is *fixed* so tokens are
byte-identical across replays):

* The coordinator issues a root token and delegates a narrowed token to each of
  the three intermediaries.
* Each intermediary delegates a further-narrowed token to its four leaves, which
  verify and report ``authz:verified:result=ok``.
* ``intermediary-0`` runs two live attacks the plugin rejects: a **scope
  escalation** (delegating a scope it does not hold) and an **audience
  confusion** (handing ``leaf-0``'s token to ``leaf-1``, which tries to present
  it).
* The coordinator **revokes** ``intermediary-2``; every leaf re-verifies later,
  and the four under ``intermediary-2`` now fail with a revoked ancestor.
* The coordinator presents a pre-minted **expired** token to exercise the
  time-expiry branch deterministically.

If the configured auth plugin lacks ``delegate`` (e.g. the default ``jwt``),
the agents skip the entire tree, no ``authz:delegated`` / ``authz:verified``
events reach the trace, and the validators report "no delegation observed" --
exactly the adversarial discrimination the charter asks for.

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

# Fixed auth clock -- every issued/delegated token gets deterministic iat/exp.
_CLOCK = 100.0
_SECRET = b"delegated-auth-scenario-secret"

# Logical tick schedule. Delegation cascades at BOOT via zero-latency sends;
# revocation and re-verification are spaced strictly after it so ordering in
# the trace is unambiguous.
_TICK_BOOT = 1.0
_TICK_REVOKE = 5.0
_TICK_STALE = 6.0
_TICK_RECHECK = 8.0

# Attenuating scope sets: root -> intermediary -> leaf, each a strict subset.
_ROOT_SCOPES = ["read", "write", "exec"]
_MID_SCOPES = ["read", "write"]
_LEAF_SCOPES = ["read"]

_MID_TTL = 500.0  # intermediary exp = 600 (<= root exp)
_LEAF_TTL = 200.0  # leaf exp = 300 (<= intermediary exp)

# Control-message opcodes (point-to-point). Prefixed so agents ignore the
# ``authz:*`` broadcasts that also arrive in ``on_message``.
_GRANT = b"grant"
_IMPERSONATE = b"impersonate"
_OP_BOOT = b"op:boot"
_OP_REVOKE = b"op:revoke"
_OP_STALE = b"op:stale"
_OP_RECHECK = b"op:recheck"

_REVOKED_INTERMEDIARY = "intermediary-2"


def _emit(fields: dict[str, str]) -> bytes:
    """Build a structured ``authz:<kind>:k=v:...`` broadcast payload.

    Scope lists are ``|``-joined so no value contains the ``:`` or ``=``
    separators the validator parser splits on.
    """
    kind = fields.pop("kind")
    body = ":".join(f"{k}={v}" for k, v in fields.items())
    return (f"authz:{kind}:{body}" if body else f"authz:{kind}").encode()


def _supports_delegation(auth: Any) -> bool:
    """Whether the resolved auth plugin is delegatable (has ``delegate``)."""
    return hasattr(auth, "delegate")


class CoordinatorAgent(StateMachineAgent):
    """Root of trust: issues the root token and delegates to intermediaries.

    Also drives the two coordinator-owned probes -- revoking
    ``intermediary-2`` (cascading revocation) and presenting a pre-minted
    expired token (time-expiry).

    Example::

        agent = CoordinatorAgent(AgentId("coordinator"), ["intermediary-0"], stale_token=None)
    """

    def __init__(
        self,
        agent_id: AgentId,
        intermediaries: list[AgentId],
        auth_cls: Any,
    ) -> None:
        self._id = agent_id
        self._intermediaries = intermediaries
        self._auth_cls = auth_cls
        self._root: str | None = None
        self._mid_tokens: dict[str, str] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(_TICK_BOOT, _OP_BOOT)
        await ctx.schedule(_TICK_REVOKE, _OP_REVOKE)
        await ctx.schedule(_TICK_STALE, _OP_STALE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        auth = ctx.plugins["auth"]
        if payload == _OP_BOOT:
            await self._boot(ctx, auth)
        elif payload == _OP_REVOKE:
            await self._revoke(ctx, auth)
        elif payload == _OP_STALE:
            await self._present_stale(ctx, auth)

    async def _boot(self, ctx: AgentContext, auth: Any) -> None:
        root = await auth.issue(self._id, _ROOT_SCOPES)
        self._root = str(root)
        await ctx.broadcast(
            _emit(
                {
                    "kind": "issued",
                    "holder": str(self._id),
                    "scopes": "|".join(_ROOT_SCOPES),
                }
            )
        )
        if not _supports_delegation(auth):
            return  # default jwt: no delegation surface -> tree never forms.
        for mid in self._intermediaries:
            child = await auth.delegate(root, mid, _MID_SCOPES, _MID_TTL)
            self._mid_tokens[str(mid)] = str(child)
            await ctx.broadcast(
                _emit(
                    {
                        "kind": "delegated",
                        "by": str(self._id),
                        "aud": str(mid),
                        "parent": str(self._id),
                        "scopes": "|".join(_MID_SCOPES),
                    }
                )
            )
            await ctx.send(mid, _GRANT + b"|" + child.encode())

    async def _revoke(self, ctx: AgentContext, auth: Any) -> None:
        token = self._mid_tokens.get(_REVOKED_INTERMEDIARY)
        if token is None:
            return
        await auth.revoke(token)
        await ctx.broadcast(
            _emit({"kind": "revoked", "by": str(self._id), "aud": _REVOKED_INTERMEDIARY})
        )

    async def _present_stale(self, ctx: AgentContext, auth: Any) -> None:
        if not _supports_delegation(auth):
            return
        stale_token = await self._mint_stale_token()
        if stale_token is None:
            return
        try:
            await auth.verify(stale_token, presenter=self._id)
        except Exception as exc:  # noqa: BLE001 -- report any rejection class
            await ctx.broadcast(
                _emit(
                    {
                        "kind": "denied",
                        "by": str(self._id),
                        "attack": "expired_parent",
                        "reason": type(exc).__name__,
                    }
                )
            )

    async def _mint_stale_token(self) -> str | None:
        """Pre-mint an already-expired delegated token via a past-clock instance.

        The throwaway instance shares ``_SECRET`` (so the signature verifies
        under the live clock) but sits far enough in the past that both links'
        ``exp`` are below ``_CLOCK`` -- making the time-expiry attack
        deterministic without moving any clock.
        """
        try:
            stale = self._auth_cls(secret=_SECRET, clock=10.0, default_ttl=20.0)
        except TypeError:
            return None
        if not _supports_delegation(stale):
            return None
        root = await stale.issue(AgentId("stale-root"), _MID_SCOPES)
        child = await stale.delegate(root, self._id, _LEAF_SCOPES, 10.0)
        return str(child)


class IntermediaryAgent(StateMachineAgent):
    """Delegates a narrowed token to each of its leaves; optionally runs attacks.

    ``intermediary-0`` additionally probes scope escalation and audience
    confusion, both of which the plugin must reject.

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), ["leaf-0"], attacker=True)
    """

    def __init__(self, agent_id: AgentId, leaves: list[AgentId], attacker: bool) -> None:
        self._id = agent_id
        self._leaves = leaves
        self._attacker = attacker

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if not payload.startswith(_GRANT + b"|"):
            return
        auth = ctx.plugins["auth"]
        my_token = payload[len(_GRANT) + 1 :].decode()
        first_leaf_token: str | None = None
        for leaf in self._leaves:
            child = await auth.delegate(my_token, leaf, _LEAF_SCOPES, _LEAF_TTL)
            if first_leaf_token is None:
                first_leaf_token = str(child)
            await ctx.broadcast(
                _emit(
                    {
                        "kind": "delegated",
                        "by": str(self._id),
                        "aud": str(leaf),
                        "parent": str(self._id),
                        "scopes": "|".join(_LEAF_SCOPES),
                    }
                )
            )
            await ctx.send(leaf, _GRANT + b"|" + child.encode())
        if self._attacker:
            await self._attack(ctx, auth, my_token, first_leaf_token)

    async def _attack(
        self,
        ctx: AgentContext,
        auth: Any,
        my_token: str,
        first_leaf_token: str | None,
    ) -> None:
        # Attack 1 -- scope escalation: delegate a scope not held by this token.
        try:
            await auth.delegate(my_token, AgentId("phantom"), ["exec"], _LEAF_TTL)
        except Exception as exc:  # noqa: BLE001
            await ctx.broadcast(
                _emit(
                    {
                        "kind": "denied",
                        "by": str(self._id),
                        "attack": "scope_escalation",
                        "reason": type(exc).__name__,
                    }
                )
            )
        # Attack 2 -- audience confusion: hand leaf-0's token to leaf-1.
        if first_leaf_token is not None and len(self._leaves) >= 2:
            await ctx.send(self._leaves[1], _IMPERSONATE + b"|" + first_leaf_token.encode())


class LeafAgent(StateMachineAgent):
    """Verifies its granted token, re-verifies after revocation, resists replay.

    On the honest path it reports ``authz:verified:result=ok``. If handed a
    foreign token it reports ``authz:denied:attack=audience_confusion``. On the
    scheduled recheck, a leaf whose intermediary was revoked reports
    ``authz:denied:attack=revoked_parent``.

    Example::

        agent = LeafAgent(AgentId("leaf-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._token: str | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        auth = ctx.plugins["auth"]
        if payload.startswith(_GRANT + b"|"):
            self._token = payload[len(_GRANT) + 1 :].decode()
            await self._verify(ctx, auth, self._token, attack=None)
            await ctx.schedule(_TICK_RECHECK - ctx.time, _OP_RECHECK)
        elif payload.startswith(_IMPERSONATE + b"|"):
            foreign = payload[len(_IMPERSONATE) + 1 :].decode()
            await self._verify(ctx, auth, foreign, attack="audience_confusion")
        elif payload == _OP_RECHECK and self._token is not None:
            await self._verify(ctx, auth, self._token, attack="revoked_parent")

    async def _verify(
        self,
        ctx: AgentContext,
        auth: Any,
        token: str,
        attack: str | None,
    ) -> None:
        try:
            authctx = await auth.verify(token, presenter=self._id)
        except Exception as exc:  # noqa: BLE001
            await ctx.broadcast(
                _emit(
                    {
                        "kind": "denied",
                        "by": str(self._id),
                        "attack": attack or "verify",
                        "presenter": str(self._id),
                        "reason": type(exc).__name__,
                    }
                )
            )
            return
        await ctx.broadcast(
            _emit(
                {
                    "kind": "verified",
                    "by": str(self._id),
                    "aud": str(authctx.subject),
                    "presenter": str(self._id),
                    "result": "ok",
                }
            )
        )


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the 16-agent delegation tree and wire one shared auth instance.

    Every agent receives the *same* ``DelegatableAuth`` instance (fixed clock,
    shared secret + revoked set) via the ``_agent_plugins`` override channel, so
    a revocation on the coordinator's instance is visible to every leaf's
    verify. For a non-delegatable auth class the shared instance is still wired,
    but the agents detect the missing ``delegate`` surface and the tree never
    forms.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    auth_cls = plugins["auth"]
    shared_revoked: set[str] = set()
    try:
        shared_auth = auth_cls(secret=_SECRET, clock=_CLOCK, revoked=shared_revoked)
    except TypeError:
        # Non-delegatable auth (e.g. jwt) -- best-effort shared instance.
        try:
            shared_auth = auth_cls(secret=_SECRET, clock=_CLOCK)
        except TypeError:
            shared_auth = auth_cls()

    intermediaries = [AgentId(f"intermediary-{i}") for i in range(3)]
    agents: dict[AgentId, StateMachineAgent] = {}

    coordinator_id = AgentId("coordinator")
    agents[coordinator_id] = CoordinatorAgent(coordinator_id, intermediaries, auth_cls=auth_cls)

    leaf_index = 0
    for i, mid in enumerate(intermediaries):
        leaves = [AgentId(f"leaf-{leaf_index + k}") for k in range(4)]
        leaf_index += 4
        agents[mid] = IntermediaryAgent(mid, leaves, attacker=(i == 0))
        for leaf in leaves:
            agents[leaf] = LeafAgent(leaf)

    overrides: dict[AgentId, dict[str, Any]] = {aid: {"auth": shared_auth} for aid in agents}
    plugins["_agent_plugins"] = overrides
    return agents
