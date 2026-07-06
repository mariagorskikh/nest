# SPDX-License-Identifier: Apache-2.0
"""Capability-token delegated auth under adversarial checks.

The scenario builds a strict delegation tree: one coordinator, three
intermediaries, and twelve leaves. It emits structured
``auth:<kind>|k=v|k=v`` broadcasts consumed by the
``capability_tokens_delegated_auth`` validators:

* scope escalation is rejected at delegation time;
* revoking an intermediary invalidates its four leaf descendants;
* audience confusion is rejected;
* a confused deputy cannot use its own token for an unscoped third-party action;
* a partitioned verifier with a stale revocation epoch fails closed.

Example::

    agents = capability_tokens_delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nest_plugins_reference.auth.capability_tokens import (
    CapabilityTokens,
    RevocationStore,
)

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

_COORDINATOR = AgentId("coordinator-0")
_INTERMEDIARIES = [AgentId(f"intermediary-{i}") for i in range(3)]
_LEAVES = [AgentId(f"leaf-{i}") for i in range(12)]
_LEAF_GROUPS = {
    _INTERMEDIARIES[0]: _LEAVES[0:4],
    _INTERMEDIARIES[1]: _LEAVES[4:8],
    _INTERMEDIARIES[2]: _LEAVES[8:12],
}
_INTERMEDIARY_SCOPES: dict[AgentId, list[str]] = {
    _INTERMEDIARIES[0]: ["alpha:read", "alpha:write"],
    _INTERMEDIARIES[1]: ["beta:read"],
    _INTERMEDIARIES[2]: ["payments:read"],
}
_LEAF_SCOPES: dict[AgentId, list[str]] = {
    **{leaf: ["alpha:read"] for leaf in _LEAVES[0:2]},
    **{leaf: ["alpha:write"] for leaf in _LEAVES[2:4]},
    **{leaf: ["beta:read"] for leaf in _LEAVES[4:8]},
    **{leaf: ["payments:read"] for leaf in _LEAVES[8:12]},
}
_ROOT_SCOPES = ["alpha:read", "alpha:write", "beta:read", "payments:read"]

_OP_DELEGATE = b"op:delegate"
_OP_VERIFY = b"op:verify"
_OP_REVOKE = b"op:revoke"
_OP_POST_REVOKE = b"op:post-revoke"
_OP_PARTITION_CHECK = b"op:partition-check"


def _emit(kind: str, fields: Mapping[str, str | int | float]) -> bytes:
    body = "|".join(f"{k}={v}" for k, v in fields.items())
    return f"auth:{kind}|{body}".encode()


def _error_name(exc: BaseException) -> str:
    return type(exc).__name__


def _set_clock(ctx: AgentContext, clock_state: dict[str, float]) -> None:
    clock_state["now"] = ctx.time


class DelegatedAuthCoordinator(StateMachineAgent):
    """Issues the root token and runs coordinator-side attack probes.

    Example::

        agent = DelegatedAuthCoordinator(tokens={}, clock_state={"now": 0.0})
    """

    def __init__(
        self,
        tokens: dict[str, Token],
        clock_state: dict[str, float],
        partitioned_auth: CapabilityTokens | None,
    ) -> None:
        self._tokens = tokens
        self._clock_state = clock_state
        self._partitioned_auth = partitioned_auth

    async def on_start(self, ctx: AgentContext) -> None:
        """Create the root token and scheduled adversarial checks.

        Example::

            await agent.on_start(ctx)
        """
        _set_clock(ctx, self._clock_state)
        auth = ctx.plugins["auth"]
        if not hasattr(auth, "delegate"):
            await self._emit_default_failures(ctx)
            return

        root = await auth.issue(_COORDINATOR, _ROOT_SCOPES)
        self._tokens[str(_COORDINATOR)] = root
        for intermediary in _INTERMEDIARIES:
            child = await auth.delegate(
                root,
                intermediary,
                _INTERMEDIARY_SCOPES[intermediary],
                ttl=80.0,
            )
            self._tokens[str(intermediary)] = child
            await ctx.broadcast(
                _emit(
                    "delegated",
                    {
                        "parent": str(_COORDINATOR),
                        "child": str(intermediary),
                        "scope_count": len(_INTERMEDIARY_SCOPES[intermediary]),
                        "ttl": 80,
                    },
                )
            )

        await self._probe_scope_escalation(ctx)
        await self._probe_audience_confusion(ctx)
        await self._probe_confused_deputy(ctx)
        await ctx.schedule(3.0, _OP_REVOKE)
        await ctx.schedule(4.0, _OP_PARTITION_CHECK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle scheduled revoke and partition-fence checks.

        Example::

            await agent.on_message(ctx, AgentId("coordinator-0"), b"op:revoke")
        """
        _set_clock(ctx, self._clock_state)
        auth = ctx.plugins["auth"]
        if payload == _OP_REVOKE:
            token = self._tokens.get(str(_INTERMEDIARIES[1]))
            if token is None or not hasattr(auth, "revoke"):
                return
            await auth.revoke(token)
            epoch = getattr(auth, "current_epoch", 0)
            await ctx.broadcast(
                _emit(
                    "revoked",
                    {
                        "target": str(_INTERMEDIARIES[1]),
                        "epoch": int(epoch),
                    },
                )
            )
            return
        if payload == _OP_PARTITION_CHECK:
            await self._probe_partition_epoch(ctx)

    async def _emit_default_failures(self, ctx: AgentContext) -> None:
        for kind in (
            "attack_scope_escalation",
            "attack_audience_confusion",
            "attack_confused_deputy",
            "attack_partition_stale_epoch",
        ):
            await ctx.broadcast(_emit(kind, {"rejected": 0, "error": "NoDelegationApi"}))

    async def _probe_scope_escalation(self, ctx: AgentContext) -> None:
        auth = ctx.plugins["auth"]
        rejected = 0
        error = "accepted"
        try:
            await auth.delegate(
                self._tokens[str(_COORDINATOR)],
                _INTERMEDIARIES[0],
                ["admin:all"],
                ttl=10.0,
            )
        except Exception as exc:  # noqa: BLE001 - trace needs the exact defensive verdict
            rejected = 1
            error = _error_name(exc)
        await ctx.broadcast(
            _emit(
                "attack_scope_escalation",
                {"requested": "admin:all", "rejected": rejected, "error": error},
            )
        )

    async def _probe_audience_confusion(self, ctx: AgentContext) -> None:
        auth = ctx.plugins["auth"]
        rejected = 0
        error = "accepted"
        try:
            await auth.verify_for_audience(self._tokens[str(_INTERMEDIARIES[0])], _LEAVES[0])
        except Exception as exc:  # noqa: BLE001 - trace needs the exact defensive verdict
            rejected = 1
            error = _error_name(exc)
        await ctx.broadcast(
            _emit(
                "attack_audience_confusion",
                {
                    "token_audience": str(_INTERMEDIARIES[0]),
                    "presenter": str(_LEAVES[0]),
                    "rejected": rejected,
                    "error": error,
                },
            )
        )

    async def _probe_confused_deputy(self, ctx: AgentContext) -> None:
        auth = ctx.plugins["auth"]
        rejected = 0
        error = "accepted"
        try:
            await auth.authorize(
                self._tokens[str(_INTERMEDIARIES[2])],
                _INTERMEDIARIES[2],
                "payments:write",
            )
        except Exception as exc:  # noqa: BLE001 - trace needs the exact defensive verdict
            rejected = 1
            error = _error_name(exc)
        await ctx.broadcast(
            _emit(
                "attack_confused_deputy",
                {
                    "deputy": str(_INTERMEDIARIES[2]),
                    "on_behalf": str(_LEAVES[8]),
                    "resource": "payments:write",
                    "rejected": rejected,
                    "error": error,
                },
            )
        )

    async def _probe_partition_epoch(self, ctx: AgentContext) -> None:
        verifier = self._partitioned_auth
        token = self._tokens.get(str(_INTERMEDIARIES[0]))
        rejected = 0
        error = "accepted"
        if verifier is None or token is None:
            rejected = 0
            error = "NoPartitionedVerifier"
        else:
            try:
                await verifier.verify_for_audience(token, _INTERMEDIARIES[0])
            except Exception as exc:  # noqa: BLE001 - trace needs the exact defensive verdict
                rejected = 1
                error = _error_name(exc)
        await ctx.broadcast(
            _emit(
                "attack_partition_stale_epoch",
                {"rejected": rejected, "error": error},
            )
        )


class DelegatedAuthIntermediary(StateMachineAgent):
    """Attenuates one intermediary token into four leaf tokens.

    Example::

        agent = DelegatedAuthIntermediary(AgentId("intermediary-0"), leaves, tokens, clock)
    """

    def __init__(
        self,
        agent_id: AgentId,
        leaves: list[AgentId],
        tokens: dict[str, Token],
        clock_state: dict[str, float],
    ) -> None:
        self._id = agent_id
        self._leaves = leaves
        self._tokens = tokens
        self._clock_state = clock_state

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule offline leaf attenuation after the coordinator issues parents.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.schedule(1.0, _OP_DELEGATE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Delegate this intermediary's token to its four leaves.

        Example::

            await agent.on_message(ctx, AgentId("intermediary-0"), b"op:delegate")
        """
        if payload != _OP_DELEGATE:
            return
        _set_clock(ctx, self._clock_state)
        auth = ctx.plugins["auth"]
        if not hasattr(auth, "delegate"):
            return
        parent = self._tokens.get(str(self._id))
        if parent is None:
            return
        for leaf in self._leaves:
            scopes = _LEAF_SCOPES[leaf]
            child = await auth.delegate(parent, leaf, scopes, ttl=30.0)
            self._tokens[str(leaf)] = child
            await ctx.broadcast(
                _emit(
                    "delegated",
                    {
                        "parent": str(self._id),
                        "child": str(leaf),
                        "scope_count": len(scopes),
                        "ttl": 30,
                    },
                )
            )


class DelegatedAuthLeaf(StateMachineAgent):
    """Verifies a leaf token before and, for one subtree, after revocation.

    Example::

        agent = DelegatedAuthLeaf(AgentId("leaf-4"), tokens, clock, post_revoke=True)
    """

    def __init__(
        self,
        agent_id: AgentId,
        tokens: dict[str, Token],
        clock_state: dict[str, float],
        *,
        post_revoke: bool,
    ) -> None:
        self._id = agent_id
        self._tokens = tokens
        self._clock_state = clock_state
        self._post_revoke = post_revoke

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule initial and optional post-revocation verification.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.schedule(2.0, _OP_VERIFY)
        if self._post_revoke:
            await ctx.schedule(5.0, _OP_POST_REVOKE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify this leaf's token and emit a validator-readable verdict.

        Example::

            await agent.on_message(ctx, AgentId("leaf-4"), b"op:post-revoke")
        """
        if payload not in (_OP_VERIFY, _OP_POST_REVOKE):
            return
        _set_clock(ctx, self._clock_state)
        auth = ctx.plugins["auth"]
        token = self._tokens.get(str(self._id))
        if token is None:
            return
        try:
            await auth.verify(token)
            rejected = 0
            error = "accepted"
        except Exception as exc:  # noqa: BLE001 - trace needs the exact defensive verdict
            rejected = 1
            error = _error_name(exc)

        if payload == _OP_VERIFY:
            await ctx.broadcast(
                _emit(
                    "leaf_verified",
                    {
                        "leaf": str(self._id),
                        "verified": int(not rejected),
                        "error": error,
                    },
                )
            )
        else:
            await ctx.broadcast(
                _emit(
                    "attack_stale_parent",
                    {
                        "leaf": str(self._id),
                        "rejected": rejected,
                        "error": error,
                    },
                )
            )


def capability_tokens_delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the 16-agent delegated-auth tree and shared auth state.

    The factory installs per-agent auth instances with a shared revocation
    store.  Under ``auth: capability_tokens`` this yields real delegation;
    under ``auth: jwt`` the coordinator emits negative attack rows so validators
    prove the default plugin lacks the capability.

    Example::

        agents = capability_tokens_delegated_auth_factory(config, plugins)
    """
    auth_cls = plugins["auth"]
    clock_state = {"now": 0.0}
    tokens: dict[str, Token] = {}
    store = RevocationStore()
    partitioned_auth: CapabilityTokens | None = None
    overrides: dict[AgentId, dict[str, Any]] = {}

    if isinstance(auth_cls, type) and issubclass(auth_cls, CapabilityTokens):
        partitioned_auth = auth_cls(
            secret=b"delegated-auth-scenario",
            clock=lambda: clock_state["now"],
            agent_id=_INTERMEDIARIES[0],
            revocation_store=store,
            stale_after=0,
            auto_sync=False,
        )

    def _auth_instance(agent_id: AgentId) -> Any:
        if isinstance(auth_cls, type) and issubclass(auth_cls, CapabilityTokens):
            return auth_cls(
                secret=b"delegated-auth-scenario",
                clock=lambda: clock_state["now"],
                agent_id=agent_id,
                revocation_store=store,
                stale_after=0,
                auto_sync=True,
            )
        try:
            return auth_cls(secret=b"delegated-auth-scenario", clock=0.0)
        except TypeError:
            return auth_cls()

    agents: dict[AgentId, StateMachineAgent] = {
        _COORDINATOR: DelegatedAuthCoordinator(tokens, clock_state, partitioned_auth),
    }
    for intermediary, leaves in _LEAF_GROUPS.items():
        agents[intermediary] = DelegatedAuthIntermediary(
            intermediary,
            leaves,
            tokens,
            clock_state,
        )
    for leaf in _LEAVES:
        agents[leaf] = DelegatedAuthLeaf(
            leaf,
            tokens,
            clock_state,
            post_revoke=leaf in _LEAF_GROUPS[_INTERMEDIARIES[1]],
        )

    for agent_id in agents:
        overrides[agent_id] = {"auth": _auth_instance(agent_id)}

    plugins["_agent_plugins"] = overrides
    plugins["_delegated_auth_revocation_store"] = store
    return agents
