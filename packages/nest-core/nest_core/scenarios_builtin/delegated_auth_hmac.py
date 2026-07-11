# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario -- a 3-level capability-delegation tree under attack.

A ``coordinator`` issues a root token and delegates a narrower sub-token to
each of 3 ``intermediary`` agents, which each delegate further to 4 ``leaf``
agents (12 leaves total). Every leaf presents its token to a single
``auditor`` for verification, twice: once right after receiving it, and once
again after the coordinator revokes one intermediary's token partway through
the run. This exercises the three attacks the problem brief names, plus the
headline cascading-revocation feature:

* **Scope escalation** -- the coordinator also tries to delegate scopes its
  own root token does not hold; must be blocked.
* **Cascading revocation** -- revoking one intermediary's token must
  invalidate that intermediary and all 4 of its leaves at the next verify,
  while the other 8 leaves (under the two untouched intermediaries) must be
  completely unaffected.
* **Audience confusion** -- one designated leaf also presents its own,
  perfectly valid token but claims to be a *different* agent; must be
  blocked.

The scenario's "stale parent" coverage is the explicit-revocation case
only: the shared auth plugin instance runs on a fixed simulated clock
(``clock=0.0``), so tokens never naturally expire during the run, and
natural-expiry rejection is exercised solely by a plugin-level unit test,
not by this scenario.

Agents resolve the auth plugin from ``ctx.plugins`` indirectly: the factory
instantiates a single shared instance (revocation state and the HMAC secret
must be shared for verification to mean anything) and injects it into every
agent's constructor. The coordinator capability-gates on ``hasattr(auth,
"delegate")`` -- so pointing this scenario at ``auth: jwt`` does not crash;
the whole cascade simply never starts, which is the honest gap the
``delegated_auth_hmac`` validators are built to catch (see
``nest_core.validators.validate_auth_delegation_occurred``).

Trace line protocol (``:``-delimited, carried in message bodies)::

    issued:<token_id>:<subject>:<scopes_csv>
    delegated:<child_id>:<parent_id>:<audience>:<scopes_csv>
    delegate_blocked:<attack_kind>:<parent_id>
    revoked:<token_id>
    verify_result:<token_id>:<check_kind>:<outcome>

``verify_request`` (leaf/intermediary -> auditor) is ``|``-delimited instead,
since its last field is a raw JSON token::

    verify_request|<presented_by>|<check_kind>|<token_json>

Example::

    agents = delegated_auth_hmac_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

#: Scopes requested by the coordinator's scope-escalation attack; "superuser"
#: is not among the root's own scopes, so this must be blocked.
_ESCALATION_SCOPES = ["read", "write", "admin", "superuser"]

#: Ticks after start at which the coordinator revokes one intermediary's token.
_REVOKE_AT = 10.0
#: Ticks after receiving a token at which intermediaries/leaves re-verify.
_REVERIFY_AT = 15.0


def _token_payload(token: Token) -> bytes:
    """Wrap a token in a JSON envelope for handoff between agents.

    Example::

        await ctx.send(intermediary, _token_payload(child))
    """
    return json.dumps({"token": str(token)}).encode()


def _unwrap_token(payload: bytes) -> Token | None:
    """Unwrap a token handoff payload, or ``None`` if this isn't one.

    Example::

        token = _unwrap_token(payload)
    """
    msg = payload.decode("utf-8", errors="replace")
    if not msg.startswith("{"):
        return None
    data = cast("dict[str, Any]", json.loads(msg))
    return cast("Token", data["token"])


class CoordinatorAgent(StateMachineAgent):
    """Issues the root token, delegates to each intermediary, attacks, revokes.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"), auth=auth,
                                  auditor=AgentId("auditor-0"),
                                  intermediaries=[...], revoke_target=AgentId("intermediary-1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        auth: Any,
        auditor: AgentId,
        intermediaries: list[AgentId],
        revoke_target: AgentId,
    ) -> None:
        self._id = agent_id
        self._auth = auth
        self._auditor = auditor
        self._intermediaries = intermediaries
        self._revoke_target = revoke_target
        self._child_tokens: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue the root, delegate to every intermediary, then attack.

        Example::

            await coordinator.on_start(ctx)
        """
        if not hasattr(self._auth, "delegate"):
            # Baseline (e.g. jwt) has no delegation concept: nothing downstream
            # can ever happen. That silence is the gap the validators catch.
            return

        from nest_plugins_reference.auth.delegatable_hmac import describe_token

        root = await self._auth.issue(self._id, ["read", "write", "admin"])
        root_id, _ = describe_token(root)
        await ctx.send(self._auditor, f"issued:{root_id}:{self._id}:read,write,admin".encode())

        for intermediary in self._intermediaries:
            child = await self._auth.delegate(root, intermediary, ["read", "write"], ttl=300.0)
            self._child_tokens[intermediary] = child
            child_id, _ = describe_token(child)
            await ctx.send(
                self._auditor,
                f"delegated:{child_id}:{root_id}:{intermediary}:read,write".encode(),
            )
            await ctx.send(intermediary, _token_payload(child))

        from nest_plugins_reference.auth.delegatable_hmac import ScopeEscalationError

        try:
            await self._auth.delegate(root, AgentId("mallory-scope"), _ESCALATION_SCOPES, ttl=60.0)
        except ScopeEscalationError:
            await ctx.send(self._auditor, f"delegate_blocked:scope_escalation:{root_id}".encode())

        await ctx.schedule(_REVOKE_AT, b"revoke_now")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Revoke the designated intermediary's token when the timer fires.

        Example::

            await coordinator.on_message(ctx, coordinator_id, b"revoke_now")
        """
        if payload != b"revoke_now":
            return
        token = self._child_tokens.get(self._revoke_target)
        if token is None:
            return

        from nest_plugins_reference.auth.delegatable_hmac import describe_token

        token_id, _ = describe_token(token)
        await self._auth.revoke(token)
        await ctx.send(self._auditor, f"revoked:{token_id}".encode())


class IntermediaryAgent(StateMachineAgent):
    """Delegates its token to 4 leaves, then verifies twice (before/after revoke).

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), auth=auth,
                                   auditor=AgentId("auditor-0"), leaves=[...])
    """

    def __init__(
        self,
        agent_id: AgentId,
        auth: Any,
        auditor: AgentId,
        leaves: list[AgentId],
    ) -> None:
        self._id = agent_id
        self._auth = auth
        self._auditor = auditor
        self._leaves = leaves
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle a token handoff (delegate onward) or a re-verify timer.

        Example::

            await intermediary.on_message(ctx, coordinator_id, token_payload)
        """
        if payload == b"verify_now":
            await self._verify_now(ctx)
            return

        token = _unwrap_token(payload)
        if token is None:
            return
        self._token = token

        from nest_plugins_reference.auth.delegatable_hmac import describe_token

        parent_id, _ = describe_token(token)
        for leaf in self._leaves:
            child = await self._auth.delegate(token, leaf, ["read"], ttl=120.0)
            child_id, _ = describe_token(child)
            await ctx.send(
                self._auditor,
                f"delegated:{child_id}:{parent_id}:{leaf}:read".encode(),
            )
            await ctx.send(leaf, _token_payload(child))

        await self._verify_now(ctx)
        await ctx.schedule(_REVERIFY_AT, b"verify_now")

    async def _verify_now(self, ctx: AgentContext) -> None:
        if self._token is None:
            return
        await ctx.send(
            self._auditor,
            f"verify_request|{self._id}|normal|{self._token}".encode(),
        )


class LeafAgent(StateMachineAgent):
    """Verifies its token twice; one designated leaf also probes audience confusion.

    Example::

        agent = LeafAgent(AgentId("leaf-0-0"), auditor=AgentId("auditor-0"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        decoy_presented_by: AgentId | None = None,
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._decoy_presented_by = decoy_presented_by
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle a token handoff (verify immediately) or a re-verify timer.

        Example::

            await leaf.on_message(ctx, intermediary_id, token_payload)
        """
        if payload == b"verify_now":
            await self._verify_now(ctx, check_kind="normal", presented_by=self._id)
            return

        token = _unwrap_token(payload)
        if token is None:
            return
        self._token = token
        await self._verify_now(ctx, check_kind="normal", presented_by=self._id)
        if self._decoy_presented_by is not None:
            await self._verify_now(
                ctx, check_kind="audience_attack", presented_by=self._decoy_presented_by
            )
        await ctx.schedule(_REVERIFY_AT, b"verify_now")

    async def _verify_now(self, ctx: AgentContext, check_kind: str, presented_by: AgentId) -> None:
        if self._token is None:
            return
        await ctx.send(
            self._auditor,
            f"verify_request|{presented_by}|{check_kind}|{self._token}".encode(),
        )


class AuditorAgent(StateMachineAgent):
    """Verifies every presented token and reports the outcome.

    All real verification happens here, offline from the delegation logic --
    the ``delegated_auth_hmac`` validators score only what this agent reports.

    Example::

        agent = AuditorAgent(AgentId("auditor-0"), auth=auth)
    """

    def __init__(self, agent_id: AgentId, auth: Any) -> None:
        self._id = agent_id
        self._auth = auth

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify a ``verify_request`` and ack the outcome; ignore everything else.

        Other breadcrumbs (``issued:``, ``delegated:``, ``delegate_blocked:``,
        ``revoked:``) are addressed here purely so they land in the trace as
        the sender's own ``send`` event; they need no reply.

        Example::

            await auditor.on_message(ctx, leaf_id, verify_request_payload)
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("verify_request|"):
            return
        _, presented_by, check_kind, token_str = msg.split("|", 3)
        token = cast("Token", token_str)

        from nest_plugins_reference.auth.delegatable_hmac import (
            AudienceMismatchError,
            RevokedAncestorError,
            describe_token,
        )

        token_id, _ = describe_token(token)
        try:
            await self._auth.verify(token, presented_by=AgentId(presented_by))
            outcome = "ok"
        except RevokedAncestorError:
            outcome = "revoked_ancestor"
        except AudienceMismatchError:
            outcome = "audience_mismatch"
        except ValueError as exc:
            outcome = "expired" if "expired" in str(exc) else "invalid_signature"
        await ctx.send(sender, f"verify_result:{token_id}:{check_kind}:{outcome}".encode())


def delegated_auth_hmac_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the coordinator / 3-intermediary / 12-leaf delegation tree.

    A single shared auth plugin instance is used by every agent -- revocation
    state and the signing secret must be shared for verification across
    agents to mean anything, unlike per-agent layers such as identity.

    Example::

        agents = delegated_auth_hmac_factory(config, plugins)
    """
    auth_cls = plugins["auth"]
    auth = auth_cls(secret=b"delegated-auth-scenario-secret", clock=0.0)

    auditor_id = AgentId("auditor-0")
    coordinator_id = AgentId("coordinator-0")
    intermediary_ids = [AgentId(f"intermediary-{i}") for i in range(3)]

    leaves_by_intermediary: dict[AgentId, list[AgentId]] = {
        intermediary_id: [AgentId(f"leaf-{i}-{j}") for j in range(4)]
        for i, intermediary_id in enumerate(intermediary_ids)
    }
    revoke_target = intermediary_ids[1]
    decoy_leaf = leaves_by_intermediary[intermediary_ids[0]][0]

    agents: dict[AgentId, StateMachineAgent] = {
        auditor_id: AuditorAgent(auditor_id, auth=auth),
        coordinator_id: CoordinatorAgent(
            coordinator_id,
            auth=auth,
            auditor=auditor_id,
            intermediaries=intermediary_ids,
            revoke_target=revoke_target,
        ),
    }
    for intermediary_id in intermediary_ids:
        agents[intermediary_id] = IntermediaryAgent(
            intermediary_id,
            auth=auth,
            auditor=auditor_id,
            leaves=leaves_by_intermediary[intermediary_id],
        )
    for leaves in leaves_by_intermediary.values():
        for leaf_id in leaves:
            decoy = AgentId("leaf-decoy-target") if leaf_id == decoy_leaf else None
            agents[leaf_id] = LeafAgent(leaf_id, auditor=auditor_id, decoy_presented_by=decoy)
    return agents
