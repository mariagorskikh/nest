# SPDX-License-Identifier: Apache-2.0
"""Delegation-tree scenario -- capability delegation with cascading revocation.

A coordinator issues a root capability token and delegates a narrower,
shorter-lived token to each of 3 intermediaries; each intermediary
delegates a further-narrowed token to 4 leaves. Strict tree, one parent per
token: coordinator -> 3 intermediaries -> 12 leaves.

Midway through the run the coordinator revokes exactly one intermediary's
token. All 4 leaves under that branch must fail re-verification with
``RevokedAncestorError`` on their *next* verify -- no leaf token is ever
revoked directly, demonstrating cascading revocation "by construction". The
other 8 leaves, under the two untouched branches, keep verifying.

Example::

    agents = delegation_tree_factory(config, plugins)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from nest_plugins_reference.auth.delegatable import RevokedAncestorError

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

if TYPE_CHECKING:
    from nest_plugins_reference.auth.delegatable import DelegatableAuth

GRANT_PREFIX = b"grant:"
RESULT_PREFIX = b"result:"
REVERIFY = b"reverify"
REVOKE_TICK = b"COORD_REVOKE_TICK"
REVERIFY_TICK = b"COORD_REVERIFY_TICK"

#: Scopes narrow strictly at every hop: root -> intermediary -> leaf.
ROOT_SCOPES = ["read", "write", "admin"]
INTERMEDIARY_SCOPES = ["read", "write"]
LEAF_SCOPES = ["read"]

#: TTLs narrow at every hop too, so a child never risks outliving its parent.
INTERMEDIARY_TTL = 1800.0
LEAF_TTL = 900.0


class CoordinatorAgent(StateMachineAgent):
    """Root of the delegation tree.

    Issues the root token, delegates one child per intermediary, then --
    on a scheduled tick -- revokes exactly one intermediary's token and
    asks every leaf to re-verify, collecting the outcomes into a shared
    report dict for the scenario factory (and tests) to inspect.
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        intermediary_ids: list[AgentId],
        all_leaf_ids: list[AgentId],
        revoke_intermediary: AgentId,
        revoke_delay: float,
        reverify_delay: float,
        report: dict[str, str],
    ) -> None:
        self._id = agent_id
        self._intermediary_ids = intermediary_ids
        self._all_leaf_ids = all_leaf_ids
        self._revoke_intermediary = revoke_intermediary
        self._revoke_delay = revoke_delay
        self._reverify_delay = reverify_delay
        self._report = report
        self._intermediary_tokens: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        auth = cast("DelegatableAuth", ctx.plugins["auth"])
        root_token = await auth.issue(self._id, list(ROOT_SCOPES))
        for inter_id in self._intermediary_ids:
            child = await auth.delegate(
                root_token, inter_id, list(INTERMEDIARY_SCOPES), INTERMEDIARY_TTL
            )
            self._intermediary_tokens[inter_id] = child
            await ctx.send(inter_id, GRANT_PREFIX + str(child).encode())
        await ctx.schedule(self._revoke_delay, REVOKE_TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if sender == ctx.agent_id and payload == REVOKE_TICK:
            auth = cast("DelegatableAuth", ctx.plugins["auth"])
            await auth.revoke(self._intermediary_tokens[self._revoke_intermediary])
            await ctx.schedule(self._reverify_delay, REVERIFY_TICK)
            return
        if sender == ctx.agent_id and payload == REVERIFY_TICK:
            for leaf_id in self._all_leaf_ids:
                await ctx.send(leaf_id, REVERIFY)
            return
        if payload.startswith(RESULT_PREFIX):
            _, status, leaf_id = payload.decode("utf-8").split(":", 2)
            self._report[leaf_id] = status


class IntermediaryAgent(StateMachineAgent):
    """Receives a delegated token from the coordinator and re-delegates to its leaves."""

    def __init__(self, agent_id: AgentId, *, leaf_ids: list[AgentId]) -> None:
        self._id = agent_id
        self._leaf_ids = leaf_ids

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if not payload.startswith(GRANT_PREFIX):
            return
        token = Token(payload[len(GRANT_PREFIX) :].decode("utf-8"))
        auth = cast("DelegatableAuth", ctx.plugins["auth"])
        await auth.verify_presented_by(token, ctx.agent_id)
        for leaf_id in self._leaf_ids:
            child = await auth.delegate(token, leaf_id, list(LEAF_SCOPES), LEAF_TTL)
            await ctx.send(leaf_id, GRANT_PREFIX + str(child).encode())


class LeafAgent(StateMachineAgent):
    """Holds a delegated token and reports its verification status on request."""

    def __init__(self, agent_id: AgentId, *, coordinator_id: AgentId) -> None:
        self._id = agent_id
        self._coordinator_id = coordinator_id
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if payload.startswith(GRANT_PREFIX):
            self._token = Token(payload[len(GRANT_PREFIX) :].decode("utf-8"))
            return
        if payload == REVERIFY:
            token = self._token
            if token is None:
                return
            auth = cast("DelegatableAuth", ctx.plugins["auth"])
            status = await self._check(auth, token, ctx.agent_id)
            await ctx.send(
                self._coordinator_id,
                RESULT_PREFIX + f"{status}:{ctx.agent_id}".encode(),
            )

    async def _check(self, auth: DelegatableAuth, token: Token, presenter: AgentId) -> str:
        try:
            await auth.verify_presented_by(token, presenter)
        except RevokedAncestorError:
            return "revoked"
        except Exception:  # noqa: BLE001 - any other failure is a distinct, reportable status
            return "error"
        return "ok"


def _instantiate_auth(plugins: dict[str, Any]) -> None:
    """Replace the resolved ``auth`` plugin class with one shared instance.

    Mirrors ``marketplace._instantiate_plugins``'s shared-instance pattern:
    every agent in the tree needs to verify tokens signed by the same
    secret and see the same revocation state, so one instance is
    constructed and handed to every agent context.

    Pins the plugin's clock (if it accepts one -- ``DelegatableAuth`` and
    ``JwtAuth`` both do) to a fixed value instead of leaving it on
    wall-clock time, so every ``issue``/``delegate`` call produces
    byte-identical caveat timestamps run over run. Falls back to the bare
    constructor for a plugin that does not accept ``clock``.

    Example::

        _instantiate_auth(plugins)
    """
    auth_cls = plugins.get("auth")
    if auth_cls is not None and isinstance(auth_cls, type):
        try:
            plugins["auth"] = auth_cls(clock=0.0)
        except TypeError:
            plugins["auth"] = auth_cls()


def delegation_tree_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create a coordinator -> 3 intermediaries -> 12 leaves delegation tree.

    ``config.task.config`` accepts ``revoke_intermediary_index`` (which of
    the 3 intermediary branches gets revoked, default 1),
    ``revoke_delay`` (ticks after start before revocation, default 50), and
    ``reverify_delay`` (ticks after revocation before leaves re-verify,
    default 100).

    Exposes ``plugins["_delegation_report"]`` (leaf id -> ``"ok"`` /
    ``"revoked"`` / ``"error"``, populated as the run progresses),
    ``plugins["_delegation_leaf_ids"]`` (all 12 leaf ids), and
    ``plugins["_delegation_revoked_leaf_ids"]`` (the 4 leaf ids under the
    revoked branch) so tests can inspect the outcome without parsing the
    trace.

    Example::

        agents = delegation_tree_factory(config, plugins)
    """
    task_config = config.task.config
    revoke_index = int(task_config.get("revoke_intermediary_index", 1))
    revoke_delay = float(task_config.get("revoke_delay", 50.0))
    reverify_delay = float(task_config.get("reverify_delay", 100.0))

    coordinator_id = AgentId("coordinator-0")
    intermediary_ids = [AgentId(f"intermediary-{i}") for i in range(3)]
    leaves_by_intermediary: dict[AgentId, list[AgentId]] = {
        inter_id: [AgentId(f"leaf-{i}-{j}") for j in range(4)]
        for i, inter_id in enumerate(intermediary_ids)
    }
    all_leaf_ids = [leaf_id for leaves in leaves_by_intermediary.values() for leaf_id in leaves]

    _instantiate_auth(plugins)

    report: dict[str, str] = {}
    revoked_intermediary = intermediary_ids[revoke_index]
    plugins["_delegation_report"] = report
    plugins["_delegation_leaf_ids"] = [str(a) for a in all_leaf_ids]
    plugins["_delegation_revoked_leaf_ids"] = [
        str(a) for a in leaves_by_intermediary[revoked_intermediary]
    ]

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator_id: CoordinatorAgent(
            coordinator_id,
            intermediary_ids=intermediary_ids,
            all_leaf_ids=all_leaf_ids,
            revoke_intermediary=revoked_intermediary,
            revoke_delay=revoke_delay,
            reverify_delay=reverify_delay,
            report=report,
        ),
    }
    for inter_id in intermediary_ids:
        agents[inter_id] = IntermediaryAgent(inter_id, leaf_ids=leaves_by_intermediary[inter_id])
    for leaf_id in all_leaf_ids:
        agents[leaf_id] = LeafAgent(leaf_id, coordinator_id=coordinator_id)

    return agents
