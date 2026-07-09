# SPDX-License-Identifier: Apache-2.0
"""Delegated-capability scenario: a coordinator builds a delegation tree and
stages the three attacks the ``delegatable`` auth plugin is built to defeat.

Topology: one ``coordinator`` roots a delegation tree over three
``intermediary`` agents, each of which sub-delegates to four ``leaf`` agents
(twelve leaves total), plus one ``auditor`` sink that records the structured
trace lines the validators parse.

The coordinator resolves its auth plugin from ``ctx.plugins["auth"]`` and drives
the whole tree through it — *capability-gated* on ``hasattr(auth, "delegate")``:

* Under ``auth: delegatable`` the coordinator delegates real macaroon-style
  sub-tokens (scopes narrow at each hop) and every staged attack is rejected by
  the plugin, so each ``attack:*`` line records ``blocked``.
* Under ``auth: jwt`` (the default) there is no ``delegate``; the coordinator
  falls back to independent ``issue`` calls, which is the honest picture of
  what JWT can express. Each attack then succeeds — an agent mints itself
  broader scopes (no delegation constraint), a revoked parent leaves its
  separately-issued child usable, and a token has no audience to bind — so each
  ``attack:*`` line records ``accepted`` and the validators fail.

That contrast is the point: the same scenario **passes** under ``delegatable``
and **fails** under ``jwt``, with no change to the driver.

Every security decision runs locally against the shared plugin at tick 0, so the
trace is byte-deterministic under any seed regardless of message drop; the
``grant:``/``ack:`` chatter between agents exists only to exercise the transport.

Trace line protocol (message bodies, ``:``-delimited; scope lists are
``,``-joined):

* ``deleg:<parent>:<child>:ok`` — a successful delegation (or issue) hop.
* ``verify:<agent>:ok`` — an honest leaf token verified for its own audience.
* ``revoke:<agent>`` — the coordinator revoked an agent's token.
* ``attack:escalation:<agent>:<blocked|accepted>`` — agent tried to gain a
  scope broader than it was delegated.
* ``attack:audience:<agent>:<blocked|accepted>`` — agent presented a token
  bound to a different audience.
* ``attack:revoke:<agent>:<blocked|accepted>`` — agent used a token whose
  ancestor was revoked.

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

_ROOT_SCOPES = ["tool:exec", "tool:read", "tool:write"]


async def _grant(
    auth: Any,
    *,
    delegation_aware: bool,
    parent: Token,
    audience: AgentId,
    scopes: list[str],
    ttl: float,
) -> Token:
    """Delegate a narrower sub-token, or (JWT fallback) issue an independent one.

    Example::

        tok = await _grant(auth, delegation_aware=True, parent=root,
                           audience=AgentId("i0"), scopes=["tool:read"], ttl=100.0)
    """
    if delegation_aware:
        return await auth.delegate(parent, audience, scopes, ttl)
    return await auth.issue(audience, scopes)


async def _attempt_escalation(
    auth: Any, *, delegation_aware: bool, held: Token, agent: AgentId, broader: list[str]
) -> str:
    """Try to obtain ``broader`` scopes than ``held`` grants; return the outcome.

    Example::

        outcome = await _attempt_escalation(auth, delegation_aware=True,
            held=leaf_tok, agent=AgentId("leaf-0"), broader=_ROOT_SCOPES)
    """
    try:
        if delegation_aware:
            token = await auth.delegate(held, agent, broader, 50.0)
        else:
            token = await auth.issue(agent, broader)
        ctx = await auth.verify(token)
        return "accepted" if set(broader).issubset(set(ctx.scopes)) else "blocked"
    except ValueError:
        return "blocked"


async def _attempt_audience(
    auth: Any, *, delegation_aware: bool, token: Token, intruder: AgentId
) -> str:
    """Present ``token`` (bound to someone else) as ``intruder``; return outcome.

    Example::

        outcome = await _attempt_audience(auth, delegation_aware=True,
            token=worker_tok, intruder=AgentId("leaf-9"))
    """
    try:
        if delegation_aware:
            await auth.verify(token, presenter=intruder)
        else:
            await auth.verify(token)  # JWT has no audience binding to check
        return "accepted"
    except ValueError:
        return "blocked"


async def _attempt_use_after_revoke(
    auth: Any, *, delegation_aware: bool, token: Token, presenter: AgentId
) -> str:
    """Use ``token`` after an ancestor was revoked; return the outcome.

    Example::

        outcome = await _attempt_use_after_revoke(auth, delegation_aware=True,
            token=leaf_tok, presenter=AgentId("leaf-8"))
    """
    try:
        if delegation_aware:
            await auth.verify(token, presenter=presenter)
        else:
            await auth.verify(token)
        return "accepted"
    except ValueError:
        return "blocked"


class CoordinatorAgent(StateMachineAgent):
    """Roots the delegation tree and stages all three attacks against the plugin.

    All delegation and attack logic runs in :meth:`on_start` at tick 0 against
    the shared auth instance in ``ctx.plugins["auth"]``, so the emitted trace is
    deterministic. Subtree 0 stages scope-escalation attacks, subtree 1 stages
    audience-confusion attacks, and subtree 2 stages use-after-revoke attacks.

    Example::

        coord = CoordinatorAgent(AgentId("coordinator"), AgentId("auditor-0"),
            {AgentId("i0"): [AgentId("leaf-0")]})
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        tree: dict[AgentId, list[AgentId]],
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._tree = tree

    async def _emit(self, ctx: AgentContext, line: str) -> None:
        await ctx.send(self._auditor, line.encode())

    async def on_start(self, ctx: AgentContext) -> None:
        """Build the delegation tree and stage the attack suite.

        Example::

            await coord.on_start(ctx)
        """
        auth = ctx.plugins.get("auth")
        if auth is None:  # pragma: no cover - scenario always configures auth
            return
        delegation_aware = hasattr(auth, "delegate")
        if hasattr(auth, "set_clock"):
            auth.set_clock(ctx.time)

        root = await auth.issue(self._id, _ROOT_SCOPES)

        # -- Build the tree: each intermediary drops one scope; each leaf holds one.
        interm_tokens: dict[AgentId, Token] = {}
        interm_scopes: dict[AgentId, list[str]] = {}
        leaf_tokens: dict[AgentId, Token] = {}

        subtrees = list(self._tree.items())
        for idx, (interm, leaves) in enumerate(subtrees):
            dropped = _ROOT_SCOPES[idx % len(_ROOT_SCOPES)]
            iscopes = [s for s in _ROOT_SCOPES if s != dropped] or [_ROOT_SCOPES[0]]
            itok = await _grant(
                auth,
                delegation_aware=delegation_aware,
                parent=root,
                audience=interm,
                scopes=iscopes,
                ttl=500.0,
            )
            interm_tokens[interm] = itok
            interm_scopes[interm] = iscopes
            await self._emit(ctx, f"deleg:{self._id}:{interm}:ok")
            await ctx.send(interm, f"grant:{','.join(iscopes)}".encode())

            for lidx, leaf in enumerate(leaves):
                lscope = [iscopes[lidx % len(iscopes)]]
                ltok = await _grant(
                    auth,
                    delegation_aware=delegation_aware,
                    parent=itok,
                    audience=leaf,
                    scopes=lscope,
                    ttl=100.0,
                )
                leaf_tokens[leaf] = ltok
                await self._emit(ctx, f"deleg:{interm}:{leaf}:ok")
                if (
                    await _attempt_use_after_revoke(
                        auth, delegation_aware=delegation_aware, token=ltok, presenter=leaf
                    )
                    == "accepted"
                ):
                    await self._emit(ctx, f"verify:{leaf}:ok")

        # -- Attack subtree 0: scope escalation (leaves try to widen to root scopes).
        _, esc_leaves = subtrees[0]
        for leaf in esc_leaves:
            outcome = await _attempt_escalation(
                auth,
                delegation_aware=delegation_aware,
                held=leaf_tokens[leaf],
                agent=leaf,
                broader=_ROOT_SCOPES,
            )
            await self._emit(ctx, f"attack:escalation:{leaf}:{outcome}")

        # -- Attack subtree 1: audience confusion (a subtree-0 leaf poses as each holder).
        _, aud_leaves = subtrees[1]
        intruder = esc_leaves[0]
        for leaf in aud_leaves:
            outcome = await _attempt_audience(
                auth,
                delegation_aware=delegation_aware,
                token=leaf_tokens[leaf],
                intruder=intruder,
            )
            await self._emit(ctx, f"attack:audience:{intruder}:{outcome}")

        # -- Attack subtree 2: use-after-revoke (revoke the intermediary, use leaves).
        rev_interm, rev_leaves = subtrees[2]
        await auth.revoke(interm_tokens[rev_interm])
        await self._emit(ctx, f"revoke:{rev_interm}")
        for leaf in rev_leaves:
            outcome = await _attempt_use_after_revoke(
                auth,
                delegation_aware=delegation_aware,
                token=leaf_tokens[leaf],
                presenter=leaf,
            )
            await self._emit(ctx, f"attack:revoke:{leaf}:{outcome}")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Coordinator ignores replies; all logic ran in ``on_start``.

        Example::

            await coord.on_message(ctx, AgentId("i0"), b"ack:")
        """
        return


class TreeAgent(StateMachineAgent):
    """Intermediary or leaf: acks grants so the transport carries real traffic.

    Holds no security logic — the coordinator drives every delegation and attack
    against the shared plugin. This agent exists to give the scenario its tree
    shape and to make message-drop/partition injection observable in the trace.

    Example::

        node = TreeAgent(AgentId("i0"), AgentId("coordinator"))
    """

    def __init__(self, agent_id: AgentId, coordinator: AgentId) -> None:
        self._id = agent_id
        self._coordinator = coordinator

    async def on_start(self, ctx: AgentContext) -> None:
        """No-op; tree agents are driven by the coordinator's grants.

        Example::

            await node.on_start(ctx)
        """
        return

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Acknowledge a grant back to its sender.

        Example::

            await node.on_message(ctx, AgentId("coordinator"), b"grant:tool:read")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("grant:"):
            await ctx.send(sender, f"ack:{self._id}".encode())


class AuditorAgent(StateMachineAgent):
    """Sink for the coordinator's structured lines; the trace is the audit log.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_start(self, ctx: AgentContext) -> None:
        """No-op; the auditor only receives.

        Example::

            await auditor.on_start(ctx)
        """
        return

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Record-only; validators read the emitted lines from the trace.

        Example::

            await auditor.on_message(ctx, AgentId("coordinator"), b"deleg:a:b:ok")
        """
        return


def _provision_auth(plugins: dict[str, Any], coordinator: AgentId) -> None:
    """Instantiate one shared auth plugin and hand it to the coordinator.

    Mirrors the identity-rotation scenario's per-agent provisioning: resolve the
    configured auth class, build a single clock-pinned instance (so its
    revocation set and MAC secret are shared), and stash it under
    ``plugins["_agent_plugins"]`` for the runner to apply. No-op when the auth
    plugin is already an instance or is absent.

    Example::

        _provision_auth(plugins, AgentId("coordinator"))
    """
    auth_cls = plugins.get("auth")
    if auth_cls is None or not isinstance(auth_cls, type):
        return
    auth = auth_cls(clock=0.0)
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    agent_plugins.setdefault(coordinator, {})["auth"] = auth
    plugins.pop("auth", None)


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create a coordinator, 3 intermediaries, 12 leaves, and an auditor.

    The tree shape is fixed (3 subtrees of 4 leaves) so the delegation depth and
    attack coverage are identical across seeds; only the transport chatter is
    seed-sensitive. Swapping ``auth: jwt`` for ``auth: delegatable`` in the YAML
    genuinely changes behaviour — the same driver stages the same attacks and
    the validators tell the two plugins apart.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    task_config = config.task.config
    intermediary_count = int(task_config.get("intermediaries", 3))
    leaves_per = int(task_config.get("leaves_per_intermediary", 4))

    coordinator_id = AgentId("coordinator")
    auditor_id = AgentId("auditor-0")

    tree: dict[AgentId, list[AgentId]] = {}
    leaf_index = 0
    for i in range(intermediary_count):
        interm = AgentId(f"intermediary-{i}")
        leaves: list[AgentId] = []
        for _ in range(leaves_per):
            leaves.append(AgentId(f"leaf-{leaf_index}"))
            leaf_index += 1
        tree[interm] = leaves

    _provision_auth(plugins, coordinator_id)

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator_id: CoordinatorAgent(coordinator_id, auditor_id, tree),
        auditor_id: AuditorAgent(auditor_id),
    }
    for interm, leaves in tree.items():
        agents[interm] = TreeAgent(interm, coordinator_id)
        for leaf in leaves:
            agents[leaf] = TreeAgent(leaf, coordinator_id)
    return agents
