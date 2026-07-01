# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario — a delegation tree with a cascading revocation.

Topology (see ``scenarios/delegated_auth.yaml``):

* ``coordinator-0`` holds the root capability ``{read, write, admin}``.
* ``intermediary-0..2`` each receive a *narrowed*, time-bounded sub-capability
  minted by the coordinator with :meth:`DelegatableAuth.delegate` — no issuer
  round-trip.
* ``leaf-0..11`` (four under each intermediary) receive a further-narrowed
  ``{read}`` capability from their intermediary and verify it, bound to their
  own identity via :meth:`DelegatableAuth.verify_presented`.

The run has two phases, ordered by the simulator's logical clock:

1. **Grant + verify** (tick 0): the tree is built top-down and every leaf
   verifies its capability.  All 12 succeed.
2. **Cascading revocation** (``revoke_at`` tick): the coordinator revokes the
   *middle* intermediary's token and asks every leaf to re-verify.  The four
   leaves under the revoked intermediary now fail with
   ``RevokedAncestorError`` — by construction, because their chains embed the
   revoked ancestor id — while the other eight still succeed.

Every agent shares the one resolved ``DelegatableAuth`` instance (the auth
authority), so a revocation is globally visible.  Verify outcomes are written
to a shared ledger exposed on the plugins dict as ``_auth_ledger`` so tests can
assert the cascade end-to-end.

Example::

    from nest_core.runner import ScenarioRunner
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml"))
    await runner.run()
    ledger = runner.resolved_plugins["_auth_ledger"]
    assert all(ok for _, ok, _ in ledger["initial"])
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

TAG_DELEGATE = b"DLG:"
"""Coordinator → intermediary: carries the intermediary's sub-capability token."""

TAG_VERIFY = b"VFY:"
"""Intermediary → leaf: carries the leaf's capability token to verify + store."""

TAG_REVERIFY = b"RVF"
"""Coordinator → all: re-verify your stored token (post-revocation probe)."""

TAG_REVOKE_TICK = b"RVK"
"""Coordinator self-message: time to revoke the middle subtree."""

ROOT_SCOPES = ["admin", "read", "write"]
"""Scopes held by the root capability minted for the coordinator."""

INTERMEDIARY_SCOPES = ["read", "write"]
"""Scopes each intermediary receives — a strict narrowing of the root."""

LEAF_SCOPES = ["read"]
"""Scopes each leaf receives — a further narrowing of its intermediary's grant."""

DEFAULT_CHILD_TTL = 100_000
"""Delegation lifetime (logical ticks); large so nothing expires mid-scenario."""

DEFAULT_REVOKE_AT = 100
"""Logical tick at which the coordinator revokes the middle intermediary."""


def _err_name(exc: Exception) -> str:
    """Return the exception's class name, for compact ledger records.

    Example::

        assert _err_name(ValueError("x")) == "ValueError"
    """
    return type(exc).__name__


class CoordinatorAgent(StateMachineAgent):
    """Root-capability holder that seeds the tree and later revokes a subtree.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"), ["intermediary-0"], 1, 100, 100000)
    """

    def __init__(
        self,
        agent_id: AgentId,
        intermediaries: list[AgentId],
        revoke_index: int,
        revoke_at: int,
        child_ttl: int,
    ) -> None:
        self._id = agent_id
        self._intermediaries = intermediaries
        self._revoke_index = revoke_index
        self._revoke_at = revoke_at
        self._child_ttl = child_ttl
        self._child_tokens: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Mint the root, delegate to each intermediary, and arm the revoke tick.

        Example::

            await agent.on_start(ctx)
        """
        auth = ctx.plugins.get("auth")
        if auth is None:
            return
        root = await auth.issue(self._id, list(ROOT_SCOPES))
        self._root: Token = root
        for interm in self._intermediaries:
            child = await auth.delegate(root, interm, list(INTERMEDIARY_SCOPES), self._child_ttl)
            self._child_tokens[interm] = child
            await ctx.send(interm, TAG_DELEGATE + str(child).encode())
        await ctx.schedule(float(self._revoke_at), TAG_REVOKE_TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the revoke self-tick: revoke the middle subtree, ask all to re-verify.

        Example::

            await agent.on_message(ctx, ctx.agent_id, TAG_REVOKE_TICK)
        """
        if sender != self._id or payload != TAG_REVOKE_TICK:
            return
        auth = ctx.plugins.get("auth")
        if auth is None:
            return
        target = self._intermediaries[self._revoke_index]
        await auth.revoke(self._child_tokens[target])
        await ctx.broadcast(TAG_REVERIFY)


class IntermediaryAgent(StateMachineAgent):
    """Holds a delegated capability and sub-delegates ``{read}`` to its leaves.

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), [AgentId("leaf-0")], 100000)
    """

    def __init__(self, agent_id: AgentId, leaves: list[AgentId], child_ttl: int) -> None:
        self._id = agent_id
        self._leaves = leaves
        self._child_ttl = child_ttl

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On receiving my capability, mint and hand out each leaf's token.

        Example::

            await agent.on_message(ctx, AgentId("coordinator-0"), TAG_DELEGATE + b"...")
        """
        if not payload.startswith(TAG_DELEGATE):
            return
        auth = ctx.plugins.get("auth")
        if auth is None:
            return
        my_token = Token(payload[len(TAG_DELEGATE) :].decode())
        for leaf in self._leaves:
            leaf_tok = await auth.delegate(my_token, leaf, list(LEAF_SCOPES), self._child_ttl)
            await ctx.send(leaf, TAG_VERIFY + str(leaf_tok).encode())


class LeafAgent(StateMachineAgent):
    """Receives a capability, verifies it bound to itself, re-verifies on request.

    Example::

        agent = LeafAgent(AgentId("leaf-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._token: Token | None = None

    async def _verify_into(self, ctx: AgentContext, phase: str) -> None:
        auth = ctx.plugins.get("auth")
        ledger = ctx.plugins.get("_auth_ledger")
        if auth is None or ledger is None or self._token is None:
            return
        try:
            await auth.verify_presented(self._token, self._id)
            ledger[phase].append((str(self._id), True, None))
        except Exception as exc:  # noqa: BLE001 - record the typed failure, don't crash the sim
            ledger[phase].append((str(self._id), False, _err_name(exc)))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Store + verify on first grant; re-verify when the coordinator asks.

        Example::

            await agent.on_message(ctx, AgentId("intermediary-0"), TAG_VERIFY + b"...")
        """
        if payload.startswith(TAG_VERIFY):
            self._token = Token(payload[len(TAG_VERIFY) :].decode())
            await self._verify_into(ctx, "initial")
        elif payload == TAG_REVERIFY:
            await self._verify_into(ctx, "after_revoke")


def delegated_auth_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build the coordinator / intermediary / leaf fleet for the delegation tree.

    Leaves are partitioned evenly across intermediaries by index.  A shared
    ``_auth_ledger`` dict is stashed on ``plugins`` so the harness and tests can
    read every verify outcome after the run.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    task_cfg = config.task.config or {}
    child_ttl = int(task_cfg.get("child_ttl", DEFAULT_CHILD_TTL))
    revoke_at = int(task_cfg.get("revoke_at", DEFAULT_REVOKE_AT))
    revoke_index = int(task_cfg.get("revoke_index", 1))

    counts: dict[str, int] = {role.name: role.count for role in config.agents.roles}
    n_coord = counts.get("coordinator", 1)
    n_interm = counts.get("intermediary", 3)
    n_leaf = counts.get("leaf", 12)

    coordinator = AgentId("coordinator-0")
    intermediaries = [AgentId(f"intermediary-{i}") for i in range(n_interm)]
    leaves = [AgentId(f"leaf-{i}") for i in range(n_leaf)]

    per_interm = n_leaf // n_interm if n_interm else 0
    leaves_of: dict[AgentId, list[AgentId]] = {interm: [] for interm in intermediaries}
    for idx, leaf in enumerate(leaves):
        owner_idx = min(idx // per_interm, n_interm - 1) if per_interm else 0
        leaves_of[intermediaries[owner_idx]].append(leaf)

    # ``PluginRegistry.resolve`` yields the plugin *class*, so instantiate one
    # shared authority here and inject it as the concrete ``auth`` instance for
    # every agent — a single instance means a revocation is globally visible.
    from nest_plugins_reference.auth.delegatable import DelegatableAuth

    plugins["auth"] = DelegatableAuth(root_ttl=max(child_ttl * 2, 1_000_000))
    plugins["_auth_ledger"] = {"initial": [], "after_revoke": []}

    agents: dict[AgentId, Any] = {}
    if n_coord:
        agents[coordinator] = CoordinatorAgent(
            coordinator,
            intermediaries,
            revoke_index=min(revoke_index, max(n_interm - 1, 0)),
            revoke_at=revoke_at,
            child_ttl=child_ttl,
        )
    for interm in intermediaries:
        agents[interm] = IntermediaryAgent(interm, leaves_of[interm], child_ttl=child_ttl)
    for leaf in leaves:
        agents[leaf] = LeafAgent(leaf)
    return agents
