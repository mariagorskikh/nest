# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario — a coordinator, 3 intermediaries, 12 leaf agents.

Topology (matches the problem brief's required shape exactly):

* ``coordinator-0`` mints a root capability token and delegates a narrowed
  copy to each of 3 intermediaries.
* Each ``intermediary-<i>`` (0..2) further narrows its scopes and delegates
  to its 4 leaves, ``leaf-<i>-<j>`` (j 0..3) — 12 leaves total.
* Every leaf verifies its own grant with :meth:`~DelegatableAuth.verify_with_audience`
  and reports the outcome back to the coordinator.
* One leaf (``task.config.byzantine_leaf_index``, default the last leaf)
  is byzantine: it holds a perfectly valid token but reports it under a
  *different* agent's identity — the audience-confusion attack — and its
  report is expected to come back rejected.

All three plugin-required attacks (scope escalation, stale-parent use,
audience confusion) are proven adversarially in
``nest_plugins_reference.validators.delegation_validators`` and
``tests/test_delegation_validators.py`` (fails against ``jwt``, passes
against ``delegatable``); this scenario's job is the *topology* the problem
brief asks for, plus one live demonstration of the audience check firing
inside the simulator itself.

``ctx.plugins["auth"]`` is a **class**, not an instance (see how
``identity_rotation.py`` has to provision identities itself for the same
reason). A delegation chain is only verifiable by whoever holds the *same*
root secret, so every agent here needs a reference to *one* shared
authority instance, not sixteen independently-keyed ones — this factory
builds that single instance and installs it as a per-agent override for
every agent via ``plugins["_agent_plugins"]``, mirroring
``_provision_identities``'s pattern exactly.

Example::

    from nest_core.runner import ScenarioRunner
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml"))
    await runner.run()
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

if TYPE_CHECKING:
    from nest_core.types import AuthContext

INTERMEDIARY_COUNT = 3
LEAVES_PER_INTERMEDIARY = 4
ROOT_SCOPES: list[str] = ["read", "write", "deploy", "admin"]
INTERMEDIARY_SCOPES: list[str] = ["read", "write", "deploy"]
LEAF_SCOPES: list[str] = ["read"]
GRANT_PREFIX = b"grant:"
REPORT_PREFIX = b"report:"
DEFAULT_TTL = 3000.0


def _sync_clock(ctx: AgentContext) -> Any:
    """Return the shared auth plugin, synced to the simulator's logical clock.

    Mirrors the ``hasattr(ident, "set_clock")`` convention from
    ``identity_rotation.py`` so tokens are minted/verified against the
    deterministic simulation clock, never wall-clock time.

    Example::

        auth = _sync_clock(ctx)
        token = await auth.issue(ctx.agent_id, ["read"])
    """
    auth = ctx.plugins.get("auth")
    if auth is not None and hasattr(auth, "set_clock"):
        auth.set_clock(ctx.time)
    return auth


class CoordinatorAgent(StateMachineAgent):
    """Mints the root token, delegates to every intermediary, tallies reports.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"), intermediary_ids=[...])
    """

    def __init__(self, agent_id: AgentId, intermediary_ids: list[AgentId]) -> None:
        self._id = agent_id
        self._intermediary_ids = intermediary_ids
        self._reports_received = 0

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue the root token and delegate one child per intermediary.

        Example::

            await agent.on_start(ctx)
        """
        auth = _sync_clock(ctx)
        root = await auth.issue(self._id, ROOT_SCOPES)
        for intermediary_id in self._intermediary_ids:
            child = await auth.delegate(root, intermediary_id, INTERMEDIARY_SCOPES, ttl=DEFAULT_TTL)
            await ctx.send(intermediary_id, GRANT_PREFIX + str(child).encode("utf-8"))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Tally leaf verification reports (observability only; no branching logic).

        Example::

            await agent.on_message(ctx, leaf_id, b"report:leaf-0-0:ok:['read']")
        """
        if payload.startswith(REPORT_PREFIX):
            self._reports_received += 1


class IntermediaryAgent(StateMachineAgent):
    """Receives a delegated grant, narrows it further, delegates to its leaves.

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), leaf_ids=[...])
    """

    def __init__(self, agent_id: AgentId, leaf_ids: list[AgentId]) -> None:
        self._id = agent_id
        self._leaf_ids = leaf_ids

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Delegate a leaf-scoped child token to each leaf on receiving a grant.

        Example::

            await agent.on_message(ctx, coordinator_id, b"grant:<token-json>")
        """
        if not payload.startswith(GRANT_PREFIX):
            return
        auth = _sync_clock(ctx)
        parent = Token(payload[len(GRANT_PREFIX) :].decode("utf-8"))
        for leaf_id in self._leaf_ids:
            child = await auth.delegate(parent, leaf_id, LEAF_SCOPES, ttl=DEFAULT_TTL / 2)
            await ctx.send(leaf_id, GRANT_PREFIX + str(child).encode("utf-8"))


class LeafAgent(StateMachineAgent):
    """Verifies its own grant and reports the outcome to the coordinator.

    A byzantine leaf (``impersonate_as`` set) presents its *genuine* token
    under a different agent's identity — the audience-confusion attack — and
    is expected to be rejected by :meth:`~DelegatableAuth.verify_with_audience`.

    Example::

        agent = LeafAgent(AgentId("leaf-0-0"), coordinator_id=AgentId("coordinator-0"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        coordinator_id: AgentId,
        impersonate_as: AgentId | None = None,
    ) -> None:
        self._id = agent_id
        self._coordinator_id = coordinator_id
        self._impersonate_as = impersonate_as

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify the received grant (honestly, or under a spoofed identity) and report.

        Example::

            await agent.on_message(ctx, intermediary_id, b"grant:<token-json>")
        """
        if not payload.startswith(GRANT_PREFIX):
            return
        auth = _sync_clock(ctx)
        token = Token(payload[len(GRANT_PREFIX) :].decode("utf-8"))
        presented_as = self._impersonate_as or self._id
        try:
            ctx_result: AuthContext = await auth.verify_with_audience(token, presented_as)
        except ValueError as exc:
            report = f"{self._id}:rejected:{exc}"
        else:
            report = f"{self._id}:ok:{sorted(ctx_result.scopes)}"
        await ctx.send(self._coordinator_id, REPORT_PREFIX + report.encode("utf-8"))


def _provision_shared_auth(plugins: dict[str, Any], agent_ids: list[AgentId]) -> None:
    """Install one shared ``DelegatableAuth`` instance as every agent's auth override.

    Mirrors ``identity_rotation.py``'s ``_provision_identities``: resolve the
    class at ``plugins["auth"]``, build exactly one instance (a delegation
    chain is only verifiable against the secret that minted its root), and
    stash it under ``plugins["_agent_plugins"][agent_id]["auth"]`` for every
    agent so the runner's per-agent merge picks it up in place of the class.
    No-op when no auth plugin is configured, or when it isn't a class (e.g.
    already an instance from a different override path).

    Example::

        _provision_shared_auth(plugins, [coordinator_id, *intermediary_ids])
    """
    auth_cls = plugins.get("auth")
    if auth_cls is None or not isinstance(auth_cls, type):
        return
    shared_auth = auth_cls()
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    for agent_id in agent_ids:
        agent_plugins.setdefault(agent_id, {})["auth"] = shared_auth
    plugins.pop("auth", None)


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the coordinator + 3 intermediaries + 12 leaves delegation tree.

    ``task.config.byzantine_leaf_index`` (default: the last leaf, index 11)
    selects which leaf attempts the audience-confusion attack against the
    coordinator's own identity.

    Example::

        agents = delegated_auth_factory(config, plugins)
        assert len(agents) == 1 + INTERMEDIARY_COUNT + INTERMEDIARY_COUNT * LEAVES_PER_INTERMEDIARY
    """
    task_config = config.task.config
    byzantine_leaf_index = int(
        task_config.get("byzantine_leaf_index", INTERMEDIARY_COUNT * LEAVES_PER_INTERMEDIARY - 1)
    )

    coordinator_id = AgentId("coordinator-0")
    intermediary_ids = [AgentId(f"intermediary-{i}") for i in range(INTERMEDIARY_COUNT)]

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator_id: CoordinatorAgent(coordinator_id, intermediary_ids=intermediary_ids)
    }

    all_ids = [coordinator_id, *intermediary_ids]
    leaf_counter = 0
    for i, intermediary_id in enumerate(intermediary_ids):
        leaf_ids = [AgentId(f"leaf-{i}-{j}") for j in range(LEAVES_PER_INTERMEDIARY)]
        agents[intermediary_id] = IntermediaryAgent(intermediary_id, leaf_ids=leaf_ids)
        for leaf_id in leaf_ids:
            impersonate_as = coordinator_id if leaf_counter == byzantine_leaf_index else None
            agents[leaf_id] = LeafAgent(
                leaf_id, coordinator_id=coordinator_id, impersonate_as=impersonate_as
            )
            all_ids.append(leaf_id)
            leaf_counter += 1

    _provision_shared_auth(plugins, all_ids)
    return agents
