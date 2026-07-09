# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario: a coordinator hands out cascading capability tokens.

A three-level delegation tree exercises the delegatable auth plugin end to end:

    coordinator ──delegate──▶ 3 intermediaries ──delegate──▶ 12 leaves (4 each)

The coordinator holds a root token and, without going back to any issuer, mints
narrower sub-tokens for the intermediaries; each intermediary mints still
narrower tokens for its leaves. The coordinator then runs a **verify sweep**
(every leaf presents its own token — all accepted; impostors presenting someone
else's token — all rejected), **revokes one intermediary**, and runs the sweep
again: the revoked intermediary's whole subtree now fails to verify while every
other agent is untouched. That is cascading revocation.

Every delegation, revocation, and verify outcome is written to the trace so the
offline validators (`validate_delegated_auth_*`) can reconstruct the tree and
check scope narrowing, cascading revocation, and audience binding. Frame grammar
(scopes are ``|``-joined so they never collide with the ``:`` delimiter)::

    dauth:issue:<owner>:<scope|scope|...>
    dauth:delegate:<parent>:<child>:<scope|scope|...>
    dauth:verify:<presenter>:<owner>:<ok|fail>:<pre|post>
    dauth:revoke:<owner>

The coordinator drives the whole exchange synchronously in ``on_start`` against a
single auth instance seeded with ``clock=0.0``, so the same seed yields a
byte-identical trace.

Example::

    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig

    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml"))
    await runner.run()
"""

from __future__ import annotations

import random
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

N_INTERMEDIARIES = 3
"""Number of intermediary agents directly under the coordinator."""

LEAVES_PER_INTERMEDIARY = 4
"""Leaf agents delegated from each intermediary (3 x 4 = 12 leaves)."""

ROOT_SCOPES = ["admin", "pay", "read", "write"]
"""The coordinator's root capabilities (sorted; the widest scope set)."""

INTERMEDIARY_SCOPES = [
    ["read", "write", "pay"],
    ["read", "write"],
    ["read", "pay"],
]
"""Scope grant for each intermediary — each a strict subset of ``ROOT_SCOPES``."""

CHILD_TTL = 600.0
"""Lifetime (seconds) of an intermediary token; leaves clamp to <= this."""

LEAF_TTL = 300.0
"""Requested lifetime (seconds) of a leaf token; clamped to its parent's expiry."""

REVOKED_INTERMEDIARY = 1
"""Index of the intermediary the coordinator revokes to demonstrate cascading."""


def _scopes_frame(scopes: list[str]) -> str:
    """Join scopes with ``|`` for embedding in a ``:``-delimited trace frame."""
    return "|".join(scopes)


class TreeAgent(StateMachineAgent):
    """A passive node (intermediary or leaf) that only needs to be addressable.

    The coordinator drives all delegation and verification; these agents exist so
    the coordinator's ``ctx.send`` frames have real destinations.

    Example::

        agent = TreeAgent(AgentId("int-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id


class CoordinatorAgent(StateMachineAgent):
    """Root of the delegation tree; builds it, sweeps it, revokes, sweeps again.

    Holds a single delegatable auth instance and the deterministic per-leaf scope
    choices, and performs the whole protocol in ``on_start`` so the trace is a
    faithful, replayable record of a cascading-revocation run.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator"), auth, leaf_scopes)
    """

    def __init__(
        self,
        coordinator_id: AgentId,
        auth: Any,
        leaf_scopes: dict[AgentId, list[str]],
    ) -> None:
        self._id = coordinator_id
        self._auth = auth
        self._leaf_scopes = leaf_scopes

    def _intermediary_id(self, idx: int) -> AgentId:
        return AgentId(f"int-{idx}")

    def _leaf_id(self, idx: int, jdx: int) -> AgentId:
        return AgentId(f"leaf-{idx}-{jdx}")

    async def _emit(self, ctx: AgentContext, to: AgentId, frame: str) -> None:
        await ctx.send(to, frame.encode())

    async def _verify_probe(
        self, ctx: AgentContext, token: Token, presenter: AgentId, owner: AgentId, phase: str
    ) -> None:
        """Verify *token* as *presenter* and record the ok/fail outcome to the trace."""
        try:
            await self._auth.verify(token, presenter=presenter)
            outcome = "ok"
        except Exception:  # noqa: BLE001 - any failure is recorded as a rejected verify
            outcome = "fail"
        await self._emit(ctx, owner, f"dauth:verify:{presenter}:{owner}:{outcome}:{phase}")

    async def on_start(self, ctx: AgentContext) -> None:
        """Build the delegation tree, sweep it, revoke one branch, sweep again.

        Example::

            await coordinator.on_start(ctx)
        """
        # Root token: the coordinator's full capability set.
        root = await self._auth.issue(self._id, ROOT_SCOPES)
        await self._emit(ctx, self._id, f"dauth:issue:{self._id}:{_scopes_frame(ROOT_SCOPES)}")

        int_tokens: dict[AgentId, Token] = {}
        leaf_tokens: dict[AgentId, tuple[AgentId, Token]] = {}

        # Level 1: delegate a narrower token to each intermediary.
        for i in range(N_INTERMEDIARIES):
            int_id = self._intermediary_id(i)
            scopes = sorted(set(INTERMEDIARY_SCOPES[i]))
            token = await self._auth.delegate(root, int_id, scopes, CHILD_TTL)
            int_tokens[int_id] = token
            await self._emit(
                ctx, int_id, f"dauth:delegate:{self._id}:{int_id}:{_scopes_frame(scopes)}"
            )

            # Level 2: each intermediary delegates to its leaves.
            for j in range(LEAVES_PER_INTERMEDIARY):
                leaf_id = self._leaf_id(i, j)
                leaf_scopes = self._leaf_scopes[leaf_id]
                leaf_token = await self._auth.delegate(token, leaf_id, leaf_scopes, LEAF_TTL)
                leaf_tokens[leaf_id] = (int_id, leaf_token)
                await self._emit(
                    ctx,
                    leaf_id,
                    f"dauth:delegate:{int_id}:{leaf_id}:{_scopes_frame(leaf_scopes)}",
                )

        # Pre-revocation sweep: every leaf presents its own token (accepted) and
        # an impostor presents it (rejected by audience binding).
        for leaf_id, (_int_id, leaf_token) in leaf_tokens.items():
            await self._verify_probe(ctx, leaf_token, leaf_id, leaf_id, "pre")
            impostor = AgentId(f"impostor-of-{leaf_id}")
            await self._verify_probe(ctx, leaf_token, impostor, leaf_id, "pre")

        # Revoke one intermediary; its whole subtree should die.
        revoked_id = self._intermediary_id(REVOKED_INTERMEDIARY)
        await self._auth.revoke(int_tokens[revoked_id])
        await self._emit(ctx, revoked_id, f"dauth:revoke:{revoked_id}")

        # Post-revocation sweep: intermediaries first, then leaves.
        for int_id, token in int_tokens.items():
            await self._verify_probe(ctx, token, int_id, int_id, "post")
        for leaf_id, (_int_id, leaf_token) in leaf_tokens.items():
            await self._verify_probe(ctx, leaf_token, leaf_id, leaf_id, "post")


def delegated_auth_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build the coordinator + 3 intermediaries + 12 leaves for the delegation tree.

    Instantiates the configured ``auth`` plugin with ``clock=0.0`` for
    determinism, derives each leaf's scope subset from a generator seeded only
    from ``config.seed``, and hands the auth instance to the coordinator, which
    drives the whole run in ``on_start``.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    auth_cls = plugins["auth"]
    auth = auth_cls(clock=0.0)

    coordinator_id = AgentId("coordinator")
    rng = random.Random(str(config.seed))

    agents: dict[AgentId, Any] = {}
    leaf_scopes: dict[AgentId, list[str]] = {}

    for i in range(N_INTERMEDIARIES):
        int_id = AgentId(f"int-{i}")
        agents[int_id] = TreeAgent(int_id)
        parent_scopes = sorted(set(INTERMEDIARY_SCOPES[i]))
        for j in range(LEAVES_PER_INTERMEDIARY):
            leaf_id = AgentId(f"leaf-{i}-{j}")
            agents[leaf_id] = TreeAgent(leaf_id)
            # "read" is always kept; a deterministic extra scope may be added if
            # the parent holds one, so leaves narrow but stay non-trivial.
            chosen = {"read"} if "read" in parent_scopes else {parent_scopes[0]}
            extras = [s for s in parent_scopes if s not in chosen]
            if extras and rng.random() < 0.5:
                chosen.add(rng.choice(extras))
            leaf_scopes[leaf_id] = sorted(chosen)

    agents[coordinator_id] = CoordinatorAgent(coordinator_id, auth, leaf_scopes)
    return agents
