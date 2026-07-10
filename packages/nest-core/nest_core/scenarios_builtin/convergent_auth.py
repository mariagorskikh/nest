# SPDX-License-Identifier: Apache-2.0
"""Delegated-capability scenario: a delegation tree under cascading revocation.

A ``coordinator`` issues one root capability and delegates a narrower sub-token
to each of 3 ``inter`` (intermediary) agents. Every intermediary then delegates
a still-narrower token to each of its 4 ``leaf`` agents — *offline*, using only
the token it holds and the shared secret, never calling back to the
coordinator. That is a 1 + 3 + 12 = 16-agent delegation tree.

Mid-run the coordinator revokes one intermediary's token and **gossips** the
revoked seal to the other agents. Revocation gossip is modelled as ordinary
messages: a receiver folds the seal into its own :class:`RevocationSet`
(a G-Set CRDT), so the revocation converges by message-passing exactly as it
would across a real swarm. Three consequences are then exercised and recorded
into the trace for the ``convergent_auth`` validator:

* **Cascading revocation** — every leaf under the revoked intermediary fails
  re-verification, while leaves under the other intermediaries still pass. No
  per-leaf revocation state exists; a revoked ancestor seal severs the subtree.
* **Convergence** — once the revoked intermediary has merged the gossiped seal,
  its *own* attempt to mint a fresh leaf token fails, proving the revocation
  propagated rather than living only on the coordinator.
* **Three attacks, all blocked** — scope escalation (a child requesting a scope
  the parent lacks), stale-parent delegation (delegating from a revoked token),
  and audience confusion (a token presented by an agent that is not its
  declared audience).

Capability gating
-----------------
Agents resolve auth from ``ctx.plugins["auth"]`` and branch on
``hasattr(auth, "delegate")``. Under the reference ``auth: jwt`` plugin — which
cannot delegate — the tree is never built and the agents emit ``unsupported``
markers instead of crashing. The ``convergent_auth`` validator then fails
against ``jwt`` (no delegation, no cascade) and passes against ``delegatable``,
which shows the default plugin cannot model delegation.

Trace line protocol (carried in message bodies, ``:``-delimited; seals are hex
digests, tokens are urlsafe-base64 so they never contain a ``:``):

* ``delegated:<parent>:<child>:<child_seal>:<result>`` — a delegation; result is
  ``ok`` or ``unsupported``.
* ``verify:<presenter>:<seal>:<verdict>`` — a verification outcome; verdict is
  ``ok``/``revoked``/``expired``/``audience``/``malformed``.
* ``revoked:<intermediary>:<seal>`` — the coordinator revoked that token.
* ``attack:<kind>:<seal>:<outcome>`` — ``kind`` is ``escalation``,
  ``stale_parent`` or ``audience``; ``outcome`` is ``blocked`` or ``LEAKED``.
* ``converge:<intermediary>:<seal>:<state>`` — post-gossip delegation probe;
  ``state`` is ``valid`` (not revoked) or ``severed`` (revoked, cannot mint).

Example::

    agents = convergent_auth_factory(config, plugins)
"""

from __future__ import annotations

import base64
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

COORDINATOR = AgentId("coordinator")

# Scope lattice: each level is a strict subset of the one above it.
ROOT_SCOPES = ["admin", "delete", "read", "write"]
INTER_SCOPES = ["read", "write"]
LEAF_SCOPES = ["read"]
# A scope the intermediary does NOT hold — used for the escalation attack.
ESCALATION_SCOPE = "admin"
LONG_TTL = 100_000.0


def _auth_of(ctx: AgentContext) -> Any:
    """Return this agent's auth plugin instance (or ``None`` if unconfigured).

    Example::

        auth = _auth_of(ctx)
    """
    return ctx.plugins.get("auth")


def _supports_delegation(auth: Any) -> bool:
    """Whether *auth* implements the delegatable surface (vs. plain ``jwt``).

    Example::

        if _supports_delegation(auth):
            ...
    """
    return auth is not None and hasattr(auth, "delegate")


def _leaf_seal(auth: Any, token: Token) -> str:
    """Return a token's leaf seal (its stable identity in the trace).

    Example::

        seal = _leaf_seal(auth, token)
    """
    return str(auth.describe(token).seals[-1])


def _encode(token: Token) -> str:
    """Encode a token as urlsafe base64 so it is ``:``-safe in the line protocol."""
    return base64.urlsafe_b64encode(str(token).encode("utf-8")).decode("ascii")


def _decode(blob: str) -> Token:
    """Inverse of :func:`_encode`."""
    return Token(base64.urlsafe_b64decode(blob.encode("ascii")).decode("utf-8"))


def _verdict_for(auth: Any, exc: Exception) -> str:
    """Map a verification exception to a compact trace verdict token."""
    name = type(exc).__name__
    return {
        "RevokedAncestorError": "revoked",
        "ExpiredTokenError": "expired",
        "AudienceMismatchError": "audience",
        "MalformedTokenError": "malformed",
    }.get(name, "error")


class DelegationCoordinator(StateMachineAgent):
    """Issues the root capability, drives phases, verifies, and revokes.

    The coordinator holds the authoritative revocation set: it mints the three
    intermediary tokens, verifies whatever leaves present, and at
    ``revoke_at_tick`` revokes one intermediary and gossips the seal. All real
    verification happens here; the trace is the audit log the validator reads.

    Example::

        coord = DelegationCoordinator(intermediaries, leaves_by_inter, revoke_at_tick=5.0)
    """

    def __init__(
        self,
        intermediaries: list[AgentId],
        leaves_by_inter: dict[AgentId, list[AgentId]],
        revoke_at_tick: float = 5.0,
    ) -> None:
        self._intermediaries = intermediaries
        self._leaves_by_inter = leaves_by_inter
        self._all_leaves = [leaf for leaves in leaves_by_inter.values() for leaf in leaves]
        self._revoke_at_tick = revoke_at_tick
        self._inter_tokens: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue the root token and delegate one sub-token per intermediary.

        Example::

            await coord.on_start(ctx)
        """
        auth = _auth_of(ctx)
        if not _supports_delegation(auth):
            # jwt path: cannot delegate. Emit an unsupported marker per
            # intermediary so the validator sees a tree that was never built.
            for inter in self._intermediaries:
                await ctx.send(inter, f"delegated:{COORDINATOR}:{inter}:na:unsupported".encode())
            return

        auth.set_now(ctx.time)
        root = await auth.issue(COORDINATOR, list(ROOT_SCOPES))
        for inter in self._intermediaries:
            child = await auth.delegate(root, inter, list(INTER_SCOPES), ttl=LONG_TTL)
            self._inter_tokens[inter] = child
            await ctx.send(inter, f"token:{_encode(child)}".encode())
            await ctx.send(
                inter, f"delegated:{COORDINATOR}:{inter}:{_leaf_seal(auth, child)}:ok".encode()
            )
        await ctx.schedule(self._revoke_at_tick, b"pulse:revoke")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify presented tokens, run the audience attack, and drive revocation.

        Example::

            await coord.on_message(ctx, leaf, b"present:leaf-0:<b64>")
        """
        msg = payload.decode("utf-8", errors="replace")
        auth = _auth_of(ctx)

        if msg.startswith("pulse:revoke") and _supports_delegation(auth):
            await self._revoke_phase(ctx, auth)
            return

        if msg.startswith("present:"):
            _, leaf, blob = msg.split(":", 2)
            await self._verify_and_record(ctx, auth, AgentId(leaf), _decode(blob), tag="verify")
            return

        if msg.startswith("spoof_present:"):
            # Audience-confusion attack: `leaf` presents a token minted for a
            # different audience. A correct plugin rejects it.
            _, leaf, blob = msg.split(":", 2)
            await self._audience_attack(ctx, auth, AgentId(leaf), _decode(blob))
            return

    async def _verify_and_record(
        self, ctx: AgentContext, auth: Any, presenter: AgentId, token: Token, tag: str
    ) -> None:
        auth.set_now(ctx.time)
        seal = _leaf_seal(auth, token)
        try:
            await auth.verify(token, presenter=presenter)
            verdict = "ok"
        except Exception as exc:  # noqa: BLE001 - verdict is derived from the type
            verdict = _verdict_for(auth, exc)
        await ctx.send(COORDINATOR, f"{tag}:{presenter}:{seal}:{verdict}".encode())

    async def _audience_attack(
        self, ctx: AgentContext, auth: Any, presenter: AgentId, token: Token
    ) -> None:
        auth.set_now(ctx.time)
        seal = _leaf_seal(auth, token)
        try:
            await auth.verify(token, presenter=presenter)
            outcome = "LEAKED"  # accepted a token bound to a different audience
        except Exception:  # noqa: BLE001 - any rejection blocks the attack
            outcome = "blocked"
        await ctx.send(COORDINATOR, f"attack:audience:{seal}:{outcome}".encode())

    async def _revoke_phase(self, ctx: AgentContext, auth: Any) -> None:
        auth.set_now(ctx.time)
        target = self._intermediaries[0]
        token = self._inter_tokens[target]
        seal = _leaf_seal(auth, token)
        await auth.revoke(token)  # records the seal on the coordinator's replica
        await ctx.send(COORDINATOR, f"revoked:{target}:{seal}".encode())
        # Gossip the revoked seal to every intermediary (CRDT merge by message).
        for inter in self._intermediaries:
            await ctx.send(inter, f"revoke:{seal}".encode())
        # Ask every leaf to present again so the cascade is recorded.
        for leaf in self._all_leaves:
            await ctx.send(leaf, b"reverify:")


class IntermediaryAgent(StateMachineAgent):
    """Delegates to its leaves offline, then probes revocation after gossip.

    On receiving its token it mints one leaf token per child (real
    :meth:`delegate` calls), attempts a scope-escalation attack, and leaks one
    leaf's token to a sibling to stage the audience attack. On revocation gossip
    it merges the seal and re-probes delegation to prove convergence.

    Example::

        inter = IntermediaryAgent(AgentId("inter-0"), leaves)
    """

    def __init__(self, agent_id: AgentId, leaves: list[AgentId]) -> None:
        self._id = agent_id
        self._leaves = leaves
        self._token: Token | None = None
        self._leaf_tokens: dict[AgentId, Token] = {}

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle the granted token and later revocation gossip.

        Example::

            await inter.on_message(ctx, coordinator, b"token:<b64>")
        """
        msg = payload.decode("utf-8", errors="replace")
        auth = _auth_of(ctx)
        if not _supports_delegation(auth):
            return

        if msg.startswith("token:"):
            await self._grant_leaves(ctx, auth, _decode(msg.split(":", 1)[1]))
        elif msg.startswith("revoke:"):
            await self._merge_and_probe(ctx, auth, msg.split(":", 1)[1])

    async def _grant_leaves(self, ctx: AgentContext, auth: Any, token: Token) -> None:
        self._token = token
        auth.set_now(ctx.time)
        leaf_tokens: dict[AgentId, Token] = {}
        for leaf in self._leaves:
            child = await auth.delegate(token, leaf, list(LEAF_SCOPES), ttl=LONG_TTL)
            leaf_tokens[leaf] = child
            self._leaf_tokens[leaf] = child
            await ctx.send(leaf, f"token:{_encode(child)}".encode())
            await ctx.send(
                COORDINATOR, f"delegated:{self._id}:{leaf}:{_leaf_seal(auth, child)}:ok".encode()
            )

        # Attack 1 — scope escalation: request a scope the parent does not hold.
        first_leaf = self._leaves[0]
        try:
            escalated = await auth.delegate(token, first_leaf, [ESCALATION_SCOPE], ttl=LONG_TTL)
            outcome, seal = "LEAKED", _leaf_seal(auth, escalated)
        except Exception:  # noqa: BLE001 - any rejection blocks the attack
            outcome, seal = "blocked", _leaf_seal(auth, token)
        await ctx.send(COORDINATOR, f"attack:escalation:{seal}:{outcome}".encode())

        # Stage the audience attack: leak leaf[0]'s token to leaf[1].
        if len(self._leaves) >= 2:
            victim_token = leaf_tokens[self._leaves[0]]
            await ctx.send(self._leaves[1], f"spoof:{_encode(victim_token)}".encode())

    async def _merge_and_probe(self, ctx: AgentContext, auth: Any, seal: str) -> None:
        # CRDT merge (load-bearing): the gossiped revocation arrives as a
        # RevocationSet and is folded in with the union merge — exercising the
        # commutative/idempotent G-Set laws end to end, not a single-element add.
        incoming = type(auth.revocations)(frozenset({seal}))
        auth.revocations.merge(incoming)
        if self._token is None:
            return
        auth.set_now(ctx.time)

        # Edge verification: this replica learned the revocation by *gossip*,
        # not by calling revoke() itself. Verifying a leaf token we minted here
        # rejects the descendant at the edge if our own grant was the revoked
        # ancestor — so cascade and convergence are proven on a non-issuer node,
        # exactly what a swarm does (verify at the edge, not at the issuer).
        for leaf, tok in self._leaf_tokens.items():
            try:
                await auth.verify(tok, presenter=leaf)
                verdict = "ok"
            except Exception as exc:  # noqa: BLE001 - verdict derived from type
                verdict = _verdict_for(auth, exc)
            await ctx.send(COORDINATOR, f"verify:{leaf}:{_leaf_seal(auth, tok)}:{verdict}".encode())
            break  # one edge verification demonstrates the property

        # Convergence probe — stale-parent delegation: after the merge, try to
        # mint a fresh leaf token from our own token. If our grant was revoked,
        # this must now fail (severed), proving the revocation propagated to us.
        own_seal = _leaf_seal(auth, self._token)
        try:
            await auth.delegate(self._token, self._leaves[0], list(LEAF_SCOPES), ttl=LONG_TTL)
            await ctx.send(COORDINATOR, f"converge:{self._id}:{own_seal}:valid".encode())
        except Exception:  # noqa: BLE001 - a revoked ancestor severs delegation
            await ctx.send(COORDINATOR, f"converge:{self._id}:{own_seal}:severed".encode())
            await ctx.send(COORDINATOR, f"attack:stale_parent:{own_seal}:blocked".encode())


class LeafAgent(StateMachineAgent):
    """Holds a doubly-delegated token; presents it for verification on demand.

    Example::

        leaf = LeafAgent(AgentId("leaf-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Store a granted token, present it, or forward a spoofed one.

        Example::

            await leaf.on_message(ctx, inter, b"token:<b64>")
        """
        msg = payload.decode("utf-8", errors="replace")
        auth = _auth_of(ctx)
        if not _supports_delegation(auth):
            return

        if msg.startswith("token:"):
            self._token = _decode(msg.split(":", 1)[1])
            await ctx.send(COORDINATOR, f"present:{self._id}:{_encode(self._token)}".encode())
        elif msg.startswith("reverify:") and self._token is not None:
            await ctx.send(COORDINATOR, f"present:{self._id}:{_encode(self._token)}".encode())
        elif msg.startswith("spoof:"):
            # Present a token minted for a *different* audience (this agent).
            spoofed = msg.split(":", 1)[1]
            await ctx.send(COORDINATOR, f"spoof_present:{self._id}:{spoofed}".encode())


def _provision_auth(plugins: dict[str, Any], agent_ids: list[AgentId]) -> None:
    """Give every agent its own auth instance sharing the default secret.

    Mirrors ``identity_rotation._provision_identities``: resolve the class at
    ``plugins["auth"]``, build one instance per agent (all with the same default
    secret so seals verify across agents, each with its own revocation replica),
    and stash them under ``plugins["_agent_plugins"]`` for the runner to apply.
    No-op when no auth plugin is configured.

    Example::

        _provision_auth(plugins, [COORDINATOR, AgentId("inter-0")])
    """
    auth_cls = plugins.get("auth")
    if auth_cls is None or not isinstance(auth_cls, type):
        return
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    for aid in agent_ids:
        agent_plugins.setdefault(aid, {})["auth"] = auth_cls()
    plugins.pop("auth", None)


def convergent_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the coordinator, 3 intermediaries and 12 leaves.

    Counts are fixed by the problem (a coordinator, 3 intermediaries, 12
    leaves); ``task.config.revoke_at_tick`` tunes when the coordinator revokes.

    Example::

        agents = convergent_auth_factory(config, plugins)
    """
    task_config = config.task.config
    revoke_at_tick = float(task_config.get("revoke_at_tick", 5.0))
    inter_count = int(task_config.get("intermediaries", 3))
    leaves_per_inter = int(task_config.get("leaves_per_intermediary", 4))

    intermediaries = [AgentId(f"inter-{i}") for i in range(inter_count)]
    leaves_by_inter: dict[AgentId, list[AgentId]] = {}
    leaf_index = 0
    for inter in intermediaries:
        leaves: list[AgentId] = []
        for _ in range(leaves_per_inter):
            leaves.append(AgentId(f"leaf-{leaf_index}"))
            leaf_index += 1
        leaves_by_inter[inter] = leaves

    all_leaves = [leaf for leaves in leaves_by_inter.values() for leaf in leaves]
    _provision_auth(plugins, [COORDINATOR, *intermediaries, *all_leaves])

    agents: dict[AgentId, StateMachineAgent] = {
        COORDINATOR: DelegationCoordinator(intermediaries, leaves_by_inter, revoke_at_tick)
    }
    for inter in intermediaries:
        agents[inter] = IntermediaryAgent(inter, leaves_by_inter[inter])
    for leaf in all_leaves:
        agents[leaf] = LeafAgent(leaf)
    return agents
