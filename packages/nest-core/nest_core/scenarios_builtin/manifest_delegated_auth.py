# SPDX-License-Identifier: Apache-2.0
"""Manifest-bound delegatable auth scenario with adversarial probes.

One coordinator receives a manifest-bound root token and builds a delegation
tree: 3 intermediaries, each with 4 leaves. Honest leaves verify with in-scope,
in-audience, unrevoked tokens. Four adversarial probes then try to:

* widen a signed manifest after signing,
* delegate a broader scope than the parent token carries,
* use a descendant after an ancestor was revoked, and
* present a token minted for one audience as another audience.

The scenario is capability-gated. With ``auth: manifest_delegatable`` the probes are
blocked. With the baseline ``auth: jwt`` there is no manifest/delegation surface,
so the scenario falls back to central re-issuance; the same four probes are accepted
and the validators fail.

Trace line protocol (carried in ``send`` message bodies):

* ``honest_leaf:<leaf>:<parent>:<scopes_csv>:ok`` — an honest leaf verified.
* ``attack:<name>:blocked`` — the configured auth plugin rejected the probe.
* ``attack:<name>:accepted`` — the baseline accepted the probe.

Example::

    agents = manifest_delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token


class DelegationCoordinator(StateMachineAgent):
    """Builds the delegation tree and emits audit lines for validators.

    Example::

        agent = DelegationCoordinator(AgentId("coordinator-0"), AgentId("auditor-0"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        intermediaries: list[AgentId],
        leaves_by_parent: dict[AgentId, list[AgentId]],
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._intermediaries = intermediaries
        self._leaves_by_parent = leaves_by_parent

    async def on_start(self, ctx: AgentContext) -> None:
        """Run the full auth probe suite at tick 0.

        Example::

            await agent.on_start(ctx)
        """
        auth = ctx.plugins.get("auth")
        if auth is None:  # pragma: no cover - scenario always configures auth
            return
        if hasattr(auth, "set_clock"):
            auth.set_clock(ctx.time)

        can_delegate = hasattr(auth, "delegate")
        root_scopes = ["tool:buy", "tool:sell", "tool:query", "tool:admin"]
        root = await auth.issue(self._id, root_scopes)

        intermediate_scopes = [
            ["tool:buy", "tool:query"],
            ["tool:sell", "tool:query"],
            ["tool:buy", "tool:sell"],
        ]
        intermediate_tokens: dict[AgentId, Token] = {}
        leaf_tokens: dict[AgentId, Token] = {}

        await self._probe_manifest_tamper(ctx, auth)
        for parent, scopes in zip(self._intermediaries, intermediate_scopes, strict=True):
            if can_delegate:
                token = await auth.delegate(root, parent, scopes, ttl=1800)
            else:
                token = await auth.issue(parent, scopes)
            intermediate_tokens[parent] = token

            leaf_scope = [scopes[0]]
            for leaf in self._leaves_by_parent[parent]:
                if can_delegate:
                    leaf_token = await auth.delegate(token, leaf, leaf_scope, ttl=600)
                    await auth.verify(leaf_token, presenter=leaf)
                else:
                    leaf_token = await auth.issue(leaf, leaf_scope)
                    await auth.verify(leaf_token)
                leaf_tokens[leaf] = leaf_token
                await self._emit(
                    ctx,
                    f"honest_leaf:{leaf}:{parent}:{','.join(leaf_scope)}:ok",
                )

        await self._probe_scope_escalation(ctx, auth, can_delegate, intermediate_tokens)
        await self._probe_stale_parent(ctx, auth, can_delegate, intermediate_tokens, leaf_tokens)
        await self._probe_audience_confusion(ctx, auth, can_delegate, leaf_tokens)

    async def _probe_manifest_tamper(self, ctx: AgentContext, auth: Any) -> None:
        attacker = AgentId("attack-manifest")
        if auth.__class__.__name__ == "ManifestDelegatableAuth":
            from nest_plugins_reference.auth.manifest_delegatable import ManifestDelegatableAuth
            from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
            from nest_plugins_reference.policy import PolicyManifest, sign_manifest

            identity = Ed25519RotatingIdentity(attacker, seed=b"manifest-tamper")
            signed = sign_manifest(identity, PolicyManifest(agent_id=attacker, tools=["buy"]))
            tampered = signed.model_copy(update={"tools": ["buy", "admin"]})
            tamper_auth = ManifestDelegatableAuth(
                manifests={attacker: tampered},
                identities={attacker: identity},
                clock=ctx.time,
            )
            token = await tamper_auth.issue(attacker, ["tool:admin"])
            verified = await tamper_auth.verify(token, presenter=attacker)
            outcome = "blocked" if not verified.scopes else "accepted"
            await self._emit(ctx, f"attack:manifest_tamper:{outcome}")
            return

        token = await auth.issue(attacker, ["tool:admin"])
        verified = await auth.verify(token)
        outcome = "accepted" if "tool:admin" in verified.scopes else "blocked"
        await self._emit(ctx, f"attack:manifest_tamper:{outcome}")

    async def _probe_scope_escalation(
        self,
        ctx: AgentContext,
        auth: Any,
        can_delegate: bool,
        intermediate_tokens: dict[AgentId, Token],
    ) -> None:
        parent = self._intermediaries[0]
        if can_delegate:
            try:
                await auth.delegate(
                    intermediate_tokens[parent],
                    AgentId("attack-scope"),
                    ["tool:buy", "tool:admin"],
                    ttl=60,
                )
            except ValueError:
                await self._emit(ctx, "attack:scope_escalation:blocked")
                return
            await self._emit(ctx, "attack:scope_escalation:accepted")
            return

        token = await auth.issue(AgentId("attack-scope"), ["tool:buy", "tool:admin"])
        verified = await auth.verify(token)
        outcome = "accepted" if "tool:admin" in verified.scopes else "blocked"
        await self._emit(ctx, f"attack:scope_escalation:{outcome}")

    async def _probe_stale_parent(
        self,
        ctx: AgentContext,
        auth: Any,
        can_delegate: bool,
        intermediate_tokens: dict[AgentId, Token],
        leaf_tokens: dict[AgentId, Token],
    ) -> None:
        parent = self._intermediaries[1]
        stale_leaf = self._leaves_by_parent[parent][0]
        await auth.revoke(intermediate_tokens[parent])
        try:
            if can_delegate:
                await auth.verify(leaf_tokens[stale_leaf], presenter=stale_leaf)
            else:
                await auth.verify(leaf_tokens[stale_leaf])
        except ValueError:
            await self._emit(ctx, "attack:stale_parent:blocked")
            return
        await self._emit(ctx, "attack:stale_parent:accepted")

    async def _probe_audience_confusion(
        self,
        ctx: AgentContext,
        auth: Any,
        can_delegate: bool,
        leaf_tokens: dict[AgentId, Token],
    ) -> None:
        leaf = self._leaves_by_parent[self._intermediaries[2]][0]
        wrong_presenter = AgentId(f"{leaf}-wrong")
        try:
            if can_delegate:
                await auth.verify(leaf_tokens[leaf], presenter=wrong_presenter)
            else:
                await auth.verify(leaf_tokens[leaf])
        except ValueError:
            await self._emit(ctx, "attack:audience_confusion:blocked")
            return
        await self._emit(ctx, "attack:audience_confusion:accepted")

    async def _emit(self, ctx: AgentContext, line: str) -> None:
        await ctx.send(self._auditor, line.encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """The coordinator is start-driven and ignores incoming messages.

        Example::

            await agent.on_message(ctx, auditor, b"noop")
        """
        return


class AuditSink(StateMachineAgent):
    """No-op receiver; the trace itself is the audit log.

    Example::

        sink = AuditSink()
    """

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Accept audit lines without side effects."""
        return


class DelegationParticipant(StateMachineAgent):
    """Started participant in the delegation tree.

    The coordinator drives token issuance and verification centrally so the
    trace stays deterministic; these agents make the scenario's advertised
    intermediaries and leaves visible as real simulator participants.

    Example::

        participant = DelegationParticipant()
    """

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ignore messages; participation is represented by lifecycle events."""
        return


def _build_auth_instance(auth_cls: Any, coordinator: AgentId) -> Any:
    if not isinstance(auth_cls, type):
        return auth_cls

    if auth_cls.__name__ == "ManifestDelegatableAuth":
        from nest_plugins_reference.auth.manifest_delegatable import ManifestDelegatableAuth
        from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
        from nest_plugins_reference.policy import Budget, PolicyManifest, sign_manifest

        ident = Ed25519RotatingIdentity(coordinator, seed=b"delegated-auth:coordinator")
        manifest = PolicyManifest(
            agent_id=coordinator,
            tools=["buy", "sell", "query"],
            budget=Budget(cap=1000),
        )
        signed = sign_manifest(ident, manifest)
        return ManifestDelegatableAuth(
            manifests={coordinator: signed},
            identities={coordinator: ident},
            clock=0.0,
        )

    try:
        return auth_cls(clock=0.0)
    except TypeError:
        return auth_cls()


def manifest_delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create one coordinator, three intermediaries, twelve leaves, and a sink.

    Example::

        agents = manifest_delegated_auth_factory(config, plugins)
    """
    coordinator = AgentId("coordinator-0")
    auditor = AgentId("auditor-0")
    intermediate_count = int(config.task.config.get("intermediaries", 3))
    leaves_per_intermediary = int(config.task.config.get("leaves_per_intermediary", 4))

    intermediaries = [AgentId(f"intermediary-{i}") for i in range(intermediate_count)]
    leaves_by_parent = {
        parent: [
            AgentId(f"leaf-{parent_idx}-{leaf_idx}") for leaf_idx in range(leaves_per_intermediary)
        ]
        for parent_idx, parent in enumerate(intermediaries)
    }

    plugins["auth"] = _build_auth_instance(plugins.get("auth"), coordinator)

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator: DelegationCoordinator(
            coordinator,
            auditor,
            intermediaries=intermediaries,
            leaves_by_parent=leaves_by_parent,
        ),
        auditor: AuditSink(),
    }

    for intermediary in intermediaries:
        agents[intermediary] = DelegationParticipant()
    for leaves in leaves_by_parent.values():
        for leaf in leaves:
            agents[leaf] = DelegationParticipant()

    return agents
