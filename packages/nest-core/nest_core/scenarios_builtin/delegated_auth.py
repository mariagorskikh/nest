# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario — exercises macaroon-style capability delegation.

Topology (16 agents):

* ``coordinator-0`` holds a root token with the full scope set.
* ``intermediary-0..2`` each hold a delegated token with a narrower scope
  (``[read, write]``, ``[read, delete]``, ``[read]``).
* ``leaf-0..11`` each hold a ``[read]`` token delegated by their intermediary
  (leaf ``i`` belongs to intermediary ``i // 4``).

Every leaf presents its token to the coordinator, which verifies it against the
presenter's identity. Two leaves are Byzantine:

* ``leaf-5`` forges a broader scope into its own token (tampering).
* ``leaf-10`` steals ``leaf-9``'s token and presents it as its own (audience
  confusion).

Once all twelve have presented, the coordinator revokes ``intermediary-0``. Its
four honest leaves (``leaf-0..3``) then fail re-verification, demonstrating
cascading revocation. The whole scenario is RNG-free, so a given seed replays to a
byte-identical trace.

Example::

    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig
    runner = ScenarioRunner(ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml"))
    await runner.run()
    results = runner.resolved_plugins["_delegation_results"]
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

COORDINATOR = AgentId("coordinator-0")
_ROOT_SCOPES = ["read", "write", "admin", "delete"]
_INTERMEDIARY_SCOPES = [["read", "write"], ["read", "delete"], ["read"]]
_PRESENT = b"PRESENT|"


class DelegationLeaf(StateMachineAgent):
    """A leaf agent that presents its capability token to the coordinator.

    Example::

        leaf = DelegationLeaf(b"PRESENT|<token>")
    """

    def __init__(self, present_payload: bytes) -> None:
        self._present_payload = present_payload

    async def on_start(self, ctx: AgentContext) -> None:
        """Send this leaf's token to the coordinator.

        Example::

            await leaf.on_start(ctx)
        """
        await ctx.send(COORDINATOR, self._present_payload)


class DelegationCoordinator(StateMachineAgent):
    """Verifies presented tokens and revokes an intermediary to show the cascade.

    Example::

        coord = DelegationCoordinator(auth, inter_tokens, cascade_tokens, 12, results)
    """

    def __init__(
        self,
        auth: Any,
        intermediary_tokens: list[Token],
        cascade_tokens: dict[str, Token],
        expected: int,
        results: dict[str, Any],
    ) -> None:
        self._auth = auth
        self._intermediary_tokens = intermediary_tokens
        self._cascade_tokens = cascade_tokens
        self._expected = expected
        self._results = results
        self._seen = 0

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify a presented token; after the last one, revoke intermediary-0.

        Example::

            await coord.on_message(ctx, AgentId("leaf-0"), b"PRESENT|<token>")
        """
        from nest_plugins_reference.auth.macaroons import DelegationError, RevokedAncestorError

        if not payload.startswith(_PRESENT):
            return
        token = Token(payload[len(_PRESENT) :].decode("utf-8"))
        try:
            self._auth.verify_for_sync(token, sender)
            self._results["authorized"].append(str(sender))
        except DelegationError as exc:
            self._results["blocked"][str(sender)] = type(exc).__name__

        self._seen += 1
        if self._seen < self._expected:
            return

        # Everyone has presented: revoke intermediary-0 and re-check its leaves.
        self._auth.revoke_sync(self._intermediary_tokens[0])
        for leaf_id, tok in self._cascade_tokens.items():
            try:
                self._auth.verify_for_sync(tok, AgentId(leaf_id))
            except RevokedAncestorError:
                self._results["cascade_revoked"].append(leaf_id)
            except DelegationError:
                pass


def delegated_auth_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build the delegation tree and the agent fleet for the scenario.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    from nest_plugins_reference.auth.macaroons import MacaroonAuth

    counts = {role.name: role.count for role in config.agents.roles}
    n_intermediaries = counts.get("intermediary", 3)
    n_leaves = counts.get("leaf", 12)

    auth = MacaroonAuth(secret=b"nanda-macaroon-scenario", clock=0.0)

    # Root and per-intermediary tokens.
    root = auth.issue_sync(COORDINATOR, _ROOT_SCOPES)
    intermediary_tokens: list[Token] = []
    for i in range(n_intermediaries):
        scopes = _INTERMEDIARY_SCOPES[i % len(_INTERMEDIARY_SCOPES)]
        intermediary_tokens.append(
            auth.delegate_sync(root, AgentId(f"intermediary-{i}"), scopes, ttl=1800.0)
        )

    # Per-leaf [read] tokens, delegated by the owning intermediary.
    leaf_tokens: dict[int, Token] = {}
    for i in range(n_leaves):
        parent_idx = i // 4
        parent_token = intermediary_tokens[parent_idx % len(intermediary_tokens)]
        leaf_tokens[i] = auth.delegate_sync(parent_token, AgentId(f"leaf-{i}"), ["read"], ttl=600.0)

    # Two Byzantine leaves: 5 forges a broader scope, 10 steals leaf-9's token.
    byzantine_tamper = 5
    byzantine_steal = 10
    present_payloads: dict[int, bytes] = {}
    for i in range(n_leaves):
        if i == byzantine_tamper:
            forged = str(leaf_tokens[i]).replace("read", "admin")  # breaks the signature
            present_payloads[i] = _PRESENT + forged.encode("utf-8")
        elif i == byzantine_steal:
            stolen = leaf_tokens[byzantine_steal - 1]  # a peer's valid token
            present_payloads[i] = _PRESENT + str(stolen).encode("utf-8")
        else:
            present_payloads[i] = _PRESENT + str(leaf_tokens[i]).encode("utf-8")

    # Honest leaves under intermediary-0 (leaf-0..3) demonstrate the cascade.
    cascade_tokens = {f"leaf-{i}": leaf_tokens[i] for i in range(n_leaves) if i // 4 == 0}

    results: dict[str, Any] = {"authorized": [], "blocked": {}, "cascade_revoked": []}
    plugins["_delegation_auth"] = auth
    plugins["_delegation_results"] = results

    agents: dict[AgentId, Any] = {
        COORDINATOR: DelegationCoordinator(
            auth, intermediary_tokens, cascade_tokens, n_leaves, results
        )
    }
    for i in range(n_intermediaries):
        agents[AgentId(f"intermediary-{i}")] = StateMachineAgent()
    for i in range(n_leaves):
        agents[AgentId(f"leaf-{i}")] = DelegationLeaf(present_payloads[i])
    return agents
