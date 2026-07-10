# SPDX-License-Identifier: Apache-2.0
"""Delegated-capability scenario: a delegation tree under three live attacks.

A ``coordinator`` mints a root capability and delegates narrowed sub-tokens
to intermediaries, who in turn delegate leaf tokens to workers. Workers then
*present* their tokens to a ``gatekeeper`` that verifies them with the
configured ``auth`` plugin. Interleaved with the honest presentations, three
adversaries attempt the attacks the delegatable plugin is built to defeat:

* **escalate** — a worker forges a child claiming a scope its delegator never
  held;
* **stale** — a worker keeps presenting a token whose ancestor the coordinator
  has since revoked;
* **confused** — a worker presents a peer's token (wrong audience).

The gatekeeper resolves the auth plugin from ``ctx.plugins["auth"]`` and emits
one ``cap:<presenter>:<expected>:<outcome>`` line per presentation. All real
checking is done by the plugin; the trace is the audit log that
``validate_delegated_auth_trace`` replays offline.

Capability-gating keeps the scenario runnable under *any* auth plugin: the
delegation helpers are attempted via ``getattr``/``attenuate`` and, where the
plugin has no real delegation (plain ``jwt``), the attacks are carried out via
central re-issuance — which the trace then shows being *allowed*, the honest
demonstration that ``jwt`` fails the validator while ``delegatable`` passes.

Determinism: every agent action is driven by the coordinator's logical-clock
pulses; no wall-clock time, no unseeded RNG.

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token


def _auth_of(ctx: AgentContext) -> Any:
    """Return the auth plugin instance from the agent's context.

    Example::

        auth = _auth_of(ctx)
    """
    return ctx.plugins.get("auth")


def _forge_broadened_child(
    parent_token: Token,
    audience: AgentId,
    scopes: list[str],
) -> Token | None:
    """Adversary tool: append a scope-*broadening* link with a valid HMAC chain.

    Returns ``None`` when the token is not a delegatable chain (e.g. plain
    ``jwt``), signalling the caller to fall back to a re-issuance escalation.
    This deliberately produces a token whose chain signature verifies but whose
    final link violates the scope-subset invariant, so it exercises the
    verifier's independent semantic check rather than the mint-time guard.

    Example::

        forged = _forge_broadened_child(leaf, AgentId("worker-0-1"), ["read", "write"])
    """
    import hashlib
    import hmac
    import json

    try:
        data = json.loads(str(parent_token))
        links = data["chain"]
        parent_sig = data["sig"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    if not isinstance(links, list) or not links:
        return None
    links_typed = cast("list[dict[str, Any]]", links)
    parent_link = links_typed[-1]
    broadened: dict[str, Any] = {
        "aud": str(audience),
        "exp": float(parent_link["exp"]),
        "iat": float(parent_link["iat"]),
        "scopes": sorted(scopes),
        "sub": parent_link.get("aud") or parent_link["sub"],
    }
    canon = json.dumps(broadened, sort_keys=True, separators=(",", ":"))
    child_sig = hmac.new(parent_sig.encode(), canon.encode(), hashlib.sha256).hexdigest()
    out: dict[str, Any] = {"chain": [*links_typed, broadened], "sig": child_sig}
    return Token(json.dumps(out, sort_keys=True, separators=(",", ":")))


async def _try_delegate(
    auth: Any,
    parent: Token,
    audience: AgentId,
    scopes: list[str],
    ttl: float,
) -> Token | None:
    """Delegate via the plugin's real API, else fall back to re-issuance.

    Returns ``None`` only if neither path is available. The fallback is the
    ``jwt`` anti-pattern (central re-issuance), included so the scenario runs
    end-to-end under the reference plugin and the validator can tell them
    apart.

    Example::

        child = await _try_delegate(auth, root, AgentId("w-0"), ["read"], 60.0)
    """
    if hasattr(auth, "delegate"):
        try:
            return await auth.delegate(parent, audience, scopes, ttl)
        except ValueError:
            return None
    if hasattr(auth, "issue"):
        return await auth.issue(audience, scopes)
    return None


class Coordinator(StateMachineAgent):
    """Roots the delegation tree and pulses the scenario forward.

    On start it mints a root token and one intermediary token per
    intermediary, distributing them. Then it pulses rounds: round 1 = honest
    presentations, round 2 = attacks, round 3 = revoke an intermediary and
    re-present (the stale attack). The gatekeeper does the verifying.

    Example::

        coord = Coordinator(AgentId("coordinator"), intermediaries, workers, gatekeeper)
    """

    def __init__(
        self,
        agent_id: AgentId,
        intermediaries: list[AgentId],
        workers: list[AgentId],
        gatekeeper: AgentId,
        rounds: int = 3,
    ) -> None:
        self._id = agent_id
        self._intermediaries = intermediaries
        self._workers = workers
        self._gatekeeper = gatekeeper
        self._rounds = rounds
        self._round = 0
        self._root: Token | None = None
        self._inter_tokens: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Mint the root + intermediary tokens and schedule the first pulse.

        Example::

            await coord.on_start(ctx)
        """
        auth = _auth_of(ctx)
        if auth is None or not hasattr(auth, "issue"):
            return
        if hasattr(auth, "set_clock"):
            auth.set_clock(ctx.time)
        root = await auth.issue(self._id, ["read", "write", "invoke"])
        self._root = root
        for inter in self._intermediaries:
            tok = await _try_delegate(auth, root, inter, ["read", "write"], 500.0)
            if tok is not None:
                self._inter_tokens[inter] = tok
                await ctx.send(inter, b"inter-token:" + str(tok).encode())
        await ctx.schedule(1.0, b"pulse:")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Advance rounds on each self ``pulse:``; revoke in the final round.

        Example::

            await coord.on_message(ctx, coord_id, b"pulse:")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("pulse:"):
            return
        self._round += 1
        auth = _auth_of(ctx)
        if auth is not None and hasattr(auth, "set_clock"):
            auth.set_clock(ctx.time)

        # Revoke the first intermediary's token → all of its workers' leaf
        # tokens cascade to invalid. Those workers re-present in this same
        # round and must now be denied (the "stale" attack).
        if (
            self._round == 3
            and auth is not None
            and hasattr(auth, "revoke")
            and self._intermediaries
        ):
            revoked = self._intermediaries[0]
            tok = self._inter_tokens.get(revoked)
            if tok is not None:
                await auth.revoke(tok)

        # Pulse every worker with the current round tag.
        for w in self._workers:
            await ctx.send(w, f"round:{self._round}".encode())
        if self._round < self._rounds:
            await ctx.schedule(1.0, b"pulse:")


class Intermediary(StateMachineAgent):
    """Holds a delegated token and sub-delegates leaf tokens to its workers.

    Example::

        inter = Intermediary(AgentId("inter-0"), [AgentId("worker-0")], gatekeeper)
    """

    def __init__(self, agent_id: AgentId, workers: list[AgentId], gatekeeper: AgentId) -> None:
        self._id = agent_id
        self._workers = workers
        self._gatekeeper = gatekeeper
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Receive our token, then mint and hand out leaf + peer tokens.

        Each worker is given its own leaf token, plus the *previous* worker's
        leaf token as a ``peer-token:`` — the material the ``confused`` attack
        presents from the wrong audience.

        Example::

            await inter.on_message(ctx, coordinator, b"inter-token:...")
        """
        msg = payload.decode("utf-8", errors="replace")
        auth = _auth_of(ctx)
        if auth is not None and hasattr(auth, "set_clock"):
            auth.set_clock(ctx.time)
        if msg.startswith("inter-token:"):
            self._token = Token(msg[len("inter-token:") :])
            if auth is None:
                return
            leaves: dict[AgentId, Token] = {}
            for w in self._workers:
                leaf = await _try_delegate(auth, self._token, w, ["read"], 120.0)
                if leaf is not None:
                    leaves[w] = leaf
                    await ctx.send(w, b"leaf-token:" + str(leaf).encode())
            # Hand each worker its predecessor's token as peer material.
            for idx, w in enumerate(self._workers):
                peer = self._workers[idx - 1]
                if peer in leaves and peer != w:
                    await ctx.send(w, b"peer-token:" + str(leaves[peer]).encode())


class Worker(StateMachineAgent):
    """A leaf agent that presents its capability — honestly, then adversarially.

    Behaviour by round pulse:

    * round 1: present its own valid leaf token (``expected=ok``);
    * round 2: attempt one assigned attack (``escalate`` / ``confused``);
    * round 3+ (after ``revoked:``): re-present the now-stale token
      (``expected=stale``).

    The worker never decides the outcome — it forwards the presentation to the
    gatekeeper, which verifies and records ``allow`` / ``deny``.

    Example::

        w = Worker(AgentId("worker-0"), gatekeeper, attack="escalate")
    """

    def __init__(self, agent_id: AgentId, gatekeeper: AgentId, attack: str = "none") -> None:
        self._id = agent_id
        self._gatekeeper = gatekeeper
        self._attack = attack
        self._token: Token | None = None
        self._peer_token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Store tokens and, on each round pulse, present as scripted.

        Example::

            await w.on_message(ctx, coordinator, b"round:1")
        """
        msg = payload.decode("utf-8", errors="replace")
        auth = _auth_of(ctx)
        if auth is not None and hasattr(auth, "set_clock"):
            auth.set_clock(ctx.time)

        if msg.startswith("leaf-token:"):
            self._token = Token(msg[len("leaf-token:") :])
            return
        if msg.startswith("peer-token:"):
            self._peer_token = Token(msg[len("peer-token:") :])
            return
        if not msg.startswith("round:"):
            return

        rnd = int(msg.split(":")[1])
        if self._token is None:
            return

        if rnd == 1:
            # Round 1 is the honest baseline: every worker's token is still
            # valid, so every presentation should be allowed.
            await self._present(ctx, self._token, "ok")
        elif rnd == 2:
            await self._attack_round(ctx, auth)
        elif rnd >= 3 and self._attack == "stale":
            # The ancestor was revoked in round 3; this token has cascaded to
            # invalid and must now be denied.
            await self._present(ctx, self._token, "stale")

    async def _attack_round(self, ctx: AgentContext, auth: Any) -> None:
        if self._attack == "escalate":
            forged = await self._forge_escalation(auth)
            if forged is not None:
                await self._present(ctx, forged, "escalate")
        elif self._attack == "confused" and self._peer_token is not None:
            await self._present(ctx, self._peer_token, "confused")

    async def _forge_escalation(self, auth: Any) -> Token | None:
        """Hand-craft a chain-valid token that *broadens* its own scopes.

        This is the realistic macaroon attack: a holder can always extend the
        HMAC chain (that is how offline delegation works), so a malicious
        holder appends a link granting itself ``write``/``invoke`` and computes
        a perfectly valid chain signature. Security must come from the
        *verifier* rejecting a link whose scopes are not a subset of its
        parent's — which is exactly the defense-in-depth check in
        ``DelegatableAuth.verify``. When the plugin has no such chain (plain
        ``jwt``), the attacker escalates via central re-issuance instead, and
        the trace then shows the gatekeeper *allowing* it — the ``jwt`` failure.

        Example::

            forged = await w._forge_escalation(auth)
        """
        if self._token is None:
            return None
        forged = _forge_broadened_child(self._token, self._id, ["read", "write", "invoke"])
        if forged is not None:
            return forged
        if hasattr(auth, "issue"):
            return await auth.issue(self._id, ["read", "write", "invoke"])
        return None

    async def _present(self, ctx: AgentContext, token: Token, expected: str) -> None:
        await ctx.send(
            self._gatekeeper,
            f"present:{self._id}:{expected}:{token}".encode(),
        )


class Gatekeeper(StateMachineAgent):
    """Verifies presented capabilities and writes the audit trail.

    For each ``present:<worker>:<expected>:<token>`` it runs the auth plugin's
    ``verify`` (presenter-aware when supported) and emits
    ``cap:<worker>:<expected>:<allow|deny>``. That single line protocol is what
    ``validate_delegated_auth_trace`` consumes.

    Example::

        gk = Gatekeeper(AgentId("gatekeeper"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Verify one presentation and record the verdict.

        Example::

            await gk.on_message(ctx, worker, b"present:worker-0:ok:<token>")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("present:"):
            return
        _tag, presenter, expected, token_str = msg.split(":", 3)
        auth = _auth_of(ctx)
        if auth is not None and hasattr(auth, "set_clock"):
            auth.set_clock(ctx.time)
        outcome = "deny"
        if auth is not None and hasattr(auth, "verify"):
            try:
                try:
                    await auth.verify(Token(token_str), presenter=AgentId(presenter))
                except TypeError:
                    await auth.verify(Token(token_str))
                outcome = "allow"
            except ValueError:
                outcome = "deny"
        await ctx.send(self._id, f"cap:{presenter}:{expected}:{outcome}".encode())


def _provision_auth(plugins: dict[str, Any], agent_ids: list[AgentId]) -> None:
    """Give every agent a shared auth instance built from the configured class.

    A single shared secret across agents models one verification authority
    (the gatekeeper's root secret), while delegation happens agent-side. When
    the configured auth is a plain class with no delegation we still share one
    instance so revocation state is visible to the gatekeeper.

    Example::

        _provision_auth(plugins, [AgentId("coordinator"), AgentId("worker-0")])
    """
    auth_cls = plugins.get("auth")
    if auth_cls is None or not isinstance(auth_cls, type):
        return
    # clock=0.0 pins plugins that would otherwise fall back to wall-clock time
    # (e.g. JwtAuth, which has no set_clock) so both arms of the scenario stay
    # byte-deterministic; the TypeError ladder keeps narrower constructors
    # runnable.
    try:
        shared = auth_cls(secret=b"delegated-auth-scenario-root", clock=0.0)
    except TypeError:
        try:
            shared = auth_cls(secret=b"delegated-auth-scenario-root")
        except TypeError:
            shared = auth_cls()
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    for aid in agent_ids:
        agent_plugins.setdefault(aid, {})["auth"] = shared
    plugins.pop("auth", None)


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build a coordinator + intermediaries + workers + gatekeeper tree.

    The tree shape comes from ``task.config``: ``intermediaries`` (default 3)
    and ``workers_per_intermediary`` (default 4). Attacks are assigned
    round-robin across workers so every attack class is represented (which the
    trace validator's coverage check requires).

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    tcfg = config.task.config
    n_inter = int(tcfg.get("intermediaries", 3))
    per = int(tcfg.get("workers_per_intermediary", 4))

    coordinator = AgentId("coordinator")
    gatekeeper = AgentId("gatekeeper")
    intermediaries = [AgentId(f"inter-{i}") for i in range(n_inter)]
    workers: list[AgentId] = []
    worker_of_inter: dict[AgentId, list[AgentId]] = {}
    for i, inter in enumerate(intermediaries):
        group = [AgentId(f"worker-{i}-{j}") for j in range(per)]
        worker_of_inter[inter] = group
        workers.extend(group)

    all_ids = [coordinator, gatekeeper, *intermediaries, *workers]
    _provision_auth(plugins, all_ids)

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator: Coordinator(coordinator, intermediaries, workers, gatekeeper),
        gatekeeper: Gatekeeper(gatekeeper),
    }
    for inter in intermediaries:
        agents[inter] = Intermediary(inter, worker_of_inter[inter], gatekeeper)

    # inter-0 is the branch the coordinator revokes in round 3, so all of its
    # workers carry the "stale" attack (their tokens cascade to invalid). The
    # remaining branches exercise escalate / confused / honest, round-robin, so
    # every attack class in the trace-validator's coverage check is present.
    revoked_workers: set[AgentId] = (
        set(worker_of_inter[intermediaries[0]]) if intermediaries else set()
    )
    other_attacks = ["none", "escalate", "confused"]
    other_idx = 0
    for w in workers:
        if w in revoked_workers:
            attack = "stale"
        else:
            attack = other_attacks[other_idx % len(other_attacks)]
            other_idx += 1
        agents[w] = Worker(w, gatekeeper, attack=attack)
    return agents
