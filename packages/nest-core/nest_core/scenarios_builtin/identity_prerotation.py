# SPDX-License-Identifier: Apache-2.0
"""Identity pre-rotation scenario: forgery, backdating, and rotation hijack.

Honest agents sign heartbeats with whatever identity plugin the YAML
configures (``identity: ed25519_prerotation`` for the real run), publish
their pre-rotation **commitment** at inception, rotate once mid-run to the
key they committed, publish the next commitment, and keep signing. The
byzantine agent runs a four-phase attack sequence:

1. **rotation hijack** (the attack reactive rotation cannot reject) — with
   the *current* key in hand, mint a continuity-signed rotation to an
   attacker-chosen successor via ``forge_rotation``. Under pre-rotation the
   revealed key's digest cannot match the pre-committed digest, so the
   attempt is emitted as a rejected ``rotate_attempt:...:hijack`` line;
2. **post-rotation forgery** — sign fresh material with the stale,
   rotated-out key (``sign_with``);
3. **backdating** — sign with the current key but claim a tick inside the
   previous key's window;
4. **recovery** — a legitimate rotation to the genuinely pre-committed cold
   key, then keep signing: the compromise-recovery story, in the trace.

Every step is capability-gated via ``hasattr``, so the same scenario runs
without crashing under ``did_key`` (no rotation at all — fails honestly)
and under ``ed25519_rotating`` (rotates but never commits — its rotations
have no prior commitment, so the pre-rotation validator fails it honestly:
the discrimination the matrix test pins down).

Trace line protocol (``:``-delimited message bodies; ``rotate:`` and
``signed:`` keep the merged ``identity_rotation`` shapes so the merged
validators run unchanged on these traces):

* ``rotate:<agent>:<old_key_id>:<new_key_id>:<tick>`` — an applied rotation.
* ``signed:<agent>:<key_id>:<claimed_tick>:<ok|forge|backdate>`` — heartbeat.
* ``commit:<agent>:<key_id>:<alg>:<hex>:<tick>`` — the commitment ``key_id``
  publishes for its successor (inception and after every rotation).
* ``rotate_attempt:<agent>:<old_key_id>:<alg>:<hex>:<alg>:<hex>:<tick>:hijack``
  — a rejected hijack: the revealed digest, then the prior commitment it
  failed to match.

Example::

    agents = identity_prerotation_factory(config, plugins)
"""

from __future__ import annotations

import hashlib
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


def _identity_of(ctx: AgentContext) -> Any:
    """Return the per-agent identity instance from the agent's context.

    Example::

        ident = _identity_of(ctx)
    """
    return ctx.plugins.get("identity")


def _key_id_token(sig: Any) -> str:
    """Render a signature's ``key_id`` for the trace (``None`` for keyless plugins).

    Example::

        token = _key_id_token(sig)
    """
    return str(getattr(sig, "key_id", None))


def _signed_at_token(sig: Any, fallback: float) -> str:
    """Render a signature's claimed ``signed_at`` tick, falling back when absent.

    Example::

        token = _signed_at_token(sig, ctx.time)
    """
    value = getattr(sig, "signed_at", None)
    return str(fallback if value is None else value)


def _commitment_of(ident: Any) -> str | None:
    """Return the identity's current alg-prefixed commitment, if it has one.

    ``ed25519_rotating`` and ``did_key`` expose no commitment — for them this
    returns ``None`` and the scenario emits no ``commit:`` lines, which is
    exactly how their lack of pre-rotation shows up in the trace.

    Example::

        commitment = _commitment_of(ident)
    """
    value = getattr(ident, "current_commitment", None)
    return None if value is None else str(value)


def _rotation_evidence(ident: Any, returned: Any) -> tuple[str, str] | None:
    """Extract ``(old_key_id, new_key_id)`` from a completed rotation.

    Handles both rotation-evidence conventions in the repo: the pre-rotation
    plugin publishes a :class:`RotationRecord` on ``latest_rotation`` and
    returns the spec's ``KeyId``; the merged reactive plugin returns the
    record itself. Returns ``None`` when neither shape is available.

    Example::

        evidence = _rotation_evidence(ident, ident.rotate_key(b"seed"))
    """
    record = getattr(ident, "latest_rotation", None)
    if record is None:
        record = returned
    old_key_id = getattr(record, "old_key_id", None)
    new_key_id = getattr(record, "new_key_id", None)
    if old_key_id is None or new_key_id is None:
        return None
    return str(old_key_id), str(new_key_id)


async def _emit_commit(ctx: AgentContext, agent_id: AgentId, auditor: AgentId) -> None:
    """Emit the agent's current commitment as a ``commit:`` line, if it has one.

    Example::

        await _emit_commit(ctx, AgentId("signer-0"), AgentId("auditor-0"))
    """
    ident = _identity_of(ctx)
    commitment = _commitment_of(ident)
    key_id = getattr(ident, "current_key_id", None)
    if commitment is None or key_id is None:
        return
    await ctx.send(
        auditor,
        f"commit:{agent_id}:{key_id}:{commitment}:{ctx.time}".encode(),
    )


async def _emit_rotation(
    ctx: AgentContext,
    agent_id: AgentId,
    auditor: AgentId,
    new_seed: bytes,
) -> None:
    """Rotate the agent's key and emit ``rotate:`` + the fresh ``commit:`` line.

    Capability-gated: a plugin without ``rotate_key`` (``did_key``) is left
    untouched; a plugin whose rotation yields no readable evidence emits
    nothing rather than crashing.

    Example::

        await _emit_rotation(ctx, AgentId("signer-0"), AgentId("auditor-0"), b"s")
    """
    ident = _identity_of(ctx)
    if not hasattr(ident, "rotate_key"):
        return
    returned = ident.rotate_key(new_seed)
    evidence = _rotation_evidence(ident, returned)
    if evidence is None:
        return
    old_key_id, new_key_id = evidence
    await ctx.send(
        auditor,
        f"rotate:{agent_id}:{old_key_id}:{new_key_id}:{ctx.time}".encode(),
    )
    await _emit_commit(ctx, agent_id, auditor)


class HonestSigner(StateMachineAgent):
    """Publishes its commitment, signs, rotates to the committed key, repeats.

    Emits ``commit:``, ``rotate:`` and ``signed:...:ok`` lines so the
    pre-rotation validator can bind every rotation to the digest committed
    one establishment event earlier, and confirm every honest signature sits
    inside a valid key window. All identity interactions are
    capability-gated, so the agent also runs (and fails honestly) under
    plugins with no rotation or no commitments.

    Example::

        agent = HonestSigner(AgentId("signer-0"), AgentId("auditor-0"), rounds=6)
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        rounds: int = 6,
        rotate_at_round: int = 3,
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._rounds = rounds
        self._rotate_at_round = rotate_at_round
        self._round = 0

    async def _emit_round(self, ctx: AgentContext) -> None:
        self._round += 1
        ident = _identity_of(ctx)
        if ident is None:  # pragma: no cover - scenario always configures identity
            return
        if hasattr(ident, "set_clock"):
            ident.set_clock(ctx.time)

        if self._round == 1:
            await _emit_commit(ctx, self._id, self._auditor)

        if self._round == self._rotate_at_round:
            await _emit_rotation(ctx, self._id, self._auditor, b"rot:" + str(self._id).encode())

        sig = ident.sign(f"heartbeat:{self._id}:{self._round}".encode())
        await ctx.send(
            self._auditor,
            f"signed:{self._id}:{_key_id_token(sig)}:{_signed_at_token(sig, ctx.time)}:ok".encode(),
        )

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit the first signing round (inception commitment included).

        Example::

            await agent.on_start(ctx)
        """
        await self._emit_round(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Advance one round on each auditor ``tick:`` pulse.

        Example::

            await agent.on_message(ctx, auditor, b"tick:1")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("tick:") and self._round < self._rounds:
            await self._emit_round(ctx)


class ByzantineSigner(StateMachineAgent):
    """Hijack attempt, post-rotation forgery, backdating, then recovery.

    The attacker models a live-key compromise: it holds its own *current*
    private key. Phase timing (defaults ``rounds=6``, ``rotate_at_round=3``,
    ``hijack_at_round=4``):

    * rounds 1..2 — honest signing (inception ``commit:`` at round 1);
    * round 3 — the normal mid-run rotation every signer performs; the
      pre-rotation key it retires becomes the forgery material;
    * round 4 — **hijack**: ``forge_rotation`` mints a continuity-signed
      rotation to an attacker-chosen key; the digest cannot match the prior
      commitment, so the attempt is emitted as a rejected
      ``rotate_attempt:...:hijack`` line (plus an honest heartbeat — the
      current key is still valid);
    * round 5 — **forgery** with the stale round-3 key and **backdating**
      with the current key claiming tick ``0.0``;
    * final round — **recovery**: a legitimate rotation to the genuinely
      pre-committed cold key, then an honest heartbeat under it.

    Every phase is capability-gated: under ``ed25519_rotating`` the hijack
    phase is skipped (no ``forge_rotation``) and the agent degrades to the
    merged scenario's forgery+backdating attacker; under ``did_key`` it
    behaves like an honest (keyless) signer.

    Example::

        agent = ByzantineSigner(AgentId("byz-0"), AgentId("auditor-0"), rounds=6)
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        rounds: int = 6,
        rotate_at_round: int = 3,
        hijack_at_round: int = 4,
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._rounds = rounds
        self._rotate_at_round = rotate_at_round
        self._hijack_at_round = hijack_at_round
        self._round = 0
        self._old_key_id = ""

    async def _emit_honest_sig(self, ctx: AgentContext, ident: Any) -> None:
        sig = ident.sign(f"heartbeat:{self._id}:{self._round}".encode())
        await ctx.send(
            self._auditor,
            f"signed:{self._id}:{_key_id_token(sig)}:{_signed_at_token(sig, ctx.time)}:ok".encode(),
        )

    async def _emit_hijack(self, ctx: AgentContext, ident: Any) -> None:
        """Mint and emit the rejected hijack attempt (no state is mutated)."""
        prior = _commitment_of(ident)
        if prior is None or not hasattr(ident, "forge_rotation"):
            return
        forged = ident.forge_rotation(b"attacker:" + str(self._id).encode())
        alg = prior.split(":", 1)[0]
        revealed = f"{alg}:{hashlib.new(alg, forged.new_public_key).hexdigest()}"
        await ctx.send(
            self._auditor,
            (
                f"rotate_attempt:{self._id}:{forged.old_key_id}:"
                f"{revealed}:{prior}:{ctx.time}:hijack"
            ).encode(),
        )

    async def _emit_attacks(self, ctx: AgentContext, ident: Any) -> None:
        """Post-rotation forgery with the stale key, then a backdated signature."""
        if self._old_key_id and hasattr(ident, "sign_with"):
            from nest_plugins_reference.identity.ed25519_prerotation import KeyId

            forged = ident.sign_with(
                f"forged:{self._id}:{self._round}".encode(), KeyId(self._old_key_id)
            )
            await ctx.send(
                self._auditor,
                (
                    f"signed:{self._id}:{_key_id_token(forged)}:"
                    f"{_signed_at_token(forged, ctx.time)}:forge"
                ).encode(),
            )

        sig = ident.sign(f"backdated:{self._id}:{self._round}".encode())
        backdated_tick = 0.0  # claim it sits at the very start (a closed window)
        await ctx.send(
            self._auditor,
            f"signed:{self._id}:{_key_id_token(sig)}:{backdated_tick}:backdate".encode(),
        )

    async def _emit_round(self, ctx: AgentContext) -> None:
        self._round += 1
        ident = _identity_of(ctx)
        if ident is None:  # pragma: no cover - scenario always configures identity
            return
        if hasattr(ident, "set_clock"):
            ident.set_clock(ctx.time)

        can_rotate = hasattr(ident, "rotate_key")

        if self._round == 1:
            await _emit_commit(ctx, self._id, self._auditor)

        if self._round == self._rotate_at_round and can_rotate:
            self._old_key_id = str(getattr(ident, "current_key_id", ""))
            await _emit_rotation(ctx, self._id, self._auditor, b"rot:" + str(self._id).encode())

        if self._round == self._hijack_at_round:
            await self._emit_hijack(ctx, ident)

        if self._round == self._hijack_at_round + 1 and can_rotate:
            # Attack round: no honest heartbeat, mirroring the merged scenario.
            await self._emit_attacks(ctx, ident)
            return

        if self._round == self._rounds and can_rotate:
            # Recovery: rotate to the genuinely pre-committed cold key.
            await _emit_rotation(
                ctx, self._id, self._auditor, b"recovery:" + str(self._id).encode()
            )

        await self._emit_honest_sig(ctx, ident)

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit the first signing round (inception commitment included).

        Example::

            await agent.on_start(ctx)
        """
        await self._emit_round(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Advance one round on each auditor ``tick:`` pulse.

        Example::

            await agent.on_message(ctx, auditor, b"tick:1")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("tick:") and self._round < self._rounds:
            await self._emit_round(ctx)


class AuditorAgent(StateMachineAgent):
    """Drives rounds and records signatures; the trace is the audit log.

    The auditor pulses every signer once per round (``tick:`` messages) via
    self-scheduled ``pulse:`` events at strictly increasing ticks, so the
    externally observed ``ts`` on every trace event advances — the anchor for
    every as-of check the validator makes. All verification happens offline
    in the ``identity_prerotation`` validator against the emitted trace.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"), signers, rounds=6)
    """

    def __init__(self, agent_id: AgentId, signers: list[AgentId], rounds: int = 6) -> None:
        self._id = agent_id
        self._signers = signers
        self._rounds = rounds
        self._round = 1  # round 1 is each signer's own on_start at tick 0

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the first round pulse one tick ahead so the clock advances.

        Round 1 is kicked off by each signer's own ``on_start`` at tick 0;
        the auditor schedules each subsequent round at a strictly increasing
        tick, so round ``N`` lands at logical tick ``N - 1``.

        Example::

            await auditor.on_start(ctx)
        """
        await self._schedule_next(ctx)

    async def _schedule_next(self, ctx: AgentContext) -> None:
        if self._round >= self._rounds:
            return
        await ctx.schedule(1.0, b"pulse:")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Drive the next round on each self-scheduled ``pulse:`` tick.

        Example::

            await auditor.on_message(ctx, auditor, b"pulse:")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("pulse:"):
            return
        self._round += 1
        for signer in self._signers:
            await ctx.send(signer, f"tick:{self._round}".encode())
        await self._schedule_next(ctx)


def _provision_identities(
    plugins: dict[str, Any],
    signer_ids: list[AgentId],
) -> None:
    """Instantiate one identity per signer and cross-register inceptions.

    Mirrors the merged scenario's identity wiring: resolve the class at
    ``plugins["identity"]``, build a per-agent instance with a deterministic
    seed, cross-register peers, and stash the instances under
    ``plugins["_agent_plugins"]`` for the runner to apply as per-agent
    overrides. Cross-registration prefers the pre-rotation inception path
    (public key **plus** commitment via ``register_peer_inception``) and
    falls back to plain ``register_peer`` for plugins without commitments.
    No-op when no identity plugin class is configured.

    Example::

        _provision_identities(plugins, [AgentId("signer-0"), AgentId("byz-0")])
    """
    identity_cls = plugins.get("identity")
    if identity_cls is None or not isinstance(identity_cls, type):
        return

    identities: dict[AgentId, Any] = {
        aid: identity_cls(aid, seed=b"identity-prerotation:" + str(aid).encode())
        for aid in signer_ids
    }
    for aid, ident in identities.items():
        for peer_id, peer_ident in identities.items():
            if peer_id == aid:
                continue
            peer_commitment = _commitment_of(peer_ident)
            if peer_commitment is not None and hasattr(ident, "register_peer_inception"):
                ident.register_peer_inception(peer_id, peer_ident.public_key, peer_commitment)
            elif hasattr(ident, "register_peer"):
                ident.register_peer(peer_id, peer_ident.public_key)

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    for aid, ident in identities.items():
        agent_plugins.setdefault(aid, {})["identity"] = ident

    plugins.pop("identity", None)


def identity_prerotation_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create honest + byzantine signers and one auditor.

    Config flags (``task.config``): ``rounds`` (default 6),
    ``rotate_at_round`` (default 3), ``hijack_at_round`` (default 4), and
    ``byzantine_fraction`` (default 0.10, overridable by
    ``failures.byzantine_agents`` or explicit agent roles). The four-phase
    byzantine sequence needs the hijack to land after the mid-run rotation
    and to leave room for the attack round plus the final-round recovery, so
    the flags are validated up front and rejected loudly when they cannot
    produce the sequence.

    Example::

        agents = identity_prerotation_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 6))
    rotate_at_round = int(task_config.get("rotate_at_round", 3))
    hijack_at_round = int(task_config.get("hijack_at_round", 4))
    byzantine_fraction = config.failures.byzantine_agents or task_config.get(
        "byzantine_fraction", 0.10
    )

    if hijack_at_round <= rotate_at_round:
        msg = f"hijack_at_round ({hijack_at_round}) must follow rotate_at_round ({rotate_at_round})"
        raise ValueError(msg)
    if rounds < hijack_at_round + 2:
        msg = (
            f"rounds ({rounds}) too small: need hijack_at_round + 2 "
            f"({hijack_at_round + 2}) for the attack and recovery phases"
        )
        raise ValueError(msg)

    signer_count = max(1, config.agents.count - 1)
    byzantine_count = int(signer_count * byzantine_fraction)
    honest_count = signer_count - byzantine_count

    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "honest":
                honest_count = role.count
            elif role.name == "byzantine":
                byzantine_count = role.count

    auditor_id = AgentId("auditor-0")
    honest_ids = [AgentId(f"signer-{i}") for i in range(honest_count)]
    byzantine_ids = [AgentId(f"byz-{i}") for i in range(byzantine_count)]
    signers: list[AgentId] = honest_ids + byzantine_ids

    _provision_identities(plugins, signers)

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in honest_ids:
        agents[aid] = HonestSigner(
            aid, auditor=auditor_id, rounds=rounds, rotate_at_round=rotate_at_round
        )
    for aid in byzantine_ids:
        agents[aid] = ByzantineSigner(
            aid,
            auditor=auditor_id,
            rounds=rounds,
            rotate_at_round=rotate_at_round,
            hijack_at_round=hijack_at_round,
        )

    agents[auditor_id] = AuditorAgent(auditor_id, signers=signers, rounds=rounds)
    return agents
