# SPDX-License-Identifier: Apache-2.0
"""Identity-recoverable scenario: time-locked rotation + K-of-N social recovery.

This scenario exercises the two governance mechanisms unique to
``ed25519_recoverable`` that ``ed25519_rotating`` (and ``did_key``) cannot
demonstrate:

1. **Time-locked rotations.** Honest signers rotate with a future
   ``activates_at`` so the key window is visible in the trace; byzantine
   signers attempt *instant* rotations (``activates_at == current_tick``) which
   the plugin rejects — the rejection itself is emitted into the trace and
   verified by the validator.

2. **K-of-N social recovery.** One designated signer per run has its key
   "compromised" at a configured round; K-of-N recovery attesters co-sign a
   ``RecoveryEvent`` that force-installs a fresh key, bypassing continuity
   entirely.  The recovered signer keeps signing under the new key;  the
   validator confirms the recovery trace line appeared and subsequent honest
   signatures are accepted.

Trace line protocol (carried in message bodies, ``:``-delimited):

* ``rotate:<agent>:<old_key_id>:<new_key_id>:<activates_at>`` — a time-locked
  rotation announced; the old key's window closes at ``activates_at``.
* ``activated:<agent>:<old_key_id>:<new_key_id>:<tick>`` — rotation activated
  (clock reached ``activates_at``).
* ``recover:<agent>:<old_key_id>:<new_key_id>:<tick>`` — social recovery
  applied; force-installs the new key from tick.
* ``timelock_reject:<agent>:<attempted_at>:<lock>`` — attempted instant
  rotation rejected by time-lock.
* ``signed:<agent>:<key_id>:<claimed_tick>:<verdict>`` — a signed heartbeat;
  ``verdict`` is ``ok`` (honest), ``forge`` (post-rotation with stale key), or
  ``backdate`` (new-key sig claiming old tick).

Example::

    agents = identity_recoverable_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


def _identity_of(ctx: AgentContext) -> Any:
    return ctx.plugins.get("identity")


def _key_id_token(sig: Any) -> str:
    return str(getattr(sig, "key_id", None))


def _signed_at_token(sig: Any, fallback: float) -> str:
    value = getattr(sig, "signed_at", None)
    return str(fallback if value is None else value)


class HonestSigner(StateMachineAgent):
    """Signs heartbeats, performs a time-locked rotation mid-run.

    Uses ``advance()`` to tick the plugin clock, then calls ``rotate()``
    (not ``rotate_key()``) which announces a pending rotation.  The pending
    rotation activates automatically once ``advance()`` reaches
    ``activates_at``.  Both the announcement and the activation are emitted
    into the trace for the validator.

    Also acts as a recovery attester for the designated victim agent: when
    asked, signs a recovery event and broadcasts it to the auditor.

    Example::

        agent = HonestSigner(AgentId("signer-0"), AgentId("auditor-0"), rounds=10)
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        rounds: int = 10,
        rotate_at_round: int = 4,
        time_lock: float = 3.0,
        victim_id: AgentId | None = None,
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._rounds = rounds
        self._rotate_at_round = rotate_at_round
        self._time_lock = time_lock
        self._victim_id = victim_id
        self._round = 0
        self._pending_activates_at: float | None = None

    async def _emit_round(self, ctx: AgentContext) -> None:
        self._round += 1
        ident = _identity_of(ctx)
        if ident is None:  # pragma: no cover
            return

        if hasattr(ident, "advance"):
            ident.advance(float(ctx.time))

        # Announce time-locked rotation at the designated round.
        if self._round == self._rotate_at_round and hasattr(ident, "rotate"):
            old_key_id = str(ident.current_key_id)
            activates_at = float(ctx.time) + self._time_lock
            pending = ident.rotate(b"rot:" + str(self._id).encode(), activates_at=activates_at)
            self._pending_activates_at = activates_at
            await ctx.send(
                self._auditor,
                f"rotate:{self._id}:{old_key_id}:{pending.new_key_id}:{activates_at}".encode(),
            )

        # Once the rotation has activated, emit the activation event once.
        if (
            self._pending_activates_at is not None
            and float(ctx.time) >= self._pending_activates_at
        ):
            # The plugin auto-activates in advance(); read the now-current key.
            new_key_id = str(ident.current_key_id)
            await ctx.send(
                self._auditor,
                f"activated:{self._id}:{new_key_id}:{ctx.time}".encode(),
            )
            self._pending_activates_at = None

        sig = ident.sign(f"heartbeat:{self._id}:{self._round}".encode())
        await ctx.send(
            self._auditor,
            f"signed:{self._id}:{_key_id_token(sig)}:{_signed_at_token(sig, ctx.time)}:ok".encode(),
        )

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit the first signing round.

        Example::

            await agent.on_start(ctx)
        """
        await self._emit_round(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Advance one round on each auditor tick, or co-sign a recovery request.

        Example::

            await agent.on_message(ctx, auditor, b"tick:1")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("tick:") and self._round < self._rounds:
            await self._emit_round(ctx)
        elif msg.startswith("recover_request:") and self._victim_id is not None:
            # Format: recover_request:<target>:<old_key_id>:<new_public_key_hex>:<recovered_at>
            parts = msg.split(":", 5)
            if len(parts) < 5:
                return
            target_str, old_key_hex, new_pub_hex, recovered_at_str = (
                parts[1],
                parts[2],
                parts[3],
                parts[4],
            )
            ident = _identity_of(ctx)
            if not hasattr(ident, "sign_recovery"):
                return
            from nest_core.types import AgentId as Aid

            from nest_plugins_reference.identity.ed25519_recoverable import KeyId

            target = Aid(target_str)
            old_key_id = KeyId(old_key_hex)
            new_pub = bytes.fromhex(new_pub_hex)
            recovered_at = float(recovered_at_str)
            sig_bytes = ident.sign_recovery(target, old_key_id, new_pub, recovered_at)
            await ctx.send(
                self._auditor,
                f"recovery_sig:{self._id}:{target_str}:{old_key_hex}:{new_pub_hex}:{recovered_at_str}:{sig_bytes.hex()}".encode(),
            )


class VictimSigner(StateMachineAgent):
    """A signer whose key is 'compromised' mid-run and later recovered via attesters.

    At ``compromise_round`` the victim broadcasts a recovery request to all
    attesters.  Once the auditor relays back enough ``recovery_sig:`` messages
    (≥ quorum_k), the victim assembles and applies the ``RecoveryEvent``,
    emits a ``recover:`` trace line, and resumes signing under the new key.

    Example::

        agent = VictimSigner(AgentId("victim-0"), AgentId("auditor-0"), attester_ids=[...])
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        attester_ids: list[AgentId],
        quorum_k: int = 2,
        rounds: int = 10,
        compromise_round: int = 5,
        recovery_seed: bytes = b"recovery-seed",
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._attester_ids = attester_ids
        self._quorum_k = quorum_k
        self._rounds = rounds
        self._compromise_round = compromise_round
        self._recovery_seed = recovery_seed
        self._round = 0
        self._recovery_initiated = False
        self._collected_sigs: dict[str, bytes] = {}
        self._recovery_applied = False
        self._new_pub: bytes | None = None
        self._new_key_id: str | None = None
        self._old_key_id: str | None = None
        self._recovered_at: float | None = None
        self._recovery_private_key: Any = None

    def _prepare_recovery_key(self, ident: Any) -> tuple[bytes, str]:
        """Derive the recovery public key deterministically; stash the private key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from nest_plugins_reference.identity.ed25519_recoverable import (
            _derive_seed,
            _key_id_for,
            _public_bytes,
        )

        priv = Ed25519PrivateKey.from_private_bytes(
            _derive_seed(self._recovery_seed, self._id, 99)
        )
        self._recovery_private_key = priv
        new_pub = _public_bytes(priv.public_key())
        new_kid = str(_key_id_for(new_pub))
        return new_pub, new_kid

    async def _emit_round(self, ctx: AgentContext) -> None:
        self._round += 1
        ident = _identity_of(ctx)
        if ident is None:  # pragma: no cover
            return
        if hasattr(ident, "advance"):
            ident.advance(float(ctx.time))

        can_recover = hasattr(ident, "observe_recovery") and hasattr(ident, "current_key_id")
        if self._round == self._compromise_round and not self._recovery_initiated and can_recover:
            self._recovery_initiated = True
            self._old_key_id = str(ident.current_key_id)
            self._recovered_at = float(ctx.time) + 1.0
            new_pub, new_kid = self._prepare_recovery_key(ident)
            self._new_pub = new_pub
            self._new_key_id = new_kid
            # Broadcast recovery request to all attesters via auditor relay.
            for att_id in self._attester_ids:
                await ctx.send(
                    att_id,
                    f"recover_request:{self._id}:{self._old_key_id}:{new_pub.hex()}:{self._recovered_at}".encode(),
                )

        sig = ident.sign(f"heartbeat:{self._id}:{self._round}".encode())
        await ctx.send(
            self._auditor,
            f"signed:{self._id}:{_key_id_token(sig)}:{_signed_at_token(sig, ctx.time)}:ok".encode(),
        )

    async def _try_apply_recovery(self, ctx: AgentContext) -> None:
        if self._recovery_applied or len(self._collected_sigs) < self._quorum_k:
            return
        if self._new_pub is None or self._old_key_id is None or self._recovered_at is None:
            return  # pragma: no cover

        ident = _identity_of(ctx)
        if not hasattr(ident, "observe_recovery"):
            return

        from nest_plugins_reference.identity.ed25519_recoverable import (
            KeyId,
            RecoveryEvent,
            _key_id_for,
        )

        new_key_id = _key_id_for(self._new_pub)
        recovery = RecoveryEvent(
            target_agent=self._id,
            old_key_id=KeyId(self._old_key_id),
            new_key_id=new_key_id,
            new_public_key=self._new_pub,
            recovered_at=self._recovered_at,
            attester_signatures=dict(self._collected_sigs),
            new_epoch=1,
        )
        ok = ident.observe_recovery(recovery)
        if ok:
            self._recovery_applied = True
            # Inject the private key into the newly installed epoch so the
            # victim can continue signing.  observe_recovery() only stores the
            # public key; the private key was derived locally in
            # _prepare_recovery_key() and is safe to inject here.
            if self._recovery_private_key is not None:
                epochs = ident._epochs.get(self._id, [])  # noqa: SLF001
                if epochs and epochs[-1].private_key is None:
                    epochs[-1].private_key = self._recovery_private_key
            await ctx.send(
                self._auditor,
                f"recover:{self._id}:{self._old_key_id}:{new_key_id}:{self._recovered_at}".encode(),
            )

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit the first signing round.

        Example::

            await agent.on_start(ctx)
        """
        await self._emit_round(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle tick pulses and incoming recovery signatures.

        Example::

            await agent.on_message(ctx, sender, b"tick:2")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("tick:") and self._round < self._rounds:
            await self._emit_round(ctx)
        elif msg.startswith("recovery_sig:"):
            # Format: recovery_sig:<attester>:<target>:<old_key>:<new_pub_hex>:<recovered_at>:<sig_hex>
            parts = msg.split(":", 7)
            if len(parts) < 7:
                return
            attester_id_str = parts[1]
            sig_hex = parts[6]
            self._collected_sigs[attester_id_str] = bytes.fromhex(sig_hex)
            await self._try_apply_recovery(ctx)


class ByzantineSigner(StateMachineAgent):
    """Attempts instant rotation (below time-lock) and post-rotation forgery.

    Two attacks:

    * At ``attack_round`` calls ``rotate()`` with ``activates_at ==
      current_tick``, which the plugin must reject with ``ValueError``.  The
      rejection is emitted as a ``timelock_reject:`` trace line.
    * After performing a valid (time-locked) rotation, uses ``sign_with()``
      to forge a signature with the rotated-out key, and also backdates a
      new-key signature — exactly the two attacks the validator must catch.

    Example::

        agent = ByzantineSigner(AgentId("byz-0"), AgentId("auditor-0"), rounds=10)
    """

    def __init__(
        self,
        agent_id: AgentId,
        auditor: AgentId,
        rounds: int = 10,
        attack_round: int = 4,
        time_lock: float = 3.0,
    ) -> None:
        self._id = agent_id
        self._auditor = auditor
        self._rounds = rounds
        self._attack_round = attack_round
        self._time_lock = time_lock
        self._round = 0
        self._old_key_id: str = ""
        self._rotated = False

    async def _emit_round(self, ctx: AgentContext) -> None:
        self._round += 1
        ident = _identity_of(ctx)
        if ident is None:  # pragma: no cover
            return
        if hasattr(ident, "advance"):
            ident.advance(float(ctx.time))

        can_attack = hasattr(ident, "rotate") and hasattr(ident, "sign_with")

        if self._round == self._attack_round and can_attack:
            # Attack 1: attempt instant rotation (must be rejected).
            try:
                ident.rotate(b"instant-evil", activates_at=float(ctx.time))
                # If we reach here the plugin did not enforce the time-lock.
                await ctx.send(
                    self._auditor,
                    f"timelock_accepted:{self._id}:{ctx.time}".encode(),
                )
            except ValueError:
                await ctx.send(
                    self._auditor,
                    f"timelock_reject:{self._id}:{ctx.time}:{self._time_lock}".encode(),
                )

            # Now perform a valid (time-locked) rotation for subsequent forgery.
            self._old_key_id = str(ident.current_key_id)
            activates_at = float(ctx.time) + self._time_lock
            pending = ident.rotate(b"rot:" + str(self._id).encode(), activates_at=activates_at)
            await ctx.send(
                self._auditor,
                f"rotate:{self._id}:{self._old_key_id}:{pending.new_key_id}:{activates_at}".encode(),
            )
            self._rotated = True

        if self._rotated and float(ctx.time) >= float(self._attack_round) + self._time_lock:
            # The rotation has activated; attempt post-rotation forgery.
            from nest_plugins_reference.identity.ed25519_recoverable import KeyId

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
            # Attack 2: backdating — sign with new key, claim old tick.
            sig = ident.sign(f"backdated:{self._id}:{self._round}".encode())
            await ctx.send(
                self._auditor,
                f"signed:{self._id}:{_key_id_token(sig)}:0.0:backdate".encode(),
            )
            return

        sig = ident.sign(f"heartbeat:{self._id}:{self._round}".encode())
        await ctx.send(
            self._auditor,
            f"signed:{self._id}:{_key_id_token(sig)}:{_signed_at_token(sig, ctx.time)}:ok".encode(),
        )

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit the first signing round.

        Example::

            await agent.on_start(ctx)
        """
        await self._emit_round(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Advance one round on each auditor tick.

        Example::

            await agent.on_message(ctx, auditor, b"tick:1")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("tick:") and self._round < self._rounds:
            await self._emit_round(ctx)


class AuditorAgent(StateMachineAgent):
    """Drives rounds, relays recovery signatures, records all trace events.

    Example::

        auditor = AuditorAgent(AgentId("auditor-0"), signers, rounds=10)
    """

    def __init__(self, agent_id: AgentId, signers: list[AgentId], rounds: int = 10) -> None:
        self._id = agent_id
        self._signers = signers
        self._rounds = rounds
        self._round = 1

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the first round pulse.

        Example::

            await auditor.on_start(ctx)
        """
        await self._schedule_next(ctx)

    async def _schedule_next(self, ctx: AgentContext) -> None:
        if self._round >= self._rounds:
            return
        await ctx.schedule(1.0, b"pulse:")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Drive the next round on each self-scheduled pulse.

        Also relays recovery signatures from attesters back to the victim.

        Example::

            await auditor.on_message(ctx, auditor, b"pulse:")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("pulse:"):
            self._round += 1
            for signer in self._signers:
                await ctx.send(signer, f"tick:{self._round}".encode())
            await self._schedule_next(ctx)
        elif msg.startswith("recovery_sig:"):
            # Relay recovery signatures back: the victim's id is parts[2].
            parts = msg.split(":", 7)
            if len(parts) >= 3:
                from nest_core.types import AgentId as Aid

                victim_id = Aid(parts[2])
                if victim_id in self._signers:
                    await ctx.send(victim_id, payload)


def _provision_identities(
    plugins: dict[str, Any],
    victim_id: AgentId,
    signer_ids: list[AgentId],
    attester_ids: list[AgentId],
    quorum_k: int,
) -> None:
    """Instantiate per-agent identity instances with recovery configuration.

    The victim's plugin is constructed with ``recovery_attesters`` and
    ``recovery_quorum_k`` set; all other agents get plain instances.  Attester
    identities are cross-registered with the victim so the victim can verify
    their recovery signatures.

    Example::

        _provision_identities(plugins, victim_id, signers, attesters, quorum_k=2)
    """
    identity_cls = plugins.get("identity")
    if identity_cls is None or not isinstance(identity_cls, type):
        return

    import inspect

    cls_params = set(inspect.signature(identity_cls.__init__).parameters)
    supports_recovery = "recovery_attesters" in cls_params

    identities: dict[AgentId, Any] = {}
    for aid in signer_ids:
        if aid == victim_id and supports_recovery:
            identities[aid] = identity_cls(
                aid,
                seed=b"identity-recoverable:" + str(aid).encode(),
                recovery_attesters=attester_ids,
                recovery_quorum_k=quorum_k,
            )
        else:
            identities[aid] = identity_cls(
                aid, seed=b"identity-recoverable:" + str(aid).encode()
            )

    # Cross-register public keys so verify() works across agents.
    for aid, ident in identities.items():
        for peer_id, peer_ident in identities.items():
            if peer_id != aid and hasattr(ident, "register_peer"):
                ident.register_peer(peer_id, peer_ident.public_key)

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    for aid, ident in identities.items():
        agent_plugins.setdefault(aid, {})["identity"] = ident

    plugins.pop("identity", None)


def identity_recoverable_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create honest signers, one victim, byzantine signers, and one auditor.

    Configuration keys (all optional):

    * ``rounds`` (int, default 10): total rounds per agent.
    * ``rotate_at_round`` (int, default 4): round at which honest signers rotate.
    * ``compromise_round`` (int, default 5): round at which the victim initiates recovery.
    * ``time_lock`` (float, default 3.0): minimum tick gap before a rotation activates.
    * ``recovery_attesters`` (int, default 3): number of agents that act as attesters.
    * ``recovery_quorum_k`` (int, default 2): minimum attesters required for recovery.

    Example::

        agents = identity_recoverable_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 10))
    rotate_at_round = int(task_config.get("rotate_at_round", 4))
    compromise_round = int(task_config.get("compromise_round", 5))
    time_lock = float(task_config.get("time_lock", 3.0))
    num_attesters = int(task_config.get("recovery_attesters", 3))
    quorum_k = int(task_config.get("recovery_quorum_k", 2))
    byzantine_fraction = config.failures.byzantine_agents or float(
        task_config.get("byzantine_fraction", 0.10)
    )

    total_signers = max(1, config.agents.count - 1)
    byzantine_count = int(total_signers * byzantine_fraction)
    honest_count = max(0, total_signers - byzantine_count - 1)  # -1 for victim

    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "honest":
                honest_count = role.count
            elif role.name == "byzantine":
                byzantine_count = role.count

    auditor_id = AgentId("auditor-0")
    victim_id = AgentId("victim-0")
    honest_ids = [AgentId(f"signer-{i}") for i in range(honest_count)]
    byzantine_ids = [AgentId(f"byz-{i}") for i in range(byzantine_count)]

    # Pick attesters from honest signers (or wrap around if not enough).
    attester_ids = honest_ids[:num_attesters]
    if len(attester_ids) < quorum_k:
        quorum_k = len(attester_ids)

    all_signers: list[AgentId] = [victim_id] + honest_ids + byzantine_ids

    _provision_identities(plugins, victim_id, all_signers, attester_ids, quorum_k)

    agents: dict[AgentId, StateMachineAgent] = {}

    agents[victim_id] = VictimSigner(
        victim_id,
        auditor=auditor_id,
        attester_ids=attester_ids,
        quorum_k=quorum_k,
        rounds=rounds,
        compromise_round=compromise_round,
    )

    for aid in honest_ids:
        agents[aid] = HonestSigner(
            aid,
            auditor=auditor_id,
            rounds=rounds,
            rotate_at_round=rotate_at_round,
            time_lock=time_lock,
            victim_id=victim_id,
        )

    for aid in byzantine_ids:
        agents[aid] = ByzantineSigner(
            aid,
            auditor=auditor_id,
            rounds=rounds,
            attack_round=rotate_at_round,
            time_lock=time_lock,
        )

    agents[auditor_id] = AuditorAgent(auditor_id, signers=all_signers, rounds=rounds)
    return agents
