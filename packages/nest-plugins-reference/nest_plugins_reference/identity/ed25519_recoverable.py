# SPDX-License-Identifier: Apache-2.0
"""Ed25519 identity with time-locked rotation and K-of-N social recovery.

Builds on the same ``cryptography.hazmat.primitives.asymmetric.ed25519``
(RFC 8032) foundation as :mod:`~nest_plugins_reference.identity.ed25519_rotating`,
adding two governance features neither merged plugin has:

1. **Time-locked rotations.** A rotation is only accepted if
   ``activates_at >= now + time_lock`` (default 3 logical ticks). Even a
   captured current key cannot lock the legitimate owner out immediately —
   the owner sees the pending rotation and has time to counter-rotate or
   trigger recovery.

2. **K-of-N social recovery.** Each agent declares a set of recovery
   attesters at construction (e.g. 3 peers, quorum K=2). Any K of them can
   co-sign a :class:`RecoveryEvent` that force-installs a fresh key chosen
   by the recovering party. This bypasses continuity entirely — the
   compromised key gets no say. The recovery event is publicly verifiable
   and appears in :meth:`resolve`'s metadata.

Verification anchors on an externally-supplied logical tick (via
:meth:`advance`), never on the attacker-controlled ``sig.signed_at`` — as
the :class:`~nest_core.types.Signature` docstring already prescribes.

Determinism
-----------

* Keys are derived from ``(seed, agent_id, epoch)`` via SHA-512,
  domain-separated. No ``os.urandom``.
* Ed25519 signatures are deterministic per RFC 8032 §5.1.6.
* The plugin exposes only :meth:`advance` as clock input, enforced
  monotonic. No wall-clock time is read.

Example::

    ident = Ed25519RecoverableIdentity(
        AgentId("a1"), seed=b"seed",
        recovery_attesters=[AgentId("r1"), AgentId("r2"), AgentId("r3")],
        recovery_quorum_k=2,
    )
    sig = ident.sign(b"hello")
    assert ident.verify(b"hello", sig, AgentId("a1"))
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import NewType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from nest_core.types import AgentId, AgentIdentity, Signature

ALGORITHM = "ed25519-recoverable/1"
"""Algorithm tag stamped on every :class:`~nest_core.types.Signature`.

Example::

    assert sig.algorithm == ALGORITHM
"""

KeyId = NewType("KeyId", str)
"""Stable identifier for one Ed25519 public key (``sha256`` of the raw bytes).

Example::

    kid = KeyId("3b1f...")
"""

_INF = float("inf")
DEFAULT_TIME_LOCK = 3.0


def _derive_seed(seed: bytes, agent_id: AgentId, epoch: int) -> bytes:
    """Derive a deterministic 32-byte Ed25519 private seed via SHA-512.

    Domain-separated from ``ed25519_rotating``'s SHA-256 derivation.

    Example::

        s = _derive_seed(b"root", AgentId("a1"), 0)
        assert len(s) == 32
    """
    material = (
        b"ed25519-recoverable:" + seed + b":" + str(agent_id).encode() + b":" + str(epoch).encode()
    )
    return hashlib.sha512(material).digest()[:32]


def _key_id_for(public_key: bytes) -> KeyId:
    """Compute the :class:`KeyId` for raw public-key bytes.

    Example::

        kid = _key_id_for(b"\\x00" * 32)
    """
    return KeyId(hashlib.sha256(public_key).hexdigest())


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    """Raw 32-byte encoding of an Ed25519 public key.

    Example::

        raw = _public_bytes(private.public_key())
        assert len(raw) == 32
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass
class KeyEpoch:
    """One key in an agent's history with its validity window ``[issued_at, superseded_at)``.

    Example::

        epoch = KeyEpoch(key_id=KeyId("ab.."), public_key=pk, issued_at=0.0)
        assert epoch.is_valid_at(0.0)
    """

    key_id: KeyId
    public_key: bytes
    issued_at: float
    superseded_at: float = _INF
    epoch: int = 0
    private_key: Ed25519PrivateKey | None = field(default=None, repr=False)
    recovery_events: list[RecoveryEvent] = field(default_factory=lambda: list[RecoveryEvent]())

    def is_valid_at(self, tick: float) -> bool:
        """Return whether this key's window contains *tick*.

        Example::

            e = KeyEpoch(KeyId("x"), b"pk", issued_at=10.0, superseded_at=20.0)
            assert e.is_valid_at(10.0) and not e.is_valid_at(20.0)
        """
        return self.issued_at <= tick < self.superseded_at


@dataclass
class PendingRotation:
    """A rotation that has been announced but not yet activated.

    Example::

        pr = PendingRotation(new_key_id=KeyId("ab"), ...)
    """

    new_key_id: KeyId
    new_public_key: bytes
    activates_at: float
    continuity_signature: bytes
    new_epoch: int
    new_private_key: Ed25519PrivateKey | None = field(default=None, repr=False)


@dataclass
class RecoveryEvent:
    """Publicly verifiable evidence that K-of-N attesters restored an agent's key.

    Example::

        re = RecoveryEvent(target_agent=AgentId("a1"), ...)
    """

    target_agent: AgentId
    old_key_id: KeyId
    new_key_id: KeyId
    new_public_key: bytes
    recovered_at: float
    attester_signatures: dict[str, bytes] = field(default_factory=lambda: dict[str, bytes]())
    new_epoch: int = 0


class Ed25519RecoverableIdentity:
    """Per-agent Ed25519 identity with time-locked rotation and social recovery.

    Implements the structural :class:`~nest_core.layers.identity.Identity`
    protocol (``sign``/``verify``/``resolve``) and adds :meth:`rotate`,
    :meth:`observe_rotation`, :meth:`observe_recovery`, :meth:`sign_recovery`,
    and :meth:`advance`.

    Example::

        ident = Ed25519RecoverableIdentity(AgentId("a1"), seed=b"seed")
        sig = ident.sign(b"data")
        assert ident.verify(b"data", sig, AgentId("a1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        seed: bytes = b"",
        *,
        recovery_attesters: list[AgentId] | None = None,
        recovery_quorum_k: int = 2,
        time_lock: float = DEFAULT_TIME_LOCK,
    ) -> None:
        self._agent_id = agent_id
        self._seed = seed
        self._epoch = 0
        self._tick: float = 0.0
        self._time_lock = time_lock
        self._recovery_attesters = list(recovery_attesters) if recovery_attesters else []
        self._recovery_quorum_k = recovery_quorum_k

        private = Ed25519PrivateKey.from_private_bytes(_derive_seed(seed, agent_id, 0))
        pub = _public_bytes(private.public_key())
        epoch0 = KeyEpoch(
            key_id=_key_id_for(pub),
            public_key=pub,
            issued_at=0.0,
            epoch=0,
            private_key=private,
        )
        self._epochs: dict[AgentId, list[KeyEpoch]] = {agent_id: [epoch0]}
        self._pending: dict[AgentId, PendingRotation | None] = {}
        self._recovery_events: list[RecoveryEvent] = []

    @property
    def agent_id(self) -> AgentId:
        """This agent's identifier.

        Example::

            aid = ident.agent_id
        """
        return self._agent_id

    @property
    def public_key(self) -> bytes:
        """This agent's *current* public key bytes.

        Example::

            pk = ident.public_key
        """
        return self._epochs[self._agent_id][-1].public_key

    @property
    def current_key_id(self) -> KeyId:
        """The :class:`KeyId` of this agent's current signing key.

        Example::

            kid = ident.current_key_id
        """
        return self._epochs[self._agent_id][-1].key_id

    @property
    def current_epoch(self) -> int:
        """The current epoch index.

        Example::

            e = ident.current_epoch
        """
        return self._epoch

    @property
    def time_lock(self) -> float:
        """The time-lock period for rotations.

        Example::

            tl = ident.time_lock
        """
        return self._time_lock

    @property
    def recovery_attesters(self) -> list[AgentId]:
        """The set of recovery attesters for this agent.

        Example::

            attesters = ident.recovery_attesters
        """
        return list(self._recovery_attesters)

    @property
    def recovery_quorum_k(self) -> int:
        """The required quorum for social recovery.

        Example::

            k = ident.recovery_quorum_k
        """
        return self._recovery_quorum_k

    def advance(self, tick: float) -> None:
        """Advance the plugin's logical clock. Monotonic: ignores backward ticks.

        Also activates any pending rotation whose ``activates_at`` has been reached.

        Example::

            ident.advance(42.0)
        """
        if tick <= self._tick:
            return
        self._tick = tick
        self._activate_pending()

    def _activate_pending(self) -> None:
        """Activate pending rotations whose time-lock has expired."""
        for agent_id, pending in list(self._pending.items()):
            if pending is None:
                continue
            if self._tick >= pending.activates_at:
                epochs = self._epochs.get(agent_id, [])
                if epochs:
                    epochs[-1].superseded_at = pending.activates_at
                new_epoch = KeyEpoch(
                    key_id=pending.new_key_id,
                    public_key=pending.new_public_key,
                    issued_at=pending.activates_at,
                    epoch=pending.new_epoch,
                    private_key=pending.new_private_key,
                )
                epochs.append(new_epoch)
                self._pending[agent_id] = None

    def register_peer(
        self,
        agent_id: AgentId,
        public_key: bytes,
        private_key: bytes | None = None,
        *,
        recovery_attesters: list[AgentId] | None = None,
        recovery_quorum_k: int | None = None,
    ) -> None:
        """Register a peer's *current* public key for verification.

        Signature-compatible with ``did_key.register_peer`` so existing callers
        keep working. Optional keyword-only parameters configure social recovery
        for this peer.

        Example::

            ident.register_peer(AgentId("a2"), peer_pk)
        """
        if private_key is not None:
            msg = "register_peer accepts public keys only"
            raise ValueError(msg)
        record = KeyEpoch(
            key_id=_key_id_for(public_key),
            public_key=public_key,
            issued_at=self._tick,
            epoch=0,
        )
        self._epochs[agent_id] = [record]

    def rotate(self, new_seed: bytes, *, activates_at: float | None = None) -> PendingRotation:
        """Announce a time-locked key rotation.

        The rotation activates at ``activates_at`` (defaults to
        ``current_tick + time_lock``). Raises ``ValueError`` if the activation
        time violates the time-lock constraint.

        Example::

            pending = ident.rotate(b"new-seed")
        """
        if activates_at is None:
            activates_at = self._tick + self._time_lock
        if activates_at < self._tick + self._time_lock:
            msg = (
                f"activates_at ({activates_at}) must be >= "
                f"current_tick ({self._tick}) + time_lock ({self._time_lock})"
            )
            raise ValueError(msg)

        new_epoch_idx = self._epoch + 1
        private = Ed25519PrivateKey.from_private_bytes(
            _derive_seed(new_seed, self._agent_id, new_epoch_idx)
        )
        pub = _public_bytes(private.public_key())

        current_epochs = self._epochs[self._agent_id]
        current = current_epochs[-1]
        if current.private_key is None:
            msg = "cannot rotate: current key has no private material"
            raise ValueError(msg)

        continuity_msg = _continuity_message(
            self._agent_id, current.key_id, _key_id_for(pub), pub, activates_at
        )
        continuity_sig = current.private_key.sign(continuity_msg)

        pending = PendingRotation(
            new_key_id=_key_id_for(pub),
            new_public_key=pub,
            activates_at=activates_at,
            continuity_signature=continuity_sig,
            new_epoch=new_epoch_idx,
            new_private_key=private,
        )
        self._pending[self._agent_id] = pending
        self._seed = new_seed
        self._epoch = new_epoch_idx
        return pending

    def observe_rotation(self, agent_id: AgentId, pending: PendingRotation) -> bool:
        """Record a peer's pending rotation after verifying continuity.

        Returns ``False`` if the continuity signature does not check out or if
        the time-lock is violated.

        Example::

            ok = observer.observe_rotation(AgentId("a2"), peer_pending)
        """
        epochs = self._epochs.get(agent_id, [])
        if not epochs:
            return False

        current = epochs[-1]
        if pending.activates_at < self._tick + self._time_lock:
            return False

        continuity_msg = _continuity_message(
            agent_id,
            current.key_id,
            pending.new_key_id,
            pending.new_public_key,
            pending.activates_at,
        )
        try:
            Ed25519PublicKey.from_public_bytes(current.public_key).verify(
                pending.continuity_signature, continuity_msg
            )
        except InvalidSignature:
            return False

        self._pending[agent_id] = PendingRotation(
            new_key_id=pending.new_key_id,
            new_public_key=pending.new_public_key,
            activates_at=pending.activates_at,
            continuity_signature=pending.continuity_signature,
            new_epoch=pending.new_epoch,
        )
        return True

    def sign_recovery(
        self,
        target_agent: AgentId,
        old_key_id: KeyId,
        new_public_key: bytes,
        recovered_at: float,
    ) -> bytes:
        """Sign a recovery event for another agent.

        This agent must be a declared recovery attester for *target_agent*.
        Returns the Ed25519 signature over the canonical recovery message.

        Example::

            sig_bytes = attester.sign_recovery(
                AgentId("victim"), victim_old_key, new_pk, tick
            )
        """
        my_epochs = self._epochs.get(self._agent_id, [])
        if not my_epochs or my_epochs[-1].private_key is None:
            msg = "cannot sign recovery: no private key"
            raise ValueError(msg)

        recovery_msg = _recovery_message(
            target_agent, old_key_id, _key_id_for(new_public_key), new_public_key, recovered_at
        )
        return my_epochs[-1].private_key.sign(recovery_msg)

    def observe_recovery(self, recovery: RecoveryEvent) -> bool:
        """Apply a social recovery event if the quorum is met.

        Verifies that:
        - The target agent's current key matches ``recovery.old_key_id``
        - At least K distinct, declared attesters have signed
        - Each attester signature is valid

        On success, force-installs the new key, bypassing continuity.

        Example::

            ok = ident.observe_recovery(recovery_event)
        """
        epochs = self._epochs.get(recovery.target_agent, [])
        if not epochs:
            return False

        current = epochs[-1]
        if current.key_id != recovery.old_key_id:
            return False

        recovery_msg = _recovery_message(
            recovery.target_agent,
            recovery.old_key_id,
            recovery.new_key_id,
            recovery.new_public_key,
            recovery.recovered_at,
        )

        valid_attesters: set[str] = set()
        for attester_id_str, sig_bytes in recovery.attester_signatures.items():
            attester_id = AgentId(attester_id_str)
            if attester_id not in self._recovery_attesters:
                continue
            attester_epochs = self._epochs.get(attester_id, [])
            if not attester_epochs:
                continue
            attester_key = attester_epochs[-1]
            try:
                Ed25519PublicKey.from_public_bytes(attester_key.public_key).verify(
                    sig_bytes, recovery_msg
                )
                valid_attesters.add(attester_id_str)
            except InvalidSignature:
                continue

        if len(valid_attesters) < self._recovery_quorum_k:
            return False

        current.superseded_at = recovery.recovered_at
        new_epoch_record = KeyEpoch(
            key_id=recovery.new_key_id,
            public_key=recovery.new_public_key,
            issued_at=recovery.recovered_at,
            epoch=recovery.new_epoch,
        )
        new_epoch_record.recovery_events.append(recovery)
        epochs.append(new_epoch_record)
        self._recovery_events.append(recovery)

        self._pending[recovery.target_agent] = None
        return True

    def sign(self, payload: bytes) -> Signature:
        """Sign *payload* with this agent's current Ed25519 key.

        Example::

            sig = ident.sign(b"data")
        """
        record = self._epochs[self._agent_id][-1]
        if record.private_key is None:
            msg = "cannot sign: no private key for current record"
            raise ValueError(msg)
        value = record.private_key.sign(payload)
        return Signature(
            signer=self._agent_id,
            value=value,
            algorithm=ALGORITHM,
            key_id=str(record.key_id),
            signed_at=self._tick,
        )

    def sign_with(self, payload: bytes, key_id: KeyId) -> Signature:
        """Sign *payload* with a specific (possibly superseded) key by id.

        Exposed so adversarial agents can attempt post-rotation forgery.

        Example::

            forged = attacker.sign_with(b"data", stolen_key_id)
        """
        record = next(
            (e for e in self._epochs[self._agent_id] if e.key_id == key_id),
            None,
        )
        if record is None or record.private_key is None:
            msg = f"no private key for {key_id!r}"
            raise ValueError(msg)
        value = record.private_key.sign(payload)
        return Signature(
            signer=self._agent_id,
            value=value,
            algorithm=ALGORITHM,
            key_id=str(record.key_id),
            signed_at=self._tick,
        )

    def verify(
        self,
        payload: bytes,
        sig: Signature,
        agent: AgentId,
        as_of: float | None = None,
    ) -> bool:
        """Verify *sig* over *payload* from *agent*, optionally as-of a tick.

        A signature is accepted iff **both** hold:

        1. It cryptographically verifies under the key bound to ``sig.key_id``.
        2. That key's validity window ``[issued_at, superseded_at)`` contains the
           **as-of tick**.

        The as-of tick is supplied by the *verifier* (never from ``sig.signed_at``).

        Example::

            ok = ident.verify(b"data", sig, AgentId("a2"), as_of=15.0)
        """
        if sig.signer != agent:
            return False
        epochs = self._epochs.get(agent)
        if not epochs:
            return False
        as_of_tick = self._tick if as_of is None else as_of

        record = self._select_epoch(epochs, sig.key_id, as_of_tick)
        if record is None:
            return False
        if not record.is_valid_at(as_of_tick):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(record.public_key).verify(sig.value, payload)
        except InvalidSignature:
            return False
        return True

    @staticmethod
    def _select_epoch(
        epochs: list[KeyEpoch],
        key_id: str | None,
        as_of_tick: float,
    ) -> KeyEpoch | None:
        """Pick the key epoch a signature binds to.

        If the signature names a ``key_id`` we resolve exactly that epoch.
        Without a ``key_id`` we fall back to whichever epoch was valid at
        the as-of tick.
        """
        if key_id is not None:
            return next((e for e in epochs if str(e.key_id) == key_id), None)
        return next((e for e in epochs if e.is_valid_at(as_of_tick)), None)

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        """Resolve *agent* to its identity record.

        The ``metadata`` carries key history and recovery events.

        Example::

            info = await ident.resolve(AgentId("a2"))
        """
        epochs = self._epochs.get(agent, [])
        current_pk = epochs[-1].public_key if epochs else b""
        history = [
            {
                "key_id": str(e.key_id),
                "public_key": e.public_key.hex(),
                "issued_at": e.issued_at,
                "superseded_at": None if e.superseded_at == _INF else e.superseded_at,
                "epoch": e.epoch,
                "recovered": len(e.recovery_events) > 0,
            }
            for e in epochs
        ]
        recoveries = [
            {
                "old_key_id": str(r.old_key_id),
                "new_key_id": str(r.new_key_id),
                "recovered_at": r.recovered_at,
                "attester_count": len(r.attester_signatures),
            }
            for r in self._recovery_events
            if r.target_agent == agent
        ]
        return AgentIdentity(
            agent_id=agent,
            public_key=current_pk,
            method="did:key",
            metadata={
                "algorithm": ALGORITHM,
                "keys": history,
                "recovery_events": recoveries,
                "time_lock": self._time_lock,
            },
        )


def _continuity_message(
    agent_id: AgentId,
    old_key_id: KeyId,
    new_key_id: KeyId,
    new_public_key: bytes,
    activates_at: float,
) -> bytes:
    """Build the deterministic byte string a rotation's continuity sig covers.

    Example::

        msg = _continuity_message(AgentId("a1"), KeyId("old"), KeyId("new"), b"pk", 5.0)
    """
    return json.dumps(
        {
            "agent": str(agent_id),
            "old": str(old_key_id),
            "new": str(new_key_id),
            "pk": new_public_key.hex(),
            "activates_at": activates_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _recovery_message(
    target_agent: AgentId,
    old_key_id: KeyId,
    new_key_id: KeyId,
    new_public_key: bytes,
    recovered_at: float,
) -> bytes:
    """Build the deterministic byte string recovery attesters sign.

    Example::

        msg = _recovery_message(AgentId("a1"), KeyId("old"), KeyId("new"), b"pk", 10.0)
    """
    return json.dumps(
        {
            "action": "recover",
            "target": str(target_agent),
            "old": str(old_key_id),
            "new": str(new_key_id),
            "pk": new_public_key.hex(),
            "recovered_at": recovered_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
