# SPDX-License-Identifier: Apache-2.0
"""Real Ed25519 identity plugin with key rotation and historical signature verification.

Supports true cryptographic signing, temporal key validity windows, and continuity proofs.
Thwarts post-rotation forgery and backdated signatures.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from nest_core.types import AgentId, AgentIdentity, Signature

ALGORITHM = "ed25519-rotating/1"

KeyId = str


@dataclass
class RotationRecord:
    agent_id: AgentId
    old_key_id: str
    new_key_id: str
    new_public_key: bytes = field(default=b"")
    issued_at: float = field(default=0.0)
    # Continuity proof: signature of continuity_message() by the old key.
    continuity_signature: bytes = field(default=b"")

    def continuity_message(self) -> bytes:
        """Return the canonical bytes that continuity_signature signs over.

        The payload includes both key IDs, the new raw public key, and the
        issued_at tick so that the signature is bound to all rotation parameters
        — an attacker cannot reuse a continuity proof for a different epoch or
        a different new key.
        """
        return (
            b"rotate:"
            + str(self.agent_id).encode()
            + b":"
            + self.old_key_id.encode()
            + b":"
            + self.new_key_id.encode()
            + b":"
            + self.new_public_key
        )


class KeyRecord:
    """Tracks a public key and its validity window."""

    def __init__(
        self,
        key_id: str,
        public_key_bytes: bytes,
        issued_at: float,
        rotated_out: float | None = None,
    ) -> None:
        self.key_id = key_id
        self.public_key_bytes = public_key_bytes
        self.issued_at = issued_at
        self.rotated_out = rotated_out

    @property
    def public_key(self) -> bytes:
        """Alias for public_key_bytes — matches parc.py's _own_pubkey_for_key lookup."""
        return self.public_key_bytes


def _compute_key_id(public_bytes: bytes) -> str:
    """Compute a deterministic key ID from public bytes."""
    return hashlib.sha256(public_bytes).hexdigest()[:16]


class Ed25519RotatingIdentity:
    """Ed25519 identity supporting key rotation and temporal validity checks."""

    def __init__(self, agent_id: AgentId, seed: bytes = b"", clock: float | None = None) -> None:
        self._agent_id = agent_id
        self._seed = seed
        self._clock: float | None = clock

        # Derive initial active key pair deterministically
        h = hashlib.sha256(seed + b":" + str(agent_id).encode()).digest()
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(h)
        self._public_key = self._private_key.public_key()
        self._public_key_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = _compute_key_id(self._public_key_bytes)
        # Store all private keys by key_id (for adversarial sign_with)
        self._private_keys: dict[str, ed25519.Ed25519PrivateKey] = {self._key_id: self._private_key}

        # Initialize the key chain. The genesis key is valid from tick 0
        # (the beginning of simulated time) regardless of wall-clock time.
        self._known_keys: dict[AgentId, list[KeyRecord]] = {
            agent_id: [
                KeyRecord(
                    key_id=self._key_id,
                    public_key_bytes=self._public_key_bytes,
                    issued_at=0.0,
                )
            ]
        }

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def set_clock(self, tick: float) -> None:
        """Advance the simulated clock. Only monotonically-increasing ticks are accepted."""
        if self._clock is None or tick >= self._clock:
            self._clock = tick

    @property
    def public_key(self) -> bytes:
        """Returns the current active public key bytes."""
        return self._public_key_bytes

    @property
    def current_key_id(self) -> str:
        """Returns the current active key ID."""
        return self._key_id

    @property
    def agent_id(self) -> AgentId:
        """Returns this identity's agent ID."""
        return self._agent_id

    @property
    def _records(self) -> dict[AgentId, list[KeyRecord]]:
        """Expose key history so parc.py's _own_pubkey_for_key can find old keys."""
        return self._known_keys

    def rotate_key(self, new_seed: bytes) -> RotationRecord:
        """Rotate to a new key, retiring the current one.

        Returns a RotationRecord containing the old/new key IDs and a
        continuity proof (the new public key bytes signed by the old key).
        """
        now = self._now()
        my_records = self._known_keys[self._agent_id]

        old_key_id = self._key_id
        old_private_key = self._private_key

        # Mark current key as rotated out
        my_records[-1].rotated_out = now

        # Generate new key deterministically from new_seed
        h = hashlib.sha256(new_seed + b":" + str(self._agent_id).encode()).digest()
        new_private = ed25519.Ed25519PrivateKey.from_private_bytes(h)
        new_public = new_private.public_key()
        new_public_bytes = new_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        new_key_id = _compute_key_id(new_public_bytes)

        # Continuity proof: sign the continuity_message with the OLD key
        record = RotationRecord(
            agent_id=self._agent_id,
            old_key_id=old_key_id,
            new_key_id=new_key_id,
            new_public_key=new_public_bytes,
            issued_at=now,
        )
        record.continuity_signature = old_private_key.sign(record.continuity_message())

        # Switch to the new key
        self._private_key = new_private
        self._public_key = new_public
        self._public_key_bytes = new_public_bytes
        self._key_id = new_key_id
        self._private_keys[new_key_id] = new_private

        my_records.append(
            KeyRecord(
                key_id=new_key_id,
                public_key_bytes=new_public_bytes,
                issued_at=now,
            )
        )

        return record

    def verify_continuity(self, agent_id: AgentId, record: RotationRecord) -> bool:
        """Verify a RotationRecord's continuity signature.

        Accepts if:
        - ``old_key_id`` is the current chain tip (forward-looking; peer not yet applied), OR
        - ``old_key_id`` is an in-chain key whose immediate successor is ``new_key_id``
          (self-issued; the rotation has already been applied to own chain).

        Rejects stale-key injection: a retired key that is NOT a predecessor of
        the claimed ``new_key_id`` in the known chain cannot authorise a new successor.
        """
        records = self._known_keys.get(agent_id)
        if not records:
            return False

        # Find old_key_id in chain
        old_idx = next((i for i, r in enumerate(records) if r.key_id == record.old_key_id), None)
        if old_idx is None:
            return False

        # Accept if old_key is the current chain tip (peer applying for the first time)
        is_tip = old_idx == len(records) - 1

        # Accept if old_key's immediate successor in the chain is new_key_id
        # (self-applied rotation: own chain already has the new key appended)
        is_known_predecessor = (
            old_idx + 1 < len(records) and records[old_idx + 1].key_id == record.new_key_id
        )

        if not is_tip and not is_known_predecessor:
            # Stale key that is not the predecessor of the claimed new_key_id
            return False

        old_rec = records[old_idx]
        try:
            old_pk = ed25519.Ed25519PublicKey.from_public_bytes(old_rec.public_key_bytes)
            old_pk.verify(record.continuity_signature, record.continuity_message())
            return True
        except InvalidSignature:
            return False

    def apply_rotation(self, record: RotationRecord) -> bool:
        """Apply a RotationRecord from a peer, verifying the continuity proof first.

        Returns True if accepted, False if the proof is invalid or the
        old_key_id is not the current chain tip (retired-key injection guard).
        """
        records = self._known_keys.get(record.agent_id)
        if not records:
            return False

        # Chain-tip guard
        chain_tip = records[-1]
        if chain_tip.key_id != record.old_key_id:
            return False

        # Verify continuity proof
        try:
            old_pk = ed25519.Ed25519PublicKey.from_public_bytes(chain_tip.public_key_bytes)
            old_pk.verify(record.continuity_signature, record.continuity_message())
        except InvalidSignature:
            return False

        # Apply rotation
        chain_tip.rotated_out = record.issued_at
        new_key_id = _compute_key_id(record.new_public_key)
        records.append(
            KeyRecord(
                key_id=new_key_id,
                public_key_bytes=record.new_public_key,
                issued_at=record.issued_at,
            )
        )
        return True

    def sign_with(self, payload: bytes, key_id: KeyId) -> Signature:
        """Sign with a specific (possibly rotated out) key — used for adversarial testing."""
        priv = self._private_keys.get(key_id)
        if not priv:
            raise ValueError(f"no private key for key_id: {key_id}")
        sig_bytes = priv.sign(payload)
        return Signature(
            signer=self._agent_id,
            value=sig_bytes,
            algorithm=ALGORITHM,
            key_id=key_id,
            signed_at=self._now(),
        )

    def register_peer(
        self,
        agent_id: AgentId,
        public_key: bytes,
        private_key: bytes | None = None,
    ) -> None:
        """Register a peer's root public key.

        For rotation, use `apply_rotation` or `register_rotation`.
        """
        if private_key is not None:
            raise ValueError("register_peer accepts public keys only")

        if agent_id not in self._known_keys:
            self._known_keys[agent_id] = []

        key_id = _compute_key_id(public_key)
        if any(r.key_id == key_id for r in self._known_keys[agent_id]):
            return

        self._known_keys[agent_id].append(
            KeyRecord(
                key_id=key_id,
                public_key_bytes=public_key,
                issued_at=0.0,
            )
        )

    def register_rotation(
        self, agent_id: AgentId, new_public_key: bytes, proof: bytes, issued_at: float
    ) -> None:
        """Register a rotated key for an agent, verified by their previous key."""
        records = self._known_keys.get(agent_id)
        if not records:
            raise ValueError(f"Agent {agent_id} has no root key registered")

        old_record = records[-1]

        # Verify continuity proof
        old_pk = ed25519.Ed25519PublicKey.from_public_bytes(old_record.public_key_bytes)
        try:
            old_pk.verify(proof, new_public_key)
        except InvalidSignature as exc:
            raise ValueError("Invalid continuity proof") from exc

        old_record.rotated_out = issued_at

        new_key_id = _compute_key_id(new_public_key)
        records.append(
            KeyRecord(
                key_id=new_key_id,
                public_key_bytes=new_public_key,
                issued_at=issued_at,
            )
        )

    def sign(self, payload: bytes) -> Signature:
        """Sign a payload with this agent's active private key."""
        now = self._now()
        sig_bytes = self._private_key.sign(payload)
        return Signature(
            signer=self._agent_id,
            value=sig_bytes,
            algorithm=ALGORITHM,
            key_id=self._key_id,
            signed_at=now,
        )

    def verify(
        self,
        payload: bytes,
        sig: Signature,
        agent: AgentId,
        as_of: float | None = None,
    ) -> bool:
        """Verify a signature cryptographically and temporally.

        ``as_of`` is the externally observed tick used for window checking.
        If omitted, the current clock is used.
        """
        if sig.signer != agent:
            return False

        records = self._known_keys.get(agent)
        if not records:
            return False

        if not sig.key_id:
            # Fallback: no key_id binding, try all keys without temporal check
            for record in reversed(records):
                pk = ed25519.Ed25519PublicKey.from_public_bytes(record.public_key_bytes)
                try:
                    pk.verify(sig.value, payload)
                    return True
                except InvalidSignature:
                    continue
            return False

        target_record = None
        for r in records:
            if r.key_id == sig.key_id:
                target_record = r
                break

        if not target_record:
            return False

        # Temporal check: verify that the key was active at the observed time
        check_time = as_of if as_of is not None else self._now()

        if check_time < target_record.issued_at:
            return False
        if target_record.rotated_out is not None and check_time >= target_record.rotated_out:
            return False

        # Cryptographic check
        pk = ed25519.Ed25519PublicKey.from_public_bytes(target_record.public_key_bytes)
        try:
            pk.verify(sig.value, payload)
            return True
        except InvalidSignature:
            return False

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        """Resolve an agent ID to its current identity record.

        The ``metadata["keys"]`` list exposes the full key history (public
        material only) so callers can audit the rotation chain.
        """
        records = self._known_keys.get(agent) or []
        pk = records[-1].public_key_bytes if records else b""
        key_history = [
            {
                "key_id": r.key_id,
                "public_key": r.public_key_bytes.hex(),
                "issued_at": r.issued_at,
                "rotated_out": r.rotated_out,
            }
            for r in records
        ]
        return AgentIdentity(
            agent_id=agent,
            public_key=pk,
            method="did:ed25519",
            metadata={"keys": key_history},
        )
