# SPDX-License-Identifier: Apache-2.0
"""Real authenticated encryption for the Privacy layer (a sealed-box alternative
to the ``noop`` passthrough).

Multi-recipient sealed-box encryption: a fresh ChaCha20-Poly1305 content key per
message, wrapped to each recipient via X25519 ECDH + HKDF-SHA256. This gives the
Privacy layer genuine confidentiality (non-audience agents cannot read a payload
through the API; the trace carries only ciphertext) and tamper-evidence (a
modified ciphertext fails to decrypt rather than silently yielding altered bytes).

Keys derive deterministically from ``(seed, agent_id)`` by default so simulation
traces replay byte-for-byte, consistent with NandaTown's replay-first identity
model. That is protocol/trace-level confidentiality, *not* secrecy against a
holder of the shared seed. Pass ``deterministic=False`` for random per-agent keys
(genuine secrecy against a seed-holder, at the cost of non-reproducible traces).

``prove`` / ``verify_proof`` are honest stubs that raise ``NotImplementedError``
— unlike the ``noop`` plugin's forged proof that always verifies. Zero-knowledge
proofs are future work.

Example::

    priv = SealedBoxPrivacy(AgentId("a1"), seed=7)
    ct = await priv.encrypt(b"secret", [AgentId("a2")])
    # only a2 (with the same seed) can decrypt; a3 raises NotInAudienceError
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.types import AgentId, Proof, Statement, Witness

_DOMAIN = b"nandatown/sealedbox/v1"
_WRAP_INFO = b"nandatown/sealedbox/v1/wrap"
_MAGIC = b"NTSB"
_VERSION = 1


# --------------------------------------------------------------------------- #
# Errors — decrypt never silently returns wrong bytes; every failure raises.
# --------------------------------------------------------------------------- #
class DecryptError(Exception):
    """Base class for all decryption failures."""


class NotInAudienceError(DecryptError):
    """This agent is not a recipient of the sealed message."""


class TamperError(DecryptError):
    """Ciphertext failed authentication (modified in transit)."""


class MalformedEnvelopeError(DecryptError):
    """The byte payload is not a valid sealedbox envelope."""


# --------------------------------------------------------------------------- #
# Deterministic X25519 key material (separate from any signing identity).
# --------------------------------------------------------------------------- #
def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def seed_to_bytes(seed: int | bytes) -> bytes:
    """Normalize a scenario seed (int or bytes) to a stable byte string."""
    if isinstance(seed, bytes):
        return hashlib.sha256(_DOMAIN + b"/seed/" + seed).digest()
    return hashlib.sha256(_DOMAIN + b"/seed/" + str(int(seed)).encode()).digest()


def _derive_secret(seed_bytes: bytes, agent_id: str) -> X25519PrivateKey:
    raw = _hkdf(seed_bytes, _DOMAIN + b"/keyAgreement/" + agent_id.encode())
    return X25519PrivateKey.from_private_bytes(raw)


def _public_raw(secret: X25519PrivateKey) -> bytes:
    return secret.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _public_raw_for_agent(seed_bytes: bytes, agent_id: str) -> bytes:
    return _public_raw(_derive_secret(seed_bytes, agent_id))


def _public_from_raw(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


def _key_id_for_public(public_raw_bytes: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + b"/kid/" + public_raw_bytes).digest()[:8]


# --------------------------------------------------------------------------- #
# Versioned, self-describing envelope (pure (de)serialization, no crypto).
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Recipient:
    key_id: bytes
    eph_pub: bytes
    wrap_nonce: bytes
    wrapped: bytes


def _serialize_envelope(nonce: bytes, recipients: list[_Recipient], ciphertext: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    out = bytearray()
    out += struct.pack(">4sB", _MAGIC, _VERSION)
    out += nonce
    out += struct.pack(">H", len(recipients))
    for r in recipients:
        if len(r.key_id) != 8 or len(r.eph_pub) != 32 or len(r.wrap_nonce) != 12:
            raise ValueError("recipient field has wrong size")
        out += r.key_id + r.eph_pub + r.wrap_nonce
        out += struct.pack(">H", len(r.wrapped)) + r.wrapped
    out += struct.pack(">I", len(ciphertext)) + ciphertext
    return bytes(out)


def _parse_envelope(blob: bytes) -> tuple[bytes, list[_Recipient], bytes]:
    try:
        if blob[:4] != _MAGIC:
            raise MalformedEnvelopeError("bad magic")
        if blob[4] != _VERSION:
            raise MalformedEnvelopeError(f"unsupported version {blob[4]}")
        off = 5
        nonce = blob[off : off + 12]
        off += 12
        if len(nonce) != 12:
            raise MalformedEnvelopeError("truncated nonce")
        (n_recip,) = struct.unpack_from(">H", blob, off)
        off += 2
        recipients: list[_Recipient] = []
        for _ in range(n_recip):
            key_id = blob[off : off + 8]
            off += 8
            eph_pub = blob[off : off + 32]
            off += 32
            wrap_nonce = blob[off : off + 12]
            off += 12
            (wrap_len,) = struct.unpack_from(">H", blob, off)
            off += 2
            wrapped = blob[off : off + wrap_len]
            off += wrap_len
            sizes_ok = (
                len(key_id) == 8
                and len(eph_pub) == 32
                and len(wrap_nonce) == 12
                and len(wrapped) == wrap_len
            )
            if not sizes_ok:
                raise MalformedEnvelopeError("truncated recipient")
            recipients.append(_Recipient(key_id, eph_pub, wrap_nonce, wrapped))
        (ct_len,) = struct.unpack_from(">I", blob, off)
        off += 4
        ciphertext = blob[off : off + ct_len]
        if len(ciphertext) != ct_len:
            raise MalformedEnvelopeError("truncated ciphertext")
        return nonce, recipients, ciphertext
    except (struct.error, IndexError) as exc:
        raise MalformedEnvelopeError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Seal / unseal — the actual multi-recipient authenticated encryption.
# --------------------------------------------------------------------------- #
def _derive(seed_bytes: bytes, sender_id: str, counter: int, tag: bytes, length: int) -> bytes:
    info = (
        b"nandatown/sealedbox/v1/" + tag + b"/" + sender_id.encode() + b"/" + str(counter).encode()
    )
    return _hkdf(seed_bytes, info, length)


def _seal(
    data: bytes,
    audience_pubs: dict[str, bytes],
    *,
    sender_id: str,
    seed_bytes: bytes,
    counter: int,
    deterministic: bool = True,
) -> bytes:
    """Encrypt *data* for every agent in *audience_pubs* (id -> raw X25519 pubkey).

    In deterministic mode the content key, nonces, and ephemeral keys are derived
    from ``(seed_bytes, sender_id, counter)``; ``counter`` MUST then be unique per
    message from a given ``(seed_bytes, sender_id)`` pair (reuse would reuse the
    content key + nonce). In random mode they come from ``os.urandom``.
    """
    if not audience_pubs:
        raise ValueError("audience must not be empty")
    if deterministic:
        cek = _derive(seed_bytes, sender_id, counter, b"cek", 32)
        payload_nonce = _derive(seed_bytes, sender_id, counter, b"nonce", 12)
    else:
        cek = os.urandom(32)
        payload_nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(cek).encrypt(payload_nonce, data, None)

    recipients: list[_Recipient] = []
    for idx, (_aid, recipient_pub_raw) in enumerate(sorted(audience_pubs.items())):
        if deterministic:
            eph_raw = _derive(seed_bytes, sender_id, counter, b"eph/" + str(idx).encode(), 32)
            eph = X25519PrivateKey.from_private_bytes(eph_raw)
            wrap_nonce = _derive(seed_bytes, sender_id, counter, b"wn/" + str(idx).encode(), 12)
        else:
            eph = X25519PrivateKey.generate()
            wrap_nonce = os.urandom(12)
        shared = eph.exchange(_public_from_raw(recipient_pub_raw))
        wrap_key = _hkdf(shared, _WRAP_INFO, 32)
        wrapped = ChaCha20Poly1305(wrap_key).encrypt(wrap_nonce, cek, None)
        recipients.append(
            _Recipient(
                key_id=_key_id_for_public(recipient_pub_raw),
                eph_pub=_public_raw(eph),
                wrap_nonce=wrap_nonce,
                wrapped=wrapped,
            )
        )
    return _serialize_envelope(payload_nonce, recipients, ciphertext)


def _unseal(blob: bytes, *, my_secret: X25519PrivateKey) -> bytes:
    payload_nonce, recipients, ciphertext = _parse_envelope(blob)
    my_kid = _key_id_for_public(_public_raw(my_secret))
    entry = next((r for r in recipients if r.key_id == my_kid), None)
    if entry is None:
        raise NotInAudienceError("no recipient entry for this agent")
    shared = my_secret.exchange(_public_from_raw(entry.eph_pub))
    wrap_key = _hkdf(shared, _WRAP_INFO, 32)
    try:
        cek = ChaCha20Poly1305(wrap_key).decrypt(entry.wrap_nonce, entry.wrapped, None)
        return ChaCha20Poly1305(cek).decrypt(payload_nonce, ciphertext, None)
    except InvalidTag as exc:
        raise TamperError("authentication failed — ciphertext was modified") from exc


# --------------------------------------------------------------------------- #
# The Privacy-layer plugin.
# --------------------------------------------------------------------------- #
class SealedBoxPrivacy:
    """Per-agent privacy plugin doing real multi-recipient authenticated encryption.

    One instance per agent. Deterministic mode (default) derives keys from
    ``(seed, agent_id)`` for replayable traces; random mode (``deterministic=False``)
    uses ``os.urandom`` for genuine secrecy at the cost of reproducibility, and
    resolves peer keys from an injected ``directory`` (agent_id -> raw pubkey).
    """

    def __init__(
        self,
        agent_id: AgentId,
        seed: int | bytes = 0,
        *,
        deterministic: bool = True,
        directory: dict[str, bytes] | None = None,
    ) -> None:
        self._agent_id = str(agent_id)
        self._seed_bytes = seed_to_bytes(seed)
        self._deterministic = deterministic
        self._counter = 0
        self._directory: dict[str, bytes] = {} if deterministic else dict(directory or {})
        if deterministic:
            secret = _derive_secret(self._seed_bytes, self._agent_id)
        else:
            secret = X25519PrivateKey.generate()
        self._secret: X25519PrivateKey = secret

    @property
    def public_key_raw(self) -> bytes:
        """This agent's raw X25519 public key (for random-mode directories)."""
        return _public_raw(self._secret)

    def register_peer(self, agent_id: AgentId, public_key_raw: bytes) -> None:
        """Add a peer public key (random mode only)."""
        self._directory[str(agent_id)] = public_key_raw

    def _public_for(self, agent_id: str) -> bytes:
        if self._deterministic:
            return _public_raw_for_agent(self._seed_bytes, agent_id)
        try:
            return self._directory[agent_id]
        except KeyError as exc:
            raise KeyError(f"no public key for {agent_id!r} in directory") from exc

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        if not audience:
            raise ValueError("audience must not be empty")
        pubs = {str(aid): self._public_for(str(aid)) for aid in audience}
        blob = _seal(
            data,
            pubs,
            sender_id=self._agent_id,
            seed_bytes=self._seed_bytes,
            counter=self._counter,
            deterministic=self._deterministic,
        )
        self._counter += 1
        return blob

    async def decrypt(self, data: bytes) -> bytes:
        return _unseal(data, my_secret=self._secret)

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        raise NotImplementedError(
            "sealedbox implements encryption only; ZK prove/verify is future work"
        )

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        raise NotImplementedError(
            "sealedbox implements encryption only; ZK prove/verify is future work"
        )
