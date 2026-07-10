# SPDX-License-Identifier: Apache-2.0
"""Nonce-misuse-resistant hybrid encryption for the Privacy layer.

``sealedbox`` is a full Problem 09 privacy plugin (hybrid encryption + selective
disclosure + broadcast revocation), but its **load-bearing contribution** is a
property the merged ``hybrid_x25519`` plugin openly concedes it lacks:
**deterministic mode that is safe under key/nonce reuse.**

Why that matters
----------------

Nanda Town's Tier-1 traces must replay byte-for-byte, so a privacy plugin that
wants to run in a scenario derives its per-message key and nonce deterministically
rather than from the system RNG. Every such scheme (including ``hybrid_x25519``)
guards the derivation with a monotonic counter and states — correctly — that
reusing a ``(key, nonce)`` pair would be catastrophic for the AEAD. But that
counter lives in memory on the plugin instance: reconstruct the plugin (a
restart, or two instances of one agent in a scenario) and the counter resets to
zero, re-deriving the *same* key and nonce for a *different* plaintext. For a
ChaCha20-Poly1305 stream that is a two-time pad — it leaks the XOR of the two
plaintexts and destroys authentication. Problem 09 names this exact anti-pattern:
*"Don't reuse the same nonce twice (test for it)."*

What sealedbox does differently (SIV-style derivation)
------------------------------------------------------

In deterministic mode the content key, the content nonce, every ephemeral scalar
and every wrap nonce are derived from a **synthetic value** that folds a digest
of the *plaintext and the sorted audience* into the HKDF ``info`` (the
synthetic-IV construction behind AES-GCM-SIV / deterministic AEAD). So a counter
collision no longer reuses a keystream across distinct messages:

* different plaintext (or audience) under the same counter  → different synthetic
  value → different key + nonce → **no reuse** (safe);
* identical plaintext *and* audience *and* counter          → identical envelope
  bytes → replayable, and the only thing an observer learns is *message
  equality* — never plaintext.

That is a strictly stronger deterministic-mode guarantee than a counter-only
scheme, and :mod:`nest_plugins_reference.validators.sealedbox_validators` ships
an adversarial validator (``check_deterministic_reuse_safe``) that **fails**
against a counter-only plugin and the ``noop`` passthrough and **passes** against
this one.

The rest of the Problem 09 surface
-----------------------------------

* **Hybrid encryption.** One fresh ChaCha20-Poly1305 content key per message
  encrypts the payload once; the key is wrapped per recipient via X25519
  ephemeral-static ECDH + HKDF-SHA256. A versioned self-describing envelope
  binds ``(version, sender, epoch, counter, sorted recipient key-ids)`` as the
  AEAD associated data, so redirecting an envelope or editing its header breaks
  authentication.
* **Selective disclosure.** :meth:`~SealedBoxPrivacy.prove` /
  :meth:`~SealedBoxPrivacy.verify_proof` implement a salted Merkle commitment:
  the holder reveals a subset of credential fields with authentication paths and
  proves the rest are committed under the same issuer-anchored root without
  revealing them.
* **Broadcast revocation.** :meth:`~SealedBoxPrivacy.revoke` advances an epoch
  and excludes a member from *future* wraps without touching any other member's
  key. Revocation is future-only (see the forward-secrecy note on ``revoke``).
* **Replay rejection.** Every envelope is remembered by digest on first decrypt
  by a live recipient instance; a byte-identical re-presented envelope raises
  :class:`ReplayError`. This memory is per-instance and in-process — it is not a
  durable anti-replay log that survives reconstruction.

Confidentiality scope of deterministic mode
--------------------------------------------

Deterministic mode derives **every** agent's X25519 keypair (its own and its
peers') from the one shared scenario ``seed`` — that is what lets a trace replay
without a key directory. The price: this is **protocol/trace-level**
confidentiality (a non-audience agent using the plugin cannot read a payload, and
the plaintext never appears on the wire), but it is **not** secrecy against a
holder of the shared seed, who can re-derive any agent's private key. For genuine
secrecy against a seed-holder, construct with ``deterministic=False`` (per-agent
random keys resolved through an injected ``directory``), at the cost of
reproducible traces.

Example::

    alice = SealedBoxPrivacy(AgentId("alice"), seed=7)
    bob = SealedBoxPrivacy(AgentId("bob"), seed=7)
    env = await alice.encrypt(b"sealed-bid:1700", [AgentId("bob")])
    assert await bob.decrypt(env) == b"sealed-bid:1700"
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass
from typing import Any, cast

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

_DOMAIN = b"nandatown/sealedbox/v2"
_WRAP_INFO = b"nandatown/sealedbox/v2/wrap"
_MAGIC = b"NTSB"
_VERSION = 2

PROOF_SCHEME = "sealedbox-merkle-disclosure/1"
"""Scheme tag stamped on every selective-disclosure :class:`~nest_core.types.Proof`.

Example::

    assert PROOF_SCHEME.startswith("sealedbox-merkle")
"""


# --------------------------------------------------------------------------- #
# Errors — decrypt/verify never silently return wrong bytes; every failure raises.
# --------------------------------------------------------------------------- #
class PrivacyError(Exception):
    """Base class for all sealedbox privacy failures."""


class NotInAudienceError(PrivacyError):
    """This agent is not a recipient of the sealed message (or was revoked)."""


class ReplayError(PrivacyError):
    """An already-seen ``(sender, epoch, counter)`` envelope was re-presented."""


class TamperError(PrivacyError):
    """Ciphertext or bound header failed authentication (modified in transit)."""


class MalformedEnvelopeError(PrivacyError):
    """The byte payload is not a valid sealedbox envelope."""


# --------------------------------------------------------------------------- #
# Deterministic X25519 key material (separate from any signing identity).
# --------------------------------------------------------------------------- #
def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def seed_to_bytes(seed: int | bytes) -> bytes:
    """Normalize a scenario seed (int or bytes) to a stable 32-byte string.

    Example::

        assert len(seed_to_bytes(7)) == 32
    """
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


@dataclass(frozen=True)
class _Header:
    """The authenticated, cleartext header of an envelope (bound as AEAD AAD)."""

    sender: str
    epoch: int
    counter: int


def _aad(header: _Header, key_ids: list[bytes]) -> bytes:
    """Associated data bound to every AEAD in the envelope.

    Reconstructible from the parsed envelope, so any edit to the sender, epoch,
    counter, or recipient set flips authentication. ``key_ids`` are sorted so the
    binding is over the *set* of recipients, order-independent.
    """
    sender_bytes = header.sender.encode()
    parts = [
        _DOMAIN,
        b"/aad/",
        struct.pack(">B", _VERSION),
        struct.pack(">H", len(sender_bytes)),
        sender_bytes,
        struct.pack(">I", header.epoch),
        struct.pack(">Q", header.counter),
        struct.pack(">H", len(key_ids)),
        b"".join(sorted(key_ids)),
    ]
    return b"".join(parts)


def _serialize_envelope(
    header: _Header, nonce: bytes, recipients: list[_Recipient], ciphertext: bytes
) -> bytes:
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    sender_bytes = header.sender.encode()
    out = bytearray()
    out += struct.pack(">4sB", _MAGIC, _VERSION)
    out += struct.pack(">H", len(sender_bytes)) + sender_bytes
    out += struct.pack(">IQ", header.epoch, header.counter)
    out += nonce
    out += struct.pack(">H", len(recipients))
    for r in recipients:
        if len(r.key_id) != 8 or len(r.eph_pub) != 32 or len(r.wrap_nonce) != 12:
            raise ValueError("recipient field has wrong size")
        out += r.key_id + r.eph_pub + r.wrap_nonce
        out += struct.pack(">H", len(r.wrapped)) + r.wrapped
    out += struct.pack(">I", len(ciphertext)) + ciphertext
    return bytes(out)


def _parse_envelope(blob: bytes) -> tuple[_Header, bytes, list[_Recipient], bytes]:
    try:
        if blob[:4] != _MAGIC:
            raise MalformedEnvelopeError("bad magic")
        if blob[4] != _VERSION:
            raise MalformedEnvelopeError(f"unsupported version {blob[4]}")
        off = 5
        (sender_len,) = struct.unpack_from(">H", blob, off)
        off += 2
        sender_raw = blob[off : off + sender_len]
        off += sender_len
        if len(sender_raw) != sender_len:
            raise MalformedEnvelopeError("truncated sender")
        epoch, counter = struct.unpack_from(">IQ", blob, off)
        off += 12
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
        header = _Header(sender=sender_raw.decode("utf-8"), epoch=epoch, counter=counter)
        return header, nonce, recipients, ciphertext
    except (struct.error, IndexError, UnicodeDecodeError) as exc:
        raise MalformedEnvelopeError(str(exc)) from exc


def content_ciphertext(envelope: bytes) -> bytes:
    """Return just the AEAD content ciphertext (``ct || tag``) from an envelope.

    Exposed for adversarial validators that need to inspect the keystream region
    of the trace (e.g. the two-time-pad detector) without decrypting.

    Example::

        body = content_ciphertext(env)  # bytes; last 16 bytes are the Poly1305 tag
    """
    _header, _nonce, _recipients, ciphertext = _parse_envelope(envelope)
    return ciphertext


# --------------------------------------------------------------------------- #
# SIV-style synthetic derivation (the misuse-resistant heart of the plugin).
# --------------------------------------------------------------------------- #
def _synthetic_iv(data: bytes, key_ids: list[bytes]) -> bytes:
    """Digest of the plaintext and sorted audience, folded into every derivation.

    This is what makes deterministic mode nonce-misuse resistant: two messages
    that differ in plaintext or audience get different synthetic values, so they
    never share a derived ``(key, nonce)`` even under an identical counter.
    """
    h = hashlib.sha256()
    h.update(_DOMAIN + b"/siv/")
    h.update(struct.pack(">I", len(data)))
    h.update(data)
    h.update(struct.pack(">H", len(key_ids)))
    for kid in sorted(key_ids):
        h.update(kid)
    return h.digest()


def _derive(seed_bytes: bytes, msg_id: bytes, tag: bytes, siv: bytes, length: int) -> bytes:
    info = _DOMAIN + b"/" + tag + b"/" + msg_id + b"/" + siv
    return _hkdf(seed_bytes, info, length)


# --------------------------------------------------------------------------- #
# Seal / unseal — the actual multi-recipient authenticated encryption.
# --------------------------------------------------------------------------- #
def _seal(
    data: bytes,
    audience_pubs: dict[str, bytes],
    *,
    header: _Header,
    seed_bytes: bytes,
    deterministic: bool = True,
) -> bytes:
    """Encrypt *data* for every agent in *audience_pubs* (id -> raw X25519 pubkey).

    In deterministic mode the content key, content nonce, ephemeral scalars and
    wrap nonces are all derived SIV-style from ``(seed, msg_id, synthetic_iv)``,
    where ``synthetic_iv`` binds the plaintext and audience — so a counter
    collision degrades to revealing message equality rather than reusing a
    keystream. In random mode they come from ``os.urandom``.
    """
    if not audience_pubs:
        raise ValueError("audience must not be empty")
    key_ids = [_key_id_for_public(pub) for pub in audience_pubs.values()]
    msg_id = f"{header.sender}:{header.epoch}:{header.counter}".encode()
    aad = _aad(header, key_ids)

    if deterministic:
        siv = _synthetic_iv(data, key_ids)
        cek = _derive(seed_bytes, msg_id, b"cek", siv, 32)
        payload_nonce = _derive(seed_bytes, msg_id, b"nonce", siv, 12)
    else:
        siv = b""
        cek = os.urandom(32)
        payload_nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(cek).encrypt(payload_nonce, data, aad)

    recipients: list[_Recipient] = []
    for idx, (_aid, recipient_pub_raw) in enumerate(sorted(audience_pubs.items())):
        if deterministic:
            idx_tag = str(idx).encode()
            eph_raw = _derive(seed_bytes, msg_id, b"eph/" + idx_tag, siv, 32)
            eph = X25519PrivateKey.from_private_bytes(eph_raw)
            wrap_nonce = _derive(seed_bytes, msg_id, b"wn/" + idx_tag, siv, 12)
        else:
            eph = X25519PrivateKey.generate()
            wrap_nonce = os.urandom(12)
        shared = eph.exchange(_public_from_raw(recipient_pub_raw))
        wrap_key = _hkdf(shared, _WRAP_INFO, 32)
        wrapped = ChaCha20Poly1305(wrap_key).encrypt(wrap_nonce, cek, aad)
        recipients.append(
            _Recipient(
                key_id=_key_id_for_public(recipient_pub_raw),
                eph_pub=_public_raw(eph),
                wrap_nonce=wrap_nonce,
                wrapped=wrapped,
            )
        )
    return _serialize_envelope(header, payload_nonce, recipients, ciphertext)


def _unseal(blob: bytes, *, my_secret: X25519PrivateKey) -> tuple[_Header, bytes]:
    header, payload_nonce, recipients, ciphertext = _parse_envelope(blob)
    my_kid = _key_id_for_public(_public_raw(my_secret))
    entry = next((r for r in recipients if r.key_id == my_kid), None)
    if entry is None:
        raise NotInAudienceError("no recipient entry for this agent")
    aad = _aad(header, [r.key_id for r in recipients])
    shared = my_secret.exchange(_public_from_raw(entry.eph_pub))
    wrap_key = _hkdf(shared, _WRAP_INFO, 32)
    try:
        cek = ChaCha20Poly1305(wrap_key).decrypt(entry.wrap_nonce, entry.wrapped, aad)
        plaintext = ChaCha20Poly1305(cek).decrypt(payload_nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise TamperError("authentication failed — envelope was modified") from exc
    return header, plaintext


# --------------------------------------------------------------------------- #
# Selective-disclosure Merkle commitment (pure functions; issuer + verifier).
# --------------------------------------------------------------------------- #
def _leaf(name: str, value: str, salt: bytes) -> bytes:
    """Salted, length-prefixed leaf hash. The salt hides low-entropy values."""
    parts = [
        _DOMAIN + b"/leaf/",
        struct.pack(">I", len(name)),
        name.encode("utf-8"),
        struct.pack(">I", len(value)),
        value.encode("utf-8"),
        salt,
    ]
    return hashlib.sha256(b"".join(parts)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + b"/node/" + left + right).digest()


def _merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        return [[hashlib.sha256(_DOMAIN + b"/empty/").digest()]]
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [_node(cur[i], cur[i + 1 if i + 1 < len(cur) else i]) for i in range(0, len(cur), 2)]
        levels.append(nxt)
    return levels


def _merkle_root(leaves: list[bytes]) -> bytes:
    return _merkle_levels(leaves)[-1][0]


def _merkle_path(leaves: list[bytes], index: int) -> list[tuple[str, bool]]:
    """Authentication path for ``leaves[index]`` as ``(sibling_hex, sibling_is_right)``."""
    path: list[tuple[str, bool]] = []
    levels = _merkle_levels(leaves)
    idx = index
    for level in levels[:-1]:
        sibling_is_right = idx % 2 == 0
        sib_idx = idx + 1 if sibling_is_right else idx - 1
        if sib_idx >= len(level):  # odd node duplicated with itself
            sib_idx = idx
        path.append((level[sib_idx].hex(), sibling_is_right))
        idx //= 2
    return path


def _root_from_path(leaf: bytes, path: list[tuple[str, bool]]) -> bytes:
    acc = leaf
    for sib_hex, sib_is_right in path:
        sib = bytes.fromhex(sib_hex)
        acc = _node(acc, sib) if sib_is_right else _node(sib, acc)
    return acc


def commit_credential(
    fields: dict[str, str], *, salt_seed: bytes | None = None
) -> tuple[str, dict[str, str]]:
    """Issuer helper: commit a multi-field credential to a single Merkle root.

    Returns ``(root_hex, salts)`` where ``salts`` maps each field name to a hex
    16-byte salt; leaves are ordered by sorted field name. With ``salt_seed=None``
    the salts come from the system RNG (hiding, unlinkable). Pass an explicit
    ``salt_seed`` only for reproducible Tier-1 trace tests — that makes the salts
    deterministic (and, for a public seed, re-derivable), trading hiding for
    replayability.

    Example::

        root, salts = commit_credential({"age": "21", "country": "NG"})
        assert len(root) == 64 and set(salts) == {"age", "country"}
    """
    names = sorted(fields)
    salts: dict[str, str] = {}
    leaves: list[bytes] = []
    for name in names:
        if salt_seed is None:
            salt = os.urandom(16)
        else:
            salt = _hkdf(salt_seed, _DOMAIN + b"/salt/" + name.encode("utf-8"), length=16)
        salts[name] = salt.hex()
        leaves.append(_leaf(name, fields[name], salt))
    return _merkle_root(leaves).hex(), salts


def _split_witness(witness: Witness) -> tuple[dict[str, str], dict[str, str]]:
    """Split a witness into ``(fields, salts)``; ``__salts__`` holds the salts JSON."""
    raw = dict(witness.private_inputs)
    salts_json = raw.pop("__salts__", "{}")
    loaded: Any = json.loads(salts_json)
    if not isinstance(loaded, dict):
        msg = "__salts__ must be a JSON object"
        raise ValueError(msg)
    mapping = cast("dict[str, Any]", loaded)
    salts: dict[str, str] = {str(k): str(v) for k, v in mapping.items()}
    fields: dict[str, str] = {k: str(v) for k, v in raw.items()}
    return fields, salts


def _reveal_list(statement: Statement) -> list[str]:
    """Parse the JSON ``reveal`` field-name list from the statement.

    A JSON array of field names (not a comma-joined string) so that field names
    may themselves contain commas without ambiguity. Falls back to treating a
    non-JSON value as a single field name for convenience.
    """
    raw = statement.public_inputs.get("reveal", "[]")
    try:
        loaded: Any = json.loads(raw)
    except (ValueError, TypeError):
        return [raw] if raw else []
    if not isinstance(loaded, list):
        return []
    return [str(name) for name in cast("list[Any]", loaded)]


def _coerce_path(raw: Any) -> list[tuple[str, bool]]:
    """Coerce a JSON-decoded path back into ``[(sibling_hex, is_right)]``."""
    if not isinstance(raw, list):
        msg = "path is not a list"
        raise TypeError(msg)
    path: list[tuple[str, bool]] = []
    for step in cast("list[Any]", raw):
        if not isinstance(step, list):
            msg = "path step is not a list"
            raise TypeError(msg)
        pair = cast("list[Any]", step)
        if len(pair) != 2:
            msg = "path step is not a 2-element list"
            raise TypeError(msg)
        path.append((str(pair[0]), bool(pair[1])))
    return path


# --------------------------------------------------------------------------- #
# The Privacy-layer plugin.
# --------------------------------------------------------------------------- #
class SealedBoxPrivacy:
    """Per-agent privacy plugin: nonce-misuse-resistant hybrid encryption,
    selective disclosure, and broadcast revocation (implements ``Privacy``).

    One instance per agent. Deterministic mode (default) derives keys SIV-style
    from ``(seed, agent_id, plaintext, audience)`` for replayable *and*
    reuse-safe traces; random mode (``deterministic=False``) uses ``os.urandom``
    and resolves peer keys from an injected ``directory`` (agent_id -> raw pubkey).

    Example::

        a = SealedBoxPrivacy(AgentId("a"), seed=7)
        b = SealedBoxPrivacy(AgentId("b"), seed=7)
        env = await a.encrypt(b"hi", [AgentId("b")])
        assert await b.decrypt(env) == b"hi"
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
        self._epoch = 0
        self._revoked: dict[str, int] = {}
        self._seen: set[bytes] = set()
        self._directory: dict[str, bytes] = {} if deterministic else dict(directory or {})
        if deterministic:
            secret = _derive_secret(self._seed_bytes, self._agent_id)
        else:
            secret = X25519PrivateKey.generate()
        self._secret: X25519PrivateKey = secret

    # -- identity / directory -------------------------------------------------

    @property
    def public_key_raw(self) -> bytes:
        """This agent's raw X25519 public key (for random-mode directories)."""
        return _public_raw(self._secret)

    @property
    def epoch(self) -> int:
        """Current revocation epoch (advances on :meth:`revoke`)."""
        return self._epoch

    def register_peer(self, agent_id: AgentId, public_key_raw: bytes) -> None:
        """Add a peer public key (random mode only; deterministic mode derives it)."""
        self._directory[str(agent_id)] = public_key_raw

    def _public_for(self, agent_id: str) -> bytes:
        if self._deterministic:
            return _public_raw_for_agent(self._seed_bytes, agent_id)
        try:
            return self._directory[agent_id]
        except KeyError as exc:
            raise KeyError(f"no public key for {agent_id!r} in directory") from exc

    # -- revocation -----------------------------------------------------------

    def revoke(self, agent_id: AgentId) -> int:
        """Revoke *agent_id*: advance the epoch and exclude it from future wraps.

        Returns the new epoch. **Forward-secrecy note:** revocation is
        *future-only*. A member revoked at epoch *E* cannot read messages issued
        at epoch ``>= E``, but any envelope it already received at an earlier
        epoch stays decryptable by it forever — true past-traffic forward secrecy
        would require per-epoch content re-keying with deletion of old key
        material, which this plugin deliberately does not do (it would change the
        broadcast cost model). We surface this rather than overclaim.

        Example::

            new_epoch = priv.revoke(AgentId("carol"))
        """
        sid = str(agent_id)
        if sid in self._revoked:
            return self._epoch  # already revoked: idempotent, preserves the first epoch
        self._epoch += 1
        self._revoked[sid] = self._epoch
        return self._epoch

    def _is_revoked(self, agent_id: str, epoch: int) -> bool:
        revoked_at = self._revoked.get(agent_id)
        return revoked_at is not None and epoch >= revoked_at

    # -- Privacy protocol: encryption -----------------------------------------

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Encrypt *data* so only non-revoked members of *audience* can read it.

        Recipients revoked as of the current epoch are silently excluded (that is
        the revocation guarantee). Raises ``ValueError`` if the resulting audience
        is empty.

        Example::

            env = await alice.encrypt(b"secret", [AgentId("bob")])
        """
        if not audience:
            raise ValueError("audience must not be empty")
        seen: set[str] = set()
        recipients: list[str] = []
        for aid in audience:
            sid = str(aid)
            if sid in seen or self._is_revoked(sid, self._epoch):
                continue
            seen.add(sid)
            recipients.append(sid)
        if not recipients:
            raise ValueError("audience is empty after excluding revoked members")

        pubs = {sid: self._public_for(sid) for sid in recipients}
        header = _Header(sender=self._agent_id, epoch=self._epoch, counter=self._counter)
        blob = _seal(
            data,
            pubs,
            header=header,
            seed_bytes=self._seed_bytes,
            deterministic=self._deterministic,
        )
        self._counter += 1
        return blob

    async def decrypt(self, data: bytes) -> bytes:
        """Decrypt an envelope addressed to this agent.

        Raises :class:`NotInAudienceError` if this agent holds no wrap entry
        (eavesdropper or stale-revocation), :class:`ReplayError` on a re-presented
        envelope, :class:`TamperError` if authentication fails, and
        :class:`MalformedEnvelopeError` on a structurally invalid envelope.

        Example::

            plaintext = await bob.decrypt(env)
        """
        header, plaintext = _unseal(data, my_secret=self._secret)
        # Key replay memory on the whole envelope, NOT (sender, epoch, counter):
        # the plugin's headline is that a reconstructed sender safely reuses a
        # counter for a DIFFERENT message (SIV), so those distinct envelopes must
        # not be mistaken for replays of each other. A byte-identical envelope
        # still collides and is rejected.
        replay_key = hashlib.sha256(data).digest()
        if replay_key in self._seen:
            raise ReplayError(f"replayed envelope {header.sender}:{header.epoch}:{header.counter}")
        self._seen.add(replay_key)
        return plaintext

    # -- Privacy protocol: selective-disclosure proofs ------------------------

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        """Prove that the revealed fields belong to the committed credential.

        ``statement.public_inputs`` carries ``root`` (issuer-committed Merkle
        root, hex) and ``reveal`` (a JSON array of field names to disclose).
        ``witness.private_inputs`` holds every field value plus a ``__salts__``
        entry (JSON ``{name: salt_hex}``). The proof discloses only the requested
        fields and their authentication paths; the rest stay hidden behind the
        root. Raises ``ValueError`` if the witness does not reconstruct the
        committed root or a requested field is unknown.

        Example::

            proof = await priv.prove(stmt, witness)
        """
        fields, salts = _split_witness(witness)
        names = sorted(fields)
        missing = [n for n in names if n not in salts]
        if missing:
            msg = f"witness missing salt(s) for field(s): {', '.join(missing)}"
            raise ValueError(msg)
        leaves = [_leaf(n, fields[n], bytes.fromhex(salts[n])) for n in names]
        root = _merkle_root(leaves).hex()
        if root != statement.public_inputs.get("root"):
            msg = "witness does not match the committed root"
            raise ValueError(msg)

        reveal = _reveal_list(statement)
        unknown = [name for name in reveal if name not in fields]
        if unknown:
            msg = f"cannot reveal unknown field(s): {', '.join(unknown)}"
            raise ValueError(msg)
        disclosed: dict[str, dict[str, Any]] = {}
        for name in reveal:
            idx = names.index(name)
            disclosed[name] = {
                "value": fields[name],
                "salt": salts[name],
                "index": idx,
                "path": _merkle_path(leaves, idx),
            }
        payload = json.dumps(
            {"root": root, "n": len(names), "disclosed": disclosed},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return Proof(statement=statement, data=payload, scheme=PROOF_SCHEME)

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Verify a selective-disclosure proof against the statement's root.

        Returns ``True`` iff the scheme matches, every disclosed field's salted
        leaf authenticates to ``statement.public_inputs['root']``, and the set of
        disclosed fields equals the statement's ``reveal`` set. Any tampering with
        a revealed value, salt, or path node flips a hash and returns ``False``.

        Example::

            ok = await priv.verify_proof(stmt, proof)
        """
        if proof.scheme != PROOF_SCHEME:
            return False
        anchored_root = statement.public_inputs.get("root")
        try:
            parsed: Any = json.loads(proof.data)
        except (ValueError, TypeError):
            return False
        if not isinstance(parsed, dict):
            return False
        body = cast("dict[str, Any]", parsed)
        if body.get("root") != anchored_root:
            return False
        raw_disclosed = body.get("disclosed")
        if not isinstance(raw_disclosed, dict):
            return False
        disclosed = cast("dict[str, Any]", raw_disclosed)
        if set(disclosed) != set(_reveal_list(statement)):
            return False
        for name, item in disclosed.items():
            if not isinstance(item, dict):
                return False
            field = cast("dict[str, Any]", item)
            try:
                value = str(field["value"])
                salt = bytes.fromhex(str(field["salt"]))
                path = _coerce_path(field["path"])
            except (KeyError, ValueError, TypeError):
                return False
            leaf = _leaf(name, value, salt)
            if _root_from_path(leaf, path).hex() != anchored_root:
                return False
        return True
