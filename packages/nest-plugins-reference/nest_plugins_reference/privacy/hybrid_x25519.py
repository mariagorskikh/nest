# SPDX-License-Identifier: Apache-2.0
"""Real hybrid encryption with selective disclosure and broadcast revocation.

Unlike :mod:`nest_plugins_reference.privacy.noop` — which returns the input
unchanged and whose ``verify_proof`` is an unconditional ``True`` — this plugin
provides **real confidentiality** built from RFC-grade primitives in the
``cryptography`` library:

* **Hybrid encryption (HPKE-shaped).** Each message gets a fresh 256-bit
  content key that encrypts the payload once with **ChaCha20-Poly1305** (AEAD).
  The content key is then *wrapped* once per recipient via an **X25519**
  ephemeral-static ECDH + **HKDF-SHA256** key-agreement. So a 1 KB message to
  ten recipients is one symmetric encryption plus ten cheap key-wraps — the
  standard broadcast/group-key shape, not N full re-encryptions.
* **Selective disclosure.** :meth:`prove` / :meth:`verify_proof` implement a
  salted **Merkle commitment** over a multi-field credential: the holder reveals
  a subset of fields with their authentication paths and proves the rest are
  well-formed (committed under the same root) **without revealing them**. No
  SNARK required — the root is the public anchor (issued by a credential
  authority and carried in the :class:`~nest_core.types.Statement`).
* **Broadcast revocation.** :meth:`revoke` removes a member from *future*
  encryptions without touching any other member's key, by advancing an **epoch**
  and excluding the revoked key from the next wrap step.

Threat model & what each guard defeats
--------------------------------------

1. **Eavesdropper.** A non-audience agent that intercepts the envelope holds no
   wrap entry keyed to its public key, so it can never recover the content key.
   :meth:`decrypt` raises :class:`NotInAudienceError`. The plaintext never
   appears in the envelope bytes.
2. **Replay.** Every envelope carries a unique ``msg_id`` (``sender:epoch:seq``)
   bound into the AEAD associated data. A recipient rejects a re-presented
   envelope via :class:`ReplayError`; a redirected envelope fails to
   authenticate because the recipient is not in the wrap set.
3. **Field-injection.** Tampering any revealed field value, salt, or Merkle path
   node changes the reconstructed root, which no longer equals the
   issuer-anchored root in the statement — :meth:`verify_proof` returns
   ``False``.
4. **Stale-revocation.** A member revoked at epoch *E* is excluded from the wrap
   set of every message at epoch ``>= E``, so :meth:`decrypt` on a
   post-revocation message raises :class:`NotInAudienceError`.

Forward-secrecy disclosure (read this before trusting it)
---------------------------------------------------------

Revocation is **future-only**. It guarantees a revoked member cannot read
messages issued *at or after* their revocation epoch. It makes **no** claim
about messages issued *before* revocation: a member who already received and
stored an earlier envelope retains the wrap entry needed to decrypt *that*
envelope forever. True forward secrecy against a *past*-traffic compromise would
require per-epoch content re-keying with deletion of old key material, which
this plugin deliberately does not do (it would change the broadcast cost model).
We surface this rather than imply a stronger property than we deliver.

Deterministic traces
---------------------

Nanda Town Tier-1 traces must be byte-for-byte reproducible, but hybrid
encryption is randomized (fresh ephemeral key + nonces per message). When
constructed with ``deterministic=True`` the plugin derives the ephemeral scalar
and every nonce from ``HKDF(seed, msg_id)`` instead of the system RNG, so the
*same* ``(seed, agent, epoch, seq, payload, audience)`` yields identical
envelope bytes. This is sound **only because** ``msg_id`` is unique per
``(sender, epoch)`` via a monotonic counter — reusing a ``(key, nonce)`` pair
would be catastrophic for any AEAD, and the counter is what prevents it. The
secure default is ``deterministic=False`` (system RNG).

Example::

    alice = HybridX25519Privacy(AgentId("alice"), seed=b"a", deterministic=True)
    bob = HybridX25519Privacy(AgentId("bob"), seed=b"b", deterministic=True)
    alice.register_peer(AgentId("bob"), bob.public_key)
    env = await alice.encrypt(b"sealed-bid:1700", [AgentId("bob")])
    assert await bob.decrypt(env) == b"sealed-bid:1700"
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
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
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from nest_core.types import AgentId, Proof, Statement, Witness

SCHEME = "hybrid-x25519-chacha20poly1305/1"
"""Wire-format tag stamped into every envelope and bound into the AEAD AAD.

Example::

    assert SCHEME.startswith("hybrid-x25519")
"""

PROOF_SCHEME = "merkle-selective-disclosure/1"
"""Scheme tag on every selective-disclosure :class:`~nest_core.types.Proof`.

Example::

    assert PROOF_SCHEME.startswith("merkle")
"""

_KEY_BYTES = 32
_NONCE_BYTES = 12


# ---------------------------------------------------------------------------
# Errors — decrypt/verify raise these so validators can discriminate failures.
# ---------------------------------------------------------------------------


class PrivacyError(Exception):
    """Base class for all privacy-plugin failures.

    Example::

        try:
            await priv.decrypt(env)
        except PrivacyError:
            ...
    """


class NotInAudienceError(PrivacyError):
    """Raised when this agent has no wrap entry in the envelope.

    Covers both the *eavesdropper* (never in the audience) and the
    *stale-revocation* (excluded from this epoch) attacks.

    Example::

        raise NotInAudienceError("carol not in audience")
    """


class ReplayError(PrivacyError):
    """Raised when an already-seen ``(sender, msg_id)`` envelope is re-presented.

    Example::

        raise ReplayError("duplicate alice:0:1")
    """


class MalformedEnvelopeError(PrivacyError):
    """Raised when envelope bytes are not a well-formed ``SCHEME`` envelope.

    Example::

        raise MalformedEnvelopeError("missing field 'ct'")
    """


class TamperError(PrivacyError):
    """Raised when AEAD authentication fails (ciphertext/AAD tampered).

    Example::

        raise TamperError("AEAD tag mismatch")
    """


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _canon(obj: dict[str, Any]) -> bytes:
    """Canonical, sorted-key JSON bytes (stable across processes for the AAD).

    Example::

        assert _canon({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(raw: bytes) -> str:
    """Standard base64 for embedding raw bytes as ASCII inside the JSON envelope."""
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    """Inverse of :func:`_b64`; raises on malformed input."""
    return base64.b64decode(text.encode("ascii"))


def _hkdf(ikm: bytes, info: bytes, *, length: int = _KEY_BYTES) -> bytes:
    """HKDF-SHA256 with a fixed (empty) salt and explicit ``info`` separation."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def _x25519_private_from_seed(seed: bytes, agent_id: AgentId) -> X25519PrivateKey:
    """Derive a deterministic X25519 private key for *agent_id* from *seed*.

    Example::

        k = _x25519_private_from_seed(b"root", AgentId("a1"))
        assert isinstance(k, X25519PrivateKey)
    """
    material = _hkdf(seed, b"veil-x25519-id|" + str(agent_id).encode("utf-8"))
    return X25519PrivateKey.from_private_bytes(material)


def _raw_public(key: X25519PublicKey) -> bytes:
    """Raw 32-byte X25519 public key encoding."""
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw_private(key: X25519PrivateKey) -> bytes:
    """Raw 32-byte X25519 private scalar (own key only; never serialised to trace)."""
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _key_id(public_key: bytes) -> str:
    """Stable short identifier for a public key (first 16 hex of its SHA-256)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def _wrap_key(shared: bytes, eph_pub: bytes, recipient_key_id: str) -> bytes:
    """Derive a per-recipient key-wrap key from an ECDH shared secret.

    Binds the **ephemeral public key** and the recipient identity into the HKDF
    ``info`` (HPKE-style key schedule), so a wrap is cryptographically tied to
    this exact encapsulation and recipient — not reusable across messages or
    recipients even if a shared secret somehow recurred.
    """
    info = b"veil-wrap|" + eph_pub + b"|" + recipient_key_id.encode("ascii")
    return _hkdf(shared, info)


# ---------------------------------------------------------------------------
# Selective-disclosure Merkle commitment (pure functions, issuer + verifier)
# ---------------------------------------------------------------------------


def _leaf(name: str, value: str, salt: bytes) -> bytes:
    """Salted, length-prefixed leaf hash ``H("veil-leaf" | name | value | salt)``.

    Length prefixes make the encoding injective, so distinct ``(name, value)``
    pairs can never collide by concatenation ambiguity. The salt hides the value
    from anyone who only sees the root.

    Example::

        h = _leaf("age", "21", b"\\x00" * 16)
        assert len(h) == 32
    """
    parts = [
        b"veil-leaf\x00",
        len(name).to_bytes(4, "big"),
        name.encode("utf-8"),
        len(value).to_bytes(4, "big"),
        value.encode("utf-8"),
        salt,
    ]
    return hashlib.sha256(b"".join(parts)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    """Inner Merkle node ``H("veil-node" | left | right)`` (domain-separated)."""
    return hashlib.sha256(b"veil-node\x00" + left + right).digest()


def _merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Build all tree levels bottom-up; odd nodes are duplicated (Bitcoin-style).

    Returns ``[leaves, ..., [root]]``. An empty credential yields ``[[H("")]]``.
    """
    if not leaves:
        return [[hashlib.sha256(b"veil-empty").digest()]]
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [_node(cur[i], cur[i + 1 if i + 1 < len(cur) else i]) for i in range(0, len(cur), 2)]
        levels.append(nxt)
    return levels


def _merkle_root(leaves: list[bytes]) -> bytes:
    """Root of the salted Merkle tree over *leaves*."""
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
    """Recompute the root from a leaf and its authentication path."""
    acc = leaf
    for sib_hex, sib_is_right in path:
        sib = bytes.fromhex(sib_hex)
        acc = _node(acc, sib) if sib_is_right else _node(sib, acc)
    return acc


def commit_credential(
    fields: dict[str, str], *, salt_seed: bytes | None = None
) -> tuple[str, dict[str, str]]:
    """Issuer helper: commit a multi-field credential to a single root.

    Returns ``(root_hex, salts)`` where ``salts`` maps each field name to a hex
    16-byte salt; fields are ordered by sorted name. The salt is what makes a
    leaf *hiding*: without it, a low-entropy field (``age``, a country code)
    could be recovered by hashing every candidate.

    **Secure default:** with ``salt_seed=None`` the salts are drawn from the
    system RNG, so the commitment is hiding and unlinkable across credentials.
    Pass an explicit ``salt_seed`` *only* for reproducible Tier-1 trace tests —
    that makes the salts deterministic (and, for a publicly known seed, publicly
    re-derivable), trading hiding for replayability. Production issuers must use
    the random default.

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
            salt = _hkdf(salt_seed, b"veil-salt|" + name.encode("utf-8"), length=16)
        salts[name] = salt.hex()
        leaves.append(_leaf(name, fields[name], salt))
    return _merkle_root(leaves).hex(), salts


# ---------------------------------------------------------------------------
# Envelope model + typed parser (json.loads is Any; we validate every field)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Wrap:
    """One per-recipient key-wrap entry inside an envelope."""

    key_id: str
    nonce: bytes
    wrapped: bytes


@dataclass(frozen=True)
class _Envelope:
    """Parsed, validated hybrid-encryption envelope."""

    scheme: str
    sender: str
    epoch: int
    msg_id: str
    eph_pub: bytes
    nonce: bytes
    ciphertext: bytes
    wraps: list[_Wrap]

    def recipient_key_ids(self) -> list[str]:
        """Sorted recipient key ids — the canonical audience binding for the AAD."""
        return sorted(w.key_id for w in self.wraps)


def _require(mapping: dict[str, Any], key: str) -> Any:
    if key not in mapping:
        raise MalformedEnvelopeError(f"missing field {key!r}")
    return mapping[key]


def _parse_envelope(data: bytes) -> _Envelope:
    """Parse and structurally validate envelope bytes (raises on any defect)."""
    try:
        loaded: Any = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise MalformedEnvelopeError("not JSON") from exc
    if not isinstance(loaded, dict):
        raise MalformedEnvelopeError("envelope is not an object")
    obj = cast("dict[str, Any]", loaded)
    if _require(obj, "s") != SCHEME:
        raise MalformedEnvelopeError("unknown scheme")
    raw_wraps = _require(obj, "to")
    if not isinstance(raw_wraps, list):
        raise MalformedEnvelopeError("'to' is not a list")
    wraps: list[_Wrap] = []
    for item in cast("list[Any]", raw_wraps):
        if not isinstance(item, dict):
            raise MalformedEnvelopeError("wrap entry is not an object")
        entry = cast("dict[str, Any]", item)
        wraps.append(
            _Wrap(
                key_id=str(_require(entry, "kid")),
                nonce=_unb64(str(_require(entry, "n"))),
                wrapped=_unb64(str(_require(entry, "w"))),
            )
        )
    try:
        return _Envelope(
            scheme=SCHEME,
            sender=str(_require(obj, "from")),
            epoch=int(_require(obj, "epoch")),
            msg_id=str(_require(obj, "msg")),
            eph_pub=_unb64(str(_require(obj, "eph"))),
            nonce=_unb64(str(_require(obj, "n0"))),
            ciphertext=_unb64(str(_require(obj, "ct"))),
            wraps=wraps,
        )
    except (ValueError, TypeError) as exc:
        raise MalformedEnvelopeError("malformed envelope field") from exc


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class HybridX25519Privacy:
    """Per-agent hybrid-encryption privacy plugin (implements ``Privacy``).

    Each agent holds its own X25519 key (derived from ``seed``) and a directory
    of peer public keys registered via :meth:`register_peer`. Construct with
    ``deterministic=True`` for reproducible Tier-1 traces.

    Example::

        a = HybridX25519Privacy(AgentId("a"), seed=b"a")
        b = HybridX25519Privacy(AgentId("b"), seed=b"b")
        a.register_peer(AgentId("b"), b.public_key)
        env = await a.encrypt(b"hi", [AgentId("b")])
        assert await b.decrypt(env) == b"hi"
    """

    def __init__(
        self, agent_id: AgentId, seed: bytes = b"", *, deterministic: bool = False
    ) -> None:
        self._agent_id = agent_id
        self._deterministic = deterministic
        self._private = _x25519_private_from_seed(seed, agent_id)
        self._public = _raw_public(self._private.public_key())
        self._key_id = _key_id(self._public)
        # Peer directory: AgentId -> current raw X25519 public key.
        self._directory: dict[AgentId, bytes] = {agent_id: self._public}
        # Revocation: AgentId -> epoch from which the member is excluded.
        self._revoked: dict[AgentId, int] = {}
        self._epoch = 0
        self._seq = 0
        # Anti-replay: (sender, msg_id) already decrypted by this agent.
        self._seen: set[tuple[str, str]] = set()

    # -- identity / directory -------------------------------------------------

    @property
    def public_key(self) -> bytes:
        """This agent's raw X25519 public key.

        Example::

            pk = priv.public_key
        """
        return self._public

    @property
    def key_id(self) -> str:
        """Short id of this agent's public key (matches envelope wrap entries).

        Example::

            kid = priv.key_id
        """
        return self._key_id

    @property
    def epoch(self) -> int:
        """Current revocation epoch (advances on :meth:`revoke`).

        Example::

            assert priv.epoch == 0
        """
        return self._epoch

    def register_peer(self, agent_id: AgentId, public_key: bytes) -> None:
        """Register a peer's current public key so messages can be wrapped for it.

        Example::

            priv.register_peer(AgentId("b"), b_public_key)
        """
        self._directory[agent_id] = public_key

    def revoke(self, agent_id: AgentId) -> int:
        """Revoke *agent_id*: advance the epoch and exclude it from future wraps.

        Returns the new epoch. Past envelopes that already wrapped to the member
        remain decryptable by it (see the module forward-secrecy note).

        Example::

            new_epoch = priv.revoke(AgentId("carol"))
        """
        self._epoch += 1
        self._revoked[agent_id] = self._epoch
        return self._epoch

    def _is_revoked(self, agent_id: AgentId, epoch: int) -> bool:
        revoked_at = self._revoked.get(agent_id)
        return revoked_at is not None and epoch >= revoked_at

    # -- randomness (deterministic or system) ---------------------------------

    def _ephemeral(self, msg_id: str) -> X25519PrivateKey:
        if self._deterministic:
            material = _hkdf(_raw_private(self._private), b"veil-eph|" + msg_id.encode("utf-8"))
            return X25519PrivateKey.from_private_bytes(material)
        return X25519PrivateKey.generate()

    def _nonce(self, msg_id: str, index: int) -> bytes:
        if self._deterministic:
            return _hkdf(
                _raw_private(self._private),
                b"veil-nonce|" + msg_id.encode("utf-8") + b"|" + str(index).encode("ascii"),
                length=_NONCE_BYTES,
            )
        return os.urandom(_NONCE_BYTES)

    def _content_key(self, msg_id: str, eph_pub: bytes) -> bytes:
        if self._deterministic:
            return _hkdf(
                _raw_private(self._private),
                b"veil-cek|" + msg_id.encode("utf-8") + b"|" + eph_pub,
            )
        return os.urandom(_KEY_BYTES)

    # -- Privacy protocol: encryption -----------------------------------------

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Encrypt *data* so only non-revoked members of *audience* can read it.

        Produces a self-describing envelope (bytes): one ChaCha20-Poly1305
        encryption of the payload under a fresh content key, plus one X25519+HKDF
        key-wrap of that content key per recipient. The sender, epoch, message id
        and the sorted recipient key-ids are bound into the AEAD associated data,
        so any redirection or field edit breaks authentication.

        Recipients not in the directory, or revoked as of the current epoch, are
        silently excluded (that is exactly the revocation guarantee).

        Example::

            env = await alice.encrypt(b"secret", [AgentId("bob")])
        """
        recipients: list[AgentId] = []
        seen: set[AgentId] = set()
        for aid in audience:
            if aid in seen or aid not in self._directory or self._is_revoked(aid, self._epoch):
                continue
            seen.add(aid)
            recipients.append(aid)

        self._seq += 1
        msg_id = f"{self._agent_id}:{self._epoch}:{self._seq}"
        eph_priv = self._ephemeral(msg_id)
        eph_pub = _raw_public(eph_priv.public_key())

        key_ids = sorted(_key_id(self._directory[aid]) for aid in recipients)
        aad = _canon(
            {
                "s": SCHEME,
                "from": str(self._agent_id),
                "epoch": self._epoch,
                "msg": msg_id,
                "to": key_ids,
            }
        )

        content_key = self._content_key(msg_id, eph_pub)
        content_nonce = self._nonce(msg_id, 0)
        ciphertext = ChaCha20Poly1305(content_key).encrypt(content_nonce, data, aad)

        wraps: list[dict[str, str]] = []
        for index, aid in enumerate(recipients):
            peer_pub = self._directory[aid]
            shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
            wrap_key = _wrap_key(shared, eph_pub, _key_id(peer_pub))
            wrap_nonce = self._nonce(msg_id, index + 1)
            wrapped = ChaCha20Poly1305(wrap_key).encrypt(wrap_nonce, content_key, aad)
            wraps.append({"kid": _key_id(peer_pub), "n": _b64(wrap_nonce), "w": _b64(wrapped)})

        envelope = {
            "v": 1,
            "s": SCHEME,
            "from": str(self._agent_id),
            "epoch": self._epoch,
            "msg": msg_id,
            "eph": _b64(eph_pub),
            "n0": _b64(content_nonce),
            "ct": _b64(ciphertext),
            "to": wraps,
        }
        return _canon(envelope)

    async def decrypt(self, data: bytes) -> bytes:
        """Decrypt an envelope addressed to this agent.

        Raises :class:`NotInAudienceError` if this agent holds no wrap entry
        (eavesdropper or stale-revocation), :class:`ReplayError` on a re-presented
        envelope, and :class:`TamperError` if AEAD authentication fails.

        Example::

            plaintext = await bob.decrypt(env)
        """
        env = _parse_envelope(data)
        wrap = next((w for w in env.wraps if w.key_id == self._key_id), None)
        if wrap is None:
            raise NotInAudienceError(f"{self._agent_id} is not in the audience")
        if (env.sender, env.msg_id) in self._seen:
            raise ReplayError(f"replayed envelope {env.sender}:{env.msg_id}")

        aad = _canon(
            {
                "s": SCHEME,
                "from": env.sender,
                "epoch": env.epoch,
                "msg": env.msg_id,
                "to": env.recipient_key_ids(),
            }
        )
        shared = self._private.exchange(X25519PublicKey.from_public_bytes(env.eph_pub))
        wrap_key = _wrap_key(shared, env.eph_pub, self._key_id)
        try:
            content_key = ChaCha20Poly1305(wrap_key).decrypt(wrap.nonce, wrap.wrapped, aad)
            plaintext = ChaCha20Poly1305(content_key).decrypt(env.nonce, env.ciphertext, aad)
        except InvalidTag as exc:
            raise TamperError("AEAD authentication failed") from exc

        self._seen.add((env.sender, env.msg_id))
        return plaintext

    # -- Privacy protocol: selective-disclosure proofs ------------------------

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        """Prove that the revealed fields belong to the committed credential.

        ``statement.public_inputs`` must carry ``root`` (the issuer's committed
        Merkle root, hex) and ``reveal`` (comma-separated field names to
        disclose). ``witness.private_inputs`` holds every field value plus a
        ``__salts__`` entry (JSON ``{name: salt_hex}``) — i.e. the full opened
        credential. The proof discloses only the requested fields and their
        authentication paths; the rest stay hidden behind the root.

        Raises ``ValueError`` if the witness does not reconstruct the committed
        root (an inconsistent credential), so a holder cannot accidentally prove
        against the wrong commitment.

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

        reveal = _reveal_set(statement)
        disclosed: dict[str, dict[str, Any]] = {}
        for name in reveal:
            idx = names.index(name)
            disclosed[name] = {
                "value": fields[name],
                "salt": salts[name],
                "index": idx,
                "path": _merkle_path(leaves, idx),
            }
        payload = _canon({"root": root, "n": len(names), "disclosed": disclosed})
        return Proof(statement=statement, data=payload, scheme=PROOF_SCHEME)

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Verify a selective-disclosure proof against the statement's root.

        Returns ``True`` iff the proof's scheme matches, every disclosed field's
        salted leaf authenticates to the committed root, the reconstructed root
        equals ``statement.public_inputs['root']``, and the set of disclosed
        fields equals the statement's ``reveal`` set. Any tampering with a
        revealed value, salt, or path node flips a hash and returns ``False``.

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
        if set(disclosed) != _reveal_set(statement):
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


# ---------------------------------------------------------------------------
# Witness / statement decoding helpers
# ---------------------------------------------------------------------------


def _split_witness(witness: Witness) -> tuple[dict[str, str], dict[str, str]]:
    """Split a witness into ``(fields, salts)``; ``__salts__`` holds the salts."""
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


def _reveal_set(statement: Statement) -> set[str]:
    """Parse the comma-separated ``reveal`` field-name list from the statement."""
    raw = statement.public_inputs.get("reveal", "")
    return {name.strip() for name in raw.split(",") if name.strip()}


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
