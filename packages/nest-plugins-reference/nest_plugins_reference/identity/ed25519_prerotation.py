# SPDX-License-Identifier: Apache-2.0
"""Ed25519 identity with KERI-style pre-rotation: next-key commitments.

Threat model
------------

Attacker capabilities assumed: full read access to the trace and to every
published artifact (rotation records, commitments, public keys), plus — in the
worst case — **exfiltration of the agent's current private signing key** (a
leaked CI secret, a compromised host). The attacker does *not* hold the root
seed or the pre-derived, never-used *cold* key.

Three attacks this plugin defeats:

1. **Post-rotation forgery** — a stolen, already-retired key signs fresh
   payloads. Defeated by as-of window verification (kept from the reactive
   rotation design): the old key's validity window is closed, so a signature
   observed after ``rotated_out`` fails.
2. **Backdating** — the new key signs but claims a tick inside the old key's
   window. Defeated by the same window rule anchored to a *verifier-supplied*
   as-of tick, never a self-asserted timestamp.
3. **Rotation hijack** — an attacker holding the *current* private key
   publishes a rotation to an attacker-chosen successor, permanently seizing
   the identity. Reactive rotation (old key signs new key) **cannot** reject
   this: the signature is genuine. Pre-rotation closes it — every
   establishment event pre-commits a digest of the *next* public key, so a
   rotation is only valid if the revealed key hashes to the *prior*
   commitment. The attacker cannot choose the successor without a digest
   preimage; the victim recovers by rotating to the genuinely pre-committed
   cold key, which never touched the compromised host.

Not defended (out of scope, stated so the boundary is explicit): compromise of
the root seed or of the cold key itself, denial of service, and multi-party
recovery (KERI witnesses/delegation) — this plugin models single-controller
pre-rotation only. No post-quantum claims are made.

Design provenance
-----------------

Pre-rotation, the key event log, and the commit-then-reveal discipline are
re-expressed from Samuel M. Smith, *Key Event Receipt Infrastructure (KERI)*,
arXiv:1907.02143 (DOI 10.48550/arXiv.1907.02143), where pre-rotation is the
primary key-management operation. No KERI implementation code is used or
depended upon; commitments are algorithm-prefixed (``"sha256:<hex>"``) in the
spirit of KERI's derivation codes, with the algorithm configurable via
``digest_alg`` and unknown algorithms rejected at construction.

Mechanics
---------

Inception derives signing key ``K0`` *and* pre-derives cold key ``K1`` from the
seed, publishing ``digest(K1.pub)`` as the commitment. ``rotate_key(new_seed)``
**reveals** the already-committed ``K1`` (it can never come from ``new_seed`` —
that is the whole point) and commits a digest of ``K2`` derived from
``new_seed``, which becomes the new cold key. Keys derive deterministically as
``sha256(seed || agent_id || key_index)`` so Tier 1 traces stay byte-for-byte
reproducible (Ed25519 per RFC 8032 is deterministic by construction).

Example::

    ident = Ed25519PreRotatingIdentity(AgentId("a1"), seed=b"seed")
    sig = ident.sign(b"hello")                 # signed by K0
    assert ident.verify(b"hello", sig, AgentId("a1"))
    kid = ident.rotate_key(b"next-root")       # reveals K1, commits digest(K2)
    assert kid == ident.current_key_id
    evidence = ident.latest_rotation           # published RotationRecord
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from nest_core.types import AgentId, AgentIdentity, Signature

ALGORITHM = "ed25519-prerotation/1"
"""Algorithm tag stamped on every :class:`~nest_core.types.Signature`.

Example::

    assert sig.algorithm == ALGORITHM
"""

DEFAULT_DIGEST_ALG = "sha256"
"""Default commitment digest algorithm (repo convention for key ids).

Example::

    ident = Ed25519PreRotatingIdentity(AgentId("a1"), digest_alg=DEFAULT_DIGEST_ALG)
"""


class KeyId(str):
    """Stable identifier for one Ed25519 public key (``sha256`` of the raw bytes).

    The spec's ``rotate_key(new_seed) -> KeyId`` return type. A ``KeyId``
    **is** a ``str`` — it equals, hashes, and prints as the bare hexdigest —
    so the spec-exact return stays a plain key id everywhere. Instances
    returned by :meth:`Ed25519PreRotatingIdentity.rotate_key` additionally
    carry ``old_key_id`` / ``new_key_id``: the merged ``identity_rotation``
    scenario reads rotation evidence off ``rotate_key``'s return value (the
    merged plugin returns a record there — a deviation from the spec's
    declared return type that the merged scenario depends on), and these
    attributes let a spec-conforming plugin slot into that scenario without
    scenario edits. For ids not produced by a rotation, both attributes
    equal the id itself.

    Example::

        kid = KeyId("3b1f...")
        assert kid == "3b1f..." and kid.new_key_id == kid
    """

    __slots__ = ("old_key_id", "new_key_id")

    old_key_id: str
    new_key_id: str

    def __new__(cls, value: str, *, old_key_id: str | None = None) -> KeyId:
        kid = super().__new__(cls, value)
        kid.new_key_id = str(value)
        kid.old_key_id = str(value) if old_key_id is None else str(old_key_id)
        return kid


_INF = float("inf")


def _validate_digest_alg(alg: str) -> None:
    """Reject digest algorithms hashlib cannot produce a plain hexdigest for.

    Example::

        _validate_digest_alg("sha256")   # ok
    """
    try:
        hashlib.new(alg, b"probe").hexdigest()
    except (ValueError, TypeError) as exc:
        msg = f"unknown or unsupported digest algorithm: {alg!r}"
        raise ValueError(msg) from exc


def _make_commitment(alg: str, public_key: bytes) -> str:
    """Build an algorithm-prefixed commitment ``"<alg>:<hexdigest>"``.

    Example::

        c = _make_commitment("sha256", b"\\x00" * 32)
        assert c.startswith("sha256:")
    """
    return f"{alg}:{hashlib.new(alg, public_key).hexdigest()}"


def _commitment_matches(commitment: str, public_key: bytes) -> bool:
    """Recompute a commitment for *public_key* and compare in constant time.

    The algorithm is parsed from the commitment's own prefix, so a verifier
    never guesses; malformed or unknown-algorithm commitments simply fail.

    Example::

        assert _commitment_matches(_make_commitment("sha256", b"pk"), b"pk")
    """
    alg, sep, expected = commitment.partition(":")
    if not sep or not alg or not expected:
        return False
    try:
        actual = hashlib.new(alg, public_key).hexdigest()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _well_formed_commitment(commitment: str) -> bool:
    """Return whether *commitment* is ``"<known-alg>:<hex>"``.

    Example::

        assert _well_formed_commitment("sha256:" + "0" * 64)
    """
    alg, sep, digest_hex = commitment.partition(":")
    if not sep or not alg or not digest_hex:
        return False
    try:
        hashlib.new(alg, b"").hexdigest()
        bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    return True


def _derive_seed(seed: bytes, agent_id: AgentId, key_index: int) -> bytes:
    """Derive a deterministic 32-byte Ed25519 private seed for *key_index*.

    Example::

        s = _derive_seed(b"root", AgentId("a1"), 0)
        assert len(s) == 32
    """
    material = seed + b":" + str(agent_id).encode() + b":" + str(key_index).encode()
    return hashlib.sha256(material).digest()


def _key_id_for(public_key: bytes) -> KeyId:
    """Compute the :class:`KeyId` for raw public-key bytes."""
    return KeyId(hashlib.sha256(public_key).hexdigest())


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    """Raw 32-byte encoding of an Ed25519 public key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _keypair_from(seed32: bytes) -> tuple[Ed25519PrivateKey, bytes]:
    """Build an Ed25519 keypair from a 32-byte seed, returning (private, raw public).

    Example::

        priv, pub = _keypair_from(b"\\x01" * 32)
        assert len(pub) == 32
    """
    private = Ed25519PrivateKey.from_private_bytes(seed32)
    return private, _public_bytes(private.public_key())


@dataclass
class KeyRecord:
    """One key in an agent's history: validity window plus next-key commitment.

    ``next_key_digest`` is the pre-rotation commitment — the algorithm-prefixed
    digest of the *successor* public key, fixed before that key is ever
    revealed. It is ``None`` only for peers registered without inception data
    (the legacy path); such peers can verify signatures but their rotations are
    rejected by design. The private key is held in-memory only for *own* keys
    and is **never** serialised into a trace or public record.

    Example::

        rec = KeyRecord(key_id=KeyId("ab.."), public_key=pk, issued_at=0.0)
        assert rec.is_valid_at(0.0) and not rec.is_valid_at(-1.0)
    """

    key_id: KeyId
    public_key: bytes
    issued_at: float
    rotated_out: float = _INF
    next_key_digest: str | None = None
    private_key: Ed25519PrivateKey | None = field(default=None, repr=False)

    def is_valid_at(self, tick: float) -> bool:
        """Return whether this key's window contains *tick* (half-open interval).

        Example::

            rec = KeyRecord(KeyId("x"), b"pk", issued_at=10.0, rotated_out=20.0)
            assert rec.is_valid_at(10.0) and not rec.is_valid_at(20.0)
        """
        return self.issued_at <= tick < self.rotated_out


@dataclass
class RotationRecord:
    """Public, signed evidence of one establishment event (rotation).

    Extends the reactive-rotation record with ``new_next_digest`` — the
    commitment for the key *after* this one, signed under the old key alongside
    everything else, so the commitment chain itself is continuity-protected.
    ``new_public_key`` must hash to the *prior* record's commitment; a verifier
    checks that in :meth:`Ed25519PreRotatingIdentity.verify_continuity`.

    Example::

        ident.rotate_key(b"new-root")
        rec = ident.latest_rotation
        assert rec is not None and ident.verify_continuity(ident.agent_id, rec)
    """

    agent_id: AgentId
    old_key_id: KeyId
    new_key_id: KeyId
    new_public_key: bytes
    new_next_digest: str
    issued_at: float
    continuity_signature: bytes

    def continuity_message(self) -> bytes:
        """Canonical bytes the continuity signature is computed over.

        Example::

            msg = rec.continuity_message()
        """
        return _continuity_message(
            self.agent_id,
            self.old_key_id,
            self.new_key_id,
            self.new_public_key,
            self.new_next_digest,
            self.issued_at,
        )


def _continuity_message(
    agent_id: AgentId,
    old_key_id: KeyId,
    new_key_id: KeyId,
    new_public_key: bytes,
    new_next_digest: str,
    issued_at: float,
) -> bytes:
    """Build the deterministic byte string a rotation's continuity sig covers."""
    return json.dumps(
        {
            "agent": str(agent_id),
            "old": str(old_key_id),
            "new": str(new_key_id),
            "pk": new_public_key.hex(),
            "next": new_next_digest,
            "issued_at": issued_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


class Ed25519PreRotatingIdentity:
    """Per-agent Ed25519 identity with pre-rotation commitments.

    Implements the structural :class:`nest_core.layers.identity.Identity`
    protocol (``sign``/``verify``/``resolve``) plus spec-exact
    ``rotate_key(new_seed) -> KeyId``, with rotation evidence published via
    :attr:`latest_rotation`. Peers are registered with their inception
    commitment via :meth:`register_peer_inception`; the commitment-less
    :meth:`register_peer` stays signature-compatible with existing callers but
    such peers' rotations are rejected — a single strict path, by design.

    Example::

        ident = Ed25519PreRotatingIdentity(AgentId("a1"), seed=b"seed")
        sig = ident.sign(b"data")
        assert ident.verify(b"data", sig, AgentId("a1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        seed: bytes = b"",
        digest_alg: str = DEFAULT_DIGEST_ALG,
    ) -> None:
        _validate_digest_alg(digest_alg)
        self._agent_id = agent_id
        self._digest_alg = digest_alg
        self._clock = 0.0
        self._latest_rotation: RotationRecord | None = None
        # Inception: K0 signs now; K1 is derived, committed, and kept cold.
        private0, pub0 = _keypair_from(_derive_seed(seed, agent_id, 0))
        self._key_index = 1
        self._pending_private, self._pending_public = _keypair_from(_derive_seed(seed, agent_id, 1))
        record = KeyRecord(
            key_id=_key_id_for(pub0),
            public_key=pub0,
            issued_at=0.0,
            next_key_digest=_make_commitment(digest_alg, self._pending_public),
            private_key=private0,
        )
        self._records: dict[AgentId, list[KeyRecord]] = {agent_id: [record]}

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
        return self._records[self._agent_id][-1].public_key

    @property
    def current_key_id(self) -> KeyId:
        """The :class:`KeyId` of this agent's current signing key.

        Example::

            kid = ident.current_key_id
        """
        return self._records[self._agent_id][-1].key_id

    @property
    def current_commitment(self) -> str:
        """The published commitment to this agent's *next* (cold) key.

        This is the public artifact peers record at inception or rotation; it
        is what makes a hijack detectable before any signature is checked.

        Example::

            c = ident.current_commitment
            assert c.startswith("sha256:")
        """
        digest = self._records[self._agent_id][-1].next_key_digest
        if digest is None:  # pragma: no cover - own records always carry one
            msg = "own key record is missing its commitment"
            raise RuntimeError(msg)
        return digest

    @property
    def latest_rotation(self) -> RotationRecord | None:
        """Published evidence for the most recent rotation, if any.

        ``rotate_key`` returns the spec-exact :class:`KeyId`; the full signed
        record an agent publishes to peers is exposed here.

        Example::

            ident.rotate_key(b"new-root")
            rec = ident.latest_rotation
        """
        return self._latest_rotation

    def set_clock(self, tick: float) -> None:
        """Advance the plugin's logical clock used to stamp new keys/signatures.

        The simulator has no wall clock; agents call this with ``ctx.time`` so
        signatures and rotations carry the logical tick. Kept monotonic.

        Example::

            ident.set_clock(42.0)
        """
        if tick > self._clock:
            self._clock = tick

    def register_peer(
        self,
        agent_id: AgentId,
        public_key: bytes,
        private_key: bytes | None = None,
    ) -> None:
        """Register a peer's *current* public key, without inception data.

        Signature-compatible with ``did_key.register_peer`` so existing callers
        keep working. A peer registered this way can have its signatures
        verified, but — lacking a commitment — no rotation for it will ever be
        accepted (:meth:`verify_continuity` is strict by design). Use
        :meth:`register_peer_inception` for rotating peers.

        Example::

            ident.register_peer(AgentId("a2"), peer_pk)
        """
        if private_key is not None:
            msg = "register_peer accepts public keys only"
            raise ValueError(msg)
        record = KeyRecord(
            key_id=_key_id_for(public_key),
            public_key=public_key,
            issued_at=self._clock,
        )
        self._records[agent_id] = [record]

    def register_peer_inception(
        self,
        agent_id: AgentId,
        public_key: bytes,
        next_key_digest: str,
    ) -> None:
        """Register a peer with its inception commitment (the pre-rotation path).

        Rejects malformed or unknown-algorithm commitments outright — a bad
        commitment recorded today is a rotation that can never be validated
        tomorrow, so it fails loudly at registration time.

        Example::

            ident.register_peer_inception(AgentId("a2"), peer_pk, peer_commitment)
        """
        if not _well_formed_commitment(next_key_digest):
            msg = f"malformed or unsupported commitment: {next_key_digest!r}"
            raise ValueError(msg)
        record = KeyRecord(
            key_id=_key_id_for(public_key),
            public_key=public_key,
            issued_at=self._clock,
            next_key_digest=next_key_digest,
        )
        self._records[agent_id] = [record]

    def rotate_key(self, new_seed: bytes) -> KeyId:
        """Rotate to the pre-committed cold key; commit the next one from *new_seed*.

        The revealed key is the one committed at the *previous* establishment
        event — it deliberately cannot be influenced by ``new_seed``. What
        ``new_seed`` controls is the key *after* this one: its digest is
        committed now, its private half becomes the new cold key. Publishes
        evidence via :attr:`latest_rotation` and returns the new key's id
        (spec-exact return type).

        Example::

            kid = ident.rotate_key(b"new-root")
            assert kid == ident.current_key_id
        """
        records = self._records[self._agent_id]
        old = records[-1]
        if old.private_key is None:  # pragma: no cover - own key always has a private key
            msg = "cannot rotate: current key has no private material"
            raise ValueError(msg)
        rotate_at = self._clock

        promoted_private, promoted_public = self._pending_private, self._pending_public
        self._key_index += 1
        self._pending_private, self._pending_public = _keypair_from(
            _derive_seed(new_seed, self._agent_id, self._key_index)
        )
        new_next_digest = _make_commitment(self._digest_alg, self._pending_public)

        new_record = KeyRecord(
            key_id=_key_id_for(promoted_public),
            public_key=promoted_public,
            issued_at=rotate_at,
            next_key_digest=new_next_digest,
            private_key=promoted_private,
        )
        continuity_msg = _continuity_message(
            self._agent_id,
            old.key_id,
            new_record.key_id,
            promoted_public,
            new_next_digest,
            rotate_at,
        )
        continuity_sig = old.private_key.sign(continuity_msg)
        old.rotated_out = rotate_at
        records.append(new_record)

        self._latest_rotation = RotationRecord(
            agent_id=self._agent_id,
            old_key_id=old.key_id,
            new_key_id=new_record.key_id,
            new_public_key=promoted_public,
            new_next_digest=new_next_digest,
            issued_at=rotate_at,
            continuity_signature=continuity_sig,
        )
        return KeyId(new_record.key_id, old_key_id=old.key_id)

    def forge_rotation(self, new_seed: bytes) -> RotationRecord:
        """Adversarial-only hook: a continuity-signed rotation to a NON-committed key.

        Models the rotation hijack — an attacker who exfiltrated the *current*
        private key mints a successor of their own choosing. The continuity
        signature is genuine (they hold the key), but the revealed public key
        was never pre-committed, so :meth:`verify_continuity` must reject it.
        Derivation is domain-separated (``b"attacker:"``): holding the current
        private key does not confer the root seed, so the attacker cannot
        reproduce the genuine cold key. Mutates no state — this is a published
        *attempt*, mirroring the ``sign_with`` forgery-hook precedent.

        Example::

            attempt = attacker.forge_rotation(b"attacker-seed")
            assert not victim_peer.verify_continuity(attempt.agent_id, attempt)
        """
        old = self._records[self._agent_id][-1]
        if old.private_key is None:  # pragma: no cover - own key always has a private key
            msg = "cannot forge: current key has no private material"
            raise ValueError(msg)
        _, forged_public = _keypair_from(
            _derive_seed(b"attacker:" + new_seed, self._agent_id, self._key_index)
        )
        _, forged_next_public = _keypair_from(
            _derive_seed(b"attacker:" + new_seed, self._agent_id, self._key_index + 1)
        )
        forged_next_digest = _make_commitment(self._digest_alg, forged_next_public)
        continuity_msg = _continuity_message(
            self._agent_id,
            old.key_id,
            _key_id_for(forged_public),
            forged_public,
            forged_next_digest,
            self._clock,
        )
        return RotationRecord(
            agent_id=self._agent_id,
            old_key_id=old.key_id,
            new_key_id=_key_id_for(forged_public),
            new_public_key=forged_public,
            new_next_digest=forged_next_digest,
            issued_at=self._clock,
            continuity_signature=old.private_key.sign(continuity_msg),
        )

    def verify_continuity(self, agent: AgentId, rotation: RotationRecord) -> bool:
        """Verify a rotation: continuity signature, chain tip, AND commitment.

        Accepts iff **all** hold:

        1. ``rotation.continuity_signature`` is a valid Ed25519 signature by
           the old key over the full event (including ``new_next_digest``).
        2. The old key is the agent's current chain tip (retired keys must
           never extend the chain — the retired-key-injection guard), unless
           this exact rotation was already applied.
        3. **The revealed key honours the prior commitment**:
           ``digest(rotation.new_public_key)`` equals the old record's
           ``next_key_digest``, recomputed under the algorithm named in the
           commitment's own prefix. A continuity signature alone proves only
           possession of the old key — which is exactly what a hijacker has.
           This check is what they cannot pass.
        4. ``rotation.new_next_digest`` is a well-formed commitment, so the
           chain stays verifiable one event ahead.

        A peer with no known commitment (legacy :meth:`register_peer`) fails
        here unconditionally: single strict path, no permissive mode.

        Example::

            ok = ident.verify_continuity(AgentId("a2"), rotation_record)
        """
        records = self._records.get(agent)
        if not records:
            return False
        old = next((r for r in records if r.key_id == rotation.old_key_id), None)
        if old is None:
            return False
        # Only the current chain tip may authorise the next key; the legitimate
        # already-retired case is an agent re-verifying its own applied
        # rotation, detectable by the successor key's presence in the chain
        # (the successor id only exists once the genuine rotation was adopted —
        # unlike the retire tick, it is not attacker-replayable from the trace).
        already_applied = any(r.key_id == rotation.new_key_id for r in records)
        if old.rotated_out != _INF and not already_applied:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(old.public_key).verify(
                rotation.continuity_signature, rotation.continuity_message()
            )
        except InvalidSignature:
            return False
        if old.next_key_digest is None:
            return False
        if not _commitment_matches(old.next_key_digest, rotation.new_public_key):
            return False
        return _well_formed_commitment(rotation.new_next_digest)

    def apply_rotation(self, rotation: RotationRecord) -> bool:
        """Adopt a verified peer rotation into local key history.

        Verifies continuity (signature + chain tip + commitment) first; on
        success closes the peer's old key window and appends the new key with
        its forward commitment. Returns ``False`` (and changes nothing) if
        verification fails — a hijack attempt leaves no trace in local state.

        Example::

            ident.apply_rotation(peer_rotation_record)
        """
        if not self.verify_continuity(rotation.agent_id, rotation):
            return False
        records = self._records[rotation.agent_id]
        for r in records:
            if r.key_id == rotation.old_key_id and r.rotated_out == _INF:
                r.rotated_out = rotation.issued_at
        records.append(
            KeyRecord(
                key_id=rotation.new_key_id,
                public_key=rotation.new_public_key,
                issued_at=rotation.issued_at,
                next_key_digest=rotation.new_next_digest,
            )
        )
        return True

    def sign(self, payload: bytes) -> Signature:
        """Sign *payload* with this agent's current Ed25519 key.

        The returned :class:`~nest_core.types.Signature` carries ``key_id`` and
        ``signed_at`` (advisory metadata for auditing only — verification never
        trusts it as the as-of authority, see :meth:`verify`).

        Example::

            sig = ident.sign(b"data")
        """
        record = self._records[self._agent_id][-1]
        if record.private_key is None:  # pragma: no cover - own key always signs
            msg = "cannot sign: no private key for current record"
            raise ValueError(msg)
        return Signature(
            signer=self._agent_id,
            value=record.private_key.sign(payload),
            algorithm=ALGORITHM,
            key_id=str(record.key_id),
            signed_at=self._clock,
        )

    def sign_with(self, payload: bytes, key_id: KeyId) -> Signature:
        """Sign *payload* with a specific (possibly rotated-out) key by id.

        Exposed so adversarial agents can attempt post-rotation forgery with a
        stale key. The honest path uses :meth:`sign`.

        Example::

            forged = attacker.sign_with(b"data", stolen_key_id)
        """
        record = next(
            (r for r in self._records[self._agent_id] if r.key_id == key_id),
            None,
        )
        if record is None or record.private_key is None:
            msg = f"no private key for {key_id!r}"
            raise ValueError(msg)
        return Signature(
            signer=self._agent_id,
            value=record.private_key.sign(payload),
            algorithm=ALGORITHM,
            key_id=str(record.key_id),
            signed_at=self._clock,
        )

    def verify(
        self,
        payload: bytes,
        sig: Signature,
        agent: AgentId,
        as_of: float | None = None,
    ) -> bool:
        """Verify *sig* over *payload* from *agent*, optionally as-of a tick.

        A signature is accepted iff it cryptographically verifies under the key
        bound to ``sig.key_id`` **and** that key's validity window
        ``[issued_at, rotated_out)`` contains the as-of tick. The as-of tick is
        supplied by the *verifier* (e.g. the observed trace tick) and is never
        read from ``sig.signed_at``, which an attacker controls. When ``as_of``
        is ``None`` we default to the plugin's current clock. This single rule
        defeats post-rotation forgery (old window closed) and backdating (new
        window not yet open).

        Example::

            ok = ident.verify(b"data", sig, AgentId("a2"), as_of=15.0)
        """
        if sig.signer != agent:
            return False
        records = self._records.get(agent)
        if not records:
            return False
        as_of_tick = self._clock if as_of is None else as_of
        record = self._select_record(records, sig.key_id, as_of_tick)
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
    def _select_record(
        records: list[KeyRecord],
        key_id: str | None,
        as_of_tick: float,
    ) -> KeyRecord | None:
        """Pick the key record a signature binds to.

        A named ``key_id`` resolves exactly that key (so a forged old-key
        signature is checked against the *old* key's closed window); without
        one we fall back to whichever key was valid at the as-of tick —
        covering peers registered through the legacy path.
        """
        if key_id is not None:
            return next((r for r in records if str(r.key_id) == key_id), None)
        return next((r for r in records if r.is_valid_at(as_of_tick)), None)

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        """Resolve *agent* to its identity record (current key + committed history).

        The ``metadata`` carries the full per-key history — public bytes,
        windows, and next-key commitments; never private material — so an
        auditor can replay both the as-of checks and the commitment chain
        straight from a resolved record.

        Example::

            info = await ident.resolve(AgentId("a2"))
        """
        records = self._records.get(agent, [])
        current_pk = records[-1].public_key if records else b""
        history = [
            {
                "key_id": str(r.key_id),
                "public_key": r.public_key.hex(),
                "issued_at": r.issued_at,
                "rotated_out": None if r.rotated_out == _INF else r.rotated_out,
                "next_key_digest": r.next_key_digest,
            }
            for r in records
        ]
        return AgentIdentity(
            agent_id=agent,
            public_key=current_pk,
            method="did:key",
            metadata={"algorithm": ALGORITHM, "keys": history},
        )
