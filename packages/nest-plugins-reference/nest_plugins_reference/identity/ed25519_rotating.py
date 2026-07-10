# SPDX-License-Identifier: Apache-2.0
"""Real Ed25519 identity with key rotation and as-of historical verification.

Unlike :mod:`nest_plugins_reference.identity.did_key` (which simulates
public-key signatures with textbook RSA and is explicitly *not* production
cryptography), this plugin signs with **real Ed25519** keys via
``cryptography.hazmat.primitives.asymmetric.ed25519`` (RFC 8032).

Ed25519 is deterministic by construction — the per-signature nonce is derived
from the private key and the message, so the same key signing the same bytes
always yields identical signature bytes. That keeps Tier 1 traces
byte-for-byte reproducible without any explicit RNG handling, as long as the
private *seed* is derived deterministically. We derive each key's 32-byte seed
as ``sha256(seed || agent_id || rotation_index)`` and feed it to
``Ed25519PrivateKey.from_private_bytes``.

Key rotation
------------

A long-running agent must be able to rotate its signing key (compromise,
policy) without invalidating signatures it already made. Each key has a
validity window ``[issued_at_tick, rotated_out_tick)``. An agent keeps an
ordered list of :class:`KeyRecord` per peer. A signature made by an old key
still verifies **iff** verification is requested *as-of* a tick inside that old
key's window — see :meth:`Ed25519RotatingIdentity.verify`.

Rotation is a *publishing* operation: the new key is signed by the old key
(continuity-of-identity). :meth:`rotate_key` returns a :class:`RotationRecord`
whose ``continuity_signature`` proves the holder of the old key authorised the
new key. A verifier (or peer) checks that signature before trusting the new
key, so an attacker who only holds the *compromised old* key cannot mint a
*future* key unless they also already control the agent — and crucially the
old key's window is closed at rotation, so signatures it makes after rotation
fail an as-of check.

Two attacks this plugin defeats (and ``did_key`` does not):

1. **Post-rotation forgery** — an attacker who exfiltrated the old key forges a
   *fresh* signature after rotation. It carries the old ``key_id``; verified
   as-of the observation tick (after ``rotated_out``) it falls outside the old
   key's window → rejected.
2. **Backdating** — an attacker signs with the *new* key but claims the
   signature belongs in the old key's window. Verified as-of the old tick, the
   new key's window does not yet contain it → rejected. (The verifier never
   trusts a self-asserted timestamp; the as-of tick is supplied externally.)

Example::

    ident = Ed25519RotatingIdentity(AgentId("a1"), seed=b"seed")
    sig = ident.sign(b"hello")            # signed by key #0
    assert ident.verify(b"hello", sig, AgentId("a1"))
    rec = ident.rotate_key(b"new-seed")   # key #0 window closes, key #1 opens
    assert ident.verify_continuity(AgentId("a1"), rec)
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

ALGORITHM = "ed25519-rotating/1"
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


@dataclass
class KeyRecord:
    """One key in an agent's history with its validity window ``[issued, rotated_out)``.

    The private key is held in-memory only for *own* keys and is **never**
    serialised into a trace or public record. ``rotated_out`` is ``+inf`` while
    the key is current.

    Example::

        rec = KeyRecord(key_id=KeyId("ab.."), public_key=pk, issued_at=0.0)
        assert rec.is_valid_at(0.0) and not rec.is_valid_at(-1.0)
    """

    key_id: KeyId
    public_key: bytes
    issued_at: float
    rotated_out: float = _INF
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
    """Public, signed evidence that one key was rotated to its successor.

    ``continuity_signature`` is an Ed25519 signature **by the old key** over the
    new key's public bytes and window, proving the agent that controlled the old
    key authorised the new one. This is the published artifact a peer verifies
    before accepting the new key — never a private key.

    Example::

        rec = ident.rotate_key(b"new-seed")
        assert ident.verify_continuity(ident.agent_id, rec)
    """

    agent_id: AgentId
    old_key_id: KeyId
    new_key_id: KeyId
    new_public_key: bytes
    issued_at: float
    continuity_signature: bytes

    def continuity_message(self) -> bytes:
        """Canonical bytes the continuity signature is computed over.

        Example::

            msg = rec.continuity_message()
        """
        return _continuity_message(
            self.agent_id, self.old_key_id, self.new_key_id, self.new_public_key, self.issued_at
        )


def _continuity_message(
    agent_id: AgentId,
    old_key_id: KeyId,
    new_key_id: KeyId,
    new_public_key: bytes,
    issued_at: float,
) -> bytes:
    """Build the deterministic byte string a rotation's continuity sig covers."""
    return json.dumps(
        {
            "agent": str(agent_id),
            "old": str(old_key_id),
            "new": str(new_key_id),
            "pk": new_public_key.hex(),
            "issued_at": issued_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _derive_seed(seed: bytes, agent_id: AgentId, rotation_index: int) -> bytes:
    """Derive a deterministic 32-byte Ed25519 private seed.

    Example::

        s = _derive_seed(b"root", AgentId("a1"), 0)
        assert len(s) == 32
    """
    material = seed + b":" + str(agent_id).encode() + b":" + str(rotation_index).encode()
    return hashlib.sha256(material).digest()


def _key_id_for(public_key: bytes) -> KeyId:
    """Compute the :class:`KeyId` for raw public-key bytes."""
    return KeyId(hashlib.sha256(public_key).hexdigest())


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    """Raw 32-byte encoding of an Ed25519 public key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


class Ed25519RotatingIdentity:
    """Per-agent Ed25519 identity supporting rotation and as-of verification.

    Implements the structural :class:`nest_core.layers.identity.Identity`
    protocol (``sign``/``verify``/``resolve``) and adds :meth:`rotate_key`,
    :meth:`verify_continuity`, and an ``as_of`` parameter on :meth:`verify`.

    The plugin keeps a per-agent ordered list of :class:`KeyRecord`. Its own
    record list always begins with key #0. Peers are registered via
    :meth:`register_peer` (current key) or :meth:`apply_rotation` (history).

    Example::

        ident = Ed25519RotatingIdentity(AgentId("a1"), seed=b"seed")
        sig = ident.sign(b"data")
        assert ident.verify(b"data", sig, AgentId("a1"))
    """

    def __init__(self, agent_id: AgentId, seed: bytes = b"") -> None:
        self._agent_id = agent_id
        self._seed = seed
        self._rotation_index = 0
        self._clock = 0.0
        # The last tick at which this agent signed with its own key. Used by
        # rotate_key to avoid stranding a co-tick signature at the rotation
        # boundary (see the "Known limitation — same-tick rotation" note on
        # verify). ``-inf`` means "never signed".
        self._last_sign_tick = float("-inf")
        private = Ed25519PrivateKey.from_private_bytes(_derive_seed(seed, agent_id, 0))
        pub = _public_bytes(private.public_key())
        record = KeyRecord(
            key_id=_key_id_for(pub),
            public_key=pub,
            issued_at=0.0,
            private_key=private,
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
        """Register a peer's *current* public key for verification.

        Signature-compatible with ``did_key.register_peer`` so existing callers
        keep working. The peer's window opens at the registrant's current clock
        and stays open until a later :meth:`apply_rotation`.

        **Non-destructive on re-announce.** Registry announcements are
        idempotent and duplicated in practice. Re-registering a peer's *current*
        key is a no-op — it must never truncate rotation history the verifier
        already learned via :meth:`apply_rotation`, because doing so would
        silently re-open a retired key's window (stale-key acceptance). A key
        *change* for a known agent must go through the continuity-checked
        :meth:`apply_rotation`, never through ``register_peer``; presenting a
        different key here for an agent whose current key is already known is
        rejected.

        Example::

            ident.register_peer(AgentId("a2"), peer_pk)
        """
        if private_key is not None:
            msg = "register_peer accepts public keys only"
            raise ValueError(msg)
        key_id = _key_id_for(public_key)
        existing = self._records.get(agent_id)
        if existing:
            tip = existing[-1]
            if tip.key_id == key_id:
                # Duplicate announcement of the already-current key: no-op.
                # Preserve all learned history/windows.
                return
            # A different key for a known agent must arrive via a
            # continuity-checked rotation, not a bare re-registration.
            msg = (
                "register_peer cannot change a known peer's key; "
                "use apply_rotation with continuity evidence"
            )
            raise ValueError(msg)
        record = KeyRecord(
            key_id=key_id,
            public_key=public_key,
            issued_at=self._clock,
        )
        self._records[agent_id] = [record]

    def rotate_key(self, new_seed: bytes) -> RotationRecord:
        """Rotate this agent's signing key, returning published continuity evidence.

        Closes the current key's window and opens a new key's window. The new
        key is signed by the *old* key (continuity of identity). After this
        call, signing uses the new key; the old key can still verify signatures
        made *during its window* but any signature observed at/after
        ``rotated_out`` fails an as-of check.

        **Same-tick self-strand guard.** A scalar logical clock cannot order
        two events within one tick, so rotating on the *same* tick this agent
        signed would strand that honest co-tick signature: its as-of tick would
        land on the closed old-key boundary and fail verification (see the
        "Known limitation" note on :meth:`verify`). Rather than silently lose an
        agent's own message — or fudge the window in a way that reopens
        post-rotation forgery — this method **raises** ``ValueError`` if called
        on a tick at or before the last own-signing tick. The caller advances
        the logical clock (``set_clock``) before rotating. This keeps behaviour
        deterministic and forgery-resistant, and turns a silent correctness bug
        into a loud, actionable one.

        Example::

            ident.sign(b"m")
            ident.set_clock(ident_tick + 1)  # advance before rotating
            rec = ident.rotate_key(b"new-seed")
            kid = rec.new_key_id
        """
        records = self._records[self._agent_id]
        old = records[-1]
        if old.private_key is None:  # pragma: no cover - own key always has a private key
            msg = "cannot rotate: current key has no private material"
            raise ValueError(msg)
        rotate_at = self._clock
        if rotate_at <= self._last_sign_tick:
            msg = (
                "cannot rotate on the same tick this agent signed: doing so "
                "would strand the co-tick signature (a scalar logical clock "
                "cannot order sign-then-rotate within one tick). Advance the "
                "clock (set_clock) before rotating. See the same-tick note on "
                "verify()."
            )
            raise ValueError(msg)
        old.rotated_out = rotate_at

        self._rotation_index += 1
        private = Ed25519PrivateKey.from_private_bytes(
            _derive_seed(new_seed, self._agent_id, self._rotation_index)
        )
        pub = _public_bytes(private.public_key())
        new_record = KeyRecord(
            key_id=_key_id_for(pub),
            public_key=pub,
            issued_at=rotate_at,
            private_key=private,
        )
        # Persist the new seed so future rotations derive from the latest root.
        self._seed = new_seed

        continuity_msg = _continuity_message(
            self._agent_id, old.key_id, new_record.key_id, pub, rotate_at
        )
        continuity_sig = old.private_key.sign(continuity_msg)
        records.append(new_record)

        return RotationRecord(
            agent_id=self._agent_id,
            old_key_id=old.key_id,
            new_key_id=new_record.key_id,
            new_public_key=pub,
            issued_at=rotate_at,
            continuity_signature=continuity_sig,
        )

    def verify_continuity(self, agent: AgentId, rotation: RotationRecord) -> bool:
        """Verify a rotation's continuity signature against the agent's old key.

        Returns ``True`` iff ``rotation.continuity_signature`` is a valid
        Ed25519 signature *by the old key* over the new key's published bytes
        **and** that old key is still the agent's current (unretired) chain tip.
        This is what proves an attacker holding only a stale key cannot mint a
        successor that peers will accept — they would also need the *current*
        key to produce the next continuity signature. Without the chain-tip
        check a compromised, already-rotated-out key could authorise a fresh
        successor (a retired-key injection), defeating the whole point of
        rotation.

        Example::

            ok = ident.verify_continuity(AgentId("a2"), rotation_record)
        """
        records = self._records.get(agent)
        if not records:
            return False
        old = next((r for r in records if r.key_id == rotation.old_key_id), None)
        if old is None:
            return False
        # Only the current chain tip may authorise the next key. A key that was
        # retired by an *earlier* rotation must never extend the identity chain,
        # even though its continuity signature is cryptographically valid — that
        # is the retired-key injection a compromised stale key would attempt.
        #
        # The legitimate case where ``old`` is already retired is when *this*
        # rotation has already been applied (an agent re-verifying its own
        # freshly published rotation): then ``rotation.new_key_id`` is present in
        # the record list. We key off that membership rather than off
        # ``rotation.issued_at`` — the retire tick is public (it appears in the
        # trace), so an attacker could otherwise replay it to slip past the
        # guard. The successor key id, by contrast, is only present once the
        # genuine rotation has been adopted.
        applied = next((r for r in records if r.key_id == rotation.new_key_id), None)
        already_applied = applied is not None
        if old.rotated_out != _INF and not already_applied:
            return False
        # Defence in depth: when we treat "already applied" as the reason a
        # retired ``old`` key is allowed, the presented record must match the
        # adopted one on more than its ``new_key_id``. A retired-key holder could
        # otherwise forge a record that reuses a legitimate successor's
        # ``new_key_id`` while substituting attacker-chosen ``new_public_key`` /
        # ``issued_at`` and still get a ``True`` here. It is not exploitable via
        # :meth:`apply_rotation` (which no-ops on a known ``new_key_id`` and never
        # ingests the forged public key), but any downstream consumer that treats
        # ``verify_continuity(True)`` as authoritative proof of "this old key
        # authorised exactly this record" would be misled. Reject the mismatch.
        if applied is not None and (
            applied.public_key != rotation.new_public_key or applied.issued_at != rotation.issued_at
        ):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(old.public_key).verify(
                rotation.continuity_signature, rotation.continuity_message()
            )
        except InvalidSignature:
            return False
        return True

    def apply_rotation(self, rotation: RotationRecord) -> bool:
        """Adopt a verified peer rotation into local key history — idempotently.

        Verifies continuity first; on success closes the peer's old key window
        and appends the new key. Returns ``False`` (and changes nothing) if the
        continuity signature does not check out.

        Rotation records are public artifacts that travel over a lossy,
        duplicating transport, so this method is hardened against replay and
        out-of-order delivery:

        - **Idempotent** — if ``rotation.new_key_id`` is already in the local
          history the call is a no-op returning ``True`` (the rotation was
          already adopted). Without this guard a replayed record appends a
          duplicate, window-overlapping ``KeyRecord`` that corrupts history and
          makes :meth:`resolve` non-deterministic.
        - **Chain-tip only** — the rotation is applied only if its
          ``old_key_id`` is the current open tip of the chain (the sole record
          with ``rotated_out == _INF``). A stale rotation whose predecessor was
          already retired is rejected, so an old record re-broadcast after later
          rotations cannot re-open a retired key's window.

        Example::

            ident.apply_rotation(peer_rotation_record)
        """
        if not self.verify_continuity(rotation.agent_id, rotation):
            return False
        records = self._records[rotation.agent_id]
        # Idempotent: this rotation has already been adopted.
        if any(r.key_id == rotation.new_key_id for r in records):
            return True
        # Chain-tip only: the predecessor must be the current open key. Rejects
        # replayed/out-of-order rotations that would re-open a retired window.
        tip = records[-1]
        if tip.key_id != rotation.old_key_id or tip.rotated_out != _INF:
            return False
        tip.rotated_out = rotation.issued_at
        records.append(
            KeyRecord(
                key_id=rotation.new_key_id,
                public_key=rotation.new_public_key,
                issued_at=rotation.issued_at,
            )
        )
        return True

    def sign(self, payload: bytes) -> Signature:
        """Sign *payload* with this agent's current Ed25519 key.

        The returned :class:`~nest_core.types.Signature` carries ``key_id`` (the
        key that signed) and ``signed_at`` (the logical tick of signing). Note
        ``signed_at`` is *advisory metadata for auditing only* — verification
        never trusts it as the as-of authority (see :meth:`verify`).

        Example::

            sig = ident.sign(b"data")
        """
        record = self._records[self._agent_id][-1]
        if record.private_key is None:  # pragma: no cover - own key always signs
            msg = "cannot sign: no private key for current record"
            raise ValueError(msg)
        value = record.private_key.sign(payload)
        # Remember when we last signed so a same-tick rotate_key can nudge its
        # boundary past this signature instead of stranding it.
        self._last_sign_tick = self._clock
        return Signature(
            signer=self._agent_id,
            value=value,
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
        value = record.private_key.sign(payload)
        return Signature(
            signer=self._agent_id,
            value=value,
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

        A signature is accepted iff **all** hold:

        1. It cryptographically verifies under the key bound to ``sig.key_id``.
        2. The signing key's window ``[issued_at, rotated_out)`` contains the
           **as-of tick** — the moment verification is anchored to.
        3. When the signature carries a ``signed_at`` claim, that claim also
           falls inside the signing key's window. This closes a backdating gap:
           a new-key signature whose ``signed_at`` is rewritten into a retired
           key's window is rejected *even when the verifier honestly anchors at
           the tick it observed* (rule 2 alone would accept it). The claim is
           only ever an extra *constraint*, never the anchor; a signature with
           no ``signed_at`` (e.g. a ``did_key``-compatible peer signature) is
           never rejected by this rule. Credit: the ``signed_at``-in-window
           check originates from BIN-HACK-FIX; we scope it so it never rejects
           an honest cross-clock peer signature.

        The as-of tick is supplied by the *verifier* via ``as_of`` (e.g. the
        observed trace tick) and is **never** the attacker-controlled
        ``signed_at``. When ``as_of is None`` we default to the plugin's current
        clock — the secure default for "is this valid now?".

        This defeats both classic attacks: post-rotation forgery is observed at
        a tick past the old key's ``rotated_out`` (rule 2 fails), and backdating
        a new-key signature into an old window fails rule 2 (anchored old) or
        rule 3 (claim outside the new key's window).

        **Known limitation — same-tick rotation.** ``rotate_key`` retires the
        old key and issues the new one at the *same* logical tick T. Because a
        scalar logical clock cannot order two events within one tick, an honest
        old-key signature made "just before" a rotation at T and a
        post-rotation forgery made "just after" at T are **byte-identical**
        (same ``key_id``, same ``signed_at == T``). The window model resolves the
        ambiguity in favour of security: at T the old key is already retired, so
        both are rejected. An honest agent therefore must not sign and rotate on
        the same tick — see :meth:`rotate_key`, which guards against stranding an
        agent's own co-tick signatures.

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
        if not self._window_admits(record, as_of_tick, sig.signed_at):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(record.public_key).verify(sig.value, payload)
        except InvalidSignature:
            return False
        return True

    @staticmethod
    def _window_admits(
        record: KeyRecord,
        as_of_tick: float,
        signed_at: float | None,
    ) -> bool:
        """Decide whether *record*'s window admits a verification.

        Combines the as-of anchor (rule 2) with the ``signed_at``-in-window
        backdating check (rule 3):

        - **Rule 2:** ``as_of_tick`` must be in the key's half-open window
          ``[issued, rotated_out)``.
        - **Rule 3:** if ``signed_at`` is present it must also be in that same
          window. A claim outside the window — e.g. a new-key signature
          backdated into a retired window — fails. ``signed_at`` is only a
          constraint; a missing claim (``None``) never rejects an honest
          cross-clock peer signature (the ``did_key``-compatible path).
        """
        if not record.is_valid_at(as_of_tick):
            return False
        return signed_at is None or record.is_valid_at(signed_at)

    @staticmethod
    def _select_record(
        records: list[KeyRecord],
        key_id: str | None,
        as_of_tick: float,
    ) -> KeyRecord | None:
        """Pick the key record a signature binds to.

        If the signature names a ``key_id`` we resolve exactly that key (so a
        forged old-key signature is checked against the *old* key's closed
        window, not a currently-valid key). Without a ``key_id`` we fall back to
        whichever key was valid at the as-of tick — covering peers registered
        through the ``did_key``-compatible :meth:`register_peer` path.
        """
        if key_id is not None:
            return next((r for r in records if str(r.key_id) == key_id), None)
        return next((r for r in records if r.is_valid_at(as_of_tick)), None)

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        """Resolve *agent* to its identity record (current key + key history).

        The ``metadata`` carries the full per-key window history (public bytes
        and windows only — never private material) so an auditor can replay
        as-of checks straight from a resolved record.

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
            }
            for r in records
        ]
        return AgentIdentity(
            agent_id=agent,
            public_key=current_pk,
            method="did:key",
            metadata={"algorithm": ALGORITHM, "keys": history},
        )
