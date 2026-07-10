# SPDX-License-Identifier: Apache-2.0
"""Trust-gated disclosure tiers on top of hybrid X25519 encryption.

:class:`~nest_plugins_reference.privacy.hybrid_x25519.HybridX25519Privacy`
answers *"who can read this?"* with a **static audience**: every recipient the
sender lists gets the full plaintext. This plugin answers the question the
trust layer has been asking all along — *"how much should each recipient be
allowed to read?"* — by composing the existing hybrid-encryption primitives
with a live :class:`~nest_core.layers.trust.Trust` feed. It re-implements **no
cryptography**: all confidentiality comes from the merged ``hybrid_x25519``
plugin; this module adds the *disclosure policy* that plugin deliberately does
not have.

Tier policy (evaluated per recipient at encrypt time)
-----------------------------------------------------

* **score >= policy.full** (default ``0.8``) — *full tier*. The recipient is
  wrapped into an inner hybrid envelope carrying the complete plaintext.
* **policy.partial <= score < policy.full** (default ``0.5``) — *partial
  tier*. The recipient is wrapped into a **separate** inner envelope that
  carries a redacted view: for a structured payload (a JSON object of string
  fields) that is the configured ``reveal_fields`` subset **plus a salted
  Merkle selective-disclosure proof** (via the composed plugin's
  :meth:`~HybridX25519Privacy.prove`) that the hidden fields are committed
  under the same issuer root; for an opaque payload it is an honest
  SHA-256 commitment and size — never a fake proof.
* **score < policy.partial** — *denied*. The recipient appears in **no** wrap
  set and receives a **signed denial receipt** (Ed25519 via the ``Identity``
  layer when provided, else an HMAC-SHA256 tag only the sender can verify —
  the receipt says which threshold failed and at what score, so a denial is
  auditable rather than silent).

Why the gate cannot be forged or stripped
------------------------------------------

The gate table (agent → tier → score) and policy are hashed into a
``gate_digest`` that is embedded **inside every inner plaintext** before
encryption. AEAD already authenticates the inner envelopes; the digest binds
them to *this* gate decision. Re-attaching an inner envelope to a doctored
gate table (a confused-deputy attempt to launder a partial-tier ciphertext as
full-tier, or to hide a denial) is detected at decrypt time and raises
:class:`~nest_plugins_reference.privacy.hybrid_x25519.TamperError`.

Threat model — what each guard defeats
--------------------------------------

1. **Gate bypass.** A denied or unknown agent holds no wrap entry in either
   inner envelope, so decryption fails exactly as an eavesdropper's would
   (:class:`NotInAudienceError`); the cryptography, not the JSON, enforces
   the gate.
2. **Tier forgery.** A partial-tier recipient tampering the revealed fields,
   salts, or Merkle path of its redacted view breaks the proof against the
   committed root (``verify_proof`` returns ``False``).
3. **Gate-table tampering.** Editing tiers, scores, or policy in the outer
   envelope changes the ``gate_digest`` and no longer matches the digest
   sealed inside the inner plaintexts — :class:`TamperError`.
4. **Denial-receipt forgery.** Receipts are signed (or MAC'd) over a
   canonical payload; :meth:`TrustGatedPrivacy.verify_denial` rejects edits
   to the score, threshold, or subject.
5. **Trust-score poisoning.** A Byzantine trust feed returning NaN,
   infinities, or out-of-range values grants nothing: the gate fails closed,
   denying the recipient with a ``-1.0`` sentinel score in its receipt.

Honest limitations (read before trusting)
-----------------------------------------

* **Gate-time trust.** Tiers are decided from the trust score *at encrypt
  time*. A recipient whose score later collapses keeps any envelope it
  already received (same future-only stance, and the same reason, as
  ``hybrid_x25519`` revocation). Pair with :meth:`revoke` for key-level
  exclusion going forward.
* **No exfiltration control.** A full-tier recipient can always re-share
  plaintext out-of-band. The gate controls *disclosure*, not *use*.
* **HMAC receipts are sender-verifiable only.** Without an ``Identity``
  instance the denial receipt proves nothing to third parties; supply an
  identity plugin for third-party-verifiable receipts.

Determinism
-----------

With ``deterministic=True`` (and a deterministic trust plugin) the entire
envelope — inner ephemeral keys, nonces, commitment salts, receipts — is a
pure function of ``(seed, agent, epoch, seq, payload, audience, scores)``,
so Tier-1 traces stay byte-identical. The secure default is
``deterministic=False``.

Example::

    trust = ScoreAverageTrust()
    alice = TrustGatedPrivacy(AgentId("alice"), trust, seed=b"a", deterministic=True)
    bob = TrustGatedPrivacy(AgentId("bob"), trust, seed=b"b", deterministic=True)
    alice.register_peer(AgentId("bob"), bob.public_key)
    env = await alice.encrypt(b"quarterly-figures", [AgentId("bob")])
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from typing import Any, cast

from nest_core.layers import Identity, Trust
from nest_core.types import AgentId, Proof, Signature, Statement, Witness

from nest_plugins_reference.privacy.hybrid_x25519 import (
    HybridX25519Privacy,
    MalformedEnvelopeError,
    NotInAudienceError,
    PrivacyError,
    TamperError,
    commit_credential,
)

GATE_SCHEME = "trust-gated-hybrid-x25519/1"
"""Wire-format tag on every trust-gated outer envelope.

Example::

    assert GATE_SCHEME.startswith("trust-gated")
"""

PARTIAL_SCHEME = "trust-gated-partial/1"
"""Scheme tag on the redacted view delivered to partial-tier recipients.

Example::

    assert PARTIAL_SCHEME.startswith("trust-gated-partial")
"""

DENIAL_SCHEME = "trust-gated-denial/1"
"""Scheme tag on signed denial receipts.

Example::

    assert DENIAL_SCHEME.startswith("trust-gated-denial")
"""

DISCLOSURE_PREDICATE = "trust_gated_disclosure"
"""Statement predicate used for partial-tier selective-disclosure proofs.

Example::

    assert DISCLOSURE_PREDICATE == "trust_gated_disclosure"
"""

_TIER_FULL = "full"
_TIER_PARTIAL = "partial"
_TIER_DENIED = "denied"

_INVALID_SCORE = -1.0
"""Sentinel recorded in gate/receipt when the trust layer emitted a non-finite
or out-of-range score; the recipient is denied (fail-closed), and the envelope
stays canonical JSON instead of carrying NaN/inf."""


class TrustDeniedError(PrivacyError):
    """Raised when this agent was gated out of an envelope for low trust.

    Carries the (signed) denial ``receipt`` naming the score and the failed
    threshold, so callers can distinguish a policy denial from an ordinary
    :class:`NotInAudienceError` and can audit or appeal it.

    Example::

        try:
            await priv.decrypt(env)
        except TrustDeniedError as exc:
            assert exc.receipt is not None and exc.receipt["s"] == DENIAL_SCHEME
    """

    def __init__(self, message: str, receipt: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.receipt: dict[str, Any] | None = receipt


@dataclass(frozen=True)
class TierPolicy:
    """Trust thresholds selecting the disclosure tier per recipient.

    ``full`` is the minimum score for full plaintext; ``partial`` is the
    minimum score for the redacted view. Anything below ``partial`` is denied.
    Both boundaries are inclusive. Construction validates
    ``0.0 <= partial <= full <= 1.0``.

    Example::

        policy = TierPolicy(full=0.8, partial=0.5)
    """

    full: float = 0.8
    partial: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.partial <= self.full <= 1.0:
            msg = f"invalid tier policy: require 0 <= partial <= full <= 1, got {self}"
            raise ValueError(msg)


# ---------------------------------------------------------------------------
# Local canonical-encoding helpers (kept private to this module on purpose:
# reaching into a sibling module's underscore-prefixed helpers would couple us
# to its internals).
# ---------------------------------------------------------------------------


def _canon(obj: dict[str, Any]) -> bytes:
    """Canonical sorted-key JSON bytes; the only encoding we hash or MAC."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(raw: bytes) -> str:
    """Standard base64 for embedding raw bytes as ASCII in the JSON envelope."""
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    """Inverse of :func:`_b64`; raises on malformed input."""
    return base64.b64decode(text.encode("ascii"))


def _round_score(score: float) -> float:
    """Quantize a trust score for canonical, replay-stable envelope bytes."""
    return round(score, 6)


def _as_str_fields(data: bytes) -> dict[str, str] | None:
    """Return the payload as a flat ``{str: str}`` credential, else ``None``."""
    try:
        loaded: Any = json.loads(data)
    except (ValueError, TypeError):
        return None
    if not isinstance(loaded, dict):
        return None
    mapping = cast("dict[Any, Any]", loaded)
    fields: dict[str, str] = {}
    for key, value in mapping.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return None
        fields[key] = value
    return fields


def _require(mapping: dict[str, Any], key: str) -> Any:
    if key not in mapping:
        raise MalformedEnvelopeError(f"missing field {key!r}")
    return mapping[key]


def _parse_object(data: bytes, context: str) -> dict[str, Any]:
    """Parse *data* as a JSON object or raise :class:`MalformedEnvelopeError`."""
    try:
        loaded: Any = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise MalformedEnvelopeError(f"{context}: not JSON") from exc
    if not isinstance(loaded, dict):
        raise MalformedEnvelopeError(f"{context}: not a JSON object")
    return cast("dict[str, Any]", loaded)


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class TrustGatedPrivacy:
    """Per-agent privacy plugin gating disclosure by live trust score.

    Implements the ``Privacy`` protocol by composition: an internal
    :class:`HybridX25519Privacy` provides all encryption and proof machinery,
    while this class decides — per recipient, per message, from the ``trust``
    layer — whether that recipient gets the full plaintext, a redacted
    selectively-disclosed view, or a signed denial receipt.

    Example::

        trust = ScoreAverageTrust()
        priv = TrustGatedPrivacy(AgentId("alice"), trust, seed=b"a", deterministic=True)
    """

    def __init__(
        self,
        agent_id: AgentId,
        trust: Trust,
        seed: bytes = b"",
        *,
        deterministic: bool = False,
        policy: TierPolicy | None = None,
        identity: Identity | None = None,
        reveal_fields: frozenset[str] = frozenset(),
    ) -> None:
        self._agent_id = agent_id
        self._trust = trust
        self._seed = seed
        self._deterministic = deterministic
        self._policy = policy or TierPolicy()
        self._identity = identity
        self._reveal_fields = reveal_fields
        self._inner = HybridX25519Privacy(agent_id, seed, deterministic=deterministic)
        self._mac_key = hashlib.sha256(b"trust-gated-mac|" + seed).digest()
        self._seq = 0

    # -- composition passthroughs (key directory lives in the inner plugin) ---

    @property
    def inner(self) -> HybridX25519Privacy:
        """The composed hybrid-encryption plugin (all cryptography lives here).

        Example::

            assert isinstance(priv.inner, HybridX25519Privacy)
        """
        return self._inner

    @property
    def policy(self) -> TierPolicy:
        """The tier policy this gate enforces.

        Example::

            assert priv.policy.full >= priv.policy.partial
        """
        return self._policy

    @property
    def public_key(self) -> bytes:
        """This agent's raw X25519 public key (from the composed plugin).

        Example::

            pk = priv.public_key
        """
        return self._inner.public_key

    @property
    def key_id(self) -> str:
        """Short id of this agent's public key (matches inner wrap entries).

        Example::

            kid = priv.key_id
        """
        return self._inner.key_id

    @property
    def epoch(self) -> int:
        """Current revocation epoch of the composed plugin.

        Example::

            assert priv.epoch >= 0
        """
        return self._inner.epoch

    def register_peer(self, agent_id: AgentId, public_key: bytes) -> None:
        """Register a peer's public key so envelopes can be wrapped for it.

        Example::

            priv.register_peer(AgentId("bob"), bob_public_key)
        """
        self._inner.register_peer(agent_id, public_key)

    def revoke(self, agent_id: AgentId) -> int:
        """Key-level revocation, delegated to the composed plugin.

        Trust gating and revocation are complementary: the gate handles *low
        trust*, revocation handles *expulsion*. Returns the new epoch.

        Example::

            new_epoch = priv.revoke(AgentId("mallory"))
        """
        return self._inner.revoke(agent_id)

    # -- tier resolution -------------------------------------------------------

    async def _tier_for(self, agent_id: AgentId) -> tuple[str, float]:
        rep = await self._trust.score(agent_id)
        score = rep.score
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            # Fail closed: a trust layer emitting NaN/inf/out-of-range scores
            # (a poisoned or Byzantine feed) grants NOTHING. The sentinel keeps
            # the receipt canonical JSON instead of echoing the garbage value.
            return _TIER_DENIED, _INVALID_SCORE
        if score >= self._policy.full:
            return _TIER_FULL, score
        if score >= self._policy.partial:
            return _TIER_PARTIAL, score
        return _TIER_DENIED, score

    # -- Privacy protocol: encryption ------------------------------------------

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Encrypt *data* with per-recipient disclosure tiers.

        Queries the trust layer for every distinct audience member and emits a
        self-describing outer envelope containing: the gate table (agent, tier,
        quantized score), at most one inner hybrid envelope for the full tier,
        at most one for the partial tier (carrying the redacted view), and a
        signed denial receipt per denied member. The gate table's digest is
        sealed inside both inner plaintexts, so the table cannot be reworked
        around the ciphertexts.

        Example::

            env = await alice.encrypt(b"secret", [AgentId("bob"), AgentId("carol")])
        """
        recipients: list[AgentId] = []
        seen: set[AgentId] = set()
        for aid in audience:
            if aid not in seen:
                seen.add(aid)
                recipients.append(aid)

        self._seq += 1
        msg_id = f"{self._agent_id}:{self._inner.epoch}:{self._seq}"

        full_tier: list[AgentId] = []
        partial_tier: list[AgentId] = []
        denied: list[tuple[AgentId, float]] = []
        gate: list[dict[str, Any]] = []
        for aid in recipients:
            tier, score = await self._tier_for(aid)
            gate.append({"agent": str(aid), "tier": tier, "score": _round_score(score)})
            if tier == _TIER_FULL:
                full_tier.append(aid)
            elif tier == _TIER_PARTIAL:
                partial_tier.append(aid)
            else:
                denied.append((aid, score))
        gate.sort(key=lambda entry: str(entry["agent"]))

        header: dict[str, Any] = {
            "s": GATE_SCHEME,
            "from": str(self._agent_id),
            "msg": msg_id,
            "policy": {"full": self._policy.full, "partial": self._policy.partial},
            "gate": gate,
        }
        gate_digest = hashlib.sha256(_canon(header)).hexdigest()

        full_blob: str | None = None
        if full_tier:
            full_plain = _canon({"d": gate_digest, "body": _b64(data)})
            full_blob = _b64(await self._inner.encrypt(full_plain, full_tier))

        partial_blob: str | None = None
        if partial_tier:
            package = await self._partial_package(data, gate_digest, msg_id)
            partial_blob = _b64(await self._inner.encrypt(_canon(package), partial_tier))

        denials = [self._denial_receipt(aid, score, msg_id) for aid, score in denied]

        envelope: dict[str, Any] = {
            "v": 1,
            **header,
            "full": full_blob,
            "partial": partial_blob,
            "denials": denials,
        }
        return _canon(envelope)

    async def _partial_package(self, data: bytes, gate_digest: str, msg_id: str) -> dict[str, Any]:
        """Build the redacted view for partial-tier recipients."""
        fields = _as_str_fields(data)
        if fields is None:
            # Opaque payload: an honest commitment, never a pretend proof.
            return {
                "s": PARTIAL_SCHEME,
                "d": gate_digest,
                "kind": "digest",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }

        salt_seed: bytes | None = None
        if self._deterministic:
            salt_seed = hashlib.sha256(
                b"trust-gated-salt|" + self._seed + b"|" + msg_id.encode("utf-8")
            ).digest()
        root, salts = commit_credential(fields, salt_seed=salt_seed)
        reveal = sorted(self._reveal_fields & set(fields))
        statement = Statement(
            predicate=DISCLOSURE_PREDICATE,
            public_inputs={"root": root, "reveal": ",".join(reveal)},
        )
        witness = Witness(private_inputs={**fields, "__salts__": json.dumps(salts)})
        proof = await self._inner.prove(statement, witness)
        return {
            "s": PARTIAL_SCHEME,
            "d": gate_digest,
            "kind": "selective",
            "root": root,
            "reveal": reveal,
            "revealed": {name: fields[name] for name in reveal},
            "proof": _b64(proof.data),
        }

    def _denial_payload(
        self, agent_id: str, score: float, threshold: float, msg_id: str, epoch: int
    ) -> bytes:
        # The threshold is a parameter — NOT read from self._policy — so that
        # verification authenticates the receipt's *claimed* threshold. Binding
        # it to the verifier's live policy instead would let a forged threshold
        # field slide through whenever the policy happened to agree.
        return _canon(
            {
                "s": DENIAL_SCHEME,
                "agent": agent_id,
                "score": score,
                "threshold": threshold,
                "msg": msg_id,
                "from": str(self._agent_id),
                "epoch": epoch,
            }
        )

    def _denial_receipt(self, agent_id: AgentId, score: float, msg_id: str) -> dict[str, Any]:
        """Build a signed (or MAC'd) receipt naming the denial and its cause."""
        quantized = _round_score(score)
        epoch = self._inner.epoch
        payload = self._denial_payload(
            str(agent_id), quantized, self._policy.partial, msg_id, epoch
        )
        receipt: dict[str, Any] = {
            "s": DENIAL_SCHEME,
            "agent": str(agent_id),
            "score": quantized,
            "threshold": self._policy.partial,
            "msg": msg_id,
            "from": str(self._agent_id),
            "epoch": epoch,
        }
        if self._identity is not None:
            sig = self._identity.sign(payload)
            receipt["alg"] = sig.algorithm
            receipt["sig"] = _b64(sig.value)
            receipt["signer"] = str(sig.signer)
        else:
            receipt["alg"] = "hmac-sha256"
            receipt["mac"] = hmac.new(self._mac_key, payload, hashlib.sha256).hexdigest()
        return receipt

    def verify_denial(self, receipt: dict[str, Any]) -> bool:
        """Verify a denial receipt's signature or MAC.

        With an ``Identity`` plugin the check is third-party verifiable; the
        HMAC fallback is verifiable only by the issuing sender (documented in
        the module notes). Any edit to the subject, score, threshold, message
        id, or epoch invalidates the receipt.

        Example::

            assert alice.verify_denial(receipt)
        """
        try:
            payload = self._denial_payload(
                str(receipt["agent"]),
                float(receipt["score"]),
                float(receipt["threshold"]),
                str(receipt["msg"]),
                int(receipt["epoch"]),
            )
        except (KeyError, TypeError, ValueError):
            return False
        if receipt.get("from") != str(self._agent_id):
            return False
        alg = receipt.get("alg")
        if alg == "hmac-sha256":
            expected = hmac.new(self._mac_key, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, str(receipt.get("mac", "")))
        if self._identity is not None and "sig" in receipt:
            sig = Signature(
                signer=AgentId(str(receipt.get("signer", ""))),
                value=_unb64(str(receipt["sig"])),
                algorithm=str(alg),
            )
            return self._identity.verify(payload, sig, AgentId(str(receipt.get("signer", ""))))
        return False

    # -- Privacy protocol: decryption ------------------------------------------

    async def decrypt(self, data: bytes) -> bytes:
        """Decrypt a trust-gated envelope addressed to this agent.

        Full-tier recipients get the original plaintext; partial-tier
        recipients get the canonical redacted-view package (scheme
        ``PARTIAL_SCHEME``) whose embedded proof they can check with
        :meth:`verify_proof`. A denied agent raises :class:`TrustDeniedError`
        carrying its receipt; an agent that was never addressed raises
        :class:`NotInAudienceError`. A gate table that does not match the
        digest sealed inside the inner plaintext raises :class:`TamperError`.

        Example::

            view = await bob.decrypt(env)
        """
        obj = _parse_object(data, "outer envelope")
        if _require(obj, "s") != GATE_SCHEME:
            raise MalformedEnvelopeError("unknown outer scheme")
        header: dict[str, Any] = {
            "s": GATE_SCHEME,
            "from": _require(obj, "from"),
            "msg": _require(obj, "msg"),
            "policy": _require(obj, "policy"),
            "gate": _require(obj, "gate"),
        }
        gate_digest = hashlib.sha256(_canon(header)).hexdigest()

        full_blob = obj.get("full")
        if isinstance(full_blob, str):
            plaintext = await self._try_inner(full_blob)
            if plaintext is not None:
                wrapper = _parse_object(plaintext, "full-tier plaintext")
                if _require(wrapper, "d") != gate_digest:
                    raise TamperError("gate table does not match full-tier plaintext")
                return _unb64(str(_require(wrapper, "body")))

        partial_blob = obj.get("partial")
        if isinstance(partial_blob, str):
            plaintext = await self._try_inner(partial_blob)
            if plaintext is not None:
                package = _parse_object(plaintext, "partial-tier plaintext")
                if _require(package, "s") != PARTIAL_SCHEME:
                    raise MalformedEnvelopeError("unexpected partial-tier scheme")
                if _require(package, "d") != gate_digest:
                    raise TamperError("gate table does not match partial-tier plaintext")
                return plaintext

        raw_denials = obj.get("denials")
        if isinstance(raw_denials, list):
            for item in cast("list[Any]", raw_denials):
                if isinstance(item, dict):
                    receipt = cast("dict[str, Any]", item)
                    if receipt.get("agent") == str(self._agent_id):
                        raise TrustDeniedError(
                            f"{self._agent_id} denied below trust threshold",
                            receipt=receipt,
                        )
        raise NotInAudienceError(f"{self._agent_id} is not in the audience")

    async def _try_inner(self, blob: str) -> bytes | None:
        """Decrypt one inner envelope; ``None`` if we are not in its audience."""
        try:
            return await self._inner.decrypt(_unb64(blob))
        except NotInAudienceError:
            return None

    # -- Privacy protocol: proofs (delegated) -----------------------------------

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        """Generate a selective-disclosure proof (delegates to the composed plugin).

        Example::

            proof = await priv.prove(stmt, witness)
        """
        return await self._inner.prove(statement, witness)

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Verify a selective-disclosure proof (delegates to the composed plugin).

        Example::

            ok = await priv.verify_proof(stmt, proof)
        """
        return await self._inner.verify_proof(statement, proof)
