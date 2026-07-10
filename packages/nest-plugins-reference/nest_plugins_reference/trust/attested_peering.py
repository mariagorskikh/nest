# SPDX-License-Identifier: Apache-2.0
"""Attested-peering trust plugin — verify a peer *before* trusting its reports.

The two bundled trust plugins answer "how well has this agent behaved?"
(:mod:`~nest_plugins_reference.trust.score_average` averages feedback,
:mod:`~nest_plugins_reference.trust.agent_receipts` corroborates it with
receipts). Neither answers the prior question: **is the thing reporting
feedback even who it claims to be, and should its evidence count at all?**
Under the default ``score_average`` plugin any agent — including a freshly
minted Sybil — can file unlimited ``report()`` calls and poison a victim's
reputation.

This plugin ports LibreSynergy's *attested peering* handshake (a production
mesh-federation gate) into the Nanda Town trust layer. Before a peer's
evidence is admitted, the peer must clear a three-question, replay-proof
mutual handshake (``hail`` → ``vouch`` → ``seal``):

1. **Friend or foe?** — does the peer hold the private key for the identity it
   presents, and is that identity's :class:`AgentFactsCard` authentic (self
   signature + operator delegation valid)? Key possession is proven by an
   Ed25519 signature over *this* session's transcript — never a replayable
   bare nonce — so a stolen passport with the wrong key, or a replayed proof
   from another session, both fail.
2. **Can I trust you with my data?** — an optional, freshly nonce-bound signed
   environment quote over the peer's measured configuration (a deterministic
   stand-in for a TPM measured-boot quote).
3. **Who do you work for?** — a named operator delegated authority to this
   agent via a signed delegation embedded in its passport, and that operator
   is on the verifier's trusted-operator roster.

Only peers whose verdict is ``ALLOW`` may contribute evidence via
:meth:`AttestedPeeringTrust.report`; everything else is quarantined and
surfaced in the trace for the adversarial validators to count.

Determinism
-----------

Ed25519 is deterministic by construction (RFC 8032): the per-signature nonce
is derived from the private key and message, so the same key signing the same
bytes always yields identical signature bytes. Private seeds are derived as
``sha256(seed || agent_id)[:32]`` exactly like
:mod:`nest_plugins_reference.identity.ed25519_rotating`; handshake nonces come
from a per-instance :class:`random.Random` seeded off the same material.
There is **no** ``os.urandom``, no wall-clock time, and no subprocess anywhere
in this module, so a Tier-1 run is byte-identical under a fixed scenario seed.

Example::

    verifier = AttestedPeeringTrust(agent_id=AgentId("observer"), seed=b"s")
    peer = AttestedPeeringTrust(
        agent_id=AgentId("a1"), seed=b"s", operator_seed=b"op",
    )
    verifier.trust_operator(peer.operator_id, peer.operator_public_key)

    hail = peer.make_hail(report_kind="positive")
    vouch = verifier.make_vouch(hail, session_key=AgentId("a1"))
    seal = peer.make_seal(vouch)
    verdict = verifier.evaluate_seal(AgentId("a1"), seal)
    assert verdict.decision == "ALLOW"
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import random
from dataclasses import dataclass, field, replace
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.types import (
    AgentId,
    Attestation,
    Claim,
    Evidence,
    ReputationScore,
    Signature,
)

ALGORITHM = "ed25519-attested/1"
"""Algorithm tag stamped on every attestation :class:`~nest_core.types.Signature`.

Example::

    assert att.signature.algorithm == ALGORITHM
"""

PROTO = "nest-attest/1"
"""Handshake protocol identifier embedded in every message and transcript.

Example::

    assert hail["proto"] == PROTO
"""

HANDSHAKE_TAG = b"nest-attest-handshake-v1"
DELEGATION_TAG = b"nest-attest-delegation-v1"
ENV_TAG = b"nest-attest-env-v1"

_ENV_COMPONENTS = ("firmware", "bootloader", "kernel", "agent_code")


# ---------------------------------------------------------------------------
# Low-level Ed25519 + encoding helpers (pure, no I/O, no clock, no os RNG)
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    """Base64-encode bytes to an ASCII string.

    Example::

        assert _b64(b"\\x00") == "AA=="
    """
    return base64.b64encode(raw).decode("ascii")


def _ub64(text: str) -> bytes:
    """Decode a base64 ASCII string back to bytes (``b""`` for falsy input).

    Never raises: malformed base64 from a byzantine peer yields ``b""``, which
    then fails signature/key verification downstream as a clean DENY rather than
    crashing the verifier.

    Example::

        assert _ub64("AA==") == b"\\x00"
        assert _ub64("!! not base64 !!") == b""
    """
    if not text:
        return b""
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        return b""


def _uhex(text: str) -> bytes:
    """Decode a hex string to bytes; ``b""`` on malformed/falsy input (never raises).

    A byzantine peer's malformed ``nonce`` field yields ``b""``, so the derived
    transcript simply won't match and the handshake ends in DENY.

    Example::

        assert _uhex("00ff") == b"\\x00\\xff"
        assert _uhex("zz") == b""
    """
    if not text:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def _sha256_hex(raw: bytes) -> str:
    """Hex SHA-256 digest of *raw*.

    Example::

        assert len(_sha256_hex(b"x")) == 64
    """
    return hashlib.sha256(raw).hexdigest()


def _fingerprint(pub_raw: bytes) -> str:
    """Stable 16-hex identity fingerprint of a raw Ed25519 public key.

    Example::

        fid = _fingerprint(b"\\x00" * 32)
    """
    return _sha256_hex(pub_raw)[:16]


def _derive_private_key(seed: bytes) -> Ed25519PrivateKey:
    """Derive a deterministic Ed25519 private key from arbitrary seed bytes.

    The 32-byte private scalar is ``sha256(seed)[:32]``; the same seed always
    yields the same key, which is what keeps Tier-1 traces reproducible.

    Example::

        key = _derive_private_key(b"seed" + b"a1")
    """
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest()[:32])


def _public_raw(priv: Ed25519PrivateKey) -> bytes:
    """Return the 32-byte raw public key for a private key.

    Example::

        pub = _public_raw(_derive_private_key(b"s"))
    """
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(priv: Ed25519PrivateKey, msg: bytes) -> bytes:
    """Ed25519-sign *msg* with *priv* (deterministic).

    Example::

        sig = _sign(_derive_private_key(b"s"), b"m")
    """
    return priv.sign(msg)


def _verify(pub_raw: bytes, msg: bytes, sig: bytes) -> bool:
    """Return whether *sig* is a valid Ed25519 signature over *msg* by *pub_raw*.

    Never raises: a malformed key or signature returns ``False``.

    Example::

        priv = _derive_private_key(b"s")
        assert _verify(_public_raw(priv), b"m", _sign(priv, b"m"))
    """
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
    except (InvalidSignature, ValueError):
        return False
    return True


def _canon(obj: dict[str, Any]) -> bytes:
    """Canonical (sorted-key, compact) JSON encoding — the only thing we sign.

    Example::

        assert _canon({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _delegation_msg(operator_id: str, agent_id: str, label: str) -> bytes:
    """Canonical bytes an operator signs to delegate authority to an agent.

    Example::

        msg = _delegation_msg("op", "a1", "buyer-1")
    """
    return DELEGATION_TAG + f"|{operator_id}|{agent_id}|{label}".encode()


# ---------------------------------------------------------------------------
# AgentFacts passport
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentFactsCard:
    """A signed identity passport an agent presents during the handshake.

    ``facts_signature`` is the agent key's Ed25519 signature over the canonical
    body (every field except the two signatures); ``delegation_signature`` is
    the *operator* key's signature over :func:`_delegation_msg`, binding
    ``operator_id`` → ``agent_id`` (the "who do you work for?" chain). A card
    with no ``operator_id`` is a self-asserted principal.

    Example::

        card = builder.card  # built and signed by AttestedPeeringTrust
        assert card.agent_id == "a1"
    """

    agent_id: str
    label: str
    public_key: bytes
    principal_name: str
    operator_id: str = ""
    operator_public_key: bytes = b""
    capabilities: tuple[str, ...] = ()
    facts_signature: bytes = b""
    delegation_signature: bytes = b""

    def body(self) -> dict[str, Any]:
        """Signable body of the card — every field except the two signatures.

        Example::

            payload = card.body()
        """
        return {
            "agent_id": self.agent_id,
            "label": self.label,
            "public_key": _b64(self.public_key),
            "principal_name": self.principal_name,
            "operator_id": self.operator_id,
            "operator_public_key": _b64(self.operator_public_key),
            "capabilities": list(self.capabilities),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full card (body + signatures) for transport.

        Example::

            wire = card.to_dict()
        """
        payload = self.body()
        payload["facts_signature"] = _b64(self.facts_signature)
        payload["delegation_signature"] = _b64(self.delegation_signature)
        return payload

    @staticmethod
    def from_dict(data: Any) -> AgentFactsCard:
        """Rebuild a card from its :meth:`to_dict` form (untrusted wire input).

        Tolerant of missing fields and non-dict input: a byzantine peer's
        truncated or type-confused passport parses into a card with an empty
        public key, which :func:`_verify_card` rejects as a clean DENY rather
        than raising ``KeyError``/``AttributeError`` in the verifier.

        Example::

            card = AgentFactsCard.from_dict(wire)
            assert AgentFactsCard.from_dict({}).public_key == b""
            assert AgentFactsCard.from_dict("garbage").public_key == b""
        """
        fields: dict[str, Any] = {}
        if isinstance(data, dict):
            fields = cast("dict[str, Any]", data)
        raw_caps = fields.get("capabilities", ())
        caps: tuple[str, ...] = (
            tuple(str(c) for c in cast("list[Any] | tuple[Any, ...]", raw_caps))
            if isinstance(raw_caps, (list, tuple))
            else ()
        )
        return AgentFactsCard(
            agent_id=str(fields.get("agent_id", "")),
            label=str(fields.get("label", "")),
            public_key=_ub64(str(fields.get("public_key", ""))),
            principal_name=str(fields.get("principal_name", "")),
            operator_id=str(fields.get("operator_id", "")),
            operator_public_key=_ub64(str(fields.get("operator_public_key", ""))),
            capabilities=caps,
            facts_signature=_ub64(str(fields.get("facts_signature", ""))),
            delegation_signature=_ub64(str(fields.get("delegation_signature", ""))),
        )

    def facts_hash(self) -> str:
        """Hex digest of the card body — what the transcript commits to.

        Example::

            h = card.facts_hash()
        """
        return _sha256_hex(_canon(self.body()))


def _verify_card(card: AgentFactsCard) -> tuple[bool, str]:
    """Verify a card's self-signature and (if present) operator delegation.

    Returns ``(authentic, detail)``. This is the cryptographic-authenticity
    arm of "friend or foe?"; the trusted-operator *roster* check lives in
    "who do you work for?". Never raises.

    Example::

        ok, detail = _verify_card(card)
    """
    if not card.public_key:
        return False, "malformed passport (no public key)"
    if not _verify(card.public_key, _canon(card.body()), card.facts_signature):
        return False, "passport self-signature invalid (forged or tampered)"
    if card.operator_id:
        if not card.operator_public_key:
            return False, "delegation claims an operator but carries no operator key"
        if _fingerprint(card.operator_public_key) != card.operator_id:
            return False, "operator_id does not match its public key"
        msg = _delegation_msg(card.operator_id, card.agent_id, card.label)
        if not _verify(card.operator_public_key, msg, card.delegation_signature):
            return False, "operator delegation signature invalid (agent not authorised)"
        return True, f"authentic passport; delegated by operator {card.operator_id}"
    return True, f"authentic passport; self-asserted principal '{card.principal_name}'"


# ---------------------------------------------------------------------------
# Environment (measured-boot) quote — deterministic simulation
# ---------------------------------------------------------------------------


def golden_measurements() -> dict[str, str]:
    """Return the deterministic 'golden' boot measurements every honest node has.

    Each component hashes a fixed label, so all honest agents share one boot
    digest a verifier can allow-list. A tampered component (see the tests)
    changes the digest and fails :func:`_verify_env`.

    Example::

        m = golden_measurements()
        assert set(m) == set(_ENV_COMPONENTS)
    """
    return {c: _sha256_hex(f"golden:{c}".encode()) for c in _ENV_COMPONENTS}


def _boot_digest(measurements: dict[str, str]) -> str:
    """Order-fixed composite of a measurement set (analogue of a TPM PCR digest).

    Example::

        d = _boot_digest(golden_measurements())
    """
    parts = [f"{c}={measurements.get(c, '')}" for c in _ENV_COMPONENTS]
    return _sha256_hex("\n".join(parts).encode("utf-8"))


def _make_env_quote(
    ak_key: Ed25519PrivateKey,
    nonce: bytes,
    measurements: dict[str, str],
) -> dict[str, Any]:
    """Produce a signed, nonce-bound boot-state quote (simulated TPM quote).

    Example::

        q = _make_env_quote(ak, b"nonce", golden_measurements())
    """
    digest = _boot_digest(measurements)
    ak_pub = _public_raw(ak_key)
    msg = ENV_TAG + digest.encode("utf-8") + b"|" + nonce
    return {
        "measurements": measurements,
        "boot_digest": digest,
        "nonce": nonce.hex(),
        "ak_pub": _b64(ak_pub),
        "ak_id": _fingerprint(ak_pub),
        "sig": _b64(_sign(ak_key, msg)),
    }


def _verify_env(quote: dict[str, Any], nonce: bytes, known_good: set[str]) -> tuple[bool, str]:
    """Verify a boot quote is fresh, self-consistent, and in the allow-list.

    Example::

        ok, detail = _verify_env(quote, nonce, {digest})
    """
    if quote.get("nonce") != nonce.hex():
        return False, "boot quote is stale (nonce mismatch — possible replay)"
    raw_measurements = quote.get("measurements", {})
    if not isinstance(raw_measurements, dict):
        return False, "boot quote measurements malformed"
    measurements = cast("dict[str, str]", raw_measurements)
    if _boot_digest(measurements) != quote.get("boot_digest"):
        return False, "boot_digest does not match measurements (tampered)"
    ak_pub = _ub64(str(quote.get("ak_pub", "")))
    if _fingerprint(ak_pub) != quote.get("ak_id"):
        return False, "attestation-key id does not match its public key"
    digest = str(quote.get("boot_digest", ""))
    msg = ENV_TAG + digest.encode("utf-8") + b"|" + nonce
    if not _verify(ak_pub, msg, _ub64(str(quote.get("sig", "")))):
        return False, "boot quote signature invalid (not signed by this AK)"
    if known_good and digest not in known_good:
        return False, f"unrecognised boot state {digest[:12]} — configuration not vetted"
    return True, f"boot state {digest[:12]} vetted, fresh"


# ---------------------------------------------------------------------------
# Verdict types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PeeringCheck:
    """Outcome of one of the three handshake questions.

    Example::

        chk = PeeringCheck(ok=True, detail="identity a2 proven")
    """

    ok: bool
    detail: str


@dataclass(frozen=True)
class PeeringVerdict:
    """The verdict :meth:`AttestedPeeringTrust.evaluate_peer` returns per peer.

    ``decision`` is ``"ALLOW"`` iff all three checks pass; the per-question
    detail is preserved so a scenario can emit it into the trace.

    Example::

        v = verifier.evaluate_peer(card, transcript, proofs, nonce)
        assert v.decision in ("ALLOW", "DENY")
    """

    peer_id: str
    friend_or_foe: PeeringCheck
    trust_my_data: PeeringCheck
    who_you_work_for: PeeringCheck
    decision: str

    @property
    def friend(self) -> bool:
        """Whether all three checks passed.

        Example::

            if verdict.friend: ...
        """
        return self.decision == "ALLOW"


@dataclass
class PeeringPolicy:
    """Verifier-side policy for :meth:`AttestedPeeringTrust.evaluate_peer`.

    Example::

        policy = PeeringPolicy(require_trusted_operator=True)
    """

    trusted_operators: dict[str, bytes] = field(default_factory=dict[str, bytes])
    roster: set[str] | None = None
    tofu: bool = True
    require_env_quote: bool = False
    known_good_boot: set[str] = field(default_factory=set[str])
    require_trusted_operator: bool = True


@dataclass
class _Session:
    """Responder-side per-peer handshake state kept between vouch and seal."""

    nonce_a: bytes
    nonce_b: bytes
    facts_a: AgentFactsCard
    report_kind: str


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class AttestedPeeringTrust:
    """Trust plugin that gates reputation on an attested-peering handshake.

    Implements the :class:`nest_core.layers.trust.Trust` protocol. The
    constructor mirrors ``ScoreAverageTrust(identity)`` (the ``identity``
    positional is accepted and ignored — this plugin carries its own keys) so
    it slots into existing scenarios; the handshake surface
    (:meth:`make_hail`, :meth:`make_vouch`, :meth:`make_seal`,
    :meth:`evaluate_seal`, :meth:`evaluate_peer`) is additive.

    Example::

        trust = AttestedPeeringTrust(agent_id=AgentId("a1"), seed=b"s")
        rep = await trust.score(AgentId("a2"))
    """

    def __init__(
        self,
        identity: Any = None,
        *,
        agent_id: AgentId | None = None,
        seed: bytes = b"",
        policy: PeeringPolicy | None = None,
        rng: random.Random | None = None,
        label: str | None = None,
        principal_name: str = "",
        operator_seed: bytes | None = None,
        operator_delegation: tuple[str, bytes, bytes] | None = None,
        capabilities: tuple[str, ...] = (),
        offer_env: bool = False,
        measurements: dict[str, str] | None = None,
    ) -> None:
        self._identity = identity
        self._agent_id = agent_id or AgentId("unknown")
        self._seed = seed
        self._policy = policy or PeeringPolicy()
        aid_bytes = str(self._agent_id).encode("utf-8")
        self._rng = rng or random.Random(_sha256_hex(b"rng:" + seed + aid_bytes))

        self._priv = _derive_private_key(b"agent:" + seed + b":" + aid_bytes)
        self._pub = _public_raw(self._priv)
        self._offer_env = offer_env
        self._measurements = measurements or golden_measurements()
        self._ak_key = _derive_private_key(b"ak:" + seed + b":" + aid_bytes)

        self._operator_id = ""
        self._operator_pub = b""
        delegation_sig = b""
        card_label = label or str(self._agent_id)
        if operator_seed is not None:
            # Normal path: an operator we control signs the delegation for us.
            op_priv = _derive_private_key(b"operator:" + operator_seed)
            self._operator_pub = _public_raw(op_priv)
            self._operator_id = _fingerprint(self._operator_pub)
            delegation_sig = _sign(
                op_priv,
                _delegation_msg(self._operator_id, str(self._agent_id), card_label),
            )
        elif operator_delegation is not None:
            # Injection path: embed a delegation block issued out-of-band
            # (``operator_id``, ``operator_public_key``, ``signature``). The card
            # is still self-signed by *this* agent's key, so a peer that claims a
            # delegation it was never granted produces a self-consistent card
            # with an invalid ``delegation_signature`` — see ``_verify_card``.
            self._operator_id, self._operator_pub, delegation_sig = operator_delegation

        card = AgentFactsCard(
            agent_id=str(self._agent_id),
            label=card_label,
            public_key=self._pub,
            principal_name=principal_name or str(self._agent_id),
            operator_id=self._operator_id,
            operator_public_key=self._operator_pub,
            capabilities=capabilities,
            delegation_signature=delegation_sig,
        )
        self._card = replace(card, facts_signature=_sign(self._priv, _canon(card.body())))

        self._sessions: dict[AgentId, _Session] = {}
        self._pending_hail: dict[str, Any] | None = None
        self._attested: set[AgentId] = set()
        self._scores: dict[AgentId, list[float]] = {}
        self._quarantined: list[Evidence] = []
        self._stakes: dict[AgentId, int] = {}

    # -- passport / policy accessors ------------------------------------

    @property
    def card(self) -> AgentFactsCard:
        """This agent's signed passport.

        Example::

            wire = trust.card.to_dict()
        """
        return self._card

    @property
    def operator_id(self) -> str:
        """The operator id delegated to this agent (``""`` if self-asserted).

        Example::

            oid = trust.operator_id
        """
        return self._operator_id

    @property
    def operator_public_key(self) -> bytes:
        """The delegating operator's raw public key (``b""`` if none).

        Example::

            pub = trust.operator_public_key
        """
        return self._operator_pub

    def trust_operator(self, operator_id: str, operator_public_key: bytes) -> None:
        """Add an operator to this verifier's trusted-operator roster.

        Example::

            verifier.trust_operator(peer.operator_id, peer.operator_public_key)
        """
        self._policy.trusted_operators[operator_id] = operator_public_key

    def allow_boot_state(self, measurements: dict[str, str] | None = None) -> None:
        """Add a boot digest to the verifier's known-good allow-list.

        Example::

            verifier.allow_boot_state()  # trust the golden config
        """
        self._policy.known_good_boot.add(_boot_digest(measurements or golden_measurements()))

    # -- transcript / proofs --------------------------------------------

    def _nonce(self) -> bytes:
        """Draw a deterministic 16-byte nonce from the per-instance RNG."""
        return self._rng.randbytes(16)

    def _transcript(
        self,
        nonce_a: bytes,
        nonce_b: bytes,
        facts_a: AgentFactsCard,
        facts_b: AgentFactsCard,
    ) -> bytes:
        """Bytes both sides sign — binds key possession to *this* exchange.

        Signing the transcript (not a bare nonce) defeats splicing and cross
        session replay: it commits to both nonces and both passports.

        Example::

            t = trust._transcript(na, nb, card_a, card_b)
        """
        blob = {
            "proto": PROTO,
            "a": {"nonce": nonce_a.hex(), "id": facts_a.agent_id, "facts": facts_a.facts_hash()},
            "b": {"nonce": nonce_b.hex(), "id": facts_b.agent_id, "facts": facts_b.facts_hash()},
        }
        return HANDSHAKE_TAG + _canon(blob)

    def _proofs(self, transcript: bytes, peer_nonce: bytes) -> dict[str, Any]:
        """The proofs this side offers: transcript signature and optional env quote.

        Example::

            proofs = trust._proofs(transcript, peer_nonce)
        """
        proofs: dict[str, Any] = {"sig": _b64(_sign(self._priv, transcript))}
        if self._offer_env:
            proofs["env"] = _make_env_quote(self._ak_key, peer_nonce, self._measurements)
        return proofs

    # -- three-message handshake ----------------------------------------

    def make_hail(
        self,
        *,
        report_kind: str = "positive",
        present_card: AgentFactsCard | None = None,
    ) -> dict[str, Any]:
        """Open a handshake as the initiator: present a passport and a fresh nonce.

        ``present_card`` lets an adversary present *someone else's* passport
        (impersonation); the seal signature is still produced by this agent's
        own key, so key possession fails at the verifier. ``report_kind`` is
        the evidence this peer intends to file once admitted.

        Example::

            hail = trust.make_hail(report_kind="positive")
        """
        card = present_card or self._card
        nonce_a = self._nonce()
        self._pending_hail = {"nonce_a": nonce_a, "facts_a": card}
        return {
            "proto": PROTO,
            "op": "hail",
            "nonce": nonce_a.hex(),
            "report_kind": report_kind,
            "facts": card.to_dict(),
        }

    def make_vouch(self, hail: dict[str, Any], *, session_key: AgentId) -> dict[str, Any]:
        """Respond to a hail: prove *this* side over the transcript, store session.

        ``session_key`` is the transport-level peer the verifier is talking to
        (so a stolen passport is bound to the real sender, not the claimed id).

        Example::

            vouch = verifier.make_vouch(hail, session_key=AgentId("a1"))
        """
        nonce_a = _uhex(str(hail.get("nonce", "")))
        facts_a = AgentFactsCard.from_dict(hail.get("facts") or {})
        nonce_b = self._nonce()
        transcript = self._transcript(nonce_a, nonce_b, facts_a, self._card)
        proofs = self._proofs(transcript, nonce_a)
        self._sessions[session_key] = _Session(
            nonce_a=nonce_a,
            nonce_b=nonce_b,
            facts_a=facts_a,
            report_kind=str(hail.get("report_kind", "positive")),
        )
        return {
            "proto": PROTO,
            "op": "vouch",
            "nonce": nonce_b.hex(),
            "facts": self._card.to_dict(),
            **proofs,
        }

    def make_seal(self, vouch: dict[str, Any]) -> dict[str, Any]:
        """Close the handshake as the initiator: prove this side over the transcript.

        Example::

            seal = trust.make_seal(vouch)
        """
        if self._pending_hail is None:
            msg = "make_seal called before make_hail"
            raise RuntimeError(msg)
        nonce_a: bytes = self._pending_hail["nonce_a"]
        facts_a: AgentFactsCard = self._pending_hail["facts_a"]
        nonce_b = _uhex(str(vouch.get("nonce", "")))
        facts_b = AgentFactsCard.from_dict(vouch.get("facts") or {})
        transcript = self._transcript(nonce_a, nonce_b, facts_a, facts_b)
        proofs = self._proofs(transcript, nonce_b)
        return {"proto": PROTO, "op": "seal", **proofs}

    def session_report_kind(self, session_key: AgentId) -> str:
        """The evidence kind the peer declared in its hail.

        Example::

            kind = verifier.session_report_kind(AgentId("a1"))
        """
        session = self._sessions.get(session_key)
        return session.report_kind if session else "positive"

    # -- verification ---------------------------------------------------

    def evaluate_peer(
        self,
        peer_facts: AgentFactsCard,
        transcript: bytes,
        proofs: dict[str, Any],
        my_nonce: bytes,
    ) -> PeeringVerdict:
        """Judge a peer from its passport plus its three fresh proofs (pure).

        No I/O, no clock, no RNG. Answers friend-or-foe (authentic passport +
        transcript key possession + roster/TOFU), trust-my-data (optional env
        quote), and who-you-work-for (trusted-operator delegation).

        Example::

            verdict = verifier.evaluate_peer(card, transcript, proofs, nonce)
        """
        policy = self._policy

        # 1) FRIEND OR FOE — authentic passport AND key possession over session.
        authentic, auth_detail = _verify_card(peer_facts)
        possession = _verify(peer_facts.public_key, transcript, _ub64(str(proofs.get("sig", ""))))
        pid = peer_facts.agent_id
        known = policy.roster is None or pid in policy.roster or policy.tofu
        if not possession:
            foe_detail = "key possession NOT proven — bad transcript signature (impostor/replay)"
        elif not authentic:
            foe_detail = auth_detail
        elif not known:
            foe_detail = f"unknown peer {pid} — not on roster and TOFU is off"
        else:
            on_roster = bool(policy.roster and pid in policy.roster)
            seen = "known peer" if on_roster else "first contact (TOFU)"
            foe_detail = f"identity {pid} proven — {seen}"
        friend_or_foe = PeeringCheck(bool(possession and authentic and known), foe_detail)

        # 2) CAN I TRUST YOU WITH MY DATA — environment / boot attestation.
        env = proofs.get("env")
        if isinstance(env, dict):
            env_quote = cast("dict[str, Any]", env)
            env_ok, env_detail = _verify_env(env_quote, my_nonce, policy.known_good_boot)
        else:
            env_ok = not policy.require_env_quote
            env_detail = "no boot quote offered" + ("" if env_ok else " (policy requires one)")
        trust_my_data = PeeringCheck(bool(env_ok), env_detail)

        # 3) WHO DO YOU WORK FOR — operator delegation on the trusted roster.
        op_id = peer_facts.operator_id
        if policy.require_trusted_operator:
            if not op_id:
                work_ok, work_detail = False, "no operator delegation (self-asserted principal)"
            elif op_id not in policy.trusted_operators:
                work_ok, work_detail = False, f"operator {op_id} is not on your trusted roster"
            else:
                work_ok, work_detail = True, f"operator {op_id} delegated and trusted"
        else:
            work_ok = True
            work_detail = f"operator {op_id or '(none)'} — operator trust not required"
        who_you_work_for = PeeringCheck(
            bool(work_ok), f"'{peer_facts.principal_name}' — {work_detail}"
        )

        decision = (
            "ALLOW" if (friend_or_foe.ok and trust_my_data.ok and who_you_work_for.ok) else "DENY"
        )
        return PeeringVerdict(pid, friend_or_foe, trust_my_data, who_you_work_for, decision)

    def evaluate_seal(self, session_key: AgentId, seal: dict[str, Any]) -> PeeringVerdict:
        """Responder-side finish: judge the initiator from the seal it sent.

        On ``ALLOW`` the transport peer ``session_key`` is admitted to the
        attested set, so its subsequent :meth:`report` evidence counts.

        Example::

            verdict = verifier.evaluate_seal(AgentId("a1"), seal)
        """
        session = self._sessions.get(session_key)
        if session is None:
            deny = PeeringCheck(False, "no open handshake session for this peer")
            return PeeringVerdict(str(session_key), deny, deny, deny, "DENY")
        transcript = self._transcript(session.nonce_a, session.nonce_b, session.facts_a, self._card)
        verdict = self.evaluate_peer(session.facts_a, transcript, seal, session.nonce_b)
        if verdict.friend:
            self._attested.add(session_key)
        return verdict

    # -- Trust protocol (nest_core.layers.trust.Trust) ------------------

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation from *admitted* (attested-reporter) evidence only.

        Example::

            rep = await trust.score(AgentId("a2"))
        """
        entries = self._scores.get(agent, [])
        if not entries:
            return ReputationScore(agent_id=agent, score=0.5, confidence=0.0, sample_count=0)
        avg = sum(entries) / len(entries)
        confidence = min(1.0, len(entries) / 100.0)
        return ReputationScore(
            agent_id=agent, score=avg, confidence=confidence, sample_count=len(entries)
        )

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Sign a claim about an agent with this agent's identity key.

        Example::

            att = await trust.attest(AgentId("a2"), claim)
        """
        value = _sign(self._priv, claim.model_dump_json().encode("utf-8"))
        sig = Signature(signer=self._agent_id, value=value, algorithm=ALGORITHM)
        return Attestation(issuer=self._agent_id, claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Admit evidence only from attested reporters; quarantine the rest.

        Example::

            await trust.report(AgentId("victim"), evidence)
        """
        if evidence.reporter not in self._attested:
            self._quarantined.append(evidence)
            return
        score_val = 0.5
        if evidence.kind == "positive":
            score_val = 1.0
        elif evidence.kind in ("negative", "byzantine"):
            score_val = 0.0
        self._scores.setdefault(agent, []).append(score_val)

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake reputation on an agent.

        Example::

            await trust.stake(AgentId("a2"), 100)
        """
        self._stakes[agent] = self._stakes.get(agent, 0) + amount

    # -- introspection used by tests and validators ---------------------

    def is_attested(self, agent: AgentId) -> bool:
        """Whether *agent* cleared the handshake with an ALLOW verdict.

        Example::

            assert verifier.is_attested(AgentId("a1"))
        """
        return agent in self._attested

    @property
    def attested_peers(self) -> frozenset[AgentId]:
        """Peers whose handshake verdict was ALLOW.

        Example::

            assert AgentId("a1") in trust.attested_peers
        """
        return frozenset(self._attested)

    @property
    def quarantined_count(self) -> int:
        """How many evidence reports were rejected as coming from unattested peers.

        Example::

            assert trust.quarantined_count == 3
        """
        return len(self._quarantined)
