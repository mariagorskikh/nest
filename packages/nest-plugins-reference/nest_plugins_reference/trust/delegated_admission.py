# SPDX-License-Identifier: Apache-2.0
"""Delegated-admission trust plugin — gate evidence on live proof-of-human grants.

The two attestation-flavoured trust plugins already answer *"has this peer
proven itself right now?"* (:mod:`~nest_plugins_reference.trust.attested_peering`
runs a three-question mutual handshake per session). They do not answer the
adjacent question that a production federated node has to answer *before* it
lets a reporter file evidence at all: *"does this reporter hold a live,
unrevoked, appropriately-scoped delegation from a human principal — and is the
proof-of-human it dangled at us fresh?"*

This plugin is the Python port of the audited production model that lives in
the NANDA node's TypeScript source
(``nexartis-nanda-node/src/lib/server/delegation-grants.ts``). Evidence from a
reporter is admitted into reputation scoring iff **all** of the following
hold at the injected logical clock ``now_ms``:

1. The reporter is bound to a delegation grant in this trust's local store.
2. The grant is not revoked, not expired, and has not been transitively
   invalidated by a revoked/expired ancestor (chain check up to
   :data:`MAX_HOPS` deep; cycle-safe).
3. The grant's scope contains :attr:`AdmissionPolicy.required_scope`.
4. The grant carries a fresh :class:`PuhProof` whose canonical envelope hash
   matches byte-exactly and whose freshness bound is satisfied against
   ``now_ms`` (:data:`PUH_FRESHNESS_MS` with :data:`PUH_SKEW_MS` slack).
5. If :attr:`AdmissionPolicy.require_signed_puh` (the default — this Python
   port is intentionally stricter than the production toggle it derives
   from), the proof must additionally carry a valid Ed25519 signature by the
   principal's trusted public key over the canonical envelope bytes.

Everything else is *quarantined* with a stable machine-string reason so the
scenario's adversarial validators can red-team both the plugin and its
baseline (:mod:`~nest_plugins_reference.trust.score_average`). The
canonicalisation is byte-for-byte compatible with the production TS
``canonicalProofEnvelope`` — a fixed vector locks that in the test suite.

Determinism
-----------

Every observable output is a deterministic function of scenario inputs:

- **No wall clock.** All freshness comparisons use an injected
  ``now_ms`` (:meth:`DelegatedAdmissionTrust.set_clock`); nothing calls
  :func:`time.time` / :func:`time.monotonic` / :func:`datetime.now`.
- **No OS randomness.** Ed25519 seeds derive as ``sha256(seed)[:32]`` exactly
  like :mod:`~nest_plugins_reference.trust.attested_peering`. Ed25519 is
  RFC 8032 deterministic, so the same key over the same bytes always
  yields the same signature.
- **No network / subprocess / filesystem.** The delegation store is a
  per-instance in-memory :class:`dict`.
- **Deterministic delegation ids.** ``del-<hex>`` where the hex is
  ``sha256(canonical_envelope || counter.to_bytes(8,'big'))`` — a
  per-instance counter guarantees uniqueness across two grants with
  identical envelopes without touching a random source.

Provenance
----------

Ported from the production NANDA node source
``nexartis-nanda-node/src/lib/server/delegation-grants.ts`` (functions
``canonicalProofEnvelope``/``verifyPuhProof``/``grantDelegation``/
``revokeDelegation``/``checkDelegation``/``assertChainNarrowing``/
``collectDescendants``, together with the CRITICAL-3 ancestor-expiry
narrowing patch). A companion scenario + trace validators (added by a
sibling change) red-team the score-average baseline against this plugin.

Example::

    principal_id, principal_key = derive_principal(b"scenario-principal")
    policy = AdmissionPolicy(
        trusted_principals={principal_id: _public_raw(principal_key)},
        required_scope="trust.report",
    )
    trust = DelegatedAdmissionTrust(agent_id=AgentId("observer"), policy=policy)
    trust.set_clock(now_ms=1_000_000_000_000)

    subject = DelegationSubject(
        delegate_id="agent-1", granted_scope=("trust.report",),
        expires_at=1_000_100, parent_delegation_id=None, revocable=True,
    )
    envelope, proof = build_proof(principal_id, principal_key, subject, now_ms=trust.now_ms)
    verdict = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert verdict.ok
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal

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

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

ALGORITHM = "ed25519-delegated-admission/1"
"""Algorithm tag stamped on :meth:`DelegatedAdmissionTrust.attest` outputs.

Example::

    att = await trust.attest(AgentId("a1"), claim)
    assert att.signature.algorithm == ALGORITHM
"""

PUH_FRESHNESS_MS = 300_000
"""Maximum forward age of a proof-of-human, in milliseconds.

A ``bound_at`` older than ``now_ms - PUH_FRESHNESS_MS`` is stale — the human
must re-attest. Matches the TS constant of the same name.

Example::

    assert PUH_FRESHNESS_MS == 300_000
"""

PUH_SKEW_MS = 30_000
"""Allowed clock skew for proof-of-human freshness comparisons.

A ``bound_at`` slightly *ahead* of the observed ``now_ms`` (by at most this
many ms) is admissible; anything more is rejected as a forward-dated proof.

Example::

    assert PUH_SKEW_MS == 30_000
"""

MAX_HOPS = 32
"""Maximum parent-chain / descendant-tree depth explored during check/revoke.

Bounds worst-case work at 32 iterations and makes malformed graphs (cycles
or extreme chains) safe to serve without stack overflow. Matches the TS
constant of the same name.

Example::

    assert MAX_HOPS == 32
"""

_PRINCIPAL_ID_PREFIX = "pk-"
"""Prefix stamped on principal ids minted by :func:`derive_principal`.

Example::

    assert _PRINCIPAL_ID_PREFIX == "pk-"
"""

_PRINCIPAL_ID_HEX_LEN = 16
"""Hex-digit length of the principal id suffix (16 hex ≈ 64 bits of key handle).

Example::

    assert _PRINCIPAL_ID_HEX_LEN == 16
"""

_DELEGATION_ID_PREFIX = "del-"
"""Prefix stamped on delegation ids minted by :meth:`DelegatedAdmissionTrust._next_delegation_id`.

Example::

    assert _DELEGATION_ID_PREFIX == "del-"
"""

_DELEGATION_ID_HEX_LEN = 24
"""Hex-digit length of the delegation id suffix (24 hex ≈ 96 bits).

Example::

    assert _DELEGATION_ID_HEX_LEN == 24
"""


# ---------------------------------------------------------------------------
# Low-level helpers (pure, deterministic; never raise on adversarial input)
# ---------------------------------------------------------------------------


def _derive_private_key(seed: bytes) -> Ed25519PrivateKey:
    """Derive a deterministic Ed25519 private key from arbitrary seed bytes.

    The 32-byte scalar is ``sha256(seed)[:32]``; the same seed always yields
    the same key. Matches the derivation used by attested_peering so the
    two plugins interoperate under a single scenario seed.

    Example::

        key = _derive_private_key(b"principal:test")
    """
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest()[:32])


def _public_raw(priv: Ed25519PrivateKey) -> bytes:
    """Return the 32-byte raw public key for a private key.

    Example::

        pub = _public_raw(_derive_private_key(b"s"))
        assert len(pub) == 32
    """
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(priv: Ed25519PrivateKey, msg: bytes) -> bytes:
    """Ed25519-sign *msg* with *priv* (deterministic per RFC 8032).

    Example::

        sig = _sign(_derive_private_key(b"s"), b"m")
    """
    return priv.sign(msg)


def _verify_sig(pub_raw: bytes, msg: bytes, sig: bytes) -> bool:
    """Return whether *sig* is a valid Ed25519 signature by *pub_raw* on *msg*.

    Never raises on malformed keys / signatures — an adversarial input
    simply returns ``False`` so the caller can emit a clean rejection reason.

    Example::

        priv = _derive_private_key(b"s")
        assert _verify_sig(_public_raw(priv), b"m", _sign(priv, b"m"))
        assert not _verify_sig(b"", b"m", b"")
    """
    if not pub_raw or not sig:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
    except (InvalidSignature, ValueError):
        return False
    return True


def derive_principal(seed: bytes) -> tuple[str, Ed25519PrivateKey]:
    """Deterministically derive a ``(principal_id, private_key)`` pair from a seed.

    ``principal_id`` is the string that appears as ``principalPk`` inside the
    canonical envelope — a stable ``pk-<16 hex>`` handle derived from the
    raw public key so trust configuration only ever carries opaque strings.
    The private key is what a test fixture uses to
    :func:`sign_proof_envelope` a :class:`PuhProof`.

    Example::

        pid, priv = derive_principal(b"scenario:principal")
        assert pid.startswith("pk-")
    """
    priv = _derive_private_key(seed)
    pub = _public_raw(priv)
    principal_id = _PRINCIPAL_ID_PREFIX + hashlib.sha256(pub).hexdigest()[:_PRINCIPAL_ID_HEX_LEN]
    return principal_id, priv


def sign_proof_envelope(priv: Ed25519PrivateKey, envelope: bytes) -> bytes:
    """Sign the canonical envelope bytes with a principal's private key.

    Public helper so scenario factories and tests can mint valid PuhProof
    signatures without importing the private ``_sign`` helper.

    Example::

        sig = sign_proof_envelope(priv, canonical_proof_envelope(proof, subject))
    """
    return _sign(priv, envelope)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PuhProof:
    """A frozen record of a proof-of-human bound to a delegation request.

    Fields mirror the TS ``PuhProof`` type exactly. Timestamps are
    **milliseconds** (matching the JS wall-clock convention the production
    node uses); the trust plugin's clock (:meth:`DelegatedAdmissionTrust
    .set_clock`) also takes milliseconds.

    Example::

        proof = PuhProof(
            principal_pk="pk-abcd1234abcd1234", device_did="did:key:z6Mk",
            request_id="req-01", bound_at_ms=1_700_000_000_000,
            issued_at_ms=1_700_000_001_000, signature=None,
        )
    """

    principal_pk: str
    device_did: str
    request_id: str
    bound_at_ms: int
    issued_at_ms: int
    signature: bytes | None = None


@dataclass(frozen=True)
class DelegationSubject:
    """The subject of a delegation grant — what is being delegated, to whom.

    Kept structurally identical to the TS ``subject`` argument to
    ``canonicalProofEnvelope``. ``expires_at`` is **unix seconds**
    (production TTL is coarse), ``parent_delegation_id`` is ``None`` for a
    root grant and never omitted from the canonicalisation.

    Example::

        subject = DelegationSubject(
            delegate_id="agent-1", granted_scope=("tool.echo", "tool.summarize"),
            expires_at=1_000_000_000, parent_delegation_id=None, revocable=True,
        )
    """

    delegate_id: str
    granted_scope: tuple[str, ...]
    expires_at: int
    parent_delegation_id: str | None = None
    revocable: bool = True


@dataclass(frozen=True)
class AdmissionPolicy:
    """Verifier-side policy consumed by :class:`DelegatedAdmissionTrust`.

    ``trusted_principals`` maps a principal id (as it appears in
    :attr:`PuhProof.principal_pk`) to the raw 32-byte Ed25519 public key we
    require signatures to verify against. ``required_scope`` is the scope
    string a grant must contain for its holder's evidence to be admitted.

    Example::

        pid, priv = derive_principal(b"seed")
        policy = AdmissionPolicy(
            trusted_principals={pid: _public_raw(priv)},
            required_scope="trust.report",
        )
    """

    trusted_principals: dict[str, bytes] = field(default_factory=dict[str, bytes])
    require_signed_puh: bool = True
    puh_freshness_ms: int = PUH_FRESHNESS_MS
    puh_skew_ms: int = PUH_SKEW_MS
    required_scope: str = "trust.report"


@dataclass(frozen=True)
class AdmissionVerdict:
    """Outcome of an admission check on a single :class:`Evidence` report.

    ``reason`` is one of a small closed set of stable machine strings so the
    scenario's validators can gate on it byte-for-byte.

    Example::

        v = trust.last_verdict(AgentId("a1"))
        assert v is not None and v.reason == "admitted"
    """

    admitted: bool
    reason: str
    delegation_id: str | None = None


@dataclass(frozen=True)
class GrantResult:
    """Result of :meth:`DelegatedAdmissionTrust.grant`.

    On success ``ok`` is ``True`` and ``delegation_id`` is the id assigned to
    the new grant; on failure ``ok`` is ``False`` and ``reason`` names the
    stable rejection code.

    Example::

        r = trust.grant(subject, proof, granted_by_proof_hash=h)
        if r.ok: use(r.delegation_id)
    """

    ok: bool
    reason: str
    delegation_id: str | None = None


@dataclass(frozen=True)
class RevokeResult:
    """Result of :meth:`DelegatedAdmissionTrust.revoke` (idempotent).

    ``cascaded`` includes the target itself and every descendant that
    transitioned from ``granted`` to ``revoked`` on this call. A repeated
    revoke returns an empty tuple with ``ok=True``.

    Example::

        r = trust.revoke(delegation_id)
        assert r.ok
    """

    ok: bool
    reason: str
    cascaded: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckResult:
    """Result of :meth:`DelegatedAdmissionTrust.check`.

    ``expires_at_effective`` reflects the CRITICAL-3 narrowing behaviour:
    when a nearer ancestor's expiry is earlier than the target's, this
    result surfaces the ancestor's expiry rather than the target's own.

    Example::

        c = trust.check(delegation_id)
        assert c.valid
    """

    valid: bool
    revoked: bool
    expired: bool
    expires_at_effective: int
    reason: str


# ---------------------------------------------------------------------------
# Canonicalisation (byte-exact port of TS canonicalProofEnvelope)
# ---------------------------------------------------------------------------


def canonical_proof_envelope(proof: PuhProof, subject: DelegationSubject) -> bytes:
    """Serialise a ``(proof, subject)`` pair to the exact bytes the TS node hashes.

    Field order is fixed by insertion (**never** sorted); ``toolNames`` are
    trimmed, dropped if empty or non-string, and sorted alphabetically;
    ``parentDelegationId=None`` serialises to JSON ``null`` and is never
    omitted. The encoded string matches production byte-for-byte — a fixed
    test vector locks that invariant.

    Example::

        subject = DelegationSubject(
            delegate_id="agent-delegate-1",
            granted_scope=("tool.echo", "tool.summarize"),
            expires_at=1000000000, parent_delegation_id=None, revocable=True,
        )
        proof = PuhProof(
            principal_pk="yz-principal-01", device_did="did:key:z6Mkdevice",
            request_id="yz-req-01", bound_at_ms=0, issued_at_ms=999500000,
        )
        blob = canonical_proof_envelope(proof, subject)
        assert blob.startswith(b'{"principalPk":"yz-principal-01"')
    """
    tool_names = sorted(
        s.strip()
        for s in subject.granted_scope
        # Defensive: the type says ``tuple[str, ...]`` but wire input via a
        # scenario factory can smuggle non-strings; drop them cleanly rather
        # than raising ``AttributeError`` on ``.strip``.
        if isinstance(s, str) and s.strip()  # pyright: ignore[reportUnnecessaryIsInstance]
    )
    envelope: dict[str, Any] = {
        "principalPk": proof.principal_pk,
        "deviceDid": proof.device_did,
        "requestId": proof.request_id,
        "grantee": subject.delegate_id,
        "scope": {"toolNames": tool_names},
        "expiresAt": subject.expires_at,
        "parentDelegationId": subject.parent_delegation_id,
        "revocable": subject.revocable,
        "issuedAt": proof.issued_at_ms,
    }
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def envelope_hash(envelope: bytes) -> str:
    """Lowercase hex SHA-256 of a canonical envelope — the ``granted_by_proof_hash``.

    Example::

        h = envelope_hash(canonical_proof_envelope(proof, subject))
        assert len(h) == 64
    """
    return hashlib.sha256(envelope).hexdigest()


def build_proof(
    principal_id: str,
    principal_key: Ed25519PrivateKey,
    subject: DelegationSubject,
    *,
    now_ms: int,
    device_did: str = "did:key:z6MkFixture",
    request_id: str = "req-fixture",
    signed: bool = True,
) -> tuple[bytes, PuhProof]:
    """Test/scenario helper: build a valid signed :class:`PuhProof` and its envelope.

    Returns ``(canonical_envelope_bytes, proof)`` so callers can compute the
    hash and hand both to :meth:`DelegatedAdmissionTrust.grant`. This is
    scenario glue — real callers construct proofs from live human input.

    Example::

        env, proof = build_proof(pid, priv, subject, now_ms=1_700_000_000_000)
        h = envelope_hash(env)
    """
    proof_unsigned = PuhProof(
        principal_pk=principal_id,
        device_did=device_did,
        request_id=request_id,
        bound_at_ms=now_ms,
        issued_at_ms=now_ms,
        signature=None,
    )
    envelope = canonical_proof_envelope(proof_unsigned, subject)
    signature = _sign(principal_key, envelope) if signed else None
    return envelope, PuhProof(
        principal_pk=principal_id,
        device_did=device_did,
        request_id=request_id,
        bound_at_ms=now_ms,
        issued_at_ms=now_ms,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Internal grant record
# ---------------------------------------------------------------------------


@dataclass
class _Grant:
    """Internal mutable delegation record — private to the plugin."""

    delegation_id: str
    # retained for parity with the TS grant row; not read by admission logic
    delegator_id: str
    delegate_id: str
    granted_scope: tuple[str, ...]
    expires_at: int
    parent_delegation_id: str | None
    revocable: bool
    granted_by_proof_hash: str
    proof: PuhProof
    status: Literal["granted", "revoked"] = "granted"
    revoked_at_ms: int | None = None


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class DelegatedAdmissionTrust:
    """Trust plugin: admit evidence iff the reporter holds a live delegation grant.

    Implements the :class:`nest_core.layers.trust.Trust` protocol
    (:meth:`score`, :meth:`attest`, :meth:`report`, :meth:`stake`). The
    handshake / grant surface (:meth:`grant`, :meth:`revoke`, :meth:`check`,
    :meth:`set_clock`) is additive. The constructor accepts an ``identity``
    positional and ignores it for compatibility with
    :class:`~nest_plugins_reference.trust.score_average.ScoreAverageTrust`.

    Example::

        trust = DelegatedAdmissionTrust(agent_id=AgentId("observer"))
        trust.set_clock(1_700_000_000_000)
        # ...seed grants, then...
        await trust.report(AgentId("victim"), evidence)
        rep = await trust.score(AgentId("victim"))
    """

    def __init__(
        self,
        identity: Any = None,
        *,
        agent_id: AgentId | None = None,
        seed: bytes = b"",
        policy: AdmissionPolicy | None = None,
        delegator_id: str = "self",
    ) -> None:
        self._identity = identity
        self._agent_id = agent_id or AgentId("unknown")
        self._seed = seed
        self._policy = policy or AdmissionPolicy()
        self._delegator_id = delegator_id

        aid_bytes = str(self._agent_id).encode("utf-8")
        self._priv = _derive_private_key(b"delegated-admission:" + seed + b":" + aid_bytes)

        # Grants indexed two ways: by their id, and by their delegate_id
        # (the reporter AgentId string) -> latest granted id, which is what
        # `report()` consults per the module docstring's admission flow.
        self._grants: dict[str, _Grant] = {}
        self._delegate_index: dict[str, str] = {}
        self._grant_counter: int = 0

        # Trust protocol state — same shape as score_average.
        self._scores: dict[AgentId, list[float]] = {}
        self._stakes: dict[AgentId, int] = {}
        self._quarantined: list[Evidence] = []
        self._admitted_count: int = 0
        self._verdicts: dict[AgentId, AdmissionVerdict] = {}

        # Logical clock in **milliseconds**. Callers must set it before
        # issuing a grant or reporting; the default 0 corresponds to
        # "epoch" and rejects every real-world dated proof as stale.
        self._now_ms: int = 0

    # -- clock -----------------------------------------------------------

    def set_clock(self, now_ms: int | float) -> None:
        """Advance the plugin's logical clock (never a wall clock).

        Rounded down to an integer millisecond — production code passes
        integer ms and the scenario runner likewise; a float argument is
        tolerated for parity with the failure-detector clock API.

        Example::

            trust.set_clock(1_700_000_000_000)
        """
        self._now_ms = int(now_ms)

    @property
    def now_s(self) -> int:
        """Current logical clock in seconds (integer, floor-divided).

        Example::

            trust.set_clock(10_000)
            assert trust.now_s == 10
        """
        return self._now_ms // 1000

    # -- policy accessors -----------------------------------------------

    @property
    def policy(self) -> AdmissionPolicy:
        """The admission policy this plugin was constructed with.

        Example::

            assert trust.policy.required_scope == "trust.report"
        """
        return self._policy

    def trust_principal(self, principal_id: str, public_key: bytes) -> None:
        """Add / replace a trusted principal → public key binding.

        Convenience for tests and scenario factories; the same effect is
        achievable by passing ``AdmissionPolicy(trusted_principals=...)``.

        Example::

            trust.trust_principal(pid, _public_raw(priv))
        """
        self._policy.trusted_principals[principal_id] = public_key

    # -- PuhProof verification (port of verifyPuhProof) -----------------

    def _verify_puh(
        self,
        proof: Any,
        subject: DelegationSubject,
        granted_by_proof_hash: str | None,
    ) -> tuple[bool, str, str, bytes]:
        """Verify a PuhProof at the current clock.

        Returns ``(ok, reason, envelope_hash_used, envelope_bytes)``. On any
        early rejection ``envelope_bytes`` is ``b""``; from the hash step
        onwards it is the canonical envelope bytes so callers (e.g.
        :meth:`grant`) can reuse them without re-serialising. ``reason`` is
        one of the stable strings ``missing-proof``, ``invalid-proof``,
        ``puh-proof-stale``, ``missing-proof-hash``, ``proof-hash-mismatch``,
        ``unknown-principal``, ``missing-signature``, ``bad-signature``.

        Example::

            ok, reason, h, env = trust._verify_puh(proof, subject, hash_or_None)
        """
        # 1. Field validity. ``proof`` is typed as ``Any`` because a
        # byzantine wire path (or a test) can hand us anything at all; we
        # never raise, we classify.
        if proof is None:
            return False, "missing-proof", "", b""
        if not isinstance(proof, PuhProof):
            return False, "invalid-proof", "", b""
        for field_val in (proof.principal_pk, proof.device_did, proof.request_id):
            if not field_val:
                return False, "invalid-proof", "", b""

        # 2. Freshness against the injected clock.
        now = self._now_ms
        skew = self._policy.puh_skew_ms
        freshness = self._policy.puh_freshness_ms
        delta_bound = now - proof.bound_at_ms
        delta_issued = now - proof.issued_at_ms
        if delta_bound < -skew or delta_bound > freshness:
            return False, "puh-proof-stale", "", b""
        if delta_issued < -skew or delta_issued > freshness:
            return False, "puh-proof-stale", "", b""
        if proof.issued_at_ms < proof.bound_at_ms - skew:
            # Ordering violation is a malformed proof, not a stale one --
            # mirrors the production verifier, which rejects this case with
            # ``invalid-proof`` (delegation-grants.ts, verifyPuhProof).
            return False, "invalid-proof", "", b""

        # 3. Envelope hash byte-for-byte.
        envelope = canonical_proof_envelope(proof, subject)
        computed_hash = envelope_hash(envelope)
        if not granted_by_proof_hash:
            return False, "missing-proof-hash", computed_hash, envelope
        if granted_by_proof_hash != computed_hash:
            return False, "proof-hash-mismatch", computed_hash, envelope

        # 4. Principal recognised.
        pub = self._policy.trusted_principals.get(proof.principal_pk)
        if pub is None:
            return False, "unknown-principal", computed_hash, envelope

        # 5. Signature — required by policy, or verified when present.
        if proof.signature is None:
            if self._policy.require_signed_puh:
                return False, "missing-signature", computed_hash, envelope
        elif not _verify_sig(pub, envelope, bytes(proof.signature)):
            return False, "bad-signature", computed_hash, envelope

        return True, "ok", computed_hash, envelope

    # -- grant / revoke / check -----------------------------------------

    def _next_delegation_id(self, envelope: bytes) -> str:
        """Deterministically mint a new delegation id (no randomness)."""
        self._grant_counter += 1
        seed = envelope + self._grant_counter.to_bytes(8, "big")
        return _DELEGATION_ID_PREFIX + hashlib.sha256(seed).hexdigest()[:_DELEGATION_ID_HEX_LEN]

    def _check_chain_narrowing(self, parent: _Grant, subject: DelegationSubject) -> str | None:
        """Enforce parent-narrowing invariants; return a rejection reason or ``None``.

        Ports the TS ``assertChainNarrowing`` checks: a child may not add
        scope its parent lacks, live longer than its parent, or flip a
        revocable parent to irrevocable.

        Example::

            reason = self._check_chain_narrowing(parent, subject)
            if reason is not None: return GrantResult(ok=False, reason=reason)
        """
        parent_scope = set(parent.granted_scope)
        if not set(subject.granted_scope).issubset(parent_scope):
            return "scope-widens-parent"
        if subject.expires_at > parent.expires_at:
            return "ttl-widens-parent"
        if parent.revocable and not subject.revocable:
            return "revocable-flip-forbidden"
        return None

    def _ancestor_depth(self, grant: _Grant) -> int:
        """Count the ancestors above ``grant`` (cycle-safe, unbounded).

        Used at mint time to keep every chain shallow enough that the
        bounded revocation cascade and ancestor walk provably cover it.

        Example::

            depth = self._ancestor_depth(parent)  # 0 for a root grant
        """
        depth = 0
        seen: set[str] = set()
        cursor = grant.parent_delegation_id
        while cursor is not None and cursor not in seen:
            seen.add(cursor)
            ancestor = self._grants.get(cursor)
            if ancestor is None:
                break
            depth += 1
            cursor = ancestor.parent_delegation_id
        return depth

    def grant(
        self,
        subject: DelegationSubject,
        proof: PuhProof,
        *,
        granted_by_proof_hash: str | None,
    ) -> GrantResult:
        """Issue a new delegation grant after validating scope, TTL, proof, chain.

        On success the reporter identified by ``subject.delegate_id`` is
        auto-indexed as the holder of this grant (the newest issued grant
        wins on collisions). On failure nothing mutates.

        Chains are capped at :data:`MAX_HOPS` ancestors at mint time
        (``chain-too-deep``) so the bounded revocation cascade and the
        ``check()`` ancestor walk always cover every legal chain — the
        production TS source bounds both walks but not mint depth, which
        fails open past twice the bound; we close that (stricter,
        disclosed in VERIFICATION.md).

        Rejection reasons (stable strings): ``empty-scope``,
        ``expired-at-grant``, any :meth:`_verify_puh` reason,
        ``parent-not-found``, ``parent-revoked``, ``chain-too-deep``,
        ``scope-widens-parent``, ``ttl-widens-parent``,
        ``revocable-flip-forbidden``.

        Example::

            r = trust.grant(subject, proof, granted_by_proof_hash=h)
            assert r.ok
        """
        # 1. Non-empty scope after normalisation (defensively drops
        # non-string entries — see :func:`canonical_proof_envelope`).
        norm_scope = tuple(
            sorted(
                s.strip()
                for s in subject.granted_scope
                if isinstance(s, str)  # pyright: ignore[reportUnnecessaryIsInstance]
                and s.strip()
            )
        )
        if not norm_scope:
            return GrantResult(ok=False, reason="empty-scope")

        # Re-canonicalise on the normalised subject so hash comparison uses
        # the same shape callers already computed.
        normalised = DelegationSubject(
            delegate_id=subject.delegate_id,
            granted_scope=norm_scope,
            expires_at=subject.expires_at,
            parent_delegation_id=subject.parent_delegation_id,
            revocable=subject.revocable,
        )

        # 2. Not already expired (compare seconds, matching TS behaviour).
        if subject.expires_at <= self.now_s:
            return GrantResult(ok=False, reason="expired-at-grant")

        # 3. Proof verification (freshness + envelope + signature).
        ok, reason, computed_hash, envelope = self._verify_puh(
            proof, normalised, granted_by_proof_hash
        )
        if not ok:
            return GrantResult(ok=False, reason=reason)

        # 4. Chain narrowing (only when a parent is claimed).
        if subject.parent_delegation_id is not None:
            parent = self._grants.get(subject.parent_delegation_id)
            if parent is None:
                return GrantResult(ok=False, reason="parent-not-found")
            if parent.status == "revoked":
                return GrantResult(ok=False, reason="parent-revoked")
            # Fail closed on depth: the new grant would have
            # ``_ancestor_depth(parent) + 1`` ancestors; past MAX_HOPS the
            # bounded cascade/ancestor walks could no longer cover it.
            if self._ancestor_depth(parent) + 1 > MAX_HOPS:
                return GrantResult(ok=False, reason="chain-too-deep")
            narrowing_reason = self._check_chain_narrowing(parent, normalised)
            if narrowing_reason is not None:
                return GrantResult(ok=False, reason=narrowing_reason)

        # 5. Assign a deterministic id and commit — reuse the envelope
        # bytes/hash already produced by ``_verify_puh`` (no double hash).
        delegation_id = self._next_delegation_id(envelope)
        record = _Grant(
            delegation_id=delegation_id,
            delegator_id=self._delegator_id,
            delegate_id=subject.delegate_id,
            granted_scope=norm_scope,
            expires_at=subject.expires_at,
            parent_delegation_id=subject.parent_delegation_id,
            revocable=subject.revocable,
            granted_by_proof_hash=computed_hash,
            proof=proof,
        )
        self._grants[delegation_id] = record
        self._delegate_index[subject.delegate_id] = delegation_id
        return GrantResult(ok=True, reason="granted", delegation_id=delegation_id)

    def _collect_descendants(self, root_id: str) -> list[str]:
        """BFS descendants of a grant, cycle-safe, bounded by :data:`MAX_HOPS`."""
        # Adjacency: parent_id -> list of child ids. Build once per call
        # (grants collection is small in practice and this keeps mutation
        # locality tight).
        children: dict[str, list[str]] = {}
        for gid, g in self._grants.items():
            if g.parent_delegation_id is not None:
                children.setdefault(g.parent_delegation_id, []).append(gid)

        seen: set[str] = {root_id}
        out: list[str] = []
        queue: deque[tuple[str, int]] = deque([(root_id, 0)])
        while queue:
            node, depth = queue.popleft()
            if depth >= MAX_HOPS:
                continue
            for child in children.get(node, ()):
                if child in seen:
                    continue
                seen.add(child)
                out.append(child)
                queue.append((child, depth + 1))
        return out

    def revoke(self, delegation_id: str) -> RevokeResult:
        """Revoke a delegation and cascade to every descendant (idempotent).

        Repeated revocation returns ``ok=True`` with empty ``cascaded`` — no
        error, no double-transition. Cycles in the parent graph (which
        should never form on happy paths but are defensively tolerated) are
        broken by the ``seen`` set inside :meth:`_collect_descendants`.

        Example::

            r = trust.revoke(delegation_id)
            assert r.ok
        """
        target = self._grants.get(delegation_id)
        if target is None:
            return RevokeResult(ok=False, reason="not-found")
        if target.status == "revoked":
            return RevokeResult(ok=True, reason="already-revoked", cascaded=())

        cascaded: list[str] = [delegation_id]
        cascaded.extend(self._collect_descendants(delegation_id))

        for gid in cascaded:
            g = self._grants[gid]
            if g.status != "revoked":
                g.status = "revoked"
                g.revoked_at_ms = self._now_ms
                # If this delegate's currently-indexed grant is the one
                # being revoked, clear the index so `report()` sees no
                # live grant on the next call.
                if self._delegate_index.get(g.delegate_id) == gid:
                    del self._delegate_index[g.delegate_id]
        return RevokeResult(ok=True, reason="revoked", cascaded=tuple(cascaded))

    def check(self, delegation_id: str) -> CheckResult:
        """Compute the effective validity of a grant at the current clock.

        Walks the parent chain up to :data:`MAX_HOPS` deep with a seen-set.
        A revoked ancestor makes the grant revoked; an expired ancestor
        makes it expired and narrows :attr:`CheckResult.expires_at_effective`
        to the ancestor's earlier bound (the production CRITICAL-3 patch).

        Example::

            c = trust.check(delegation_id)
            assert c.valid or c.revoked or c.expired
        """
        target = self._grants.get(delegation_id)
        if target is None:
            return CheckResult(
                valid=False,
                revoked=False,
                expired=False,
                expires_at_effective=0,
                reason="not-found",
            )

        revoked = target.status == "revoked"
        effective_expiry = target.expires_at

        # Ancestor walk.
        seen: set[str] = {target.delegation_id}
        current: str | None = target.parent_delegation_id
        for _ in range(MAX_HOPS):
            if current is None or current in seen:
                # Cycle guard — treat as a break, matching TS behaviour.
                break
            seen.add(current)
            ancestor = self._grants.get(current)
            if ancestor is None:
                break
            if ancestor.status == "revoked":
                revoked = True
            if ancestor.expires_at < effective_expiry:
                effective_expiry = ancestor.expires_at
            current = ancestor.parent_delegation_id

        expired = (not revoked) and self.now_s >= effective_expiry
        valid = not revoked and not expired
        if revoked:
            reason = "revoked"
        elif expired:
            reason = "expired"
        else:
            reason = "valid"
        return CheckResult(
            valid=valid,
            revoked=revoked,
            expired=expired,
            expires_at_effective=effective_expiry,
            reason=reason,
        )

    # -- Trust protocol -------------------------------------------------

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation from *admitted* evidence only — same shape as score_average.

        Example::

            rep = await trust.score(AgentId("a1"))
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
        """Sign a claim about an agent with this plugin's identity key.

        Example::

            att = await trust.attest(AgentId("a2"), claim)
        """
        _ = agent  # `agent` is the subject inside `claim`; kept in signature for the Protocol.
        value = _sign(self._priv, claim.model_dump_json().encode("utf-8"))
        sig = Signature(signer=self._agent_id, value=value, algorithm=ALGORITHM)
        return Attestation(issuer=self._agent_id, claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Admit evidence iff the reporter holds a live, in-scope, fresh grant.

        Defensive: never raises. Every rejection appends to the quarantine
        list with a stable machine reason recorded in
        :meth:`last_verdict`; admitted evidence contributes a score in the
        same way as :mod:`~nest_plugins_reference.trust.score_average`.

        Example::

            await trust.report(AgentId("victim"), evidence)
        """
        verdict = self._evaluate(evidence)
        # ``_evaluate`` is the single defense layer for objects that lack a
        # ``reporter`` attribute; if it returned a verdict, we know the
        # attribute access below succeeded there and will succeed here.
        reporter = evidence.reporter
        self._verdicts[reporter] = verdict

        if not verdict.admitted:
            self._quarantined.append(evidence)
            return

        self._admitted_count += 1
        score_val = 0.5
        if evidence.kind == "positive":
            score_val = 1.0
        elif evidence.kind in ("negative", "byzantine"):
            score_val = 0.0
        self._scores.setdefault(agent, []).append(score_val)

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake reputation on an agent (delegates to the same ledger as the baseline).

        Example::

            await trust.stake(AgentId("a1"), 100)
        """
        self._stakes[agent] = self._stakes.get(agent, 0) + amount

    # -- introspection --------------------------------------------------

    def _evaluate(self, evidence: Evidence) -> AdmissionVerdict:
        """Return an :class:`AdmissionVerdict` for *evidence*; never raises."""
        try:
            reporter_str = str(evidence.reporter)
        except (AttributeError, TypeError):
            return AdmissionVerdict(admitted=False, reason="malformed-evidence")

        delegation_id = self._delegate_index.get(reporter_str)
        if delegation_id is None:
            return AdmissionVerdict(admitted=False, reason="no-grant")

        grant = self._grants.get(delegation_id)
        if grant is None:  # pragma: no cover — index is kept in sync
            return AdmissionVerdict(admitted=False, reason="no-grant", delegation_id=delegation_id)

        check = self.check(delegation_id)
        if check.revoked:
            return AdmissionVerdict(admitted=False, reason="revoked", delegation_id=delegation_id)
        if check.expired:
            return AdmissionVerdict(admitted=False, reason="expired", delegation_id=delegation_id)

        if self._policy.required_scope not in grant.granted_scope:
            return AdmissionVerdict(
                admitted=False, reason="scope-mismatch", delegation_id=delegation_id
            )

        # Re-verify the stored proof against the *current* clock — a proof
        # that was fresh at grant time may have aged out by the time evidence
        # is filed.
        subject = DelegationSubject(
            delegate_id=grant.delegate_id,
            granted_scope=grant.granted_scope,
            expires_at=grant.expires_at,
            parent_delegation_id=grant.parent_delegation_id,
            revocable=grant.revocable,
        )
        ok, reason, _, _ = self._verify_puh(grant.proof, subject, grant.granted_by_proof_hash)
        if not ok:
            return AdmissionVerdict(admitted=False, reason=reason, delegation_id=delegation_id)

        return AdmissionVerdict(admitted=True, reason="admitted", delegation_id=delegation_id)

    def last_verdict(self, reporter: AgentId) -> AdmissionVerdict | None:
        """The verdict from the most recent :meth:`report` for *reporter*.

        Returns ``None`` if this reporter has never been evaluated. Used by
        scenario trace validators to gate on stable rejection reasons.

        Example::

            v = trust.last_verdict(AgentId("a1"))
            if v: assert v.reason in ("admitted", "no-grant", "revoked")
        """
        return self._verdicts.get(reporter)

    @property
    def quarantined_count(self) -> int:
        """How many evidence reports have been quarantined so far.

        Example::

            assert trust.quarantined_count >= 0
        """
        return len(self._quarantined)

    @property
    def admitted_count(self) -> int:
        """How many evidence reports have been admitted so far.

        Example::

            assert trust.admitted_count >= 0
        """
        return self._admitted_count
