# SPDX-License-Identifier: Apache-2.0
"""Example-based + adversarial tests for the ``trust_gated`` privacy plugin.

Three layers of coverage (mirrors the ``hybrid_x25519`` test structure):

1. **Disclosure tiers** — full plaintext for high trust, a redacted
   selectively-disclosed view (with a *verifiable* Merkle proof) for medium
   trust, a signed denial receipt for low trust, and inclusive threshold
   boundaries.
2. **Discrimination** — the gate invariant ("a low-trust audience member must
   not recover the plaintext") FAILS against ``noop`` *and* against
   ``hybrid_x25519`` (which is deliberately trust-blind), and PASSES only
   against ``trust_gated``. This is the charter's bar: a check the existing
   reference plugins cannot satisfy.
3. **Byzantine behaviour** — poisoned trust scores (NaN/inf/out-of-range)
   fail closed; gate-table tampering, tier-blob swapping, forged denial
   receipts, and replay are all rejected; envelopes stay byte-deterministic.

Example::

    pytest packages/nest-plugins-reference/tests/test_trust_gated.py
"""

from __future__ import annotations

import base64
import json
import math
from typing import Any, cast

import pytest
from nest_core.layers.privacy import Privacy
from nest_core.plugins import PluginRegistry
from nest_core.types import (
    AgentId,
    AgentIdentity,
    Attestation,
    Claim,
    Evidence,
    Proof,
    ReputationScore,
    Signature,
    Statement,
)
from nest_plugins_reference.privacy.hybrid_x25519 import (
    PROOF_SCHEME,
    HybridX25519Privacy,
    MalformedEnvelopeError,
    NotInAudienceError,
    ReplayError,
    TamperError,
)
from nest_plugins_reference.privacy.noop import NoopPrivacy
from nest_plugins_reference.privacy.trust_gated import (
    DENIAL_SCHEME,
    DISCLOSURE_PREDICATE,
    PARTIAL_SCHEME,
    TierPolicy,
    TrustDeniedError,
    TrustGatedPrivacy,
)
from nest_plugins_reference.trust.score_average import ScoreAverageTrust
from nest_plugins_reference.validators import (
    check_denial_receipt_auditable,
    check_gate_tamper_rejected,
    check_low_trust_blocked,
    check_partial_redaction_enforced,
)

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

_HIDDEN_1 = "250000"
_HIDDEN_2 = "123-45-6789"
_PAYLOAD_FIELDS = {"dept": "finance", "region": "EU", "salary": _HIDDEN_1, "ssn": _HIDDEN_2}
_PAYLOAD = json.dumps(_PAYLOAD_FIELDS, sort_keys=True).encode("utf-8")
_REVEAL = frozenset({"dept", "region"})


class StaticTrust:
    """Trust stub returning preset scores (default 0.5); the other protocol
    methods are inert. Deterministic by construction."""

    def __init__(self, scores: dict[str, float] | None = None) -> None:
        self._scores = dict(scores or {})

    async def score(self, agent: AgentId) -> ReputationScore:
        return ReputationScore(agent_id=agent, score=self._scores.get(str(agent), 0.5))

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        sig = Signature(signer=AgentId("static"), value=b"", algorithm="none")
        return Attestation(issuer=AgentId("static"), claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        return None

    async def stake(self, agent: AgentId, amount: int) -> None:
        return None


class StubIdentity:
    """Deterministic shared-secret Identity stub (test-only, not real crypto)."""

    def __init__(self, agent_id: AgentId, secret: bytes) -> None:
        self._agent_id = agent_id
        self._secret = secret

    def sign(self, payload: bytes) -> Signature:
        import hashlib
        import hmac as _hmac

        tag = _hmac.new(self._secret, payload, hashlib.sha256).digest()
        return Signature(signer=self._agent_id, value=tag, algorithm="hmac-test")

    def verify(self, payload: bytes, sig: Signature, agent: AgentId) -> bool:
        import hashlib
        import hmac as _hmac

        expected = _hmac.new(self._secret, payload, hashlib.sha256).digest()
        return _hmac.compare_digest(expected, sig.value)

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        return AgentIdentity(agent_id=agent, public_key=b"", method="stub")


_SCORES = {"bob": 0.9, "carol": 0.6, "mallory": 0.1}


def _mk(
    name: str,
    trust: StaticTrust | ScoreAverageTrust,
    *,
    identity: StubIdentity | None = None,
) -> TrustGatedPrivacy:
    return TrustGatedPrivacy(
        AgentId(name),
        trust,
        seed=name.encode("utf-8"),
        deterministic=True,
        identity=identity,
        reveal_fields=_REVEAL,
    )


def _fleet(
    trust: StaticTrust | ScoreAverageTrust,
    *,
    identity: StubIdentity | None = None,
) -> tuple[TrustGatedPrivacy, TrustGatedPrivacy, TrustGatedPrivacy, TrustGatedPrivacy]:
    """A wired (alice, bob, carol, mallory) fleet sharing one trust feed."""
    alice = _mk("alice", trust, identity=identity)
    bob = _mk("bob", trust)
    carol = _mk("carol", trust)
    mallory = _mk("mallory", trust)
    for name, plugin in (("bob", bob), ("carol", carol), ("mallory", mallory)):
        alice.register_peer(AgentId(name), plugin.public_key)
    return alice, bob, carol, mallory


_AUDIENCE = [AgentId("bob"), AgentId("carol"), AgentId("mallory")]


def _view_of(plaintext: bytes) -> dict[str, Any]:
    loaded: Any = json.loads(plaintext)
    assert isinstance(loaded, dict)
    return cast("dict[str, Any]", loaded)


def _proof_from_view(view: dict[str, Any]) -> tuple[Statement, Proof]:
    statement = Statement(
        predicate=DISCLOSURE_PREDICATE,
        public_inputs={
            "root": str(view["root"]),
            "reveal": ",".join(str(n) for n in cast("list[Any]", view["reveal"])),
        },
    )
    proof = Proof(
        statement=statement,
        data=base64.b64decode(str(view["proof"])),
        scheme=PROOF_SCHEME,
    )
    return statement, proof


# ---------------------------------------------------------------------------
# 1. Disclosure tiers
# ---------------------------------------------------------------------------


class TestDisclosureTiers:
    async def test_full_tier_gets_plaintext(self) -> None:
        alice, bob, _, _ = _fleet(StaticTrust(_SCORES))
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        assert await bob.decrypt(env) == _PAYLOAD

    async def test_partial_tier_gets_redacted_view_with_valid_proof(self) -> None:
        alice, _, carol, _ = _fleet(StaticTrust(_SCORES))
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        view = _view_of(await carol.decrypt(env))
        assert view["s"] == PARTIAL_SCHEME
        assert view["kind"] == "selective"
        assert view["revealed"] == {"dept": "finance", "region": "EU"}
        statement, proof = _proof_from_view(view)
        assert await carol.verify_proof(statement, proof)

    async def test_hidden_fields_never_reach_partial_tier_or_wire(self) -> None:
        alice, _, carol, _ = _fleet(StaticTrust(_SCORES))
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        view_bytes = await carol.decrypt(env)
        for secret in (_HIDDEN_1.encode(), _HIDDEN_2.encode()):
            assert secret not in env, "hidden field leaked on the wire"
            assert secret not in view_bytes, "hidden field leaked to partial tier"

    async def test_denied_tier_raises_with_verifiable_receipt(self) -> None:
        alice, _, _, mallory = _fleet(StaticTrust(_SCORES))
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        with pytest.raises(TrustDeniedError) as excinfo:
            await mallory.decrypt(env)
        receipt = excinfo.value.receipt
        assert receipt is not None
        assert receipt["s"] == DENIAL_SCHEME
        assert receipt["agent"] == "mallory"
        assert receipt["score"] == 0.1
        assert receipt["threshold"] == alice.policy.partial
        assert alice.verify_denial(receipt)

    async def test_outsider_is_not_in_audience(self) -> None:
        trust = StaticTrust(_SCORES)
        alice, _, _, _ = _fleet(trust)
        eve = _mk("eve", trust)
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        with pytest.raises(NotInAudienceError):
            await eve.decrypt(env)

    async def test_threshold_boundaries_are_inclusive(self) -> None:
        trust = StaticTrust({"bob": 0.8, "carol": 0.5, "mallory": 0.4999})
        alice, bob, carol, mallory = _fleet(trust)
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        assert await bob.decrypt(env) == _PAYLOAD, "score == full threshold must be full tier"
        view = _view_of(await carol.decrypt(env))
        assert view["kind"] == "selective", "score == partial threshold must be partial tier"
        with pytest.raises(TrustDeniedError):
            await mallory.decrypt(env)

    async def test_opaque_payload_partial_tier_gets_honest_digest(self) -> None:
        import hashlib

        alice, _, carol, _ = _fleet(StaticTrust(_SCORES))
        opaque = b"\x00\x01binary-blob\xff"
        env = await alice.encrypt(opaque, _AUDIENCE)
        view = _view_of(await carol.decrypt(env))
        assert view["kind"] == "digest"
        assert view["sha256"] == hashlib.sha256(opaque).hexdigest()
        assert view["size"] == len(opaque)
        assert opaque not in env

    async def test_integrates_with_reference_score_average_trust(self) -> None:
        trust = ScoreAverageTrust()
        for _ in range(10):
            await trust.report(
                AgentId("bob"),
                Evidence(reporter=AgentId("boss"), subject=AgentId("bob"), kind="positive"),
            )
            await trust.report(
                AgentId("mallory"),
                Evidence(reporter=AgentId("boss"), subject=AgentId("mallory"), kind="negative"),
            )
        alice, bob, carol, mallory = _fleet(trust)
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        assert await bob.decrypt(env) == _PAYLOAD  # mean 1.0 -> full
        view = _view_of(await carol.decrypt(env))  # unknown agent -> 0.5 -> partial
        assert view["s"] == PARTIAL_SCHEME
        with pytest.raises(TrustDeniedError):  # mean 0.0 -> denied
            await mallory.decrypt(env)

    def test_policy_validation_rejects_nonsense(self) -> None:
        with pytest.raises(ValueError, match="tier policy"):
            TierPolicy(full=0.4, partial=0.6)
        with pytest.raises(ValueError, match="tier policy"):
            TierPolicy(full=1.2, partial=0.5)
        with pytest.raises(ValueError, match="tier policy"):
            TierPolicy(full=0.8, partial=-0.1)


# ---------------------------------------------------------------------------
# 2. Discrimination: the gate invariant vs. the existing reference plugins
# ---------------------------------------------------------------------------


async def _low_trust_reader_blocked(
    sender: Privacy, low_trust_reader: Privacy, payload: bytes, audience: list[AgentId]
) -> bool:
    """The gate invariant: an audience member below the trust floor must not
    recover the plaintext, and the plaintext must not ride the wire in clear."""
    envelope = await sender.encrypt(payload, audience)
    if payload in envelope:
        return False
    try:
        recovered = await low_trust_reader.decrypt(envelope)
    except Exception:  # noqa: BLE001 - any refusal satisfies the invariant
        return True
    return recovered != payload


class TestGateInvariantDiscrimination:
    """The check that FAILS without this plugin and PASSES with it."""

    async def test_noop_fails_the_gate_invariant(self) -> None:
        noop = NoopPrivacy()
        assert not await _low_trust_reader_blocked(noop, noop, _PAYLOAD, [AgentId("mallory")]), (
            "noop must fail: it hands every byte to everyone"
        )

    async def test_hybrid_x25519_fails_the_gate_invariant(self) -> None:
        alice = HybridX25519Privacy(AgentId("alice"), seed=b"alice", deterministic=True)
        mallory = HybridX25519Privacy(AgentId("mallory"), seed=b"mallory", deterministic=True)
        alice.register_peer(AgentId("mallory"), mallory.public_key)
        assert not await _low_trust_reader_blocked(
            alice, mallory, _PAYLOAD, [AgentId("mallory")]
        ), "hybrid_x25519 must fail: it is deliberately trust-blind"

    async def test_trust_gated_passes_the_gate_invariant(self) -> None:
        alice, _, _, mallory = _fleet(StaticTrust(_SCORES))
        assert await _low_trust_reader_blocked(alice, mallory, _PAYLOAD, [AgentId("mallory")])


# ---------------------------------------------------------------------------
# 3. Byzantine behaviour
# ---------------------------------------------------------------------------


class TestByzantineTrust:
    async def test_poisoned_scores_fail_closed(self) -> None:
        for poison in (math.nan, math.inf, -math.inf, 2.0, -3.0):
            trust = StaticTrust({"bob": poison})
            alice, bob, _, _ = _fleet(trust)
            env = await alice.encrypt(_PAYLOAD, [AgentId("bob")])
            with pytest.raises(TrustDeniedError) as excinfo:
                await bob.decrypt(env)
            receipt = excinfo.value.receipt
            assert receipt is not None
            assert receipt["score"] == -1.0, f"poison {poison!r} must record the sentinel"
            assert _PAYLOAD not in env

    async def test_gate_table_tamper_detected(self) -> None:
        trust = StaticTrust(_SCORES)
        alice, _, _, _ = _fleet(trust)
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        obj = cast("dict[str, Any]", json.loads(env))
        for entry in cast("list[dict[str, Any]]", obj["gate"]):
            if entry["agent"] == "mallory":
                entry["tier"] = "full"
                entry["score"] = 0.99
        forged = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        fresh_bob = _mk("bob", trust)  # same keys, empty replay set
        with pytest.raises(TamperError):
            await fresh_bob.decrypt(forged)

    async def test_policy_tamper_detected(self) -> None:
        trust = StaticTrust(_SCORES)
        alice, _, _, _ = _fleet(trust)
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        obj = cast("dict[str, Any]", json.loads(env))
        cast("dict[str, Any]", obj["policy"])["partial"] = 0.0
        forged = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        fresh_bob = _mk("bob", trust)
        with pytest.raises(TamperError):
            await fresh_bob.decrypt(forged)

    async def test_tier_blob_swap_never_yields_plaintext(self) -> None:
        trust = StaticTrust(_SCORES)
        alice, _, _, _ = _fleet(trust)
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        obj = cast("dict[str, Any]", json.loads(env))
        obj["full"], obj["partial"] = obj["partial"], obj["full"]
        swapped = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        for name in ("bob", "carol"):
            reader = _mk(name, trust)
            with pytest.raises(MalformedEnvelopeError):
                await reader.decrypt(swapped)

    async def test_forged_denial_receipts_rejected(self) -> None:
        alice, _, _, mallory = _fleet(StaticTrust(_SCORES))
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        with pytest.raises(TrustDeniedError) as excinfo:
            await mallory.decrypt(env)
        receipt = excinfo.value.receipt
        assert receipt is not None
        for field, forged_value in (
            ("score", 0.99),
            ("agent", "bob"),
            ("threshold", 0.0),
            ("epoch", 42),
        ):
            forged = dict(receipt)
            forged[field] = forged_value
            assert not alice.verify_denial(forged), f"forged {field} accepted"

    async def test_replay_rejected(self) -> None:
        alice, bob, _, _ = _fleet(StaticTrust(_SCORES))
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        assert await bob.decrypt(env) == _PAYLOAD
        with pytest.raises(ReplayError):
            await bob.decrypt(env)

    async def test_tampered_proof_fails_verification(self) -> None:
        alice, _, carol, _ = _fleet(StaticTrust(_SCORES))
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        view = _view_of(await carol.decrypt(env))
        statement, proof = _proof_from_view(view)
        body = cast("dict[str, Any]", json.loads(proof.data))
        disclosed = cast("dict[str, dict[str, Any]]", body["disclosed"])
        disclosed["dept"]["value"] = "engineering"
        tampered = Proof(
            statement=statement,
            data=json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            scheme=PROOF_SCHEME,
        )
        assert not await carol.verify_proof(statement, tampered)

    async def test_identity_signed_receipts(self) -> None:
        identity = StubIdentity(AgentId("alice"), secret=b"alice-signing-secret")
        alice, _, _, mallory = _fleet(StaticTrust(_SCORES), identity=identity)
        env = await alice.encrypt(_PAYLOAD, _AUDIENCE)
        with pytest.raises(TrustDeniedError) as excinfo:
            await mallory.decrypt(env)
        receipt = excinfo.value.receipt
        assert receipt is not None
        assert receipt["alg"] == "hmac-test"
        assert alice.verify_denial(receipt)
        forged = dict(receipt)
        forged["score"] = 0.99
        assert not alice.verify_denial(forged)


# ---------------------------------------------------------------------------
# 4. Determinism, registry, protocol conformance
# ---------------------------------------------------------------------------


class TestDeterminismAndWiring:
    async def test_envelopes_are_byte_deterministic(self) -> None:
        envs: list[bytes] = []
        for _ in range(2):
            alice, _, _, _ = _fleet(StaticTrust(_SCORES))
            envs.append(await alice.encrypt(_PAYLOAD, _AUDIENCE))
        assert envs[0] == envs[1], "same seed + trust must yield byte-identical envelopes"

    async def test_different_seeds_yield_different_envelopes(self) -> None:
        trust = StaticTrust(_SCORES)
        alice_a, _, _, _ = _fleet(trust)
        alice_b = TrustGatedPrivacy(
            AgentId("alice"), trust, seed=b"other", deterministic=True, reveal_fields=_REVEAL
        )
        bob = _mk("bob", trust)
        alice_b.register_peer(AgentId("bob"), bob.public_key)
        env_a = await alice_a.encrypt(_PAYLOAD, [AgentId("bob")])
        env_b = await alice_b.encrypt(_PAYLOAD, [AgentId("bob")])
        assert env_a != env_b

    def test_registry_resolves_trust_gated(self) -> None:
        cls = PluginRegistry().resolve("privacy", "trust_gated")
        assert cls is TrustGatedPrivacy

    def test_satisfies_privacy_protocol(self) -> None:
        plugin = _mk("alice", StaticTrust())
        assert isinstance(plugin, Privacy)


# ---------------------------------------------------------------------------
# 5. Adversarial validators: PASS vs trust_gated, FAIL vs noop AND hybrid_x25519
# ---------------------------------------------------------------------------


def _hybrid_pair(reader_name: str) -> tuple[HybridX25519Privacy, HybridX25519Privacy]:
    """A wired (sender, reader) pair of trust-blind hybrid plugins."""
    sender = HybridX25519Privacy(AgentId("alice"), seed=b"alice", deterministic=True)
    reader = HybridX25519Privacy(
        AgentId(reader_name), seed=reader_name.encode("utf-8"), deterministic=True
    )
    sender.register_peer(AgentId(reader_name), reader.public_key)
    return sender, reader


class TestAdversarialValidators:
    """Charter bar: each check fails vs BOTH reference plugins, passes vs ours."""

    async def test_low_trust_blocked_discriminates(self) -> None:
        alice, _, _, mallory = _fleet(StaticTrust(_SCORES))
        assert (
            await check_low_trust_blocked(
                alice, mallory, payload=_PAYLOAD, audience=[AgentId("mallory")]
            )
        ).passed
        noop = NoopPrivacy()
        assert not (
            await check_low_trust_blocked(
                noop, noop, payload=_PAYLOAD, audience=[AgentId("mallory")]
            )
        ).passed
        h_sender, h_reader = _hybrid_pair("mallory")
        assert not (
            await check_low_trust_blocked(
                h_sender, h_reader, payload=_PAYLOAD, audience=[AgentId("mallory")]
            )
        ).passed

    async def test_partial_redaction_discriminates(self) -> None:
        hidden = [_HIDDEN_1.encode(), _HIDDEN_2.encode()]
        alice, _, carol, _ = _fleet(StaticTrust(_SCORES))
        assert (
            await check_partial_redaction_enforced(
                alice, carol, payload=_PAYLOAD, audience=_AUDIENCE, hidden=hidden
            )
        ).passed
        noop = NoopPrivacy()
        assert not (
            await check_partial_redaction_enforced(
                noop, noop, payload=_PAYLOAD, audience=[AgentId("carol")], hidden=hidden
            )
        ).passed
        h_sender, h_reader = _hybrid_pair("carol")
        assert not (
            await check_partial_redaction_enforced(
                h_sender, h_reader, payload=_PAYLOAD, audience=[AgentId("carol")], hidden=hidden
            )
        ).passed

    async def test_gate_tamper_discriminates(self) -> None:
        trust = StaticTrust(_SCORES)
        alice, _, _, _ = _fleet(trust)
        fresh_bob = _mk("bob", trust)
        assert (
            await check_gate_tamper_rejected(
                alice, fresh_bob, payload=_PAYLOAD, audience=_AUDIENCE, upgrade_agent="mallory"
            )
        ).passed
        noop = NoopPrivacy()
        assert not (
            await check_gate_tamper_rejected(
                noop, noop, payload=_PAYLOAD, audience=[AgentId("bob")], upgrade_agent="mallory"
            )
        ).passed
        h_sender, h_reader = _hybrid_pair("bob")
        assert not (
            await check_gate_tamper_rejected(
                h_sender,
                h_reader,
                payload=_PAYLOAD,
                audience=[AgentId("bob")],
                upgrade_agent="mallory",
            )
        ).passed

    async def test_denial_receipt_discriminates(self) -> None:
        alice, _, _, mallory = _fleet(StaticTrust(_SCORES))
        assert (
            await check_denial_receipt_auditable(
                alice, mallory, payload=_PAYLOAD, audience=_AUDIENCE
            )
        ).passed
        noop = NoopPrivacy()
        assert not (
            await check_denial_receipt_auditable(
                noop, noop, payload=_PAYLOAD, audience=[AgentId("mallory")]
            )
        ).passed
        # hybrid refuses the outsider but silently: no receipt, nothing to audit.
        h_sender, _ = _hybrid_pair("bob")
        h_outsider = HybridX25519Privacy(AgentId("mallory"), seed=b"mallory", deterministic=True)
        assert not (
            await check_denial_receipt_auditable(
                h_sender, h_outsider, payload=_PAYLOAD, audience=[AgentId("bob")]
            )
        ).passed
