# SPDX-License-Identifier: Apache-2.0
"""Example-based + adversarial tests for the ``hybrid_x25519`` privacy plugin.

Three layers of coverage (mirrors the gossip plugin's test structure):

1. **Unit / round-trip** — encryption to one and many recipients, selective
   disclosure prove/verify, and the structural guarantees (plaintext never on
   the wire, undisclosed fields never in the proof).
2. **Adversarial discrimination** — the four validators
   (:mod:`nest_plugins_reference.validators.privacy_validators`) MUST PASS
   against ``hybrid_x25519`` and MUST FAIL against the ``noop`` reference
   plugin. This is the charter's bar for "adversarial".
3. **Sealed-bid-with-privacy scenario** — a 5-bidder first-/second-price auction
   where bids are encrypted to the auctioneer; an eavesdropper on the wire
   learns nothing, yet the auctioneer recovers every bid and resolves the
   winner. This is the ``scenarios/sealed_bid_with_privacy.yaml`` story in
   runnable form.

Example::

    pytest packages/nest-plugins-reference/tests/test_hybrid_x25519.py
"""

from __future__ import annotations

from nest_core.types import AgentId, Statement, Witness
from nest_plugins_reference.privacy.hybrid_x25519 import (
    HybridX25519Privacy,
    NotInAudienceError,
    ReplayError,
    commit_credential,
)
from nest_plugins_reference.privacy.noop import NoopPrivacy
from nest_plugins_reference.validators import (
    check_eavesdropper_blocked,
    check_field_injection_rejected,
    check_replay_rejected,
    check_stale_revocation_blocked,
    corrupt_proof,
)


def _mk(name: str, *, seed: bytes | None = None) -> HybridX25519Privacy:
    return HybridX25519Privacy(
        AgentId(name), seed=seed if seed is not None else name.encode(), deterministic=True
    )


def _credential() -> tuple[Statement, Witness, dict[str, str]]:
    """A 3-field credential committed to a root, revealing age + country only."""
    fields = {"age": "21", "country": "NG", "salary": "99999"}
    root, salts = commit_credential(fields, salt_seed=b"issuer-seed")
    statement = Statement(
        predicate="selective_disclosure",
        public_inputs={"root": root, "reveal": "age,country"},
    )
    witness = Witness(private_inputs={**fields, "__salts__": _dumps(salts)})
    return statement, witness, fields


def _dumps(mapping: dict[str, str]) -> str:
    import json

    return json.dumps(mapping, sort_keys=True)


# ---------------------------------------------------------------------------
# 1. Unit / round-trip
# ---------------------------------------------------------------------------


class TestEncryptionRoundTrip:
    async def test_single_recipient_round_trip(self) -> None:
        alice, bob = _mk("alice"), _mk("bob")
        alice.register_peer(AgentId("bob"), bob.public_key)
        env = await alice.encrypt(b"sealed-bid:1700", [AgentId("bob")])
        assert await bob.decrypt(env) == b"sealed-bid:1700"

    async def test_plaintext_never_on_the_wire(self) -> None:
        alice, bob = _mk("alice"), _mk("bob")
        alice.register_peer(AgentId("bob"), bob.public_key)
        secret = b"the-password-is-hunter2"
        env = await alice.encrypt(secret, [AgentId("bob")])
        assert secret not in env

    async def test_broadcast_to_many_recipients(self) -> None:
        alice = _mk("alice")
        recipients = {name: _mk(name) for name in ("bob", "carol", "dave")}
        for name, plugin in recipients.items():
            alice.register_peer(AgentId(name), plugin.public_key)
        env = await alice.encrypt(b"group-secret", [AgentId(n) for n in recipients])
        for plugin in recipients.values():
            assert await plugin.decrypt(env) == b"group-secret"

    async def test_outsider_cannot_decrypt(self) -> None:
        alice, bob, snoop = _mk("alice"), _mk("bob"), _mk("snoop")
        alice.register_peer(AgentId("bob"), bob.public_key)
        env = await alice.encrypt(b"secret", [AgentId("bob")])
        try:
            await snoop.decrypt(env)
        except NotInAudienceError:
            pass
        else:  # pragma: no cover - failure path
            raise AssertionError("outsider unexpectedly decrypted")

    async def test_tampered_ciphertext_rejected(self) -> None:
        alice, bob = _mk("alice"), _mk("bob")
        alice.register_peer(AgentId("bob"), bob.public_key)
        env = bytearray(await alice.encrypt(b"secret", [AgentId("bob")]))
        # Flip a byte inside the base64 ciphertext region; still valid JSON shape.
        marker = env.index(b'"ct":"') + len(b'"ct":"')
        env[marker] = env[marker] ^ 0x01 if env[marker] != ord("A") else ord("B")
        try:
            await bob.decrypt(bytes(env))
        except Exception:  # noqa: BLE001 - any failure means "not accepted"
            return
        raise AssertionError("tampered ciphertext unexpectedly accepted")  # pragma: no cover

    async def test_determinism_same_seed_same_bytes(self) -> None:
        a1, a2 = _mk("alice"), _mk("alice")
        b1 = _mk("bob")
        a1.register_peer(AgentId("bob"), b1.public_key)
        a2.register_peer(AgentId("bob"), b1.public_key)
        env1 = await a1.encrypt(b"same", [AgentId("bob")])
        env2 = await a2.encrypt(b"same", [AgentId("bob")])
        assert env1 == env2


class TestSelectiveDisclosure:
    async def test_revealed_fields_verify(self) -> None:
        alice = _mk("alice")
        statement, witness, _ = _credential()
        proof = await alice.prove(statement, witness)
        assert await alice.verify_proof(statement, proof)

    async def test_undisclosed_field_absent_from_proof(self) -> None:
        alice = _mk("alice")
        statement, witness, _ = _credential()
        proof = await alice.prove(statement, witness)
        # The hidden salary value must not leak into the proof bytes.
        assert b"99999" not in proof.data

    async def test_tampered_revealed_value_fails(self) -> None:
        alice = _mk("alice")
        statement, witness, _ = _credential()
        proof = await alice.prove(statement, witness)
        assert not await alice.verify_proof(statement, corrupt_proof(proof))

    async def test_wrong_root_fails(self) -> None:
        alice = _mk("alice")
        statement, witness, _ = _credential()
        proof = await alice.prove(statement, witness)
        forged = Statement(
            predicate=statement.predicate,
            public_inputs={**statement.public_inputs, "root": "00" * 32},
        )
        assert not await alice.verify_proof(forged, proof)

    async def test_inconsistent_witness_raises(self) -> None:
        alice = _mk("alice")
        statement, _, _ = _credential()
        bad_witness = Witness(private_inputs={"age": "21", "__salts__": "{}"})
        try:
            await alice.prove(statement, bad_witness)
        except ValueError:
            return
        raise AssertionError("inconsistent witness unexpectedly proved")  # pragma: no cover

    async def test_random_salts_by_default_are_unlinkable_but_verify(self) -> None:
        """With no salt_seed the salts are random: two commitments of the same
        fields differ (unlinkable), yet each still proves and verifies."""
        alice = _mk("alice")
        fields = {"age": "21", "country": "NG"}
        root1, salts1 = commit_credential(fields)
        root2, _ = commit_credential(fields)
        assert root1 != root2
        statement = Statement(
            predicate="selective_disclosure", public_inputs={"root": root1, "reveal": "age"}
        )
        witness = Witness(private_inputs={**fields, "__salts__": _dumps(salts1)})
        proof = await alice.prove(statement, witness)
        assert await alice.verify_proof(statement, proof)


# ---------------------------------------------------------------------------
# 2. Adversarial discrimination — validators pass vs hybrid, fail vs noop
# ---------------------------------------------------------------------------


class TestValidatorsPassAgainstHybrid:
    async def test_eavesdropper_blocked(self) -> None:
        alice, bob, snoop = _mk("alice"), _mk("bob"), _mk("snoop")
        alice.register_peer(AgentId("bob"), bob.public_key)
        secret = b"bid:1700"
        env = await alice.encrypt(secret, [AgentId("bob")])
        report = await check_eavesdropper_blocked(snoop, env, secret=secret)
        assert report.passed, report.detail

    async def test_replay_rejected(self) -> None:
        alice, bob = _mk("alice"), _mk("bob")
        alice.register_peer(AgentId("bob"), bob.public_key)
        env = await alice.encrypt(b"once", [AgentId("bob")])
        report = await check_replay_rejected(bob, env)
        assert report.passed, report.detail

    async def test_field_injection_rejected(self) -> None:
        alice = _mk("alice")
        statement, witness, _ = _credential()
        good = await alice.prove(statement, witness)
        report = await check_field_injection_rejected(alice, statement, good, corrupt_proof(good))
        assert report.passed, report.detail

    async def test_stale_revocation_blocked(self) -> None:
        sender, carol = _mk("sender"), _mk("carol")
        sender.register_peer(AgentId("carol"), carol.public_key)
        pre = await sender.encrypt(b"pre", [AgentId("carol")])
        sender.revoke(AgentId("carol"))
        post = await sender.encrypt(b"post", [AgentId("carol")])
        report = await check_stale_revocation_blocked(carol, pre, post)
        assert report.passed, report.detail


class TestValidatorsFailAgainstNoop:
    """The same validators must be unsatisfiable by the passthrough reference."""

    async def test_eavesdropper_leaks(self) -> None:
        noop = NoopPrivacy()
        secret = b"bid:1700"
        env = await noop.encrypt(secret, [AgentId("bob")])
        report = await check_eavesdropper_blocked(noop, env, secret=secret)
        assert not report.passed

    async def test_replay_accepted(self) -> None:
        noop = NoopPrivacy()
        env = await noop.encrypt(b"once", [AgentId("bob")])
        report = await check_replay_rejected(noop, env)
        assert not report.passed

    async def test_field_injection_accepted(self) -> None:
        noop = NoopPrivacy()
        statement, witness, _ = _credential()
        good = await noop.prove(statement, witness)
        report = await check_field_injection_rejected(noop, statement, good, corrupt_proof(good))
        assert not report.passed

    async def test_revocation_not_enforced(self) -> None:
        noop = NoopPrivacy()
        pre = await noop.encrypt(b"pre", [AgentId("carol")])
        post = await noop.encrypt(b"post", [AgentId("carol")])
        report = await check_stale_revocation_blocked(noop, pre, post)
        assert not report.passed


# ---------------------------------------------------------------------------
# 3. Sealed-bid-with-privacy scenario (runnable form of the YAML)
# ---------------------------------------------------------------------------


class TestSealedBidWithPrivacy:
    async def test_bids_sealed_on_wire_but_auctioneer_resolves_winner(self) -> None:
        auctioneer = _mk("auctioneer")
        bids = {"bidder-0": 1200, "bidder-1": 1750, "bidder-2": 900, "bidder-3": 1500}
        bidders = {name: _mk(name) for name in bids}
        for plugin in bidders.values():
            plugin.register_peer(AgentId("auctioneer"), auctioneer.public_key)

        # Each bidder seals its bid to the auctioneer only.
        envelopes: dict[str, bytes] = {}
        for name, plugin in bidders.items():
            secret = f"bid:{bids[name]}".encode()
            envelopes[name] = await plugin.encrypt(secret, [AgentId("auctioneer")])

        # An eavesdropper watching the wire learns nothing about any bid.
        snoop = _mk("snoop")
        for name, env in envelopes.items():
            report = await check_eavesdropper_blocked(
                snoop, env, secret=f"bid:{bids[name]}".encode()
            )
            assert report.passed, report.detail
            assert str(bids[name]).encode() not in env

        # The auctioneer alone decrypts every bid and resolves a second-price win.
        decoded = {
            name: int((await auctioneer.decrypt(env)).split(b":")[1])
            for name, env in envelopes.items()
        }
        assert decoded == bids
        winner = max(decoded, key=lambda n: decoded[n])
        clearing_price = sorted(decoded.values())[-2]
        assert winner == "bidder-1"
        assert clearing_price == 1500


def test_replay_error_is_distinct_from_audience_error() -> None:
    """Sanity anchor: the two decrypt failure modes are distinct exception types."""
    assert issubclass(ReplayError, Exception)
    assert issubclass(NotInAudienceError, Exception)
    assert ReplayError is not NotInAudienceError
