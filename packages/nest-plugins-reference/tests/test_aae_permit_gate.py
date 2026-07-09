# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Phase-1 smoke tests for the AAE permit gate and its envelope chain.

Covers: envelope round-trip sign/verify, single-field tamper detection,
malformed-input hardening, chain ordering (intact chain of three, gap, fork,
foreign-chain splice), deny-by-default, first-match-wins, denials as
verifiable receipts, conditional-is-not-permission, deterministic double-run
(byte-identical envelopes), constructor validation, scoring, attestation, and
storage-only evidence reporting.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.types import AgentId, Claim, Evidence
from nest_plugins_reference.trust.aae_envelope import (
    canonical_bytes,
    envelope_hash,
    issue_envelope,
    order_chain,
    verify_envelope,
)
from nest_plugins_reference.trust.aae_permit_gate import AAEPermitGate, permits

_SK = hashlib.sha256(b"aae-test-signing-key").hexdigest()
_T0 = "2026-01-01T00:00:00+00:00"
_ALLOW_READS = [{"agent": "a*", "verb": "read", "resource": "*", "effect": "authorized"}]


def _make_chain(n: int, agent: str = "a1") -> list[dict[str, Any]]:
    envs: list[dict[str, Any]] = []
    prev: str | None = None
    for i in range(n):
        env = issue_envelope(
            _SK,
            agent_id=agent,
            verb="read",
            resource=f"doc/{i}",
            params={"i": i},
            policy_id="rule:0",
            outcome="authorized",
            prev_hash=prev,
            issued_at=_T0,
        )
        envs.append(env)
        prev = envelope_hash(env)
    return envs


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def test_envelope_round_trip() -> None:
    env = _make_chain(1)[0]
    assert verify_envelope(env)
    assert set(env) == {
        "agent_id",
        "action",
        "policy_id",
        "outcome",
        "prev_hash",
        "issued_at",
        "sig",
        "pubkey",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "mallory"),
        ("policy_id", "rule:99"),
        ("outcome", "authorized"),
        ("issued_at", "2026-01-01T00:00:01+00:00"),
        ("prev_hash", "ab" * 32),
    ],
)
def test_envelope_single_field_tamper_fails(field: str, value: str) -> None:
    env = issue_envelope(
        _SK,
        agent_id="a1",
        verb="write",
        resource="db",
        params={"n": 1},
        policy_id="rule:0",
        outcome="denied",
        prev_hash=None,
        issued_at=_T0,
    )
    tampered = {**env, field: value}
    assert verify_envelope(tampered) is False


def test_envelope_action_tamper_fails() -> None:
    env = _make_chain(1)[0]
    tampered = {**env, "action": {**env["action"], "verb": "delete"}}
    assert verify_envelope(tampered) is False
    tampered = {**env, "action": {**env["action"], "params": {"i": 999}}}
    assert verify_envelope(tampered) is False


def test_envelope_malformed_input_never_raises() -> None:
    env = _make_chain(1)[0]
    assert verify_envelope(None) is False
    assert verify_envelope([env]) is False
    assert verify_envelope({k: v for k, v in env.items() if k != "outcome"}) is False
    assert verify_envelope({**env, "extra": 1}) is False
    assert verify_envelope({**env, "outcome": "maybe"}) is False
    assert verify_envelope({**env, "sig": "zz" * 64}) is False
    assert verify_envelope({**env, "issued_at": "yesterday-ish"}) is False


def test_issue_envelope_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError, match="outcome"):
        issue_envelope(
            _SK,
            agent_id="a1",
            verb="v",
            resource="r",
            params={},
            policy_id="p",
            outcome="approved",
            prev_hash=None,
            issued_at=_T0,
        )
    with pytest.raises(ValueError, match="RFC 3339"):
        issue_envelope(
            _SK,
            agent_id="a1",
            verb="v",
            resource="r",
            params={},
            policy_id="p",
            outcome="denied",
            prev_hash=None,
            issued_at="not-a-time",
        )
    with pytest.raises(ValueError, match="prev_hash"):
        issue_envelope(
            _SK,
            agent_id="a1",
            verb="v",
            resource="r",
            params={},
            policy_id="p",
            outcome="denied",
            prev_hash="short",
            issued_at=_T0,
        )


def test_chain_of_three_orders_and_verifies() -> None:
    envs = _make_chain(3)
    shuffled = [envs[2], envs[0], envs[1]]
    ordered = order_chain(shuffled)
    assert ordered == envs


def test_chain_gap_detected() -> None:
    envs = _make_chain(3)
    assert order_chain([envs[0], envs[2]]) is None  # interior link deleted


def test_chain_fork_detected() -> None:
    envs = _make_chain(2)
    fork = issue_envelope(
        _SK,
        agent_id="a1",
        verb="read",
        resource="doc/alt",
        params={},
        policy_id="rule:0",
        outcome="authorized",
        prev_hash=envelope_hash(envs[0]),
        issued_at=_T0,
    )
    assert order_chain([*envs, fork]) is None


def test_prev_hash_points_at_foreign_agent_envelope_rejected() -> None:
    """A prev_hash reaching into another agent's chain is a splice, not a link."""
    a_envs = _make_chain(1, agent="a1")
    spliced = issue_envelope(
        _SK,
        agent_id="b1",
        verb="read",
        resource="doc/0",
        params={},
        policy_id="rule:0",
        outcome="authorized",
        prev_hash=envelope_hash(a_envs[0]),
        issued_at=_T0,
    )
    assert order_chain([a_envs[0], spliced]) is None  # two agents: not one chain
    assert order_chain([spliced]) is None  # predecessor absent entirely: gap


async def test_replayed_envelope_detected_out_of_sequence() -> None:
    """Replaying a valid envelope at a second chain position is not a valid chain."""
    envs = _make_chain(3)
    # A verbatim replay of an earlier envelope appears twice -> duplicate rejected.
    assert order_chain([*envs, envs[1]]) is None
    # Through the gate: injecting a replay of the genesis into stored history
    # (a second prev_hash=None) makes verify_chain fail (duplicate / two genesis).
    gate = AAEPermitGate(policy=_ALLOW_READS, key_seed=b"seed")
    for i in range(2):
        await gate.evaluate(AgentId("a1"), "read", f"doc/{i}", {}, now=_T0)
    gate._chains["a1"].append(gate._chains["a1"][0])  # replay genesis out of sequence
    assert gate.verify_chain(AgentId("a1")) is False


def test_forged_pubkey_substitution_fails() -> None:
    """Swapping an interior envelope's pubkey — re-signed so it self-verifies in
    isolation — still breaks the chain: envelope_hash commits to pubkey+sig, so the
    successor's prev_hash no longer resolves (a foreign-key splice reads as a gap)."""
    envs = _make_chain(3)
    attacker_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"attacker").digest())
    attacker_pub = attacker_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    forged = {**envs[1], "pubkey": attacker_pub}
    forged["sig"] = attacker_key.sign(canonical_bytes(forged)).hex()

    assert verify_envelope(forged) is True  # self-consistent under the attacker key
    assert forged["pubkey"] != envs[1]["pubkey"]
    # env[2] still points at the ORIGINAL hash of env[1], which no longer exists.
    assert order_chain([envs[0], forged, envs[2]]) is None


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


async def test_deny_by_default() -> None:
    gate = AAEPermitGate(key_seed=b"seed")
    env = await gate.evaluate(AgentId("a1"), "write", "db", {}, now=_T0)
    assert env["outcome"] == "denied"
    assert env["policy_id"] == "default"
    assert permits(env) is False


async def test_first_match_wins() -> None:
    gate = AAEPermitGate(
        policy=[
            {"agent": "a1", "verb": "read", "resource": "*", "effect": "denied"},
            {"agent": "a*", "verb": "read", "resource": "*", "effect": "authorized"},
        ],
        key_seed=b"seed",
    )
    denied = await gate.evaluate(AgentId("a1"), "read", "doc/1", {}, now=_T0)
    granted = await gate.evaluate(AgentId("a2"), "read", "doc/1", {}, now=_T0)
    assert (denied["outcome"], denied["policy_id"]) == ("denied", "rule:0")
    assert (granted["outcome"], granted["policy_id"]) == ("authorized", "rule:1")


async def test_role_rule_matches_exactly() -> None:
    gate = AAEPermitGate(
        policy=[{"role": "auditor", "verb": "*", "resource": "*", "effect": "authorized"}],
        roles={"a1": "auditor"},
        key_seed=b"seed",
    )
    assert (await gate.evaluate(AgentId("a1"), "read", "x", {}, now=_T0))["outcome"] == "authorized"
    assert (await gate.evaluate(AgentId("a2"), "read", "x", {}, now=_T0))["outcome"] == "denied"


async def test_denial_is_a_verifiable_receipt() -> None:
    gate = AAEPermitGate(key_seed=b"seed")
    env = await gate.evaluate(AgentId("a1"), "shutdown", "town", {"force": True}, now=_T0)
    assert env["outcome"] == "denied"
    assert verify_envelope(env)


async def test_conditional_is_not_permission() -> None:
    gate = AAEPermitGate(
        policy=[{"agent": "*", "verb": "pay", "resource": "*", "effect": "conditional"}],
        key_seed=b"seed",
    )
    env = await gate.evaluate(AgentId("a1"), "pay", "invoice/7", {"limit": 10}, now=_T0)
    assert env["outcome"] == "conditional"
    assert verify_envelope(env)
    assert permits(env) is False


async def test_gate_chain_links_and_verifies() -> None:
    gate = AAEPermitGate(policy=_ALLOW_READS, key_seed=b"seed")
    for i in range(3):
        await gate.evaluate(AgentId("a1"), "read", f"doc/{i}", {}, now=_T0)
    chain = gate.chain(AgentId("a1"))
    assert len(chain) == 3
    assert chain[0]["prev_hash"] is None
    assert chain[1]["prev_hash"] == envelope_hash(chain[0])
    assert chain[2]["prev_hash"] == envelope_hash(chain[1])
    assert gate.verify_chain(AgentId("a1"))
    assert gate.verify_chain(AgentId("nobody"))  # empty history is an intact chain


async def test_deterministic_double_run() -> None:
    def build() -> AAEPermitGate:
        return AAEPermitGate(policy=_ALLOW_READS, key_seed=b"twin")

    runs: list[list[dict[str, Any]]] = []
    for gate in (build(), build()):
        for i in range(3):
            await gate.evaluate(AgentId("a1"), "read", f"doc/{i}", {"i": i}, now=_T0)
        await gate.evaluate(AgentId("a1"), "write", "db", {}, now=_T0)
        runs.append(gate.chain(AgentId("a1")))
    assert json.dumps(runs[0], sort_keys=True) == json.dumps(runs[1], sort_keys=True)


def test_constructor_requires_a_key() -> None:
    with pytest.raises(ValueError, match="signing_key"):
        AAEPermitGate()
    # Same seed -> same key; explicit hex key also accepted.
    sk = hashlib.sha256(b"explicit").hexdigest()
    assert AAEPermitGate(signing_key=sk)._signing_key == sk


@pytest.mark.parametrize(
    "kwargs",
    [
        {"default_effect": "allow", "key_seed": b"s"},
        {"policy": [{"verb": "*", "resource": "*", "effect": "denied"}], "key_seed": b"s"},
        {
            "policy": [
                {"agent": "a", "role": "r", "verb": "*", "resource": "*", "effect": "denied"}
            ],
            "key_seed": b"s",
        },
        {
            "policy": [{"agent": "a", "verb": "*", "resource": "*", "effect": "blocked"}],
            "key_seed": b"s",
        },
        {
            "policy": [{"agent": 3, "verb": "*", "resource": "*", "effect": "denied"}],
            "key_seed": b"s",
        },
        {
            "policy": [
                {"agent": "a", "verb": "*", "resource": "*", "effect": "denied", "priority": 1}
            ],
            "key_seed": b"s",
        },
        {"policy": ["allow-everything"], "key_seed": b"s"},
        {"policy": "not-a-list", "key_seed": b"s"},
        {"roles": {"a1": 7}, "key_seed": b"s"},
        {"signing_key": "not-hex"},
        {"signing_key": "ab" * 16 + "cd"},
    ],
)
def test_constructor_validation_errors(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        AAEPermitGate(**kwargs)


async def test_score_is_authorization_rate() -> None:
    gate = AAEPermitGate(policy=_ALLOW_READS, key_seed=b"seed")
    empty = await gate.score(AgentId("a1"))
    assert (empty.score, empty.confidence, empty.sample_count) == (0.0, 0.0, 0)
    for i in range(2):
        await gate.evaluate(AgentId("a1"), "read", f"doc/{i}", {}, now=_T0)
        await gate.evaluate(AgentId("a1"), "write", f"doc/{i}", {}, now=_T0)
    rep = await gate.score(AgentId("a1"))
    assert (rep.score, rep.confidence, rep.sample_count) == (0.5, 0.4, 4)


async def test_attest_signs_with_gate_key() -> None:
    gate = AAEPermitGate(key_seed=b"seed")
    claim = Claim(subject=AgentId("a1"), predicate="evaluated_by", value="aae_permit_gate")
    att = await gate.attest(AgentId("a1"), claim)
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"seed").digest())
    key.public_key().verify(att.signature.value, claim.model_dump_json().encode())


async def test_report_is_storage_only() -> None:
    gate = AAEPermitGate(policy=_ALLOW_READS, key_seed=b"seed")
    before = await gate.evaluate(AgentId("a1"), "read", "doc/1", {}, now=_T0)
    ev = Evidence(reporter=AgentId("r1"), subject=AgentId("a1"), kind="negative", detail="spam")
    await gate.report(AgentId("a1"), ev)
    after = await gate.evaluate(AgentId("a1"), "read", "doc/1", {}, now=_T0)
    assert gate._evidence_log["a1"] == [ev]
    assert before["outcome"] == after["outcome"] == "authorized"  # no hidden enforcement
    await gate.stake(AgentId("a1"), 5)  # parity no-op
    assert gate._stakes["a1"] == 5
