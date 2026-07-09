# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for the AAE permit gate and its envelopes.

These complement the example-based ``test_aae_permit_gate.py`` by asserting the
core invariants over *generated* keys, fields, chains, and policy tables rather
than hand-picked cases:

1. Round-trip: any ``issue_envelope(...)`` verifies and carries exactly the
   eight fields with ``outcome`` in ``OUTCOMES``.
2. Tamper: any single-field mutation (or a pubkey swap, or a truncated /
   extended / non-hex ``sig``) makes ``verify_envelope`` return ``False`` and
   never raise.
3. Chain re-orderability: any valid N>=1 sequence for one agent has a unique
   causal order; deleting an interior link (gap), a shared-predecessor fork, or
   a foreign-agent splice each makes ``order_chain`` return ``None``.
4. Policy determinism / no-denied-executes: ``evaluate`` is byte-deterministic
   for fixed inputs+seed; the first matching rule (an independent fnmatch
   oracle) decides the outcome; ``permits`` is ``True`` iff that outcome is
   ``"authorized"`` — so a denied ``(verb, resource)`` never yields permission.
5. Score invariants: ``score`` equals authorized/total in [0, 1], sample_count
   equals total, and confidence stays in [0, 1] and is monotonic non-decreasing
   as evaluations accrue.

Determinism follows the repo convention for ``*_properties.py``: bounded
``@settings(max_examples=N, deadline=None)`` with no wall clock (timestamps are
fixed base + integer offset RFC 3339 strings) and deterministic Ed25519 keys
(derived from generated 32-byte seeds). Ed25519 signing dominates cost, so
generated sizes are kept small.

Example::

    pytest packages/nest-plugins-reference/tests/test_aae_permit_gate_properties.py
"""

from __future__ import annotations

import fnmatch
import json
import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId
from nest_plugins_reference.trust.aae_envelope import (
    OUTCOMES,
    Envelope,
    envelope_hash,
    issue_envelope,
    order_chain,
    verify_envelope,
)
from nest_plugins_reference.trust.aae_permit_gate import AAEPermitGate, permits

# ---------------------------------------------------------------------------
# Deterministic, wall-clock-free building blocks
# ---------------------------------------------------------------------------

_BASE = datetime(2026, 1, 1, tzinfo=UTC)
_T0 = _BASE.isoformat()


def _ts(offset: int) -> str:
    """RFC 3339 timestamp a fixed base plus ``offset`` seconds (no wall clock)."""
    return (_BASE + timedelta(seconds=offset)).isoformat()


def _pubkey_hex(sk_hex: str) -> str:
    """Raw 32-byte Ed25519 public key (hex) for a private key given as hex."""
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk_hex))
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


# A printable alphabet with no fnmatch metacharacters (``* ? [ ]``), so generated
# field *values* are always literals; glob patterns add "*" explicitly below.
_SAFE = "abcABC012/-_."
_names = st.text(alphabet=_SAFE, min_size=1, max_size=8)
_tokens = st.text(alphabet=_SAFE, min_size=0, max_size=8)
_scalars = st.one_of(
    st.text(alphabet=_SAFE, max_size=6),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
    st.none(),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
)
_param_keys = st.text(alphabet="xyzw", min_size=1, max_size=3)
_params = st.dictionaries(_param_keys, _scalars, max_size=4)
_params_nonempty = st.dictionaries(_param_keys, _scalars, min_size=1, max_size=4)
_offsets = st.integers(min_value=0, max_value=1_000_000)
_outcomes = st.sampled_from(sorted(OUTCOMES))
# 32-byte Ed25519 private key as hex (issue_envelope takes the raw key hex).
_sk_hex = st.binary(min_size=32, max_size=32).map(lambda b: b.hex())
_prev_hash = st.one_of(st.none(), st.binary(min_size=32, max_size=32).map(lambda b: b.hex()))


# ---------------------------------------------------------------------------
# 1. Round-trip
# ---------------------------------------------------------------------------

_EXPECTED_FIELDS = {
    "agent_id",
    "action",
    "policy_id",
    "outcome",
    "prev_hash",
    "issued_at",
    "sig",
    "pubkey",
}


class TestRoundTrip:
    @settings(max_examples=100, deadline=None)
    @given(
        sk_hex=_sk_hex,
        agent_id=_names,
        verb=_tokens,
        resource=_tokens,
        params=_params,
        policy_id=_tokens,
        outcome=_outcomes,
        prev_hash=_prev_hash,
        offset=_offsets,
    )
    def test_issue_then_verify_holds_with_exactly_eight_fields(
        self,
        sk_hex: str,
        agent_id: str,
        verb: str,
        resource: str,
        params: dict[str, Any],
        policy_id: str,
        outcome: str,
        prev_hash: str | None,
        offset: int,
    ) -> None:
        """Any issued envelope verifies, has exactly the eight fields, and its
        outcome is one of the closed ``OUTCOMES`` set."""
        env = issue_envelope(
            sk_hex,
            agent_id=agent_id,
            verb=verb,
            resource=resource,
            params=params,
            policy_id=policy_id,
            outcome=outcome,
            prev_hash=prev_hash,
            issued_at=_ts(offset),
        )
        assert verify_envelope(env) is True
        assert set(env) == _EXPECTED_FIELDS
        assert env["outcome"] in OUTCOMES


# ---------------------------------------------------------------------------
# 2. Tamper
# ---------------------------------------------------------------------------


class TestTamper:
    @settings(max_examples=100, deadline=None)
    @given(
        sk_hex=_sk_hex,
        agent_id=_names,
        verb=_tokens,
        resource=_tokens,
        params=_params_nonempty,
        policy_id=_tokens,
        outcome=_outcomes,
        prev_hash=_prev_hash,
        offset=_offsets,
    )
    def test_any_single_mutation_or_bad_sig_fails_closed(
        self,
        sk_hex: str,
        agent_id: str,
        verb: str,
        resource: str,
        params: dict[str, Any],
        policy_id: str,
        outcome: str,
        prev_hash: str | None,
        offset: int,
    ) -> None:
        """For an arbitrary issued envelope, flipping any one field value, swapping
        the pubkey, or corrupting the signature makes ``verify_envelope`` return
        ``False`` — and it never raises on hostile input."""
        env = issue_envelope(
            sk_hex,
            agent_id=agent_id,
            verb=verb,
            resource=resource,
            params=params,
            policy_id=policy_id,
            outcome=outcome,
            prev_hash=prev_hash,
            issued_at=_ts(offset),
        )
        assert verify_envelope(env) is True  # baseline

        # A distinct valid outcome, timestamp, prev_hash, and pubkey for flips.
        other_outcome = sorted(OUTCOMES - {env["outcome"]})[0]
        other_ts = _ts(offset + 1)
        other_prev = "cd" * 32 if env["prev_hash"] is None else "ab" * 32
        # Attacker key derived from (and guaranteed distinct from) the signing key.
        sk_bytes = bytes.fromhex(sk_hex)
        attacker_hex = bytes([sk_bytes[0] ^ 0xFF, *sk_bytes[1:]]).hex()
        attacker_pub = _pubkey_hex(attacker_hex)
        first_key = next(iter(params))
        mutated_params = {**params, first_key: f"{params[first_key]!r}-tampered"}

        mutations: list[Envelope] = [
            {**env, "agent_id": env["agent_id"] + "X"},
            {**env, "action": {**env["action"], "verb": str(env["action"]["verb"]) + "X"}},
            {**env, "action": {**env["action"], "resource": str(env["action"]["resource"]) + "X"}},
            {**env, "action": {**env["action"], "params": mutated_params}},
            {**env, "policy_id": env["policy_id"] + "X"},
            {**env, "outcome": other_outcome},
            {**env, "prev_hash": other_prev},
            {**env, "issued_at": other_ts},
            {**env, "pubkey": attacker_pub},  # sig no longer matches the key
            {**env, "sig": str(env["sig"])[:-2]},  # truncated -> wrong length
            {**env, "sig": str(env["sig"]) + "ab"},  # extended -> wrong length
            {**env, "sig": "zz" * 64},  # right length, non-hex
        ]
        assert attacker_pub != env["pubkey"]  # the swap is a genuine key change
        for tampered in mutations:
            assert verify_envelope(tampered) is False


# ---------------------------------------------------------------------------
# 3. Chain re-orderability
# ---------------------------------------------------------------------------


@st.composite
def _linked_chain(draw: st.DrawFn) -> tuple[str, str, list[Envelope]]:
    """Generate a valid N>=1 envelope chain for a single agent (one signing key).

    Each envelope's ``prev_hash`` is the ``envelope_hash`` of its predecessor;
    distinct resources keep every envelope hash distinct.
    """
    sk_hex = draw(_sk_hex)
    agent = draw(_names)
    n = draw(st.integers(min_value=1, max_value=6))
    base = draw(_offsets)
    envs: list[Envelope] = []
    prev: str | None = None
    for i in range(n):
        env = issue_envelope(
            sk_hex,
            agent_id=agent,
            verb="read",
            resource=f"doc/{i}",
            params={"i": i},
            policy_id=f"rule:{i}",
            outcome="authorized",
            prev_hash=prev,
            issued_at=_ts(base + i),
        )
        envs.append(env)
        prev = envelope_hash(env)
    return sk_hex, agent, envs


class TestChainReorderability:
    @settings(max_examples=60, deadline=None)
    @given(built=_linked_chain(), perm_seed=st.integers(min_value=0, max_value=2**31))
    def test_shuffle_recovers_the_unique_causal_order(
        self, built: tuple[str, str, list[Envelope]], perm_seed: int
    ) -> None:
        """A shuffled valid chain re-orders to exactly one genesis-first sequence."""
        _sk, _agent, envs = built
        shuffled = list(envs)
        random.Random(perm_seed).shuffle(shuffled)
        ordered = order_chain(shuffled)
        assert ordered == envs
        assert order_chain(envs) == envs  # already-ordered is a fixed point

    @settings(max_examples=60, deadline=None)
    @given(built=_linked_chain())
    def test_deleting_an_interior_link_is_a_gap(
        self, built: tuple[str, str, list[Envelope]]
    ) -> None:
        """Removing any interior envelope leaves a dangling prev_hash -> ``None``.

        Meaningful only for N>=3 (an interior link must exist); shorter chains
        assert the intact chain still orders."""
        _sk, _agent, envs = built
        if len(envs) < 3:
            assert order_chain(envs) == envs
            return
        for i in range(1, len(envs) - 1):
            without_interior = [e for j, e in enumerate(envs) if j != i]
            assert order_chain(without_interior) is None

    @settings(max_examples=60, deadline=None)
    @given(built=_linked_chain())
    def test_fork_sharing_a_predecessor_is_rejected(
        self, built: tuple[str, str, list[Envelope]]
    ) -> None:
        """Two envelopes claiming the same predecessor (or two genesis blocks) is
        never one intact chain."""
        sk_hex, agent, envs = built
        if len(envs) >= 2:
            # A sibling of envs[1]: same prev_hash, different resource -> distinct.
            fork = issue_envelope(
                sk_hex,
                agent_id=agent,
                verb="read",
                resource="doc/forked",
                params={},
                policy_id="rule:fork",
                outcome="authorized",
                prev_hash=envs[1]["prev_hash"],
                issued_at=_ts(0),
            )
        else:
            # N == 1: a second genesis (prev_hash None) is the multi-genesis fork.
            fork = issue_envelope(
                sk_hex,
                agent_id=agent,
                verb="read",
                resource="doc/forked",
                params={},
                policy_id="rule:fork",
                outcome="authorized",
                prev_hash=None,
                issued_at=_ts(0),
            )
        assert order_chain([*envs, fork]) is None

    @settings(max_examples=60, deadline=None)
    @given(built=_linked_chain(), other_agent=_names)
    def test_foreign_agent_splice_is_rejected(
        self, built: tuple[str, str, list[Envelope]], other_agent: str
    ) -> None:
        """An envelope for a *different* agent, however it links, means two agents
        are present -> not one chain."""
        sk_hex, agent, envs = built
        if other_agent == agent:
            other_agent = agent + "Z"  # force a genuinely foreign identity
        spliced = issue_envelope(
            sk_hex,
            agent_id=other_agent,
            verb="read",
            resource="doc/foreign",
            params={},
            policy_id="rule:foreign",
            outcome="authorized",
            prev_hash=envelope_hash(envs[-1]),
            issued_at=_ts(0),
        )
        assert order_chain([*envs, spliced]) is None


# ---------------------------------------------------------------------------
# 4. Policy determinism / first-match-wins / no denied-executes
# ---------------------------------------------------------------------------

_AGENT_NAMES = ["a1", "a2", "b1"]
_ROLE_NAMES = ["admin", "auditor"]
_VERBS = ["read", "write", "pay"]
_RESOURCES = ["doc/1", "db", "town/hall"]


def _pattern(values: list[str]) -> st.SearchStrategy[str]:
    """A glob over ``values``: ``"*"``, an exact value, or a one-char prefix + ``*``."""
    return st.one_of(
        st.just("*"),
        st.sampled_from(values),
        st.sampled_from(values).map(lambda v: v[:1] + "*"),
    )


@st.composite
def _rule(draw: st.DrawFn) -> dict[str, str]:
    """One policy entry naming exactly one of ``agent`` (glob) or ``role`` (exact)."""
    if draw(st.booleans()):
        subject_key, subject = "agent", draw(_pattern(_AGENT_NAMES))
    else:
        subject_key, subject = "role", draw(st.sampled_from(_ROLE_NAMES))
    return {
        subject_key: subject,
        "verb": draw(_pattern(_VERBS)),
        "resource": draw(_pattern(_RESOURCES)),
        "effect": draw(_outcomes),
    }


_policy = st.lists(_rule(), max_size=6)
_roles_map = st.dictionaries(
    st.sampled_from(_AGENT_NAMES), st.sampled_from(_ROLE_NAMES), max_size=3
)


def _oracle(
    rules: list[dict[str, str]],
    roles: dict[str, str],
    default_effect: str,
    agent: str,
    verb: str,
    resource: str,
) -> tuple[str, str]:
    """Independent first-match-wins reimplementation, mirroring ``AAEPermitGate._match``."""
    for i, rule in enumerate(rules):
        if "agent" in rule:
            if not fnmatch.fnmatchcase(agent, rule["agent"]):
                continue
        elif roles.get(agent) != rule["role"]:
            continue
        if fnmatch.fnmatchcase(verb, rule["verb"]) and fnmatch.fnmatchcase(
            resource, rule["resource"]
        ):
            return rule["effect"], f"rule:{i}"
    return default_effect, "default"


class TestPolicyDeterminism:
    @settings(max_examples=100, deadline=None)
    @given(
        policy=_policy,
        roles=_roles_map,
        default_effect=_outcomes,
        agent=st.sampled_from(_AGENT_NAMES),
        verb=st.sampled_from(_VERBS),
        resource=st.sampled_from(_RESOURCES),
    )
    @pytest.mark.asyncio
    async def test_first_match_decides_and_is_byte_deterministic(
        self,
        policy: list[dict[str, str]],
        roles: dict[str, str],
        default_effect: str,
        agent: str,
        verb: str,
        resource: str,
    ) -> None:
        """The gate's outcome and policy_id match the independent first-match oracle;
        ``permits`` is ``True`` iff authorized (so no denied pair ever permits); and
        two gates with the same seed emit byte-identical envelopes."""
        exp_effect, exp_pid = _oracle(policy, roles, default_effect, agent, verb, resource)

        def build() -> AAEPermitGate:
            return AAEPermitGate(
                policy=policy, roles=roles, default_effect=default_effect, key_seed=b"prop"
            )

        env = await build().evaluate(AgentId(agent), verb, resource, {}, now=_T0)
        assert env["outcome"] == exp_effect
        assert env["policy_id"] == exp_pid
        assert permits(env) is (exp_effect == "authorized")
        if exp_effect == "denied":
            assert permits(env) is False  # no denied (verb, resource) ever permits

        env_twin = await build().evaluate(AgentId(agent), verb, resource, {}, now=_T0)
        assert json.dumps(env, sort_keys=True) == json.dumps(env_twin, sort_keys=True)


# ---------------------------------------------------------------------------
# 5. Score invariants
# ---------------------------------------------------------------------------

_MIXED_POLICY = [
    {"agent": "*", "verb": "read", "resource": "*", "effect": "authorized"},
    {"agent": "*", "verb": "pay", "resource": "*", "effect": "conditional"},
    {"agent": "*", "verb": "write", "resource": "*", "effect": "denied"},
]
_query = st.tuples(st.sampled_from(_VERBS), st.sampled_from(_RESOURCES))


class TestScoreInvariants:
    @settings(max_examples=60, deadline=None)
    @given(queries=st.lists(_query, min_size=1, max_size=12))
    @pytest.mark.asyncio
    async def test_score_tracks_authorization_rate_and_confidence_is_monotonic(
        self, queries: list[tuple[str, str]]
    ) -> None:
        """After each evaluation, ``score`` equals authorized/total (6 dp) in [0, 1],
        ``sample_count`` equals total, and ``confidence`` stays in [0, 1] and never
        decreases as history grows."""
        gate = AAEPermitGate(policy=_MIXED_POLICY, key_seed=b"score")
        authorized = 0
        prev_confidence = -1.0
        for total, (verb, resource) in enumerate(queries, start=1):
            env = await gate.evaluate(AgentId("a1"), verb, resource, {}, now=_T0)
            if env["outcome"] == "authorized":
                authorized += 1
            rep = await gate.score(AgentId("a1"))
            assert rep.sample_count == total
            assert 0.0 <= rep.score <= 1.0
            assert rep.score == round(authorized / total, 6)
            assert 0.0 <= rep.confidence <= 1.0
            assert rep.confidence == round(min(1.0, total / 10), 6)
            assert rep.confidence >= prev_confidence
            prev_confidence = rep.confidence
