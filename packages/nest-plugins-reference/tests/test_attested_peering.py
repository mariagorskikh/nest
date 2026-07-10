# SPDX-License-Identifier: Apache-2.0
"""Unit + property + end-to-end tests for the attested-peering trust plugin.

Four layers of coverage, mirroring ``test_failure_detection.py``:

1. **Verifier unit tests** — drive the handshake directly with two agents and
   assert the happy path is ``ALLOW`` and each attack is ``DENY`` on the
   expected axis: an *impostor* presenting a stolen passport signed with the
   wrong key, a cross-session *replay* of a genuine seal, a *forged operator
   delegation*, and a *tampered boot quote*.
2. **Property-based tests** (``hypothesis``) — for arbitrary agent ids and
   payloads: honest handshakes always verify; a single flipped byte in the
   transcript signature always fails key possession; reordering the reporter
   set never changes the victim's final reputation.
3. **Full simulator integration** — boot ``scenarios/attested_peering.yaml``
   via ``ScenarioRunner`` under seeds 42, 7, 1337 and assert both validators
   pass.
4. **Adversarial discrimination + determinism** — the *same* scenario under
   the baseline ``score_average`` plugin FAILs the Sybil-quarantine validator
   while ``attested_peering`` PASSes it, and two runs at one seed are
   byte-identical.
"""

from __future__ import annotations

import asyncio
import base64
import random
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nest_core.layers.trust import Trust
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Evidence
from nest_core.validators import ValidationResult, validate_trace
from nest_plugins_reference.trust.attested_peering import (
    AgentFactsCard,
    AttestedPeeringTrust,
    PeeringPolicy,
    golden_measurements,
)

_OP = b"unit-test-operator-seed"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _verifier(**kwargs: Any) -> AttestedPeeringTrust:
    return AttestedPeeringTrust(
        agent_id=AgentId("observer"),
        seed=b"unit",
        policy=PeeringPolicy(require_trusted_operator=True, **kwargs),
    )


def _honest(agent_id: str = "honest-0", rng_tag: str | None = None) -> AttestedPeeringTrust:
    return AttestedPeeringTrust(
        agent_id=AgentId(agent_id),
        seed=b"unit",
        operator_seed=_OP,
        offer_env=True,
        rng=random.Random(rng_tag) if rng_tag else None,
    )


def _handshake(
    verifier: AttestedPeeringTrust,
    initiator: AttestedPeeringTrust,
    session_name: str,
    *,
    present_card: Any = None,
    seal_override: dict[str, Any] | None = None,
    kind: str = "positive",
) -> Any:
    """Drive hail -> vouch -> seal and return the verifier's verdict."""
    session = AgentId(session_name)
    hail = initiator.make_hail(report_kind=kind, present_card=present_card)
    vouch = verifier.make_vouch(hail, session_key=session)
    seal = seal_override if seal_override is not None else initiator.make_seal(vouch)
    return verifier.evaluate_seal(session, seal)


# ---------------------------------------------------------------------------
# 0. Wiring / protocol conformance
# ---------------------------------------------------------------------------


def test_registry_resolves_attested_peering() -> None:
    """The plugin is wired into the built-in registry as trust:attested_peering."""
    cls = PluginRegistry().resolve("trust", "attested_peering")
    assert cls is AttestedPeeringTrust


def test_satisfies_trust_protocol() -> None:
    """An instance structurally satisfies the Trust layer Protocol."""
    assert isinstance(AttestedPeeringTrust(agent_id=AgentId("a1")), Trust)


def test_unattested_reports_are_quarantined() -> None:
    """Evidence from a reporter with no ALLOW handshake never moves a score."""
    trust = AttestedPeeringTrust(agent_id=AgentId("observer"))
    ev = Evidence(reporter=AgentId("sybil-0"), subject=AgentId("victim"), kind="negative")
    _run(trust.report(AgentId("victim"), ev))
    rep = _run(trust.score(AgentId("victim")))
    assert rep.sample_count == 0
    assert rep.score == 0.5
    assert trust.quarantined_count == 1


# ---------------------------------------------------------------------------
# 1. Verifier unit tests — happy path + each attack denied on its own axis
# ---------------------------------------------------------------------------


def test_valid_handshake_allows_peer() -> None:
    """An honest, delegated, correctly-booted peer passes all three checks."""
    verifier = _verifier()
    honest = _honest()
    verifier.trust_operator(honest.operator_id, honest.operator_public_key)
    verifier.allow_boot_state()

    verdict = _handshake(verifier, honest, "honest-0")
    assert verdict.decision == "ALLOW"
    assert verdict.friend_or_foe.ok
    assert verdict.trust_my_data.ok
    assert verdict.who_you_work_for.ok
    assert verifier.is_attested(AgentId("honest-0"))


def test_sybil_without_delegation_denied() -> None:
    """A self-asserted identity with no operator delegation fails who-you-work-for."""
    verifier = _verifier()
    sybil = AttestedPeeringTrust(agent_id=AgentId("sybil-0"), seed=b"unit")

    verdict = _handshake(verifier, sybil, "sybil-0", kind="negative")
    assert verdict.decision == "DENY"
    assert verdict.friend_or_foe.ok  # it genuinely holds its own key
    assert not verdict.who_you_work_for.ok


def test_impostor_signature_denied() -> None:
    """A peer presenting a stolen passport but signing with its own key is denied."""
    verifier = _verifier()
    honest = _honest()
    verifier.trust_operator(honest.operator_id, honest.operator_public_key)
    verifier.allow_boot_state()
    impostor = AttestedPeeringTrust(agent_id=AgentId("impostor-0"), seed=b"unit")

    verdict = _handshake(
        verifier, impostor, "impostor-0", present_card=honest.card, kind="negative"
    )
    assert verdict.decision == "DENY"
    assert not verdict.friend_or_foe.ok
    assert "possession" in verdict.friend_or_foe.detail
    assert not verifier.is_attested(AgentId("impostor-0"))


def test_replayed_proof_denied() -> None:
    """A genuine honest seal captured from another session fails the live transcript."""
    verifier = _verifier()
    honest = _honest()
    verifier.trust_operator(honest.operator_id, honest.operator_public_key)
    verifier.allow_boot_state()

    # Capture a real seal from a throwaway session on a distinct RNG stream.
    cap_honest = _honest(rng_tag="capture")
    cap_obs = AttestedPeeringTrust(
        agent_id=AgentId("observer"), seed=b"unit", rng=random.Random("capture-obs")
    )
    cap_hail = cap_honest.make_hail(report_kind="positive")
    cap_vouch = cap_obs.make_vouch(cap_hail, session_key=AgentId("honest-0"))
    captured = cap_honest.make_seal(cap_vouch)

    replayer = AttestedPeeringTrust(agent_id=AgentId("replayer-0"), seed=b"unit")
    verdict = _handshake(
        verifier,
        replayer,
        "replayer-0",
        present_card=honest.card,
        seal_override=captured,
        kind="negative",
    )
    assert verdict.decision == "DENY"
    assert not verdict.friend_or_foe.ok


def test_forged_operator_delegation_denied() -> None:
    """A passport claiming a trusted operator with an invalid delegation is denied.

    The attacker mints a card whose ``operator_id`` names the trusted operator
    but whose delegation signature is bogus, then self-signs that body. The
    self-signature is valid, but the operator never issued the delegation.
    """
    verifier = _verifier()
    honest = _honest()
    verifier.trust_operator(honest.operator_id, honest.operator_public_key)
    verifier.allow_boot_state()

    # The forger self-signs a card that claims the trusted operator's id + key
    # but carries a bogus delegation signature the operator never produced.
    forger = AttestedPeeringTrust(
        agent_id=AgentId("forger-0"),
        seed=b"unit",
        operator_delegation=(
            honest.operator_id,
            honest.operator_public_key,
            b"not-a-real-signature",
        ),
    )

    verdict = _handshake(verifier, forger, "forger-0", kind="negative")
    assert verdict.decision == "DENY"
    assert not verdict.friend_or_foe.ok
    assert "delegation" in verdict.friend_or_foe.detail


def test_tampered_boot_quote_denied_when_required() -> None:
    """A peer whose boot state is not on the allow-list fails trust-my-data."""
    verifier = _verifier(require_env_quote=True)
    verifier.allow_boot_state()  # only the golden config is vetted
    tampered = {**golden_measurements(), "kernel": "evil-kernel"}
    peer = AttestedPeeringTrust(
        agent_id=AgentId("compromised-0"),
        seed=b"unit",
        operator_seed=_OP,
        offer_env=True,
        measurements=tampered,
    )
    verifier.trust_operator(peer.operator_id, peer.operator_public_key)

    verdict = _handshake(verifier, peer, "compromised-0")
    assert verdict.decision == "DENY"
    assert not verdict.trust_my_data.ok


def test_missing_required_boot_quote_denied() -> None:
    """When the policy requires a boot quote, a peer that offers none is denied."""
    verifier = _verifier(require_env_quote=True)
    honest_no_env = AttestedPeeringTrust(
        agent_id=AgentId("honest-0"), seed=b"unit", operator_seed=_OP, offer_env=False
    )
    verifier.trust_operator(honest_no_env.operator_id, honest_no_env.operator_public_key)

    verdict = _handshake(verifier, honest_no_env, "honest-0")
    assert verdict.decision == "DENY"
    assert not verdict.trust_my_data.ok


# ---------------------------------------------------------------------------
# 1b. Byzantine wire input — a malformed frame is a clean DENY, never a crash
# ---------------------------------------------------------------------------


_GARBAGE_SEALS: list[dict[str, Any]] = [
    {},  # empty frame
    {"proto": "x", "op": "seal"},  # missing sig
    {"op": "seal", "sig": "!!! not base64 !!!"},  # undecodable signature
    {"op": "seal", "sig": "AAAA", "env": "not-a-dict"},  # wrong env type
    {"op": "seal", "sig": "AAAA", "env": {"nonce": "zz", "measurements": 5}},  # junk env
]


@pytest.mark.parametrize("seal", _GARBAGE_SEALS)
def test_malformed_seal_denies_without_raising(seal: dict[str, Any]) -> None:
    """A byzantine peer's garbage seal yields DENY, not an unhandled exception."""
    verifier = _verifier()
    honest = _honest()
    verifier.trust_operator(honest.operator_id, honest.operator_public_key)
    session = AgentId("honest-0")
    # Open a real session so evaluate_seal reaches evaluate_peer with the junk.
    verifier.make_vouch(honest.make_hail(report_kind="positive"), session_key=session)
    verdict = verifier.evaluate_seal(session, seal)
    assert verdict.decision == "DENY"
    assert not verdict.friend_or_foe.ok


_GARBAGE_HAILS: list[dict[str, Any]] = [
    {},  # no nonce, no facts
    {"op": "hail", "nonce": "not-hex", "facts": {}},  # bad hex nonce + empty card
    {"op": "hail", "nonce": "00ff", "facts": "not-a-dict"},  # facts wrong type
    {"op": "hail", "nonce": "00ff", "facts": {"public_key": "@@@"}},  # undecodable key
    {"op": "hail", "nonce": "00ff", "facts": {"capabilities": 5}},  # non-iterable caps
    {"op": "hail", "nonce": "00ff", "facts": {"capabilities": None}},  # null caps
]


@pytest.mark.parametrize("hail", _GARBAGE_HAILS)
def test_malformed_hail_does_not_crash_responder(hail: dict[str, Any]) -> None:
    """make_vouch tolerates a garbage hail; the session it opens later DENYs."""
    verifier = _verifier()
    session = AgentId("attacker")
    vouch = verifier.make_vouch(hail, session_key=session)  # must not raise
    assert vouch["op"] == "vouch"
    # An attacker who sent junk can never satisfy the transcript on the seal.
    verdict = verifier.evaluate_seal(session, {"op": "seal", "sig": "AAAA"})
    assert verdict.decision == "DENY"


def test_from_dict_tolerates_missing_and_nondict_input() -> None:
    """AgentFactsCard.from_dict never raises on truncated / non-dict wire data."""
    assert AgentFactsCard.from_dict({}).public_key == b""
    assert AgentFactsCard.from_dict("not-a-dict").public_key == b""
    assert AgentFactsCard.from_dict({"public_key": "@@@"}).public_key == b""
    # Non-iterable/null capabilities must not raise TypeError — coerce to empty.
    assert AgentFactsCard.from_dict({"capabilities": 5}).capabilities == ()
    assert AgentFactsCard.from_dict({"capabilities": None}).capabilities == ()


# ---------------------------------------------------------------------------
# 2. Property-based tests
# ---------------------------------------------------------------------------


@settings(max_examples=40, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    agent_name=st.text(
        alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=8
    )
)
def test_property_honest_handshake_always_allows(agent_name: str) -> None:
    """Any honest, delegated, correctly-booted peer is admitted, whatever its id."""
    verifier = _verifier()
    honest = AttestedPeeringTrust(
        agent_id=AgentId(f"h-{agent_name}"), seed=b"prop", operator_seed=_OP, offer_env=True
    )
    verifier.trust_operator(honest.operator_id, honest.operator_public_key)
    verifier.allow_boot_state()
    assert _handshake(verifier, honest, f"h-{agent_name}").decision == "ALLOW"


@settings(max_examples=40)
@given(flip=st.integers(min_value=0, max_value=63))
def test_property_tampered_signature_always_denied(flip: int) -> None:
    """Flipping any byte of the transcript signature always breaks key possession."""
    verifier = _verifier()
    honest = _honest()
    verifier.trust_operator(honest.operator_id, honest.operator_public_key)
    verifier.allow_boot_state()

    session = AgentId("honest-0")
    hail = honest.make_hail(report_kind="positive")
    vouch = verifier.make_vouch(hail, session_key=session)
    seal = honest.make_seal(vouch)
    raw = bytearray(base64.b64decode(seal["sig"]))
    raw[flip % len(raw)] ^= 0x01
    seal["sig"] = base64.b64encode(bytes(raw)).decode("ascii")

    verdict = verifier.evaluate_seal(session, seal)
    assert verdict.decision == "DENY"
    assert not verdict.friend_or_foe.ok


@settings(max_examples=20, deadline=None)
@given(seed=st.integers(min_value=0, max_value=2**16))
def test_property_report_order_invariant(seed: int) -> None:
    """The victim's admitted score is independent of the order reports arrive in.

    Only honest reporters are admitted, so their positive evidence yields 1.0
    regardless of interleaving with quarantined Sybil reports.
    """
    rng = random.Random(seed)
    verifier = _verifier()
    honest_ids = [AgentId(f"honest-{i}") for i in range(4)]
    verifier.allow_boot_state()
    for hid in honest_ids:
        h = AttestedPeeringTrust(agent_id=hid, seed=b"prop", operator_seed=_OP, offer_env=True)
        verifier.trust_operator(h.operator_id, h.operator_public_key)
        _handshake(verifier, h, str(hid))  # admit the honest reporter

    reports = [
        Evidence(reporter=hid, subject=AgentId("victim"), kind="positive") for hid in honest_ids
    ] + [
        Evidence(reporter=AgentId(f"sybil-{i}"), subject=AgentId("victim"), kind="negative")
        for i in range(6)
    ]
    rng.shuffle(reports)
    for ev in reports:
        _run(verifier.report(AgentId("victim"), ev))

    rep = _run(verifier.score(AgentId("victim")))
    assert rep.sample_count == len(honest_ids)
    assert rep.score == 1.0


# ---------------------------------------------------------------------------
# 3./4. Full simulator integration, discrimination, determinism
# ---------------------------------------------------------------------------

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "attested_peering.yaml"
_SEEDS = [42, 7, 1337]


def _run_scenario(seed: int, trust_plugin: str) -> dict[str, ValidationResult]:
    """Run the scenario under a given trust plugin and return validator results."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": seed})
    config = config.model_copy(
        update={"layers": config.layers.model_copy(update={"trust": trust_plugin})}
    )
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"ap_{trust_plugin}_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        asyncio.run(ScenarioRunner(config, registry=PluginRegistry()).run())
        results = validate_trace(trace_path, "attested_peering")
    return {r.name: r for r in results}


def _run_bytes(seed: int) -> bytes:
    """Run the scenario and return the raw trace bytes."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": seed})
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / "ap_replay.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        asyncio.run(ScenarioRunner(config, registry=PluginRegistry()).run())
        return trace_path.read_bytes()


@pytest.mark.parametrize("seed", _SEEDS)
def test_scenario_attested_passes_every_validator(seed: int) -> None:
    """With attested_peering, both gate validators pass at every seed."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    results = _run_scenario(seed, "attested_peering")
    expected = {"attested_no_denied_admitted", "attested_sybil_quarantined"}
    assert expected <= set(results), f"missing validators: {expected - set(results)}"
    for name, res in results.items():
        assert res.passed, f"seed={seed} {name} failed: {res.detail}"


@pytest.mark.parametrize("seed", _SEEDS)
def test_scenario_baseline_fails_sybil_but_attested_passes(seed: int) -> None:
    """The discriminator: score_average admits the Sybil swarm; attested does not.

    The safety validator (no denied peer admitted) holds for both — the baseline
    simply runs no handshake, so it has nothing to admit incorrectly. The
    Sybil-quarantine validator is the property that separates the two plugins.
    """
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    baseline = _run_scenario(seed, "score_average")
    assert not baseline["attested_sybil_quarantined"].passed, (
        f"seed={seed}: baseline should be defamed but passed: "
        f"{baseline['attested_sybil_quarantined'].detail}"
    )

    ours = _run_scenario(seed, "attested_peering")
    assert ours["attested_sybil_quarantined"].passed, (
        f"seed={seed}: attested plugin failed: {ours['attested_sybil_quarantined'].detail}"
    )


def test_scenario_is_byte_deterministic() -> None:
    """Two runs at the same seed produce byte-identical traces."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    assert _run_bytes(42) == _run_bytes(42)
