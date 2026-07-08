# SPDX-License-Identifier: Apache-2.0
"""Synthetic-trace tests for the pre-rotation adversarial validator.

Both directions are exercised: honest traces (attacks present but rejected)
PASS, and traces where any of the five checks is violated FAIL — including
the hijack-acceptance shapes a reactive-rotation validator cannot see.

Example::

    pytest packages/nest-core/tests/chainaim/test_identity_prerotation.py
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId
from nest_core.validators import validate_identity_prerotation, validate_trace
from nest_plugins_reference.identity.ed25519_prerotation import (
    Ed25519PreRotatingIdentity,
)

type Event = dict[str, Any]


def _send(agent: str, msg: str, ts: float) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": "auditor", "msg": msg}


def _kid(label: str) -> str:
    """A realistic key id: the sha256 hexdigest of a label."""
    return hashlib.sha256(label.encode()).hexdigest()


K0, K1, K2 = _kid("s0-k0"), _kid("s0-k1"), _kid("s0-k2")
KX = _kid("attacker-chosen")  # hijack successor, never committed


def _commit(agent: str, key_id: str, next_key_id: str, ts: float) -> Event:
    return _send(agent, f"commit:{agent}:{key_id}:sha256:{next_key_id}:{ts}", ts)


def _honest_trace() -> list[Event]:
    """Inception commit; K0 signs; bound rotation to K1; K1 signs."""
    return [
        _commit("s0", K0, K1, 0.0),
        _send("s0", f"signed:s0:{K0}:0.0:ok", 0.0),
        _send("s0", f"signed:s0:{K0}:1.0:ok", 1.0),
        _send("s0", f"rotate:s0:{K0}:{K1}:2.0", 2.0),
        _commit("s0", K1, K2, 2.0),
        _send("s0", f"signed:s0:{K1}:2.0:ok", 2.0),
        _send("s0", f"signed:s0:{K1}:3.0:ok", 3.0),
    ]


def _hijack_trace() -> list[Event]:
    """Hijack attempt at tick 2 rejected; recovery rotation at tick 3."""
    return [
        _commit("s0", K0, K1, 0.0),
        _send("s0", f"signed:s0:{K0}:0.0:ok", 0.0),
        _send("s0", f"rotate_attempt:s0:{K0}:sha256:{KX}:sha256:{K1}:2.0:hijack", 2.0),
        _send("s0", f"rotate:s0:{K0}:{K1}:3.0", 3.0),
        _commit("s0", K1, K2, 3.0),
        _send("s0", f"signed:s0:{K1}:3.0:ok", 3.0),
    ]


class TestHonestDirection:
    def test_honest_trace_passes(self) -> None:
        res = validate_identity_prerotation(_honest_trace())[0]
        assert res.passed, res.detail
        assert "1 rotations commitment-bound" in res.detail

    def test_rejected_window_attacks_pass(self) -> None:
        events = [
            *_honest_trace(),
            _send("s0", f"signed:s0:{K0}:3.0:forge", 3.0),  # stale key, late
            _send("s0", f"signed:s0:{K1}:0.0:backdate", 3.0),  # new key, old tick
        ]
        res = validate_identity_prerotation(events)[0]
        assert res.passed, res.detail
        assert "2 attacks rejected" in res.detail

    def test_rejected_hijack_with_recovery_passes(self) -> None:
        res = validate_identity_prerotation(_hijack_trace())[0]
        assert res.passed, res.detail
        assert "1 hijacks rejected" in res.detail
        assert "1 recoveries verified" in res.detail

    def test_empty_trace_vacuously_passes(self) -> None:
        # Composition covers emptiness: identity_rotation_occurred fails it.
        assert validate_identity_prerotation([]).pop().passed


class TestAttackDirection:
    def test_rotation_without_commitment_fails(self) -> None:
        # ed25519_rotating-shaped trace: rotates, never commits.
        events = [
            _send("s0", f"signed:s0:{K0}:0.0:ok", 0.0),
            _send("s0", f"rotate:s0:{K0}:{K1}:2.0", 2.0),
            _send("s0", f"signed:s0:{K1}:3.0:ok", 3.0),
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "no prior commitment" in res.detail

    def test_revealed_key_mismatch_fails(self) -> None:
        events = [
            _commit("s0", K0, K1, 0.0),
            _send("s0", f"rotate:s0:{K0}:{KX}:2.0", 2.0),  # not the committed K1
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "does not match commitment" in res.detail

    def test_unrecomputable_commitment_alg_fails(self) -> None:
        events = [
            _send("s0", f"commit:s0:{K0}:sha512:{'a' * 128}:0.0", 0.0),
            _send("s0", f"rotate:s0:{K0}:{K1}:2.0", 2.0),
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "not recomputable" in res.detail

    def test_hijack_digest_matching_commitment_fails(self) -> None:
        events = [
            _commit("s0", K0, K1, 0.0),
            _send("s0", f"rotate_attempt:s0:{K0}:sha256:{K1}:sha256:{K1}:2.0:hijack", 2.0),
            _send("s0", f"rotate:s0:{K0}:{K1}:3.0", 3.0),
            _commit("s0", K1, K2, 3.0),
            _send("s0", f"signed:s0:{K1}:3.0:ok", 3.0),
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "matched the commitment" in res.detail

    def test_hijacked_key_signing_validly_fails(self) -> None:
        # The check reactive rotation misses: the attacker key must never be
        # lazily trusted as a "first key" when it later signs with verdict ok.
        events = [
            _commit("s0", K0, K1, 0.0),
            _send("s0", f"rotate_attempt:s0:{K0}:sha256:{KX}:sha256:{K1}:2.0:hijack", 2.0),
            _send("s0", f"rotate:s0:{K0}:{K1}:3.0", 3.0),
            _commit("s0", K1, K2, 3.0),
            _send("s0", f"signed:s0:{K1}:3.0:ok", 3.0),
            _send("s0", f"signed:s0:{KX}:4.0:ok", 4.0),  # attacker signs, claims ok
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "hijacked key" in res.detail

    def test_hijacked_key_applied_as_rotation_fails(self) -> None:
        events = [
            _commit("s0", K0, K1, 0.0),
            _send("s0", f"rotate_attempt:s0:{K0}:sha256:{KX}:sha256:{K1}:2.0:hijack", 2.0),
            _send("s0", f"rotate:s0:{K0}:{KX}:2.0", 2.0),  # protocol applied the hijack
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "was applied as a rotation" in res.detail

    def test_missing_recovery_fails(self) -> None:
        events = [
            _commit("s0", K0, K1, 0.0),
            _send("s0", f"signed:s0:{K0}:0.0:ok", 0.0),
            _send("s0", f"rotate_attempt:s0:{K0}:sha256:{KX}:sha256:{K1}:2.0:hijack", 2.0),
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "never recovered" in res.detail

    def test_recovery_key_never_signing_fails(self) -> None:
        events = [
            _commit("s0", K0, K1, 0.0),
            _send("s0", f"rotate_attempt:s0:{K0}:sha256:{KX}:sha256:{K1}:2.0:hijack", 2.0),
            _send("s0", f"rotate:s0:{K0}:{K1}:3.0", 3.0),
            _commit("s0", K1, K2, 3.0),
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "never signed validly" in res.detail

    def test_honest_signature_outside_window_fails(self) -> None:
        events = [
            *_honest_trace(),
            _send("s0", f"signed:s0:{K0}:5.0:ok", 5.0),  # K0 closed at 2.0
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "not in a valid window" in res.detail

    def test_window_valid_forge_fails(self) -> None:
        events = [
            *_honest_trace(),
            _send("s0", f"signed:s0:{K1}:3.5:forge", 3.5),  # inside K1's window
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed
        assert "accepted" in res.detail

    def test_did_key_style_trace_fails_without_crashing(self) -> None:
        events = [
            _send("s0", "signed:s0:None:0.0:ok", 0.0),
            _send("s0", "signed:s0:None:1.0:ok", 1.0),
        ]
        res = validate_identity_prerotation(events)[0]
        assert not res.passed


# ---------------------------------------------------------------------------
# End-to-end scenario tests (runner + trace + registry-dispatched validators)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_OUR_YAML = _REPO_ROOT / "scenarios" / "identity_prerotation.yaml"
_MERGED_YAML = _REPO_ROOT / "scenarios" / "identity_rotation.yaml"


def _config(yaml_path: Path, trace: Path, identity: str) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(yaml_path)
    config.layers.identity = identity
    config.output.trace = str(trace)
    return config


async def _run_and_validate(
    yaml_path: Path, trace: Path, identity: str, scenario_type: str
) -> tuple[Path, list[Any]]:
    runner = ScenarioRunner(_config(yaml_path, trace, identity))
    result = await runner.run()
    return result, validate_trace(result, scenario_type)


class TestScenarioEndToEnd:
    @pytest.mark.asyncio
    async def test_passes_against_ed25519_prerotation(self, tmp_path: Path) -> None:
        result, results = await _run_and_validate(
            _OUR_YAML, tmp_path / "ours.jsonl", "ed25519_prerotation", "identity_prerotation"
        )
        assert all(r.passed for r in results), [str(r) for r in results]
        # Sanity: commitments, rotations, all three attack kinds in the trace.
        text = result.read_text()
        for token in ("commit:", "rotate:", "rotate_attempt:", ":forge", ":backdate", ":hijack"):
            assert token in text, f"missing {token} lines"

    @pytest.mark.asyncio
    async def test_registry_dispatch_composes_both_validators(self, tmp_path: Path) -> None:
        _, results = await _run_and_validate(
            _OUR_YAML, tmp_path / "dispatch.jsonl", "ed25519_prerotation", "identity_prerotation"
        )
        assert [r.name for r in results] == [
            "identity_rotation_occurred",
            "identity_prerotation",
        ]

    @pytest.mark.asyncio
    async def test_deterministic_byte_identical(self, tmp_path: Path) -> None:
        traces: list[bytes] = []
        for i in range(2):
            trace = tmp_path / f"det-{i}.jsonl"
            await ScenarioRunner(_config(_OUR_YAML, trace, "ed25519_prerotation")).run()
            traces.append(trace.read_bytes())
        assert traces[0] == traces[1]
        assert len(traces[0]) > 0


class TestDiscriminationMatrix:
    """The scoring matrix: only pre-rotation survives the pre-rotation validator.

    ``did_key`` fails everything (no rotation at all); the merged
    ``ed25519_rotating`` rotates — and even passes the rotation-occurred
    check — but every one of its rotations lacks a prior commitment, so the
    pre-rotation validator fails it. Both runs complete WITHOUT crashing:
    the scenario capability-gates every identity interaction.
    """

    @pytest.mark.asyncio
    async def test_did_key_fails_without_crashing(self, tmp_path: Path) -> None:
        result, results = await _run_and_validate(
            _OUR_YAML, tmp_path / "didkey.jsonl", "did_key", "identity_prerotation"
        )
        assert not any(r.passed for r in results)
        assert "rotate:" not in result.read_text()

    @pytest.mark.asyncio
    async def test_ed25519_rotating_fails_on_commitments(self, tmp_path: Path) -> None:
        _, results = await _run_and_validate(
            _OUR_YAML, tmp_path / "rotating.jsonl", "ed25519_rotating", "identity_prerotation"
        )
        by_name = {r.name: r for r in results}
        # It genuinely rotates — the reactive capability is real...
        assert by_name["identity_rotation_occurred"].passed
        # ...but no rotation is commitment-bound: the hidden property.
        prerot = by_name["identity_prerotation"]
        assert not prerot.passed
        assert "no prior commitment" in prerot.detail

    @pytest.mark.asyncio
    async def test_ed25519_prerotation_passes(self, tmp_path: Path) -> None:
        _, results = await _run_and_validate(
            _OUR_YAML, tmp_path / "prerot.jsonl", "ed25519_prerotation", "identity_prerotation"
        )
        assert all(r.passed for r in results), [str(r) for r in results]


class TestDropInCompatibility:
    """Our plugin slots into the MERGED scenario without scenario edits.

    The merged ``identity_rotation`` scenario reads rotation evidence off
    ``rotate_key``'s return value (the merged plugin returns a record there,
    where the problem spec declares ``rotate_key(new_seed) -> KeyId``). Our
    ``KeyId`` is a ``str`` subclass that satisfies the spec's declared type
    and carries that evidence, so the merged yaml runs unmodified — only the
    identity layer is overridden programmatically — and the merged
    validators pass.
    """

    @pytest.mark.asyncio
    async def test_merged_yaml_with_our_plugin_passes_merged_validators(
        self, tmp_path: Path
    ) -> None:
        result, results = await _run_and_validate(
            _MERGED_YAML, tmp_path / "dropin.jsonl", "ed25519_prerotation", "identity_rotation"
        )
        assert all(r.passed for r in results), [str(r) for r in results]
        # The merged scenario really exercised rotation + both attacks.
        text = result.read_text()
        assert "rotate:" in text
        assert ":forge" in text
        assert ":backdate" in text

    def test_keyid_is_the_specs_return_type(self) -> None:
        # Spec: rotate_key(new_seed) -> KeyId, and a KeyId is the key id.
        ident = Ed25519PreRotatingIdentity(AgentId("a1"), seed=b"drop-in")
        returned = ident.rotate_key(b"next")
        assert isinstance(returned, str)
        assert returned == ident.current_key_id
        # The evidence the merged scenario reads is carried, not wrapped.
        assert returned.new_key_id == returned
        assert returned.old_key_id != returned
