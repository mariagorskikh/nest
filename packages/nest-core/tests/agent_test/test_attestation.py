# SPDX-License-Identifier: Apache-2.0
"""Tests for detached attestation over ``town.test-result/1``.

The round trip is one test. The rest pin the properties the signature is
supposed to carry: that every field of the result is covered, that a document
whose verdict its own checks do not support is refused, and that whether
anything was left unfrozen is always stated rather than inferred.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nest_core.agent_test import (
    ATTESTATION_SCHEMA_VERSION,
    AttestationError,
    MutableDependency,
    build_attestation,
    result_digest,
    verify_attestation,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture
def result() -> dict[str, Any]:
    return _load("result-pass")


def _sign(
    result: dict[str, Any],
    key: Ed25519PrivateKey,
    deps: list[MutableDependency] | None = None,
) -> dict[str, Any]:
    return build_attestation(result, signing_key=key, mutable_dependencies=deps or [])


def test_round_trip_verifies(result: dict[str, Any], key: Ed25519PrivateKey) -> None:
    verdict = verify_attestation(result, _sign(result, key))
    assert verdict.ok, verdict.reasons
    assert verdict.issuer_did == key.public_key().public_bytes_raw().hex()


def test_signing_does_not_modify_the_result(result: dict[str, Any], key: Ed25519PrivateKey) -> None:
    before = copy.deepcopy(result)
    _sign(result, key)
    assert result == before


def test_statement_restates_the_bindings(result: dict[str, Any], key: Ed25519PrivateKey) -> None:
    statement = _sign(result, key)
    assert statement["schema_version"] == ATTESTATION_SCHEMA_VERSION
    assert statement["profile"]["digest"] == result["profile"]["digest"]
    assert statement["execution"]["seed"] == result["execution"]["seed"]
    assert statement["evaluation"]["verdict"] == result["evaluation"]["verdict"]


def _flip_verdict(result: dict[str, Any]) -> None:
    result["evaluation"]["verdict"] = "fail"


def _change_seed(result: dict[str, Any]) -> None:
    result["execution"]["seed"] = 8


def _rename_target(result: dict[str, Any]) -> None:
    result["target"]["label"] = "someone-else"


def _widen_coverage(result: dict[str, Any]) -> None:
    result["coverage"][1]["status"] = "exercised"


def _swap_trace_digest(result: dict[str, Any]) -> None:
    result["artifacts"][0]["digest"] = "sha256:" + "11" * 32


def _swap_profile_digest(result: dict[str, Any]) -> None:
    result["profile"]["digest"] = "sha256:" + "ab" * 32


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(_flip_verdict, id="verdict"),
        pytest.param(_change_seed, id="seed"),
        pytest.param(_rename_target, id="target"),
        pytest.param(_widen_coverage, id="coverage"),
        pytest.param(_swap_trace_digest, id="trace-digest"),
        pytest.param(_swap_profile_digest, id="profile-digest"),
    ],
)
def test_any_edit_breaks_the_binding(
    result: dict[str, Any],
    key: Ed25519PrivateKey,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    """The digest covers the whole document, so every field is load-bearing."""
    statement = _sign(result, key)
    tampered = copy.deepcopy(result)
    mutate(tampered)
    verdict = verify_attestation(tampered, statement)
    assert not verdict.ok
    assert any("does not match" in reason for reason in verdict.reasons)


def test_attestation_for_another_run_is_rejected(
    result: dict[str, Any], key: Ed25519PrivateKey
) -> None:
    other = copy.deepcopy(result)
    other["run_id"] = "01K00000000000000000000009"
    assert not verify_attestation(result, _sign(other, key)).ok


def test_edited_statement_fails_the_signature(
    result: dict[str, Any], key: Ed25519PrivateKey
) -> None:
    statement = _sign(result, key)
    statement["evaluation"]["verdict"] = "fail"
    verdict = verify_attestation(result, statement)
    assert not verdict.ok
    assert verdict.reasons == ("signature does not verify",)


def test_histogram_restates_statuses_verbatim(
    result: dict[str, Any], key: Ed25519PrivateKey
) -> None:
    """Statuses are counted as they stand, never folded into coarser buckets."""
    assert _sign(result, key)["evaluation"]["check_histogram"] == {"pass": 1}


def _fail_a_required_check(result: dict[str, Any]) -> None:
    result["evaluation"]["checks"].append(
        {
            "id": "broken",
            "required": True,
            "status": "fail",
            "summary": "did not complete",
            "evidence_refs": ["trace.jsonl#seq=2"],
        }
    )


def _claim_failure_without_one(result: dict[str, Any]) -> None:
    result["evaluation"]["verdict"] = "fail"


def _use_an_unknown_status(result: dict[str, Any]) -> None:
    result["evaluation"]["checks"][0]["status"] = "probably-fine"


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        pytest.param(
            _fail_a_required_check,
            "every required check to pass",
            id="pass-over-a-failed-check",
        ),
        pytest.param(
            _claim_failure_without_one,
            "one failure and no inconclusive",
            id="fail-with-no-failure",
        ),
        pytest.param(_use_an_unknown_status, "status", id="unknown-check-status"),
    ],
)
def test_the_contract_gates_what_can_be_signed(
    result: dict[str, Any],
    key: Ed25519PrivateKey,
    mutate: Callable[[dict[str, Any]], None],
    expected: str,
) -> None:
    """Consistency is inherited from TestResult rather than re-implemented.

    Signing parses through the contract's own model, so a document the contract
    rejects can never be signed, and this module carries no second copy of those
    rules to drift out of step with it.
    """
    mutate(result)
    with pytest.raises(AttestationError, match="does not satisfy") as excinfo:
        _sign(result, key)
    assert expected in str(excinfo.value)


def test_unfrozen_dependencies_are_carried_and_surfaced(
    result: dict[str, Any], key: Ed25519PrivateKey
) -> None:
    dep = MutableDependency(
        name="a-hosted-model",
        kind="hosted-model",
        observed_at="2026-08-23T00:00:00Z",
    )
    verdict = verify_attestation(result, _sign(result, key, [dep]))
    assert verdict.ok, verdict.reasons
    assert verdict.mutable_dependencies == (
        {
            "name": "a-hosted-model",
            "kind": "hosted-model",
            "observed_at": "2026-08-23T00:00:00Z",
            "observed_version": None,
        },
    )


def test_no_unfrozen_dependencies_is_a_signed_claim(
    result: dict[str, Any], key: Ed25519PrivateKey
) -> None:
    """An empty list is present in the statement: 'none' and 'unsaid' differ."""
    assert _sign(result, key)["mutable_dependencies"] == []


def test_digest_ignores_key_order(result: dict[str, Any]) -> None:
    """JCS means presentation cannot change identity."""
    reordered = json.loads(json.dumps(result, sort_keys=True))
    assert result_digest(reordered) == result_digest(result)


def test_incomplete_result_attests(key: Ed25519PrivateKey) -> None:
    incomplete = _load("result-incomplete")
    verdict = verify_attestation(incomplete, _sign(incomplete, key))
    assert verdict.ok, verdict.reasons
