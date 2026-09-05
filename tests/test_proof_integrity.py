import hashlib
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_a2a_app, build_agent_card
from nandatown.bundle import attest_bundle, verify_bundle
from nandatown.cli import main
from nandatown.identity_portable import Keystore
from nandatown.path_runner import run_path_test
from nandatown.receipt import make_receipt, render_proof, verify_receipt
from nandatown.records import fingerprint


def complete_bundle(tmp_path):
    url = "http://testserver"
    with TestClient(build_a2a_app(url)) as client:
        directory, result = run_path_test(
            url, str(tmp_path), http=client,
            pin_card_digest=fingerprint(build_agent_card(url)))
    assert result.verdict == "passed"
    assert all(stage.status == "passed" for stage in result.stages)
    return Path(directory)


def test_verified_complete_bundle_still_renders_proof(tmp_path):
    directory = complete_bundle(tmp_path)
    assert verify_bundle(str(directory)) == []

    ok, text = render_proof(str(directory))

    assert ok, text
    assert "TOWN-TESTED" in text
    assert verify_receipt(str(directory / "receipt.json")) == []


@pytest.mark.parametrize("existing_receipt", [False, True])
def test_proof_rejects_changed_evidence_before_issuing_receipt(
        tmp_path, existing_receipt):
    directory = complete_bundle(tmp_path)
    receipt_path = directory / "receipt.json"
    if existing_receipt:
        make_receipt(str(directory))
        original_receipt = receipt_path.read_bytes()

    run_path = directory / "run.json"
    run = json.loads(run_path.read_text())
    run["config"]["subject"] = "https://different-agent.invalid"
    run_path.write_text(json.dumps(run))
    assert any("run.json hash mismatch" in problem
               for problem in verify_bundle(str(directory)))

    ok, text = render_proof(str(directory))

    assert not ok
    assert "TOWN-TESTED" not in text
    assert "run.json hash mismatch" in text
    if existing_receipt:
        assert receipt_path.read_bytes() == original_receipt
        assert verify_receipt(str(receipt_path)) == []
    else:
        assert not receipt_path.exists()


def test_cli_proof_rejects_missing_evidence(tmp_path, capsys):
    directory = complete_bundle(tmp_path)
    (directory / "events.jsonl").unlink()

    assert main(["proof", str(directory)]) == 1

    text = capsys.readouterr().out
    assert "events.jsonl missing" in text
    assert "TOWN-TESTED" not in text
    assert not (directory / "receipt.json").exists()


def test_proof_requires_evaluator_replay_not_just_valid_signatures(tmp_path):
    directory = complete_bundle(tmp_path)
    events_path = directory / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    for event in events:
        if event["kind"] == "fulfillment_observed":
            event["detail"]["total_cents"] = 4090
    events_path.write_text("".join(json.dumps(event) + "\n" for event in events))
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["events.jsonl"] = (
        "sha256:" + hashlib.sha256(events_path.read_bytes()).hexdigest())
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    manifest_path.write_text(json.dumps(manifest))
    # Valid signatures commit to these bytes; they do not make the
    # recorded passing verdict agree with the changed observations.
    attest_bundle(str(directory))
    path = make_receipt(str(directory))
    assert verify_receipt(path, str(directory)) == []
    assert any("evaluator replay mismatch" in problem
               for problem in verify_bundle(str(directory)))

    ok, text = render_proof(str(directory))

    assert not ok
    assert "evaluator replay mismatch" in text
    assert "TOWN-TESTED" not in text


def test_partial_receipt_remains_independently_verifiable(tmp_path):
    url = "http://testserver"
    with TestClient(build_a2a_app(url)) as client:
        directory, result = run_path_test(url, str(tmp_path), http=client)
    assert result.verdict == "passed"
    assert any(stage.status == "not_tested" for stage in result.stages)

    path = make_receipt(directory)

    assert verify_receipt(path) == []
    assert verify_receipt(path, directory) == []

    ok, text = render_proof(directory)

    assert not ok
    assert "descriptor_consistency" in text
    assert "not tested" in text


def _resign_changed_receipt(directory, keys, path, value):
    receipt_path = directory / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    target = receipt["payload"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    receipt["signature"] = keys.sign("reviewer", receipt["payload"])
    receipt_path.write_text(json.dumps(receipt))
    return receipt_path


@pytest.mark.parametrize(
    ("field", "path", "value"),
    [
        ("claim verdict", ("claim", "verdict"), "failed"),
        ("claim subject", ("claim", "subject"), "other-agent"),
        ("claim capability", ("claim", "capability"), "other-capability"),
        ("claim profile", ("claim", "profile"), "other-profile"),
        ("claim release basis", ("claim", "release_basis"),
         {"profile_fingerprint": "sha256:other"}),
        ("coverage", ("coverage",), {"tested": ["invented"],
                                      "not_tested": []}),
        ("evidence run id", ("evidence", "run_id"), "other-run"),
        ("window", ("window",), {"started": 1.0, "evaluated": 2.0}),
    ],
)
def test_bundle_aware_verification_rejects_validly_resigned_false_claims(
        tmp_path, field, path, value):
    directory = complete_bundle(tmp_path)
    keys = Keystore(str(tmp_path / "keys"))
    make_receipt(str(directory), keystore=keys, signer="reviewer")
    receipt_path = _resign_changed_receipt(directory, keys, path, value)

    assert verify_receipt(str(receipt_path)) == []
    problems = verify_receipt(str(receipt_path), str(directory))

    assert any(field in problem for problem in problems), problems


def test_validly_resigned_pass_claim_cannot_badge_failed_bundle(tmp_path):
    url = "http://testserver"
    with TestClient(build_a2a_app(url, defect="wrong_total")) as client:
        directory_text, result = run_path_test(
            url, str(tmp_path), http=client,
            pin_card_digest=fingerprint(build_agent_card(url)))
    assert result.verdict == "failed"
    directory = Path(directory_text)
    keys = Keystore(str(tmp_path / "keys"))
    make_receipt(str(directory), keystore=keys, signer="reviewer")
    receipt_path = _resign_changed_receipt(
        directory, keys, ("claim", "verdict"), "passed")
    assert verify_receipt(str(receipt_path)) == []

    ok, text = render_proof(str(directory))

    assert not ok
    assert "claim verdict" in text
    assert "TOWN-TESTED" not in text


def test_malformed_existing_receipt_refuses_proof_without_crashing(tmp_path):
    directory = complete_bundle(tmp_path)
    (directory / "receipt.json").write_text("{}")

    try:
        ok, text = render_proof(str(directory))
    except Exception as exc:  # pragma: no cover - the assertion is the contract
        pytest.fail(f"malformed receipt raised {type(exc).__name__}: {exc}")

    assert not ok
    assert "receipt" in text
    assert "TOWN-TESTED" not in text


def test_make_receipt_does_not_write_through_dangling_symlink(tmp_path):
    directory = complete_bundle(tmp_path)
    outside = tmp_path / "outside-receipt.json"
    (directory / "receipt.json").symlink_to(outside)

    with pytest.raises(ValueError, match="regular file"):
        make_receipt(str(directory))

    assert not outside.exists()


def test_proof_rejects_dangling_receipt_symlink_without_creating_target(
        tmp_path):
    directory = complete_bundle(tmp_path)
    outside = tmp_path / "outside-receipt.json"
    (directory / "receipt.json").symlink_to(outside)

    ok, text = render_proof(str(directory))

    assert not ok
    assert "not a regular file" in text
    assert not outside.exists()


@pytest.mark.parametrize(
    ("evaluated_at", "reason"),
    [(float("nan"), "finite"), (float("inf"), "finite"),
     (float("-inf"), "finite"), (time.time() + 86400, "future")],
    ids=["nan", "positive-infinity", "negative-infinity", "future"],
)
def test_proof_rejects_invalid_evidence_timestamp(
        tmp_path, evaluated_at, reason):
    directory = complete_bundle(tmp_path)
    result_path = directory / "result.json"
    result = json.loads(result_path.read_text())
    result["evaluated_at"] = evaluated_at
    result_path.write_text(json.dumps(result))
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["result.json"] = (
        "sha256:" + hashlib.sha256(result_path.read_bytes()).hexdigest())
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    manifest_path.write_text(json.dumps(manifest))
    attest_bundle(str(directory))
    assert verify_bundle(str(directory)) == []

    try:
        ok, text = render_proof(str(directory))
    except Exception as exc:  # pragma: no cover - public proof boundary
        pytest.fail(f"invalid evidence timestamp raised {type(exc).__name__}: {exc}")

    assert not ok
    assert reason in text.lower()
    assert "TOWN-TESTED" not in text
