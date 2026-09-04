import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_a2a_app, build_agent_card
from nandatown.bundle import attest_bundle, verify_bundle
from nandatown.cli import main
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
