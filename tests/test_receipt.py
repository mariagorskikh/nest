import json
import os

import pytest
from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_a2a_app, build_agent_card
from nandatown.cli import main
from nandatown.path_runner import run_path_test
from nandatown.receipt import make_receipt, render_proof, verify_receipt
from nandatown.records import fingerprint


def passed_bundle(tmp_path):
    expected = fingerprint(build_agent_card("http://testserver"))
    bundle_dir, result = run_path_test(
        "http://testserver", str(tmp_path),
        pin_card_digest=expected,
        http=TestClient(build_a2a_app("http://testserver")))
    assert result.verdict == "passed"
    return bundle_dir


def failed_bundle(tmp_path):
    expected = fingerprint(build_agent_card("http://testserver"))
    bundle_dir, result = run_path_test(
        "http://testserver", str(tmp_path / "bad"),
        pin_card_digest=expected,
        http=TestClient(build_a2a_app("http://testserver",
                                      defect="wrong_total")))
    assert result.verdict == "failed"
    return bundle_dir


def test_receipt_is_sanitized_signed_and_verifiable(tmp_path):
    bundle_dir = passed_bundle(tmp_path)
    path = make_receipt(bundle_dir)
    assert verify_receipt(path, bundle_dir=bundle_dir) == []
    with open(path) as f:
        receipt = json.load(f)
    payload = receipt["payload"]
    assert payload["claim"]["capability"] == "quote"
    assert payload["claim"]["verdict"] == "passed"
    assert payload["observer"].startswith("did:town:")
    assert "semantic_result" in payload["coverage"]["tested"]
    assert payload["limitations"]
    text = json.dumps(receipt)
    assert "widget" not in text
    assert "sku" not in text
    assert "unit_price_cents" not in text
    assert "quantity" not in text
    assert "request_id" not in text


def test_tampered_receipt_is_caught(tmp_path):
    bundle_dir = passed_bundle(tmp_path)
    path = make_receipt(bundle_dir)
    with open(path) as f:
        receipt = json.load(f)
    receipt["payload"]["claim"]["verdict"] = "passed-forever"
    with open(path, "w") as f:
        json.dump(receipt, f)
    problems = verify_receipt(path, bundle_dir=bundle_dir)
    assert any("signature" in p for p in problems)


@pytest.mark.parametrize("bad_not_tested", [None, [1]])
def test_proof_refuses_receipt_with_tampered_coverage_shape(
        tmp_path, bad_not_tested):
    bundle_dir = passed_bundle(tmp_path)
    path = make_receipt(bundle_dir)
    with open(path) as f:
        receipt = json.load(f)
    if bad_not_tested is None:
        del receipt["payload"]["coverage"]["not_tested"]
    else:
        receipt["payload"]["coverage"]["not_tested"] = bad_not_tested
    with open(path, "w") as f:
        json.dump(receipt, f)

    ok, text = render_proof(bundle_dir)
    assert not ok
    assert "TOWN-TESTED" not in text
    assert "signature" in text


def test_proof_renders_only_from_passing_fresh_evidence(tmp_path):
    bundle_dir = passed_bundle(tmp_path)
    path = make_receipt(bundle_dir)
    assert verify_receipt(path, bundle_dir=bundle_dir) == []
    with open(path) as f:
        receipt = json.load(f)
    assert receipt["payload"]["coverage"]["not_tested"] == []

    ok, text = render_proof(bundle_dir)
    assert ok, text
    assert "TOWN-TESTED" in text
    assert "observed to pass for release basis sha256:" in text
    assert "narrow and expiring" in text

    bad_dir = failed_bundle(tmp_path)
    ok, text = render_proof(bad_dir)
    assert not ok
    assert "No Town Proof" in text
    assert "verdict is failed" in text


def test_partial_coverage_receipt_verifies_but_refuses_proof(tmp_path):
    bundle_dir, result = run_path_test(
        "http://testserver", str(tmp_path),
        http=TestClient(build_a2a_app("http://testserver")))
    assert result.verdict == "passed"

    path = make_receipt(bundle_dir)
    with open(path) as f:
        receipt = json.load(f)
    assert receipt["payload"]["coverage"]["not_tested"] == [
        "descriptor_consistency"]
    assert verify_receipt(path, bundle_dir=bundle_dir) == []

    ok, text = render_proof(bundle_dir)
    assert not ok
    assert "TOWN-TESTED" not in text
    assert "coverage is incomplete" in text
    assert "descriptor_consistency" in text


def test_stale_evidence_refuses_a_badge(tmp_path):
    bundle_dir = passed_bundle(tmp_path)
    path = make_receipt(bundle_dir)
    ok, text = render_proof(bundle_dir, freshness_days=0.0)
    assert not ok
    assert "freshness" in text
    assert os.path.exists(path)


def test_cli_receipt_verify_proof(tmp_path, capsys):
    bundle_dir = passed_bundle(tmp_path)
    assert main(["receipt", bundle_dir]) == 0
    assert main(["verify-receipt", f"{bundle_dir}/receipt.json",
                 "--bundle", bundle_dir]) == 0
    assert main(["proof", bundle_dir]) == 0
    out = capsys.readouterr().out
    assert "TOWN-TESTED" in out
    assert "commitment is not truth" in out
