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
    bundle_dir, result = run_path_test(
        "http://testserver", str(tmp_path),
        http=TestClient(build_a2a_app("http://testserver")))
    assert result.verdict == "passed"
    return bundle_dir


def complete_passed_bundle(tmp_path):
    url = "http://testserver"
    bundle_dir, result = run_path_test(
        url, str(tmp_path),
        pin_card_digest=fingerprint(build_agent_card(url)),
        http=TestClient(build_a2a_app(url)))
    assert result.verdict == "passed"
    assert all(stage.status == "passed" for stage in result.stages)
    return bundle_dir


def failed_bundle(tmp_path):
    bundle_dir, result = run_path_test(
        "http://testserver", str(tmp_path / "bad"),
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


def test_proof_renders_only_from_passing_fresh_evidence(tmp_path):
    bundle_dir = complete_passed_bundle(tmp_path)
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


def test_stale_evidence_refuses_a_badge(tmp_path):
    bundle_dir = complete_passed_bundle(tmp_path)
    path = make_receipt(bundle_dir)
    ok, text = render_proof(bundle_dir, freshness_days=0.0)
    assert not ok
    assert "freshness" in text
    assert os.path.exists(path)


def test_cli_receipt_verify_proof(tmp_path, capsys):
    bundle_dir = complete_passed_bundle(tmp_path)
    assert main(["receipt", bundle_dir]) == 0
    assert main(["verify-receipt", f"{bundle_dir}/receipt.json",
                 "--bundle", bundle_dir]) == 0
    assert main(["proof", bundle_dir]) == 0
    out = capsys.readouterr().out
    assert "TOWN-TESTED" in out
    assert "commitment is not truth" in out


@pytest.mark.parametrize("freshness_days", [float("nan"), float("inf"), -1.0],
                         ids=["nan", "infinite", "negative"])
def test_proof_rejects_invalid_freshness_domain(tmp_path, freshness_days):
    bundle_dir = complete_passed_bundle(tmp_path)

    ok, text = render_proof(bundle_dir, freshness_days=freshness_days)

    assert not ok
    assert "freshness days must be a finite non-negative number" in text


@pytest.mark.parametrize("document", [[], {"payload": []},
                                         {"payload": {},
                                          "controller_public": [],
                                          "signature": []}],
                         ids=["list", "payload-list", "non-string-signature"])
def test_malformed_receipt_is_reported_not_raised(tmp_path, document):
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(document))

    try:
        problems = verify_receipt(str(receipt_path))
    except Exception as exc:  # pragma: no cover - the assertion is the contract
        pytest.fail(f"malformed receipt raised {type(exc).__name__}: {exc}")

    assert problems
    assert any("receipt" in problem for problem in problems)


def test_symlinked_receipt_is_rejected_before_read(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.symlink_to(target)

    problems = verify_receipt(str(receipt_path))

    assert any("not a regular file" in problem for problem in problems), problems


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_fifo_receipt_is_rejected_before_open(tmp_path, monkeypatch):
    receipt_path = tmp_path / "receipt.json"
    os.mkfifo(receipt_path)

    def forbidden_open(*_args, **_kwargs):
        pytest.fail("verify_receipt attempted to open a FIFO")

    monkeypatch.setattr("builtins.open", forbidden_open)

    problems = verify_receipt(str(receipt_path))

    assert any("not a regular file" in problem for problem in problems), problems
