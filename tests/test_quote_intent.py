"""Quote-intent regressions inspired by legacy PR #215, without payment rails."""

import json
import os
import subprocess
import sys

import httpx
import pytest
from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_agent_card, build_a2a_app
from nandatown.bundle import load_bundle, verify_bundle
from nandatown.path_runner import evaluate_path, run_path_test
from nandatown.records import fingerprint
from nandatown.report import render_report

SUBJECT = "http://testserver"
PROFILE = "a2a-quote-intent@0.1"
MISSING = object()


def quote_client(changes=None, *, artifact=MISSING, duplicate=False):
    """A deterministic peer at the HTTP boundary, not a mocked evaluator."""
    attempts = 0

    def handle(request):
        nonlocal attempts
        if request.method == "GET":
            return httpx.Response(200, json=build_agent_card(SUBJECT))
        envelope = json.loads(request.content)
        order = json.loads(envelope["params"]["message"]["parts"][0]["text"])
        attempts += 1
        quote = {"request_id": order["request_id"], "total_cents": 3990,
                 "sku": "widget", "quantity": 2, "color": "blue",
                 "merchant_id": "town-reference", "currency": "USD"}
        for key, value in (changes or {}).items():
            if value is MISSING:
                quote.pop(key)
            else:
                quote[key] = value
        if duplicate and attempts == 2:
            quote["quote_revision"] = "different"
        payload = quote if artifact is MISSING else artifact
        task = {"id": f"task-{attempts}", "kind": "task",
                "status": {"state": "completed"},
                "artifacts": [{"artifactId": "quote", "parts": [
                    {"kind": "text", "text": json.dumps(payload)}]}]}
        return httpx.Response(200, json={"jsonrpc": "2.0",
                                        "id": envelope["id"], "result": task})

    return httpx.Client(base_url=SUBJECT, transport=httpx.MockTransport(handle))


def run_quote(tmp_path, **kwargs):
    with quote_client(**kwargs) as http:
        return run_path_test(SUBJECT, str(tmp_path), profile_ref=PROFILE,
                             pin_card_digest=fingerprint(build_agent_card(SUBJECT)),
                             http=http)


@pytest.mark.parametrize(("field", "value"), [
    ("sku", "other-widget"), ("color", "red"), ("quantity", 1),
    ("quantity", True), ("quantity", 2.0), ("merchant_id", "other-merchant"),
    ("currency", "EUR"), ("sku", None), ("color", MISSING),
    ("merchant_id", MISSING), ("currency", MISSING), ("quantity", MISSING),
])
def test_wrong_or_missing_quote_term_fails_even_at_the_expected_price(
        tmp_path, field, value):
    # Removing any one field comparison must let its wrong/missing case escape.
    directory, result = run_quote(tmp_path, changes={field: value})
    stages = {s.name: s for s in result.stages}
    assert stages["protocol_invocation"].status == "passed"
    assert stages["semantic_result"].status == "failed"
    assert field in stages["semantic_result"].note
    assert result.verdict == "failed"
    assert verify_bundle(directory) == []
    assert "First broken stage: semantic_result" in render_report(load_bundle(directory))


@pytest.mark.parametrize("total", [0, 1, 3000, 3990])
def test_matching_quote_within_budget_passes_and_replays(tmp_path, total):
    directory, result = run_quote(tmp_path, changes={"total_cents": total})
    assert result.verdict == "passed"
    assert verify_bundle(directory) == []
    bundle = load_bundle(directory)
    event = next(e for e in bundle["events"]
                 if e.kind == "fulfillment_observed" and e.detail["attempt"] == 1)
    assert event.detail["quote"] == {
        "sku": "widget", "color": "blue", "quantity": 2,
        "merchant_id": "town-reference", "currency": "USD"}
    assert event.detail["total_cents"] == total
    assert "--path-profile a2a-quote-intent@0.1" in bundle["run"].config["rerun_command"]


def test_cheaper_wrong_item_is_not_a_successful_discount(tmp_path):
    directory, result = run_quote(
        tmp_path, changes={"sku": "other-widget", "color": "red", "total_cents": 3000})
    semantic = next(s for s in result.stages if s.name == "semantic_result")
    assert semantic.status == "failed"
    assert "sku" in semantic.note and "color" in semantic.note
    assert verify_bundle(directory) == []


@pytest.mark.parametrize("total", [3991, -1, True, False, 3990.0, "3990", None, MISSING])
def test_quote_budget_requires_nonnegative_integer_cents(tmp_path, total):
    directory, result = run_quote(tmp_path, changes={"total_cents": total})
    semantic = next(s for s in result.stages if s.name == "semantic_result")
    assert semantic.status == "failed"
    assert "total_cents" in semantic.note
    assert verify_bundle(directory) == []


@pytest.mark.parametrize("request_id", ["old-order", "", None, MISSING])
def test_intent_quote_still_requires_current_request_id(tmp_path, request_id):
    directory, result = run_quote(tmp_path, changes={"request_id": request_id})
    semantic = next(s for s in result.stages if s.name == "semantic_result")
    assert semantic.status == "failed"
    assert "request_id" in semantic.note
    assert verify_bundle(directory) == []


@pytest.mark.parametrize("artifact", [None, [], 1, "not a quote"])
def test_nonobject_quote_artifact_is_subject_semantic_failure(tmp_path, artifact):
    directory, result = run_quote(tmp_path, artifact=artifact)
    stages = {s.name: s.status for s in result.stages}
    assert stages["protocol_invocation"] == "passed"
    assert stages["semantic_result"] == "failed"
    assert result.verdict == "failed"
    assert verify_bundle(directory) == []


def test_second_distinct_quote_remains_a_duplicate_failure(tmp_path):
    directory, result = run_quote(tmp_path, duplicate=True)
    stages = {s.name: s.status for s in result.stages}
    assert stages["semantic_result"] == "passed"
    assert stages["duplicate_request"] == "failed"
    assert verify_bundle(directory) == []


@pytest.mark.parametrize("profile", [
    "a2a-capability-fulfillment@0.1", "a2a-capability-fulfillment@0.2"])
def test_price_only_profiles_keep_their_old_contract_and_replay(tmp_path, profile):
    with quote_client({"sku": "different", "color": "red"}) as http:
        directory, result = run_path_test(
            SUBJECT, str(tmp_path), profile_ref=profile, http=http)
    assert result.verdict == "passed"
    assert result.evaluator_version == "path-0.2"
    assert verify_bundle(directory) == []


def test_reference_seller_supports_the_explicit_item_quote(tmp_path):
    with TestClient(build_a2a_app(SUBJECT)) as http:
        directory, result = run_path_test(
            SUBJECT, str(tmp_path), profile_ref=PROFILE, http=http)
    assert result.verdict == "passed"
    assert verify_bundle(directory) == []


def test_reference_wrong_item_demonstrates_cheaper_substitution(tmp_path):
    with TestClient(build_a2a_app(SUBJECT, defect="wrong_item")) as http:
        directory, result = run_path_test(
            SUBJECT, str(tmp_path), profile_ref=PROFILE, http=http)
    bundle = load_bundle(directory)
    observed = next(e for e in bundle["events"]
                    if e.kind == "fulfillment_observed")
    assert observed.detail["total_cents"] == 3000
    assert observed.detail["quote"]["color"] == "red"
    semantic = next(s for s in result.stages if s.name == "semantic_result")
    assert semantic.status == "failed"
    assert "color" in semantic.note
    assert verify_bundle(directory) == []


def test_quote_evidence_replays_without_a_running_peer(tmp_path):
    directory, result = run_quote(tmp_path)
    # The client is closed. A fresh interpreter must load the shipped profile
    # and select the matching evaluator, rather than rely on this process.
    checked = subprocess.run([
        sys.executable, "-c",
        "import json,sys; from nandatown.bundle import verify_bundle; "
        "print(json.dumps(verify_bundle(sys.argv[1])))", directory,
    ], capture_output=True, text=True, check=True, env=dict(os.environ))
    assert json.loads(checked.stdout) == []
    bundle = load_bundle(directory)
    assert bundle["run"].releases["evaluator"] == result.evaluator_version
    assert result.evaluator_version != "path-0.2"
    events = [event.model_copy(deep=True) for event in bundle["events"]]
    first = next(e for e in events if e.kind == "fulfillment_observed")
    first.detail["quote"]["color"] = "red"
    replay = evaluate_path(bundle["profile"], result.run_id, events)
    assert next(s for s in replay.stages if s.name == "semantic_result").status == "failed"
