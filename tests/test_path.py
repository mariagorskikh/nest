import json

import httpx
import pytest
from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_a2a_app, build_agent_card
from nandatown.bundle import load_bundle, verify_bundle
from nandatown.path_profiles import get_path_profile
from nandatown.path_runner import run_path_test
from nandatown.records import fingerprint
from nandatown.report import render_report

SUBJECT = "http://testserver"
MISSING_REQUEST_ID = object()


def client(defect=None):
    return TestClient(build_a2a_app(SUBJECT, defect=defect))


def fulfillment_id_client(returned_request_id):
    """In-process A2A service whose fulfillment ID may differ from its order."""
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=build_agent_card(SUBJECT))

        message = json.loads(request.content)
        text = message["params"]["message"]["parts"][0]["text"]
        order = json.loads(text)
        fulfillment = {"total_cents": 3990}
        if returned_request_id is not MISSING_REQUEST_ID:
            fulfillment["request_id"] = (
                order["request_id"]
                if returned_request_id == "matching"
                else returned_request_id
            )
        task = {
            "id": "task-1",
            "kind": "task",
            "status": {"state": "completed"},
            "artifacts": [{"parts": [{"kind": "text",
                                         "text": json.dumps(fulfillment)}]}],
        }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                         "result": task})

    return httpx.Client(base_url=SUBJECT,
                        transport=httpx.MockTransport(handler))


def stage(result, name):
    return {s.name: s for s in result.stages}[name]


def statuses(result):
    return {s.name: s.status for s in result.stages}


def test_healthy_agent_passes_the_path(tmp_path):
    bundle_dir, result = run_path_test(SUBJECT, str(tmp_path),
                                       http=client())
    s = statuses(result)
    assert result.verdict == "passed", s
    for name in ["resolution", "agent_card_retrieval",
                 "protocol_invocation", "semantic_result",
                 "duplicate_request"]:
        assert s[name] == "passed", s
    assert s["descriptor_consistency"] == "not_tested"
    assert verify_bundle(bundle_dir) == []
    report = render_report(load_bundle(bundle_dir))
    assert "already-running external agent" in report
    assert "Rerun:" in report
    assert "First broken stage" not in report


def test_pinned_digest_match_passes_descriptor(tmp_path):
    expected = fingerprint(build_agent_card(SUBJECT))
    _, result = run_path_test(SUBJECT, str(tmp_path),
                              pin_card_digest=expected, http=client())
    assert stage(result, "descriptor_consistency").status == "passed"
    assert result.verdict == "passed"


def test_card_mismatch_names_both_digests_and_halts(tmp_path):
    bundle_dir, result = run_path_test(SUBJECT, str(tmp_path),
                                       pin_card_digest="sha256:deadbeef",
                                       http=client())
    s = statuses(result)
    consistency = stage(result, "descriptor_consistency")
    assert consistency.status == "failed"
    assert "expected card sha256:deadbeef" in consistency.note
    assert "observed" in consistency.note
    assert s["protocol_invocation"] == "not_tested"
    assert s["semantic_result"] == "not_tested"
    assert result.verdict == "failed"
    report = render_report(load_bundle(bundle_dir))
    assert "First broken stage: descriptor_consistency" in report


def test_wrong_total_fails_semantics_only(tmp_path):
    _, result = run_path_test(SUBJECT, str(tmp_path),
                              http=client("wrong_total"))
    s = statuses(result)
    assert s["protocol_invocation"] == "passed"
    semantic = stage(result, "semantic_result")
    assert semantic.status == "failed"
    assert "expected total 3990, observed 4090" in semantic.note
    assert result.verdict == "failed"


@pytest.mark.parametrize(
    ("returned_request_id", "passes"),
    [
        ("matching", True),
        ("order-from-an-earlier-run", False),
        ("unrelated-request", False),
        (MISSING_REQUEST_ID, False),
        (None, False),
    ],
    ids=["matching", "stale-order", "other", "missing", "null"],
)
def test_fulfillment_request_id_must_exactly_match_issued_order_and_replay(
        tmp_path, returned_request_id, passes):
    bundle_dir, result = run_path_test(
        SUBJECT, str(tmp_path), http=fulfillment_id_client(returned_request_id))

    semantic = stage(result, "semantic_result")
    assert verify_bundle(bundle_dir) == []
    if passes:
        assert semantic.status == "passed"
        assert result.verdict == "passed"
        return

    bundle = load_bundle(bundle_dir)
    fulfillment = next(event for event in bundle["events"]
                       if event.kind == "fulfillment_observed"
                       and event.detail["attempt"] == 1)
    assert semantic.status == "failed"
    assert result.verdict == "failed"
    assert f"expected request_id {fulfillment.subject!r}" in semantic.note
    assert "observed request_id" in semantic.note


def test_duplicate_fulfillment_exposes_idempotency_defect(tmp_path):
    _, result = run_path_test(SUBJECT, str(tmp_path),
                              http=client("duplicate_fulfillment"))
    s = statuses(result)
    assert s["semantic_result"] == "passed"
    duplicate = stage(result, "duplicate_request")
    assert duplicate.status == "failed"
    assert "second distinct fulfillment" in duplicate.note
    assert result.verdict == "failed"


def test_unreachable_endpoint_fails_retrieval_only(tmp_path):
    _, result = run_path_test("http://127.0.0.1:1", str(tmp_path))
    s = statuses(result)
    assert s["resolution"] == "passed"
    assert s["agent_card_retrieval"] == "failed"
    assert s["protocol_invocation"] == "not_tested"
    assert s["semantic_result"] == "not_tested"
    assert result.verdict == "failed"


def test_index_resolution_and_missing_pointer(tmp_path):
    index = tmp_path / "index.json"
    expected = fingerprint(build_agent_card(SUBJECT))
    index.write_text(json.dumps({"agents": {
        "maya-seller": {"url": SUBJECT, "card_digest": expected}}}))

    _, result = run_path_test(None, str(tmp_path), index_file=str(index),
                              agent_name="maya-seller", http=client())
    assert stage(result, "descriptor_consistency").status == "passed"
    assert result.verdict == "passed"

    _, missing = run_path_test(None, str(tmp_path),
                               index_file=str(index),
                               agent_name="ghost", http=client())
    s = statuses(missing)
    resolution = stage(missing, "resolution")
    assert resolution.status == "failed"
    assert "missing card pointer" in resolution.note
    assert s["agent_card_retrieval"] == "not_tested"
    assert missing.verdict == "failed"


def test_town_driver_fault_is_an_error_not_a_failure(tmp_path,
                                                     monkeypatch):
    import nandatown.a2a_adapter as a2a

    def broken(*args, **kwargs):
        raise TypeError("driver bug: bad argument shape")

    monkeypatch.setattr(a2a, "send_message", broken)
    _, result = run_path_test(SUBJECT, str(tmp_path), http=client())
    invocation = stage(result, "protocol_invocation")
    assert invocation.status == "error"
    assert "Town's own driver malfunctioned" in invocation.note
    assert result.verdict == "error"
    assert stage(result, "semantic_result").status == "not_tested"


def test_profile_is_frozen_and_fingerprinted():
    profile = get_path_profile("a2a-capability-fulfillment@0.1")
    assert profile.ref == "a2a-capability-fulfillment@0.1"
    assert profile.fingerprint().startswith("sha256:")
    with pytest.raises(KeyError):
        get_path_profile("nonsense@9.9")
