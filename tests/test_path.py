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


def client(defect=None):
    return TestClient(build_a2a_app(SUBJECT, defect=defect))


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


def test_oversized_card_does_not_reach_path_invocation(tmp_path):
    url = "http://fixture.invalid"
    card = build_agent_card(url)
    card["description"] = "x" * 1_048_576
    methods = []
    def handle(request):
        methods.append(request.method)
        return httpx.Response(200, json=card)
    with httpx.Client(base_url=url, transport=httpx.MockTransport(handle)) as http:
        bundle_dir, result = run_path_test(url, str(tmp_path), http=http)
        assert not http.is_closed
    assert methods == ["GET"]
    assert stage(result, "agent_card_retrieval").status == "failed"
    assert stage(result, "agent_card_retrieval").note == (
        "a2a_response_budget_exceeded: selected local byte budget exceeded for this run")
    assert stage(result, "semantic_result").status == "not_tested"
    bundle = load_bundle(bundle_dir)
    assert bundle["run"].profile_name == "a2a-capability-fulfillment@0.2"
    assert bundle["run"].config["a2a_transport_policy"] == {
        "policy_id": "a2a-bounded-json@0.1",
        "max_response_bytes": 1_048_576,
        "budget_basis": "profile",
        "accept_encoding": "identity",
        "follow_redirects": False,
        "trust_env": "caller_controlled",
        "transport_retries": "caller_controlled",
        "client_ownership": "injected",
        "phase_timeout_seconds": 15.0,
        "total_deadline_seconds": None,
    }
    assert verify_bundle(bundle_dir) == []


def test_old_profile_is_unchanged_and_new_bundles_replay(tmp_path):
    old = get_path_profile("a2a-capability-fulfillment@0.1")
    assert old.fingerprint() == "sha256:80d238c2de68dbe3de577ad88ae5eb742daeaf2628dc7802be2b11e68b8d4b83"
    assert old.limits == {"timeout_seconds": 15.0}
    new = get_path_profile("a2a-capability-fulfillment@0.2")
    assert new.limits == {"timeout_seconds": 15.0, "max_response_bytes": 1_048_576}
    assert old.fingerprint() != new.fingerprint()
    for profile in (old, new):
        with client() as http:
            directory, result = run_path_test(SUBJECT, str(tmp_path), profile_ref=profile.ref, http=http)
        assert result.verdict == "passed"
        bundle = load_bundle(directory)
        assert bundle["run"].profile_fingerprint == profile.fingerprint()
        assert bundle["run"].config["a2a_transport_policy"]["budget_basis"] == (
            "implementation_ceiling" if profile.version == "0.1" else "profile")
        assert verify_bundle(directory) == []


def test_owned_path_keeps_card_session_for_both_logical_requests(tmp_path, monkeypatch):
    import nandatown.a2a_transport as transport
    real_client = httpx.Client
    clients = []
    def handle(request):
        if request.method == "GET":
            return httpx.Response(200, json=build_agent_card(SUBJECT),
                                  headers={"set-cookie": "session=local; Path=/"})
        assert request.headers.get("cookie") == "session=local"
        order = json.loads(json.loads(request.content)["params"]["message"]["parts"][0]["text"])
        return httpx.Response(200, json={"result": {
            "kind": "task", "id": "local", "status": {"state": "completed"},
            "artifacts": [{"parts": [{"kind": "text", "text": json.dumps({
                "request_id": order["request_id"], "total_cents": 3990})}]}]}})
    def client_factory(**kwargs):
        kwargs.pop("transport", None)
        http = real_client(**kwargs, transport=httpx.MockTransport(handle))
        clients.append(http)
        return http
    monkeypatch.setattr(transport.httpx, "Client", client_factory)
    _, result = run_path_test(SUBJECT, str(tmp_path))
    assert result.verdict == "passed"
    assert len(clients) == 1 and clients[0].is_closed
