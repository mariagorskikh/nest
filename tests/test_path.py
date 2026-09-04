import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_a2a_app, build_agent_card
from nandatown.bundle import load_bundle, verify_bundle
from nandatown.path_profiles import PATH_PROFILES, get_path_profile
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


def start_reference_agent():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    source_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                       PYTHONPATH=os.path.join(source_root, "src"))
    process = subprocess.Popen(
        [sys.executable, "-m", "nandatown.cli", "a2a", "serve",
         "--port", str(port)], env=environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    import httpx

    for _ in range(50):
        try:
            if httpx.get(url + "/.well-known/agent-card.json").status_code == 200:
                return process, url
        except httpx.HTTPError:
            time.sleep(0.05)
    process.terminate()
    process.wait()
    raise RuntimeError("reference A2A agent did not start")


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


def test_generated_rerun_keeps_explicit_path_profile_when_default_changes(
        tmp_path, monkeypatch):
    """Catches a generated --profile being parsed as the Track flag."""
    fallback = get_path_profile("a2a-capability-fulfillment@0.1").model_copy(
        update={"version": "0.2"})
    monkeypatch.setitem(PATH_PROFILES, fallback.ref, fallback)
    original_add_argument = argparse.ArgumentParser.add_argument

    def different_path_default(parser, *names, **kwargs):
        if "--path-profile" in names:
            kwargs["default"] = fallback.ref
        return original_add_argument(parser, *names, **kwargs)

    monkeypatch.setattr(argparse.ArgumentParser, "add_argument",
                        different_path_default)
    process, url = start_reference_agent()
    try:
        expected_digest = fingerprint(build_agent_card(url))
        bundle_dir, _ = run_path_test(
            url, str(tmp_path),
            profile_ref="a2a-capability-fulfillment@0.1",
            pin_card_digest=expected_digest)
        rerun = load_bundle(bundle_dir)["run"].config["rerun_command"]
        assert url in rerun
        assert "--pin-card-digest " + expected_digest in rerun

        monkeypatch.chdir(tmp_path)
        from nandatown.cli import main

        assert main(shlex.split(rerun)[1:]) == 0
        rerun_bundle = next((tmp_path / "runs").iterdir())
        replayed = load_bundle(str(rerun_bundle))
        assert replayed["run"].profile_name == "a2a-capability-fulfillment@0.1"
        assert replayed["run"].config["pinned_card_digest"] == expected_digest
    finally:
        process.terminate()
        process.wait()
