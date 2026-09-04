import hashlib
import json

from nandatown.bundle import (
    attest_bundle,
    load_bundle,
    verify_bundle,
    write_bundle,
)
from nandatown.identity_portable import Keystore
from nandatown.report import render_report
from nandatown.evaluator import evaluate
from nandatown.records import RunRecord, fingerprint

from test_evaluator import clean_events, profile

SCOPE_SENTENCE = ("This result applies only to the named agents, releases,"
                  " scenario, failure, evaluator, and time window.")


def make_bundle(tmp_path):
    p = profile()
    events = clean_events()
    run = RunRecord(
        run_id="run-1", profile_name=p.name, profile_fingerprint="sha256:x",
        created_at=1.0,
        participants=[{"name": "buyer", "role": "buyer"},
                      {"name": "seller", "role": "seller"}],
        releases={"nandatown": "0.2.0", "evaluator": "0.2.0",
                  "python": "3.14"},
    )
    intents = [{"intent_id": "in-1", "run_id": "run-1", "at": 1.0,
                "actor": "buyer", "action": "send",
                "payload": {"message_id": "q-1"}}]
    result = evaluate(p, "run-1", events)
    out = tmp_path / "bundle"
    write_bundle(str(out), p, run, intents, events, result)
    return str(out), result


def refresh_file_hash(manifest, name, path):
    manifest["files"][name] = "sha256:" + hashlib.sha256(
        path.read_bytes()).hexdigest()


def test_clean_unsigned_bundle_remains_allowed(tmp_path):
    path, _ = make_bundle(tmp_path)
    assert verify_bundle(path) == []


def test_clean_signed_bundle_is_valid(tmp_path):
    path, _ = make_bundle(tmp_path)
    attest_bundle(path, keystore=Keystore(str(tmp_path / "keys")))
    assert verify_bundle(path) == []
    bundle = load_bundle(path)
    assert bundle["profile"].name == "quote-none"
    assert bundle["result"].verdict == "passed"
    assert len(bundle["events"]) == 10


def test_tampered_events_are_detected(tmp_path):
    path, _ = make_bundle(tmp_path)
    events_file = tmp_path / "bundle" / "events.jsonl"
    lines = events_file.read_text().splitlines()
    first = json.loads(lines[0])
    first["observer"] = "attacker"
    lines[0] = json.dumps(first)
    events_file.write_text("\n".join(lines) + "\n")
    problems = verify_bundle(path)
    assert any("events.jsonl" in p for p in problems)


def test_edited_result_is_detected(tmp_path):
    path, _ = make_bundle(tmp_path)
    result_file = tmp_path / "bundle" / "result.json"
    data = json.loads(result_file.read_text())
    data["verdict"] = "failed"
    for s in data["stages"]:
        if s["name"] == "correct":
            s["status"] = "failed"
    result_file.write_text(json.dumps(data))
    problems = verify_bundle(path)
    assert any("result.json" in p for p in problems)


def test_evaluator_mismatch_is_detected_even_with_valid_hashes(tmp_path):
    path, _ = make_bundle(tmp_path)
    result_file = tmp_path / "bundle" / "result.json"
    data = json.loads(result_file.read_text())
    for s in data["stages"]:
        if s["name"] == "correct":
            s["status"] = "failed"
    data["verdict"] = "failed"
    result_file.write_text(json.dumps(data))
    manifest_file = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    refresh_file_hash(manifest, "result.json", result_file)
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    manifest_file.write_text(json.dumps(manifest))
    problems = verify_bundle(path)
    assert any("evaluator" in p for p in problems)


def test_refreshed_file_hash_with_stale_root_is_detected(tmp_path):
    path, _ = make_bundle(tmp_path)
    run_file = tmp_path / "bundle" / "run.json"
    run = json.loads(run_file.read_text())
    run["participants"][0]["name"] = "attacker"
    run_file.write_text(json.dumps(run))
    manifest_file = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    refresh_file_hash(manifest, "run.json", run_file)
    manifest_file.write_text(json.dumps(manifest))

    problems = verify_bundle(path)

    assert any("bundle fingerprint mismatch" in p for p in problems)


def test_refreshed_root_rejects_unchanged_attestation(tmp_path):
    path, _ = make_bundle(tmp_path)
    attest_bundle(path, keystore=Keystore(str(tmp_path / "keys")))
    run_file = tmp_path / "bundle" / "run.json"
    run = json.loads(run_file.read_text())
    run["participants"][0]["name"] = "attacker"
    run_file.write_text(json.dumps(run))
    manifest_file = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    refresh_file_hash(manifest, "run.json", run_file)
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    manifest_file.write_text(json.dumps(manifest))

    problems = verify_bundle(path)

    assert "attestation names a different bundle fingerprint" in problems


def test_updated_attestation_root_with_original_signature_is_rejected(tmp_path):
    path, _ = make_bundle(tmp_path)
    attest_bundle(path, keystore=Keystore(str(tmp_path / "keys")))
    run_file = tmp_path / "bundle" / "run.json"
    run = json.loads(run_file.read_text())
    run["participants"][0]["name"] = "attacker"
    run_file.write_text(json.dumps(run))
    manifest_file = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    refresh_file_hash(manifest, "run.json", run_file)
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    manifest_file.write_text(json.dumps(manifest))
    attestation_file = tmp_path / "bundle" / "attestation.json"
    attestation = json.loads(attestation_file.read_text())
    attestation["payload"]["bundle_fingerprint"] = \
        manifest["bundle_fingerprint"]
    attestation_file.write_text(json.dumps(attestation))

    problems = verify_bundle(path)

    assert "attestation signature does not verify" in problems


def test_root_only_edit_is_detected(tmp_path):
    path, _ = make_bundle(tmp_path)
    manifest_file = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    manifest["bundle_fingerprint"] = "sha256:attacker"
    manifest_file.write_text(json.dumps(manifest))

    problems = verify_bundle(path)

    assert any("bundle fingerprint mismatch" in p for p in problems)


def test_report_contains_scope_and_stages(tmp_path):
    path, _ = make_bundle(tmp_path)
    bundle = load_bundle(path)
    text = render_report(bundle)
    assert SCOPE_SENTENCE in text
    for name in ["accepted", "claimed", "received", "processed", "response",
                 "correct", "portable_identity"]:
        assert name in text
    assert "bring" in text and "disrupt" in text and "improve" in text
    report_md = (tmp_path / "bundle" / "report.md").read_text()
    assert SCOPE_SENTENCE in report_md
    assert "—" not in text and "–" not in text
