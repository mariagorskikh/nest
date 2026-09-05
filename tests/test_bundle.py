import hashlib
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nandatown.a2a_adapter import build_a2a_app
from nandatown.bundle import (
    attest_bundle,
    load_bundle,
    verify_bundle,
    write_bundle,
)
from nandatown.identity_portable import Keystore
from nandatown.path_runner import run_path_test
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
        run_id="run-1", profile_name=p.name,
        profile_fingerprint=fingerprint(p.model_dump()),
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


def write_manifest(bundle_path, manifest):
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    (bundle_path / "manifest.json").write_text(json.dumps(manifest))


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
    manifest["bundle_fingerprint"] = "sha256:" + "0" * 64
    manifest_file.write_text(json.dumps(manifest))

    problems = verify_bundle(path)

    assert any("bundle fingerprint mismatch" in p for p in problems)


def test_manifest_must_name_all_five_canonical_records(tmp_path):
    path, _ = make_bundle(tmp_path)
    bundle_path = tmp_path / "bundle"
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    del manifest["files"]["run.json"]
    write_manifest(bundle_path, manifest)

    problems = verify_bundle(path)

    assert any("canonical records" in problem and "run.json" in problem
               for problem in problems), problems


def test_manifest_rejects_traversal_member_even_when_hash_matches(tmp_path):
    path, _ = make_bundle(tmp_path)
    bundle_path = tmp_path / "bundle"
    outside = tmp_path / "outside.json"
    outside.write_text("outside")
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    manifest["files"]["../outside.json"] = (
        "sha256:" + hashlib.sha256(outside.read_bytes()).hexdigest())
    write_manifest(bundle_path, manifest)

    problems = verify_bundle(path)

    assert any("canonical records" in problem and "../outside.json" in problem
               for problem in problems), problems


@pytest.mark.parametrize("manifest_text", ["[]", "{not-json", '{"files": []}'],
                         ids=["array", "invalid-json", "files-array"])
def test_malformed_manifest_is_reported_not_raised(tmp_path, manifest_text):
    path, _ = make_bundle(tmp_path)
    (tmp_path / "bundle" / "manifest.json").write_text(manifest_text)

    try:
        problems = verify_bundle(path)
    except Exception as exc:  # pragma: no cover - public API must not raise
        pytest.fail(f"malformed manifest raised {type(exc).__name__}: {exc}")

    assert problems
    assert any("manifest.json" in problem for problem in problems)


def test_manifest_rejects_malformed_file_digest(tmp_path):
    path, _ = make_bundle(tmp_path)
    bundle_path = tmp_path / "bundle"
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    manifest["files"]["run.json"] = "sha256:not-a-digest"
    write_manifest(bundle_path, manifest)

    problems = verify_bundle(path)

    assert any("run.json digest is malformed" in problem
               for problem in problems), problems


def test_manifest_rejects_malformed_bundle_fingerprint(tmp_path):
    path, _ = make_bundle(tmp_path)
    manifest_path = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["bundle_fingerprint"] = "sha256:not-a-digest"
    manifest_path.write_text(json.dumps(manifest))

    problems = verify_bundle(path)

    assert "bundle fingerprint is malformed" in problems


def test_manifest_rejects_unknown_bundle_mode(tmp_path):
    path, _ = make_bundle(tmp_path)
    manifest_path = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["mode"] = "mystery"
    manifest_path.write_text(json.dumps(manifest))

    problems = verify_bundle(path)

    assert any("unknown bundle mode" in problem for problem in problems), problems


def test_manifest_rejects_unhashable_bundle_mode_without_raising(tmp_path):
    path, _ = make_bundle(tmp_path)
    manifest_path = tmp_path / "bundle" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["mode"] = []
    manifest_path.write_text(json.dumps(manifest))

    try:
        problems = verify_bundle(path)
    except Exception as exc:  # pragma: no cover - public API must not raise
        pytest.fail(f"malformed mode raised {type(exc).__name__}: {exc}")

    assert any("unknown bundle mode" in problem for problem in problems), problems


def test_bundle_rejects_symlinked_canonical_record(tmp_path):
    path, _ = make_bundle(tmp_path)
    bundle_path = tmp_path / "bundle"
    run_path = bundle_path / "run.json"
    outside = tmp_path / "run-copy.json"
    shutil.copyfile(run_path, outside)
    run_path.unlink()
    run_path.symlink_to(outside)

    problems = verify_bundle(path)

    assert any("run.json is not a regular file" in problem
               for problem in problems), problems


def test_bundle_rejects_nonregular_canonical_record_without_reading_it(tmp_path):
    path, _ = make_bundle(tmp_path)
    run_path = tmp_path / "bundle" / "run.json"
    run_path.unlink()
    run_path.mkdir()

    try:
        problems = verify_bundle(path)
    except Exception as exc:  # pragma: no cover - must reject before open
        pytest.fail(f"nonregular record raised {type(exc).__name__}: {exc}")

    assert any("run.json is not a regular file" in problem
               for problem in problems), problems


@pytest.mark.parametrize(
    ("record_name", "mutate", "message"),
    [
        ("run.json", lambda value: value.update(run_id="other-run"),
         "run and result name different run ids"),
        ("run.json", lambda value: value.update(profile_name="other-profile"),
         "run profile name does not match profile"),
        ("run.json", lambda value: value.update(
            profile_fingerprint="sha256:" + "0" * 64),
         "run profile fingerprint does not match profile"),
        ("intents.jsonl", lambda value: value.update(run_id="other-run"),
         "intent names a different run id"),
        ("events.jsonl", lambda value: value.update(run_id="other-run"),
         "event names a different run id"),
        ("result.json", lambda value: value.update(run_id="other-run"),
         "run and result name different run ids"),
    ],
)
def test_bundle_binds_cross_record_metadata(
        tmp_path, record_name, mutate, message):
    path, _ = make_bundle(tmp_path)
    bundle_path = tmp_path / "bundle"
    record_path = bundle_path / record_name
    if record_name.endswith(".jsonl"):
        records = record_path.read_text().splitlines()
        value = json.loads(records[0])
        mutate(value)
        records[0] = json.dumps(value)
        record_path.write_text("\n".join(records) + "\n")
    else:
        value = json.loads(record_path.read_text())
        mutate(value)
        record_path.write_text(json.dumps(value))
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    refresh_file_hash(manifest, record_name, record_path)
    write_manifest(bundle_path, manifest)

    problems = verify_bundle(path)

    assert message in problems, problems


@pytest.mark.parametrize("change", ["note", "evidence", "duplicate"],
                         ids=["stage-note", "stage-evidence", "duplicate-stage"])
def test_evaluator_replay_compares_complete_deterministic_result(tmp_path, change):
    path, _ = make_bundle(tmp_path)
    bundle_path = tmp_path / "bundle"
    result_path = bundle_path / "result.json"
    result = json.loads(result_path.read_text())
    if change == "note":
        result["stages"][0]["note"] = "forged note"
    elif change == "evidence":
        result["stages"][0]["evidence"] = ["forged-event"]
    else:
        result["stages"].append(dict(result["stages"][0]))
    result_path.write_text(json.dumps(result))
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    refresh_file_hash(manifest, "result.json", result_path)
    write_manifest(bundle_path, manifest)

    problems = verify_bundle(path)

    expected = ("duplicate stage names" if change == "duplicate"
                else "evaluator replay mismatch")
    assert any(expected in problem for problem in problems), problems


def test_evaluator_replay_error_is_reported_not_raised(tmp_path):
    url = "http://testserver"
    with TestClient(build_a2a_app(url)) as client:
        directory, _ = run_path_test(url, str(tmp_path), http=client)
    bundle_path = Path(directory)
    events_path = bundle_path / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    card = next(event for event in events if event["kind"] == "card_retrieved")
    card["detail"] = {}
    events_path.write_text("".join(json.dumps(event) + "\n" for event in events))
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    refresh_file_hash(manifest, "events.jsonl", events_path)
    write_manifest(bundle_path, manifest)

    try:
        problems = verify_bundle(directory)
    except Exception as exc:  # pragma: no cover - verifier boundary
        pytest.fail(f"evaluator replay raised {type(exc).__name__}: {exc}")

    assert any("evaluator replay failed" in problem for problem in problems), problems


@pytest.mark.parametrize(
    ("field", "value"),
    [("run_id", "other-run"), ("verdict", "failed"),
     ("evaluator_version", "other-evaluator")],
)
def test_validly_resigned_attestation_must_match_bundle(
        tmp_path, field, value):
    path, _ = make_bundle(tmp_path)
    keys = Keystore(str(tmp_path / "keys"))
    attest_bundle(path, keystore=keys, signer="reviewer")
    attestation_path = tmp_path / "bundle" / "attestation.json"
    attestation = json.loads(attestation_path.read_text())
    attestation["payload"][field] = value
    attestation["signature"] = keys.sign("reviewer", attestation["payload"])
    attestation_path.write_text(json.dumps(attestation))

    problems = verify_bundle(path)

    assert any(f"attestation {field.replace('_', ' ')}" in problem
               for problem in problems), problems


def test_malformed_attestation_is_reported_not_raised(tmp_path):
    path, _ = make_bundle(tmp_path)
    (tmp_path / "bundle" / "attestation.json").write_text("[]")

    try:
        problems = verify_bundle(path)
    except Exception as exc:  # pragma: no cover - public API must not raise
        pytest.fail(f"malformed attestation raised {type(exc).__name__}: {exc}")

    assert any("attestation.json" in problem for problem in problems), problems


def test_historical_evaluator_mismatch_remains_explicit(tmp_path):
    path, _ = make_bundle(tmp_path)
    bundle_path = tmp_path / "bundle"
    result_path = bundle_path / "result.json"
    result = json.loads(result_path.read_text())
    result["evaluator_version"] = "historical-evaluator"
    result_path.write_text(json.dumps(result))
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    manifest["evaluator_version"] = "historical-evaluator"
    refresh_file_hash(manifest, "result.json", result_path)
    write_manifest(bundle_path, manifest)

    problems = verify_bundle(path)

    assert problems == [
        "evaluator version differs: bundle historical-evaluator, local 0.2.0;"
        " reproducibility not checked"
    ]


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
