"""The portable evidence bundle.

One directory holds the five records: the profile (the recipe), the run
(the attempt), the intents (the requested actions), the events (the
attributed facts), and the result (the evaluator's scoped observation).
A manifest fingerprints every file. The human report is a rendered view
of the bundle, not a sixth record. Later conclusions can reference this
evidence; they never rewrite it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from typing import Any

from . import __version__
from .evaluator import EVALUATOR_VERSION, evaluate
from .records import (
    EvidenceResult,
    Intent,
    RunRecord,
    TestProfile,
    TownEvent,
    fingerprint,
)

RECORD_FILES = ["profile.json", "run.json", "intents.jsonl", "events.jsonl",
                "result.json"]
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BUNDLE_MODES = {"track", "lab", "path"}


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _regular_file_problem(path: str, name: str) -> str | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return f"{name} missing"
    except OSError as exc:
        return f"{name} unreadable: {exc}"
    if not stat.S_ISREG(metadata.st_mode):
        return f"{name} is not a regular file"
    return None


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    repeated: set[str] = set()
    for value in values:
        if value in seen:
            repeated.add(value)
        else:
            seen.add(value)
    return sorted(repeated)


def write_bundle(directory: str, profile, run: RunRecord,
                 intents: list[dict[str, Any]], events: list[TownEvent],
                 result: EvidenceResult, mode: str = "track") -> dict[str, Any]:
    os.makedirs(directory, exist_ok=True)

    def write(name: str, text: str) -> None:
        with open(os.path.join(directory, name), "w") as f:
            f.write(text)

    write("profile.json", profile.model_dump_json(indent=2))
    write("run.json", run.model_dump_json(indent=2))
    write("intents.jsonl",
          "".join(json.dumps(i) + "\n" for i in intents))
    write("events.jsonl",
          "".join(e.model_dump_json() + "\n" for e in events))
    write("result.json", result.model_dump_json(indent=2))

    files = {name: _sha256_file(os.path.join(directory, name))
             for name in RECORD_FILES}
    manifest = {
        "mode": mode,
        "files": files,
        "bundle_fingerprint": fingerprint(files),
        "created_at": time.time(),
        "nandatown_version": __version__,
        "evaluator_version": result.evaluator_version,
    }
    write("manifest.json", json.dumps(manifest, indent=2))

    from .report import render_report
    write("report.md", render_report(load_bundle(directory)))
    return manifest


def attest_bundle(directory: str, keystore=None,
                  signer: str | None = None) -> dict[str, Any]:
    """A signed, replayable attestation with provenance.

    The operator's controller key signs the bundle fingerprint and the
    verdict; anyone can replay the evidence and check the signature, so
    the attestation is measurable, not a marketing claim."""
    from .identity_portable import (
        OPERATOR_NAME,
        Keystore,
        default_keystore_dir,
    )

    keystore = keystore or Keystore(default_keystore_dir())
    signer = signer or OPERATOR_NAME
    identity = keystore.new_identity(signer)
    with open(os.path.join(directory, "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(directory, "result.json")) as f:
        result = json.load(f)
    payload = {
        "bundle_fingerprint": manifest["bundle_fingerprint"],
        "run_id": result["run_id"],
        "verdict": result["verdict"],
        "evaluator_version": result["evaluator_version"],
        "signer": identity["agent_id"],
        "signed_at": time.time(),
    }
    attestation = {
        "payload": payload,
        "signature": keystore.sign(signer, payload),
        "controller_public": identity["controller_public"],
    }
    with open(os.path.join(directory, "attestation.json"), "w") as f:
        json.dump(attestation, f, indent=2)
    return attestation


def load_bundle(directory: str) -> dict[str, Any]:
    def read(name: str) -> str:
        with open(os.path.join(directory, name)) as f:
            return f.read()

    manifest = json.loads(read("manifest.json"))
    mode = manifest.get("mode", "track")
    if mode == "lab":
        from .sim.scenario import ScenarioSpec
        profile: Any = ScenarioSpec.model_validate_json(read("profile.json"))
    elif mode == "path":
        from .path_profiles import PathProfile
        profile = PathProfile.model_validate_json(read("profile.json"))
    else:
        profile = TestProfile.model_validate_json(read("profile.json"))
    return {
        "directory": directory,
        "mode": mode,
        "profile": profile,
        "run": RunRecord.model_validate_json(read("run.json")),
        "intents": [Intent.model_validate_json(line)
                    for line in read("intents.jsonl").splitlines() if line],
        "events": [TownEvent.model_validate_json(line)
                   for line in read("events.jsonl").splitlines() if line],
        "result": EvidenceResult.model_validate_json(read("result.json")),
        "manifest": manifest,
    }


def verify_bundle(directory: str) -> list[str]:
    """Check integrity and evaluator reproducibility. Returns problems."""
    problems: list[str] = []
    manifest_path = os.path.join(directory, "manifest.json")
    manifest_problem = _regular_file_problem(manifest_path, "manifest.json")
    if manifest_problem:
        return [manifest_problem]
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"manifest.json unreadable: {exc}"]
    if not isinstance(manifest, dict):
        return ["manifest.json must contain a JSON object"]

    mode = manifest.get("mode", "track")
    if not isinstance(mode, str) or mode not in BUNDLE_MODES:
        problems.append(f"unknown bundle mode {mode!r}")
    files = manifest.get("files")
    if not isinstance(files, dict):
        problems.append("manifest.json files must be a JSON object")
        return problems
    actual_names = set(files)
    canonical_names = set(RECORD_FILES)
    if actual_names != canonical_names:
        missing = sorted(canonical_names - actual_names)
        unexpected = sorted(actual_names - canonical_names, key=repr)
        problems.append("manifest must name exactly the five canonical records:"
                        f" missing={missing}, unexpected={unexpected}")
    for name, expected in files.items():
        if not isinstance(expected, str) or not DIGEST_RE.fullmatch(expected):
            problems.append(f"{name} digest is malformed")
    bundle_fingerprint = manifest.get("bundle_fingerprint")
    if not isinstance(bundle_fingerprint, str) \
            or not DIGEST_RE.fullmatch(bundle_fingerprint):
        problems.append("bundle fingerprint is malformed")
    if problems:
        return problems

    for name in RECORD_FILES:
        problem = _regular_file_problem(os.path.join(directory, name), name)
        if problem:
            problems.append(problem)
    if problems:
        return problems

    calculated_fingerprint = fingerprint(files)
    if bundle_fingerprint != calculated_fingerprint:
        problems.append(
            "bundle fingerprint mismatch: manifest "
            f"{bundle_fingerprint}, calculated "
            f"{calculated_fingerprint}")
    for name, expected in files.items():
        path = os.path.join(directory, name)
        try:
            actual = _sha256_file(path)
        except OSError as exc:
            problems.append(f"{name} unreadable: {exc}")
            continue
        if actual != expected:
            problems.append(f"{name} hash mismatch: manifest {expected},"
                            f" actual {actual}")
    if problems:
        return problems

    try:
        bundle = load_bundle(directory)
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError,
            ValueError) as exc:
        return [f"bundle records invalid: {exc}"]
    recorded = bundle["result"]
    run = bundle["run"]
    profile = bundle["profile"]
    profile_name = (profile.ref if bundle["mode"] == "path"
                    else profile.name)
    if run.run_id != recorded.run_id:
        problems.append("run and result name different run ids")
    if run.profile_name != profile_name:
        problems.append("run profile name does not match profile")
    if run.profile_fingerprint != fingerprint(profile.model_dump()):
        problems.append("run profile fingerprint does not match profile")
    if any(intent.run_id != run.run_id for intent in bundle["intents"]):
        problems.append("intent names a different run id")
    if any(event.run_id != run.run_id for event in bundle["events"]):
        problems.append("event names a different run id")
    participant_problems = []
    if not run.participants:
        participant_problems.append("run has no participants")
    for index, participant in enumerate(run.participants):
        for field in ("name", "role"):
            value = participant.get(field)
            if not isinstance(value, str) or not value.strip():
                participant_problems.append(
                    f"run participant {index} has no valid {field}")
    problems.extend(participant_problems)
    if manifest.get("nandatown_version") != run.releases.get("nandatown"):
        problems.append("manifest nandatown version does not match run release")
    if run.releases.get("evaluator") != recorded.evaluator_version:
        problems.append("run evaluator release does not match result")
    if manifest.get("evaluator_version") != recorded.evaluator_version:
        problems.append("manifest evaluator version does not match result")
    if bundle["mode"] in {"lab", "path"} \
            and run.config.get("mode") != bundle["mode"]:
        problems.append("run mode does not match manifest mode")
    intent_ids = [intent.intent_id for intent in bundle["intents"]]
    duplicate_intent_ids = _duplicates(intent_ids)
    if duplicate_intent_ids:
        problems.append(f"duplicate intent ids: {duplicate_intent_ids}")
    event_ids = [event.event_id for event in bundle["events"]]
    duplicate_event_ids = _duplicates(event_ids)
    if duplicate_event_ids:
        problems.append(f"duplicate event ids: {duplicate_event_ids}")
    stage_names = [stage.name for stage in recorded.stages]
    duplicate_names = _duplicates(stage_names)
    if duplicate_names:
        problems.append(f"result has duplicate stage names: {duplicate_names}")
    records_coherent = not problems

    try:
        if bundle["mode"] == "lab":
            from .sim.validators import LAB_EVALUATOR_VERSION, evaluate_scenario
            expected_version = LAB_EVALUATOR_VERSION
            replay_fn = evaluate_scenario
        elif bundle["mode"] == "path":
            from .path_runner import evaluate_path, path_evaluator_version
            expected_version = path_evaluator_version(bundle["profile"])
            replay_fn = evaluate_path
        else:
            expected_version = EVALUATOR_VERSION
            replay_fn = evaluate
    except (KeyError, ValueError) as exc:
        expected_version = None
        replay_fn = None
        problems.append(str(exc))
    if expected_version is not None \
            and recorded.evaluator_version != expected_version:
        problems.append(
            f"evaluator version differs: bundle {recorded.evaluator_version},"
            f" local {expected_version}; reproducibility not checked")
    elif replay_fn is not None and records_coherent:
        try:
            replay = replay_fn(
                bundle["profile"], recorded.run_id, bundle["events"])
        except Exception as exc:
            problems.append(
                "evaluator replay failed on the recorded evidence:"
                f" {type(exc).__name__}: {exc}")
        else:
            recorded_result = recorded.model_dump(exclude={"evaluated_at"})
            replay_result = replay.model_dump(exclude={"evaluated_at"})
            if recorded_result != replay_result:
                problems.append(
                    "evaluator replay mismatch: result.json does not match a"
                    " fresh deterministic evaluation")

    attestation_path = os.path.join(directory, "attestation.json")
    if os.path.lexists(attestation_path):
        from .identity_portable import verify_signature
        from .records import fingerprint as _fingerprint

        attestation_problem = _regular_file_problem(
            attestation_path, "attestation.json")
        if attestation_problem:
            problems.append(attestation_problem)
            return problems
        try:
            with open(attestation_path) as f:
                attestation = json.load(f)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            problems.append(f"attestation.json unreadable: {exc}")
            return problems
        if not isinstance(attestation, dict) \
                or not isinstance(attestation.get("payload"), dict):
            problems.append("attestation.json must contain an object payload")
            return problems
        payload = attestation["payload"]
        expected_claims = {
            "bundle_fingerprint": bundle["manifest"]["bundle_fingerprint"],
            "run_id": recorded.run_id,
            "verdict": recorded.verdict,
            "evaluator_version": recorded.evaluator_version,
        }
        if payload.get("bundle_fingerprint") != \
                expected_claims["bundle_fingerprint"]:
            problems.append("attestation names a different bundle"
                            " fingerprint")
        for name in ("run_id", "verdict", "evaluator_version"):
            if payload.get(name) != expected_claims[name]:
                problems.append(
                    f"attestation {name.replace('_', ' ')} does not match bundle")
        controller_public = attestation.get("controller_public")
        signature = attestation.get("signature")
        if not isinstance(controller_public, str) \
                or not isinstance(signature, str):
            problems.append("attestation signature and controller key must be strings")
        elif not verify_signature(controller_public, payload, signature):
            problems.append("attestation signature does not verify")
        if isinstance(controller_public, str):
            derived = ("did:town:" + _fingerprint(
                controller_public)
                .removeprefix("sha256:")[:24])
            if derived != payload.get("signer"):
                problems.append("attestation signer id does not match"
                                " its controller key")
    return problems
