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


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


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
    try:
        with open(os.path.join(directory, "manifest.json")) as f:
            manifest = json.load(f)
    except OSError as exc:
        return [f"manifest.json unreadable: {exc}"]
    calculated_fingerprint = fingerprint(manifest.get("files", {}))
    if manifest.get("bundle_fingerprint") != calculated_fingerprint:
        problems.append(
            "bundle fingerprint mismatch: manifest "
            f"{manifest.get('bundle_fingerprint')}, calculated "
            f"{calculated_fingerprint}")
    for name, expected in manifest.get("files", {}).items():
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            problems.append(f"{name} missing")
            continue
        actual = _sha256_file(path)
        if actual != expected:
            problems.append(f"{name} hash mismatch: manifest {expected},"
                            f" actual {actual}")
    if problems:
        return problems

    bundle = load_bundle(directory)
    recorded = bundle["result"]
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
    if recorded.evaluator_version != expected_version:
        problems.append(
            f"evaluator version differs: bundle {recorded.evaluator_version},"
            f" local {expected_version}; reproducibility not checked")
        return problems
    replay = replay_fn(bundle["profile"], recorded.run_id, bundle["events"])
    recorded_stages = {s.name: s.status for s in recorded.stages}
    replay_stages = {s.name: s.status for s in replay.stages}
    if recorded_stages != replay_stages or recorded.verdict != replay.verdict:
        problems.append(
            "evaluator replay mismatch: result.json does not match a fresh"
            f" evaluation (recorded {recorded_stages} verdict"
            f" {recorded.verdict}, replay {replay_stages} verdict"
            f" {replay.verdict})")

    attestation_path = os.path.join(directory, "attestation.json")
    if os.path.exists(attestation_path):
        from .identity_portable import verify_signature
        from .records import fingerprint as _fingerprint

        with open(attestation_path) as f:
            attestation = json.load(f)
        payload = attestation["payload"]
        if payload["bundle_fingerprint"] != \
                bundle["manifest"]["bundle_fingerprint"]:
            problems.append("attestation names a different bundle"
                            " fingerprint")
        elif not verify_signature(attestation["controller_public"],
                                  payload, attestation["signature"]):
            problems.append("attestation signature does not verify")
        else:
            derived = ("did:town:" + _fingerprint(
                attestation["controller_public"])
                .removeprefix("sha256:")[:24])
            if derived != payload["signer"]:
                problems.append("attestation signer id does not match"
                                " its controller key")
    return problems
