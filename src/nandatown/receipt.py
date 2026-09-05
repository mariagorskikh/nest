"""Shareable receipts and Town Proof.

Full bodies, prompts, and sensitive traces stay in the bundle. A
receipt is a deliberately sanitized derivative: the exact claim,
digests, evidence references, observer, time window, coverage, and
limitations, signed when it crosses organizational boundaries. The
signature proves that a named key committed to those exact bytes; it
does not prove the observation was true, the observer was independent,
or the agent was safe.

Town Proof is a scoped view over a verified receipt: one capability
observed under one exact profile, release basis, observer, window, and
coverage. Narrow and expiring by construction; never a universal
reputation score.
"""

from __future__ import annotations

import json
import math
import os
import stat
import time
from typing import Any

from .records import fingerprint

DEFAULT_LIMITATIONS = [
    "one run is one scoped observation, not a certificate",
    "the signature proves key commitment, not truth, independence, or"
    " safety",
    "a favorable result grants no permissions and endorses nothing",
]

RECEIPT_FIELDS = {"payload", "signature", "controller_public"}
PAYLOAD_FIELDS = {
    "claim", "observer", "window", "coverage", "limitations", "evidence",
}
CLAIM_FIELDS = {
    "capability", "subject", "release_basis", "profile", "verdict",
}
WINDOW_FIELDS = {"started", "evaluated"}
COVERAGE_FIELDS = {"tested", "not_tested"}
EVIDENCE_FIELDS = {"bundle_fingerprint", "result_digest", "run_id"}
RELEASE_BASIS_FIELDS = {"profile_fingerprint"}
RELEASE_BASIS_OPTIONAL_FIELDS = {"card_digest"}
RECEIPT_VERDICTS = {"passed", "failed", "incomplete", "error"}


def _field_set_problems(value: dict[str, Any], label: str,
                        required: set[str],
                        optional: set[str] | None = None) -> list[str]:
    optional = optional or set()
    keys = set(value)
    missing = sorted(required - keys)
    unexpected = sorted(keys - required - optional)
    problems = []
    if missing:
        problems.append(f"{label} is missing fields: {missing}")
    if unexpected:
        problems.append(f"{label} has unexpected fields: {unexpected}")
    return problems


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _receipt_shape_problems(receipt: dict[str, Any],
                            payload: dict[str, Any]) -> list[str]:
    problems = _field_set_problems(receipt, "receipt", RECEIPT_FIELDS)
    problems += _field_set_problems(payload, "receipt payload", PAYLOAD_FIELDS)

    observer = payload.get("observer")
    if not _nonempty_string(observer):
        problems.append("receipt observer must be a non-empty string")

    claim = payload.get("claim")
    if not isinstance(claim, dict):
        problems.append("receipt claim must be a JSON object")
    else:
        problems += _field_set_problems(
            claim, "receipt claim", CLAIM_FIELDS)
        for name in ("capability", "subject", "profile"):
            if not _nonempty_string(claim.get(name)):
                problems.append(
                    f"receipt claim {name} must be a non-empty string")
        if claim.get("verdict") not in RECEIPT_VERDICTS:
            problems.append("receipt claim verdict is invalid")
        release_basis = claim.get("release_basis")
        if not isinstance(release_basis, dict):
            problems.append("receipt claim release basis must be a JSON object")
        else:
            problems += _field_set_problems(
                release_basis, "receipt claim release basis",
                RELEASE_BASIS_FIELDS, RELEASE_BASIS_OPTIONAL_FIELDS)
            for name in RELEASE_BASIS_FIELDS | RELEASE_BASIS_OPTIONAL_FIELDS:
                if name in release_basis \
                        and not _nonempty_string(release_basis[name]):
                    problems.append(
                        "receipt claim release basis"
                        f" {name.replace('_', ' ')} must be a non-empty string")

    window = payload.get("window")
    if not isinstance(window, dict):
        problems.append("receipt window must be a JSON object")
    else:
        problems += _field_set_problems(
            window, "receipt window", WINDOW_FIELDS)
        for name in WINDOW_FIELDS:
            value = window.get(name)
            if isinstance(value, bool) \
                    or not isinstance(value, (int, float)) \
                    or not math.isfinite(value):
                problems.append(
                    f"receipt window {name} must be a finite number")

    coverage = payload.get("coverage")
    if not isinstance(coverage, dict):
        problems.append("receipt coverage must be a JSON object")
    else:
        problems += _field_set_problems(
            coverage, "receipt coverage", COVERAGE_FIELDS)
        for name in COVERAGE_FIELDS:
            values = coverage.get(name)
            if not isinstance(values, list) \
                    or any(not _nonempty_string(value) for value in values):
                problems.append(
                    f"receipt coverage {name} must be a list of"
                    " non-empty strings")

    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not limitations \
            or any(not _nonempty_string(value) for value in limitations):
        problems.append(
            "receipt limitations must be a non-empty list of non-empty strings")

    evidence = payload.get("evidence")
    if not isinstance(evidence, dict):
        problems.append("receipt evidence must be a JSON object")
    else:
        problems += _field_set_problems(
            evidence, "receipt evidence", EVIDENCE_FIELDS)
        for name in EVIDENCE_FIELDS:
            if not _nonempty_string(evidence.get(name)):
                problems.append(
                    f"receipt evidence {name.replace('_', ' ')}"
                    " must be a non-empty string")
    return problems


def _receipt_file_problem(path: str, *, missing_ok: bool = False) -> str | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None if missing_ok else "receipt missing"
    except OSError as exc:
        return f"receipt unreadable: {exc}"
    if not stat.S_ISREG(metadata.st_mode):
        return "receipt is not a regular file"
    return None


def _load_receipt_document(path: str) -> tuple[Any | None, str | None]:
    problem = _receipt_file_problem(path)
    if problem:
        return None, problem
    try:
        with open(path) as f:
            return json.load(f), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"receipt unreadable: {exc}"


def _proof_window_problems(window: dict[str, Any], now: float) -> list[str]:
    problems = []
    for name in ("started", "evaluated"):
        value = window.get(name)
        if isinstance(value, bool) \
                or not isinstance(value, (int, float)) \
                or not math.isfinite(value):
            problems.append(
                f"the evidence window {name} timestamp must be finite")
        elif value > now:
            problems.append(
                f"the evidence window {name} timestamp is in the future")
    return problems


def _bundle_receipt_fields(bundle: dict[str, Any]) -> dict[str, Any]:
    """Derive every receipt field that makes a claim about one bundle."""
    run = bundle["run"]
    result = bundle["result"]
    profile = bundle["profile"]
    capability = getattr(profile, "capability", None) \
        or getattr(getattr(profile, "task", None), "kind", None) \
        or run.profile_name
    subject = run.config.get("subject")
    if subject is not None and subject != "":
        if not _nonempty_string(subject):
            raise ValueError("bundle receipt subject must be a non-empty string")
    else:
        participant_names = []
        for index, participant in enumerate(run.participants):
            name = participant.get("name")
            if not _nonempty_string(name):
                raise ValueError(
                    f"bundle participant {index} has no valid name")
            participant_names.append(name)
        if not participant_names:
            raise ValueError("bundle has no participant name for receipt subject")
        subject = ", ".join(participant_names)
    release_basis = {"profile_fingerprint": run.profile_fingerprint}
    if run.config.get("pinned_card_digest"):
        release_basis["card_digest"] = run.config["pinned_card_digest"]
    tested = [s.name for s in result.stages if s.status != "not_tested"]
    not_tested = [s.name for s in result.stages
                  if s.status == "not_tested"]
    return {
        "claim": {
            "capability": capability,
            "subject": subject,
            "release_basis": release_basis,
            "profile": run.profile_name,
            "verdict": result.verdict,
        },
        "window": {"started": run.created_at,
                   "evaluated": result.evaluated_at},
        "coverage": {"tested": tested, "not_tested": not_tested},
        "evidence": {
            "bundle_fingerprint": bundle["manifest"]["bundle_fingerprint"],
            "result_digest": fingerprint(result.model_dump()),
            "run_id": run.run_id,
        },
    }


def make_receipt(bundle_dir: str, keystore=None,
                 signer: str | None = None,
                 limitations: list[str] | None = None) -> str:
    from .bundle import load_bundle
    from .identity_portable import (
        OPERATOR_NAME,
        Keystore,
        default_keystore_dir,
    )

    path = os.path.join(bundle_dir, "receipt.json")
    path_problem = _receipt_file_problem(path, missing_ok=True)
    if path_problem:
        raise ValueError(f"refusing to write receipt: {path_problem}")

    bundle = load_bundle(bundle_dir)
    fields = _bundle_receipt_fields(bundle)

    keystore = keystore or Keystore(default_keystore_dir())
    signer = signer or OPERATOR_NAME
    identity = keystore.new_identity(signer)

    payload = {
        "claim": fields["claim"],
        "observer": identity["agent_id"],
        "window": fields["window"],
        "coverage": fields["coverage"],
        "limitations": limitations or DEFAULT_LIMITATIONS,
        "evidence": fields["evidence"],
    }
    receipt = {"payload": payload,
               "signature": keystore.sign(signer, payload),
               "controller_public": identity["controller_public"]}
    with open(path, "w") as f:
        json.dump(receipt, f, indent=2)
    return path


def verify_receipt(receipt_path: str,
                   bundle_dir: str | None = None) -> list[str]:
    """Offline verification. Returns problems; empty means the receipt
    verifies (which still proves commitment, not truth)."""
    from .identity_portable import verify_signature

    problems: list[str] = []
    receipt, read_problem = _load_receipt_document(receipt_path)
    if read_problem:
        return [read_problem]
    if not isinstance(receipt, dict):
        return ["receipt must be a JSON object"]
    payload = receipt.get("payload")
    if not isinstance(payload, dict):
        return ["receipt payload must be a JSON object"]
    problems.extend(_receipt_shape_problems(receipt, payload))
    controller_public = receipt.get("controller_public")
    signature = receipt.get("signature")
    if not isinstance(controller_public, str) \
            or not isinstance(signature, str):
        problems.append("receipt signature and controller key must be strings")
    elif not verify_signature(controller_public, payload, signature):
        problems.append("signature does not verify over the payload")
    if isinstance(controller_public, str):
        derived = ("did:town:"
                   + fingerprint(controller_public)
                   .removeprefix("sha256:")[:24])
        if derived != payload.get("observer"):
            problems.append("observer id does not match the signing key")
    if bundle_dir:
        from .bundle import load_bundle

        try:
            bundle = load_bundle(bundle_dir)
        except (OSError, json.JSONDecodeError, KeyError, TypeError,
                ValueError) as exc:
            problems.append(f"bundle unreadable for receipt verification: {exc}")
            return problems
        try:
            expected = _bundle_receipt_fields(bundle)
        except (KeyError, TypeError, ValueError) as exc:
            problems.append(
                f"bundle cannot produce receipt claims: {exc}")
            return problems
        claim = payload.get("claim")
        if not isinstance(claim, dict):
            problems.append("receipt claim must be a JSON object")
        else:
            for name, value in expected["claim"].items():
                if claim.get(name) != value:
                    problems.append(
                        f"receipt claim {name.replace('_', ' ')} does not match bundle")
        for name in ("coverage", "window"):
            if payload.get(name) != expected[name]:
                problems.append(f"receipt {name} does not match bundle")
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            problems.append("receipt evidence must be a JSON object")
        else:
            labels = {
                "bundle_fingerprint": "bundle fingerprint",
                "result_digest": "result digest",
                "run_id": "evidence run id",
            }
            for name, value in expected["evidence"].items():
                if evidence.get(name) != value:
                    problems.append(
                        f"receipt {labels[name]} does not match bundle")
    return problems


def render_proof(bundle_dir: str,
                 freshness_days: float = 30.0) -> tuple[bool, str]:
    """The TOWN-TESTED badge, rendered only when the evidence is
    conclusive, covered, fresh, and the bundle and receipt verify."""
    from .bundle import load_bundle, verify_bundle

    if isinstance(freshness_days, bool) \
            or not isinstance(freshness_days, (int, float)) \
            or not math.isfinite(freshness_days) or freshness_days < 0:
        return (False, "No Town Proof. freshness days must be a finite"
                " non-negative number.\n")

    bundle_problems = verify_bundle(bundle_dir)
    if bundle_problems:
        lines = ["No Town Proof. Bundle verification failed:"]
        lines += [f"  {problem}" for problem in bundle_problems]
        return False, "\n".join(lines) + "\n"

    bundle = load_bundle(bundle_dir)
    window_problems = _proof_window_problems(
        _bundle_receipt_fields(bundle)["window"], time.time())
    if window_problems:
        lines = ["No Town Proof. The evidence window is invalid:"]
        lines += [f"  {problem}" for problem in window_problems]
        return False, "\n".join(lines) + "\n"

    receipt_path = os.path.join(bundle_dir, "receipt.json")
    if not os.path.lexists(receipt_path):
        make_receipt(bundle_dir)
    problems = verify_receipt(receipt_path, bundle_dir)
    if problems:
        lines = ["No Town Proof. Receipt verification failed:"]
        lines += [f"  {problem}" for problem in problems]
        return False, "\n".join(lines) + "\n"
    receipt, read_problem = _load_receipt_document(receipt_path)
    if read_problem:
        return False, f"No Town Proof. {read_problem}.\n"
    if not isinstance(receipt, dict) \
            or not isinstance(receipt.get("payload"), dict):
        return False, "No Town Proof. Receipt became malformed.\n"
    payload = receipt["payload"]

    reasons: list[str] = list(problems)
    claim = payload["claim"]
    if claim["verdict"] != "passed":
        reasons.append(f"the verdict is {claim['verdict']}, not passed;"
                       " evidence of failure never renders a badge")
    age_days = (time.time() - payload["window"]["evaluated"]) / 86400.0
    if age_days > freshness_days:
        reasons.append(f"the evidence is {age_days:.1f} days old,"
                       f" beyond the {freshness_days:.0f} day freshness"
                       " window")
    if not payload["coverage"]["tested"]:
        reasons.append("nothing was tested")
    if payload["coverage"]["not_tested"]:
        reasons.append("not tested: "
                       + ", ".join(payload["coverage"]["not_tested"]))

    if reasons:
        lines = ["No Town Proof. The badge renders only from"
                 " conclusive, fresh, verified evidence:"]
        lines += [f"  {r}" for r in reasons]
        return False, "\n".join(lines) + "\n"

    tested = payload["coverage"]["tested"]
    not_tested = payload["coverage"]["not_tested"]
    coverage = f"{len(tested)} stages tested"
    if not_tested:
        coverage += f" ({', '.join(not_tested)} not tested)"
    window = time.strftime("%Y-%m-%d", time.gmtime(
        payload["window"]["evaluated"]))
    basis = claim["release_basis"]["profile_fingerprint"][:23]
    text = (
        "TOWN-TESTED\n"
        f"Capability {claim['capability']} was observed to pass for"
        f" release basis {basis},\n"
        f"under profile {claim['profile']}, by observer"
        f" {payload['observer']},\n"
        f"during window {window}, with coverage: {coverage}.\n"
        f"View exact evidence: {bundle_dir}\n"
        "This badge is narrow and expiring. It never means the agent"
        " is universally safe,\nreliable, authorized, endorsed, or"
        " future-proof.\n")
    return True, text
