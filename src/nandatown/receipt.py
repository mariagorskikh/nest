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
import os
import time
from typing import Any

from .records import fingerprint

DEFAULT_LIMITATIONS = [
    "one run is one scoped observation, not a certificate",
    "the signature proves key commitment, not truth, independence, or"
    " safety",
    "a favorable result grants no permissions and endorses nothing",
]


def make_receipt(bundle_dir: str, keystore=None,
                 signer: str | None = None,
                 limitations: list[str] | None = None) -> str:
    from .bundle import load_bundle
    from .identity_portable import (
        OPERATOR_NAME,
        Keystore,
        default_keystore_dir,
    )

    bundle = load_bundle(bundle_dir)
    run = bundle["run"]
    result = bundle["result"]
    profile = bundle["profile"]

    capability = getattr(profile, "capability", None) \
        or getattr(getattr(profile, "task", None), "kind", None) \
        or run.profile_name
    subject = run.config.get("subject") \
        or ", ".join(p["name"] for p in run.participants)
    release_basis = {"profile_fingerprint": run.profile_fingerprint}
    if run.config.get("pinned_card_digest"):
        release_basis["card_digest"] = run.config["pinned_card_digest"]

    tested = [s.name for s in result.stages if s.status != "not_tested"]
    not_tested = [s.name for s in result.stages
                  if s.status == "not_tested"]

    keystore = keystore or Keystore(default_keystore_dir())
    signer = signer or OPERATOR_NAME
    identity = keystore.new_identity(signer)

    payload = {
        "claim": {
            "capability": capability,
            "subject": subject,
            "release_basis": release_basis,
            "profile": run.profile_name,
            "verdict": result.verdict,
        },
        "observer": identity["agent_id"],
        "window": {"started": run.created_at,
                   "evaluated": result.evaluated_at},
        "coverage": {"tested": tested, "not_tested": not_tested},
        "limitations": limitations or DEFAULT_LIMITATIONS,
        "evidence": {
            "bundle_fingerprint":
                bundle["manifest"]["bundle_fingerprint"],
            "result_digest": fingerprint(result.model_dump()),
            "run_id": run.run_id,
        },
    }
    receipt = {"payload": payload,
               "signature": keystore.sign(signer, payload),
               "controller_public": identity["controller_public"]}
    path = os.path.join(bundle_dir, "receipt.json")
    with open(path, "w") as f:
        json.dump(receipt, f, indent=2)
    return path


def verify_receipt(receipt_path: str,
                   bundle_dir: str | None = None) -> list[str]:
    """Offline verification. Returns problems; empty means the receipt
    verifies (which still proves commitment, not truth)."""
    from .identity_portable import verify_signature

    problems: list[str] = []
    try:
        with open(receipt_path) as f:
            receipt = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"receipt unreadable: {exc}"]
    payload = receipt.get("payload", {})
    if not verify_signature(receipt.get("controller_public", ""),
                            payload, receipt.get("signature", "")):
        problems.append("signature does not verify over the payload")
    derived = ("did:town:"
               + fingerprint(receipt.get("controller_public", ""))
               .removeprefix("sha256:")[:24])
    if derived != payload.get("observer"):
        problems.append("observer id does not match the signing key")
    if bundle_dir:
        from .bundle import load_bundle

        bundle = load_bundle(bundle_dir)
        if payload.get("evidence", {}).get("bundle_fingerprint") \
                != bundle["manifest"]["bundle_fingerprint"]:
            problems.append("receipt names a different bundle"
                            " fingerprint")
        if payload.get("evidence", {}).get("result_digest") \
                != fingerprint(bundle["result"].model_dump()):
            problems.append("receipt result digest does not match the"
                            " bundle's result")
    return problems


def render_proof(bundle_dir: str,
                 freshness_days: float = 30.0) -> tuple[bool, str]:
    """The TOWN-TESTED badge, rendered only when the evidence is
    conclusive, covered, fresh, and the bundle and receipt verify."""
    from .bundle import verify_bundle

    bundle_problems = verify_bundle(bundle_dir)
    if bundle_problems:
        lines = ["No Town Proof. Bundle verification failed:"]
        lines += [f"  {problem}" for problem in bundle_problems]
        return False, "\n".join(lines) + "\n"

    receipt_path = os.path.join(bundle_dir, "receipt.json")
    if not os.path.exists(receipt_path):
        make_receipt(bundle_dir)
    problems = verify_receipt(receipt_path, bundle_dir)
    with open(receipt_path) as f:
        payload = json.load(f)["payload"]

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
