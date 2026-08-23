# SPDX-License-Identifier: Apache-2.0
"""Detached signing and offline verification for ``town.test-result/1``.

A result already binds what it ran against: the profile by ``profile.digest``,
the run by ``execution.seed`` and ``execution.scenario``, the trace by an
artifact digest. The document carrying those bindings is itself unsigned, so a
reader who did not run it cannot tell an untouched result from an edited one —
changing ``evaluation.verdict`` is a text edit that leaves every one of those
internal digests valid.

This module closes that one gap. It never modifies the result. It digests the
document *as received* with :func:`~nest_core.canonical.jcs_digest`, restates the
facts a reader needs in order to interpret the verdict, and signs the whole
statement. Verification recomputes the digest and checks the signature, reaching
nothing but the two objects it is handed — no network, no service, no registry.

Reusing ``nest_core.canonical`` is deliberate rather than incidental. The
attestation is a receipt in exactly the shape the rest of the repository already
signs and verifies, over exactly the same canonicalization, so an attested
digest and a sealed one can never disagree about what a document *is*.

Signing validates the document through :class:`TestResult` rather than around it,
so a signature can only ever cover something the contract already accepts. Every
invariant the model enforces is inherited for free — that a completed ``pass``
has no non-passing required check, that an ``incomplete`` run is
``inconclusive``, that conclusive checks carry evidence. None of that is
re-implemented here; a self-contradicting result is refused because the contract
refuses it.

One thing the contract cannot know is added. A hosted model can be revised
without notice, mutating what was tested while every local digest stays valid, so
``mutable_dependencies`` is required and an empty sequence is a positive claim
rather than a default — the difference between "nothing was unfrozen" and "nobody
said". It is why an attested verdict is a statement about a run at a time rather
than a standing certificate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from nest_core.canonical import issuer_signed_payload, jcs_digest, verify_receipt_signature

from .models import TestResult

ATTESTATION_SCHEMA_VERSION: Final = "town.test-attestation/1"
RESULT_SCHEMA_VERSION: Final = "town.test-result/1"


class AttestationError(Exception):
    """The result cannot be honestly attested in the form it was given."""


@dataclass(frozen=True)
class MutableDependency:
    """Something that could change underneath the run's pinned artifacts.

    The case this exists for is a hosted model: every local artifact stays frozen
    and every digest stays valid while the thing under test is quietly revised.
    Naming it is what keeps the attestation honest about what it could not freeze,
    and is why a rung or verdict is a statement about a run at a time rather than
    a standing certificate.
    """

    name: str
    kind: str
    observed_at: str
    observed_version: str | None = None

    def to_json(self) -> dict[str, Any]:
        """Return the JSON form embedded in the signed statement."""
        return {
            "name": self.name,
            "kind": self.kind,
            "observed_at": self.observed_at,
            "observed_version": self.observed_version,
        }


@dataclass(frozen=True)
class AttestationVerdict:
    """Outcome of checking an attestation against the result it claims to cover."""

    ok: bool
    issuer_did: str | None = None
    mutable_dependencies: tuple[dict[str, Any], ...] = ()
    reasons: tuple[str, ...] = ()


def result_digest(result: Mapping[str, Any]) -> str:
    """Return the lowercase-hex JCS digest of *result* exactly as received.

    This is the binding between statement and document. It covers the whole
    result, so every field is load-bearing: a changed verdict, a widened coverage
    claim, or a swapped seed all break it.
    """
    return jcs_digest(dict(result))


def _validate_shape(result: Mapping[str, Any]) -> TestResult:
    """Parse *result* through the contract's own model, failing closed."""
    try:
        return TestResult.model_validate(dict(result))
    except ValidationError as exc:
        raise AttestationError(f"result does not satisfy {RESULT_SCHEMA_VERSION}: {exc}") from exc


def _histogram(parsed: TestResult) -> dict[str, int]:
    """Return the verbatim count of each check status.

    Nothing is folded together. A reader gets the same breakdown the result
    carried, so ``inconclusive`` can never be mistaken for a pass on the way into
    the signed statement.
    """
    counts: dict[str, int] = {}
    for check in parsed.evaluation.checks:
        counts[check.status] = counts.get(check.status, 0) + 1
    return counts


def build_attestation(
    result: Mapping[str, Any],
    *,
    signing_key: Ed25519PrivateKey,
    mutable_dependencies: Sequence[MutableDependency],
    attested_at: str | None = None,
) -> dict[str, Any]:
    """Return a signed statement covering *result*, which is never modified.

    *mutable_dependencies* is required. Pass an empty sequence to make the
    positive claim that nothing in this run could change underneath its pinned
    artifacts.
    """
    parsed = _validate_shape(result)
    histogram = _histogram(parsed)

    statement: dict[str, Any] = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "result_schema_version": parsed.schema_version,
        "result_digest": result_digest(result),
        "run_id": parsed.run_id,
        "profile": {
            "id": parsed.profile.id,
            "version": parsed.profile.version,
            "digest": parsed.profile.digest,
        },
        "execution": {
            "scenario": parsed.execution.scenario,
            "seed": parsed.execution.seed,
            "status": parsed.execution.status,
            "finished_at": parsed.execution.finished_at,
        },
        "evaluation": {
            "verdict": parsed.evaluation.verdict,
            "check_histogram": histogram,
        },
        "target": {
            "kind": parsed.target.kind,
            "label": parsed.target.label,
            "attribution": parsed.target.attribution,
        },
        "tool": {
            "name": parsed.tool.name,
            "version": parsed.tool.version,
            "commit": parsed.tool.commit,
        },
        "mutable_dependencies": [dep.to_json() for dep in mutable_dependencies],
        "attested_at": attested_at or parsed.execution.finished_at,
        "issuer_did": signing_key.public_key().public_bytes_raw().hex(),
    }
    statement["signature"] = signing_key.sign(issuer_signed_payload(statement)).hex()
    return statement


def verify_attestation(
    result: Mapping[str, Any], attestation: Mapping[str, Any]
) -> AttestationVerdict:
    """Check that *attestation* covers *result*. Offline: reads nothing else.

    The signature is checked first, so every field consulted afterwards is one the
    issuer actually committed to; only then is the result's digest recomputed and
    compared.
    """
    statement = dict(attestation)
    if not verify_receipt_signature(statement):
        return AttestationVerdict(ok=False, reasons=("signature does not verify",))

    reasons: list[str] = []
    issuer = statement.get("issuer_did")
    issuer_did = issuer if isinstance(issuer, str) else None

    if statement.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        reasons.append(
            f"attestation schema_version is {statement.get('schema_version')!r}, "
            f"expected {ATTESTATION_SCHEMA_VERSION!r}"
        )

    claimed = statement.get("result_digest")
    actual = result_digest(result)
    if claimed != actual:
        reasons.append(
            f"result does not match the attestation "
            f"(attested {claimed}, this result digests to {actual})"
        )

    if statement.get("result_schema_version") != result.get("schema_version"):
        reasons.append("result schema_version differs from the attested one")

    if "mutable_dependencies" not in statement:
        reasons.append("attestation does not state whether any dependency was unfrozen")

    raw_deps = statement.get("mutable_dependencies")
    deps: tuple[dict[str, Any], ...] = ()
    if isinstance(raw_deps, list):
        entries = cast("list[Any]", raw_deps)
        deps = tuple(
            dict(cast("dict[str, Any]", entry)) for entry in entries if isinstance(entry, dict)
        )

    return AttestationVerdict(
        ok=not reasons,
        issuer_did=issuer_did,
        mutable_dependencies=deps,
        reasons=tuple(reasons),
    )
