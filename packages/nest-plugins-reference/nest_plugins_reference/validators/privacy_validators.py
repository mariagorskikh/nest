# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the ``hybrid_x25519`` privacy plugin.

Four attacks the default ``noop`` privacy plugin silently allows — because
``encrypt`` returns the plaintext unchanged, ``decrypt`` returns its input, and
``verify_proof`` is an unconditional ``True``:

1. **Eavesdropper.** A non-audience agent decrypts an intercepted envelope.
   ``check_eavesdropper_blocked`` asserts the outsider cannot recover the
   plaintext *and* the plaintext never appears verbatim in the envelope bytes.
2. **Replay.** A recorded envelope is re-presented to its recipient.
   ``check_replay_rejected`` asserts the first decrypt succeeds and the second
   (identical) decrypt fails.
3. **Field-injection.** An attacker edits a revealed field of a
   selective-disclosure proof. ``check_field_injection_rejected`` asserts the
   untampered proof verifies and the tampered one does not.
4. **Stale-revocation.** A member revoked at epoch *E* decrypts a message issued
   at epoch ``>= E``. ``check_stale_revocation_blocked`` asserts the member can
   read a pre-revocation envelope but not a post-revocation one.

Each validator is a pure ``async`` function on the :class:`~nest_core.layers.privacy.Privacy`
protocol surface — it performs only ``encrypt``/``decrypt``/``verify_proof``
calls and never reaches into plugin internals. That is what lets the *same*
check run against both plugins:

* against ``hybrid_x25519`` every check **passes**;
* against ``noop`` every check **fails** — the validators literally cannot be
  satisfied by the passthrough reference plugin, which is the charter's bar for
  "adversarial".

The caller supplies the already-built artifacts (envelopes, proofs) so the
validator stays plugin-agnostic; helpers :func:`corrupt_proof` build the
tampered proof used by attack 3.

Example::

    report = await check_eavesdropper_blocked(outsider, envelope, secret=b"bid:1700")
    assert report.passed, report.detail
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from nest_core.layers.privacy import Privacy
    from nest_core.types import Proof, Statement


async def _try_decrypt(privacy: Privacy, envelope: bytes) -> tuple[bool, bytes | None]:
    """Attempt a decrypt; return ``(ok, plaintext)`` with failures normalised.

    Any exception (not-in-audience, replay, tamper, malformed) is treated as a
    decrypt failure rather than propagating, so a validator can reason about the
    *policy outcome* uniformly across plugins.

    Example::

        ok, pt = await _try_decrypt(outsider, envelope)
    """
    try:
        return True, await privacy.decrypt(envelope)
    except Exception:  # noqa: BLE001 - any failure is, for policy purposes, "blocked"
        return False, None


async def check_eavesdropper_blocked(
    eavesdropper: Privacy, envelope: bytes, *, secret: bytes
) -> ValidatorReport:
    """Assert a non-audience agent cannot recover the plaintext from *envelope*.

    Passes iff the outsider's decrypt does **not** yield ``secret`` and
    ``secret`` does not appear as a substring of the envelope bytes (so even a
    passthrough "encryption" that leaks the payload on the wire fails).

    Against ``noop`` the envelope *is* the plaintext, so both conditions fail.

    Example::

        report = await check_eavesdropper_blocked(carol, env, secret=b"bid:1700")
        assert report.passed, report.detail
    """
    ok, recovered = await _try_decrypt(eavesdropper, envelope)
    leaked_via_decrypt = ok and recovered == secret
    leaked_on_wire = secret in envelope
    if leaked_via_decrypt or leaked_on_wire:
        return ValidatorReport(
            passed=False,
            detail="eavesdropper recovered plaintext"
            if leaked_via_decrypt
            else "plaintext appears verbatim in the envelope",
            evidence={"via_decrypt": leaked_via_decrypt, "on_wire": leaked_on_wire},
        )
    return ValidatorReport(passed=True, detail="eavesdropper learned nothing")


async def check_replay_rejected(recipient: Privacy, envelope: bytes) -> ValidatorReport:
    """Assert a recipient accepts an envelope once and rejects a replay of it.

    Passes iff the first decrypt succeeds and the second (byte-identical) decrypt
    fails. Against ``noop`` both succeed (it has no replay memory).

    Example::

        report = await check_replay_rejected(bob, env)
        assert report.passed, report.detail
    """
    first_ok, _ = await _try_decrypt(recipient, envelope)
    second_ok, _ = await _try_decrypt(recipient, envelope)
    if not first_ok:
        return ValidatorReport(passed=False, detail="legitimate first decrypt failed")
    if second_ok:
        return ValidatorReport(passed=False, detail="replayed envelope was accepted twice")
    return ValidatorReport(passed=True, detail="replay rejected on second presentation")


async def check_field_injection_rejected(
    verifier: Privacy, statement: Statement, good_proof: Proof, tampered_proof: Proof
) -> ValidatorReport:
    """Assert an untampered proof verifies and a field-tampered proof does not.

    Passes iff ``verify_proof`` accepts ``good_proof`` and rejects
    ``tampered_proof``. Against ``noop`` (``verify_proof`` is always ``True``)
    the tampered proof is wrongly accepted.

    Example::

        bad = corrupt_proof(good)
        report = await check_field_injection_rejected(v, stmt, good, bad)
        assert report.passed, report.detail
    """
    if not await verifier.verify_proof(statement, good_proof):
        return ValidatorReport(passed=False, detail="honest proof failed to verify")
    if await verifier.verify_proof(statement, tampered_proof):
        return ValidatorReport(passed=False, detail="tampered proof was accepted")
    return ValidatorReport(passed=True, detail="field-injected proof rejected")


async def check_stale_revocation_blocked(
    member: Privacy, pre_revocation: bytes, post_revocation: bytes
) -> ValidatorReport:
    """Assert a revoked member can read a pre- but not a post-revocation message.

    Passes iff the member decrypts ``pre_revocation`` (it was in that audience)
    and fails to decrypt ``post_revocation`` (excluded after revocation). Against
    ``noop`` both passthrough-"decrypt" successfully.

    Example::

        report = await check_stale_revocation_blocked(carol, pre, post)
        assert report.passed, report.detail
    """
    pre_ok, _ = await _try_decrypt(member, pre_revocation)
    post_ok, _ = await _try_decrypt(member, post_revocation)
    if not pre_ok:
        return ValidatorReport(passed=False, detail="member could not read pre-revocation message")
    if post_ok:
        return ValidatorReport(
            passed=False, detail="revoked member decrypted a post-revocation message"
        )
    return ValidatorReport(passed=True, detail="post-revocation message blocked for revoked member")


def corrupt_proof(proof: Proof, *, field: str | None = None) -> Proof:
    """Return a copy of *proof* with one revealed field's value flipped.

    Used to drive :func:`check_field_injection_rejected`. If *field* is ``None``
    the first disclosed field (sorted) is corrupted. Works on the
    ``merkle-selective-disclosure`` proof body; on any other body it returns the
    proof unchanged (so the validator simply observes no tamper effect).

    Example::

        bad = corrupt_proof(good_proof)
    """
    try:
        loaded: Any = json.loads(proof.data)
    except (ValueError, TypeError):
        return proof
    if not isinstance(loaded, dict):
        return proof
    body = cast("dict[str, Any]", loaded)
    raw_disclosed = body.get("disclosed")
    if not isinstance(raw_disclosed, dict):
        return proof
    disclosed = cast("dict[str, Any]", raw_disclosed)
    if not disclosed:
        return proof
    target = field if field is not None else sorted(disclosed)[0]
    raw_entry = disclosed.get(target)
    if not isinstance(raw_entry, dict):
        return proof
    entry = cast("dict[str, Any]", raw_entry)
    if "value" not in entry:
        return proof
    entry["value"] = str(entry["value"]) + "!tampered"
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return proof.model_copy(update={"data": payload})
