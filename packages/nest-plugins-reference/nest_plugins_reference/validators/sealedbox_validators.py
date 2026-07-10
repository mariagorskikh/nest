# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the ``sealedbox`` privacy plugin.

The default ``noop`` privacy plugin silently allows every attack below — its
``encrypt`` returns the plaintext unchanged, its ``decrypt`` returns its input,
and its ``verify_proof`` is an unconditional ``True``. These validators run on
the :class:`~nest_core.layers.privacy.Privacy` protocol surface (plus a
byte-level trace inspector for the reuse check), so the *same* check passes
against ``sealedbox`` and fails against ``noop``.

Problem 09 requires four attacks; ``sealedbox`` adds a fifth that is the point of
the plugin:

1. **Eavesdropper** — ``check_eavesdropper_blocked``: a non-audience agent must
   not recover the plaintext, and the plaintext must not appear verbatim on the
   wire.
2. **Replay** — ``check_replay_rejected``: a recipient accepts an envelope once
   and rejects a byte-identical replay.
3. **Field-injection** — ``check_field_injection_rejected``: an untampered
   selective-disclosure proof verifies; one with an edited revealed field does
   not.
4. **Stale-revocation** — ``check_stale_revocation_blocked``: a revoked member
   can read a pre-revocation message but not a post-revocation one.
5. **Deterministic key/nonce reuse (novel)** — ``check_no_two_time_pad`` /
   ``check_deterministic_reuse_safe``: reconstructing a deterministic plugin
   (counter reset to zero) and encrypting two *different* plaintexts must not
   produce a two-time pad. This **fails** against a counter-only scheme (the
   deterministic mode ``hybrid_x25519`` concedes is unsafe under reuse) and
   against ``noop``, and **passes** against ``sealedbox``'s SIV derivation. It is
   the adversarial witness that the plugin's headline property is load-bearing.

Example::

    report = await check_eavesdropper_blocked(outsider, envelope, secret=b"bid:1700")
    assert report.passed, report.detail
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from nest_plugins_reference.privacy.sealedbox import content_ciphertext
from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from nest_core.layers.privacy import Privacy
    from nest_core.types import AgentId, Proof, Statement


async def _try_decrypt(privacy: Privacy, envelope: bytes) -> tuple[bool, bytes | None]:
    """Attempt a decrypt; return ``(ok, plaintext)`` with any failure normalised.

    Any exception (not-in-audience, replay, tamper, malformed) is treated as a
    decrypt failure rather than propagating, so a validator can reason about the
    *policy outcome* uniformly across plugins.
    """
    try:
        return True, await privacy.decrypt(envelope)
    except Exception:  # noqa: BLE001 - any failure is, for policy purposes, "blocked"
        return False, None


async def check_eavesdropper_blocked(
    eavesdropper: Privacy, envelope: bytes, *, secret: bytes
) -> ValidatorReport:
    """Assert a non-audience agent cannot recover the plaintext from *envelope*.

    Passes iff the outsider's decrypt does **not** yield ``secret`` and ``secret``
    does not appear as a substring of the envelope bytes. Against ``noop`` the
    envelope *is* the plaintext, so both conditions fail. The on-wire substring
    test is a heuristic best suited to secrets of reasonable length; a 1-2 byte
    secret can match ciphertext bytes by chance, so use a realistic secret.

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
    ``tampered_proof``. Against ``noop`` (``verify_proof`` always ``True``) the
    tampered proof is wrongly accepted.

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

    Passes iff the member decrypts ``pre_revocation`` and fails to decrypt
    ``post_revocation``. Against ``noop`` both passthrough-"decrypt" successfully.

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


def check_no_two_time_pad(ct_a: bytes, pt_a: bytes, ct_b: bytes, pt_b: bytes) -> ValidatorReport:
    """Assert two ciphertexts do not share a keystream (no two-time pad).

    For any stream/CTR AEAD (ChaCha20-Poly1305 included) the ciphertext body is
    ``keystream XOR plaintext``. If two messages reuse a ``(key, nonce)`` pair
    their keystreams cancel, so ``ct_a XOR ct_b == pt_a XOR pt_b`` over the common
    length — a textbook two-time pad that leaks the plaintext XOR. This check
    detects exactly that signature.

    ``pt_a`` and ``pt_b`` must be **distinct** (otherwise the XOR is trivially
    zero and the test is vacuous).

    Example::

        report = check_no_two_time_pad(ct1, b"aaaa", ct2, b"bbbb")
        assert report.passed, report.detail
    """
    # Clamp to the shortest of all four so the zip(strict=True) below cannot raise
    # on a malformed/short ciphertext — a mismatch is a failed check, not a crash.
    n = min(len(pt_a), len(pt_b), len(ct_a), len(ct_b))
    if n == 0:
        return ValidatorReport(
            passed=False, detail="cannot check with an empty plaintext/ciphertext"
        )
    if pt_a[:n] == pt_b[:n]:
        return ValidatorReport(passed=False, detail="plaintexts must be distinct to detect reuse")
    ct_xor = bytes(x ^ y for x, y in zip(ct_a[:n], ct_b[:n], strict=True))
    pt_xor = bytes(x ^ y for x, y in zip(pt_a[:n], pt_b[:n], strict=True))
    if ct_xor == pt_xor:
        return ValidatorReport(
            passed=False,
            detail="two-time pad: ciphertext XOR reveals plaintext XOR (key/nonce reused)",
            evidence={"leaked_bytes": n},
        )
    return ValidatorReport(passed=True, detail="no keystream reuse across reconstructed instances")


async def check_deterministic_reuse_safe(
    make_sender: Callable[[], Privacy],
    *,
    audience: list[AgentId],
    plaintext_a: bytes,
    plaintext_b: bytes,
    extract: Callable[[bytes], bytes] = content_ciphertext,
) -> ValidatorReport:
    """Assert reconstructing a deterministic plugin does not leak a two-time pad.

    Builds two **fresh** sender instances via ``make_sender`` — modelling a
    restart or two instances of one agent, which resets any in-memory message
    counter to zero — and encrypts two *different* plaintexts, one per instance.
    A counter-only deterministic scheme re-derives the same ``(key, nonce)`` and
    produces a two-time pad; ``sealedbox``'s SIV derivation binds the plaintext
    into the key/nonce, so the keystreams differ.

    ``extract`` pulls the content ciphertext out of an envelope (default: the
    ``sealedbox`` parser). For a passthrough plugin, pass ``lambda env: env``.

    Passes against ``sealedbox``; fails against ``noop`` and any counter-only
    deterministic plugin.

    Example::

        report = await check_deterministic_reuse_safe(
            lambda: SealedBoxPrivacy(AgentId("s"), seed=7),
            audience=[AgentId("r")], plaintext_a=b"AAAA", plaintext_b=b"BBBB",
        )
        assert report.passed, report.detail
    """
    env_a = await make_sender().encrypt(plaintext_a, audience)
    env_b = await make_sender().encrypt(plaintext_b, audience)
    try:
        ct_a = extract(env_a)
        ct_b = extract(env_b)
    except Exception as exc:  # noqa: BLE001 - a malformed extract is a failed check
        return ValidatorReport(passed=False, detail=f"could not extract ciphertext: {exc}")
    return check_no_two_time_pad(ct_a, plaintext_a, ct_b, plaintext_b)


def corrupt_proof(proof: Proof, *, field: str | None = None) -> Proof:
    """Return a copy of *proof* with one revealed field's value flipped.

    Drives :func:`check_field_injection_rejected`. If *field* is ``None`` the
    first disclosed field (sorted) is corrupted. On a proof body without a
    ``disclosed`` map it returns the proof unchanged (the validator then simply
    observes no tamper effect).

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
