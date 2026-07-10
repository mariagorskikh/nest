# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the ``trust_gated`` privacy plugin.

Four attack classes that **both** existing reference privacy plugins allow —
``noop`` because it hands every byte to everyone, and ``hybrid_x25519``
because it is deliberately trust-blind (any agent the sender lists in the
audience gets the full plaintext, regardless of reputation):

1. **Low-trust exfiltration.** A recipient below the trust floor recovers the
   plaintext. :func:`check_low_trust_blocked` asserts the low-trust reader
   cannot recover the payload and the payload never rides the wire in clear.
2. **Partial-tier overexposure.** A mid-trust recipient sees fields the
   policy says it must not. :func:`check_partial_redaction_enforced` asserts
   the mid-trust reader receives *something* other than the full plaintext
   and that no hidden field value reaches it (or the wire).
3. **Gate laundering.** An attacker edits the gate table to upgrade a tier.
   :func:`check_gate_tamper_rejected` asserts a doctored envelope (built with
   :func:`forge_tier_upgrade`) never yields the plaintext. Against the
   reference plugins the "forgery" is a no-op — their envelopes carry no gate
   — so the plaintext flows and the check fails, which is the point.
4. **Silent denial.** A gated-out agent is refused with no auditable trail.
   :func:`check_denial_receipt_auditable` asserts the denial surfaces a
   receipt bound to the message that the issuer verifies, and that a forged
   copy of the receipt does not verify.

Each validator is a pure ``async`` function on the
:class:`~nest_core.layers.privacy.Privacy` protocol surface (receipt access is
duck-typed via the exception's ``receipt`` attribute and the sender's
``verify_denial`` callable, so no import of the plugin class is needed). The
same check therefore runs against every privacy plugin:

* against ``trust_gated`` every check **passes**;
* against ``noop`` **and** ``hybrid_x25519`` every check **fails** — the
  charter's bar for "adversarial", raised one notch: the attack class must be
  one the *hardened* merged plugin also cannot catch.

Example::

    report = await check_low_trust_blocked(alice, mallory, payload=secret, audience=aud)
    assert report.passed, report.detail
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from nest_core.layers.privacy import Privacy
    from nest_core.types import AgentId


async def _try_decrypt(
    privacy: Privacy, envelope: bytes
) -> tuple[bool, bytes | None, Exception | None]:
    """Attempt a decrypt; return ``(ok, plaintext, exception)`` without raising.

    Example::

        ok, plaintext, exc = await _try_decrypt(reader, envelope)
    """
    try:
        return True, await privacy.decrypt(envelope), None
    except Exception as exc:  # noqa: BLE001 - refusal is a policy outcome here
        return False, None, exc


async def check_low_trust_blocked(
    sender: Privacy, low_trust_reader: Privacy, *, payload: bytes, audience: list[AgentId]
) -> ValidatorReport:
    """Assert an audience member below the trust floor cannot read *payload*.

    Passes iff the low-trust reader's decrypt does not yield the payload and
    the payload does not appear verbatim in the envelope. ``noop`` fails both
    conditions; ``hybrid_x25519`` fails the first — it encrypts *to* the
    low-trust member because it never consults trust.

    Example::

        report = await check_low_trust_blocked(alice, mallory, payload=b"s", audience=aud)
        assert report.passed, report.detail
    """
    envelope = await sender.encrypt(payload, audience)
    if payload in envelope:
        return ValidatorReport(passed=False, detail="payload rides the wire in clear")
    ok, recovered, _ = await _try_decrypt(low_trust_reader, envelope)
    if ok and recovered == payload:
        return ValidatorReport(
            passed=False,
            detail="low-trust audience member recovered the full plaintext",
            evidence={"recovered_bytes": len(recovered or b"")},
        )
    return ValidatorReport(passed=True, detail="low-trust member blocked from plaintext")


async def check_partial_redaction_enforced(
    sender: Privacy,
    mid_trust_reader: Privacy,
    *,
    payload: bytes,
    audience: list[AgentId],
    hidden: list[bytes],
) -> ValidatorReport:
    """Assert a mid-trust member gets a redacted view, never the hidden fields.

    Passes iff no ``hidden`` byte-string appears in the envelope, the reader's
    recovered view is not the full payload, and no hidden value appears in
    that view. ``noop`` and ``hybrid_x25519`` both hand the mid-trust member
    the complete payload, so both fail.

    Example::

        report = await check_partial_redaction_enforced(
            alice, carol, payload=doc, audience=aud, hidden=[b"250000"]
        )
        assert report.passed, report.detail
    """
    envelope = await sender.encrypt(payload, audience)
    for secret in hidden:
        if secret in envelope:
            return ValidatorReport(passed=False, detail="hidden field rides the wire in clear")
    ok, recovered, _ = await _try_decrypt(mid_trust_reader, envelope)
    if ok and recovered == payload:
        return ValidatorReport(
            passed=False, detail="mid-trust member received the full, unredacted plaintext"
        )
    if ok and recovered is not None:
        for secret in hidden:
            if secret in recovered:
                return ValidatorReport(
                    passed=False, detail="hidden field leaked into the mid-trust view"
                )
    return ValidatorReport(passed=True, detail="mid-trust member confined to the redacted view")


def forge_tier_upgrade(envelope: bytes, *, agent: str) -> bytes:
    """Rewrite *envelope*'s gate table to claim *agent* deserves the full tier.

    For envelopes without a gate table (``noop``, ``hybrid_x25519``) the input
    is returned unchanged — the "attack" needs no forgery there, which is
    exactly why those plugins fail :func:`check_gate_tamper_rejected`.

    Example::

        forged = forge_tier_upgrade(envelope, agent="mallory")
    """
    try:
        loaded: Any = json.loads(envelope)
    except (ValueError, TypeError):
        return envelope
    if not isinstance(loaded, dict):
        return envelope
    obj = cast("dict[str, Any]", loaded)
    gate = obj.get("gate")
    if not isinstance(gate, list):
        return envelope
    for item in cast("list[Any]", gate):
        if isinstance(item, dict):
            entry = cast("dict[str, Any]", item)
            if entry.get("agent") == agent:
                entry["tier"] = "full"
                entry["score"] = 0.99
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


async def check_gate_tamper_rejected(
    sender: Privacy,
    reader: Privacy,
    *,
    payload: bytes,
    audience: list[AgentId],
    upgrade_agent: str,
) -> ValidatorReport:
    """Assert a doctored gate table never yields the plaintext to *reader*.

    Builds the forgery with :func:`forge_tier_upgrade` and passes iff the
    reader cannot recover the payload from the forged envelope. Reference
    plugins carry no gate to authenticate, so the payload flows and the check
    fails against them.

    Example::

        report = await check_gate_tamper_rejected(
            alice, bob, payload=b"s", audience=aud, upgrade_agent="mallory"
        )
        assert report.passed, report.detail
    """
    envelope = await sender.encrypt(payload, audience)
    forged = forge_tier_upgrade(envelope, agent=upgrade_agent)
    ok, recovered, exc = await _try_decrypt(reader, forged)
    if ok and recovered == payload:
        return ValidatorReport(
            passed=False,
            detail="reader recovered plaintext from an envelope with a doctored gate table",
            evidence={"forgery_changed_bytes": forged != envelope},
        )
    return ValidatorReport(
        passed=True,
        detail="doctored gate table rejected",
        evidence={"refusal": type(exc).__name__ if exc is not None else "plaintext-mismatch"},
    )


async def check_denial_receipt_auditable(
    sender: Privacy, denied_reader: Privacy, *, payload: bytes, audience: list[AgentId]
) -> ValidatorReport:
    """Assert a trust denial is refused *with* a verifiable receipt.

    Passes iff the denied reader's decrypt raises an exception carrying a
    ``receipt`` mapping, the sender's ``verify_denial`` accepts it, and a
    score-forged copy is rejected. ``noop`` fails because the denied agent
    simply reads the payload; ``hybrid_x25519`` fails because its refusal is
    silent — no receipt, nothing to audit.

    Example::

        report = await check_denial_receipt_auditable(alice, mallory, payload=b"s", audience=aud)
        assert report.passed, report.detail
    """
    envelope = await sender.encrypt(payload, audience)
    ok, recovered, exc = await _try_decrypt(denied_reader, envelope)
    if ok:
        return ValidatorReport(
            passed=False,
            detail="denied agent was not refused",
            evidence={"recovered_payload": recovered == payload},
        )
    receipt_obj: Any = getattr(exc, "receipt", None)
    if not isinstance(receipt_obj, dict):
        return ValidatorReport(
            passed=False, detail="denial is silent: refusal carries no auditable receipt"
        )
    receipt = cast("dict[str, Any]", receipt_obj)
    verify_attr: Any = getattr(sender, "verify_denial", None)
    if not callable(verify_attr):
        return ValidatorReport(passed=False, detail="sender cannot verify its own receipts")
    if not bool(verify_attr(receipt)):
        return ValidatorReport(passed=False, detail="issued receipt failed verification")
    forged = dict(receipt)
    forged["score"] = 0.99
    if bool(verify_attr(forged)):
        return ValidatorReport(passed=False, detail="score-forged receipt verified")
    return ValidatorReport(
        passed=True, detail="denial refused with a verifiable, unforgeable receipt"
    )
