# SPDX-License-Identifier: Apache-2.0
"""Vendored, pure-Python canonicalization + sealing primitives.

Single source of truth shared by the capsule anchored-reputation trust plugin
(which *seals*) and the ``receipt_reputation_capsule`` validator (which
*verifies*), so the two can never diverge on canonicalization. Nothing here
touches the network, the filesystem, the clock, or any external package — the
digests are a pure function of the receipt content, which is exactly why the
anchoring evidence can live on the deterministic trace instead of a file.

- ``jcs_digest`` — RFC 8785 (JCS) SHA-256 over the absent-field-normalized value,
  the sealed content digest. Fails closed on raw floats (§5.1): a binary float
  is not reproducibly digestible, so it raises rather than silently sealing a
  value a verifier could never confirm (matches capsule-emit 0.3.2 byte-for-byte).
- ``seal_chain`` — folds a digest into a running hash chain so seals cannot be
  reordered, dropped, or injected without detection.
- ``issuer_signed_payload`` / ``verify_receipt_signature`` — the *signing*
  canonicalization (plain sorted-key JSON) and Ed25519 check, distinct from the
  JCS *digest* form above.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: Genesis value the seal hash chain folds the first digest into.
SEAL_CHAIN_GENESIS = "0" * 64


def _jcs_string(s: str) -> str:
    """RFC 8785 §3.2.2.2 minimal-escape string serialization."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x08:
            out.append("\\b")
        elif o == 0x09:
            out.append("\\t")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0C:
            out.append("\\f")
        elif o == 0x0D:
            out.append("\\r")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_value(v: Any) -> str:
    """RFC 8785 JCS serialization of a JSON value (str/int/bool/null/list/dict).

    Floats are rejected: a digest over a binary float is not reproducible, so we
    fail closed rather than seal a value a verifier could never confirm.
    """
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, int):  # bool handled above (subclass of int)
        return str(v)
    if isinstance(v, float):
        raise ValueError("float is not permitted in a reproducible digest")
    if isinstance(v, list):
        return "[" + ",".join(_jcs_value(x) for x in cast("list[Any]", v)) + "]"
    if isinstance(v, dict):
        items = sorted(cast("dict[str, Any]", v).items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs_value(val) for k, val in items) + "}"
    raise TypeError(f"value of type {type(v).__name__!r} is not JSON-serializable here")


def _normalize_absent(v: Any) -> Any:
    """Drop null / empty-array / empty-object members, bottom-up (AAC canon)."""
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for key, val in cast("dict[str, Any]", v).items():
            nv = _normalize_absent(val)
            if nv is None:
                continue
            if isinstance(nv, (dict, list)) and len(cast("Any", nv)) == 0:
                continue
            out[key] = nv
        return out
    if isinstance(v, list):
        return [_normalize_absent(x) for x in cast("list[Any]", v)]
    return v


def jcs_digest(value: Any) -> str:
    """Lowercase-hex SHA-256 of JCS(normalize(value)) — the sealed content digest.

    Pure function of ``value``. Raises ``ValueError`` on a raw float (§5.1) and
    ``TypeError`` on a non-JSON-native type — fail-closed, so seal and verify
    agree for every value or agree to reject it.
    """
    return hashlib.sha256(_jcs_value(_normalize_absent(value)).encode("utf-8")).hexdigest()


def seal_chain(prev_chain_hex: str, subject_digest_hex: str) -> str:
    """Fold ``subject_digest`` into the running seal chain.

    ``chain[i] = SHA-256(chain[i-1] ‖ subject_digest[i])`` over the hex strings,
    with ``chain[-1] = SEAL_CHAIN_GENESIS``. Reordering, dropping, or injecting a
    seal changes every subsequent chain value, so the validator can detect it
    from the seal events alone.
    """
    return hashlib.sha256((prev_chain_hex + subject_digest_hex).encode("utf-8")).hexdigest()


def issuer_signed_payload(receipt: dict[str, Any]) -> bytes:
    """Sorted-key compact-JSON bytes the issuer signs: receipt minus signatures.

    This is the *signing* canonicalization (plain sorted-key JSON), distinct from
    the JCS *digest* form used for sealing — the issuer signs these bytes.
    """
    core: dict[str, Any] = {k: v for k, v in receipt.items() if k != "signature"}
    evidence = core.get("evidence")
    if isinstance(evidence, dict):
        trimmed: dict[str, Any] = {
            k: v for k, v in cast("dict[str, Any]", evidence).items() if k != "witness_signatures"
        }
        if trimmed:
            core["evidence"] = trimmed
        else:
            core.pop("evidence", None)
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_receipt_signature(receipt: dict[str, Any]) -> bool:
    """Return whether the receipt's issuer Ed25519 signature verifies; never raises.

    ``issuer_did`` is the hex of the raw 32-byte Ed25519 public key; ``signature``
    is the hex signature over :func:`issuer_signed_payload`.
    """
    issuer = receipt.get("issuer_did")
    sig = receipt.get("signature")
    if not isinstance(issuer, str) or not isinstance(sig, str):
        return False
    try:
        pub = bytes.fromhex(issuer)
        raw_sig = bytes.fromhex(sig)
        Ed25519PublicKey.from_public_bytes(pub).verify(raw_sig, issuer_signed_payload(receipt))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
