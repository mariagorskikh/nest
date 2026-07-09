# SPDX-License-Identifier: Apache-2.0
"""Signed pre-action permit envelopes forming a per-agent hash chain.

An *envelope* is a small signed JSON object issued **before** an action
executes: who asked to do what, which policy entry decided, and what the
decision was. Refusals are first-class — a denied request yields a signed
envelope exactly like a grant, so "we said no" is provable later, not just an
absence of evidence.

An envelope has exactly eight fields:

- ``agent_id`` — whatever identity string the town's identity layer yields.
- ``action`` — ``{"verb": str, "resource": str, "params": dict}``.
- ``policy_id`` — the policy entry that produced the outcome.
- ``outcome`` — ``"authorized"`` | ``"denied"`` | ``"conditional"``.
- ``prev_hash`` — hex SHA-256 of the same agent's previous envelope (``None``
  for the first): deleting or reordering history breaks the chain.
- ``issued_at`` — RFC 3339 timestamp, **always caller-supplied** (the
  scenario's virtual clock); validated here, never generated.
- ``sig`` — hex Ed25519 signature over the canonical form minus ``sig``.
- ``pubkey`` — hex of the issuer's raw 32-byte Ed25519 public key.

Determinism: sorted-key compact JSON canonicalization, deterministic Ed25519
(RFC 8032), caller-supplied time — identical inputs give byte-identical
envelopes. Hostile input never raises out of the verifiers.

Example::

    env = issue_envelope(sk_hex, agent_id="a1", verb="read", resource="doc/1",
                         params={}, policy_id="rule:0", outcome="authorized",
                         prev_hash=None, issued_at="2026-01-01T00:00:00+00:00")
    assert verify_envelope(env)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

Envelope = dict[str, Any]
"""A permit envelope document (plain dict; see the module docstring)."""

OUTCOMES: frozenset[str] = frozenset({"authorized", "denied", "conditional"})
"""The closed set of permitted ``outcome`` values."""

_FIELDS = frozenset(
    {"agent_id", "action", "policy_id", "outcome", "prev_hash", "issued_at", "sig", "pubkey"}
)
_ACTION_FIELDS = frozenset({"verb", "resource", "params"})


def _is_hex(value: object, length: int) -> bool:
    """Return whether *value* is a hex string of exactly *length* characters."""
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def canonical_bytes(envelope: Envelope) -> bytes:
    """Canonical signing bytes: sorted-key compact JSON of the envelope minus ``sig``.

    Example::

        payload = canonical_bytes(env)
    """
    body = {k: v for k, v in envelope.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def envelope_hash(envelope: Envelope) -> str:
    """Hex SHA-256 of the full canonical envelope **including** ``sig``.

    This is the value a successor's ``prev_hash`` points at. Including the
    signature means the chain commits to the signed artifact itself, not just
    its content — swapping a signature breaks every later link.

    Example::

        h = envelope_hash(env)
    """
    body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def issue_envelope(
    signing_key: str,
    *,
    agent_id: str,
    verb: str,
    resource: str,
    params: dict[str, Any],
    policy_id: str,
    outcome: str,
    prev_hash: str | None,
    issued_at: str,
) -> Envelope:
    """Build and sign a complete envelope; the only way envelopes are minted.

    ``signing_key`` is the hex of a 32-byte Ed25519 private key. ``issued_at``
    is validated (RFC 3339 via :meth:`datetime.fromisoformat`) but never
    generated here. Raises ``ValueError`` on an unknown outcome, a bad key,
    a malformed ``prev_hash``, or an unparseable timestamp.

    Example::

        env = issue_envelope(sk_hex, agent_id="a1", verb="read", resource="r",
                             params={}, policy_id="default", outcome="denied",
                             prev_hash=None, issued_at="2026-01-01T00:00:00+00:00")
    """
    if outcome not in OUTCOMES:
        msg = f"unknown outcome {outcome!r}; expected one of {sorted(OUTCOMES)}"
        raise ValueError(msg)
    if prev_hash is not None and not _is_hex(prev_hash, 64):
        msg = "prev_hash must be None or a 64-character hex SHA-256"
        raise ValueError(msg)
    try:
        datetime.fromisoformat(issued_at)
    except (ValueError, TypeError) as exc:
        msg = f"issued_at is not a valid RFC 3339 timestamp: {issued_at!r}"
        raise ValueError(msg) from exc
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key))
    envelope: Envelope = {
        "agent_id": agent_id,
        "action": {"verb": verb, "resource": resource, "params": params},
        "policy_id": policy_id,
        "outcome": outcome,
        "prev_hash": prev_hash,
        "issued_at": issued_at,
        "pubkey": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
    }
    envelope["sig"] = key.sign(canonical_bytes(envelope)).hex()
    return envelope


def _well_formed(candidate: object) -> Envelope | None:
    """Structural validation: exactly eight fields, right types, closed enums."""
    if not isinstance(candidate, dict):
        return None
    env = cast("dict[str, Any]", candidate)
    if frozenset(env) != _FIELDS:
        return None
    action = env["action"]
    if not isinstance(action, dict) or frozenset(cast("dict[str, Any]", action)) != _ACTION_FIELDS:
        return None
    act = cast("dict[str, Any]", action)
    if (
        not all(isinstance(act[k], str) for k in ("verb", "resource"))
        or not isinstance(act["params"], dict)
        or not isinstance(env["agent_id"], str)
        or not env["agent_id"]
        or not isinstance(env["policy_id"], str)
        or env["outcome"] not in OUTCOMES
        or (env["prev_hash"] is not None and not _is_hex(env["prev_hash"], 64))
        or not isinstance(env["issued_at"], str)
        or not _is_hex(env["pubkey"], 64)
        or not _is_hex(env["sig"], 128)
    ):
        return None
    try:
        datetime.fromisoformat(env["issued_at"])
    except ValueError:
        return None
    return env


def verify_envelope(candidate: object) -> bool:
    """Return whether *candidate* is a well-formed envelope with a valid signature.

    Recomputes the canonical bytes and verifies ``sig`` under the embedded
    ``pubkey``. Any mutation of any field — or any structural defect — yields
    ``False``; hostile input never raises.

    Example::

        assert verify_envelope(env)
    """
    env = _well_formed(candidate)
    if env is None:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(env["pubkey"])))
        pub.verify(bytes.fromhex(str(env["sig"])), canonical_bytes(env))
    except (InvalidSignature, ValueError):
        return False
    return True


def order_chain(envelopes: list[Envelope]) -> list[Envelope] | None:
    """Order one agent's envelopes into its unique causal chain, or ``None``.

    Accepts envelopes in any order; returns them genesis-first, or ``None``
    unless they form exactly one intact chain. Rejected: any invalid envelope,
    more than one agent represented (a ``prev_hash`` reaching into another
    agent's chain is a foreign-chain splice), zero or multiple genesis
    envelopes, a ``prev_hash`` naming no present envelope (a gap, including a
    deleted interior link), two envelopes sharing a predecessor (a fork), or
    duplicates. An empty list is the empty chain.

    Example::

        ordered = order_chain([env_b, env_a])
        assert ordered is not None and ordered[0]["prev_hash"] is None
    """
    if not envelopes:
        return []
    if any(not verify_envelope(e) for e in envelopes):
        return None
    if len({str(e["agent_id"]) for e in envelopes}) != 1:
        return None
    by_hash: dict[str, Envelope] = {}
    for env in envelopes:
        digest = envelope_hash(env)
        if digest in by_hash:
            return None  # duplicate envelope
        by_hash[digest] = env
    genesis = [e for e in envelopes if e["prev_hash"] is None]
    if len(genesis) != 1:
        return None
    successor: dict[str, Envelope] = {}
    for env in envelopes:
        prev = env["prev_hash"]
        if prev is None:
            continue
        if prev not in by_hash:
            return None  # gap: predecessor missing (deleted or never present)
        if prev in successor:
            return None  # fork: two envelopes claim the same predecessor
        successor[str(prev)] = env
    chain = [genesis[0]]
    while (nxt := successor.get(envelope_hash(chain[-1]))) is not None:
        chain.append(nxt)
    return chain if len(chain) == len(envelopes) else None
