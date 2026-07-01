# SPDX-License-Identifier: Apache-2.0
"""Signed, identity-bound policy manifests for agent governance.

A :class:`PolicyManifest` is the owner-authored, cryptographically-signed
declaration of what an agent is allowed to do across four governance
dimensions: which tools/actions it may call, what data it may expose (and to
whom), how much it may spend, and which actions require prior authorization.

The manifest is signed with the agent's own identity key (see
``nest_plugins_reference.identity.ed25519_rotating``) so it is bound to the
agent's cryptographic identity: only a manifest signed by the agent's key is
honoured, and any tampering — widening the tool list, raising the spend cap —
invalidates the signature, so :func:`verify_manifest` returns ``False``. The
owner *authors* the policy, but the agent's own code cannot loosen it at
runtime.

Example::

    from nest_core.types import AgentId
    from nest_plugins_reference.identity.ed25519_rotating import (
        Ed25519RotatingIdentity,
    )

    ident = Ed25519RotatingIdentity(AgentId("buyer-1"), seed=b"seed")
    manifest = PolicyManifest(
        agent_id=AgentId("buyer-1"), tools=["buy"], budget=Budget(cap=500),
    )
    signed = sign_manifest(ident, manifest)
    assert verify_manifest(ident, signed)
"""

from __future__ import annotations

import json
from typing import Any, Protocol, cast

from nest_core.types import AgentId, Signature
from pydantic import BaseModel, Field, field_serializer, field_validator


class Budget(BaseModel):
    """A spend ceiling for one currency.

    Example::

        budget = Budget(cap=500, currency="credits")
    """

    cap: int
    currency: str = "credits"


class Approval(BaseModel):
    """A rule marking an op as requiring prior authorization above a threshold.

    An action ``op`` whose amount exceeds ``threshold`` may only proceed when an
    approval for ``op`` has been granted (recorded in policy state). A
    ``threshold`` of ``0`` means the op always needs authorization.

    Example::

        approval = Approval(op="pay", threshold=200)
    """

    op: str
    threshold: int = 0


class PolicyManifest(BaseModel):
    """An agent's signed, identity-bound governance policy.

    ``data`` maps a data classification (e.g. ``"pii"``) to the list of agent
    ids that classification may be exposed to (``"*"`` means any audience).

    Example::

        manifest = PolicyManifest(
            agent_id=AgentId("a1"), tools=["buy"], budget=Budget(cap=500),
        )
    """

    agent_id: AgentId
    tools: list[str] = Field(default_factory=list)
    data: dict[str, list[str]] = Field(default_factory=dict)
    budget: Budget | None = None
    approvals: list[Approval] = Field(default_factory=lambda: list[Approval]())
    issued_at: float = 0.0
    signature: Signature | None = None

    def signing_bytes(self) -> bytes:
        """Return the canonical, deterministic bytes the signature covers.

        Excludes the ``signature`` field itself so signing and verification
        operate over identical content regardless of insertion order.

        Example::

            raw = manifest.signing_bytes()
        """
        payload = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")

    @field_serializer("signature", when_used="json")
    def _serialize_signature(self, sig: Signature | None) -> dict[str, Any] | None:
        """Render the signature JSON-safely (raw ``bytes`` -> hex).

        Without this, ``model_dump_json`` raises on the signature's raw byte
        ``value``. Hex keeps the *signed* manifest serialisable into a trace
        ``manifest:`` announcement and decodable by validators, while
        :meth:`signing_bytes` (which excludes the signature) is unaffected.

        Example::

            payload = signed.model_dump_json()
        """
        if sig is None:
            return None
        return {
            "signer": str(sig.signer),
            "value": sig.value.hex(),
            "algorithm": sig.algorithm,
            "key_id": sig.key_id,
            "signed_at": sig.signed_at,
        }

    @field_validator("signature", mode="before")
    @classmethod
    def _decode_signature(cls, value: Any) -> Any:
        """Decode a hex-encoded signature ``value`` back into ``bytes``.

        Inverse of :meth:`_serialize_signature`, so a manifest round-trips
        through ``model_validate_json(signed.model_dump_json())`` and still
        verifies. Pass-through for the normal in-memory ``Signature`` path.

        Example::

            same = PolicyManifest.model_validate_json(signed.model_dump_json())
        """
        if not isinstance(value, dict):
            return value
        raw = cast("dict[str, Any]", value)
        hex_value = raw.get("value")
        if not isinstance(hex_value, str):
            return raw
        try:
            decoded = bytes.fromhex(hex_value)
        except ValueError:
            return raw
        return {**raw, "value": decoded}


class ManifestSigner(Protocol):
    """Structural identity interface used to sign and verify manifests.

    Satisfied by ``nest_plugins_reference.identity.ed25519_rotating`` (and any
    identity plugin exposing ``sign``/``verify``).

    Example::

        signer: ManifestSigner = Ed25519RotatingIdentity(AgentId("a1"), seed=b"s")
    """

    def sign(self, payload: bytes) -> Signature: ...

    def verify(
        self,
        payload: bytes,
        sig: Signature,
        agent: AgentId,
        as_of: float | None = None,
    ) -> bool: ...


def sign_manifest(identity: ManifestSigner, manifest: PolicyManifest) -> PolicyManifest:
    """Return a copy of *manifest* signed by *identity* over its canonical bytes.

    Example::

        signed = sign_manifest(ident, manifest)
        assert signed.signature is not None
    """
    sig = identity.sign(manifest.signing_bytes())
    return manifest.model_copy(update={"signature": sig})


def verify_manifest(
    identity: ManifestSigner,
    manifest: PolicyManifest,
    *,
    as_of: float | None = None,
) -> bool:
    """Return whether *manifest*'s signature is valid for its declared agent.

    Returns ``False`` for an unsigned manifest, a tampered manifest (the
    recomputed canonical bytes no longer match the signature), or a signature
    made by a key the verifier does not bind to ``manifest.agent_id``.

    ``as_of`` is forwarded to the identity's verification, anchoring it to an
    externally observed tick (e.g. the trace tick at which the manifest was
    adopted) so a manifest still verifies under key-window/rotation rules.
    It is a *verifier-supplied* tick — never ``manifest.issued_at`` or the
    signature's self-asserted ``signed_at`` (an attacker controls those).
    Defaulting to ``None`` anchors to the identity's current clock, which fails
    safe (closed) rather than open.

    Example::

        assert verify_manifest(ident, signed)
        assert not verify_manifest(ident, signed.model_copy(update={"tools": ["x"]}))
    """
    if manifest.signature is None:
        return False
    return identity.verify(
        manifest.signing_bytes(), manifest.signature, manifest.agent_id, as_of=as_of
    )
