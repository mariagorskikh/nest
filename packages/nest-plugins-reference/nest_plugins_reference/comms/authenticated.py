# SPDX-License-Identifier: Apache-2.0
"""Tamper-evident versioned comms — HMAC-bound envelopes that resist downgrade.

The merged :class:`~nest_plugins_reference.comms.versioned.VersionedComms` plugin
solved *forward/backward compatibility*: newer-minor fields survive a round-trip
and a breaking major is rejected. But it trusts the wire. Its ``schema_version``,
``kind`` and every field ride in cleartext with **no integrity protection**, so an
on-path adversary — a malicious relay, a compromised transport, a buggy proxy —
can silently rewrite them and the receiver cannot tell. Two concrete attacks slip
straight through ``versioned`` (and, a fortiori, ``nest_native``):

* **Version rollback.** Rewrite ``"schema_version": "1.1"`` to ``"1.0"`` (or delete
  the field, which ``versioned`` reads as ``"1.0"``). The receiver now applies the
  *older*, more permissive contract to a message that was authored under a newer,
  stricter one — the classic downgrade that TLS fought with ``POODLE`` / ``FREAK`` /
  ``Logjam`` and ultimately ``TLS_FALLBACK_SCSV``.
* **Field stripping.** Delete a security-relevant field a newer peer added (an
  ``x-trace-id``, an authorization hint) so the receiver acts on a truncated
  message it believes is whole.

This plugin closes that gap by binding an ``HMAC-SHA256`` **authentication tag**
over the *entire* canonical envelope — version, kind, and every field — keyed by a
per-pair channel secret the on-path attacker does not hold. Any rewrite of any
covered byte makes the tag recomputation fail, so rollback and stripping become
*detectable* rather than silent. It is a strict superset of ``versioned``: the
version negotiation, unknown-field preservation and unknown-major rejection are all
inherited unchanged, and untagged legacy traffic still flows in permissive mode.

Threat model (what the tag does and does not buy)::

    in scope    tamper-evidence: rewrite / strip / reorder any covered field
                is detected at the receiver (constant-time compare).
    in scope    version-rollback resistance: schema_version is covered, so a
                downgrade cannot masquerade as authentic.
    out scope   key exchange: the pairwise key is a pre-shared simulation secret
                standing in for an ECDH/TLS session key. We test tamper-evidence,
                not how the endpoints agreed on the key.
    out scope   replay: a *verbatim* re-send of a genuine envelope still verifies.
                Bind a nonce/sequence into ``metadata`` to close that separately.

The MAC covers the canonical JSON of the envelope with the ``auth_tag`` field
removed (encrypt-then-MAC's "MAC everything else" discipline, expressed in JSON),
so the tag is deterministic and Tier-1 replayable.

Example::

    comms = AuthenticatedComms(AgentId("a1"))
    raw = comms.serialize(msg)
    assert comms.deserialize(raw) == msg          # lossless, tag-verified round-trip
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, cast

from nest_core.types import (
    AgentCard,
    AgentId,
    Message,
    MessageId,
    Query,
    Response,
)

#: Major version this build understands. A higher major on the wire is a breaking
#: change and is rejected rather than mis-decoded (inherited from ``versioned``).
SCHEMA_MAJOR = 1
#: Minor version this build emits. Bumping it must stay backward compatible.
SCHEMA_MINOR = 1
#: SemVer string stamped onto every outgoing envelope, e.g. ``"1.1"``.
SCHEMA_VERSION = f"{SCHEMA_MAJOR}.{SCHEMA_MINOR}"

#: The top-level envelope field carrying the hex authentication tag.
AUTH_TAG_FIELD = "auth_tag"

#: Pre-shared pairwise-channel secret used to key the HMAC in this simulation. In
#: a real deployment this is replaced by a per-session key from an authenticated
#: key exchange (e.g. X25519 ECDH); here it is a fixed constant so traces replay
#: byte-for-byte. The security property under test is *tamper-evidence*: an
#: attacker who lacks this secret cannot forge a tag for rewritten bytes.
CHANNEL_SECRET_DEFAULT = b"nest-authenticated-comms/v1/pre-shared-channel-secret"

#: Envelope keys this build assigns meaning to. Anything else on the wire is an
#: unknown field from a newer peer: it is preserved (forward compat) *and* covered
#: by the tag, so a newer peer's additions cannot be stripped undetected.
KNOWN_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "kind",
        "id",
        "sender",
        "receiver",
        "payload",
        "correlation_id",
        "timestamp",
        "metadata",
        AUTH_TAG_FIELD,
    }
)

#: ``metadata`` keys this plugin reserves for surfacing envelope control data on
#: the decoded :class:`~nest_core.types.Message`. Treat as read-only.
RESERVED_METADATA_KEYS: frozenset[str] = frozenset({"schema_version", "kind", "_unknown"})


class UnsupportedSchemaError(ValueError):
    """Raised when an envelope's schema version cannot be safely decoded.

    Subclasses :class:`ValueError` so existing ``except ValueError`` guards in the
    simulator keep catching it.

    Example::

        try:
            comms.deserialize(future_major_bytes)
        except UnsupportedSchemaError as exc:
            assert exc.version == "2.0"
    """

    def __init__(self, version: str, detail: str = "") -> None:
        self.version = version
        suffix = f": {detail}" if detail else ""
        super().__init__(f"unsupported schema version {version!r}{suffix}")


class DowngradeError(UnsupportedSchemaError):
    """Raised when an envelope's authentication tag does not cover its bytes.

    This is the tamper alarm: the delivered envelope was rewritten (version
    rolled back, a field stripped or altered) after it was authenticated, or it
    arrived unauthenticated while the receiver required authentication. Kept a
    subclass of :class:`UnsupportedSchemaError` (hence :class:`ValueError`) so a
    receiver that only knows how to ``except ValueError`` still refuses it.

    Example::

        try:
            comms.deserialize(rolled_back_bytes)
        except DowngradeError as exc:
            assert exc.reason in {"tag_mismatch", "tag_missing"}
    """

    def __init__(self, version: str, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(version, detail or reason)


def _parse_major(version: str) -> int:
    """Return the integer major component of a SemVer string.

    Example::

        assert _parse_major("2.7") == 2
    """
    head = version.split(".", 1)[0]
    try:
        return int(head)
    except ValueError as exc:
        raise UnsupportedSchemaError(version, "malformed version") from exc


def pair_key(a: str, b: str, channel_secret: bytes = CHANNEL_SECRET_DEFAULT) -> bytes:
    """Derive the symmetric tag key for the unordered channel ``{a, b}``.

    Both endpoints of a conversation derive the *same* key regardless of send
    direction (the pair is sorted first), while an attacker without
    ``channel_secret`` cannot. Models a pairwise session key; deterministic for
    Tier-1 replay.

    Example::

        assert pair_key("a1", "a2") == pair_key("a2", "a1")
    """
    label = "::".join(sorted((a, b))).encode("utf-8")
    return hmac.new(channel_secret, label, hashlib.sha256).digest()


def canonical_untagged(envelope: dict[str, Any]) -> bytes:
    """Serialize ``envelope`` (minus its ``auth_tag``) to canonical JSON bytes.

    Sorting keys makes the MAC input independent of field order, so a re-encode
    by an intermediary that reorders keys does not spuriously break the tag while
    any change to a *value* still does.

    Example::

        raw = canonical_untagged({"id": "m1", "auth_tag": "deadbeef"})
        assert b"auth_tag" not in raw
    """
    without_tag = {k: v for k, v in envelope.items() if k != AUTH_TAG_FIELD}
    return json.dumps(without_tag, sort_keys=True).encode("utf-8")


def expected_auth_tag(
    envelope: dict[str, Any],
    channel_secret: bytes = CHANNEL_SECRET_DEFAULT,
) -> str:
    """Compute the hex HMAC-SHA256 tag an authentic ``envelope`` must carry.

    Keyed by the ``sender``/``receiver`` pair key and taken over the canonical
    envelope with any existing tag excluded. Exposed at module scope so an
    independent trace validator can recompute ground truth without instantiating
    the plugin.

    Example::

        env = {"schema_version": "1.1", "id": "m1", "sender": "a1",
               "receiver": "a2", "payload": "eA==", "kind": "offer",
               "correlation_id": None, "timestamp": None, "metadata": {}}
        tag = expected_auth_tag(env)
        assert len(tag) == 64
    """
    key = pair_key(
        str(envelope.get("sender", "")),
        str(envelope.get("receiver", "")),
        channel_secret,
    )
    return hmac.new(key, canonical_untagged(envelope), hashlib.sha256).hexdigest()


class AuthenticatedComms:
    """Versioned JSON comms with an HMAC tag bound over the whole envelope.

    Drop-in for ``versioned``/``nest_native`` that additionally makes tampering
    evident. In permissive mode (default) untagged legacy envelopes are still
    accepted so a rolling upgrade can proceed; flip ``require_auth`` once every
    peer is upgraded to refuse any unauthenticated envelope and fully close the
    rollback-by-stripping-the-tag hole.

    Example::

        comms = AuthenticatedComms(AgentId("a1"), require_auth=True)
        resp = await comms.send(AgentId("a2"), msg)
    """

    def __init__(
        self,
        agent_id: AgentId,
        transport: Any = None,
        registry: Any = None,
        *,
        channel_secret: bytes = CHANNEL_SECRET_DEFAULT,
        require_auth: bool = False,
    ) -> None:
        self._agent_id = agent_id
        self._transport = transport
        self._registry = registry
        self._channel_secret = channel_secret
        self._require_auth = require_auth

    def serialize(self, msg: Message) -> bytes:
        """Serialize ``msg`` into a versioned envelope carrying an ``auth_tag``.

        Stamps :data:`SCHEMA_VERSION` and a ``kind`` tag, re-emits any preserved
        forward-compat fields from ``metadata['_unknown']``, then binds the tag
        over the finished (canonical) envelope. Byte-identical for identical
        input (Tier-1 determinism).

        Example::

            raw = comms.serialize(msg)
        """
        meta: dict[str, Any] = dict(msg.metadata)
        version = str(meta.pop("schema_version", SCHEMA_VERSION))
        kind = str(meta.pop("kind", "message"))
        unknown: dict[str, Any] = meta.pop("_unknown", {}) or {}

        envelope: dict[str, Any] = {
            "schema_version": version,
            "kind": kind,
            "id": str(msg.id),
            "sender": str(msg.sender),
            "receiver": str(msg.receiver),
            "payload": base64.b64encode(msg.payload).decode("ascii"),
            "correlation_id": str(msg.correlation_id) if msg.correlation_id else None,
            "timestamp": msg.timestamp,
            "metadata": meta,
        }
        # Re-emit preserved unknown fields; our own fields win on collision so a
        # replayed unknown can never shadow a field this build authenticates.
        for key, value in unknown.items():
            if key not in envelope:
                envelope[key] = value
        envelope[AUTH_TAG_FIELD] = expected_auth_tag(envelope, self._channel_secret)
        return json.dumps(envelope, sort_keys=True).encode("utf-8")

    def deserialize(self, raw: bytes) -> Message:
        """Deserialize an envelope, enforcing versioning *and* tamper-evidence.

        Order of checks: parse → reject non-object → reject unknown major →
        verify the authentication tag → build the message. A present-but-wrong
        tag always raises :class:`DowngradeError`; a missing tag raises only when
        ``require_auth`` is set (permissive mode accepts untagged legacy peers).

        Example::

            msg = comms.deserialize(raw)
            assert msg.metadata["schema_version"]
        """
        try:
            loaded = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise UnsupportedSchemaError("<unparseable>", str(exc)) from exc
        if not isinstance(loaded, dict):
            raise UnsupportedSchemaError("<non-object>", "envelope is not a JSON object")
        data = cast("dict[str, Any]", loaded)

        version = str(data.get("schema_version", "1.0"))
        if _parse_major(version) > SCHEMA_MAJOR:
            raise UnsupportedSchemaError(version, f"this build speaks major {SCHEMA_MAJOR}")

        self._verify_tag(data, version)

        unknown = {k: v for k, v in data.items() if k not in KNOWN_FIELDS}
        meta: dict[str, Any] = dict(data.get("metadata") or {})
        meta["schema_version"] = version
        meta["kind"] = str(data.get("kind", "message"))
        if unknown:
            meta["_unknown"] = unknown

        return Message(
            id=MessageId(data["id"]),
            sender=AgentId(data["sender"]),
            receiver=AgentId(data["receiver"]),
            payload=base64.b64decode(data["payload"]),
            correlation_id=data.get("correlation_id"),
            timestamp=data.get("timestamp"),
            metadata=meta,
        )

    def _verify_tag(self, data: dict[str, Any], version: str) -> None:
        """Enforce the tamper-evidence contract for one parsed envelope.

        Raises :class:`DowngradeError` if a carried tag does not match the
        recomputed tag (rewrite/rollback/strip), or if the envelope is untagged
        while ``require_auth`` is set. A constant-time compare avoids leaking how
        much of a forged tag was correct.

        Example::

            comms._verify_tag({"sender": "a1", "receiver": "a2"}, "1.1")
        """
        carried = data.get(AUTH_TAG_FIELD)
        if carried is None:
            if self._require_auth:
                raise DowngradeError(version, "tag_missing", "unauthenticated envelope refused")
            return
        expected = expected_auth_tag(data, self._channel_secret)
        if not hmac.compare_digest(str(carried), expected):
            raise DowngradeError(version, "tag_mismatch", "envelope authentication failed")

    async def send(self, to: AgentId, msg: Message) -> Response:
        """Serialize and route a message through the transport layer.

        Example::

            resp = await comms.send(AgentId("a2"), msg)
        """
        raw = self.serialize(msg)
        if self._transport is not None:
            await self._transport.send(to, raw)
        return Response(success=True)

    async def advertise(self, card: AgentCard) -> None:
        """Advertise an agent card to the registry.

        Example::

            await comms.advertise(my_card)
        """
        if self._registry is not None:
            await self._registry.register(card)

    async def discover(self, query: Query) -> list[AgentCard]:
        """Discover agents via the registry.

        Example::

            cards = await comms.discover(Query(capabilities=["sell"]))
        """
        if self._registry is not None:
            result: list[AgentCard] = await self._registry.lookup(query)
            return result
        return []
