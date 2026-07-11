# SPDX-License-Identifier: Apache-2.0
"""Schema-evolution-aware comms plugin.

This plugin implements a small schema evolution contract for Nanda Town
wire envelopes:

- every serialized envelope carries an explicit ``schema_version`` and
  a ``kind`` message tag.
- same-major versions are accepted.
- newer-minor fields are preserved and re-emitted on round-trip.
- unknown-major versions are rejected with a typed ``UnsupportedSchemaError``.

This is the comms layer needed for safe rolling upgrades and compatible
extension of the wire format.
"""

from __future__ import annotations

import base64
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

SCHEMA_MAJOR = 1
SCHEMA_MINOR = 1
SCHEMA_VERSION = f"{SCHEMA_MAJOR}.{SCHEMA_MINOR}"

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
    }
)

RESERVED_METADATA_KEYS: frozenset[str] = frozenset(
    {"schema_version", "kind", "_unknown"}
)


class UnsupportedSchemaError(ValueError):
    """Raised when an envelope schema version is unsafe to decode.

    This is the safe failure mode for a breaking major version. It subclasses
    :class:`ValueError` so existing ``except ValueError`` handlers continue to
    catch versioning failures.
    """

    def __init__(self, version: str, detail: str = "") -> None:
        self.version = version
        suffix = f": {detail}" if detail else ""
        super().__init__(f"unsupported schema version {version!r}{suffix}")


def _parse_major(version: str) -> int:
    """Return the major SemVer component of a version string."""
    head = version.split(".", 1)[0]
    try:
        return int(head)
    except ValueError as exc:
        raise UnsupportedSchemaError(version, "malformed version") from exc


class SchemaEvolutionComms:
    """Communication layer with explicit in-band schema evolution.

    This layer preserves forward-compatible unknown fields and rejects
    unsupported major versions rather than silently decoding them.
    """

    def __init__(
        self,
        agent_id: AgentId,
        transport: Any = None,
        registry: Any = None,
    ) -> None:
        self._agent_id = agent_id
        self._transport = transport
        self._registry = registry

    def serialize(self, msg: Message) -> bytes:
        """Serialize a Message to a schema-evolution envelope.

        The envelope is canonical JSON with stable ``sort_keys`` ordering. If
        the message carries preserved forward-compat fields in
        ``metadata['_unknown']``, they are re-emitted at the top level.
        """
        meta: dict[str, Any] = dict(msg.metadata)
        version = str(meta.pop("schema_version", SCHEMA_VERSION))
        kind = str(meta.pop("kind", "message"))
        unknown = meta.pop("_unknown", {}) or {}

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
        for key, value in unknown.items():
            if key not in envelope:
                envelope[key] = value
        return json.dumps(envelope, sort_keys=True).encode("utf-8")

    def deserialize(self, raw: bytes) -> Message:
        """Deserialize a versioned envelope with the schema evolution contract.

        Missing ``schema_version`` is treated as ``1.0`` for backward compatibility
        with pre-versioning peers.
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

    async def send(self, to: AgentId, msg: Message) -> Response:
        raw = self.serialize(msg)
        if self._transport is not None:
            await self._transport.send(to, raw)
        return Response(success=True)

    async def advertise(self, card: AgentCard) -> None:
        if self._registry is not None:
            await self._registry.register(card)

    async def discover(self, query: Query) -> list[AgentCard]:
        if self._registry is not None:
            result: list[AgentCard] = await self._registry.lookup(query)
            return result
        return []
