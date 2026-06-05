# SPDX-License-Identifier: Apache-2.0
"""Versioned communication plugin — schema-versioned JSON envelopes.

Unlike :class:`~nest_plugins_reference.comms.nest_native.NestNativeComms`, which
emits a fixed JSON envelope with **no schema version and no unknown-field
handling**, this plugin stamps every envelope with an explicit ``schema_version``
(semver) and a ``kind`` tag, and handles cross-version traffic safely:

- **Forward compatibility** — a message whose *minor* version is newer than this
  plugin knows is still accepted; any unknown top-level fields are preserved
  (round-tripped) instead of silently dropped.
- **Major-version safety** — a message whose *major* version is newer is rejected
  with a typed :class:`UnsupportedSchemaError` instead of being misinterpreted.
- **Backward compatibility** — a legacy (``nest_native``) envelope with no
  ``schema_version`` is still accepted.

This makes rolling upgrades and third-party plugin evolution possible: the wire
format can grow without breaking older or newer peers. Determinism is preserved
(pure JSON, sorted keys, no clock, no randomness).

Example::

    comms = VersionedComms(AgentId("a1"))
    raw = comms.serialize(msg)          # includes schema_version + kind
    msg2 = comms.deserialize(raw)       # unknown future fields preserved
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

#: Semver this plugin speaks. Same-major minor bumps stay compatible.
SCHEMA_VERSION = "2.0"
SUPPORTED_MAJOR = 2

#: Envelope keys this plugin understands; anything else is an "unknown" field.
_KNOWN_FIELDS = frozenset(
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

# Reserved metadata keys used to round-trip envelope fields through the
# (unversioned) ``Message`` model without colliding with user metadata.
_META_UNKNOWN = "_unknown"
_META_KIND = "_kind"


class UnsupportedSchemaError(Exception):
    """Raised when a message declares a major schema version this plugin can't read.

    Example::

        raise UnsupportedSchemaError("got major 3, support 2")
    """


def _major_of(version: str) -> int:
    """Return the integer major component of a semver string.

    Example::

        _major_of("2.3")  # 2
    """
    head = version.split(".", 1)[0]
    try:
        return int(head)
    except ValueError as exc:
        msg = f"Malformed schema_version: {version!r}"
        raise UnsupportedSchemaError(msg) from exc


class VersionedComms:
    """Schema-versioned JSON communication protocol.

    Example::

        comms = VersionedComms(AgentId("a1"))
        raw = comms.serialize(msg)
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
        """Serialize a Message into a versioned JSON envelope.

        Re-emits any preserved unknown fields (forward compatibility) and stamps
        the current ``schema_version`` and ``kind``.

        Example::

            raw = comms.serialize(msg)
        """
        meta = dict(msg.metadata)
        unknown = meta.pop(_META_UNKNOWN, {})
        kind = meta.pop(_META_KIND, "message")

        data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "kind": kind,
            "id": str(msg.id),
            "sender": str(msg.sender),
            "receiver": str(msg.receiver),
            "payload": base64.b64encode(msg.payload).decode("ascii"),
            "correlation_id": str(msg.correlation_id) if msg.correlation_id else None,
            "timestamp": msg.timestamp,
            "metadata": meta,
        }
        # Forward compat: re-emit preserved unknown fields at the top level.
        if isinstance(unknown, dict):
            for key, value in cast("dict[str, Any]", unknown).items():
                if key not in _KNOWN_FIELDS:
                    data[key] = value
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def deserialize(self, raw: bytes) -> Message:
        """Deserialize a versioned (or legacy) envelope into a Message.

        Rejects unknown-major versions with :class:`UnsupportedSchemaError`;
        preserves unknown top-level fields from newer minor versions.

        Example::

            msg = comms.deserialize(raw)
        """
        data = json.loads(raw)

        version = data.get("schema_version")
        if version is not None and _major_of(str(version)) > SUPPORTED_MAJOR:
            msg = f"Unsupported major version {version!r}; this plugin speaks {SCHEMA_VERSION}"
            raise UnsupportedSchemaError(msg)

        meta = dict(data.get("metadata", {}) or {})
        unknown = {k: v for k, v in data.items() if k not in _KNOWN_FIELDS}
        if unknown:
            meta[_META_UNKNOWN] = unknown
        if "kind" in data:
            meta[_META_KIND] = data["kind"]

        return Message(
            id=MessageId(str(data["id"])),
            sender=AgentId(str(data["sender"])),
            receiver=AgentId(str(data["receiver"])),
            payload=base64.b64decode(data["payload"]),
            correlation_id=data.get("correlation_id"),
            timestamp=data.get("timestamp"),
            metadata=meta,
        )

    async def send(self, to: AgentId, msg: Message) -> Response:
        """Send a message via the transport layer.

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
