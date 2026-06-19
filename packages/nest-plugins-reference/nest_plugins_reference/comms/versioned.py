# SPDX-License-Identifier: Apache-2.0
"""Versioned communication plugin — forward/backward-compatible wire envelopes.

The default :class:`~nest_plugins_reference.comms.nest_native.NestNativeComms`
envelope has no version field, so two swarms running different NEST builds
silently mis-read each other's wire format: a newer field is dropped without a
trace, and a breaking (major) format bump deserializes into a plausible-but-wrong
:class:`~nest_core.types.Message`. This plugin adds an explicit, in-band
``schema_version`` (SemVer) and a ``kind`` tag to every envelope and gives
``deserialize`` a precise compatibility contract:

* **Same major, any minor (forward compat).** Unknown top-level fields from a
  *newer minor* peer are preserved verbatim into ``metadata["_unknown"]`` and
  re-emitted on the next ``serialize`` — the MUST-ignore-but-preserve rule that
  lets a v1.1 message survive a round-trip through a v1.0 reader. This mirrors
  Protobuf's unknown-field retention, expressed in JSON.
* **Higher major (breaking).** A major version this build does not understand is
  rejected with a typed :class:`UnsupportedSchemaError` instead of being decoded
  into a wrong message. Refusing is the safe failure: a breaking change means we
  *cannot* know what the bytes mean.

Compatibility matrix (this build speaks ``1.1``)::

    wire version   behaviour
    -----------    ---------------------------------------------
    1.0            accept (older minor, no unknown fields)
    1.1            accept (exact)
    1.7            accept, preserve unknown fields  (forward compat)
    2.0            reject -> UnsupportedSchemaError (breaking)
    "garbage"      reject -> UnsupportedSchemaError (malformed)

Example::

    comms = VersionedComms(AgentId("a1"))
    raw = comms.serialize(msg)
    assert comms.deserialize(raw) == msg          # lossless round-trip
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

#: Major version this build understands. Bumping it is a *breaking* change:
#: peers on an older major will reject our envelopes, and we reject theirs.
SCHEMA_MAJOR = 1
#: Minor version this build emits. Bumping it must stay backward compatible:
#: older-minor peers MUST still be able to read our envelopes.
SCHEMA_MINOR = 1
#: SemVer string stamped onto every outgoing envelope, e.g. ``"1.1"``.
SCHEMA_VERSION = f"{SCHEMA_MAJOR}.{SCHEMA_MINOR}"

#: Top-level envelope keys this build assigns meaning to. Anything else on the
#: wire is an *unknown field* from a newer peer and is preserved, not dropped.
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

#: ``metadata`` keys this plugin reserves for carrying envelope control data in
#: and out of the :class:`~nest_core.types.Message` model. Callers should treat
#: these as read-only: ``schema_version`` and ``kind`` report what arrived (and
#: select what is emitted), and ``_unknown`` holds preserved forward-compat
#: fields.
RESERVED_METADATA_KEYS: frozenset[str] = frozenset({"schema_version", "kind", "_unknown"})


class UnsupportedSchemaError(ValueError):
    """Raised when an envelope's schema version cannot be safely decoded.

    Carries the offending ``version`` string so callers can log or branch on it
    rather than string-matching the message. Subclasses :class:`ValueError` so
    existing ``except ValueError`` deserialization guards keep working.

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


class VersionedComms:
    """JSON communication protocol with explicit, in-band schema versioning.

    Drop-in replacement for ``nest_native`` that survives rolling upgrades:
    unknown fields from newer-minor peers are preserved, and unknown-major
    peers are rejected rather than silently mis-decoded.

    Example::

        comms = VersionedComms(AgentId("a1"), transport=t, registry=r)
        resp = await comms.send(AgentId("a2"), msg)
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

        Stamps :data:`SCHEMA_VERSION` and a ``kind`` tag (read from
        ``metadata['kind']``, default ``"message"``), and re-emits any
        forward-compat fields previously parked in ``metadata['_unknown']``.
        Output is ``sort_keys``-canonical so the same message always produces
        byte-identical wire bytes (Tier 1 determinism).

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
        # Re-emit preserved unknown fields at the top level. Never let them
        # clobber a field this build owns -- our semantics win on collision.
        for key, value in unknown.items():
            if key not in envelope:
                envelope[key] = value
        return json.dumps(envelope, sort_keys=True).encode("utf-8")

    def deserialize(self, raw: bytes) -> Message:
        """Deserialize a versioned envelope, enforcing the compatibility contract.

        Accepts any envelope whose major version equals :data:`SCHEMA_MAJOR`
        (preserving unknown fields from newer minors) and raises
        :class:`UnsupportedSchemaError` for a higher major or a malformed/
        non-object envelope. A missing ``schema_version`` is treated as the
        oldest known release, ``"1.0"`` (backward compat with pre-versioning
        peers).

        Example::

            msg = comms.deserialize(raw)
            assert msg.metadata["schema_version"]  # always populated
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
