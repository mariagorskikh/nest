# SPDX-License-Identifier: Apache-2.0

"""Replay-safe authenticated comms — sequence-bound envelopes.

Extends ``authenticated`` with a per-peer monotonic sequence number so that
verbatim replays of genuine envelopes are detectable. A sliding window
buffers out-of-order deliveries up to ``WINDOW_SIZE`` ahead; anything older
than the last accepted sequence, or further than the window, is rejected.

Threat model:
  in scope  — replay of a captured envelope; ordering enforcement per peer.
  out scope — cross-peer ordering; crash recovery of sequence state.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections import defaultdict
from typing import Any, cast

from nest_core.types import AgentCard, AgentId, Message, MessageId, Query, Response

from nest_plugins_reference.comms.authenticated import (
    AUTH_TAG_FIELD,
    CHANNEL_SECRET_DEFAULT,
    KNOWN_FIELDS,
    SCHEMA_MAJOR,
    SCHEMA_VERSION,
    AuthenticatedComms,
    DowngradeError,
    UnsupportedSchemaError,
    _parse_major,
    expected_auth_tag,
)

SEQUENCE_FIELD = "sequence"
WINDOW_SIZE = 10


class ReplayError(DowngradeError):
    """Raised when an envelope's sequence is stale, missing, or out of window."""

    def __init__(self, version: str, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(version, reason, detail or reason)


class ReplaySafeComms(AuthenticatedComms):
    """Tamper-evident + replay-safe comms.

    Drop-in for ``authenticated`` that additionally rejects replays by binding
    a per-peer monotonic sequence into the HMAC-covered envelope.
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
        super().__init__(
            agent_id, transport, registry,
            channel_secret=channel_secret, require_auth=require_auth,
        )
        self._outgoing_sequences: dict[tuple[str, str], int] = {}
        self._incoming_sequences: dict[tuple[str, str], int] = {}
        self._out_of_order_buffer: dict[tuple[str, str], dict[int, bytes]] = defaultdict(dict)

    def serialize(self, msg: Message) -> bytes:
        meta: dict[str, Any] = dict(msg.metadata)
        version = str(meta.pop("schema_version", SCHEMA_VERSION))
        kind = str(meta.pop("kind", "message"))
        unknown: dict[str, Any] = meta.pop("_unknown", {}) or {}

        pair_key = (str(msg.sender), str(msg.receiver))
        seq = self._outgoing_sequences.get(pair_key, 0)
        self._outgoing_sequences[pair_key] = seq + 1

        envelope: dict[str, Any] = {
            "schema_version": version, "kind": kind, "id": str(msg.id),
            "sender": str(msg.sender), "receiver": str(msg.receiver),
            "payload": base64.b64encode(msg.payload).decode("ascii"),
            "correlation_id": str(msg.correlation_id) if msg.correlation_id else None,
            "timestamp": msg.timestamp, "metadata": meta,
            SEQUENCE_FIELD: seq,
        }
        for key, value in unknown.items():
            if key not in envelope:
                envelope[key] = value

        envelope[AUTH_TAG_FIELD] = expected_auth_tag(envelope, self._channel_secret)
        return json.dumps(envelope, sort_keys=True).encode("utf-8")

    def deserialize(self, raw: bytes) -> Message:
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
        return self._process_sequence_and_build(data, version)

    def _process_sequence_and_build(self, data: dict, version: str) -> Message:
        sender = str(data.get("sender", ""))
        receiver = str(data.get("receiver", ""))
        seq = data.get(SEQUENCE_FIELD)
        pair_key = (sender, receiver)

        if seq is None:
            if not self._require_auth:
                return self._build_message(data)
            raise ReplayError(version, "missing_sequence", "envelope has no sequence number")

        if not isinstance(seq, int) or seq < 0:
            raise ReplayError(
                version, "invalid_sequence",
                "sequence must be a non-negative integer",
            )

        last_seen = self._incoming_sequences.get(pair_key, -1)

        # Next expected — accept and flush any buffered successors.
        if seq == last_seen + 1:
            self._incoming_sequences[pair_key] = seq
            self._flush_buffer(pair_key)
            return self._build_message(data)

        # Within the window — buffer until the gap is filled.
        if last_seen + 1 < seq <= last_seen + WINDOW_SIZE:
            self._out_of_order_buffer[pair_key][seq] = data
            raise ReplayError(
                version, "out_of_order_buffered",
                f"message {seq} buffered, waiting for {last_seen + 1}",
            )

        # Stale — replay.
        if seq <= last_seen:
            raise ReplayError(
                version, "stale_sequence",
                f"sequence {seq} <= last seen {last_seen}",
            )

        # Beyond the window — cannot safely buffer.
        raise ReplayError(
            version, "sequence_gap_too_large",
            f"sequence {seq} is beyond window {last_seen + WINDOW_SIZE}",
        )

    def _flush_buffer(self, pair_key: tuple[str, str]) -> None:
        last_seen = self._incoming_sequences[pair_key]
        next_expected = last_seen + 1
        while next_expected in self._out_of_order_buffer[pair_key]:
            self._out_of_order_buffer[pair_key].pop(next_expected)
            self._incoming_sequences[pair_key] = next_expected
            next_expected += 1

    def _build_message(self, data: dict) -> Message:
        unknown = {k: v for k, v in data.items() if k not in KNOWN_FIELDS and k != SEQUENCE_FIELD}
        meta: dict[str, Any] = dict(data.get("metadata") or {})
        meta["schema_version"] = str(data.get("schema_version", "1.0"))
        meta["kind"] = str(data.get("kind", "message"))
        meta["sequence"] = data.get(SEQUENCE_FIELD, 0)
        if unknown:
            meta["_unknown"] = unknown

        return Message(
            id=MessageId(data["id"]), sender=AgentId(data["sender"]),
            receiver=AgentId(data["receiver"]), payload=base64.b64decode(data["payload"]),
            correlation_id=data.get("correlation_id"), timestamp=data.get("timestamp"),
            metadata=meta,
        )

    def _verify_tag(self, data: dict, version: str) -> None:
        tag = data.pop(AUTH_TAG_FIELD, None)
        expected = expected_auth_tag(data, self._channel_secret)
        if tag is None or not hmac.compare_digest(str(tag), str(expected)):
            raise DowngradeError(version, "bad_tag", "HMAC verification failed")
        data[AUTH_TAG_FIELD] = tag

    async def send(self, to: AgentId, msg: Message) -> Response:
        raw = self.serialize(msg)
        if self._transport is not None:
            await self._transport.send(to, raw)
        return Response(success=True)