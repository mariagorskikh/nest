# SPDX-License-Identifier: Apache-2.0
"""Sensor-redaction privacy plugin for robot-agent traces.

``SensorRedactionPrivacy`` targets problem 09's reference-plugin failure mode:
``noop`` privacy returns sensitive payloads unchanged. This plugin is narrower
than ``hybrid_x25519``: it does not claim general encryption. It deterministically
filters robot sensor text before the message reaches the trace, replacing raw
camera/person/private-zone tokens with auditable redaction markers.

Example::

    priv = SensorRedactionPrivacy()
    safe = await priv.encrypt(b"raw_camera person_detected action_id=vision-1", [])
    assert b"privacy_filtered=vision-1" in safe
"""

from __future__ import annotations

from nest_core.types import AgentId, Proof, Statement, Witness

_SENSITIVE_TOKENS = {
    "raw_camera",
    "camera_frame",
    "person_detected",
    "private_zone",
    "lidar_scan",
    "map_save",
}


def _field_value(msg: str, key: str) -> str | None:
    """Return a whitespace/colon-delimited ``key=value`` field from *msg*.

    Example::

        assert _field_value("action_id=vision-1 raw_camera", "action_id") == "vision-1"
    """
    prefix = f"{key}="
    for token in msg.replace(":", " ").split():
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class SensorRedactionPrivacy:
    """Deterministic privacy filter for sensitive robot sensor payloads.

    The plugin preserves non-sensitive fields and replaces sensitive tokens with
    ``redacted_<token>`` fields. When any redaction occurs it appends
    ``privacy_filtered=<action_id> no_raw_storage redacted`` so trace validators
    can distinguish protected payloads from raw leaks.

    Example::

        priv = SensorRedactionPrivacy()
        out = await priv.encrypt(b"raw_camera action_id=v1", [])
    """

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Return a redacted sensor payload.

        ``audience`` is accepted for Privacy protocol compatibility; this plugin
        is a deterministic filter, not audience-specific encryption.

        Example::

            out = await priv.encrypt(b"person_detected action_id=v1", [])
        """
        text = data.decode("utf-8", errors="replace")
        action_id = _field_value(text, "action_id") or "unscoped"
        changed = False
        redacted: list[str] = []
        for token in text.split():
            key = token.split(":", 1)[0].split("=", 1)[0]
            if key in _SENSITIVE_TOKENS:
                redacted.append(f"redacted_{key}")
                changed = True
            else:
                redacted.append(token)

        if changed:
            redacted.extend(
                [
                    f"privacy_filtered={action_id}",
                    "no_raw_storage",
                    "redacted",
                ]
            )
        return " ".join(redacted).encode("utf-8")

    async def decrypt(self, data: bytes) -> bytes:
        """Return the already-filtered payload.

        Example::

            assert await priv.decrypt(b"redacted") == b"redacted"
        """
        return data

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        """Produce a deterministic redaction proof marker.

        Example::

            proof = await priv.prove(stmt, witness)
        """
        return Proof(statement=statement, data=b"sensor-redaction-proof", scheme="sensor_redaction")

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Verify this plugin's redaction proof marker.

        Example::

            ok = await priv.verify_proof(stmt, proof)
        """
        return proof.scheme == "sensor_redaction" and proof.statement == statement
