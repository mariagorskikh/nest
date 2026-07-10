# SPDX-License-Identifier: Apache-2.0
"""Tests for the sensor-redaction privacy plugin."""

from __future__ import annotations

from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Statement, Witness
from nest_plugins_reference.privacy.noop import NoopPrivacy
from nest_plugins_reference.privacy.sensor_redaction import SensorRedactionPrivacy


class TestSensorRedactionPrivacy:
    async def test_redacts_sensitive_sensor_tokens(self) -> None:
        priv = SensorRedactionPrivacy()
        payload = b"raw_camera person_detected private_zone action_id=vision-1"

        out = await priv.encrypt(payload, [AgentId("mapper-0")])
        tokens = set(out.decode().split())

        assert "raw_camera" not in tokens
        assert "person_detected" not in tokens
        assert "private_zone" not in tokens
        assert b"privacy_filtered=vision-1" in out
        assert b"no_raw_storage" in out
        assert b"redacted" in out

    async def test_noop_leaks_same_payload(self) -> None:
        priv = NoopPrivacy()
        payload = b"raw_camera person_detected private_zone action_id=vision-1"

        out = await priv.encrypt(payload, [AgentId("mapper-0")])

        assert out == payload

    async def test_non_sensitive_payload_passes_through(self) -> None:
        priv = SensorRedactionPrivacy()
        payload = b"status ok action_id=vision-1"

        out = await priv.encrypt(payload, [AgentId("mapper-0")])

        assert out == payload

    async def test_proof_round_trip(self) -> None:
        priv = SensorRedactionPrivacy()
        statement = Statement(predicate="redacted", public_inputs={"action_id": "vision-1"})
        witness = Witness(private_inputs={"raw": "camera"})

        proof = await priv.prove(statement, witness)

        assert await priv.verify_proof(statement, proof)

    def test_registry_resolves_sensor_redaction(self) -> None:
        cls = PluginRegistry().resolve("privacy", "sensor_redaction")

        assert cls is SensorRedactionPrivacy
