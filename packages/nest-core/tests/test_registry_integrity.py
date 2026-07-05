# SPDX-License-Identifier: Apache-2.0
"""Tests for the registry_integrity scenario and its adversarial validators.

Proves the validators FAIL against ``in_memory`` and PASS against
``verified`` end-to-end, that all three registration attacks are caught at
the trace level with the right typed reasons, and that the scenario is
deterministic.

Example::

    pytest packages/nest-core/tests/test_registry_integrity.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_events,
    validate_registry_authentic_discovery,
    validate_registry_honest_admitted,
    validate_registry_rejection_reasons,
    validate_registry_unauthenticated_rejected,
    validate_trace,
)

type Event = dict[str, Any]


def _send(agent: str, to: str, msg: str, ts: float = 0.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "size": len(msg), "msg": msg}


def _attempt(actor: str, claimed: str, attack: str, verdict: str, reason: str) -> Event:
    msg = (
        f"reg:attempt:actor={actor}:claimed={claimed}:attack={attack}"
        f":verdict={verdict}:reason={reason}"
    )
    return _send(actor, "auditor-0", msg)


def _lookup(claimed: str, present: int, authentic: int) -> Event:
    return _send(
        "auditor-0",
        "auditor-0",
        f"reg:lookup:claimed={claimed}:present={present}:authentic={authentic}",
        ts=1.0,
    )


def _honest_trace() -> list[Event]:
    return [
        _attempt("honest-0", "honest-0", "honest", "accepted", "ok"),
        _attempt("honest-1", "honest-1", "honest", "accepted", "ok"),
        _attempt("sybil-0", "honest-0", "impersonate", "rejected", "signer_mismatch"),
        _attempt("sybil-1", "honest-0", "unsigned", "rejected", "missing_signature"),
        _attempt("sybil-2", "sybil-2", "tamper", "rejected", "bad_signature"),
        _lookup("honest-0", 1, 1),
        _lookup("honest-1", 1, 1),
    ]


# ---------------------------------------------------------------------------
# Unit-level validator tests (synthetic traces)
# ---------------------------------------------------------------------------


class TestValidatorsSynthetic:
    def test_honest_trace_passes_all(self) -> None:
        events = _honest_trace()
        assert validate_registry_unauthenticated_rejected(events)[0].passed
        assert validate_registry_honest_admitted(events)[0].passed
        assert validate_registry_rejection_reasons(events)[0].passed
        assert validate_registry_authentic_discovery(events)[0].passed

    def test_accepted_attack_fails(self) -> None:
        events = [
            *_honest_trace(),
            _attempt("sybil-3", "honest-1", "impersonate", "accepted", "ok"),
        ]
        res = validate_registry_unauthenticated_rejected(events)[0]
        assert not res.passed
        assert "sybil-3" in res.detail

    def test_no_attacks_fails_not_vacuous(self) -> None:
        events = [_attempt("honest-0", "honest-0", "honest", "accepted", "ok")]
        assert not validate_registry_unauthenticated_rejected(events)[0].passed

    def test_rejected_honest_fails_admission_guard(self) -> None:
        events = [
            *_honest_trace(),
            _attempt("honest-2", "honest-2", "honest", "rejected", "bad_signature"),
        ]
        res = validate_registry_honest_admitted(events)[0]
        assert not res.passed
        assert "honest-2" in res.detail

    def test_wrong_typed_reason_fails(self) -> None:
        events = [
            *_honest_trace(),
            _attempt("sybil-3", "honest-1", "unsigned", "rejected", "bad_signature"),
        ]
        res = validate_registry_rejection_reasons(events)[0]
        assert not res.passed
        assert "missing_signature" in res.detail

    def test_poisoned_lookup_fails(self) -> None:
        events = [*_honest_trace(), _lookup("honest-2", 1, 0)]
        res = validate_registry_authentic_discovery(events)[0]
        assert not res.passed
        assert "poisoned" in res.detail

    def test_missing_agent_fails_discovery(self) -> None:
        events = [*_honest_trace(), _lookup("honest-2", 0, 0)]
        res = validate_registry_authentic_discovery(events)[0]
        assert not res.passed
        assert "not discoverable" in res.detail

    def test_receive_copies_do_not_double_count(self) -> None:
        events = _honest_trace()
        receive_copy = dict(events[2])
        receive_copy["kind"] = "receive"
        res = validate_registry_unauthenticated_rejected([*events, receive_copy])[0]
        assert res.passed
        assert "all 3" in res.detail

    def test_registry_dispatch(self) -> None:
        results = validate_events(_honest_trace(), "registry_integrity")
        assert len(results) == 4
        assert all(r.passed for r in results)


# ---------------------------------------------------------------------------
# End-to-end scenario tests
# ---------------------------------------------------------------------------

_YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "registry_integrity.yaml"


def _config(trace: Path, registry: str) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(_YAML)
    config.layers.registry = registry
    config.output.trace = str(trace)
    return config


class TestScenarioEndToEnd:
    @pytest.mark.asyncio
    async def test_passes_against_verified(self, tmp_path: Path) -> None:
        trace = tmp_path / "verified.jsonl"
        runner = ScenarioRunner(_config(trace, "verified"))
        result = await runner.run()
        assert result.exists()

        results = validate_trace(result, "registry_integrity")
        assert all(r.passed for r in results), [str(r) for r in results]
        # Sanity: all three attack kinds and their typed reasons hit the trace.
        text = result.read_text()
        for token in (
            "attack=impersonate",
            "attack=unsigned",
            "attack=tamper",
            "reason=signer_mismatch",
            "reason=missing_signature",
            "reason=bad_signature",
        ):
            assert token in text, token

    @pytest.mark.asyncio
    async def test_fails_against_in_memory_without_crashing(self, tmp_path: Path) -> None:
        trace = tmp_path / "inmemory.jsonl"
        runner = ScenarioRunner(_config(trace, "in_memory"))
        # Must NOT raise -- in_memory accepts everything; the validators object.
        result = await runner.run()
        assert result.exists()

        results = validate_trace(result, "registry_integrity")
        by_name = {r.name: r for r in results}
        assert not by_name["registry_unauthenticated_rejected"].passed
        assert not by_name["registry_authentic_discovery"].passed
        # The honest-admission guard still holds: in_memory admits everyone.
        assert by_name["registry_honest_admitted"].passed
        assert "attack=impersonate" in result.read_text()

    @pytest.mark.asyncio
    async def test_deterministic(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for i in range(2):
            trace = tmp_path / f"det-{i}.jsonl"
            runner = ScenarioRunner(_config(trace, "verified"))
            await runner.run()
            traces.append(trace.read_text())
        assert traces[0] == traces[1]
        assert len(traces[0]) > 0
