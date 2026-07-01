# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the delegatable auth plugin.

Boots ``scenarios/delegated_auth.yaml`` through the real ``ScenarioRunner`` /
``Simulator`` — no mocking past the plugin boundary — and asserts the two
phases of the cascading-revocation story:

1. **Grant + verify**: all 12 leaves verify their delegated ``{read}``
   capability, bound to their own identity.
2. **Cascading revocation**: after the coordinator revokes ``intermediary-1``'s
   token, exactly its four leaves (``leaf-4..7``) fail with
   ``RevokedAncestorError`` while the other eight still verify.

Also asserts determinism: the same seed yields the same ledger, across seeds
42, 7, and 1337.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "delegated_auth.yaml"

REVOKED_LEAVES = {f"leaf-{i}" for i in range(4, 8)}  # the four under intermediary-1
ALL_LEAVES = {f"leaf-{i}" for i in range(12)}


def _run_scenario(seed: int) -> dict[str, list[tuple[str, bool, str | None]]]:
    """Run the scenario at ``seed`` and return the shared auth ledger."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = config.model_copy(update={"seed": seed})
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"delegated_auth_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        ledger: dict[str, list[Any]] = runner.resolved_plugins["_auth_ledger"]
        return ledger


def test_scenario_file_exists() -> None:
    assert SCENARIO_PATH.exists(), f"missing scenario at {SCENARIO_PATH}"


@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_all_leaves_verify_before_revocation(seed: int) -> None:
    """Phase 1: every leaf successfully verifies its delegated capability."""
    ledger = _run_scenario(seed)
    initial = ledger["initial"]
    verified = {aid for aid, ok, _ in initial if ok}
    assert verified == ALL_LEAVES, f"seed={seed}: not all leaves verified: {verified}"
    assert all(ok for _, ok, _ in initial)


@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_revocation_cascades_to_only_the_revoked_subtree(seed: int) -> None:
    """Phase 2: revoking intermediary-1 fails exactly leaf-4..7, others survive."""
    ledger = _run_scenario(seed)
    after = ledger["after_revoke"]
    assert after, f"seed={seed}: no post-revocation verifications recorded"

    failed = {aid for aid, ok, _ in after if not ok}
    passed = {aid for aid, ok, _ in after if ok}

    assert failed == REVOKED_LEAVES, f"seed={seed}: wrong failed set {failed}"
    assert passed == (ALL_LEAVES - REVOKED_LEAVES), f"seed={seed}: wrong passed set {passed}"

    # The failures are specifically the cascading-revocation error, not something else.
    errors = {err for _, ok, err in after if not ok}
    assert errors == {"RevokedAncestorError"}, f"seed={seed}: unexpected errors {errors}"


def test_scenario_deterministic_under_replay() -> None:
    """Same seed → identical ledger (sorted for order-independence)."""

    def normalized(seed: int) -> dict[str, list[tuple[str, bool, str | None]]]:
        led = _run_scenario(seed)
        return {phase: sorted(rows) for phase, rows in led.items()}

    assert normalized(42) == normalized(42)
