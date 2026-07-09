# SPDX-License-Identifier: Apache-2.0
"""End-to-end + adversarial tests for the split_settlement scenario.

Boots the ``split_settlement`` scenario through the real ``Simulator`` and proves
the two validators discriminate:

* under ``payments: split_settlement`` -- both PASS;
* under ``payments: prepaid_credits`` -- both FAIL (no fan-out protocol, no
  ``split:*`` events);
* under a deliberately buggy in-test splitter -- the matching validator FAILS,
  and a *penny-shaving* bug (which conservation catches) is shown to be distinct
  from a *weight-tampering* bug (which conservation misses but fidelity catches).

Also pins determinism: same seed -> byte-identical trace, across seeds 42/7/1337.
The buggy splitters live here, not in the shipped plugin package, per the charter.
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
from nest_core.scenarios_builtin.split_settlement import split_settlement_factory
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId, Money, PaymentRef, Receipt
from nest_core.validators import ValidationResult, validate_events, validate_trace
from nest_plugins_reference.payments.split_settlement import SplitError, SplitSettlement

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "split_settlement.yaml"


# --------------------------------------------------------------------------
# Buggy in-test splitters -- NOT shipped as plugins (charter requirement).
# --------------------------------------------------------------------------


class _PennyShavingSplitter(SplitSettlement):
    """Floors every share and silently keeps the indivisible dust.

    The classic settlement bug: ``credit_i = floor(amount * w_i / total)`` with no
    largest-remainder step, so the credits sum to *less* than the debit and the
    operator pockets the difference.
    """

    async def settle_split(self, ref: PaymentRef, amount: Money) -> list[Receipt]:
        contract = self.contract(ref)
        if contract is None:
            msg = f"no split for reference: {ref}"
            raise SplitError(msg)
        allocations = [
            (payee, (amount.amount * weight) // contract.total_weight)
            for payee, weight in contract.payees
        ]
        contract.state = "SETTLED"
        contract.settled_amount = amount.amount
        contract.allocations = tuple(allocations)
        return [
            Receipt(ref=ref, payer=contract.payer, payee=payee, amount=Money(amount=credit))
            for payee, credit in allocations
        ]


class _WeightTamperingSplitter(SplitSettlement):
    """Conserves the total but routes it all to the first payee.

    Sums to the amount (so a conservation-only check is fooled) yet ignores the
    declared weights entirely -- exactly the mid-flight reweight / self-dealing
    that ``split_weight_fidelity`` is built to catch.
    """

    async def settle_split(self, ref: PaymentRef, amount: Money) -> list[Receipt]:
        contract = self.contract(ref)
        if contract is None:
            msg = f"no split for reference: {ref}"
            raise SplitError(msg)
        allocations = [
            (payee, amount.amount if index == 0 else 0)
            for index, (payee, _weight) in enumerate(contract.payees)
        ]
        contract.state = "SETTLED"
        contract.settled_amount = amount.amount
        contract.allocations = tuple(allocations)
        return [
            Receipt(ref=ref, payer=contract.payer, payee=payee, amount=Money(amount=credit))
            for payee, credit in allocations
        ]


# --------------------------------------------------------------------------
# Runners
# --------------------------------------------------------------------------


def _run_registered(plugin_name: str, seed: int = 42) -> Path:
    """Run the scenario via the registry (for plugins resolvable by name)."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    new_layers = config.layers.model_copy(update={"payments": plugin_name})
    config = config.model_copy(update={"layers": new_layers, "seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace = tmp / f"{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace


def _run_injected(payments_cls: type[Any], seed: int = 42) -> Path:
    """Drive the scenario with an arbitrary (unregistered) payments class."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    plugins: dict[str, Any] = {"payments": payments_cls}
    agents = split_settlement_factory(config, plugins)
    overrides: dict[AgentId, dict[str, Any]] = plugins.pop("_agent_plugins", {})
    tmp = Path(tempfile.mkdtemp())
    trace = tmp / f"injected_{seed}.jsonl"
    sim = Simulator(seed=seed, trace_path=trace, plugins={})
    for agent_id, agent in agents.items():
        sim.add_agent(agent_id, agent)
    for agent_id, agent_overrides in overrides.items():
        sim.set_agent_plugins(agent_id, agent_overrides)
    asyncio.run(sim.run(max_ticks=config.get_max_ticks()))
    return trace


def _by_name(results: list[ValidationResult]) -> dict[str, ValidationResult]:
    return {r.name: r for r in results}


# --------------------------------------------------------------------------
# Discrimination through the real simulator
# --------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_split_settlement_passes_both_validators() -> None:
    results = validate_trace(_run_registered("split_settlement"), "split_settlement")
    failures = [f"{r.name}: {r.detail}" for r in results if not r.passed]
    assert all(r.passed for r in results), failures


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_prepaid_credits_fails_both_validators() -> None:
    """The default plugin has no fan-out: buyers fall back to pay(), no split:* events."""
    results = _by_name(validate_trace(_run_registered("prepaid_credits"), "split_settlement"))
    assert not results["split_conservation"].passed
    assert not results["split_weight_fidelity"].passed


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_penny_shaving_splitter_is_caught_by_conservation() -> None:
    results = _by_name(validate_trace(_run_injected(_PennyShavingSplitter), "split_settlement"))
    assert not results["split_conservation"].passed
    assert "dust leak" in results["split_conservation"].detail


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_weight_tampering_passes_conservation_but_fails_fidelity() -> None:
    """The point of the second validator: conservation alone cannot see self-dealing."""
    results = _by_name(validate_trace(_run_injected(_WeightTamperingSplitter), "split_settlement"))
    assert results["split_conservation"].passed
    assert not results["split_weight_fidelity"].passed


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_deterministic_and_valid_across_seeds(seed: int) -> None:
    """Same seed -> byte-identical trace; validators pass under every seed."""
    first = _run_registered("split_settlement", seed).read_bytes()
    second = _run_registered("split_settlement", seed).read_bytes()
    assert first == second
    results = validate_trace(_run_registered("split_settlement", seed), "split_settlement")
    assert all(r.passed for r in results)


# --------------------------------------------------------------------------
# Fast synthetic-trace unit tests of the validators themselves
# --------------------------------------------------------------------------


def _broadcast(agent: str, msg: str) -> dict[str, Any]:
    return {"kind": "broadcast", "agent": agent, "msg": msg}


def _honest_events() -> list[dict[str, Any]]:
    return [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~40;b~40;c~20"),
        _broadcast("buyer-0", "split:settled:ref=r0:amount=1001:alloc=a~401;b~400;c~200"),
    ]


def test_validator_accepts_honest_trace() -> None:
    results = _by_name(validate_events(_honest_events(), "split_settlement"))
    assert results["split_conservation"].passed
    assert results["split_weight_fidelity"].passed


def test_validator_flags_penny_shave_event() -> None:
    events = [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~40;b~40;c~20"),
        # floors of 1001: 400/400/200 = 1000, one unit shaved.
        _broadcast("buyer-0", "split:settled:ref=r0:amount=1001:alloc=a~400;b~400;c~200"),
    ]
    results = _by_name(validate_events(events, "split_settlement"))
    assert not results["split_conservation"].passed


def test_validator_flags_weight_tamper_event() -> None:
    events = [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~40;b~40;c~20"),
        # sums to 1001 but ignores the declared weights.
        _broadcast("buyer-0", "split:settled:ref=r0:amount=1001:alloc=a~1001;b~0;c~0"),
    ]
    results = _by_name(validate_events(events, "split_settlement"))
    assert results["split_conservation"].passed
    assert not results["split_weight_fidelity"].passed


def test_validator_flags_settled_without_opened() -> None:
    events = [_broadcast("buyer-0", "split:settled:ref=r0:amount=100:alloc=a~100")]
    results = _by_name(validate_events(events, "split_settlement"))
    assert not results["split_weight_fidelity"].passed


def test_validator_flags_negative_credit() -> None:
    events = [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~1;b~1"),
        _broadcast("buyer-0", "split:settled:ref=r0:amount=100:alloc=a~150;b~-50"),
    ]
    results = _by_name(validate_events(events, "split_settlement"))
    assert not results["split_conservation"].passed


def test_validator_reports_no_lifecycle_on_empty_trace() -> None:
    results = _by_name(validate_events([], "split_settlement"))
    assert not results["split_conservation"].passed
    assert "no split" in results["split_conservation"].detail
    assert not results["split_weight_fidelity"].passed
