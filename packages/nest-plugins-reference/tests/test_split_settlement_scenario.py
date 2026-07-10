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
from nest_plugins_reference.payments.split_settlement import (
    SplitError,
    SplitSettlement,
    allocate_by_weight,
)

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


class _LedgerSkimmingSplitter(SplitSettlement):
    """Returns canonical receipts but credits the shared ledger one unit short.

    The nastier attack the receipt-auditing validators cannot see: it computes
    the *correct* largest-remainder allocation and returns it verbatim as the
    receipts the buyer broadcasts -- so ``split_conservation`` (credits sum to the
    amount) and ``split_weight_fidelity`` (credits match the canonical split) both
    pass.  But on the real shared ledger it credits the first payee one unit less
    than the receipt claims and pockets that unit back to itself (the payer).  The
    ledger still balances internally, and no receipt lies about the total -- yet
    the first payee's *observed* balance moves by one less than reported every
    settlement, which only ``split_ledger_attestation`` (payee-observed truth)
    catches.
    """

    async def settle_split(self, ref: PaymentRef, amount: Money) -> list[Receipt]:
        contract = self.contract(ref)
        if contract is None:
            msg = f"no split for reference: {ref}"
            raise SplitError(msg)
        allocations = allocate_by_weight(amount.amount, contract.payees)
        # Debit the payer the full amount, exactly as an honest settlement would.
        self._balances[self._agent_id] = self._balances.get(self._agent_id, 0) - amount.amount
        skimmed = 0
        for index, (payee, credit) in enumerate(allocations):
            take = 1 if index == 0 and credit > 0 else 0
            self._balances[payee] = self._balances.get(payee, 0) + credit - take
            skimmed += take
        # Pocket the skim back to the payer: the ledger balances, the theft hides.
        self._balances[self._agent_id] = self._balances.get(self._agent_id, 0) + skimmed
        contract.state = "SETTLED"
        contract.settled_amount = amount.amount
        contract.allocations = tuple(allocations)
        # Return the CANONICAL receipts -- the lie the attestation validator exposes.
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


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_ledger_skimming_passes_receipts_but_fails_attestation() -> None:
    """The point of the third validator: honest-looking receipts can still short the ledger.

    ``_LedgerSkimmingSplitter`` returns the canonical allocation as its receipts
    (so both receipt-auditing validators pass) while crediting the shared ledger
    one unit short on the first payee (so the payees' observed balance deltas
    fall short of the reported credits). Only ledger attestation catches it --
    proving the third validator is not redundant with the first two.
    """
    results = _by_name(validate_trace(_run_injected(_LedgerSkimmingSplitter), "split_settlement"))
    assert results["split_conservation"].passed
    assert results["split_weight_fidelity"].passed
    assert not results["split_ledger_attestation"].passed
    assert "observed ledger delta" in results["split_ledger_attestation"].detail


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
    assert not results["split_ledger_attestation"].passed
    assert "no split" in results["split_ledger_attestation"].detail


# --------------------------------------------------------------------------
# ASK 4: fidelity is order-insensitive (payee->credit map, not position)
# --------------------------------------------------------------------------


def test_fidelity_accepts_reordered_but_correct_allocation() -> None:
    """Credits listed in a different order than the declared weights still pass.

    The canonical split of 1001 over a~40;b~40;c~20 is a~401;b~400;c~200. Here the
    settled event lists the same payees and credits in reverse -- correct amounts,
    different order -- which the order-insensitive map compare accepts.
    """
    events = [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~40;b~40;c~20"),
        _broadcast("buyer-0", "split:settled:ref=r0:amount=1001:alloc=c~200;b~400;a~401"),
    ]
    results = _by_name(validate_events(events, "split_settlement"))
    assert results["split_weight_fidelity"].passed
    assert results["split_conservation"].passed


def test_fidelity_rejects_duplicate_payee_in_allocation() -> None:
    """A payee that repeats in the reported allocation is a violation, not merged."""
    events = [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~1;b~1"),
        # 'a' repeated: it sums to 100 but names a duplicate payee -- must fail.
        _broadcast("buyer-0", "split:settled:ref=r0:amount=100:alloc=a~50;a~50"),
    ]
    results = _by_name(validate_events(events, "split_settlement"))
    assert not results["split_weight_fidelity"].passed
    assert "duplicate payee" in results["split_weight_fidelity"].detail


# --------------------------------------------------------------------------
# ASK 3: ledger-attestation validator (synthetic traces)
# --------------------------------------------------------------------------


def _attested_events() -> list[dict[str, Any]]:
    """Two settlements with payee attestations whose deltas match the credits."""
    return [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~40;b~40;c~20"),
        _broadcast("buyer-0", "split:settled:ref=r0:amount=1000:alloc=a~400;b~400;c~200"),
        _broadcast("a", "split:observed:ref=r0:payee=a:balance=400"),
        _broadcast("b", "split:observed:ref=r0:payee=b:balance=400"),
        _broadcast("c", "split:observed:ref=r0:payee=c:balance=200"),
        _broadcast("buyer-1", "split:opened:ref=r1:payer=buyer-1:weights=a~1;c~1"),
        _broadcast("buyer-1", "split:settled:ref=r1:amount=100:alloc=a~50;c~50"),
        # a and c are credited again; the delta from the prior attestation is 50.
        _broadcast("a", "split:observed:ref=r1:payee=a:balance=450"),
        _broadcast("c", "split:observed:ref=r1:payee=c:balance=250"),
    ]


def test_attestation_accepts_matching_ledger_deltas() -> None:
    results = _by_name(validate_events(_attested_events(), "split_settlement"))
    assert results["split_ledger_attestation"].passed


def test_attestation_flags_shorted_ledger_delta() -> None:
    """A payee whose observed balance moves less than reported is caught."""
    events = _attested_events()
    # a's first attestation is one unit short of the reported 400 credit; keep the
    # later balance consistent with the shorted start so only r0/a is flagged.
    events[2] = _broadcast("a", "split:observed:ref=r0:payee=a:balance=399")
    events[7] = _broadcast("a", "split:observed:ref=r1:payee=a:balance=449")
    results = _by_name(validate_events(events, "split_settlement"))
    assert not results["split_ledger_attestation"].passed
    assert "observed ledger delta" in results["split_ledger_attestation"].detail


def test_attestation_flags_settlement_without_attestation() -> None:
    """A settlement with no covering payee attestation fails, like the other two."""
    events = [
        _broadcast("buyer-0", "split:opened:ref=r0:payer=buyer-0:weights=a~1;b~1"),
        _broadcast("buyer-0", "split:settled:ref=r0:amount=100:alloc=a~50;b~50"),
    ]
    results = _by_name(validate_events(events, "split_settlement"))
    assert not results["split_ledger_attestation"].passed
    assert "no covering attestation" in results["split_ledger_attestation"].detail
