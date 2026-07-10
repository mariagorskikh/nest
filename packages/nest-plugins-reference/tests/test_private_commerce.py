# SPDX-License-Identifier: Apache-2.0
"""Tests for the private_commerce scenario and its joint cross-layer validators.

Three layers of coverage, mirroring the repo's gossip/privacy test structure:

1. **Validator unit tests** — hand-built event lists exercising pass, fail,
   and absent-marker code paths for each of the four joint validators.
2. **Adversarial discrimination** — the full scenario re-run with exactly one
   YAML layer swapped: ``privacy: noop`` must fail the opacity validator and
   ``trust: score_average`` must fail the undelivered-penalty validator,
   while the intended composition passes all four. This is the charter's bar:
   validators the reference plugins literally cannot satisfy.
3. **Full simulator integration** — the ``private_commerce`` scenario booted
   via ``ScenarioRunner``: determinism (same seed → byte-identical trace),
   seed sensitivity, and all four validators green under two seeds.

Property tests (Hypothesis) fuzz the validator parsers with arbitrary
interleavings of well-formed and junk markers to pin the no-crash and
order-independence properties.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    VALIDATORS,
    validate_commerce_bid_opacity,
    validate_commerce_delivery_rewarded,
    validate_commerce_discovery_precedes_bid,
    validate_commerce_undelivered_penalized,
    validate_trace,
)

SCENARIO_YAML = Path(__file__).resolve().parents[3] / "scenarios" / "private_commerce.yaml"


def _bc(msg: str, agent: str = "x") -> dict[str, Any]:
    """A broadcast trace event with the given body, from the given sender.

    ``agent`` defaults to a bystander id ("x") for markers that don't carry
    a principal to bind against. Markers the validators bind to a principal
    (``fulfilled:<seller>``, ``score:`` from the auditor) must pass the
    matching real sender explicitly.
    """
    return {"kind": "broadcast", "agent": agent, "msg": msg}


def _send(msg: str) -> dict[str, Any]:
    """A point-to-point send trace event with the given body."""
    return {"kind": "send", "agent": "x", "to": "y", "msg": msg}


# ---------------------------------------------------------------------------
# 1. Validator unit tests
# ---------------------------------------------------------------------------


class TestDiscoveryPrecedesBid:
    def test_passes_when_discovery_comes_first(self) -> None:
        events = [
            _bc("discovered:buyer-0:seller-0"),
            _bc("bidmeta:buyer-0:seller-0:bid-buyer-0:150"),
        ]
        (result,) = validate_commerce_discovery_precedes_bid(events)
        assert result.passed, result.detail

    def test_fails_when_bid_has_no_discovery(self) -> None:
        events = [_bc("bidmeta:buyer-0:seller-0:bid-buyer-0:150")]
        (result,) = validate_commerce_discovery_precedes_bid(events)
        assert not result.passed
        assert "without prior gossip discovery" in result.detail

    def test_fails_when_discovery_is_for_a_different_seller(self) -> None:
        events = [
            _bc("discovered:buyer-0:seller-1"),
            _bc("bidmeta:buyer-0:seller-0:bid-buyer-0:150"),
        ]
        (result,) = validate_commerce_discovery_precedes_bid(events)
        assert not result.passed

    def test_fails_on_empty_trace(self) -> None:
        (result,) = validate_commerce_discovery_precedes_bid([])
        assert not result.passed
        assert "no bidmeta markers" in result.detail


class TestBidOpacity:
    def test_passes_when_wire_bid_is_ciphertext(self) -> None:
        events = [
            _bc("bidmeta:buyer-0:seller-0:bid-buyer-0:150"),
            _send("bid:\x8f\x02\xa1 opaque envelope bytes"),
        ]
        (result,) = validate_commerce_bid_opacity(events)
        assert result.passed, result.detail

    def test_fails_when_plaintext_marker_is_on_the_wire(self) -> None:
        events = [
            _bc("bidmeta:buyer-0:seller-0:bid-buyer-0:150"),
            _send("bid:bidamount:150:from:buyer-0:ref:bid-buyer-0"),
        ]
        (result,) = validate_commerce_bid_opacity(events)
        assert not result.passed
        assert "visible on the wire" in result.detail

    def test_checks_dropped_deliveries_too(self) -> None:
        events = [
            _bc("bidmeta:buyer-0:seller-0:bid-buyer-0:150"),
            {"kind": "dropped", "agent": "e", "msg": "bid:bidamount:150:from:buyer-0:ref:r"},
        ]
        (result,) = validate_commerce_bid_opacity(events)
        assert not result.passed

    def test_fails_on_trace_without_wire_bids(self) -> None:
        (result,) = validate_commerce_bid_opacity([_bc("bidmeta:buyer-0:seller-0:r:150")])
        assert not result.passed
        assert "no bid wire messages" in result.detail


class TestUndeliveredPenalized:
    def test_passes_when_offender_scores_low(self) -> None:
        events = [
            _bc("stream:open:buyer-0:shill_seller-0:bid-buyer-0:10"),
            _bc("stream:close:buyer-0:shill_seller-0:bid-buyer-0:200"),
            _bc("score:shill_seller-0:0.000000:0.000000"),
        ]
        (result,) = validate_commerce_undelivered_penalized(events)
        assert result.passed, result.detail

    def test_fails_when_offender_scores_high(self) -> None:
        events = [
            _bc("stream:open:buyer-0:shill_seller-0:bid-buyer-0:10"),
            _bc("stream:close:buyer-0:shill_seller-0:bid-buyer-0:200"),
            _bc("score:shill_seller-0:0.750000:0.500000"),
        ]
        (result,) = validate_commerce_undelivered_penalized(events)
        assert not result.passed
        assert "0.750" in result.detail

    def test_fails_when_offender_never_scored(self) -> None:
        events = [
            _bc("stream:open:buyer-0:shill_seller-0:bid-buyer-0:10"),
            _bc("stream:close:buyer-0:shill_seller-0:bid-buyer-0:200"),
        ]
        (result,) = validate_commerce_undelivered_penalized(events)
        assert not result.passed
        assert "never scored" in result.detail

    def test_delivered_stream_is_not_an_offense(self) -> None:
        events = [
            _bc("stream:open:buyer-0:seller-0:bid-buyer-0:10"),
            _bc("fulfilled:seller-0:buyer-0:bid-buyer-0", agent="seller-0"),
            _bc("stream:close:buyer-0:seller-0:bid-buyer-0:200"),
        ]
        (result,) = validate_commerce_undelivered_penalized(events)
        # No offenders at all → the adversary never fired → validator fails loudly.
        assert not result.passed
        assert "adversary never fired" in result.detail

    def test_forged_fulfilled_from_wrong_sender_does_not_count(self) -> None:
        """A ``fulfilled:seller-0`` broadcast by someone other than seller-0
        must not clear seller-0 of the drain -- the marker names a principal
        it didn't actually come from."""
        events = [
            _bc("stream:open:buyer-0:shill_seller-0:bid-buyer-0:10"),
            _bc("fulfilled:shill_seller-0:buyer-0:bid-buyer-0", agent="attacker-0"),
            _bc("stream:close:buyer-0:shill_seller-0:bid-buyer-0:200"),
            _bc("score:shill_seller-0:0.750000:0.500000"),
        ]
        (result,) = validate_commerce_undelivered_penalized(events)
        assert not result.passed
        assert "0.750" in result.detail

    def test_zero_total_stream_is_not_a_drain(self) -> None:
        events = [
            _bc("stream:open:buyer-0:shill_seller-0:bid-buyer-0:10"),
            _bc("stream:close:buyer-0:shill_seller-0:bid-buyer-0:0"),
        ]
        (result,) = validate_commerce_undelivered_penalized(events)
        assert not result.passed
        assert "adversary never fired" in result.detail


class TestDeliveryRewarded:
    def test_passes_when_fulfilment_is_paid_and_scored(self) -> None:
        events = [
            _bc("stream:open:buyer-0:seller-0:bid-buyer-0:10"),
            _bc("fulfilled:seller-0:buyer-0:bid-buyer-0", agent="seller-0"),
            _bc("score:seller-0:0.400000:1.000000"),
        ]
        (result,) = validate_commerce_delivery_rewarded(events)
        assert result.passed, result.detail

    def test_fails_on_unpaid_fulfilment(self) -> None:
        events = [
            _bc("fulfilled:seller-0:buyer-0:bid-buyer-0", agent="seller-0"),
            _bc("score:seller-0:0.400000:1.000000"),
        ]
        (result,) = validate_commerce_delivery_rewarded(events)
        assert not result.passed
        assert "without a matching payment stream" in result.detail

    def test_fails_when_fulfilling_seller_scores_low(self) -> None:
        events = [
            _bc("stream:open:buyer-0:seller-0:bid-buyer-0:10"),
            _bc("fulfilled:seller-0:buyer-0:bid-buyer-0", agent="seller-0"),
            _bc("score:seller-0:0.100000:1.000000"),
        ]
        (result,) = validate_commerce_delivery_rewarded(events)
        assert not result.passed
        assert "0.100" in result.detail

    def test_fails_on_trace_without_fulfilments(self) -> None:
        (result,) = validate_commerce_delivery_rewarded([])
        assert not result.passed
        assert "no fulfilment markers" in result.detail

    def test_forged_fulfilled_from_wrong_sender_does_not_count(self) -> None:
        """A seller can't be credited with a fulfilment someone else claimed
        on its behalf -- the marker's principal must match its broadcaster."""
        events = [
            _bc("stream:open:buyer-0:seller-0:bid-buyer-0:10"),
            _bc("fulfilled:seller-0:buyer-0:bid-buyer-0", agent="attacker-0"),
            _bc("score:seller-0:0.400000:1.000000"),
        ]
        (result,) = validate_commerce_delivery_rewarded(events)
        assert not result.passed
        assert "no fulfilment markers" in result.detail

    def test_forged_score_after_the_auditor_does_not_override_it(self) -> None:
        """A byzantine agent broadcasting a ``score:`` line after the real
        auditor finalized must not win last-write-wins: the canonical
        auditor is whoever broadcast the *first* score: marker in the trace,
        and every later score: from a different sender is discarded."""
        events = [
            _bc("stream:open:buyer-0:seller-0:bid-buyer-0:10"),
            _bc("fulfilled:seller-0:buyer-0:bid-buyer-0", agent="seller-0"),
            _bc("score:seller-0:0.750000:1.000000", agent="auditor-0"),
            # Forged low score from a non-auditor sender, broadcast after the
            # real one -- must not overwrite the honest 0.75.
            _bc("score:seller-0:0.000000:0.000000", agent="attacker-0"),
        ]
        (result,) = validate_commerce_delivery_rewarded(events)
        assert result.passed, result.detail


# ---------------------------------------------------------------------------
# Property tests: parser robustness and duplicate-collapse
# ---------------------------------------------------------------------------

_JUNK = st.text(alphabet=st.characters(codec="utf-8"), max_size=40)


class TestValidatorProperties:
    @given(junk=st.lists(_JUNK, max_size=25))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_junk_markers_never_crash_any_validator(self, junk: list[str]) -> None:
        """Arbitrary garbage interleaved with valid markers must not raise."""
        events = [_bc(m) for m in junk]
        events.insert(0, _bc("discovered:buyer-0:seller-0"))
        events.append(_bc("bidmeta:buyer-0:seller-0:r:150"))
        for validator in VALIDATORS["private_commerce"]:
            results = validator(events)
            assert results and isinstance(results[0].passed, bool)

    @given(copies=st.integers(min_value=1, max_value=6))
    @settings(max_examples=20)
    def test_redundant_marker_copies_do_not_change_verdicts(self, copies: int) -> None:
        """Senders re-broadcast markers for drop-redundancy; dedup must hold."""
        # (message, sender) -- fulfilled: and score: need their real principal
        # as sender now that the validators check marker provenance.
        base = [
            ("discovered:buyer-0:seller-0", "x"),
            ("stream:open:buyer-0:seller-0:bid-buyer-0:10", "x"),
            ("bidmeta:buyer-0:seller-0:bid-buyer-0:150", "x"),
            ("fulfilled:seller-0:buyer-0:bid-buyer-0", "seller-0"),
            ("stream:close:buyer-0:seller-0:bid-buyer-0:60", "x"),
            ("stream:open:buyer-1:shill_seller-0:bid-buyer-1:10", "x"),
            ("bidmeta:buyer-1:shill_seller-0:bid-buyer-1:150", "x"),
            ("discovered:buyer-1:shill_seller-0", "x"),
            ("stream:close:buyer-1:shill_seller-0:bid-buyer-1:60", "x"),
            ("score:seller-0:0.400000:1.000000", "auditor-0"),
            ("score:shill_seller-0:0.000000:0.000000", "auditor-0"),
        ]
        # Move the second discovery before its bid to keep ordering legal.
        base.insert(5, base.pop(7))
        once = [_bc(m, agent=a) for m, a in base]
        multi = [_bc(m, agent=a) for m, a in base for _ in range(copies)]
        for validator in (
            validate_commerce_discovery_precedes_bid,
            validate_commerce_undelivered_penalized,
            validate_commerce_delivery_rewarded,
        ):
            (r_once,) = validator(once)
            (r_multi,) = validator(multi)
            assert r_once.passed == r_multi.passed, (validator.__name__, r_multi.detail)


# ---------------------------------------------------------------------------
# 2 + 3. Full-simulator integration and adversarial discrimination
# ---------------------------------------------------------------------------


def _run_scenario(tmp_path: Path, *, seed: int = 42, **layer_overrides: str) -> Path:
    """Run the private_commerce scenario with optional layer swaps; return the trace path."""
    config = ScenarioConfig.from_yaml(SCENARIO_YAML)
    config.seed = seed
    for layer, plugin in layer_overrides.items():
        setattr(config.layers, layer, plugin)
    trace = tmp_path / f"pc-{seed}-{'-'.join(layer_overrides.values()) or 'intended'}.jsonl"
    config.output.trace = str(trace)
    asyncio.run(ScenarioRunner(config).run())
    return trace


class TestPrivateCommerceIntegration:
    def test_intended_composition_passes_all_validators(self, tmp_path: Path) -> None:
        trace = _run_scenario(tmp_path)
        results = validate_trace(trace, "private_commerce")
        assert len(results) == 4
        failures = [r for r in results if not r.passed]
        assert not failures, [f"{r.name}: {r.detail}" for r in failures]

    def test_second_seed_also_passes(self, tmp_path: Path) -> None:
        trace = _run_scenario(tmp_path, seed=7)
        failures = [r for r in validate_trace(trace, "private_commerce") if not r.passed]
        assert not failures, [f"{r.name}: {r.detail}" for r in failures]

    def test_same_seed_gives_byte_identical_traces(self, tmp_path: Path) -> None:
        h = [
            hashlib.sha256(_run_scenario(tmp_path / f"run{i}", seed=42).read_bytes()).hexdigest()
            for i in (1, 2)
        ]
        assert h[0] == h[1]

    def test_different_seeds_give_different_traces(self, tmp_path: Path) -> None:
        h42 = hashlib.sha256(_run_scenario(tmp_path / "a", seed=42).read_bytes()).hexdigest()
        h7 = hashlib.sha256(_run_scenario(tmp_path / "b", seed=7).read_bytes()).hexdigest()
        assert h42 != h7

    def test_noop_privacy_fails_exactly_the_opacity_validator(self, tmp_path: Path) -> None:
        """Adversarial discrimination: plaintext envelopes must be caught."""
        trace = _run_scenario(tmp_path, privacy="noop")
        verdicts = {r.name: r.passed for r in validate_trace(trace, "private_commerce")}
        assert verdicts["commerce_bid_opacity"] is False
        assert verdicts["commerce_discovery_precedes_bid"] is True
        assert verdicts["commerce_undelivered_penalized"] is True
        assert verdicts["commerce_delivery_rewarded"] is True

    def test_score_average_trust_fails_exactly_the_penalty_validator(self, tmp_path: Path) -> None:
        """Adversarial discrimination: wash-traded receipts must inflate the
        reference trust average past the threshold, which the joint validator
        catches. ``agent_receipts`` severance is what makes the intended
        composition pass instead."""
        trace = _run_scenario(tmp_path, trust="score_average")
        verdicts = {r.name: r.passed for r in validate_trace(trace, "private_commerce")}
        assert verdicts["commerce_undelivered_penalized"] is False
        assert verdicts["commerce_bid_opacity"] is True
        assert verdicts["commerce_discovery_precedes_bid"] is True
        assert verdicts["commerce_delivery_rewarded"] is True
