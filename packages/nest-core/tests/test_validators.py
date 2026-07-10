# SPDX-License-Identifier: Apache-2.0
"""Tests for protocol invariant validators."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nest_core.validators import (
    VALIDATORS,
    ValidationResult,
    validate_auction_all_notified,
    validate_auction_single_winner,
    validate_auction_winner_highest,
    validate_consensus_agreement,
    validate_consensus_no_conflict,
    validate_consensus_validity,
    validate_empic_all_escrows_terminal,
    validate_empic_delivery_policy_integrity,
    validate_empic_escrow_conservation,
    validate_empic_invalid_delivery_not_paid,
    validate_empic_max_spend_enforced,
    validate_empic_no_drain_after_close,
    validate_empic_no_duplicate_settlement,
    validate_empic_no_overbill_on_partition,
    validate_empic_no_release_without_accepted_delivery,
    validate_empic_no_secret_material,
    validate_empic_payment_participant_binding,
    validate_empic_provider_service_binding,
    validate_empic_pubsub_billing_caps,
    validate_escrow_bps_in_range,
    validate_escrow_no_payout_without_delivery,
    validate_escrow_role_binding,
    validate_escrow_state_machine,
    validate_events,
    validate_marketplace_no_double_sell,
    validate_marketplace_price_agreement,
    validate_marketplace_responses,
    validate_reputation_scoring,
    validate_reputation_warnings,
    validate_rogue_trusted_agent_blocked,
    validate_rogue_trusted_agent_reputation,
    validate_supply_chain_no_lost,
    validate_supply_chain_pipeline,
    validate_trace,
    validate_voting_all_counted,
    validate_voting_no_double_vote,
    validate_voting_tally,
)

type Event = dict[str, Any]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send(agent: str, to: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _empic(event: dict[str, Any], *, agent: str = "consumer", tick: int = 0) -> Event:
    body = {"type": "empic_audit", "tick": tick, **event}
    return _send(agent, agent, json.dumps(body, sort_keys=True), ts=float(tick))


def _empic_delivery(
    event: dict[str, Any],
    *,
    agent: str = "provider",
    to: str = "consumer",
    tick: int = 0,
) -> Event:
    body = {"type": "empic_delivery", **event}
    return _send(agent, to, json.dumps(body, sort_keys=True), ts=float(tick))


def _empic_weather_policy() -> dict[str, Any]:
    return {
        "required_fields": [
            "temperature_c",
            "temperature_f",
            "windspeed_kmh",
            "timestamp",
            "tick",
        ],
        "numeric_ranges": {
            "temperature_c": {"min": -50, "max": 60},
            "temperature_f": {"min": -58, "max": 140},
            "windspeed_kmh": {"min": 0, "max": 300},
        },
        "max_age_ticks": 3,
        "bind_service_id": True,
        "bind_provider_id": True,
        "bind_consumer_id": True,
        "bind_request_params": True,
    }


def _broadcast(agent: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "broadcast", "msg": msg}


# ===================================================================
# Marketplace
# ===================================================================


class TestMarketplaceNoDoubleSell:
    def test_pass_unique_sales(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("seller-0", "buyer-1", "sold:product-1:60"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert len(results) == 1
        assert results[0].passed is True

    def test_fail_double_sell(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("seller-0", "buyer-1", "sold:product-0:50"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert len(results) == 1
        assert results[0].passed is False
        assert "product-0" in results[0].detail

    def test_pass_different_sellers_same_product(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("seller-1", "buyer-1", "sold:product-0:60"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert results[0].passed is True

    def test_pass_no_sales(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "reject:product-0:60"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert results[0].passed is True


class TestMarketplaceResponses:
    def test_pass_all_answered(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("buyer-1", "seller-0", "buy:product-1:30"),
            _send("seller-0", "buyer-1", "reject:product-1:40"),
        ]
        results = validate_marketplace_responses(events)
        assert results[0].passed is True

    def test_fail_unanswered_request(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("buyer-1", "seller-0", "buy:product-1:30"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            # buyer-1's request for product-1 never answered
        ]
        results = validate_marketplace_responses(events)
        assert results[0].passed is False
        assert "1 unanswered" in results[0].detail

    def test_pass_no_requests(self) -> None:
        events = [
            {"ts": 0.0, "agent": "seller-0", "kind": "start"},
        ]
        results = validate_marketplace_responses(events)
        assert results[0].passed is True


class TestMarketplacePriceAgreement:
    def test_pass_price_matches_buy(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is True

    def test_pass_price_matches_counter(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:30"),
            _send("seller-0", "buyer-0", "reject:product-0:40"),
            _send("buyer-0", "seller-0", "buy:product-0:40"),
            _send("seller-0", "buyer-0", "sold:product-0:40"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is True

    def test_fail_price_mismatch(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:99"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is False
        assert "99" in results[0].detail

    def test_fail_signed_price_mismatch(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50|sig:abc"),
            _send("seller-0", "buyer-0", "sold:product-0:99|sig:def"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is False
        assert "99" in results[0].detail

    def test_fail_sale_without_offer(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is False
        assert "without an offer" in results[0].detail


# ===================================================================
# Auction
# ===================================================================


class TestAuctionWinnerHighest:
    def test_pass_highest_wins(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:150"),
            _send("bidder-2", "auctioneer-0", "bid:item-1:120"),
            _send("auctioneer-0", "bidder-1", "won:item-1:150"),
        ]
        results = validate_auction_winner_highest(events)
        assert results[0].passed is True

    def test_fail_lower_bid_wins(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:200"),
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
        ]
        results = validate_auction_winner_highest(events)
        assert results[0].passed is False
        assert "200" in results[0].detail

    def test_pass_no_auctions(self) -> None:
        events = [{"ts": 0.0, "agent": "auctioneer-0", "kind": "start"}]
        results = validate_auction_winner_highest(events)
        assert results[0].passed is True


class TestAuctionSingleWinner:
    def test_pass_one_winner(self) -> None:
        events = [
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
            _send("auctioneer-0", "bidder-1", "lost:item-1:100"),
        ]
        results = validate_auction_single_winner(events)
        assert results[0].passed is True

    def test_fail_two_winners(self) -> None:
        events = [
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
            _send("auctioneer-0", "bidder-1", "won:item-1:100"),
        ]
        results = validate_auction_single_winner(events)
        assert results[0].passed is False
        assert "item-1" in results[0].detail

    def test_pass_different_items(self) -> None:
        events = [
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
            _send("auctioneer-0", "bidder-1", "won:item-2:150"),
        ]
        results = validate_auction_single_winner(events)
        assert results[0].passed is True


class TestAuctionAllNotified:
    def test_pass_all_notified(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:150"),
            _send("auctioneer-0", "bidder-0", "lost:item-1:150"),
            _send("auctioneer-0", "bidder-1", "won:item-1:150"),
        ]
        results = validate_auction_all_notified(events)
        assert results[0].passed is True

    def test_fail_missing_notification(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:150"),
            _send("auctioneer-0", "bidder-1", "won:item-1:150"),
            # bidder-0 never notified
        ]
        results = validate_auction_all_notified(events)
        assert results[0].passed is False
        assert "bidder-0" in results[0].detail


# ===================================================================
# Voting
# ===================================================================


class TestVotingTally:
    def test_pass_correct_tally(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("voter-2", "coordinator-0", "vote:1:yes:voter-2"),
            _send("coordinator-0", "proposer-0", "result:1:passed:2/3"),
        ]
        results = validate_voting_tally(events)
        assert results[0].passed is True

    def test_fail_wrong_tally(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("voter-2", "coordinator-0", "vote:1:yes:voter-2"),
            _send("coordinator-0", "proposer-0", "result:1:passed:3/3"),
        ]
        results = validate_voting_tally(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail


class TestVotingAllCounted:
    def test_pass_all_counted(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("coordinator-0", "proposer-0", "result:1:passed:1/2"),
        ]
        results = validate_voting_all_counted(events)
        assert results[0].passed is True

    def test_fail_vote_not_counted(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("voter-2", "coordinator-0", "vote:1:yes:voter-2"),
            # Tally says only 2 total but 3 voted
            _send("coordinator-0", "proposer-0", "result:1:passed:2/2"),
        ]
        results = validate_voting_all_counted(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail


class TestVotingNoDoubleVote:
    def test_pass_single_votes(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
        ]
        results = validate_voting_no_double_vote(events)
        assert results[0].passed is True

    def test_fail_double_vote(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-0", "coordinator-0", "vote:1:no:voter-0"),
        ]
        results = validate_voting_no_double_vote(events)
        assert results[0].passed is False
        assert "voter-0" in results[0].detail

    def test_pass_same_voter_different_rounds(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-0", "coordinator-0", "vote:2:yes:voter-0"),
        ]
        results = validate_voting_no_double_vote(events)
        assert results[0].passed is True


# ===================================================================
# Consensus
# ===================================================================


class TestConsensusAgreement:
    def test_pass_quorum_met(self) -> None:
        events = [
            _send("follower-0", "leader-0", "vote:1:accept"),
            _send("follower-1", "leader-0", "vote:1:accept"),
            _send("follower-2", "leader-0", "vote:1:reject"),
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-1", "result:1:committed:2/3"),
            _send("leader-0", "follower-2", "result:1:committed:2/3"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is True

    def test_fail_quorum_not_met(self) -> None:
        events = [
            _send("follower-0", "leader-0", "vote:1:accept"),
            _send("follower-1", "leader-0", "vote:1:reject"),
            _send("follower-2", "leader-0", "vote:1:reject"),
            # Committed with only 1/3 accepts
            _send("leader-0", "follower-0", "result:1:committed:1/3"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is False
        assert "1/3" in results[0].detail

    def test_fail_reported_tally_disagrees_with_votes(self) -> None:
        events = [
            _send("follower-0", "leader-0", "vote:1:reject"),
            _send("follower-1", "leader-0", "vote:1:reject"),
            _send("follower-2", "leader-0", "vote:1:reject"),
            _send("leader-0", "follower-0", "result:1:committed:3/3"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is False
        assert "reported 3/3 but actual 0/3" in results[0].detail

    def test_pass_aborted_no_quorum(self) -> None:
        """Aborted rounds are fine even without quorum."""
        events = [
            _send("follower-0", "leader-0", "vote:1:reject"),
            _send("follower-1", "leader-0", "vote:1:reject"),
            _send("leader-0", "follower-0", "result:1:aborted:0/2"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is True


class TestConsensusValidity:
    def test_pass_proposed_value_committed(self) -> None:
        events = [
            _send("leader-0", "follower-0", "propose:1:42"),
            _send("leader-0", "follower-1", "propose:1:42"),
            _send("leader-0", "follower-0", "result:1:committed:2/2"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is True

    def test_fail_committed_without_proposal(self) -> None:
        events = [
            # No propose for round 1
            _send("leader-0", "follower-0", "result:1:committed:2/2"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail

    def test_pass_no_commits(self) -> None:
        events = [
            _send("leader-0", "follower-0", "propose:1:42"),
            _send("leader-0", "follower-0", "result:1:aborted:0/2"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is True

    def test_fail_conflicting_proposals_same_round(self) -> None:
        events = [
            _send("leader-0", "follower-0", "propose:1:42"),
            _send("leader-0", "follower-1", "propose:1:99"),
            _send("leader-0", "follower-0", "result:1:committed:2/2:42"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is False
        assert "conflicting proposals" in results[0].detail


class TestConsensusNoConflict:
    def test_pass_single_commit_per_round(self) -> None:
        events = [
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-1", "result:1:committed:2/3"),
            _send("leader-0", "follower-2", "result:1:committed:2/3"),
        ]
        results = validate_consensus_no_conflict(events)
        assert results[0].passed is True

    def test_fail_conflicting_commits(self) -> None:
        events = [
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-1", "result:1:committed:3/3"),
        ]
        results = validate_consensus_no_conflict(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail

    def test_pass_different_rounds(self) -> None:
        events = [
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-0", "result:2:committed:3/3"),
        ]
        results = validate_consensus_no_conflict(events)
        assert results[0].passed is True


# ===================================================================
# Supply chain
# ===================================================================


class TestSupplyChainPipeline:
    def test_pass_full_pipeline(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("manufacturer-0", "distributor-0", "product:1:good-0"),
            _send("distributor-0", "retailer-0", "shipment:1:good-0"),
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
        ]
        results = validate_supply_chain_pipeline(events)
        assert results[0].passed is True

    def test_fail_missing_hop(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            # Skip manufacturer and distributor
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
        ]
        results = validate_supply_chain_pipeline(events)
        assert results[0].passed is False
        assert "product" in results[0].detail
        assert "shipment" in results[0].detail

    def test_fail_unmatched_delivery(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("manufacturer-0", "distributor-0", "product:2:good-0"),
            _send("distributor-0", "retailer-0", "shipment:3:good-0"),
            _send("retailer-0", "supplier-0", "delivered:4:good-0"),
        ]
        results = validate_supply_chain_pipeline(events)
        assert results[0].passed is False
        assert "4/good-0" in results[0].detail


class TestSupplyChainNoLost:
    def test_pass_all_delivered(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("supplier-0", "manufacturer-0", "material:1:raw-1"),
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
            _send("retailer-0", "supplier-0", "delivered:1:good-1"),
        ]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is True

    def test_fail_lost_goods(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("supplier-0", "manufacturer-0", "material:1:raw-1"),
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
            # raw-1 never delivered
        ]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is False
        assert "1 of 2" in results[0].detail

    def test_fail_nothing_delivered(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
        ]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is False

    def test_pass_no_materials(self) -> None:
        events = [{"ts": 0.0, "agent": "supplier-0", "kind": "start"}]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is True


# ===================================================================
# Reputation
# ===================================================================


class TestReputationScoring:
    def test_pass_cheaters_reported(self) -> None:
        events = [
            _send("malicious-0", "honest-0", "cheat:1:malicious-0"),
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
        ]
        results = validate_reputation_scoring(events)
        assert results[0].passed is True

    def test_fail_cheater_unreported(self) -> None:
        events = [
            _send("malicious-0", "honest-0", "cheat:1:malicious-0"),
            # No report:...:bad for malicious-0
        ]
        results = validate_reputation_scoring(events)
        assert results[0].passed is False
        assert "malicious-0" in results[0].detail

    def test_pass_no_cheating(self) -> None:
        events = [
            _send("honest-0", "honest-1", "deliver:1:honest-0"),
            _send("honest-1", "observer-0", "report:1:honest-0:good"),
        ]
        results = validate_reputation_scoring(events)
        assert results[0].passed is True


class TestReputationWarnings:
    def test_pass_warning_issued(self) -> None:
        events = [
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
            _send("honest-1", "observer-0", "report:2:malicious-0:bad"),
            _broadcast("observer-0", "warning:2:malicious-0:untrusted"),
        ]
        results = validate_reputation_warnings(events)
        assert results[0].passed is True

    def test_fail_no_warning(self) -> None:
        events = [
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
            _send("honest-1", "observer-0", "report:2:malicious-0:bad"),
            # Score is -4, should be warned but isn't
        ]
        results = validate_reputation_warnings(events)
        assert results[0].passed is False
        assert "malicious-0" in results[0].detail

    def test_pass_above_threshold(self) -> None:
        events = [
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
            # Score is -2, above -3 threshold
        ]
        results = validate_reputation_warnings(events)
        assert results[0].passed is True


# ===================================================================
# Integration tests
# ===================================================================


class TestValidateEvents:
    def test_marketplace_pass(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
        ]
        results = validate_events(events, "marketplace")
        assert len(results) == 3
        assert all(r.passed for r in results)

    def test_unknown_scenario(self) -> None:
        events = [_send("a", "b", "hello")]
        results = validate_events(events, "unknown_scenario")
        assert results == []


class TestValidateTrace:
    def test_from_file(self, tmp_path: Path) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50", ts=1.0),
        ]
        trace = tmp_path / "trace.jsonl"
        trace.write_text("\n".join(json.dumps(e) for e in events))
        results = validate_trace(trace, "marketplace")
        assert len(results) == 3
        assert all(r.passed for r in results)


class TestValidationResult:
    def test_repr_pass(self) -> None:
        r = ValidationResult("test", True, "ok")
        assert "PASS" in repr(r)

    def test_repr_fail(self) -> None:
        r = ValidationResult("test", False, "bad")
        assert "FAIL" in repr(r)


class TestStreamingValidators:
    """Tests for the three streaming payment validators."""

    def test_conservation_passes(self) -> None:
        """Conservation passes when debited == credited."""
        from nest_core.validators import validate_streaming_conservation

        events = [
            {"kind": "payment_debited", "agent": "payer", "amount": 100, "tick": 0},
            {"kind": "payment_credited", "agent": "payee", "amount": 100, "tick": 0},
            {"kind": "payment_debited", "agent": "payer", "amount": 50, "tick": 1},
            {"kind": "payment_credited", "agent": "payee", "amount": 50, "tick": 1},
        ]
        results = validate_streaming_conservation(events)
        assert len(results) == 1
        assert results[0].passed

    def test_conservation_fails_on_imbalance(self) -> None:
        """Conservation fails when debited != credited."""
        from nest_core.validators import validate_streaming_conservation

        events = [
            {"kind": "payment_debited", "agent": "payer", "amount": 100, "tick": 0},
            {"kind": "payment_credited", "agent": "payee", "amount": 50, "tick": 0},
        ]
        results = validate_streaming_conservation(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "conservation violation" in results[0].detail

    def test_no_drain_after_close_passes(self) -> None:
        """No drain-after-close passes when debits stop before close."""
        from nest_core.validators import validate_streaming_no_drain_after_close

        events = [
            {"event_type": "stream_opened", "stream_ref": "s1", "tick": 0},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 2},
            {"event_type": "stream_closed", "stream_ref": "s1", "tick": 3},
        ]
        results = validate_streaming_no_drain_after_close(events)
        assert len(results) == 1
        assert results[0].passed

    def test_no_drain_after_close_fails(self) -> None:
        """Fails when debit occurs after close."""
        from nest_core.validators import validate_streaming_no_drain_after_close

        events = [
            {"event_type": "stream_opened", "stream_ref": "s1", "tick": 0},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"event_type": "stream_closed", "stream_ref": "s1", "tick": 2},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 5},  # AFTER close!
        ]
        results = validate_streaming_no_drain_after_close(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "debited after close" in results[0].detail

    def test_no_overbill_on_partition_passes(self) -> None:
        """No over-bill passes when drops occur but no debits after."""
        from nest_core.validators import validate_streaming_no_overbill_on_partition

        events = [
            {
                "event_type": "stream_opened",
                "stream_ref": "s1",
                "agent": "payer",
                "to": "payee",
                "tick": 0,
            },
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"kind": "dropped", "from": "payer", "agent": "payee", "tick": 2},
            # No payment_debited after the partition
        ]
        results = validate_streaming_no_overbill_on_partition(events)
        assert len(results) == 1
        assert results[0].passed

    def test_no_overbill_on_partition_fails(self) -> None:
        """Fails when debit occurs after partition between payer and payee."""
        from nest_core.validators import validate_streaming_no_overbill_on_partition

        events = [
            {
                "event_type": "stream_opened",
                "stream_ref": "s1",
                "agent": "payer",
                "to": "payee",
                "tick": 0,
            },
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"kind": "dropped", "from": "payer", "agent": "payee", "tick": 3},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 5},  # OVER-BILL
        ]
        results = validate_streaming_no_overbill_on_partition(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "partitioned" in results[0].detail

    def test_no_overbill_ignores_other_drops(self) -> None:
        """Drop between unrelated agents does not trigger a violation."""
        from nest_core.validators import validate_streaming_no_overbill_on_partition

        events = [
            {
                "event_type": "stream_opened",
                "stream_ref": "s1",
                "agent": "payer",
                "to": "payee",
                "tick": 0,
            },
            {"kind": "dropped", "from": "other-a", "agent": "other-b", "tick": 2},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 5},
        ]
        results = validate_streaming_no_overbill_on_partition(events)
        assert len(results) == 1
        assert results[0].passed  # unrelated drop, not a violation


class TestEscrowValidators:
    """Direct validator tests with synthetic broadcast events."""

    @staticmethod
    def _ev(agent: str, msg: str) -> dict[str, Any]:
        return {"kind": "broadcast", "agent": agent, "msg": msg}

    @staticmethod
    def _happy(ref: str = "e1") -> list[dict[str, Any]]:
        return [
            TestEscrowValidators._ev(
                "buyer",
                f"escrow:opened:ref={ref}:payer=buyer:payee=seller:arbiter=arbiter:amount=250",
            ),
            TestEscrowValidators._ev("seller", f"escrow:delivered:ref={ref}:proof=sha256-cafe"),
            TestEscrowValidators._ev("buyer", f"escrow:released:ref={ref}"),
        ]

    @staticmethod
    def _dispute(ref: str = "e2", bps: int = 3000) -> list[dict[str, Any]]:
        return [
            TestEscrowValidators._ev(
                "buyer",
                f"escrow:opened:ref={ref}:payer=buyer:payee=seller:arbiter=arbiter:amount=400",
            ),
            TestEscrowValidators._ev("seller", f"escrow:delivered:ref={ref}:proof=partial"),
            TestEscrowValidators._ev("buyer", f"escrow:disputed:ref={ref}:reason=incomplete"),
            TestEscrowValidators._ev("arbiter", f"escrow:arbitrated:ref={ref}:payee_bps={bps}"),
        ]

    def test_state_machine_passes_happy_path(self) -> None:
        results = validate_escrow_state_machine(self._happy())
        assert len(results) == 1
        assert results[0].passed, results[0].detail

    def test_state_machine_passes_dispute_path(self) -> None:
        results = validate_escrow_state_machine(self._dispute())
        assert results[0].passed, results[0].detail

    def test_state_machine_passes_combined(self) -> None:
        results = validate_escrow_state_machine(self._happy("a") + self._dispute("b"))
        assert results[0].passed, results[0].detail

    def test_state_machine_fails_on_release_without_delivery(self) -> None:
        events = [
            self._ev(
                "buyer",
                "escrow:opened:ref=x:payer=buyer:payee=seller:arbiter=arbiter:amount=100",
            ),
            self._ev("buyer", "escrow:released:ref=x"),  # skipped delivered
        ]
        results = validate_escrow_state_machine(events)
        assert not results[0].passed
        assert "illegal transition" in results[0].detail

    def test_state_machine_fails_on_arbitrate_without_dispute(self) -> None:
        events = [
            self._ev(
                "buyer",
                "escrow:opened:ref=y:payer=buyer:payee=seller:arbiter=arbiter:amount=100",
            ),
            self._ev("seller", "escrow:delivered:ref=y:proof=x"),
            self._ev("arbiter", "escrow:arbitrated:ref=y:payee_bps=5000"),
        ]
        results = validate_escrow_state_machine(events)
        assert not results[0].passed

    def test_state_machine_fails_on_double_release(self) -> None:
        events = self._happy()
        events.append(self._ev("buyer", "escrow:released:ref=e1"))
        results = validate_escrow_state_machine(events)
        assert not results[0].passed

    def test_state_machine_fails_when_no_escrow_events(self) -> None:
        # Mirrors what happens under prepaid_credits (no escrow protocol).
        events = [
            {"kind": "payment_debited", "agent": "buyer", "amount": 100, "tick": 0},
            {"kind": "payment_credited", "agent": "seller", "amount": 100, "tick": 0},
        ]
        results = validate_escrow_state_machine(events)
        assert not results[0].passed
        assert "no escrow lifecycle" in results[0].detail

    def test_role_binding_passes_happy(self) -> None:
        results = validate_escrow_role_binding(self._happy() + self._dispute())
        assert results[0].passed, results[0].detail

    def test_role_binding_fails_on_forged_delivery(self) -> None:
        events = [
            self._ev(
                "buyer",
                "escrow:opened:ref=e1:payer=buyer:payee=seller:arbiter=arbiter:amount=100",
            ),
            # An ATTACKER (not seller) tries to claim delivery.
            self._ev("attacker", "escrow:delivered:ref=e1:proof=fake"),
        ]
        results = validate_escrow_role_binding(events)
        assert not results[0].passed
        assert "delivered" in results[0].detail and "attacker" in results[0].detail

    def test_role_binding_fails_on_unauthorized_release(self) -> None:
        events = self._happy()
        # Replace the legitimate release with an unauthorized one.
        events[-1] = self._ev("attacker", "escrow:released:ref=e1")
        results = validate_escrow_role_binding(events)
        assert not results[0].passed

    def test_role_binding_fails_on_arbitrate_by_non_arbiter(self) -> None:
        events = self._dispute()
        events[-1] = self._ev("buyer", "escrow:arbitrated:ref=e2:payee_bps=10000")
        results = validate_escrow_role_binding(events)
        assert not results[0].passed

    def test_bps_in_range_passes_at_bounds(self) -> None:
        results = validate_escrow_bps_in_range(
            self._dispute("a", bps=0) + self._dispute("b", bps=10000)
        )
        assert results[0].passed, results[0].detail

    def test_bps_in_range_fails_negative(self) -> None:
        events = self._dispute(bps=-1)
        results = validate_escrow_bps_in_range(events)
        assert not results[0].passed

    def test_bps_in_range_fails_over_max(self) -> None:
        events = self._dispute(bps=15000)
        results = validate_escrow_bps_in_range(events)
        assert not results[0].passed

    def test_bps_in_range_fails_non_integer(self) -> None:
        events = [
            self._ev(
                "buyer",
                "escrow:opened:ref=z:payer=buyer:payee=seller:arbiter=arbiter:amount=100",
            ),
            self._ev("seller", "escrow:delivered:ref=z:proof=x"),
            self._ev("buyer", "escrow:disputed:ref=z:reason=x"),
            self._ev("arbiter", "escrow:arbitrated:ref=z:payee_bps=NaN"),
        ]
        results = validate_escrow_bps_in_range(events)
        assert not results[0].passed
        assert "non-integer" in results[0].detail

    def test_no_payout_without_delivery_passes(self) -> None:
        results = validate_escrow_no_payout_without_delivery(self._happy() + self._dispute())
        assert results[0].passed, results[0].detail

    def test_no_payout_without_delivery_fails_on_skipped_delivery(self) -> None:
        events = [
            self._ev(
                "buyer",
                "escrow:opened:ref=q:payer=buyer:payee=seller:arbiter=arbiter:amount=100",
            ),
            self._ev("buyer", "escrow:released:ref=q"),
        ]
        results = validate_escrow_no_payout_without_delivery(events)
        assert not results[0].passed
        assert "without prior delivered" in results[0].detail

    def test_no_payout_without_delivery_fails_when_no_payouts_at_all(self) -> None:
        # Plugin lacks escrow -- no escrow events ever emitted.
        results = validate_escrow_no_payout_without_delivery([])
        assert not results[0].passed
        assert "no escrow payouts" in results[0].detail


class TestEmpicPaymentsValidators:
    """Tests for EMPIC escrow and delivery validators."""

    def test_conservation_passes(self) -> None:
        """Debited escrow equals released plus refunded funds."""
        events = [
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic({"event_type": "empic_escrow_released", "payment_ref": "p1", "amount": 20}),
            _empic({"event_type": "empic_escrow_refunded", "payment_ref": "p1", "amount": 30}),
        ]

        results = validate_empic_escrow_conservation(events)
        assert len(results) == 1
        assert results[0].passed

    def test_conservation_fails(self) -> None:
        """Unaccounted escrow fails conservation."""
        events = [
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic({"event_type": "empic_escrow_released", "payment_ref": "p1", "amount": 20}),
        ]

        results = validate_empic_escrow_conservation(events)
        assert len(results) == 1
        assert not results[0].passed

    def test_conservation_fails_per_payment_ref_cross_subsidy(self) -> None:
        """Balanced totals still fail when one escrow subsidizes another."""
        events = [
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p2", "amount": 50}),
            _empic({"event_type": "empic_escrow_released", "payment_ref": "p1", "amount": 70}),
            _empic({"event_type": "empic_escrow_refunded", "payment_ref": "p2", "amount": 30}),
        ]

        results = validate_empic_escrow_conservation(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "p1" in results[0].detail
        assert "p2" in results[0].detail

    def test_no_release_without_accepted_delivery(self) -> None:
        """Release must reference an accepted delivery id."""
        events = [
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": True,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "amount": 10,
                }
            ),
        ]

        results = validate_empic_no_release_without_accepted_delivery(events)
        assert len(results) == 1
        assert results[0].passed

    def test_release_without_accepted_delivery_fails(self) -> None:
        """Release against rejected evidence fails."""
        events = [
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": False,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "amount": 10,
                }
            ),
        ]

        results = validate_empic_no_release_without_accepted_delivery(events)
        assert len(results) == 1
        assert not results[0].passed

    def test_invalid_delivery_not_paid_fails(self) -> None:
        """Rejected delivery ids must not appear in release events."""
        events = [
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": False,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "amount": 10,
                }
            ),
        ]

        results = validate_empic_invalid_delivery_not_paid(events)
        assert len(results) == 1
        assert not results[0].passed

    def test_delivery_policy_integrity_passes(self) -> None:
        """Accepted delivery must independently satisfy the declared policy."""
        request_params = {"lat": 42.3601, "lon": -71.0942}
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "request_params": request_params,
                    "policy": _empic_weather_policy(),
                }
            ),
            _empic_delivery(
                {
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "service_id": "weather",
                    "provider_id": "provider",
                    "consumer_id": "consumer",
                    "request_params": request_params,
                    "data": {
                        "temperature_c": 21.0,
                        "temperature_f": 69.8,
                        "windspeed_kmh": 8.0,
                        "timestamp": "tick-1",
                        "tick": 1,
                    },
                },
                tick=1,
            ),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": True,
                },
                tick=1,
            ),
        ]

        results = validate_empic_delivery_policy_integrity(events)
        assert len(results) == 1
        assert results[0].passed

    def test_delivery_policy_integrity_fails_bad_data_accepted(self) -> None:
        """Consumer acceptance cannot bless out-of-range weather data."""
        request_params = {"lat": 42.3601, "lon": -71.0942}
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "request_params": request_params,
                    "policy": _empic_weather_policy(),
                }
            ),
            _empic_delivery(
                {
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "service_id": "weather",
                    "provider_id": "provider",
                    "consumer_id": "consumer",
                    "request_params": request_params,
                    "data": {
                        "temperature_c": 120.0,
                        "temperature_f": 248.0,
                        "windspeed_kmh": 8.0,
                        "timestamp": "tick-1",
                        "tick": 1,
                    },
                },
                tick=1,
            ),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": True,
                },
                tick=1,
            ),
        ]

        results = validate_empic_delivery_policy_integrity(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "policy accepted=False" in results[0].detail

    def test_delivery_policy_integrity_fails_wrong_service_provider_or_params(self) -> None:
        """Provider/service/request binding must match the funded service."""
        request_params = {"lat": 42.3601, "lon": -71.0942}
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "request_params": request_params,
                    "policy": _empic_weather_policy(),
                }
            ),
            _empic_delivery(
                {
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "service_id": "weather-spoof",
                    "provider_id": "provider-spoof",
                    "consumer_id": "consumer",
                    "request_params": {"lat": 0, "lon": 0},
                    "data": {
                        "temperature_c": 21.0,
                        "temperature_f": 69.8,
                        "windspeed_kmh": 8.0,
                        "timestamp": "tick-1",
                        "tick": 1,
                    },
                },
                tick=1,
            ),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": True,
                },
                tick=1,
            ),
        ]

        results = validate_empic_delivery_policy_integrity(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "mismatch" in results[0].detail

    def test_delivery_policy_integrity_fails_wrong_consumer_replay(self) -> None:
        """A valid payload for the wrong consumer cannot release escrow."""
        request_params = {"lat": 42.3601, "lon": -71.0942}
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "request_params": request_params,
                    "policy": _empic_weather_policy(),
                }
            ),
            _empic_delivery(
                {
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "service_id": "weather",
                    "provider_id": "provider",
                    "consumer_id": "consumer-spoof",
                    "request_params": request_params,
                    "data": {
                        "temperature_c": 21.0,
                        "temperature_f": 69.8,
                        "windspeed_kmh": 8.0,
                        "timestamp": "tick-1",
                        "tick": 1,
                    },
                },
                tick=1,
            ),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": True,
                },
                tick=1,
            ),
        ]

        results = validate_empic_delivery_policy_integrity(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "consumer_id mismatch" in results[0].detail

    def test_pubsub_billing_caps_pass(self) -> None:
        """Pubsub release is capped by accepted delivery count and stream terms."""
        events = [
            _empic(
                {
                    "event_type": "empic_stream_opened",
                    "payment_ref": "s1",
                    "rate_per_tick": 10,
                    "max_total": 40,
                    "mode": "pubsub",
                }
            ),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "s1",
                    "delivery_id": "d1",
                    "accepted": True,
                    "mode": "pubsub",
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "s1",
                    "delivery_id": "d1",
                    "amount": 10,
                    "mode": "pubsub",
                }
            ),
        ]

        results = validate_empic_pubsub_billing_caps(events)
        assert len(results) == 1
        assert results[0].passed

    def test_pubsub_billing_caps_fails_over_rate(self) -> None:
        """A single pubsub delivery cannot be paid above the tick rate."""
        events = [
            _empic(
                {
                    "event_type": "empic_stream_opened",
                    "payment_ref": "s1",
                    "rate_per_tick": 10,
                    "max_total": 40,
                    "mode": "pubsub",
                }
            ),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "s1",
                    "delivery_id": "d1",
                    "accepted": True,
                    "mode": "pubsub",
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "s1",
                    "delivery_id": "d1",
                    "amount": 20,
                    "mode": "pubsub",
                }
            ),
        ]

        results = validate_empic_pubsub_billing_caps(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "release 20 > rate 10" in results[0].detail

    def test_pubsub_billing_caps_fails_without_accepted_evidence(self) -> None:
        """Accepted delivery count limits total pubsub payout."""
        events = [
            _empic(
                {
                    "event_type": "empic_stream_opened",
                    "payment_ref": "s1",
                    "rate_per_tick": 10,
                    "max_total": 40,
                    "mode": "pubsub",
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "s1",
                    "delivery_id": "d1",
                    "amount": 10,
                    "mode": "pubsub",
                }
            ),
        ]

        results = validate_empic_pubsub_billing_caps(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "accepted delivery cap 0" in results[0].detail

    def test_max_spend_enforced_passes(self) -> None:
        """Funded amount can equal but not exceed consumer max spend."""
        policy = {**_empic_weather_policy(), "max_spend": 50}
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "p1",
                    "policy": policy,
                    "max_spend": 50,
                }
            ),
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
        ]

        results = validate_empic_max_spend_enforced(events)
        assert len(results) == 1
        assert results[0].passed

    def test_max_spend_enforced_fails_over_budget_escrow(self) -> None:
        """Escrow funding above the consumer budget fails validation."""
        policy = {**_empic_weather_policy(), "max_spend": 40}
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "p1",
                    "policy": policy,
                    "max_spend": 40,
                }
            ),
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
        ]

        results = validate_empic_max_spend_enforced(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "exceeds declared max_spend" in results[0].detail

    def test_max_spend_enforced_fails_over_budget_stream(self) -> None:
        """Pubsub stream cap is checked against the consumer budget."""
        policy = {**_empic_weather_policy(), "max_spend": 30}
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "s1",
                    "policy": policy,
                    "max_spend": 30,
                }
            ),
            _empic(
                {
                    "event_type": "empic_stream_opened",
                    "payment_ref": "s1",
                    "max_total": 40,
                    "amount": 40,
                    "mode": "pubsub",
                }
            ),
        ]

        results = validate_empic_max_spend_enforced(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "funded 40 exceeds" in results[0].detail

    def test_all_escrows_terminal_passes(self) -> None:
        """Every funded escrow is fully released or refunded."""
        events = [
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic({"event_type": "empic_escrow_released", "payment_ref": "p1", "amount": 50}),
        ]

        results = validate_empic_all_escrows_terminal(events)
        assert len(results) == 1
        assert results[0].passed

    def test_all_escrows_terminal_fails_unbalanced(self) -> None:
        """Partially settled escrow is not terminal."""
        events = [
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic({"event_type": "empic_escrow_released", "payment_ref": "p1", "amount": 10}),
        ]

        results = validate_empic_all_escrows_terminal(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "not terminal" in results[0].detail

    def test_all_escrows_terminal_fails_pubsub_refund_without_close(self) -> None:
        """Pubsub refund must correspond to an observed close."""
        events = [
            _empic({"event_type": "empic_stream_opened", "payment_ref": "s1", "mode": "pubsub"}),
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "s1", "amount": 40}),
            _empic({"event_type": "empic_escrow_refunded", "payment_ref": "s1", "amount": 40}),
        ]

        results = validate_empic_all_escrows_terminal(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "without stream close" in results[0].detail

    def test_no_duplicate_settlement_fails_duplicate_release(self) -> None:
        """Replay of the same delivery evidence must be caught."""
        events = [
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "accepted": True,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "amount": 25,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "amount": 25,
                }
            ),
        ]

        results = validate_empic_no_duplicate_settlement(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "duplicate release" in results[0].detail

    def test_no_duplicate_settlement_fails_duplicate_debit_and_refund(self) -> None:
        """Payment refs cannot be debited or refunded twice."""
        events = [
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic({"event_type": "empic_escrow_debited", "payment_ref": "p1", "amount": 50}),
            _empic({"event_type": "empic_escrow_refunded", "payment_ref": "p1", "amount": 25}),
            _empic({"event_type": "empic_escrow_refunded", "payment_ref": "p1", "amount": 25}),
        ]

        results = validate_empic_no_duplicate_settlement(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "duplicate escrow debit" in results[0].detail
        assert "duplicate refund" in results[0].detail

    def test_provider_service_binding_passes(self) -> None:
        """Debit and release bind to the registered provider for a service."""
        events = [
            _empic(
                {
                    "event_type": "empic_service_registered",
                    "service_id": "weather",
                    "provider": "provider",
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_debited",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "provider": "provider",
                    "amount": 50,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "provider": "provider",
                    "delivery_id": "d1",
                    "amount": 50,
                }
            ),
        ]

        results = validate_empic_provider_service_binding(events)
        assert len(results) == 1
        assert results[0].passed

    def test_provider_service_binding_fails_wrong_provider(self) -> None:
        """Settlement cannot redirect release to a different provider."""
        events = [
            _empic(
                {
                    "event_type": "empic_service_registered",
                    "service_id": "weather",
                    "provider": "provider",
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_debited",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "provider": "provider",
                    "amount": 50,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "provider": "attacker",
                    "delivery_id": "d1",
                    "amount": 50,
                }
            ),
        ]

        results = validate_empic_provider_service_binding(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "does not match" in results[0].detail

    def test_provider_service_binding_fails_unregistered_service(self) -> None:
        """Consumers cannot fund a service that has no provider registration."""
        events = [
            _empic(
                {
                    "event_type": "empic_escrow_debited",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "provider": "provider",
                    "amount": 50,
                }
            ),
        ]

        results = validate_empic_provider_service_binding(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "was not registered" in results[0].detail

    def test_payment_participant_binding_passes(self) -> None:
        """Lifecycle events keep the same payer, consumer, provider, service, and mode."""
        events = [
            _empic(
                {
                    "event_type": "empic_acceptance_policy",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "mode": "pull",
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_debited",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "mode": "pull",
                    "amount": 50,
                }
            ),
            _empic(
                {
                    "event_type": "empic_delivery_evaluated",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "mode": "pull",
                    "accepted": True,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "mode": "pull",
                    "amount": 50,
                }
            ),
        ]

        results = validate_empic_payment_participant_binding(events)
        assert len(results) == 1
        assert results[0].passed

    def test_payment_participant_binding_fails_rebound_ref(self) -> None:
        """A payment ref cannot switch consumer/provider/service identity."""
        events = [
            _empic(
                {
                    "event_type": "empic_escrow_debited",
                    "payment_ref": "p1",
                    "service_id": "weather",
                    "payer": "consumer",
                    "consumer_id": "consumer",
                    "provider": "provider",
                    "mode": "pull",
                    "amount": 50,
                }
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "p1",
                    "delivery_id": "d1",
                    "service_id": "weather",
                    "payer": "attacker",
                    "consumer_id": "attacker",
                    "provider": "provider",
                    "mode": "pull",
                    "amount": 50,
                }
            ),
        ]

        results = validate_empic_payment_participant_binding(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "payer changed" in results[0].detail
        assert "consumer_id changed" in results[0].detail

    def test_no_secret_material_passes_public_metadata(self) -> None:
        """Public wallet-style metadata can appear in traces."""
        events = [
            _empic(
                {
                    "event_type": "empic_service_registered",
                    "service_id": "weather",
                    "provider": "provider",
                    "wallet_address": "0x00000000000000000000000000000000000000aa",
                    "did": "did:empic:test",
                }
            )
        ]

        results = validate_empic_no_secret_material(events)
        assert len(results) == 1
        assert results[0].passed

    def test_no_secret_material_fails_private_key(self) -> None:
        """Trace messages must not leak private keys or API secrets."""
        private_marker = "-----BEGIN " + "PRIVATE " + "KEY-----\nredacted"
        events = [
            _empic(
                {
                    "event_type": "empic_service_registered",
                    "service_id": "weather",
                    "provider": "provider",
                    "private_key": private_marker,
                }
            )
        ]

        results = validate_empic_no_secret_material(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "private_key" in results[0].detail

    def test_no_drain_after_close_fails(self) -> None:
        """Pubsub release after stream close is an attack."""
        events = [
            _empic(
                {"event_type": "empic_stream_closed", "payment_ref": "s1", "mode": "pubsub"},
                tick=2,
            ),
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "s1",
                    "mode": "pubsub",
                    "delivery_id": "d1",
                    "amount": 10,
                },
                tick=3,
            ),
        ]

        results = validate_empic_no_drain_after_close(events)
        assert len(results) == 1
        assert not results[0].passed

    def test_no_overbill_on_partition_fails(self) -> None:
        """Pubsub release after a dropped edge between parties is an attack."""
        events = [
            _empic(
                {
                    "event_type": "empic_stream_opened",
                    "payment_ref": "s1",
                    "payer": "consumer",
                    "provider": "provider",
                },
                tick=0,
            ),
            {"kind": "dropped", "from": "provider", "agent": "consumer", "ts": 2.0},
            _empic(
                {
                    "event_type": "empic_escrow_released",
                    "payment_ref": "s1",
                    "mode": "pubsub",
                    "delivery_id": "d1",
                    "amount": 10,
                },
                tick=3,
            ),
        ]

        results = validate_empic_no_overbill_on_partition(events)
        assert len(results) == 1
        assert not results[0].passed


class TestRogueTrustedAgentValidators:
    """Direct validator tests with synthetic broadcast trace lines."""

    @staticmethod
    def _bc(agent: str, msg: str) -> dict[str, Any]:
        return {"kind": "broadcast", "agent": agent, "msg": msg}

    def _gated(self) -> list[dict[str, Any]]:
        """Trace under a permit gate: warm-up execs, then a blocked rogue."""
        events: list[dict[str, Any]] = []
        for i in range(5):
            events.append(self._bc("veteran", f"permit:veteran:read:town/board:authorized:abc{i}"))
            events.append(self._bc("veteran", "exec:veteran:read:town/board"))
        events.append(self._bc("veteran", "rogue_attempt:veteran:spend:town/treasury"))
        events.append(self._bc("veteran", "permit:veteran:spend:town/treasury:denied:dead0000"))
        events.append(self._bc("veteran", "blocked:veteran:spend:town/treasury"))
        return events

    def _ungated(self) -> list[dict[str, Any]]:
        """Trace with no gate: warm-up execs, then the rogue exec runs."""
        events: list[dict[str, Any]] = []
        for _ in range(5):
            events.append(self._bc("veteran", "exec:veteran:read:town/board"))
        events.append(self._bc("veteran", "rogue_attempt:veteran:spend:town/treasury"))
        events.append(self._bc("veteran", "exec:veteran:spend:town/treasury"))
        return events

    def test_blocked_passes_under_gate(self) -> None:
        results = validate_rogue_trusted_agent_blocked(self._gated())
        assert results[0].passed, results[0].detail

    def test_blocked_fails_when_rogue_executes(self) -> None:
        results = validate_rogue_trusted_agent_blocked(self._ungated())
        assert not results[0].passed
        assert "executed" in results[0].detail

    def test_blocked_fails_without_declaration(self) -> None:
        results = validate_rogue_trusted_agent_blocked(
            [self._bc("veteran", "exec:veteran:read:town/board")]
        )
        assert not results[0].passed
        assert "no rogue_attempt" in results[0].detail

    def test_blocked_fails_when_neither_run_nor_denied(self) -> None:
        events = [self._bc("veteran", "rogue_attempt:veteran:spend:town/treasury")]
        results = validate_rogue_trusted_agent_blocked(events)
        assert not results[0].passed
        assert "no signed denial" in results[0].detail

    def test_reputation_passes_under_gate(self) -> None:
        results = validate_rogue_trusted_agent_reputation(self._gated())
        assert results[0].passed, results[0].detail

    def test_reputation_passes_under_ungated(self) -> None:
        # The corroborating invariant holds on both layers (no rogue block needed).
        results = validate_rogue_trusted_agent_reputation(self._ungated())
        assert results[0].passed, results[0].detail

    def test_reputation_fails_without_prior_actions(self) -> None:
        events = [
            self._bc("veteran", "rogue_attempt:veteran:spend:town/treasury"),
            self._bc("veteran", "permit:veteran:spend:town/treasury:denied:dead0000"),
            self._bc("veteran", "blocked:veteran:spend:town/treasury"),
        ]
        results = validate_rogue_trusted_agent_reputation(events)
        assert not results[0].passed
        assert "in-policy action" in results[0].detail

    def test_reputation_fails_on_spurious_denial(self) -> None:
        events = self._gated()
        # A benign in-policy action wrongly refused.
        spurious = self._bc("resident-0", "permit:resident-0:read:town/events:denied:0badf00d")
        events.insert(0, spurious)
        results = validate_rogue_trusted_agent_reputation(events)
        assert not results[0].passed
        assert "spuriously denied" in results[0].detail

    def test_no_crash_on_empty(self) -> None:
        assert not validate_rogue_trusted_agent_blocked([])[0].passed
        assert not validate_rogue_trusted_agent_reputation([])[0].passed


class TestValidatorRegistry:
    def test_all_scenario_types_registered(self) -> None:
        expected = {
            "marketplace",
            "auction",
            "voting",
            "consensus",
            "supply_chain",
            "reputation",
            "identity_rotation",
            "memory_concurrent_writers",
            "streaming_payments",
            "empic_payments",
            "comms_versioning",
            "comms_downgrade",
            "receipt_reputation",
            "multi_attribute_market",
            "provenance_supply_chain",
            "bft_hotstuff",
            "escrow_marketplace",
            "failure_detection",
            "parc_migration",
            "rogue_trusted_agent",
        }
        assert set(VALIDATORS.keys()) == expected

    def test_each_scenario_has_validators(self) -> None:
        for scenario, validators in VALIDATORS.items():
            assert len(validators) >= 2, f"{scenario} needs at least 2 validators"
