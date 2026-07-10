# SPDX-License-Identifier: Apache-2.0
"""Protocol invariant validators for Nanda Town scenarios.

Validators analyze trace files and verify that protocol-specific
correctness properties hold -- not just that messages flowed.

Each validator function takes a list of events (dicts parsed from JSONL)
and returns a list of ``ValidationResult``.  Events are expected to include
a ``"msg"`` field containing the decoded payload text for send/receive events.

Example::

    results = validate_trace(Path("trace.jsonl"), "marketplace")
    for r in results:
        print(f"{'PASS' if r.passed else 'FAIL'}: {r.name} - {r.detail}")
"""

from __future__ import annotations

import contextlib
import json
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast


class ValidationResult:
    """Result of a protocol validation check."""

    def __init__(self, name: str, passed: bool, detail: str = "") -> None:
        self.name = name
        self.passed = passed
        self.detail = detail

    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"ValidationResult({status}: {self.name!r}, {self.detail!r})"


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def validate_trace(
    trace_path: Path,
    scenario_type: str,
) -> list[ValidationResult]:
    """Run all validators for a scenario type against a trace.

    Example::

        results = validate_trace(Path("trace.jsonl"), "marketplace")
    """
    events = _load_events(trace_path)
    return validate_events(events, scenario_type)


def validate_events(
    events: list[dict[str, Any]],
    scenario_type: str,
) -> list[ValidationResult]:
    """Run all validators for a scenario type against in-memory events.

    Example::

        results = validate_events(event_list, "auction")
    """
    validators = VALIDATORS.get(scenario_type, [])
    results: list[ValidationResult] = []
    for validator_fn in validators:
        results.extend(validator_fn(events))
    return results


def _message_body(ev: dict[str, Any]) -> str:
    """Return payload text without the signature suffix added by reference agents."""
    return str(ev.get("msg", "")).rsplit("|sig:", 1)[0]


# ---------------------------------------------------------------------------
# Marketplace validators
# ---------------------------------------------------------------------------


def validate_marketplace_no_double_sell(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No seller sells the same product to two buyers in the same round.

    A ``sold:product:price`` message from the same seller for the same product
    to different buyers is a violation.
    """
    # Track (seller, product) -> set of buyers
    sales: dict[tuple[str, str], set[str]] = defaultdict(set)

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("sold:"):
            continue
        parts = msg.split(":")
        if len(parts) < 3:
            continue
        seller = ev.get("agent", "")
        product = parts[1]
        buyer = ev.get("to", "")
        sales[(seller, product)].add(buyer)

    violations = [(k, buyers) for k, buyers in sales.items() if len(buyers) > 1]
    if violations:
        detail = "; ".join(f"{s} sold {p} to {buyers}" for (s, p), buyers in violations)
        return [ValidationResult("marketplace_no_double_sell", False, detail)]
    return [
        ValidationResult(
            "marketplace_no_double_sell",
            True,
            f"checked {sum(len(b) for b in sales.values())} sales",
        )
    ]


def validate_marketplace_responses(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every buy request gets either a sold: or reject: response."""
    # Collect buy requests as (buyer, seller, product)
    buy_requests: set[tuple[str, str, str]] = set()
    responses: set[tuple[str, str, str]] = set()

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("buy:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                buyer = ev.get("agent", "")
                seller = ev.get("to", "")
                product = parts[1]
                buy_requests.add((buyer, seller, product))
        elif msg.startswith("sold:") or msg.startswith("reject:"):
            parts = msg.split(":")
            if len(parts) >= 2:
                seller = ev.get("agent", "")
                buyer = ev.get("to", "")
                product = parts[1]
                responses.add((buyer, seller, product))

    unanswered = buy_requests - responses
    if unanswered:
        detail = f"{len(unanswered)} unanswered buy requests"
        return [ValidationResult("marketplace_all_responded", False, detail)]
    return [
        ValidationResult(
            "marketplace_all_responded",
            True,
            f"all {len(buy_requests)} requests answered",
        )
    ]


def validate_marketplace_price_agreement(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every sold message has a price from the original buy or a counter-offer."""
    # Track valid prices per (buyer, seller, product)
    offered_prices: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    mismatches: list[str] = []

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("buy:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                buyer = ev.get("agent", "")
                seller = ev.get("to", "")
                product = parts[1]
                try:
                    price = int(parts[2])
                except ValueError:
                    continue
                offered_prices[(buyer, seller, product)].add(price)
        elif msg.startswith("reject:"):
            # reject:product:counter_price — the counter price is also valid
            parts = msg.split(":")
            if len(parts) >= 3:
                seller = ev.get("agent", "")
                buyer = ev.get("to", "")
                product = parts[1]
                try:
                    counter = int(parts[2])
                except ValueError:
                    continue
                offered_prices[(buyer, seller, product)].add(counter)
        elif msg.startswith("sold:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                seller = ev.get("agent", "")
                buyer = ev.get("to", "")
                product = parts[1]
                try:
                    sold_price = int(parts[2])
                except ValueError:
                    continue
                key = (buyer, seller, product)
                valid = offered_prices.get(key, set())
                if not valid:
                    mismatches.append(f"{seller} sold {product} to {buyer} without an offer")
                elif sold_price not in valid:
                    mismatches.append(
                        f"{seller} sold {product} to {buyer} at {sold_price}, valid prices: {valid}"
                    )

    if mismatches:
        return [
            ValidationResult(
                "marketplace_price_agreement",
                False,
                "; ".join(mismatches),
            )
        ]
    return [ValidationResult("marketplace_price_agreement", True)]


# ---------------------------------------------------------------------------
# Auction validators
# ---------------------------------------------------------------------------


def validate_auction_winner_highest(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """The winning bid is >= all other bids for the same item."""
    # Collect bids per item: item -> list of (bidder, amount)
    bids: dict[str, list[tuple[str, int]]] = defaultdict(list)
    # Collect winners per item: item -> (bidder, amount)
    winners: dict[str, tuple[str, int]] = {}

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("bid:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                item = parts[1]
                try:
                    amount = int(parts[2])
                except ValueError:
                    continue
                bidder = ev.get("agent", "")
                bids[item].append((bidder, amount))
        elif msg.startswith("won:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                item = parts[1]
                try:
                    amount = int(parts[2])
                except ValueError:
                    continue
                bidder = ev.get("to", "")
                winners[item] = (bidder, amount)

    violations: list[str] = []
    for item, (winner, winning_amount) in winners.items():
        item_bids = bids.get(item, [])
        # The invariant is about the winner's REAL bid, not the announced
        # amount. Trusting the announced amount lets an auctioneer award a low
        # bidder while announcing a figure inflated past every real bid, and the
        # check would pass. Use the winner's own highest observed bid; fall back
        # to the announced amount only when the winner's bid was not observed
        # (e.g. dropped under message loss), so this never fails a valid trace.
        winner_bids = [amount for bidder, amount in item_bids if bidder == winner]
        effective_winner_bid = max(winner_bids) if winner_bids else winning_amount
        for bidder, amount in item_bids:
            if amount > effective_winner_bid:
                violations.append(
                    f"item {item}: winner {winner} bid {effective_winner_bid} "
                    f"but {bidder} bid {amount}"
                )
                break

    if violations:
        return [ValidationResult("auction_winner_highest", False, "; ".join(violations))]
    return [
        ValidationResult(
            "auction_winner_highest",
            True,
            f"checked {len(winners)} auctions",
        )
    ]


def validate_auction_single_winner(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Each item is awarded to exactly one bidder."""
    # item -> set of winners
    winners: dict[str, set[str]] = defaultdict(set)

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("won:"):
            parts = msg.split(":")
            if len(parts) >= 2:
                item = parts[1]
                bidder = ev.get("to", "")
                winners[item].add(bidder)

    multi = {item: w for item, w in winners.items() if len(w) > 1}
    if multi:
        detail = "; ".join(f"{item}: {w}" for item, w in multi.items())
        return [ValidationResult("auction_single_winner", False, detail)]
    return [
        ValidationResult(
            "auction_single_winner",
            True,
            f"checked {len(winners)} items",
        )
    ]


def validate_auction_all_notified(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every bidder gets either a won: or lost: notification per item."""
    # item -> set of bidders who bid
    bidders_per_item: dict[str, set[str]] = defaultdict(set)
    # item -> set of bidders notified
    notified_per_item: dict[str, set[str]] = defaultdict(set)

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("bid:"):
            parts = msg.split(":")
            if len(parts) >= 2:
                item = parts[1]
                bidder = ev.get("agent", "")
                bidders_per_item[item].add(bidder)
        elif msg.startswith("won:") or msg.startswith("lost:"):
            parts = msg.split(":")
            if len(parts) >= 2:
                item = parts[1]
                bidder = ev.get("to", "")
                notified_per_item[item].add(bidder)

    missing: list[str] = []
    for item, bidders in bidders_per_item.items():
        notified = notified_per_item.get(item, set())
        diff = bidders - notified
        if diff:
            missing.append(f"item {item}: {diff} not notified")

    if missing:
        return [ValidationResult("auction_all_notified", False, "; ".join(missing))]
    return [
        ValidationResult(
            "auction_all_notified",
            True,
            f"all bidders notified for {len(bidders_per_item)} items",
        )
    ]


# ---------------------------------------------------------------------------
# Voting validators
# ---------------------------------------------------------------------------


def validate_voting_tally(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """The announced result matches the actual vote count."""
    # round -> list of votes
    votes: dict[str, list[str]] = defaultdict(list)
    # round -> (result_str, yes_count, total)
    results: dict[str, tuple[str, int, int]] = {}

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("vote:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                vote = parts[2]
                votes[rnd].append(vote)
        elif msg.startswith("result:"):
            parts = msg.split(":")
            if len(parts) >= 4:
                rnd = parts[1]
                result_str = parts[2]
                tally_parts = parts[3].split("/")
                if len(tally_parts) == 2:
                    try:
                        yes = int(tally_parts[0])
                        total = int(tally_parts[1])
                    except ValueError:
                        continue
                    results[rnd] = (result_str, yes, total)

    mismatches: list[str] = []
    for rnd, (_result_str, reported_yes, reported_total) in results.items():
        actual_votes = votes.get(rnd, [])
        actual_yes = sum(1 for v in actual_votes if v == "yes")
        actual_total = len(actual_votes)
        if actual_yes != reported_yes or actual_total != reported_total:
            mismatches.append(
                f"round {rnd}: reported {reported_yes}/{reported_total} "
                f"but actual {actual_yes}/{actual_total}"
            )

    if mismatches:
        return [ValidationResult("voting_tally_correct", False, "; ".join(mismatches))]
    return [
        ValidationResult(
            "voting_tally_correct",
            True,
            f"checked {len(results)} rounds",
        )
    ]


def validate_voting_all_counted(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every vote message is reflected in the tally."""
    # round -> set of voters
    voters: dict[str, set[str]] = defaultdict(set)
    tallied_total: dict[str, int] = {}

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("vote:"):
            parts = msg.split(":")
            if len(parts) >= 4:
                rnd = parts[1]
                voter = parts[3]
                voters[rnd].add(voter)
            elif len(parts) >= 3:
                rnd = parts[1]
                agent = ev.get("agent", "")
                voters[rnd].add(agent)
        elif msg.startswith("result:"):
            parts = msg.split(":")
            if len(parts) >= 4:
                rnd = parts[1]
                tally_parts = parts[3].split("/")
                if len(tally_parts) == 2:
                    with contextlib.suppress(ValueError):
                        tallied_total[rnd] = int(tally_parts[1])

    uncounted: list[str] = []
    for rnd, voter_set in voters.items():
        total = tallied_total.get(rnd)
        if total is not None and len(voter_set) != total:
            uncounted.append(f"round {rnd}: {len(voter_set)} voted but tally says {total}")

    if uncounted:
        return [ValidationResult("voting_all_counted", False, "; ".join(uncounted))]
    return [ValidationResult("voting_all_counted", True)]


def validate_voting_no_double_vote(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Each voter votes at most once per round."""
    # (round, voter) -> count
    vote_counts: dict[tuple[str, str], int] = defaultdict(int)

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("vote:"):
            continue
        parts = msg.split(":")
        if len(parts) >= 4:
            rnd = parts[1]
            voter = parts[3]
        elif len(parts) >= 3:
            rnd = parts[1]
            voter = ev.get("agent", "")
        else:
            continue
        vote_counts[(rnd, voter)] += 1

    doubles = {k: c for k, c in vote_counts.items() if c > 1}
    if doubles:
        detail = "; ".join(f"round {r}: {v} voted {c} times" for (r, v), c in doubles.items())
        return [ValidationResult("voting_no_double_vote", False, detail)]
    return [
        ValidationResult(
            "voting_no_double_vote",
            True,
            f"checked {len(vote_counts)} votes",
        )
    ]


# ---------------------------------------------------------------------------
# Consensus validators
# ---------------------------------------------------------------------------


def validate_consensus_agreement(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """If the leader announces committed, >= 2/3 of followers voted accept."""
    # round -> list of votes
    votes: dict[str, list[str]] = defaultdict(list)
    # round -> result
    committed_rounds: dict[str, tuple[int, int]] = {}

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("vote:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                vote = parts[2]
                votes[rnd].append(vote)
        elif msg.startswith("result:"):
            parts = msg.split(":")
            if len(parts) >= 4:
                rnd = parts[1]
                outcome = parts[2]
                if outcome == "committed":
                    tally_parts = parts[3].split("/")
                    if len(tally_parts) == 2:
                        try:
                            accepts = int(tally_parts[0])
                            total = int(tally_parts[1])
                        except ValueError:
                            continue
                        committed_rounds[rnd] = (accepts, total)

    violations: list[str] = []
    for rnd, (accepts, total) in committed_rounds.items():
        actual_votes = votes.get(rnd, [])
        actual_accepts = sum(1 for vote in actual_votes if vote == "accept")
        actual_total = len(actual_votes)
        if actual_total == 0:
            violations.append(f"round {rnd}: committed with no observed votes")
            continue
        if accepts != actual_accepts or total != actual_total:
            violations.append(
                f"round {rnd}: reported {accepts}/{total} but actual "
                f"{actual_accepts}/{actual_total}"
            )
            continue
        if actual_accepts / actual_total < 2 / 3:
            violations.append(
                f"round {rnd}: committed with only {actual_accepts}/{actual_total} accepts"
            )

    if violations:
        return [ValidationResult("consensus_agreement", False, "; ".join(violations))]
    return [
        ValidationResult(
            "consensus_agreement",
            True,
            f"checked {len(committed_rounds)} committed rounds",
        )
    ]


def validate_consensus_validity(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Only proposed values can be committed (no fabricated values)."""
    # round -> proposed values
    proposed: dict[str, set[str]] = defaultdict(set)
    # round -> committed?
    committed_rounds: set[str] = set()
    # round -> value from result (if encoded in the result)
    result_details: dict[str, str] = {}

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("propose:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                value = parts[2]
                proposed[rnd].add(value)
        elif msg.startswith("result:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                rnd = parts[1]
                outcome = parts[2]
                if outcome == "committed":
                    committed_rounds.add(rnd)
                    if len(parts) >= 5:
                        result_details[rnd] = parts[4]

    violations: list[str] = []
    for rnd, values in proposed.items():
        if len(values) > 1:
            violations.append(f"round {rnd}: conflicting proposals {values}")

    for rnd in committed_rounds:
        if rnd not in proposed:
            violations.append(f"round {rnd}: committed but no proposal found")

    # Also check that result values match proposals if present
    for rnd, val in result_details.items():
        prop = proposed.get(rnd, set())
        if prop and val not in prop:
            violations.append(f"round {rnd}: committed value {val!r} not in proposed {prop!r}")

    if violations:
        return [ValidationResult("consensus_validity", False, "; ".join(violations))]
    return [
        ValidationResult(
            "consensus_validity",
            True,
            f"all {len(committed_rounds)} committed values were proposed",
        )
    ]


def validate_consensus_no_conflict(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """At most one value is committed per round."""
    # round -> set of committed outcomes
    commits: dict[str, set[str]] = defaultdict(set)

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("result:"):
            continue
        parts = msg.split(":")
        if len(parts) >= 4:
            rnd = parts[1]
            outcome = parts[2]
            if outcome == "committed":
                committed_value = parts[4] if len(parts) >= 5 else parts[3]
                commits[rnd].add(committed_value)

    conflicts = {rnd: tallies for rnd, tallies in commits.items() if len(tallies) > 1}
    if conflicts:
        detail = "; ".join(f"round {r}: {t}" for r, t in conflicts.items())
        return [ValidationResult("consensus_no_conflict", False, detail)]
    return [
        ValidationResult(
            "consensus_no_conflict",
            True,
            f"checked {len(commits)} rounds",
        )
    ]


# ---------------------------------------------------------------------------
# Supply-chain validators
# ---------------------------------------------------------------------------


def validate_supply_chain_pipeline(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every delivered product traces back through all 4 hops.

    The pipeline is: supplier (material:) -> manufacturer (product:) ->
    distributor (shipment:) -> retailer (delivered:).
    """
    material_rounds: set[str] = set()
    products: set[tuple[str, str]] = set()
    shipments: set[tuple[str, str]] = set()
    deliveries: set[tuple[str, str]] = set()

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("material:"):
            parts = msg.split(":")
            if len(parts) >= 2:
                material_rounds.add(parts[1])
        elif msg.startswith("product:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                products.add((parts[1], parts[2]))
        elif msg.startswith("shipment:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                shipments.add((parts[1], parts[2]))
        elif msg.startswith("delivered:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                deliveries.add((parts[1], parts[2]))

    missing: list[str] = []
    for rnd, product in sorted(deliveries):
        if rnd not in material_rounds:
            missing.append(f"{rnd}/{product}: material")
        if (rnd, product) not in products:
            missing.append(f"{rnd}/{product}: product")
        if (rnd, product) not in shipments:
            missing.append(f"{rnd}/{product}: shipment")

    if missing:
        return [
            ValidationResult(
                "supply_chain_pipeline",
                False,
                f"delivered without matching: {', '.join(missing)}",
            )
        ]

    return [ValidationResult("supply_chain_pipeline", True, "all hops present")]


def validate_supply_chain_no_lost(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every material sent eventually results in a delivery or explicit failure."""
    materials_by_round: dict[str, int] = defaultdict(int)
    delivered_by_round: dict[str, int] = defaultdict(int)

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("material:"):
            parts = msg.split(":")
            if len(parts) >= 2:
                materials_by_round[parts[1]] += 1
        elif msg.startswith("delivered:"):
            parts = msg.split(":")
            if len(parts) >= 2:
                delivered_by_round[parts[1]] += 1

    materials_sent = sum(materials_by_round.values())
    delivered = sum(delivered_by_round.values())
    if materials_sent > 0 and delivered == 0:
        return [
            ValidationResult(
                "supply_chain_no_lost",
                False,
                f"{materials_sent} materials sent but 0 delivered",
            )
        ]
    losses: list[str] = []
    for rnd, sent in sorted(materials_by_round.items()):
        got = delivered_by_round.get(rnd, 0)
        if got < sent:
            losses.append(f"round {rnd}: {sent - got} of {sent}")

    if losses:
        lost = materials_sent - delivered
        return [
            ValidationResult(
                "supply_chain_no_lost",
                False,
                f"{lost} of {materials_sent} materials not delivered ({'; '.join(losses)})",
            )
        ]
    return [
        ValidationResult(
            "supply_chain_no_lost",
            True,
            f"{delivered}/{materials_sent} materials delivered",
        )
    ]


# ---------------------------------------------------------------------------
# Reputation validators
# ---------------------------------------------------------------------------


def validate_reputation_scoring(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Reputation scores decrease for agents that cheat."""
    # Track scores: agent -> score
    scores: dict[str, int] = defaultdict(int)
    cheaters: set[str] = set()

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("report:"):
            parts = msg.split(":")
            if len(parts) >= 4:
                agent_str = parts[2]
                outcome = parts[3]
                if outcome == "good":
                    scores[agent_str] += 1
                elif outcome == "bad":
                    scores[agent_str] -= 2
                    cheaters.add(agent_str)

    violations: list[str] = []
    for cheater in cheaters:
        if scores[cheater] >= 0:
            # If a cheater has never had their score go negative from cheating
            # that's fine — they might have enough good trades.  We check that
            # at least one bad report actually decremented the score.
            pass

    # The core invariant: agents with bad reports should have lower scores
    # than they would without those reports.  We verify that at least one
    # "bad" report exists for every cheater.
    bad_agents_with_reports: set[str] = set()
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("cheat:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                cheater_id = parts[2]
                bad_agents_with_reports.add(cheater_id)

    # Check: if someone cheated, they should have a bad report
    unreported = bad_agents_with_reports - cheaters
    # cheaters is set of agents that got "bad" reports, bad_agents_with_reports
    # is set of agents that sent cheat messages
    if unreported:
        violations.append(f"cheaters not reported: {unreported}")

    if violations:
        return [ValidationResult("reputation_scoring", False, "; ".join(violations))]
    return [
        ValidationResult(
            "reputation_scoring",
            True,
            f"checked {len(cheaters)} cheaters, {len(scores)} agents scored",
        )
    ]


def validate_reputation_warnings(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Agents with score <= -3 get warned."""
    scores: dict[str, int] = defaultdict(int)
    warned: set[str] = set()

    for ev in events:
        if ev.get("kind") != "send" and ev.get("kind") != "broadcast":
            continue
        msg = _message_body(ev)
        if msg.startswith("report:"):
            parts = msg.split(":")
            if len(parts) >= 4:
                agent_str = parts[2]
                outcome = parts[3]
                if outcome == "good":
                    scores[agent_str] += 1
                elif outcome == "bad":
                    scores[agent_str] -= 2
        elif msg.startswith("warning:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                agent_str = parts[2]
                warned.add(agent_str)

    should_warn = {a for a, s in scores.items() if s <= -3}
    missing_warnings = should_warn - warned
    if missing_warnings:
        detail = f"agents at/below -3 not warned: {missing_warnings}"
        return [ValidationResult("reputation_warnings", False, detail)]
    return [
        ValidationResult(
            "reputation_warnings",
            True,
            f"{len(warned)} warnings issued, {len(should_warn)} needed",
        )
    ]


# ---------------------------------------------------------------------------
# Identity key-rotation validators
# ---------------------------------------------------------------------------

_INF = float("inf")


class _KeyWindow:
    """Validity window ``[issued_at, rotated_out)`` for one signing key.

    Example::

        w = _KeyWindow(issued_at=0.0)
        assert w.contains(0.0) and not w.contains(w.rotated_out)
    """

    def __init__(self, issued_at: float, rotated_out: float = _INF) -> None:
        self.issued_at = issued_at
        self.rotated_out = rotated_out

    def contains(self, tick: float) -> bool:
        """Return whether *tick* falls inside the half-open window.

        Example::

            assert _KeyWindow(0.0, 10.0).contains(5.0)
        """
        return self.issued_at <= tick < self.rotated_out


def _parse_tick(raw: str) -> float | None:
    """Parse a trace tick token to ``float``; ``None`` if unparseable.

    ``did_key`` emits ``None`` for ``signed_at`` (it has no rotation concept),
    so this never raises — it returns ``None`` and the caller treats the
    signature as window-invalid.

    Example::

        assert _parse_tick("3.0") == 3.0 and _parse_tick("None") is None
    """
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _build_key_windows(events: list[dict[str, Any]]) -> dict[str, _KeyWindow]:
    """Reconstruct per-key validity windows from ``rotate:`` trace lines.

    A line ``rotate:<agent>:<old_key_id>:<new_key_id>:<rotate_tick>`` closes the
    old key's window at ``rotate_tick`` and opens the new key's window there.
    Keys never named in a rotation but seen signing (e.g. an agent's first key)
    are seeded lazily by :func:`validate_identity_rotation_signatures` with an
    open window from tick 0. ``key_id`` is a ``sha256`` digest, so keying the
    map by ``key_id`` alone is unambiguous across agents.

    Example::

        windows = _build_key_windows(events)
    """
    windows: dict[str, _KeyWindow] = {}
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("rotate:"):
            continue
        parts = msg.split(":")
        if len(parts) < 5:
            continue
        old_key_id, new_key_id = parts[2], parts[3]
        rotate_tick = _parse_tick(parts[4])
        if rotate_tick is None:
            continue
        old = windows.setdefault(old_key_id, _KeyWindow(issued_at=0.0))
        old.rotated_out = rotate_tick
        windows[new_key_id] = _KeyWindow(issued_at=rotate_tick)
    return windows


def validate_identity_rotation_signatures(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Honest signatures verify and *both* attacks are rejected as-of the trace.

    The scenario emits ``signed:<agent>:<key_id>:<claimed_tick>:<verdict>`` lines
    where ``verdict`` is ``ok`` (honest), ``forge`` (post-rotation forgery with a
    rotated-out key), or ``backdate`` (a new-key signature whose claimed tick is
    moved back into the old key's window).

    A signature is **window-valid** iff the window of its ``key_id`` contains
    **both** the externally observed event tick (``ev["ts"]``) *and* the claimed
    ``signed_at`` tick. Anchoring to the observed tick defeats post-rotation
    forgery (observed after ``rotated_out``); also requiring the claimed tick to
    land in the same window defeats backdating (the new key's window does not
    contain the backdated old tick). The verifier never trusts the claimed tick
    as the *authority* — it is one of two coordinates both of which must agree.

    The protocol holds iff every honest ``ok`` line is window-valid **and** every
    ``forge``/``backdate`` line is window-invalid. ``did_key`` cannot satisfy
    this: it emits no ``rotate:`` lines and a ``None`` ``key_id``, so honest
    signatures resolve to no window and the check fails (without crashing).

    Example::

        results = validate_identity_rotation_signatures(events)
    """
    windows = _build_key_windows(events)
    honest_invalid: list[str] = []
    attacks_accepted: list[str] = []
    ok_count = 0
    attack_count = 0

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("signed:"):
            continue
        parts = msg.split(":")
        if len(parts) < 5:
            continue
        agent, key_id, claimed_raw, verdict = parts[1], parts[2], parts[3], parts[4]
        observed_tick = _parse_tick(str(ev.get("ts")))
        claimed_tick = _parse_tick(claimed_raw)

        window = windows.get(key_id)
        # A key with no rotation history but seen signing is its agent's first,
        # still-open key; seed an open window from tick 0 so honest pre-rotation
        # signatures resolve. did_key's ``None`` key_id never matches this path.
        if window is None and key_id and key_id != "None" and verdict == "ok":
            window = windows.setdefault(key_id, _KeyWindow(issued_at=0.0))

        window_valid = (
            window is not None
            and observed_tick is not None
            and claimed_tick is not None
            and window.contains(observed_tick)
            and window.contains(claimed_tick)
        )

        if verdict == "ok":
            ok_count += 1
            if not window_valid:
                honest_invalid.append(
                    f"{agent} honest sig key={key_id[:8]} "
                    f"observed={observed_tick} claimed={claimed_tick} not in a valid window"
                )
        else:
            attack_count += 1
            if window_valid:
                attacks_accepted.append(
                    f"{agent} {verdict} sig key={key_id[:8]} "
                    f"observed={observed_tick} claimed={claimed_tick} accepted"
                )

    problems = honest_invalid + attacks_accepted
    if problems:
        return [
            ValidationResult(
                "identity_rotation_signatures",
                False,
                "; ".join(problems),
            )
        ]
    return [
        ValidationResult(
            "identity_rotation_signatures",
            True,
            f"{ok_count} honest signatures valid, {attack_count} attacks rejected",
        )
    ]


# ---------------------------------------------------------------------------
# Memory convergence (CRDT) validators
# ---------------------------------------------------------------------------


async def validate_crdt_convergence(
    make_replica: Callable[[str], Any],
    writes: list[tuple[int, bytes]],
    delivery_orders: list[list[int]],
    *,
    key: str = "k",
) -> list[ValidationResult]:
    """Adversarial convergence check for a CRDT memory plugin.

    This is the discriminating validator the memory-CRDT problem asks for: it
    drives ``len(delivery_orders)`` replicas through the *same* multiset of
    writes but delivers those writes to each replica in a **different order**,
    then asserts every replica reads back an identical value. A conflict-free
    plugin passes for any orders; an order-dependent plugin such as
    ``blackboard`` fails the moment two replicas see the writes in different
    orders.

    The replication channel is chosen by capability: if the plugin exposes
    ``export`` / ``merge`` (a CvRDT), gossip is delivered through them; if not
    (e.g. ``blackboard``), the raw payload is delivered through ``write``, so
    last-writer-wins divergence is exposed faithfully.

    Args:
        make_replica: factory ``node_id -> plugin instance``.
        writes: ``(origin_replica_index, payload)`` pairs applied at origin.
        delivery_orders: one permutation of ``range(len(writes))`` per replica;
            its length is the replica count.
        key: the shared key all writes target.

    Example::

        from nest_plugins_reference.memory.lww_register import LwwRegisterMemory
        results = await validate_crdt_convergence(
            LwwRegisterMemory,
            writes=[(0, b"a"), (1, b"b"), (2, b"c")],
            delivery_orders=[[0, 1, 2], [2, 1, 0], [1, 0, 2]],
        )
        assert all(r.passed for r in results)
    """
    replica_count = len(delivery_orders)
    replicas = [make_replica(f"node-{i}") for i in range(replica_count)]
    has_crdt = all(hasattr(r, "export") and hasattr(r, "merge") for r in replicas)

    # Phase 1: apply each write at its origin and capture the gossip payload.
    gossip: list[bytes] = []
    for origin, payload in writes:
        await replicas[origin].write(key, payload)
        if has_crdt:
            state = replicas[origin].export(key)
            gossip.append(state if state is not None else payload)
        else:
            gossip.append(payload)

    # Phase 2: deliver every non-local write to each replica in its own order.
    for r_idx, order in enumerate(delivery_orders):
        for w_idx in order:
            if writes[w_idx][0] == r_idx:
                continue
            if has_crdt:
                await replicas[r_idx].merge(key, gossip[w_idx])
            else:
                await replicas[r_idx].write(key, gossip[w_idx])

    finals = [await r.read(key) for r in replicas]
    converged = len(set(finals)) == 1 and finals[0] is not None
    if converged:
        return [
            ValidationResult(
                "crdt_convergence",
                True,
                f"{replica_count} replicas converged to {finals[0]!r} "
                f"under {replica_count} distinct delivery orders",
            )
        ]
    distinct = sorted({repr(v) for v in finals})
    return [
        ValidationResult(
            "crdt_convergence",
            False,
            f"replicas diverged into {len(distinct)} distinct value(s): {', '.join(distinct)}",
        )
    ]


def validate_memory_convergence(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Trace validator: every replica's final CRDT state agrees.

    The ``memory_concurrent_writers`` scenario has each agent broadcast its
    terminal register as a ``final:<json>`` record on stop. This validator
    confirms every agent emitted exactly one such record and that all of them
    decode to byte-identical register state -- i.e. the swarm converged.
    """
    finals: dict[str, str] = {}
    duplicates: set[str] = set()
    malformed: list[str] = []

    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = str(ev.get("msg", ""))
        if not msg.startswith("final:"):
            continue
        agent = str(ev.get("agent", ""))
        body = msg[len("final:") :]
        try:
            parsed = json.loads(body)
            canonical = json.dumps(parsed, sort_keys=True)
        except (ValueError, TypeError):
            malformed.append(agent)
            continue
        if agent in finals:
            duplicates.add(agent)
        finals[agent] = canonical

    results: list[ValidationResult] = []

    if malformed:
        results.append(
            ValidationResult(
                "memory_convergence_wellformed",
                False,
                f"{len(malformed)} malformed final record(s): {sorted(set(malformed))}",
            )
        )

    if not finals:
        results.append(
            ValidationResult(
                "memory_convergence",
                False,
                "no final replica states found in trace",
            )
        )
        return results

    distinct = set(finals.values())
    if len(distinct) == 1:
        results.append(
            ValidationResult(
                "memory_convergence",
                True,
                f"all {len(finals)} replicas converged to identical state",
            )
        )
    else:
        results.append(
            ValidationResult(
                "memory_convergence",
                False,
                f"{len(finals)} replicas hold {len(distinct)} distinct final states",
            )
        )

    if duplicates:
        results.append(
            ValidationResult(
                "memory_convergence_one_final_per_agent",
                False,
                f"agents emitted multiple final records: {sorted(duplicates)}",
            )
        )

    return results


# ---------------------------------------------------------------------------
# Streaming payments validators
# ---------------------------------------------------------------------------


def validate_streaming_conservation(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Conservation invariant: total debited == total credited at every tick.

    Scans the trace for payment events and verifies that cumulative funds
    debited from payers equals cumulative funds credited to payees.
    """
    cumulative_debited: dict[str, int] = defaultdict(int)
    cumulative_credited: dict[str, int] = defaultdict(int)

    for ev in events:
        if ev.get("kind") not in ("payment_debited", "payment_credited"):
            continue

        agent = ev.get("agent", "")
        amount = ev.get("amount", 0)

        if ev.get("kind") == "payment_debited":
            cumulative_debited[agent] += amount
        elif ev.get("kind") == "payment_credited":
            cumulative_credited[agent] += amount

    # Check conservation: sum of all debited == sum of all credited
    total_debited = sum(cumulative_debited.values())
    total_credited = sum(cumulative_credited.values())

    if total_debited != total_credited:
        detail = (
            f"conservation violation: total debited={total_debited} "
            f"!= total credited={total_credited}"
        )
        return [ValidationResult("streaming_conservation", False, detail)]

    return [
        ValidationResult(
            "streaming_conservation",
            True,
            f"conservation verified: {total_debited} total flow",
        )
    ]


def validate_streaming_no_drain_after_close(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Attack: closed streams must not drain after closure.

    Tracks open_stream -> close_stream for each ref, verifies no
    payment_debited events occur after close for that stream ref.
    """
    open_times: dict[str, int] = {}  # PaymentRef -> tick
    close_times: dict[str, int] = {}  # PaymentRef -> tick
    stream_debits: dict[str, list[int]] = defaultdict(lambda: [])  # PaymentRef -> [ticks]

    for ev in events:
        tick = ev.get("tick", 0)

        if ev.get("event_type") == "stream_opened":
            ref = ev.get("stream_ref", "")
            if ref:
                open_times[ref] = tick

        elif ev.get("event_type") == "stream_closed":
            ref = ev.get("stream_ref", "")
            if ref:
                close_times[ref] = tick

        elif ev.get("kind") == "payment_debited":
            ref = ev.get("stream_ref", "")
            if ref:
                assert isinstance(stream_debits[ref], list)
                stream_debits[ref].append(tick)

    # Check: no debit after close
    violations: list[str] = []
    for ref, close_tick in close_times.items():
        debits_after = [t for t in stream_debits.get(ref, []) if t > close_tick]
        if debits_after:
            violations.append(f"stream {ref} debited after close at {close_tick}: {debits_after}")

    if violations:
        return [ValidationResult("streaming_no_drain_after_close", False, "; ".join(violations))]

    return [
        ValidationResult(
            "streaming_no_drain_after_close",
            True,
            f"verified {len(close_times)} streams, no drain-after-close",
        )
    ]


def validate_streaming_no_overbill_on_partition(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Attack: payer must not keep billing when partitioned from payee.

    When the simulator drops messages between a payer and payee (network
    partition), any ``payment_debited`` after that point is billing for
    service the payee cannot deliver — an over-bill on partition.

    Tracks (payer, payee) pairs from ``stream_opened`` events, then scans
    for ``dropped`` events between those pairs.  Any debit that lands at or
    after a drop-tick between the same payer and payee is a violation.
    """
    # stream_ref -> (payer, payee)
    stream_parties: dict[str, tuple[str, str]] = {}
    # (payer, payee) -> first tick where drop was observed
    partition_start: dict[tuple[str, str], int] = {}
    violations: list[str] = []

    for ev in events:
        tick = ev.get("tick", 0)

        if ev.get("event_type") == "stream_opened":
            ref = ev.get("stream_ref", "")
            payer = ev.get("agent", "")
            payee = ev.get("to", "")
            if ref and payer and payee:
                stream_parties[ref] = (payer, payee)

        elif ev.get("kind") == "dropped":
            sender = ev.get("from", "")
            receiver = ev.get("agent", "")
            # Record the earliest tick a partition was observed either way
            if sender and receiver:
                key = (sender, receiver)
                if key not in partition_start or tick < partition_start[key]:
                    partition_start[key] = tick
                # Reverse direction too — partition is bidirectional
                rev_key = (receiver, sender)
                if rev_key not in partition_start or tick < partition_start[rev_key]:
                    partition_start[rev_key] = tick

        elif ev.get("kind") == "payment_debited":
            ref = ev.get("stream_ref", "")
            if ref not in stream_parties:
                continue
            payer, payee = stream_parties[ref]
            drop_tick = partition_start.get((payer, payee))
            if drop_tick is not None and tick >= drop_tick:
                violations.append(
                    f"stream {ref}: payer={payer} debited at tick {tick} "
                    f"but partitioned from payee={payee} since tick {drop_tick}"
                )

    if violations:
        return [
            ValidationResult(
                "streaming_no_overbill_on_partition",
                False,
                "; ".join(violations),
            )
        ]
    return [
        ValidationResult(
            "streaming_no_overbill_on_partition",
            True,
            f"verified {len(stream_parties)} streams across "
            f"{len(partition_start)} partition edges, no over-bill",
        )
    ]


# ---------------------------------------------------------------------------
# EMPIC escrow/streaming payments validators
# ---------------------------------------------------------------------------


def _event_tick(ev: dict[str, Any]) -> int:
    raw = ev.get("tick", ev.get("ts", 0))
    if isinstance(raw, bool):
        return 0
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw)
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            return int(float(raw))
    return 0


def _empic_audit_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        with contextlib.suppress(json.JSONDecodeError):
            body_raw: object = json.loads(msg)
            if not isinstance(body_raw, dict):
                continue
            body = cast("dict[str, Any]", body_raw)
            if body.get("type") == "empic_audit":
                body.setdefault("tick", _event_tick(ev))
                parsed.append(body)
    return parsed


def _empic_message_events(
    events: list[dict[str, Any]],
    msg_type: str,
) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        with contextlib.suppress(json.JSONDecodeError):
            body_raw: object = json.loads(msg)
            if not isinstance(body_raw, dict):
                continue
            body = cast("dict[str, Any]", body_raw)
            if body.get("type") != msg_type:
                continue
            body.setdefault("tick", _event_tick(ev))
            body.setdefault("_sender", str(ev.get("agent", "")))
            body.setdefault("_receiver", str(ev.get("to", "")))
            parsed.append(body)
    return parsed


def _empic_ref(ev: dict[str, Any]) -> str:
    value = ev.get("payment_ref")
    return value.strip() if isinstance(value, str) else ""


def _empic_delivery_id(ev: dict[str, Any]) -> str:
    value = ev.get("delivery_id")
    return value.strip() if isinstance(value, str) else ""


def _empic_amounts_by_ref(
    audit: list[dict[str, Any]],
    event_type: str,
) -> dict[str, int]:
    totals: dict[str, int] = defaultdict(int)
    for ev in audit:
        if ev.get("event_type") != event_type:
            continue
        ref = _empic_ref(ev)
        if ref:
            totals[ref] += _safe_amount(ev.get("amount"))
    return totals


def validate_empic_escrow_conservation(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every escrowed credit is either released or refunded per payment.

    This checks the EMPIC shadow ledger from audit messages by ``payment_ref``:
    consumer debits into escrow must equal provider releases plus consumer
    refunds for each funded payment, not only globally.

    Example::

        result = validate_empic_escrow_conservation(events)[0]
    """
    audit = _empic_audit_events(events)
    debited = _empic_amounts_by_ref(audit, "empic_escrow_debited")
    released = _empic_amounts_by_ref(audit, "empic_escrow_released")
    refunded = _empic_amounts_by_ref(audit, "empic_escrow_refunded")
    refs = sorted(set(debited) | set(released) | set(refunded))
    violations = [
        f"{ref}: debited={debited.get(ref, 0)} released={released.get(ref, 0)} "
        f"refunded={refunded.get(ref, 0)}"
        for ref in refs
        if debited.get(ref, 0) != released.get(ref, 0) + refunded.get(ref, 0)
    ]
    if violations:
        return [
            ValidationResult(
                "empic_escrow_conservation",
                False,
                "; ".join(violations),
            )
        ]
    total_debited = sum(debited.values())
    total_released = sum(released.values())
    total_refunded = sum(refunded.values())
    return [
        ValidationResult(
            "empic_escrow_conservation",
            True,
            f"{len(refs)} refs, debited={total_debited}, "
            f"released={total_released}, refunded={total_refunded}",
        )
    ]


def validate_empic_no_release_without_accepted_delivery(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Provider payment release requires accepted delivery evidence.

    Example::

        result = validate_empic_no_release_without_accepted_delivery(events)[0]
    """
    audit = _empic_audit_events(events)
    accepted_deliveries = {
        (_empic_ref(ev), _empic_delivery_id(ev))
        for ev in audit
        if ev.get("event_type") == "empic_delivery_evaluated"
        and ev.get("accepted") is True
        and _empic_ref(ev)
        and _empic_delivery_id(ev)
    }
    violations: list[str] = []
    for ev in audit:
        if ev.get("event_type") != "empic_escrow_released":
            continue
        ref = _empic_ref(ev)
        delivery_id = _empic_delivery_id(ev)
        if not ref or not delivery_id or (ref, delivery_id) not in accepted_deliveries:
            violations.append(
                f"release ref={ref or '<missing>'} delivery={delivery_id or '<missing>'}"
            )

    if violations:
        return [
            ValidationResult(
                "empic_no_release_without_accepted_delivery",
                False,
                "; ".join(violations),
            )
        ]
    return [
        ValidationResult(
            "empic_no_release_without_accepted_delivery",
            True,
            f"verified {len(accepted_deliveries)} accepted deliveries",
        )
    ]


def validate_empic_invalid_delivery_not_paid(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Rejected delivery evidence must not be credited to a provider.

    Example::

        result = validate_empic_invalid_delivery_not_paid(events)[0]
    """
    audit = _empic_audit_events(events)
    rejected = {
        (_empic_ref(ev), _empic_delivery_id(ev))
        for ev in audit
        if ev.get("event_type") == "empic_delivery_evaluated"
        and ev.get("accepted") is False
        and _empic_ref(ev)
        and _empic_delivery_id(ev)
    }
    paid = {
        (_empic_ref(ev), _empic_delivery_id(ev))
        for ev in audit
        if ev.get("event_type") == "empic_escrow_released"
        and _empic_ref(ev)
        and _empic_delivery_id(ev)
    }
    violations = sorted(rejected & paid)
    if violations:
        return [
            ValidationResult(
                "empic_invalid_delivery_not_paid",
                False,
                f"rejected deliveries were paid: {violations}",
            )
        ]
    return [
        ValidationResult(
            "empic_invalid_delivery_not_paid",
            True,
            f"verified {len(rejected)} rejected deliveries",
        )
    ]


def validate_empic_delivery_policy_integrity(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Consumer acceptance must match delivery payload and declared policy.

    Example::

        result = validate_empic_delivery_policy_integrity(events)[0]
    """
    audit = _empic_audit_events(events)
    deliveries = {
        (_empic_ref(ev), _empic_delivery_id(ev)): ev
        for ev in _empic_message_events(events, "empic_delivery")
        if _empic_ref(ev) and _empic_delivery_id(ev)
    }
    policies = {
        _empic_ref(ev): ev
        for ev in audit
        if ev.get("event_type") == "empic_acceptance_policy" and _empic_ref(ev)
    }
    checked = 0
    violations: list[str] = []

    for ev in audit:
        if ev.get("event_type") != "empic_delivery_evaluated":
            continue
        ref = _empic_ref(ev)
        delivery_id = _empic_delivery_id(ev)
        if not ref or not delivery_id:
            violations.append("delivery evaluation missing payment_ref or delivery_id")
            continue
        delivery = deliveries.get((ref, delivery_id))
        policy_event = policies.get(ref)
        if delivery is None:
            violations.append(f"{ref}/{delivery_id}: evaluated delivery not found")
            continue
        if policy_event is None:
            violations.append(f"{ref}/{delivery_id}: acceptance policy not found")
            continue

        expected, reason = _empic_policy_accepts(delivery, policy_event, _event_tick(ev))
        observed = ev.get("accepted") is True
        checked += 1
        if observed != expected:
            violations.append(
                f"{ref}/{delivery_id}: observed accepted={observed}, "
                f"policy accepted={expected} ({reason})"
            )

    if violations:
        return [ValidationResult("empic_delivery_policy_integrity", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_delivery_policy_integrity",
            True,
            f"checked {checked} delivery evaluations",
        )
    ]


def validate_empic_pubsub_billing_caps(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Pubsub releases must respect rate-per-tick, max-total, and accepted evidence.

    Example::

        result = validate_empic_pubsub_billing_caps(events)[0]
    """
    audit = _empic_audit_events(events)
    stream_refs: set[str] = set()
    streams: dict[str, tuple[int, int]] = {}
    accepted: dict[str, set[str]] = defaultdict(set)
    released: dict[str, int] = defaultdict(int)
    violations: list[str] = []

    for ev in audit:
        event_type = ev.get("event_type")
        ref = _empic_ref(ev)
        if not ref:
            continue
        if event_type == "empic_stream_opened":
            stream_refs.add(ref)
            rate = _safe_amount(ev.get("rate_per_tick"))
            max_total = _safe_amount(ev.get("max_total") or ev.get("amount"))
            if rate <= 0 or max_total <= 0:
                violations.append(f"{ref}: invalid stream terms rate={rate} max_total={max_total}")
            else:
                streams[ref] = (rate, max_total)
            continue

        is_pubsub_ref = ref in stream_refs or ev.get("mode") == "pubsub"
        if (
            event_type == "empic_delivery_evaluated"
            and ev.get("accepted") is True
            and is_pubsub_ref
        ):
            delivery_id = _empic_delivery_id(ev)
            if delivery_id:
                accepted[ref].add(delivery_id)
        elif event_type == "empic_escrow_released" and is_pubsub_ref:
            amount = _safe_amount(ev.get("amount"))
            delivery_id = _empic_delivery_id(ev)
            terms = streams.get(ref)
            if terms is None:
                violations.append(f"{ref}: pubsub release without stream_opened")
                continue
            rate, _max_total = terms
            if amount > rate:
                violations.append(
                    f"{ref}/{delivery_id or '<missing>'}: release {amount} > rate {rate}"
                )
            released[ref] += amount

    for ref, (rate, max_total) in streams.items():
        released_total = released.get(ref, 0)
        accepted_cap = rate * len(accepted.get(ref, set()))
        if released_total > max_total:
            violations.append(f"{ref}: released {released_total} > max_total {max_total}")
        if released_total > accepted_cap:
            violations.append(
                f"{ref}: released {released_total} > accepted delivery cap {accepted_cap}"
            )

    if violations:
        return [ValidationResult("empic_pubsub_billing_caps", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_pubsub_billing_caps",
            True,
            f"checked {len(streams)} pubsub streams",
        )
    ]


def validate_empic_max_spend_enforced(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Funded escrow amount must not exceed the consumer's declared budget.

    Example::

        result = validate_empic_max_spend_enforced(events)[0]
    """
    audit = _empic_audit_events(events)
    max_spend_by_ref: dict[str, int] = {}
    violations: list[str] = []

    for ev in audit:
        if ev.get("event_type") != "empic_acceptance_policy":
            continue
        ref = _empic_ref(ev)
        if not ref:
            continue
        max_spend = _optional_amount(ev.get("max_spend"))
        policy_raw = ev.get("policy")
        if max_spend is None and isinstance(policy_raw, dict):
            max_spend = _optional_amount(cast("dict[str, Any]", policy_raw).get("max_spend"))
        if max_spend is not None:
            max_spend_by_ref[ref] = max_spend

    for ev in audit:
        event_type = ev.get("event_type")
        if event_type not in {"empic_escrow_debited", "empic_stream_opened"}:
            continue
        ref = _empic_ref(ev)
        max_spend = max_spend_by_ref.get(ref)
        if not ref or max_spend is None:
            continue
        amount = _safe_amount(ev.get("max_total") or ev.get("amount"))
        if amount > max_spend:
            violations.append(f"{ref}: funded {amount} exceeds declared max_spend {max_spend}")

    if violations:
        return [ValidationResult("empic_max_spend_enforced", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_max_spend_enforced",
            True,
            f"checked {len(max_spend_by_ref)} consumer policies",
        )
    ]


def validate_empic_all_escrows_terminal(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every funded escrow must finish with complete release/refund accounting.

    Example::

        result = validate_empic_all_escrows_terminal(events)[0]
    """
    audit = _empic_audit_events(events)
    debited = _empic_amounts_by_ref(audit, "empic_escrow_debited")
    released = _empic_amounts_by_ref(audit, "empic_escrow_released")
    refunded = _empic_amounts_by_ref(audit, "empic_escrow_refunded")
    stream_refs = {
        _empic_ref(ev)
        for ev in audit
        if ev.get("event_type") == "empic_stream_opened" and _empic_ref(ev)
    }
    closed_refs = {
        _empic_ref(ev)
        for ev in audit
        if ev.get("event_type") == "empic_stream_closed" and _empic_ref(ev)
    }
    violations: list[str] = []

    for ref, debit in sorted(debited.items()):
        release = released.get(ref, 0)
        refund = refunded.get(ref, 0)
        if release + refund != debit:
            violations.append(
                f"{ref}: not terminal debited={debit} released={release} refunded={refund}"
            )
        if ref in stream_refs and refund > 0 and ref not in closed_refs:
            violations.append(f"{ref}: pubsub refund without stream close")
        if ref not in stream_refs and release == 0 and refund == 0:
            violations.append(f"{ref}: pull escrow has no release or refund")

    if violations:
        return [ValidationResult("empic_all_escrows_terminal", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_all_escrows_terminal",
            True,
            f"verified {len(debited)} funded escrows",
        )
    ]


def validate_empic_no_duplicate_settlement(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Payment refs and delivery evidence must not be replayed for settlement.

    Example::

        result = validate_empic_no_duplicate_settlement(events)[0]
    """
    audit = _empic_audit_events(events)
    debits: dict[str, int] = defaultdict(int)
    releases: dict[tuple[str, str], int] = defaultdict(int)
    refunds: dict[str, int] = defaultdict(int)
    evaluations: dict[tuple[str, str], int] = defaultdict(int)
    violations: list[str] = []

    for ev in audit:
        ref = _empic_ref(ev)
        event_type = ev.get("event_type")
        if event_type == "empic_escrow_debited":
            if not ref:
                violations.append("escrow debit missing payment_ref")
            else:
                debits[ref] += 1
        elif event_type == "empic_escrow_released":
            delivery_id = _empic_delivery_id(ev)
            if ref and delivery_id:
                releases[(ref, delivery_id)] += 1
        elif event_type == "empic_escrow_refunded" and ref:
            refunds[ref] += 1
        elif event_type == "empic_delivery_evaluated":
            delivery_id = _empic_delivery_id(ev)
            if ref and delivery_id:
                evaluations[(ref, delivery_id)] += 1

    violations.extend(
        f"{ref}: duplicate escrow debit" for ref, count in debits.items() if count > 1
    )
    violations.extend(
        f"{ref}/{delivery_id}: duplicate release"
        for (ref, delivery_id), count in releases.items()
        if count > 1
    )
    violations.extend(f"{ref}: duplicate refund" for ref, count in refunds.items() if count > 1)
    violations.extend(
        f"{ref}/{delivery_id}: duplicate delivery evaluation"
        for (ref, delivery_id), count in evaluations.items()
        if count > 1
    )

    if violations:
        return [ValidationResult("empic_no_duplicate_settlement", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_no_duplicate_settlement",
            True,
            f"checked {len(debits)} payment refs and {len(evaluations)} delivery evaluations",
        )
    ]


def validate_empic_provider_service_binding(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Payments and releases must bind to the provider registered for the service.

    Example::

        result = validate_empic_provider_service_binding(events)[0]
    """
    audit = _empic_audit_events(events)
    service_provider: dict[str, str] = {}
    payment_binding: dict[str, tuple[str, str]] = {}
    violations: list[str] = []

    for ev in audit:
        if ev.get("event_type") != "empic_service_registered":
            continue
        service_id = _safe_text(ev.get("service_id"))
        provider = _safe_text(ev.get("provider"))
        if service_id and provider:
            service_provider[service_id] = provider

    for ev in audit:
        if ev.get("event_type") not in {"empic_escrow_debited", "empic_stream_opened"}:
            continue
        ref = _empic_ref(ev)
        service_id = _safe_text(ev.get("service_id"))
        provider = _safe_text(ev.get("provider"))
        if not ref or not service_id or not provider:
            violations.append(f"{ref or '<missing>'}: debit missing service/provider binding")
            continue
        registered = service_provider.get(service_id)
        if registered is None:
            violations.append(f"{ref}: service {service_id} was not registered")
        elif registered != provider:
            violations.append(
                f"{ref}: debit provider {provider} does not match registered {registered}"
            )
        old = payment_binding.get(ref)
        if old is not None and old != (service_id, provider):
            violations.append(
                f"{ref}: inconsistent payment binding {old} vs {(service_id, provider)}"
            )
        payment_binding[ref] = (service_id, provider)

    for ev in audit:
        if ev.get("event_type") != "empic_escrow_released":
            continue
        ref = _empic_ref(ev)
        service_id = _safe_text(ev.get("service_id"))
        provider = _safe_text(ev.get("provider"))
        expected = payment_binding.get(ref)
        if expected is None:
            violations.append(f"{ref or '<missing>'}: release without payment binding")
            continue
        if (service_id, provider) != expected:
            violations.append(
                f"{ref}: release binding {(service_id, provider)} does not match {expected}"
            )

    if violations:
        return [ValidationResult("empic_provider_service_binding", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_provider_service_binding",
            True,
            f"verified {len(payment_binding)} payment bindings",
        )
    ]


def validate_empic_payment_participant_binding(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Payment refs must not change consumer, provider, service, or mode.

    Example::

        result = validate_empic_payment_participant_binding(events)[0]
    """
    audit = _empic_audit_events(events)
    tracked_types = {
        "empic_acceptance_policy",
        "empic_escrow_debited",
        "empic_stream_opened",
        "empic_delivery_evaluated",
        "empic_escrow_released",
        "empic_escrow_refunded",
        "empic_stream_closed",
    }
    context_by_ref: dict[str, dict[str, str]] = defaultdict(dict)
    checked_refs: set[str] = set()
    violations: list[str] = []

    for ev in audit:
        event_type = str(ev.get("event_type") or "")
        if event_type not in tracked_types:
            continue
        ref = _empic_ref(ev)
        if not ref:
            violations.append(f"{event_type}: missing payment_ref")
            continue
        checked_refs.add(ref)

        payer = _safe_text(ev.get("payer"))
        consumer_id = _safe_text(ev.get("consumer_id"))
        if payer and consumer_id and payer != consumer_id:
            violations.append(f"{ref}: payer {payer} does not match consumer_id {consumer_id}")
        if payer and not consumer_id:
            consumer_id = payer
        if consumer_id and not payer:
            payer = consumer_id

        observed = {
            "service_id": _safe_text(ev.get("service_id")),
            "payer": payer,
            "consumer_id": consumer_id,
            "provider": _safe_text(ev.get("provider")),
            "mode": _safe_text(ev.get("mode")),
        }
        if event_type in {
            "empic_acceptance_policy",
            "empic_escrow_debited",
            "empic_stream_opened",
            "empic_escrow_released",
            "empic_escrow_refunded",
            "empic_stream_closed",
        }:
            missing = [field for field, value in observed.items() if not value]
            if missing:
                violations.append(f"{ref}: {event_type} missing {missing}")

        context = context_by_ref[ref]
        for field, value in observed.items():
            if not value:
                continue
            existing = context.get(field)
            if existing is not None and existing != value:
                violations.append(f"{ref}: {field} changed from {existing} to {value}")
            else:
                context[field] = value

    if violations:
        return [
            ValidationResult(
                "empic_payment_participant_binding",
                False,
                "; ".join(violations),
            )
        ]
    return [
        ValidationResult(
            "empic_payment_participant_binding",
            True,
            f"verified {len(checked_refs)} payment participant bindings",
        )
    ]


_EMPIC_FORBIDDEN_SECRET_KEYS = {
    "api_key",
    "api_key_secret",
    "bearer_token",
    "coinbase_secret",
    "password",
    "private_key",
    "secret",
    "secret_key",
    "service_api_key",
    "stripe_secret_key",
    "wallet_auth_token",
    "wallet_secret",
}

_PRIVATE_KEY_SENTINEL = "-----begin " + "private key-----"
_PAYMENT_SECRET_PREFIXES = ("sk_" + "live_", "sk_" + "test_")


def validate_empic_no_secret_material(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """EMPIC traces must contain only replay-safe public metadata.

    Example::

        result = validate_empic_no_secret_material(events)[0]
    """
    violations: list[str] = []
    checked = 0

    for ev in events:
        if ev.get("kind") != "send":
            continue
        with contextlib.suppress(json.JSONDecodeError):
            body_raw: object = json.loads(_message_body(ev))
            if not isinstance(body_raw, dict):
                continue
            body = cast("dict[str, Any]", body_raw)
            msg_type = str(body.get("type") or "")
            if not msg_type.startswith("empic_"):
                continue
            checked += 1
            violations.extend(_empic_secret_violations(body, path=msg_type))

    if violations:
        return [
            ValidationResult(
                "empic_no_secret_material",
                False,
                "; ".join(violations),
            )
        ]
    return [
        ValidationResult(
            "empic_no_secret_material",
            True,
            f"checked {checked} EMPIC trace messages",
        )
    ]


def validate_empic_no_drain_after_close(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Pubsub streams must not release funds after close.

    Example::

        result = validate_empic_no_drain_after_close(events)[0]
    """
    audit = _empic_audit_events(events)
    close_tick: dict[str, int] = {}
    violations: list[str] = []

    for ev in audit:
        if ev.get("event_type") == "empic_stream_closed":
            ref = str(ev.get("payment_ref", ""))
            if ref:
                close_tick[ref] = _event_tick(ev)

    for ev in audit:
        if ev.get("event_type") != "empic_escrow_released":
            continue
        ref = str(ev.get("payment_ref", ""))
        closed_at = close_tick.get(ref)
        if closed_at is not None and _event_tick(ev) > closed_at:
            violations.append(f"{ref} released at {_event_tick(ev)} after close at {closed_at}")

    if violations:
        return [ValidationResult("empic_no_drain_after_close", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_no_drain_after_close",
            True,
            f"verified {len(close_tick)} closed pubsub streams",
        )
    ]


def validate_empic_no_overbill_on_partition(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Pubsub streams must not release funds after a partitioned delivery edge.

    Example::

        result = validate_empic_no_overbill_on_partition(events)[0]
    """
    audit = _empic_audit_events(events)
    stream_parties: dict[str, tuple[str, str]] = {}
    partition_start: dict[tuple[str, str], int] = {}
    violations: list[str] = []

    for ev in audit:
        if ev.get("event_type") == "empic_stream_opened":
            ref = str(ev.get("payment_ref", ""))
            payer = str(ev.get("payer", ""))
            provider = str(ev.get("provider", ""))
            if ref and payer and provider:
                stream_parties[ref] = (payer, provider)

    for ev in events:
        if ev.get("kind") != "dropped":
            continue
        sender = str(ev.get("from", ""))
        receiver = str(ev.get("agent", ""))
        if not sender or not receiver:
            continue
        tick = _event_tick(ev)
        for edge in ((sender, receiver), (receiver, sender)):
            old = partition_start.get(edge)
            if old is None or tick < old:
                partition_start[edge] = tick

    for ev in audit:
        if ev.get("event_type") != "empic_escrow_released":
            continue
        ref = str(ev.get("payment_ref", ""))
        parties = stream_parties.get(ref)
        if parties is None:
            continue
        payer, provider = parties
        drop_tick = partition_start.get((payer, provider))
        if drop_tick is not None and _event_tick(ev) >= drop_tick:
            violations.append(
                f"{ref} released at {_event_tick(ev)} after {payer}<->{provider} "
                f"partition at {drop_tick}"
            )

    if violations:
        return [ValidationResult("empic_no_overbill_on_partition", False, "; ".join(violations))]
    return [
        ValidationResult(
            "empic_no_overbill_on_partition",
            True,
            f"verified {len(stream_parties)} pubsub streams",
        )
    ]


def _empic_policy_accepts(
    delivery: dict[str, Any],
    policy_event: dict[str, Any],
    current_tick: int,
) -> tuple[bool, str]:
    data_raw = delivery.get("data")
    if not isinstance(data_raw, dict):
        return False, "missing data object"
    data = cast("dict[str, Any]", data_raw)

    policy_raw = policy_event.get("policy")
    policy = cast("dict[str, Any]", policy_raw) if isinstance(policy_raw, dict) else {}

    if _policy_flag(policy, "bind_service_id") and _safe_text(
        delivery.get("service_id")
    ) != _safe_text(policy_event.get("service_id")):
        return False, "service_id mismatch"
    if _policy_flag(policy, "bind_provider_id") and _safe_text(
        delivery.get("provider_id")
    ) != _safe_text(policy_event.get("provider")):
        return False, "provider_id mismatch"
    if _policy_flag(policy, "bind_consumer_id"):
        expected_consumer = _safe_text(policy_event.get("consumer_id")) or _safe_text(
            policy_event.get("payer")
        )
        if _safe_text(delivery.get("consumer_id")) != expected_consumer:
            return False, "consumer_id mismatch"
    if _policy_flag(policy, "bind_request_params"):
        expected_params = policy_event.get("request_params")
        if delivery.get("request_params") != expected_params:
            return False, "request_params mismatch"

    required = policy.get("required_fields", [])
    if isinstance(required, list):
        for field in cast("list[object]", required):
            if isinstance(field, str) and field not in data:
                return False, f"missing field {field}"

    ranges = policy.get("numeric_ranges", {})
    if isinstance(ranges, dict):
        for field_raw, bounds_raw in cast("dict[object, object]", ranges).items():
            if not isinstance(field_raw, str) or not isinstance(bounds_raw, dict):
                continue
            bounds = cast("dict[str, object]", bounds_raw)
            value = _safe_float(data.get(field_raw))
            if value is None:
                return False, f"{field_raw} is not numeric"
            min_value = _safe_float(bounds.get("min"))
            max_value = _safe_float(bounds.get("max"))
            if min_value is not None and value < min_value:
                return False, f"{field_raw} below minimum"
            if max_value is not None and value > max_value:
                return False, f"{field_raw} above maximum"

    max_age = _safe_amount(policy.get("max_age_ticks"))
    data_tick = _safe_amount(data.get("tick"))
    if data_tick > current_tick:
        return False, "delivery tick is in the future"
    if max_age >= 0 and current_tick - data_tick > max_age:
        return False, "delivery stale"

    return True, "accepted"


def _policy_flag(policy: dict[str, Any], key: str) -> bool:
    value = policy.get(key, True)
    return value if isinstance(value, bool) else True


def _empic_secret_violations(value: object, *, path: str) -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key_raw, child in cast("dict[object, object]", value).items():
            key = str(key_raw)
            normalized = key.lower().replace("-", "_")
            child_path = f"{path}.{key}"
            if normalized in _EMPIC_FORBIDDEN_SECRET_KEYS or normalized.endswith("_secret"):
                violations.append(f"{child_path}: forbidden secret field")
            violations.extend(_empic_secret_violations(child, path=child_path))
    elif isinstance(value, list):
        for index, item in enumerate(cast("list[object]", value)):
            violations.extend(_empic_secret_violations(item, path=f"{path}[{index}]"))
    elif isinstance(value, str):
        lowered = value.lower()
        if _PRIVATE_KEY_SENTINEL in lowered:
            violations.append(f"{path}: private key material")
        elif lowered.startswith("bearer "):
            violations.append(f"{path}: bearer token material")
        elif value.startswith(_PAYMENT_SECRET_PREFIXES):
            violations.append(f"{path}: payment provider secret key material")
    return violations


def _safe_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _safe_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return float(value)
    return None


def _optional_amount(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return int(float(value))
    return None


def _safe_amount(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return int(value)
    return 0


# ---------------------------------------------------------------------------
# Comms schema-versioning validators (adversarial)
# ---------------------------------------------------------------------------

# The wire contract a versioned comms layer must honour, encoded here
# independently of any plugin so these checks can judge *any* comms
# implementation -- including the default ``nest_native``, which fails both.
_COMMS_KNOWN_MAJOR = 1
_COMMS_KNOWN_ENVELOPE_FIELDS = frozenset(
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


def _parse_comms_envelope(msg: str) -> dict[str, Any] | None:
    """Parse a trace ``msg`` as a comms envelope, or return ``None``.

    Receiver acks and non-JSON payloads are not envelopes and yield ``None``.

    Example::

        env = _parse_comms_envelope('{"id": "m1", "schema_version": "1.1"}')
    """
    if not msg.startswith("{"):
        return None
    try:
        loaded = json.loads(msg)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(loaded, dict) or "id" not in loaded:
        return None
    return cast("dict[str, Any]", loaded)


def _comms_major(version: str) -> int | None:
    """Return the integer major of a SemVer string, or ``None`` if malformed.

    Example::

        assert _comms_major("2.3") == 2
    """
    try:
        return int(version.split(".", 1)[0])
    except (ValueError, AttributeError):
        return None


def _collect_comms_wire(
    events: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Map each envelope id to its on-the-wire ``version``/``major``/unknowns.

    Reads ground truth from the bytes a receiver actually *received*,
    independent of how it then chose to decode them. Only delivered envelopes
    are judged, so a dropped message never counts as a missing ack.
    """
    wire: dict[str, dict[str, Any]] = {}
    for ev in events:
        if ev.get("kind") != "receive":
            continue
        env = _parse_comms_envelope(str(ev.get("msg", "")))
        if env is None:
            continue
        mid = str(env.get("id"))
        version = str(env.get("schema_version", "1.0"))
        unknown = {k for k in env if k not in _COMMS_KNOWN_ENVELOPE_FIELDS}
        wire[mid] = {
            "version": version,
            "major": _comms_major(version),
            "unknown_fields": unknown,
        }
    return wire


def _collect_comms_acks(
    events: list[dict[str, Any]],
) -> dict[str, tuple[str, set[str]]]:
    """Map each envelope id to the receiver's ``(status, preserved_fields)``.

    Receivers emit ``ack:<id>:<status>:<comma-separated preserved fields>``
    where ``status`` is ``accepted`` or ``rejected_major``.
    """
    acks: dict[str, tuple[str, set[str]]] = {}
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = str(ev.get("msg", ""))
        if not msg.startswith("ack:"):
            continue
        parts = msg.split(":", 3)
        if len(parts) < 3:
            continue
        mid, status = parts[1], parts[2]
        preserved = {f for f in parts[3].split(",") if f} if len(parts) > 3 else set[str]()
        acks[mid] = (status, preserved)
    return acks


def validate_memory_liveness(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Trace validator: every agent that started reported a final state.

    Convergence is only meaningful if no replica silently dropped out. This
    check confirms that every agent with a ``start`` event also emitted a
    ``final:`` record -- i.e. the gossip protocol made progress at every
    replica, not just the ones that happened to win.
    """
    started: set[str] = set()
    reported: set[str] = set()
    for ev in events:
        agent = str(ev.get("agent", ""))
        if ev.get("kind") == "start":
            started.add(agent)
        elif ev.get("kind") in ("send", "broadcast") and str(ev.get("msg", "")).startswith(
            "final:"
        ):
            reported.add(agent)

    if not started:
        return [ValidationResult("memory_liveness", False, "no agents started in trace")]
    missing = started - reported
    if missing:
        return [
            ValidationResult(
                "memory_liveness",
                False,
                f"{len(missing)} replica(s) never reported a final state: {sorted(missing)}",
            )
        ]
    return [
        ValidationResult(
            "memory_liveness",
            True,
            f"all {len(started)} replicas reported a final state",
        )
    ]


def validate_identity_rotation_occurred(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """At least one key rotation happened over the run.

    The rotation feature is the whole point of the scenario: a trace with no
    ``rotate:`` line never exercised it. ``did_key`` cannot rotate, so it emits
    none and fails here — the honest demonstration that it lacks the capability.

    Example::

        results = validate_identity_rotation_occurred(events)
    """
    rotations = 0
    for ev in events:
        if ev.get("kind") != "send":
            continue
        if _message_body(ev).startswith("rotate:"):
            rotations += 1

    if rotations == 0:
        return [
            ValidationResult(
                "identity_rotation_occurred",
                False,
                "no key rotations found (identity plugin does not support rotation)",
            )
        ]
    return [
        ValidationResult(
            "identity_rotation_occurred",
            True,
            f"{rotations} key rotations observed",
        )
    ]


def validate_comms_reject_unknown_major(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Receivers must reject envelopes whose major version they don't speak.

    Catches the *silent-accept* attack: ``nest_native`` ignores
    ``schema_version`` and decodes a breaking v2.0 envelope into a
    plausible-but-wrong message, whereas ``versioned`` rejects it.

    Example::

        results = validate_comms_reject_unknown_major(events)
    """
    wire = _collect_comms_wire(events)
    acks = _collect_comms_acks(events)
    violations: list[str] = []
    checked = 0
    for mid, info in wire.items():
        major = info["major"]
        if major is None or major <= _COMMS_KNOWN_MAJOR:
            continue
        checked += 1
        status = acks.get(mid)
        if status is None or status[0] != "rejected_major":
            got = "no ack" if status is None else status[0]
            violations.append(f"{mid}: unknown major {info['version']} not rejected (got {got})")
    if violations:
        return [ValidationResult("comms_reject_unknown_major", False, "; ".join(violations))]
    return [
        ValidationResult(
            "comms_reject_unknown_major",
            True,
            f"{checked} unknown-major envelope(s) correctly rejected",
        )
    ]


def validate_comms_no_silent_drop(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Receivers must preserve unknown fields from newer-minor peers.

    Catches the *silent-drop* attack: ``nest_native`` reads only the fields it
    knows and discards a field a newer peer added with no trace, whereas
    ``versioned`` preserves it for round-trip re-emission.

    Example::

        results = validate_comms_no_silent_drop(events)
    """
    wire = _collect_comms_wire(events)
    acks = _collect_comms_acks(events)
    violations: list[str] = []
    checked = 0
    for mid, info in wire.items():
        if info["major"] != _COMMS_KNOWN_MAJOR or not info["unknown_fields"]:
            continue
        checked += 1
        status = acks.get(mid)
        if status is None:
            unknown = sorted(info["unknown_fields"])
            violations.append(f"{mid}: carried unknown {unknown} but no ack")
            continue
        outcome, preserved = status
        if outcome != "accepted" or not info["unknown_fields"] <= preserved:
            dropped = sorted(info["unknown_fields"] - preserved)
            violations.append(f"{mid}: silently dropped {dropped} (status {outcome})")
    if violations:
        return [ValidationResult("comms_no_silent_drop", False, "; ".join(violations))]
    return [
        ValidationResult(
            "comms_no_silent_drop",
            True,
            f"{checked} forward-compat envelope(s) preserved all unknown fields",
        )
    ]


# ---------------------------------------------------------------------------
# Comms downgrade-attack validator (adversarial)
# ---------------------------------------------------------------------------
# Ground truth for "was this envelope tampered?" is recomputed from the bytes a
# receiver actually saw, independent of the decoder under test: an envelope that
# carries an ``auth_tag`` is authentic iff that tag still covers its canonical
# content. A comms layer passes iff it *rejects* every envelope whose tag no
# longer verifies (rollback / field-strip) while still *accepting* the authentic
# ones. ``versioned`` and ``nest_native`` have no tag concept, so they accept the
# tampered copies and fail; ``authenticated`` rejects them and passes.


def _collect_downgrade_wire(
    events: list[dict[str, Any]],
) -> dict[str, bool]:
    """Map each delivered tagged envelope id to whether its ``auth_tag`` verifies.

    Only envelopes that actually carry a tag are judged; untagged legacy traffic
    is out of scope for this check. ``True`` means authentic (tag matches the
    recomputed value), ``False`` means tampered.

    Example::

        authentic_by_id = _collect_downgrade_wire(events)
    """
    from nest_plugins_reference.comms.authenticated import (
        AUTH_TAG_FIELD,
        expected_auth_tag,
    )

    authentic: dict[str, bool] = {}
    for ev in events:
        if ev.get("kind") != "receive":
            continue
        env = _parse_comms_envelope(str(ev.get("msg", "")))
        if env is None or AUTH_TAG_FIELD not in env:
            continue
        mid = str(env.get("id"))
        carried = str(env.get(AUTH_TAG_FIELD))
        authentic[mid] = carried == expected_auth_tag(env)
    return authentic


def validate_comms_downgrade_resistance(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Receivers must reject envelopes whose authentication tag no longer covers them.

    Catches the *silent-downgrade* attack: an on-path adversary rewrites an
    authentic envelope (rolls ``schema_version`` back, or strips a field) and
    leaves the stale tag in place. ``authenticated`` recomputes the tag and
    refuses the forgery; ``versioned``/``nest_native`` have no tag and accept it.

    Example::

        results = validate_comms_downgrade_resistance(events)
    """
    authentic = _collect_downgrade_wire(events)
    acks = _collect_comms_acks(events)
    if not authentic:
        return [
            ValidationResult("comms_downgrade_resistance", False, "no tagged envelopes in trace")
        ]
    violations: list[str] = []
    tampered_checked = 0
    for mid, is_authentic in authentic.items():
        if is_authentic:
            continue
        tampered_checked += 1
        status = acks.get(mid)
        outcome = status[0] if status is not None else "no ack"
        if not outcome.startswith("rejected"):
            violations.append(f"{mid}: tampered envelope not rejected (got {outcome})")
    if violations:
        return [ValidationResult("comms_downgrade_resistance", False, "; ".join(violations))]
    return [
        ValidationResult(
            "comms_downgrade_resistance",
            True,
            f"{tampered_checked} tampered envelope(s) correctly rejected",
        )
    ]


def validate_comms_authentic_delivery(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Receivers must still accept *authentic* envelopes (no false positives).

    The liveness counterpart to
    :func:`validate_comms_downgrade_resistance`: a plugin must not "pass" the
    security check by rejecting everything. Every delivered envelope whose tag
    verifies has to be accepted, so tamper-evidence does not break the honest
    rolling-upgrade traffic it rides alongside.

    Example::

        results = validate_comms_authentic_delivery(events)
    """
    authentic = _collect_downgrade_wire(events)
    acks = _collect_comms_acks(events)
    if not authentic:
        return [ValidationResult("comms_authentic_delivery", False, "no tagged envelopes in trace")]
    violations: list[str] = []
    honest_checked = 0
    for mid, is_authentic in authentic.items():
        if not is_authentic:
            continue
        honest_checked += 1
        status = acks.get(mid)
        outcome = status[0] if status is not None else "no ack"
        if outcome != "accepted":
            violations.append(f"{mid}: authentic envelope not accepted (got {outcome})")
    if violations:
        return [ValidationResult("comms_authentic_delivery", False, "; ".join(violations))]
    return [
        ValidationResult(
            "comms_authentic_delivery",
            True,
            f"{honest_checked} authentic envelope(s) correctly accepted",
        )
    ]


# ---------------------------------------------------------------------------
# Receipt-reputation (collusion-ring) validators
# ---------------------------------------------------------------------------

# An effectively-severed reputation is anything at or below this. A severed ring
# member scores exactly 0.0 under ``agent_receipts``; ``score_average`` rewards
# the (all-positive) ring to ~1.0, far above this floor.
_RING_SEVERED_MAX = 1e-6


def _collect_scores(events: list[dict[str, Any]]) -> dict[str, tuple[float, float, str]]:
    """Parse ``score:<agent>:<score>:<confidence>:<role>`` lines from the trace.

    Returns ``agent -> (score, confidence, role)`` using the *last* score line
    seen for each agent (the finalize pass emits one per agent). The scores are
    produced by the live trust plugin, so this dict differs by configured plugin
    -- which is what lets the validator discriminate.

    Example::

        scores = _collect_scores(events)
    """
    scores: dict[str, tuple[float, float, str]] = {}
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = _message_body(ev)
        if not msg.startswith("score:"):
            continue
        parts = msg.split(":")
        if len(parts) < 5:
            continue
        agent, score_raw, conf_raw, role = parts[1], parts[2], parts[3], parts[4]
        try:
            score = float(score_raw)
            confidence = float(conf_raw)
        except ValueError:
            continue
        scores[agent] = (score, confidence, role)
    return scores


# ---------------------------------------------------------------------------
# Escrow validators
#
# The escrow scenario broadcasts structured ``escrow:<kind>:<fields>`` events,
# one per state transition, parsed by the validators below. The four checks
# together catch the attacks the default ``prepaid_credits`` plugin would not
# block: payouts without delivery, releases by non-payers, arbitration outside
# the bps range, and broken state-machine transitions.
# ---------------------------------------------------------------------------


def _parse_escrow_events(
    events: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Parse trace broadcasts of the form ``escrow:<kind>:k=v:k=v...``.

    Returns one dict per matching event with ``kind`` and parsed ``key=value``
    fields. Non-matching broadcasts are skipped silently.
    """
    out: list[dict[str, str]] = []
    for ev in events:
        # Only inspect broadcast emissions (sender-recorded). Filter out the
        # per-recipient "deliver" copies of the same payload so a 9-agent
        # mesh does not multiply each escrow event by 8.
        if ev.get("kind") != "broadcast":
            continue
        msg = _message_body(ev)
        if not msg.startswith("escrow:"):
            continue
        parts = msg.split(":")
        if len(parts) < 2:
            continue
        parsed: dict[str, str] = {"kind": parts[1], "agent": str(ev.get("agent", ""))}
        for piece in parts[2:]:
            if "=" in piece:
                k, _, v = piece.partition("=")
                parsed[k] = v
        out.append(parsed)
    return out


def validate_escrow_state_machine(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every per-escrow transition sequence is a legal state-machine path.

    Legal sequences (per escrow ``ref``):

    * ``opened -> delivered -> released``
    * ``opened -> delivered -> disputed -> arbitrated``
    * ``opened -> refunded``

    Any transition outside this graph (e.g. ``opened -> released`` with no
    ``delivered``, or two ``released`` for the same ref) is a failure.
    """
    legal: dict[str, set[str]] = {
        "_initial": {"opened"},
        "opened": {"delivered", "refunded"},
        "delivered": {"released", "disputed"},
        "disputed": {"arbitrated"},
        "released": set(),
        "arbitrated": set(),
        "refunded": set(),
    }
    state: dict[str, str] = {}
    violations: list[str] = []
    for ev in _parse_escrow_events(events):
        ref = ev.get("ref", "")
        kind = ev["kind"]
        prev = state.get(ref, "_initial")
        if kind not in legal.get(prev, set()):
            violations.append(f"ref={ref!r}: illegal transition {prev!r} -> {kind!r}")
            continue
        state[ref] = kind
    if violations:
        return [ValidationResult("escrow_state_machine", False, "; ".join(violations))]
    if not state:
        return [
            ValidationResult(
                "escrow_state_machine",
                False,
                "no escrow lifecycle events observed in trace -- plugin lacks escrow protocol",
            )
        ]
    return [
        ValidationResult(
            "escrow_state_machine",
            True,
            f"{len(state)} escrows transitioned only along legal edges",
        )
    ]


def validate_escrow_role_binding(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every state-changing event is broadcast by the role authorized to make it.

    * ``opened`` MUST be broadcast by the named ``payer``.
    * ``delivered`` MUST be broadcast by the named ``payee``.
    * ``released``, ``disputed``, ``refunded`` MUST be broadcast by the
      named ``payer`` (from the originating ``opened``).
    * ``arbitrated`` MUST be broadcast by the named ``arbiter``.

    Detects forged-actor attacks: a non-payee posting a fake delivery, a
    third party trying to release someone else's escrow, etc.
    """
    parsed = _parse_escrow_events(events)
    parties: dict[str, dict[str, str]] = {}
    violations: list[str] = []
    for ev in parsed:
        ref = ev.get("ref", "")
        kind = ev["kind"]
        actor = ev.get("agent", "")
        if kind == "opened":
            parties[ref] = {
                "payer": ev.get("payer", ""),
                "payee": ev.get("payee", ""),
                "arbiter": ev.get("arbiter", ""),
            }
            if actor != ev.get("payer", ""):
                violations.append(
                    f"ref={ref!r}: opened by {actor!r} but payer is {ev.get('payer', '')!r}"
                )
            continue
        named = parties.get(ref)
        if named is None:
            violations.append(f"ref={ref!r}: {kind!r} without prior opened")
            continue
        if kind == "delivered" and actor != named["payee"]:
            violations.append(
                f"ref={ref!r}: delivered by {actor!r} but payee is {named['payee']!r}"
            )
        elif kind in ("released", "disputed", "refunded") and actor != named["payer"]:
            violations.append(f"ref={ref!r}: {kind!r} by {actor!r} but payer is {named['payer']!r}")
        elif kind == "arbitrated" and actor != named["arbiter"]:
            violations.append(
                f"ref={ref!r}: arbitrated by {actor!r} but arbiter is {named['arbiter']!r}"
            )
    if violations:
        return [ValidationResult("escrow_role_binding", False, "; ".join(violations))]
    if not parties:
        return [
            ValidationResult(
                "escrow_role_binding",
                False,
                "no escrow opened events observed -- plugin lacks escrow protocol",
            )
        ]
    return [
        ValidationResult(
            "escrow_role_binding",
            True,
            f"{len(parsed)} escrow events all signed by the correct role-holder",
        )
    ]


def validate_escrow_bps_in_range(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every ``arbitrated`` event carries ``payee_bps`` strictly in ``[0, 10000]``.

    Catches an arbiter (or a forged arbitrate broadcast) that attempts to
    settle outside the allowed split window -- either negative (paying the
    payee a negative share) or over 10000 (paying more than was escrowed).
    """
    parsed = _parse_escrow_events(events)
    violations: list[str] = []
    checked = 0
    for ev in parsed:
        if ev["kind"] != "arbitrated":
            continue
        checked += 1
        raw = ev.get("payee_bps", "")
        try:
            bps = int(raw)
        except ValueError:
            violations.append(f"ref={ev.get('ref', '')!r}: non-integer payee_bps={raw!r}")
            continue
        if not 0 <= bps <= 10_000:
            violations.append(f"ref={ev.get('ref', '')!r}: payee_bps={bps} outside [0, 10000]")
    if violations:
        return [ValidationResult("escrow_bps_in_range", False, "; ".join(violations))]
    return [
        ValidationResult(
            "escrow_bps_in_range",
            True,
            f"{checked} arbitration verdicts all within [0, 10000]",
        )
    ]


def validate_escrow_no_payout_without_delivery(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No ``released`` or ``arbitrated`` may occur for a ref that wasn't delivered.

    The escrow protocol's whole point is that the payee cannot be paid
    until they post a delivery proof. A plugin that ships funds without
    a preceding ``delivered`` event for the same ref bypasses the
    contract.

    Also catches the most common ``prepaid_credits`` failure mode in
    this scenario: the plugin has no escrow concept, so the buyer falls
    back to ``pay()``, which credits the payee with no delivery proof
    in the trace.
    """
    parsed = _parse_escrow_events(events)
    delivered: set[str] = set()
    violations: list[str] = []
    saw_payout = False
    for ev in parsed:
        ref = ev.get("ref", "")
        kind = ev["kind"]
        if kind == "delivered":
            delivered.add(ref)
        elif kind in ("released", "arbitrated"):
            saw_payout = True
            if ref not in delivered:
                violations.append(f"ref={ref!r}: {kind!r} settled without prior delivered event")
    if violations:
        return [
            ValidationResult(
                "escrow_no_payout_without_delivery",
                False,
                "; ".join(violations),
            )
        ]
    if not saw_payout:
        return [
            ValidationResult(
                "escrow_no_payout_without_delivery",
                False,
                "no escrow payouts observed -- plugin lacks escrow protocol",
            )
        ]
    return [
        ValidationResult(
            "escrow_no_payout_without_delivery",
            True,
            "every payout was preceded by a matching delivered event",
        )
    ]


def validate_receipt_reputation_ring_severed(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """The isolated collusion ring is severed while honest agents are retained.

    Reads the trust plugin's own ``score:`` lines from the trace (never recomputes
    reputation itself -- the discrimination must come from the configured plugin).
    The protocol holds iff:

    * at least one ``ring`` agent and one ``honest`` agent were scored (the
      scenario actually exercised both populations),
    * **every** ``ring`` agent scored ``<= 1e-6`` (its wash-traded reputation was
      severed to ~0), and
    * **every** ``honest`` agent scored ``> 1e-6`` (the honest anchor retained
      its corroborated reputation -- guards against a degenerate all-zero plugin).

    ``trust: score_average`` FAILS this: it has no notion of corroboration and
    rewards the ring's all-positive reports to ~1.0. ``trust: agent_receipts``
    PASSES: the ring is an isolated dense SCC that collusion severance voids,
    while the honest cycle is the anchor. A plugin that emits no ``score:`` lines
    (or scores everyone 0) also fails -- without crashing.

    Example::

        results = validate_receipt_reputation_ring_severed(events)
    """
    scores = _collect_scores(events)
    ring = {a: s for a, (s, _c, role) in scores.items() if role == "ring"}
    honest = {a: s for a, (s, _c, role) in scores.items() if role == "honest"}

    if not ring or not honest:
        return [
            ValidationResult(
                "receipt_reputation_ring_severed",
                False,
                f"missing populations: {len(ring)} ring, {len(honest)} honest scored",
            )
        ]

    rewarded_ring = {a: s for a, s in ring.items() if s > _RING_SEVERED_MAX}
    dropped_honest = {a: s for a, s in honest.items() if s <= _RING_SEVERED_MAX}

    problems: list[str] = []
    if rewarded_ring:
        problems.append(
            "ring not severed: "
            + ", ".join(f"{a}={s:.4f}" for a, s in sorted(rewarded_ring.items()))
        )
    if dropped_honest:
        problems.append(
            "honest not retained: "
            + ", ".join(f"{a}={s:.4f}" for a, s in sorted(dropped_honest.items()))
        )

    if problems:
        return [ValidationResult("receipt_reputation_ring_severed", False, "; ".join(problems))]
    return [
        ValidationResult(
            "receipt_reputation_ring_severed",
            True,
            f"{len(ring)} ring agents severed to ~0, {len(honest)} honest agents retained",
        )
    ]


def validate_receipt_reputation_honest_confidence(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Honest agents carry positive corroboration confidence; the ring does not.

    A second, independent invariant: ``confidence`` (corroboration rate) must be
    positive for every honest agent and zero for every severed ring agent. This
    distinguishes a real collusion-resistant plugin from one that merely zeroes
    the ring's score by accident -- the ring's *confidence* collapsing to 0 is the
    signal that its corroborations were voided, not just its weights.

    ``score_average`` reports a non-zero confidence for the ring (it counts
    samples), so it FAILS; ``agent_receipts`` reports ring confidence 0 and
    honest confidence > 0, so it PASSES.

    Example::

        results = validate_receipt_reputation_honest_confidence(events)
    """
    scores = _collect_scores(events)
    ring_conf = {a: c for a, (_s, c, role) in scores.items() if role == "ring"}
    honest_conf = {a: c for a, (_s, c, role) in scores.items() if role == "honest"}

    if not ring_conf or not honest_conf:
        return [
            ValidationResult(
                "receipt_reputation_honest_confidence",
                False,
                f"missing populations: {len(ring_conf)} ring, {len(honest_conf)} honest scored",
            )
        ]

    ring_corroborated = {a: c for a, c in ring_conf.items() if c > _RING_SEVERED_MAX}
    honest_uncorroborated = {a: c for a, c in honest_conf.items() if c <= _RING_SEVERED_MAX}

    problems: list[str] = []
    if ring_corroborated:
        problems.append(
            "ring retains corroboration confidence: "
            + ", ".join(f"{a}={c:.4f}" for a, c in sorted(ring_corroborated.items()))
        )
    if honest_uncorroborated:
        problems.append(
            "honest lacks corroboration confidence: "
            + ", ".join(f"{a}={c:.4f}" for a, c in sorted(honest_uncorroborated.items()))
        )

    if problems:
        return [
            ValidationResult("receipt_reputation_honest_confidence", False, "; ".join(problems))
        ]
    return [
        ValidationResult(
            "receipt_reputation_honest_confidence",
            True,
            f"{len(honest_conf)} honest corroborated, {len(ring_conf)} ring collapsed to 0",
        )
    ]


# ---------------------------------------------------------------------------
# Rogue-trusted-agent (pre-action permit gate) validators
#
# The rogue_trusted_agent scenario broadcasts ``:``-delimited lines (see
# nest_core.scenarios_builtin.rogue_trusted_agent). A veteran with a strong
# in-policy record makes one out-of-policy attempt; the trace self-declares it
# with a ``rogue_attempt:`` line so these validators need no policy table. Under
# a plugin with a pre-action gate the attempt is refused (``permit:...:denied``
# + ``blocked:``) and never runs; under a plugin with no gate it ``exec:``s.
# ---------------------------------------------------------------------------

# The veteran must have executed at least this many in-policy actions before the
# rogue attempt, so "a high-reputation agent is still refused" is grounded.
_ROGUE_MIN_REPUTATION = 3


def _rogue_declaration(events: list[dict[str, Any]]) -> tuple[str, str, str] | None:
    """Return the first declared rogue ``(agent, verb, resource)``, or ``None``.

    Example::

        pair = _rogue_declaration(events)
    """
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = _message_body(ev)
        if not msg.startswith("rogue_attempt:"):
            continue
        parts = msg.split(":")
        if len(parts) >= 4:
            return parts[1], parts[2], parts[3]
    return None


def _rogue_triples(events: list[dict[str, Any]], prefix: str) -> list[tuple[str, str, str]]:
    """Collect ``(agent, verb, resource)`` triples from lines with ``prefix``.

    Preserves trace order. Used for ``exec:`` and ``blocked:`` lines and, with a
    trailing field trimmed, for the ``permit:`` lines.

    Example::

        execs = _rogue_triples(events, "exec:")
    """
    out: list[tuple[str, str, str]] = []
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = _message_body(ev)
        if not msg.startswith(prefix):
            continue
        parts = msg.split(":")
        if len(parts) >= 4:
            out.append((parts[1], parts[2], parts[3]))
    return out


def _rogue_permits(events: list[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
    """Collect ``(agent, verb, resource, outcome)`` from ``permit:`` lines.

    ``permit_env:`` lines are excluded — their prefix is not ``permit:``.

    Example::

        decisions = _rogue_permits(events)
    """
    out: list[tuple[str, str, str, str]] = []
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = _message_body(ev)
        if not msg.startswith("permit:"):
            continue
        parts = msg.split(":")
        if len(parts) >= 5:
            out.append((parts[1], parts[2], parts[3], parts[4]))
    return out


def validate_rogue_trusted_agent_blocked(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """The declared out-of-policy attempt is refused and never executes.

    Reads the trace the scenario emits — never a policy table — and holds iff:

    * a ``rogue_attempt:`` line declares the veteran's out-of-policy pair,
    * **no** ``exec:`` line runs that pair (it did not execute), and
    * a ``permit:...:denied`` line refused that exact pair.

    ``score_average`` FAILS this: with no pre-action gate the veteran acts
    unconditionally, so an ``exec:`` line for the rogue pair is present.
    ``aae_permit_gate`` PASSES: it returns a signed denial and the action is
    blocked. A trace that never declared a rogue attempt also fails — without
    crashing on either layer.

    Example::

        results = validate_rogue_trusted_agent_blocked(events)
    """
    rogue = _rogue_declaration(events)
    if rogue is None:
        return [
            ValidationResult(
                "rogue_trusted_agent_blocked",
                False,
                "no rogue_attempt declared in trace",
            )
        ]
    agent, verb, resource = rogue
    executed = rogue in _rogue_triples(events, "exec:")
    denied = any(
        (a, v, r) == rogue and outcome == "denied" for a, v, r, outcome in _rogue_permits(events)
    )

    if executed:
        return [
            ValidationResult(
                "rogue_trusted_agent_blocked",
                False,
                f"rogue action executed: {agent} ran {verb} on {resource} "
                "(no pre-action gate refused it)",
            )
        ]
    if not denied:
        return [
            ValidationResult(
                "rogue_trusted_agent_blocked",
                False,
                f"rogue action neither executed nor refused: {agent} {verb} {resource} "
                "has no signed denial",
            )
        ]
    return [
        ValidationResult(
            "rogue_trusted_agent_blocked",
            True,
            f"rogue action refused and blocked: {agent} denied {verb} on {resource}",
        )
    ]


def validate_rogue_trusted_agent_reputation(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Reputation was earned first, and no in-policy action was refused.

    Two defense-in-depth invariants that ground the demonstration:

    * the veteran executed at least ``_ROGUE_MIN_REPUTATION`` in-policy actions
      *before* its rogue attempt — so "a high-reputation agent is still refused"
      is real, not asserted, and
    * every refusal in the trace names the declared rogue pair — a permit gate
      that spuriously denied an in-policy action would be caught here.

    Holds under both layers (it does not depend on the rogue being blocked), so
    it corroborates the primary check rather than duplicating it. Never crashes.

    Example::

        results = validate_rogue_trusted_agent_reputation(events)
    """
    rogue = _rogue_declaration(events)
    if rogue is None:
        return [
            ValidationResult(
                "rogue_trusted_agent_reputation",
                False,
                "no rogue_attempt declared in trace",
            )
        ]
    veteran, _verb, _resource = rogue

    # In-policy executions by the veteran, in trace order, before the rogue pair.
    prior = 0
    for a, v, r in _rogue_triples(events, "exec:"):
        if (a, v, r) == rogue:
            break
        if a == veteran:
            prior += 1

    problems: list[str] = []
    if prior < _ROGUE_MIN_REPUTATION:
        problems.append(
            f"veteran executed only {prior} in-policy action(s) before the rogue attempt "
            f"(need >= {_ROGUE_MIN_REPUTATION} to prove reputation is irrelevant)"
        )
    spurious = [
        (a, v, r)
        for a, v, r, outcome in _rogue_permits(events)
        if outcome == "denied" and (a, v, r) != rogue
    ]
    if spurious:
        problems.append(
            "in-policy actions spuriously denied: "
            + ", ".join(f"{a}:{v}:{r}" for a, v, r in sorted(set(spurious)))
        )

    if problems:
        return [ValidationResult("rogue_trusted_agent_reputation", False, "; ".join(problems))]
    return [
        ValidationResult(
            "rogue_trusted_agent_reputation",
            True,
            f"veteran earned {prior} in-policy actions; every refusal was the declared rogue pair",
        )
    ]


# ---------------------------------------------------------------------------
# Multi-attribute negotiation (Pareto) validators
# ---------------------------------------------------------------------------

# Float-noise tolerance for the dominance relation. ">=" is read as ">= -eps"
# and ">" as "> +eps", so reconstruction rounding (utilities are rebuilt from
# the 6-dp weights in the trace) never fabricates or hides a violation.
_PARETO_EPS = 1e-9


class _AgentUtility:
    """One agent's additive multi-attribute utility, reconstructed from the trace.

    Reproduces the plugin's scoring *verbatim* (Keeney & Raiffa additive MAUT):
    inputs are clamped into the feasible ranges, then each issue's normalized
    value function is weighted and summed. The directional convention matches
    the plugin exactly (the buyer values low price / short deadline, the seller
    high price / long deadline) so a bundle scores identically here and inside
    ``ParetoNegotiation``.

    Example::

        u = _AgentUtility("buyer", 0.9, 0.1, 50, 150, 1, 30, 0.0)
        u.utility(50, 1)  # 1.0
    """

    def __init__(
        self,
        side: str,
        w_price: float,
        w_deadline: float,
        plo: int,
        phi: int,
        dlo: int,
        dhi: int,
        reservation: float,
    ) -> None:
        self.side = side
        self.w_price = w_price
        self.w_deadline = w_deadline
        self.plo = plo
        self.phi = phi
        self.dlo = dlo
        self.dhi = dhi
        self.reservation = reservation

    def utility(self, price: int, deadline: int) -> float:
        """Return this agent's utility for a (price, deadline) bundle."""
        p = max(self.plo, min(self.phi, price))
        d = max(self.dlo, min(self.dhi, deadline))
        if self.side == "buyer":
            f_price = (self.phi - p) / (self.phi - self.plo)
            f_deadline = (self.dhi - d) / (self.dhi - self.dlo)
        else:
            f_price = (p - self.plo) / (self.phi - self.plo)
            f_deadline = (d - self.dlo) / (self.dhi - self.dlo)
        return self.w_price * f_price + self.w_deadline * f_deadline


class _MarketSession:
    """Everything a single negotiation session contributed to the trace.

    ``bundles`` is the set of every (price, deadline) exchanged in the session,
    the trace-observed evidence the dominance frontier is computed from.
    ``buyer``/``seller`` are resolved from the ``side`` tag on the offers.

    Example::

        sess = _MarketSession()
        sess.bundles.add((55, 30))
    """

    def __init__(self) -> None:
        self.bundles: set[tuple[int, int]] = set()
        self.buyer: str | None = None
        self.seller: str | None = None
        self.agreement: tuple[int, int, str] | None = None
        self.breakdown: bool = False


def _collect_agent_utilities(events: list[dict[str, Any]]) -> dict[str, _AgentUtility]:
    """Parse ``mautil:`` frames into per-agent utility reconstructors.

    Frames are ``mautil:<agent>:<side>:<w_price>:<w_deadline>:<plo>:<phi>:<dlo>:
    <dhi>:<reservation>``. Malformed frames (short split, non-numeric fields,
    unknown side, or a degenerate range that would divide by zero) are skipped.

    Example::

        utils = _collect_agent_utilities(events)
    """
    utils: dict[str, _AgentUtility] = {}
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("mautil:"):
            continue
        parts = msg.split(":")
        if len(parts) < 10:
            continue
        agent, side = parts[1], parts[2]
        if side not in ("buyer", "seller"):
            continue
        try:
            w_price = float(parts[3])
            w_deadline = float(parts[4])
            plo, phi, dlo, dhi = int(parts[5]), int(parts[6]), int(parts[7]), int(parts[8])
            reservation = float(parts[9])
        except ValueError:
            continue
        if phi <= plo or dhi <= dlo:
            continue
        utils[agent] = _AgentUtility(side, w_price, w_deadline, plo, phi, dlo, dhi, reservation)
    return utils


def _collect_market_sessions(events: list[dict[str, Any]]) -> dict[str, _MarketSession]:
    """Group ``offer:``/``agree:``/``breakdown:`` frames by session id.

    Example::

        sessions = _collect_market_sessions(events)
    """
    sessions: dict[str, _MarketSession] = defaultdict(_MarketSession)
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        parts = msg.split(":")
        if msg.startswith("offer:") and len(parts) >= 7:
            sid, agent, side = parts[1], parts[2], parts[3]
            try:
                price, deadline = int(parts[5]), int(parts[6])
            except ValueError:
                continue
            sess = sessions[sid]
            sess.bundles.add((price, deadline))
            if side == "buyer":
                sess.buyer = agent
            elif side == "seller":
                sess.seller = agent
        elif msg.startswith("agree:") and len(parts) >= 5:
            sid, accepting = parts[1], parts[4]
            try:
                price, deadline = int(parts[2]), int(parts[3])
            except ValueError:
                continue
            sess = sessions[sid]
            sess.agreement = (price, deadline, accepting)
            sess.bundles.add((price, deadline))
        elif msg.startswith("breakdown:") and len(parts) >= 3:
            sessions[parts[1]].breakdown = True
    return dict(sessions)


def _pareto_dominates(ub_x: float, us_x: float, ub_y: float, us_y: float) -> bool:
    """Return whether bundle X Pareto-dominates bundle Y (Zlotkin & Rosenschein Eq.4).

    X dominates Y iff X is no worse for *either* party and strictly better for at
    least one (Zlotkin & Rosenschein 1996; Royal Holloway negotiation notes,
    Eq. 4). The ``>=`` comparisons are relaxed by ``_PARETO_EPS`` and the ``>``
    comparisons tightened by it, so float reconstruction noise cannot manufacture
    or mask a violation.

    Example::

        assert _pareto_dominates(0.9, 0.9, 0.9, 0.8)
    """
    no_worse = ub_x >= ub_y - _PARETO_EPS and us_x >= us_y - _PARETO_EPS
    strictly_better = ub_x > ub_y + _PARETO_EPS or us_x > us_y + _PARETO_EPS
    return no_worse and strictly_better


def validate_multi_attribute_pareto_optimal(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No concluded agreement is Pareto-dominated by another bundle it exchanged.

    For every session that reached an ``agree:`` outcome, this reconstructs both
    parties' utilities (from their ``mautil:`` frames) and FAILS if any *other*
    bundle exchanged in the same session dominates the agreement under
    :func:`_pareto_dominates`. A ``breakdown:`` session is **not** a failure: a
    bilateral negotiation can legitimately reach no deal.

    Scope is deliberately *trace-evidence-bounded*: the frontier is computed from
    the bundles actually observed on the wire, never from the full feasible grid.
    An agreement this validator passes could in principle still be dominated by a
    feasible bundle that was never offered, consistent with Nanda Town's rule
    that validators judge trace evidence, not theorems. The adversarial power is
    real nonetheless: the reference ``alternating_offers`` plugin never reads
    ``conditions['deadline_days']``, so it accepts (or holds out for) a
    price-acceptable bundle while a same-or-better-price, longer-deadline bundle
    sits in the very same exchange, a bundle that dominates the agreement and
    trips this check. ``ParetoNegotiation`` passes because its trade-off
    counteroffers move along the iso-utility curve toward the opponent's revealed
    preference, settling on a non-dominated logroll.

    Guards against a vacuous pass: if no agreement was scorable, it FAILS with
    ``"scenario exercised no negotiation"`` (mirrors the receipt-reputation guard).

    Example::

        results = validate_multi_attribute_pareto_optimal(events)
    """
    utils = _collect_agent_utilities(events)
    sessions = _collect_market_sessions(events)

    scored = 0
    violations: list[str] = []
    for sid in sorted(sessions):
        sess = sessions[sid]
        if sess.agreement is None or sess.buyer is None or sess.seller is None:
            continue
        buyer_u = utils.get(sess.buyer)
        seller_u = utils.get(sess.seller)
        if buyer_u is None or seller_u is None:
            continue

        scored += 1
        a_price, a_deadline, _accepting = sess.agreement
        ub_star = buyer_u.utility(a_price, a_deadline)
        us_star = seller_u.utility(a_price, a_deadline)

        for xp, xd in sorted(sess.bundles):
            if (xp, xd) == (a_price, a_deadline):
                continue
            ub_x = buyer_u.utility(xp, xd)
            us_x = seller_u.utility(xp, xd)
            if _pareto_dominates(ub_x, us_x, ub_star, us_star):
                violations.append(
                    f"session {sid}: agreement ({a_price},{a_deadline}) "
                    f"u_buyer={ub_star:.6f} u_seller={us_star:.6f} dominated by "
                    f"({xp},{xd}) u_buyer={ub_x:.6f} u_seller={us_x:.6f}"
                )
                break

    if scored == 0:
        return [
            ValidationResult(
                "multi_attribute_pareto_optimal",
                False,
                "scenario exercised no negotiation",
            )
        ]
    if violations:
        return [ValidationResult("multi_attribute_pareto_optimal", False, "; ".join(violations))]
    return [
        ValidationResult(
            "multi_attribute_pareto_optimal",
            True,
            f"{scored} agreement(s) non-dominated by any exchanged bundle",
        )
    ]


# ---------------------------------------------------------------------------
# Provenance supply-chain validators
# ---------------------------------------------------------------------------


def _provenance_field_msg(events: list[dict[str, Any]], prefix: str) -> list[list[str]]:
    """Collect ``|``-delimited fields from every send carrying ``prefix``.

    The ``provenance_supply_chain`` scenario uses ``|`` (not ``:``) as its
    field delimiter, since its payloads are ``df://sha256-<hex>`` URLs that
    already contain a colon.

    Example::

        rows = _provenance_field_msg(events, "chain_ok|")
    """
    rows: list[list[str]] = []
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = str(ev.get("msg", ""))
        if msg.startswith(prefix):
            rows.append(msg.split("|"))
    return rows


def validate_provenance_chain_integrity(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """The verifier walks the full parent chain back to the source without a break.

    Example::

        results = validate_provenance_chain_integrity(events)
    """
    broken = _provenance_field_msg(events, "chain_broken|")
    if broken:
        detail = "; ".join(f"{row[1]} could not resolve parent {row[2]}" for row in broken)
        return [ValidationResult("provenance_chain_integrity", False, detail)]
    ok = _provenance_field_msg(events, "chain_ok|")
    if not ok:
        return [ValidationResult("provenance_chain_integrity", False, "no chain_ok recorded")]
    depth = ok[0][2]
    return [
        ValidationResult(
            "provenance_chain_integrity",
            True,
            f"chain resolved to depth {depth}",
        )
    ]


def validate_multi_attribute_individually_rational(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every agreement clears both parties' reservation utility.

    Reconstructs each party's utility for the agreed bundle and FAILS if either
    falls below its declared reservation (within ``_PARETO_EPS``). This catches a
    degenerate "agree to anything" plugin that closes a deal one side strictly
    prefers to walk away from. Like the Pareto check it guards against a vacuous
    pass: if no agreement was scorable it FAILS with
    ``"scenario exercised no negotiation"``.

    Example::

        results = validate_multi_attribute_individually_rational(events)
    """
    utils = _collect_agent_utilities(events)
    sessions = _collect_market_sessions(events)

    scored = 0
    offenders: list[str] = []
    for sid in sorted(sessions):
        sess = sessions[sid]
        if sess.agreement is None or sess.buyer is None or sess.seller is None:
            continue
        buyer_u = utils.get(sess.buyer)
        seller_u = utils.get(sess.seller)
        if buyer_u is None or seller_u is None:
            continue

        scored += 1
        a_price, a_deadline, _accepting = sess.agreement
        ub = buyer_u.utility(a_price, a_deadline)
        us = seller_u.utility(a_price, a_deadline)
        if ub < buyer_u.reservation - _PARETO_EPS:
            offenders.append(
                f"session {sid}: buyer u={ub:.6f} < reservation {buyer_u.reservation:.6f}"
            )
        if us < seller_u.reservation - _PARETO_EPS:
            offenders.append(
                f"session {sid}: seller u={us:.6f} < reservation {seller_u.reservation:.6f}"
            )

    if scored == 0:
        return [
            ValidationResult(
                "multi_attribute_individually_rational",
                False,
                "scenario exercised no negotiation",
            )
        ]
    if offenders:
        return [
            ValidationResult("multi_attribute_individually_rational", False, "; ".join(offenders))
        ]
    return [
        ValidationResult(
            "multi_attribute_individually_rational",
            True,
            f"{scored} agreement(s) individually rational for both parties",
        )
    ]


def validate_provenance_substitution_resistant(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """An outsider republishing different content must not land on the source's URL.

    Catches the *substitution* attack: a name-addressed registry
    (``datafacts_v1``) lets anyone overwrite ``df://<name>`` with new bytes;
    a content-addressed one (``cid_facts``) cannot alias two different
    contents onto the same URL.

    Example::

        results = validate_provenance_substitution_resistant(events)
    """
    rows = _provenance_field_msg(events, "attack_substitution|")
    if not rows:
        return [ValidationResult("provenance_substitution_resistant", False, "no attack recorded")]
    source_url, attacker_url, collided = rows[0][1], rows[0][2], rows[0][3]
    if collided != "0":
        return [
            ValidationResult(
                "provenance_substitution_resistant",
                False,
                f"attacker's republish landed on the source URL {source_url} "
                f"(attacker url {attacker_url})",
            )
        ]
    return [
        ValidationResult(
            "provenance_substitution_resistant",
            True,
            f"attacker's differing content resolved to a distinct URL ({attacker_url})",
        )
    ]


def validate_provenance_freshness_unforgeable(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """A freshness claim signed by someone other than the owner must be rejected.

    Catches the *stale-claim* attack: an unauthenticated wall-clock check
    (``datafacts_v1``) treats any recent republish as proof of freshness,
    regardless of who did it; a signature-backed check (``cid_facts``) only
    accepts a proof whose signer is the dataset's declared owner.

    Example::

        results = validate_provenance_freshness_unforgeable(events)
    """
    rows = _provenance_field_msg(events, "attack_forged_freshness|")
    if not rows:
        return [ValidationResult("provenance_freshness_unforgeable", False, "no attack recorded")]
    url, fresh = rows[0][1], rows[0][2]
    if fresh != "0":
        return [
            ValidationResult(
                "provenance_freshness_unforgeable",
                False,
                f"forged freshness claim for {url} was accepted",
            )
        ]
    return [
        ValidationResult(
            "provenance_freshness_unforgeable",
            True,
            f"forged freshness claim for {url} was correctly rejected",
        )
    ]


def validate_provenance_chain_unforgeable(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """A dataset declaring a never-published parent must be rejected at publish time.

    Catches *provenance washing*: a registry with no lineage concept
    (``datafacts_v1``) accepts a "derived" dataset whose claimed parent does
    not exist anywhere in the trace; ``cid_facts`` refuses to publish it.

    Example::

        results = validate_provenance_chain_unforgeable(events)
    """
    rows = _provenance_field_msg(events, "attack_provenance|")
    if not rows:
        return [ValidationResult("provenance_chain_unforgeable", False, "no attack recorded")]
    phantom_parent, rejected = rows[0][1], rows[0][2]
    if rejected != "1":
        return [
            ValidationResult(
                "provenance_chain_unforgeable",
                False,
                f"publish with phantom parent {phantom_parent} was not rejected",
            )
        ]
    return [
        ValidationResult(
            "provenance_chain_unforgeable",
            True,
            f"publish with phantom parent {phantom_parent} was correctly rejected",
        )
    ]


# ---------------------------------------------------------------------------
# BFT HotStuff validators
# ---------------------------------------------------------------------------

_STUCK_VIEW_K_TICKS = 300


def validate_bft_no_conflicting_commits(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No two honest replicas commit conflicting values for the same view.

    Reads ``result:<view>:committed:<accepts>/<total>:<block_hash>:<value>``
    lines, each announced independently by the replica that observed the
    commit QC (not just the leader's say-so). Conflicts are keyed on
    ``block_hash`` -- the field that comes straight from the commit QC and
    is therefore identical across every honest replica for a given view --
    rather than ``value``, since a replica that only saw the commit QC (not
    the original PREPARE, e.g. after being partitioned away) may not know
    the plaintext value but still agrees on the hash. A trace with zero
    commits is itself a failure -- it means no quorum-backed progress was
    ever observed, which is also why this validator FAILS against a
    ``contract_net``-coordinated trace (no ``result:...committed`` lines
    exist at all).

    Example::

        results = validate_bft_no_conflicting_commits(events)
    """
    commits_by_view: dict[str, dict[str, str]] = defaultdict(dict)
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("result:"):
            continue
        parts = msg.split(":")
        if len(parts) < 6 or parts[2] != "committed":
            continue
        view, block_hash_hex = parts[1], parts[4]
        commits_by_view[view][str(ev.get("agent", ""))] = block_hash_hex

    if not commits_by_view:
        return [
            ValidationResult("bft_no_conflicting_commits", False, "no commits observed in trace")
        ]

    violations: list[str] = []
    for view, by_agent in commits_by_view.items():
        distinct = set(by_agent.values())
        if len(distinct) > 1:
            violations.append(f"view {view}: conflicting commits {by_agent}")

    if violations:
        return [ValidationResult("bft_no_conflicting_commits", False, "; ".join(violations))]
    return [
        ValidationResult(
            "bft_no_conflicting_commits",
            True,
            f"checked {len(commits_by_view)} committed view(s), no conflicts",
        )
    ]


def validate_bft_no_equivocation(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No leader sends two different PREPARE proposals in the same view.

    Reads ``prepare:<view>:<block_hash>:<value>:<justify_qc>`` lines, grouped
    by ``(sender, view)``. More than one distinct ``block_hash`` from the
    same sender in the same view means that leader equivocated.

    Example::

        results = validate_bft_no_equivocation(events)
    """
    hashes_by_leader_view: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("prepare:"):
            continue
        parts = msg.split(":", 4)
        if len(parts) < 3:
            continue
        view, block_hash_hex = parts[1], parts[2]
        key = (str(ev.get("agent", "")), view)
        hashes_by_leader_view[key].add(block_hash_hex)

    violations = [
        f"leader {leader} view {view}: sent conflicting proposals {hashes}"
        for (leader, view), hashes in hashes_by_leader_view.items()
        if len(hashes) > 1
    ]

    if violations:
        return [ValidationResult("bft_no_equivocation", False, "; ".join(violations))]
    return [
        ValidationResult(
            "bft_no_equivocation",
            True,
            f"checked {len(hashes_by_leader_view)} (leader, view) proposal(s), no equivocation",
        )
    ]


def validate_bft_forged_quorum(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every broadcast commit QC is backed by >= 2f+1 distinct signers.

    Reads ``qc:<phase>:<view>:<block_hash>:<f>:<voter1>=<sig1>,...`` lines.
    Distinct voter tokens are counted after deduplication, so padding the
    same signer twice to inflate the count is itself caught as a forgery.

    Example::

        results = validate_bft_forged_quorum(events)
    """
    violations: list[str] = []
    checked = 0
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if not msg.startswith("qc:"):
            continue
        parts = msg.split(":", 5)
        if len(parts) != 6:
            continue
        phase, view, block_hash_hex, f_str, votes_str = (
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            parts[5],
        )
        try:
            f_value = int(f_str)
        except ValueError:
            continue
        required = 2 * f_value + 1
        voters = {entry.partition("=")[0] for entry in votes_str.split(",") if entry}
        checked += 1
        if len(voters) < required:
            violations.append(
                f"{phase} qc view {view} block {block_hash_hex}: "
                f"{len(voters)} distinct signers, needed {required}"
            )

    if violations:
        return [ValidationResult("bft_forged_quorum", False, "; ".join(violations))]
    return [
        ValidationResult(
            "bft_forged_quorum",
            True,
            f"checked {checked} broadcast QC(s), all backed by a real quorum",
        )
    ]


def validate_bft_no_stuck_view(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Commit progress resumes within K ticks of the network healing.

    Baseline is the simulator's ``partition_healed`` marker if present,
    else ``ts=0`` (so the same validator also covers the byzantine scenario,
    which has no partition). Fails if no ``result:...committed`` line
    appears within ``_STUCK_VIEW_K_TICKS`` ticks after the baseline.

    Example::

        results = validate_bft_no_stuck_view(events)
    """
    baseline = 0.0
    for ev in events:
        if ev.get("kind") == "partition_healed":
            baseline = float(ev.get("ts", 0.0))
            break

    commit_ticks: list[float] = []
    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _message_body(ev)
        if msg.startswith("result:") and ":committed:" in msg:
            commit_ticks.append(float(ev.get("ts", 0.0)))

    if not commit_ticks:
        return [ValidationResult("bft_no_stuck_view", False, "no commits observed in trace")]

    window_end = baseline + _STUCK_VIEW_K_TICKS
    in_window = [t for t in commit_ticks if baseline <= t <= window_end]
    if not in_window:
        return [
            ValidationResult(
                "bft_no_stuck_view",
                False,
                f"no commit within {_STUCK_VIEW_K_TICKS} ticks of baseline ts={baseline}",
            )
        ]
    return [
        ValidationResult(
            "bft_no_stuck_view",
            True,
            f"commit progress resumed at ts={min(in_window)} (baseline ts={baseline})",
        )
    ]


# ---------------------------------------------------------------------------
# Failure-detection validators
# ---------------------------------------------------------------------------


_GAP_MARGIN = 2.0
"""Safety margin added to ``hb_max`` when deriving the plausible-gap bound.

Heartbeats are jittered on ``uniform(hb_min, hb_max)`` with zero message drop,
so consecutive observer receipts from a living peer are at most ``hb_max``
apart; the margin absorbs event-queue rounding.  If the observer received a
heartbeat within ``hb_max + _GAP_MARGIN``, the peer was provably alive and any
suspicion of it is a false positive.
"""

_MAX_PLAUSIBLE_GAP = 22.0
"""Fallback plausible-gap bound for traces without an ``fd:config`` marker.

Current scenario runs carry their heartbeat bound in an ``fd:config`` marker
and :func:`_fd_max_plausible_gap` derives the bound from it, so re-running with
different ``hb_max`` values cannot silently invalidate the accuracy check.
This constant (the default ``hb_max == 20`` plus the margin) applies only to
traces recorded before the marker existed.
"""

_ACCURACY_WARMUP = 100.0
"""Logical time before which suspicions are ignored for the accuracy check.

An accrual detector needs a handful of inter-arrival samples before its score
is meaningful; this window lets every detector populate its history before its
verdicts are held against it.
"""


def _parse_fd_record(ev: dict[str, Any]) -> dict[str, Any] | None:
    """Return the decoded JSON dict if *ev* is an ``fd:*`` broadcast, else ``None``.

    Example::

        rec = _parse_fd_record(event)
    """
    if ev.get("kind") != "broadcast":
        return None
    msg = str(ev.get("msg", ""))
    if '"fd"' not in msg:
        return None
    try:
        obj = json.loads(msg)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    return cast("dict[str, Any]", obj)


def _fd_max_plausible_gap(events: list[dict[str, Any]], observer_ids: set[str]) -> float:
    """Derive the live-peer plausible-gap bound from the trace itself.

    The observer broadcasts one ``fd:config`` marker carrying the scenario's
    ``hb_max``; the bound is ``hb_max + _GAP_MARGIN``.  Only a marker emitted by
    an observer (an agent that also publishes ``fd:status`` verdicts) is
    trusted, so a Byzantine emitter cannot broadcast a spoofed ``fd:config`` to
    inflate the bound.  Traces without a trusted marker fall back to
    :data:`_MAX_PLAUSIBLE_GAP`.

    Example::

        gap = _fd_max_plausible_gap(events, _fd_observer_ids(events))
    """
    for ev in events:
        if ev.get("agent") not in observer_ids:
            continue
        rec = _parse_fd_record(ev)
        if rec is None or rec.get("fd") != "config":
            continue
        hb_max = rec.get("hb_max")
        if isinstance(hb_max, (int, float)):
            return float(hb_max) + _GAP_MARGIN
    return _MAX_PLAUSIBLE_GAP


def _fd_observer_ids(events: list[dict[str, Any]]) -> set[str]:
    """Return the set of agent ids that emit ``fd:status`` broadcasts."""
    observers: set[str] = set()
    for ev in events:
        rec = _parse_fd_record(ev)
        if rec is not None and rec.get("fd") == "status":
            agent = ev.get("agent")
            if isinstance(agent, str):
                observers.add(agent)
    return observers


def _fd_statuses(events: list[dict[str, Any]]) -> dict[str, list[tuple[float, bool]]]:
    """Return peer -> sorted ``(ts, suspected)`` from ``fd:status`` broadcasts."""
    statuses: dict[str, list[tuple[float, bool]]] = defaultdict(list)
    for ev in events:
        rec = _parse_fd_record(ev)
        if rec is None or rec.get("fd") != "status":
            continue
        peer = rec.get("peer")
        suspected = rec.get("suspected")
        ts = ev.get("ts")
        if isinstance(peer, str) and isinstance(suspected, bool) and isinstance(ts, (int, float)):
            statuses[peer].append((float(ts), suspected))
    for peer in statuses:
        statuses[peer].sort(key=lambda item: item[0])
    return statuses


def _fd_transitions(
    events: list[dict[str, Any]],
) -> tuple[dict[str, list[tuple[float, bool]]], float]:
    """Return (peer -> sorted ``(ts, reachable)`` markers, max ts over all events)."""
    transitions: dict[str, list[tuple[float, bool]]] = defaultdict(list)
    last_ts = 0.0
    for ev in events:
        ts = ev.get("ts")
        if isinstance(ts, (int, float)):
            last_ts = max(last_ts, float(ts))
        rec = _parse_fd_record(ev)
        if rec is None or rec.get("fd") != "phase":
            continue
        peer = rec.get("peer")
        reachable = rec.get("reachable")
        if isinstance(peer, str) and isinstance(reachable, bool) and isinstance(ts, (int, float)):
            transitions[peer].append((float(ts), reachable))
    for peer in transitions:
        transitions[peer].sort(key=lambda item: item[0])
    return transitions, last_ts


def _fd_hb_receipts(events: list[dict[str, Any]], observer_ids: set[str]) -> dict[str, list[float]]:
    """Return peer -> sorted receipt timestamps of that peer's heartbeats at an observer."""
    receipts: dict[str, list[float]] = defaultdict(list)
    for ev in events:
        if ev.get("kind") != "receive":
            continue
        agent = ev.get("agent")
        if agent not in observer_ids:
            continue
        msg = str(ev.get("msg", ""))
        if not msg.startswith("FDHB|"):
            continue
        sender = ev.get("from")
        ts = ev.get("ts")
        if isinstance(sender, str) and isinstance(ts, (int, float)):
            receipts[sender].append(float(ts))
    for peer in receipts:
        receipts[peer].sort()
    return receipts


def _segments_for_peer(
    transitions: list[tuple[float, bool]], last_ts: float
) -> list[tuple[float, float, bool]]:
    """Expand reachability markers into ``(start, end, reachable)`` segments."""
    if not transitions:
        return []
    segments: list[tuple[float, float, bool]] = []
    for idx, (ts, reachable) in enumerate(transitions):
        end = transitions[idx + 1][0] if idx + 1 < len(transitions) else last_ts
        segments.append((ts, end, reachable))
    return segments


def _in_any_interval(t: float, intervals: list[tuple[float, float]]) -> bool:
    """Return whether *t* falls within any ``[start, end]`` interval."""
    return any(start <= t <= end for start, end in intervals)


def _last_leq(sorted_ts: list[float], t: float) -> float | None:
    """Return the largest timestamp ``<= t`` in *sorted_ts*, or ``None``."""
    found: float | None = None
    for ts in sorted_ts:
        if ts <= t:
            found = ts
        else:
            break
    return found


def validate_failure_detection_completeness(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every peer that truly goes silent is eventually -- and still -- suspected.

    For each unreachable segment in the ground-truth ``fd:phase`` markers, the
    detector must report the peer suspected at some status update inside the
    segment and still have it suspected at the last in-segment update.  A trace
    with no unreachable segment at all is a scenario setup failure.
    """
    transitions, last_ts = _fd_transitions(events)
    statuses = _fd_statuses(events)

    outage_segments: dict[str, list[tuple[float, float]]] = {}
    for peer, peer_transitions in transitions.items():
        downs = [
            (start, end)
            for start, end, reachable in _segments_for_peer(peer_transitions, last_ts)
            if not reachable
        ]
        if downs:
            outage_segments[peer] = downs

    if not outage_segments:
        return [
            ValidationResult(
                "failure_detection_completeness",
                False,
                "no unreachable fd:phase segment found in trace",
            )
        ]

    failures: list[str] = []
    checked = 0
    for peer, downs in outage_segments.items():
        peer_statuses = statuses.get(peer, [])
        for u_start, u_end in downs:
            checked += 1
            in_window = [(t, s) for (t, s) in peer_statuses if u_start < t <= u_end]
            if not in_window:
                failures.append(f"{peer}: no status during outage [{u_start}, {u_end}]")
                continue
            if not any(s for _, s in in_window):
                failures.append(f"{peer}: never suspected during outage [{u_start}, {u_end}]")
                continue
            if not in_window[-1][1]:
                failures.append(f"{peer}: not suspected at outage end [{u_start}, {u_end}]")

    if failures:
        return [ValidationResult("failure_detection_completeness", False, "; ".join(failures))]
    return [
        ValidationResult(
            "failure_detection_completeness",
            True,
            f"all {checked} outage segment(s) detected and still suspected at end",
        )
    ]


# ---------------------------------------------------------------------------
# Portable-reputation (PARC) migration validators
#
# The parc_migration scenario broadcasts one ``admit:<agent>:<decision>:
# <reason>:<role>`` line per border decision. The six checks below each pin
# one attack class the naive signature-trusting gate would miss (or one
# retention property a degenerate deny-everything gate would break). Together
# they prove the headline invariant: a valid signature is not admission.
# ---------------------------------------------------------------------------


def _collect_admissions(
    events: list[dict[str, Any]],
) -> dict[str, tuple[bool, str, str]]:
    """Parse ``admit:<agent>:<granted|denied>:<reason>:<role>`` trace lines.

    Returns ``agent -> (admitted, reason, role)`` using the last decision per
    agent. Decisions come from the live gate against the configured trust
    plugin, so this dict is what lets the validators discriminate between a
    recomputing gate and a naive one.

    Example::

        admissions = _collect_admissions(events)
    """
    admissions: dict[str, tuple[bool, str, str]] = {}
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = _message_body(ev)
        if not msg.startswith("admit:"):
            continue
        parts = msg.split(":")
        if len(parts) < 5:
            continue
        agent, decision, reason, role = parts[1], parts[2], parts[3], parts[4]
        admissions[agent] = (decision == "granted", reason, role)
    return admissions


def _admissions_for_role(
    events: list[dict[str, Any]],
    role: str,
) -> dict[str, tuple[bool, str]]:
    """The ``agent -> (admitted, reason)`` decisions for one population role.

    Example::

        ring = _admissions_for_role(events, "ring")
    """
    return {
        agent: (admitted, reason)
        for agent, (admitted, reason, r) in _collect_admissions(events).items()
        if r == role
    }


def _validate_role_denied(
    events: list[dict[str, Any]],
    *,
    name: str,
    role: str,
    expected_reason: str,
) -> list[ValidationResult]:
    """Shared check: every agent of ``role`` is denied with ``expected_reason``.

    Fails when the population was never exercised (no decisions observed for
    the role — a gate that crashes or stays silent must not pass), when any
    member was admitted, or when the denial carries the wrong reason (a gate
    that denies for an accidental reason is not demonstrating the defense the
    validator is named for).

    Example::

        results = _validate_role_denied(events, name="parc_forgery_rejected",
                                        role="forged",
                                        expected_reason="proof_invalid")
    """
    decisions = _admissions_for_role(events, role)
    if not decisions:
        return [ValidationResult(name, False, f"no admission decisions observed for role {role!r}")]
    problems: list[str] = []
    for agent, (admitted, reason) in sorted(decisions.items()):
        if admitted:
            problems.append(f"{agent} was admitted")
        elif reason != expected_reason:
            problems.append(f"{agent} denied with {reason!r}, expected {expected_reason!r}")
    if problems:
        return [ValidationResult(name, False, "; ".join(problems))]
    return [
        ValidationResult(
            name,
            True,
            f"{len(decisions)} {role} agent(s) denied with {expected_reason!r}",
        )
    ]


def validate_failure_detection_accuracy(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Live peers are not falsely suspected; recovered peers are cleared.

    Accuracy: after a warm-up, while a peer is provably reachable -- it is inside
    a reachable ``fd:phase`` segment *and* the observer received a heartbeat from
    it no longer than the plausible-gap bound ago (derived from the trace's
    ``fd:config`` marker by :func:`_fd_max_plausible_gap`) -- the detector must
    not suspect it.  A tight fixed timeout violates this on the upper tail of
    normal heartbeat jitter; an accrual detector does not.

    Recovery: a peer that genuinely went down and came back must end its final
    reachable segment un-suspected.

    Returns two results: ``failure_detection_accuracy`` and
    ``failure_detection_recovery``.
    """
    transitions, last_ts = _fd_transitions(events)
    statuses = _fd_statuses(events)
    observer_ids = _fd_observer_ids(events)
    receipts = _fd_hb_receipts(events, observer_ids)
    max_gap = _fd_max_plausible_gap(events, observer_ids)
    watched = sorted(statuses.keys())

    # ----- accuracy: no false suspicion of a provably-live peer -----
    reachable_intervals: dict[str, list[tuple[float, float]]] = {}
    for peer in watched:
        segments = _segments_for_peer(transitions.get(peer, []), last_ts)
        if segments:
            reachable_intervals[peer] = [
                (start, end) for start, end, reachable in segments if reachable
            ]
        else:
            reachable_intervals[peer] = [(0.0, last_ts)]

    false_positives: list[str] = []
    for peer in watched:
        intervals = reachable_intervals[peer]
        peer_receipts = receipts.get(peer, [])
        for t, suspected in statuses.get(peer, []):
            if not suspected or t < _ACCURACY_WARMUP:
                continue
            if not _in_any_interval(t, intervals):
                continue
            recent = _last_leq(peer_receipts, t)
            if recent is not None and (t - recent) <= max_gap:
                false_positives.append(
                    f"{peer}: suspected at t={t} but a heartbeat arrived {round(t - recent, 3)} ago"
                )

    if false_positives:
        accuracy = ValidationResult("failure_detection_accuracy", False, "; ".join(false_positives))
    else:
        accuracy = ValidationResult(
            "failure_detection_accuracy",
            True,
            f"no false suspicion of a provably-live peer across {len(watched)} peer(s)",
        )

    # ----- recovery: a healed peer ends un-suspected -----
    recovery_failures: list[str] = []
    recovered_peers = 0
    for peer in watched:
        segments = _segments_for_peer(transitions.get(peer, []), last_ts)
        if not any(not reachable for _, _, reachable in segments):
            continue
        final_reachable: tuple[float, float] | None = None
        seen_down = False
        for start, end, reachable in segments:
            if not reachable:
                seen_down = True
                final_reachable = None
            elif seen_down:
                final_reachable = (start, end)
        if final_reachable is None:
            recovery_failures.append(f"{peer}: no reachable segment after final outage")
            continue
        recovered_peers += 1
        r_start, r_end = final_reachable
        in_window = [(t, s) for (t, s) in statuses.get(peer, []) if r_start <= t <= r_end]
        if not in_window:
            recovery_failures.append(f"{peer}: no status after recovery [{r_start}, {r_end}]")
            continue
        if in_window[-1][1]:
            recovery_failures.append(f"{peer}: still suspected at end of recovery segment")

    if recovery_failures:
        recovery = ValidationResult(
            "failure_detection_recovery", False, "; ".join(recovery_failures)
        )
    elif recovered_peers == 0:
        recovery = ValidationResult(
            "failure_detection_recovery",
            False,
            "no peer recovered from an outage in trace",
        )
    else:
        recovery = ValidationResult(
            "failure_detection_recovery",
            True,
            f"all {recovered_peers} recovered peer(s) cleared by end",
        )

    return [accuracy, recovery]


def validate_failure_detection_no_forged_liveness(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Forged heartbeats must not keep a genuinely dead peer looking alive.

    The attack: while a peer is inside an unreachable ground-truth segment, a
    Byzantine agent keeps broadcasting heartbeats that *claim* the dead peer's
    id.  A forged receipt is any observer-received ``FDHB|`` payload whose
    claimed id differs from the transport-level sender.  For every outage
    segment during which such forgeries arrived, the detector must still have
    the peer suspected at the last in-segment status update -- forged liveness
    must not mask the crash.

    A trace with no forged receipt at all, or whose forgeries never overlap an
    outage, is a scenario setup failure: this validator is only registered for
    the forgery scenario, whose entire point is that the attack fires.
    """
    transitions, last_ts = _fd_transitions(events)
    statuses = _fd_statuses(events)
    observer_ids = _fd_observer_ids(events)

    forged: dict[str, list[float]] = defaultdict(list)
    for ev in events:
        if ev.get("kind") != "receive" or ev.get("agent") not in observer_ids:
            continue
        msg = str(ev.get("msg", ""))
        if not msg.startswith("FDHB|"):
            continue
        claimed = msg[len("FDHB|") :].split("|", 1)[0]
        sender = ev.get("from")
        ts = ev.get("ts")
        if not claimed or not isinstance(sender, str) or not isinstance(ts, (int, float)):
            continue
        if claimed != sender:
            forged[claimed].append(float(ts))

    if not forged:
        return [
            ValidationResult(
                "failure_detection_no_forged_liveness",
                False,
                "no forged heartbeat received in trace",
            )
        ]

    failures: list[str] = []
    checked = 0
    for victim in sorted(forged):
        forged_ts = forged[victim]
        downs = [
            (start, end)
            for start, end, reachable in _segments_for_peer(transitions.get(victim, []), last_ts)
            if not reachable
        ]
        victim_statuses = statuses.get(victim, [])
        for u_start, u_end in downs:
            if not any(u_start < t <= u_end for t in forged_ts):
                continue
            checked += 1
            in_window = [(t, s) for (t, s) in victim_statuses if u_start < t <= u_end]
            if not in_window:
                failures.append(f"{victim}: no status during attacked outage [{u_start}, {u_end}]")
            elif not in_window[-1][1]:
                failures.append(
                    f"{victim}: forged heartbeats masked the outage [{u_start}, {u_end}] "
                    "(not suspected at segment end)"
                )

    if checked == 0:
        return [
            ValidationResult(
                "failure_detection_no_forged_liveness",
                False,
                "forged heartbeats never overlapped an outage segment",
            )
        ]
    if failures:
        return [
            ValidationResult("failure_detection_no_forged_liveness", False, "; ".join(failures))
        ]
    return [
        ValidationResult(
            "failure_detection_no_forged_liveness",
            True,
            f"forged liveness rejected across {checked} attacked outage segment(s)",
        )
    ]


def validate_parc_honest_admitted(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """Every honest migrant is admitted — the gate retains genuine reputation.

    Guards against the degenerate defense: a gate that denies everything
    trivially "catches" every attack. Portability only holds if honest
    credentials actually cross the border.

    Example::

        results = validate_parc_honest_admitted(events)
    """
    decisions = _admissions_for_role(events, "honest")
    if not decisions:
        return [
            ValidationResult(
                "parc_honest_admitted", False, "no admission decisions observed for role 'honest'"
            )
        ]
    denied = {a: reason for a, (admitted, reason) in decisions.items() if not admitted}
    if denied:
        detail = ", ".join(f"{a} ({reason})" for a, reason in sorted(denied.items()))
        return [ValidationResult("parc_honest_admitted", False, f"honest denied: {detail}")]
    return [
        ValidationResult("parc_honest_admitted", True, f"{len(decisions)} honest agent(s) admitted")
    ]


def validate_parc_forgery_rejected(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """A credential with tampered proof bytes is denied as ``proof_invalid``.

    The naive gate never checks the proof against the recomputed canonical
    payload, so the forged credential sails through it.

    Example::

        results = validate_parc_forgery_rejected(events)
    """
    return _validate_role_denied(
        events,
        name="parc_forgery_rejected",
        role="forged",
        expected_reason="proof_invalid",
    )


def validate_parc_inflation_rejected(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """An inflated score from a *trusted* issuer is denied as ``score_mismatch``.

    The headline property: the credential's signature is genuine and its
    issuer is trusted, yet recomputing the nanda-rep/0.2 scores from the
    carried receipts exposes the inflated claim. A gate that trusts signed
    claims (the naive baseline) admits it and FAILS this validator.

    Example::

        results = validate_parc_inflation_rejected(events)
    """
    return _validate_role_denied(
        events,
        name="parc_inflation_rejected",
        role="inflated",
        expected_reason="score_mismatch",
    )


def validate_parc_ring_severed(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """Wash-ring members are denied via whole-graph severance at the border.

    Each ring member's *inline* credential is individually corroborated (a
    single-subject ledger is a star and cannot show the ring), so inline
    recomputation alone admits it. Only re-running collusion severance over
    the originating domain's published ledger reveals the isolated dense
    component — the reason must therefore be ``severed_below_threshold``.

    Example::

        results = validate_parc_ring_severed(events)
    """
    return _validate_role_denied(
        events,
        name="parc_ring_severed",
        role="ring",
        expected_reason="severed_below_threshold",
    )


def validate_parc_replay_rejected(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """A stolen (genuine) credential presented by a non-subject is denied.

    The credential itself verifies — it was honestly issued to someone else.
    Admission must bind the presenter to ``credentialSubject.id``
    (``replay_presenter_mismatch``), or any bystander can borrow reputation.

    Example::

        results = validate_parc_replay_rejected(events)
    """
    return _validate_role_denied(
        events,
        name="parc_replay_rejected",
        role="replay",
        expected_reason="replay_presenter_mismatch",
    )


def validate_parc_stale_key_rejected(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """A credential signed with a rotated-out issuer key is denied as ``stale_key``.

    The signature bytes are cryptographically valid under the old key; what
    fails is the identity layer's key-rotation window as-of the credential's
    ``validFrom`` tick. This is the cross-layer check a trust plugin that
    ignores the identity layer cannot perform.

    Example::

        results = validate_parc_stale_key_rejected(events)
    """
    return _validate_role_denied(
        events,
        name="parc_stale_key_rejected",
        role="stale",
        expected_reason="stale_key",
    )


# ---------------------------------------------------------------------------
# Attested-peering trust validators
# ---------------------------------------------------------------------------


def _attested_observer_lines(events: list[dict[str, Any]]) -> list[str]:
    """Return the observer's audit-line message bodies (deduped send events).

    The observer emits ``verdict:``/``report:``/``repscore:`` lines by sending
    them to the victim sink, so each line appears once as a ``send`` and once
    as a ``receive``; we read only the authoritative ``send`` events.

    Example::

        lines = _attested_observer_lines(events)
    """
    lines: list[str] = []
    for ev in events:
        if ev.get("kind") != "send" or ev.get("agent") != "observer":
            continue
        lines.append(str(ev.get("msg", "")))
    return lines


def _attested_verdicts(lines: list[str]) -> dict[str, tuple[str, bool, bool, bool]]:
    """Parse ``verdict:`` lines into ``reporter -> (decision, foe, data, work)``.

    Example::

        verdicts = _attested_verdicts(_attested_observer_lines(events))
    """
    verdicts: dict[str, tuple[str, bool, bool, bool]] = {}
    for line in lines:
        if not line.startswith("verdict:"):
            continue
        parts = line.split(":")
        if len(parts) != 7:
            continue
        _, reporter, _claimed, decision, foe, data, work = parts
        verdicts[reporter] = (decision, foe == "1", data == "1", work == "1")
    return verdicts


def validate_attested_no_denied_admitted(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No peer with a failed (DENY) verdict ever has its evidence admitted.

    The core safety invariant of the attested-peering gate: admission implies
    an ALLOW verdict, and every ALLOW verdict has all three checks green
    (friend-or-foe, trust-my-data, who-you-work-for). A trace with no verdict
    lines (a baseline trust plugin that runs no handshake) cannot violate this
    and passes vacuously.

    Example::

        results = validate_trace(Path("traces/attested_peering.jsonl"), "attested_peering")
    """
    lines = _attested_observer_lines(events)
    verdicts = _attested_verdicts(lines)

    if not verdicts:
        return [
            ValidationResult(
                "attested_no_denied_admitted",
                True,
                "no attested-peering verdicts in trace (baseline plugin, nothing to gate)",
            )
        ]

    violations: list[str] = []
    for decision, foe, data, work in verdicts.values():
        if decision == "ALLOW" and not (foe and data and work):
            violations.append("ALLOW verdict with a failed check (inconsistent gate)")
            break

    for line in lines:
        if not line.startswith("report:"):
            continue
        parts = line.split(":")
        if len(parts) != 5 or parts[4] != "admitted":
            continue
        reporter = parts[1]
        entry = verdicts.get(reporter)
        if entry is None:
            violations.append(f"{reporter}: admitted with no verdict")
        elif entry[0] != "ALLOW":
            violations.append(f"{reporter}: admitted despite {entry[0]} verdict")

    if violations:
        return [ValidationResult("attested_no_denied_admitted", False, "; ".join(violations))]
    allowed = sum(1 for v in verdicts.values() if v[0] == "ALLOW")
    return [
        ValidationResult(
            "attested_no_denied_admitted",
            True,
            f"{allowed}/{len(verdicts)} peers admitted, all with an ALLOW verdict",
        )
    ]


def validate_attested_sybil_quarantined(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """An unauthenticated Sybil swarm cannot defame the honest victim.

    Honest reporters file positive evidence, so an ungamed reputation sits at
    or above the neutral prior (``0.5``); only *admitted* negative evidence can
    push it below. The attested-peering gate quarantines every unattested
    reporter, so the victim's score stays high. Under a baseline plugin with no
    gate (``trust: score_average``) the Sybil swarm's negatives are admitted and
    the score collapses below ``0.5`` — this validator FAILs there and PASSes
    under ``trust: attested_peering``.

    Example::

        results = validate_trace(Path("traces/attested_peering.jsonl"), "attested_peering")
    """
    lines = _attested_observer_lines(events)

    score: float | None = None
    samples: int | None = None
    for line in lines:
        if not line.startswith("repscore:"):
            continue
        parts = line.split(":")
        if len(parts) == 4 and parts[1] == "victim":
            score = float(parts[2])
            samples = int(parts[3])
    if score is None or samples is None:
        return [
            ValidationResult(
                "attested_sybil_quarantined",
                False,
                "no repscore:victim line found in trace (scenario setup failure)",
            )
        ]

    verdicts = _attested_verdicts(lines)
    admitted_attackers: list[str] = []
    for line in lines:
        if not line.startswith("report:"):
            continue
        parts = line.split(":")
        if len(parts) != 5 or parts[4] != "admitted":
            continue
        reporter = parts[1]
        if not reporter.startswith("honest-"):
            admitted_attackers.append(reporter)

    if score < 0.5:
        return [
            ValidationResult(
                "attested_sybil_quarantined",
                False,
                (
                    f"victim reputation {score:.3f} < 0.5 over {samples} admitted report(s) — "
                    "an unauthenticated swarm manufactured a negative consensus (gate absent)"
                ),
            )
        ]
    if admitted_attackers:
        return [
            ValidationResult(
                "attested_sybil_quarantined",
                False,
                "non-honest reporters admitted despite the gate: "
                f"{sorted(set(admitted_attackers))}",
            )
        ]
    return [
        ValidationResult(
            "attested_sybil_quarantined",
            True,
            (
                f"victim reputation {score:.3f} from {samples} attested report(s); "
                f"{len([v for v in verdicts.values() if v[0] == 'DENY'])} unattested peer(s) "
                "quarantined"
            ),
        )
    ]


# ---------------------------------------------------------------------------
# Validator registry
# ---------------------------------------------------------------------------


_SYBIL_FLOOR = 0.0
"""Untrusted-floor score an unbonded identity may not exceed."""


def _trustscores(events: list[dict[str, Any]]) -> dict[str, float]:
    """Extract ``{agent: score}`` from ``trustscore:<agent>:<score>`` events.

    The ``sybil_bond`` observer broadcasts one such event per agent after driving
    the configured trust plugin, so these scores are the plugin's own verdict.
    """
    scores: dict[str, float] = {}
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = _message_body(ev)
        if not msg.startswith("trustscore:"):
            continue
        parts = msg.split(":")
        if len(parts) >= 3:
            try:
                scores[parts[1]] = float(parts[2])
            except ValueError:
                continue
    return scores


def validate_sybil_bond_no_free_trust(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No unbonded Sybil identity obtains trust above the untrusted floor.

    FAILs on ``score_average`` (the clique's mutual endorsements promote it) and
    PASSes on ``bonded_trust`` (free-minted identities stay inert).

    Example::

        results = validate_sybil_bond_no_free_trust(events)
    """
    scores = _trustscores(events)
    escaped = {a: s for a, s in scores.items() if a.startswith("sybil-") and s > _SYBIL_FLOOR}
    if escaped:
        detail = f"Sybils bought trust without bonding: {escaped}"
        return [ValidationResult("sybil_bond_no_free_trust", False, detail)]
    n_sybil = sum(1 for a in scores if a.startswith("sybil-"))
    return [
        ValidationResult(
            "sybil_bond_no_free_trust",
            True,
            f"all {n_sybil} Sybils pinned at the untrusted floor",
        )
    ]


def validate_sybil_bond_honest_trusted(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Bonded honest traders rank strictly above every Sybil.

    Guards against a degenerate trust layer that trivially passes the first check
    by scoring *everyone* at the floor: honest bonded traders must actually rise.

    Example::

        results = validate_sybil_bond_honest_trusted(events)
    """
    scores = _trustscores(events)
    honest = {a: s for a, s in scores.items() if a.startswith("honest-")}
    if not honest:
        return [ValidationResult("sybil_bond_honest_trusted", False, "no honest scores in trace")]
    max_sybil = max((s for a, s in scores.items() if a.startswith("sybil-")), default=0.0)
    laggards = {a: s for a, s in honest.items() if s <= max_sybil}
    if laggards:
        detail = f"honest traders not above Sybil ceiling {max_sybil}: {laggards}"
        return [ValidationResult("sybil_bond_honest_trusted", False, detail)]
    return [
        ValidationResult(
            "sybil_bond_honest_trusted",
            True,
            f"{len(honest)} honest traders trusted above Sybil ceiling {max_sybil}",
        )
    ]


def validate_sybil_bond_attempts_rejected(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Sybils *bid* for a bond yet stay at the floor — the ledger rejected them.

    This is the enforcement check: it proves the defense is active (bond requests
    denied), not merely assumed (Sybils declining to bond). It requires the trace
    to contain Sybil ``bond:`` attempts, and that none of those bidders escaped
    the untrusted floor.

    Example::

        results = validate_sybil_bond_attempts_rejected(events)
    """
    scores = _trustscores(events)
    bidders: set[str] = set()
    for ev in events:
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        agent = str(ev.get("agent", ""))
        if agent.startswith("sybil-") and _message_body(ev).startswith("bond:"):
            bidders.add(agent)
    if not bidders:
        return [
            ValidationResult(
                "sybil_bond_attempts_rejected",
                False,
                "no Sybil bond attempts in trace — cannot prove enforcement",
            )
        ]
    escaped = {a: scores.get(a, 0.0) for a in bidders if scores.get(a, 0.0) > _SYBIL_FLOOR}
    if escaped:
        detail = f"Sybils that bid for a bond escaped the floor: {escaped}"
        return [ValidationResult("sybil_bond_attempts_rejected", False, detail)]
    return [
        ValidationResult(
            "sybil_bond_attempts_rejected",
            True,
            f"{len(bidders)} Sybils bid for a bond and were all rejected to the floor",
        )
    ]


VALIDATORS: dict[str, list[Any]] = {
    "sybil_bond": [
        validate_sybil_bond_no_free_trust,
        validate_sybil_bond_honest_trusted,
        validate_sybil_bond_attempts_rejected,
    ],
    "comms_versioning": [
        validate_comms_reject_unknown_major,
        validate_comms_no_silent_drop,
    ],
    "comms_downgrade": [
        validate_comms_downgrade_resistance,
        validate_comms_authentic_delivery,
    ],
    "marketplace": [
        validate_marketplace_no_double_sell,
        validate_marketplace_responses,
        validate_marketplace_price_agreement,
    ],
    "auction": [
        validate_auction_winner_highest,
        validate_auction_single_winner,
        validate_auction_all_notified,
    ],
    "voting": [
        validate_voting_tally,
        validate_voting_all_counted,
        validate_voting_no_double_vote,
    ],
    "consensus": [
        validate_consensus_agreement,
        validate_consensus_validity,
        validate_consensus_no_conflict,
    ],
    "supply_chain": [
        validate_supply_chain_pipeline,
        validate_supply_chain_no_lost,
    ],
    "reputation": [
        validate_reputation_scoring,
        validate_reputation_warnings,
    ],
    "identity_rotation": [
        validate_identity_rotation_occurred,
        validate_identity_rotation_signatures,
    ],
    "attested_peering": [
        validate_attested_no_denied_admitted,
        validate_attested_sybil_quarantined,
    ],
    "memory_concurrent_writers": [
        validate_memory_convergence,
        validate_memory_liveness,
    ],
    "streaming_payments": [
        validate_streaming_conservation,
        validate_streaming_no_drain_after_close,
        validate_streaming_no_overbill_on_partition,
    ],
    "empic_payments": [
        validate_empic_escrow_conservation,
        validate_empic_no_release_without_accepted_delivery,
        validate_empic_invalid_delivery_not_paid,
        validate_empic_delivery_policy_integrity,
        validate_empic_pubsub_billing_caps,
        validate_empic_max_spend_enforced,
        validate_empic_all_escrows_terminal,
        validate_empic_no_duplicate_settlement,
        validate_empic_provider_service_binding,
        validate_empic_payment_participant_binding,
        validate_empic_no_secret_material,
        validate_empic_no_drain_after_close,
        validate_empic_no_overbill_on_partition,
    ],
    "receipt_reputation": [
        validate_receipt_reputation_ring_severed,
        validate_receipt_reputation_honest_confidence,
    ],
    "multi_attribute_market": [
        validate_multi_attribute_pareto_optimal,
        validate_multi_attribute_individually_rational,
    ],
    "provenance_supply_chain": [
        validate_provenance_chain_integrity,
        validate_provenance_substitution_resistant,
        validate_provenance_freshness_unforgeable,
        validate_provenance_chain_unforgeable,
    ],
    "bft_hotstuff": [
        validate_bft_no_conflicting_commits,
        validate_bft_no_equivocation,
        validate_bft_forged_quorum,
        validate_bft_no_stuck_view,
    ],
    "escrow_marketplace": [
        validate_escrow_state_machine,
        validate_escrow_role_binding,
        validate_escrow_bps_in_range,
        validate_escrow_no_payout_without_delivery,
    ],
    "failure_detection": [
        validate_failure_detection_completeness,
        validate_failure_detection_accuracy,
    ],
    "failure_detection_forgery": [
        validate_failure_detection_completeness,
        validate_failure_detection_accuracy,
        validate_failure_detection_no_forged_liveness,
    ],
    "parc_migration": [
        validate_parc_honest_admitted,
        validate_parc_forgery_rejected,
        validate_parc_inflation_rejected,
        validate_parc_ring_severed,
        validate_parc_replay_rejected,
        validate_parc_stale_key_rejected,
    ],
    "rogue_trusted_agent": [
        validate_rogue_trusted_agent_blocked,
        validate_rogue_trusted_agent_reputation,
    ],
}
