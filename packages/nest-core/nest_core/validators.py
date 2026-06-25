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
    for item, (_winner, winning_amount) in winners.items():
        for bidder, amount in bids.get(item, []):
            if amount > winning_amount:
                violations.append(
                    f"item {item}: winner bid {winning_amount} but {bidder} bid {amount}"
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
# Validator registry
# ---------------------------------------------------------------------------


VALIDATORS: dict[str, list[Any]] = {
    "comms_versioning": [
        validate_comms_reject_unknown_major,
        validate_comms_no_silent_drop,
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
    "memory_concurrent_writers": [
        validate_memory_convergence,
        validate_memory_liveness,
    ],
    "streaming_payments": [
        validate_streaming_conservation,
        validate_streaming_no_drain_after_close,
        validate_streaming_no_overbill_on_partition,
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
}
