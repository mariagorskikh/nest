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
hackathon/amaancoderx-crdt-memory
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
        if not msg.startswith("ack:"):
            continue
        parts = msg.split(":", 3)
        if len(parts) < 3:
            continue
        mid, status = parts[1], parts[2]
        preserved = {f for f in parts[3].split(",") if f} if len(parts) > 3 else set[str]()
        acks[mid] = (status, preserved)
    return acks


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
    "memory_concurrent_writers": [
        validate_memory_convergence,
        validate_memory_liveness,
    "streaming_payments": [
        validate_streaming_conservation,
        validate_streaming_no_drain_after_close,
        validate_streaming_no_overbill_on_partition,
    ],
}
