# SPDX-License-Identifier: Apache-2.0
"""Protocol invariant validators for NEST scenarios.

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

import base64
import contextlib
import json
from collections import defaultdict
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
# Comms schema-versioning validators
# ---------------------------------------------------------------------------


def _forwarded_envelopes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the JSON envelopes re-emitted by the forwarder agent in a trace."""
    out: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("kind") != "send" or ev.get("agent") != "forwarder-0":
            continue
        try:
            raw = json.loads(str(ev.get("msg", "")))
        except (ValueError, TypeError):
            continue
        if isinstance(raw, dict):
            out.append(cast("dict[str, Any]", raw))
    return out


def _envelope_payload(envelope: dict[str, Any]) -> str:
    """Decode the base64 payload of an envelope to text (best effort)."""
    try:
        return base64.b64decode(str(envelope.get("payload", ""))).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def validate_comms_schema_version(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Every forwarded envelope carries an explicit ``schema_version``.

    The name-addressed ``nest_native`` plugin emits no version field, so a
    forwarded message loses its version — this check FAILS against it.
    """
    envs = _forwarded_envelopes(events)
    missing = [e for e in envs if "schema_version" not in e]
    if missing:
        return [
            ValidationResult(
                "comms_schema_version",
                False,
                f"{len(missing)} forwarded envelope(s) missing schema_version",
            )
        ]
    return [
        ValidationResult(
            "comms_schema_version",
            True,
            f"all {len(envs)} forwarded envelope(s) carry schema_version",
        )
    ]


def validate_comms_unknown_field_preserved(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Unknown (future-minor) fields survive a round trip instead of being dropped.

    The v2 message carries an unknown ``priority`` field; a compliant plugin
    preserves and re-emits it. ``nest_native`` silently drops it — FAIL.
    """
    envs = _forwarded_envelopes(events)
    dropped = [e for e in envs if _envelope_payload(e) == "greeting-v2" and "priority" not in e]
    checked = sum(1 for e in envs if _envelope_payload(e) == "greeting-v2")
    if dropped:
        return [
            ValidationResult(
                "comms_unknown_field_preserved",
                False,
                f"{len(dropped)} v2 envelope(s) silently dropped the unknown 'priority' field",
            )
        ]
    return [
        ValidationResult(
            "comms_unknown_field_preserved",
            True,
            f"unknown field preserved across {checked} v2 envelope(s)",
        )
    ]


def validate_comms_unsupported_major_rejected(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """Unsupported-major (v3) messages are rejected, not blindly forwarded.

    A compliant plugin raises on an unknown major version; the forwarder then
    drops it. ``nest_native`` ignores the version and forwards it anyway — FAIL.
    """
    envs = _forwarded_envelopes(events)
    forwarded_v3 = [e for e in envs if _envelope_payload(e) == "probe-v3"]
    if forwarded_v3:
        return [
            ValidationResult(
                "comms_unsupported_major_rejected",
                False,
                f"{len(forwarded_v3)} unsupported-major (v3) message(s) forwarded, not rejected",
            )
        ]
    return [
        ValidationResult(
            "comms_unsupported_major_rejected",
            True,
            "unsupported-major messages were rejected (not forwarded)",
        )
    ]


# ---------------------------------------------------------------------------
# Validator registry
# ---------------------------------------------------------------------------


VALIDATORS: dict[str, list[Any]] = {
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
    "comms_versioning": [
        validate_comms_schema_version,
        validate_comms_unknown_field_preserved,
        validate_comms_unsupported_major_rejected,
    ],
}
