"""Scenario validators: stage checks computed from the trace alone.

Everything a validator asserts must be recoverable from events.jsonl,
so a bundle's result can be replayed and verified by anyone. Missing
evidence is reported as missing, never inferred.
"""

from __future__ import annotations

import math
import time
from typing import Any, Callable

from ..records import EvidenceResult, StageResult, TownEvent

LAB_EVALUATOR_VERSION = "lab-0.2.6"

VALIDATORS: dict[str, Callable] = {}


def validator(name: str):
    def wrap(fn):
        VALIDATORS[name] = fn
        return fn
    return wrap


def _passed(name, evidence, note=""):
    return StageResult(name=name, status="passed",
                       evidence=evidence[:8], note=note)


def _failed(name, evidence, note):
    return StageResult(name=name, status="failed", evidence=evidence[:8],
                       note=note)


def _missing(name, note):
    return StageResult(name=name, status="not_enough_evidence", note=note)


def _event_ids(events: list[TownEvent]) -> list[str]:
    return [event.event_id for event in events
            if isinstance(event.event_id, str) and event.event_id]


def _check(name: str, ok: bool, evidence: list[str], fail_note: str,
           pass_note: str = "") -> StageResult:
    if not evidence:
        return _missing(name, fail_note)
    return (_passed(name, evidence, pass_note) if ok
            else _failed(name, evidence, fail_note))


class Trace:
    def __init__(self, events: list[TownEvent], run_id: str | None = None):
        self.events = events
        self.run_id = run_id

    def find(self, ekind: str, **conds) -> list[TownEvent]:
        out = []
        for e in self.events:
            if e.kind != ekind:
                continue
            if "observer" in conds and e.observer != conds["observer"]:
                continue
            if "subject" in conds and e.subject != conds["subject"]:
                continue
            detail = e.detail if isinstance(e.detail, dict) else {}
            ok = all(detail.get(k) == v for k, v in conds.items()
                     if k not in ("observer", "subject"))
            if ok:
                out.append(e)
        return out

    def ids(self, ekind: str, **conds) -> list[str]:
        return [e.event_id for e in self.find(ekind, **conds)]

    def index(self, event: TownEvent) -> int:
        return self.events.index(event)


def ledger_conserved(trace: Trace) -> StageResult:
    balances: dict[str, int] = {}
    escrow: dict[str, int] = {}
    opened = 0
    evidence: list[str] = []
    for e in trace.events:
        d = e.detail
        if (e.kind in {"account_opened", "escrow_held", "escrow_released",
                       "escrow_refunded", "payment_settled"}
                and not isinstance(d, dict)):
            return _failed("ledger_conserved", _event_ids([e]),
                           f"malformed money event {e.event_id}")
        if e.kind == "account_opened":
            amount = d.get("balance_cents")
            if (not isinstance(e.subject, str) or not e.subject
                    or type(amount) is not int):
                return _failed("ledger_conserved", _event_ids([e]),
                               f"malformed account opening {e.event_id}")
            balances[e.subject] = amount
            opened += amount
        elif e.kind == "escrow_held":
            payer, amount = d.get("from"), d.get("cents")
            if (not isinstance(e.subject, str) or not e.subject
                    or not isinstance(payer, str) or not payer
                    or type(amount) is not int):
                return _failed("ledger_conserved", _event_ids([e]),
                               f"malformed escrow hold {e.event_id}")
            balances[payer] = balances.get(payer, 0) - amount
            escrow[e.subject] = amount
            evidence.extend(_event_ids([e]))
        elif e.kind == "escrow_released":
            payee, amount = d.get("to"), d.get("cents")
            if (not isinstance(e.subject, str) or not e.subject
                    or not isinstance(payee, str) or not payee
                    or type(amount) is not int):
                return _failed("ledger_conserved", _event_ids([e]),
                               f"malformed escrow release {e.event_id}")
            escrow.pop(e.subject, None)
            balances[payee] = balances.get(payee, 0) + amount
            evidence.extend(_event_ids([e]))
        elif e.kind == "escrow_refunded":
            payee, amount = d.get("to"), d.get("cents")
            if (not isinstance(e.subject, str) or not e.subject
                    or not isinstance(payee, str) or not payee
                    or type(amount) is not int):
                return _failed("ledger_conserved", _event_ids([e]),
                               f"malformed escrow refund {e.event_id}")
            escrow.pop(e.subject, None)
            balances[payee] = balances.get(payee, 0) + amount
            evidence.extend(_event_ids([e]))
        elif e.kind == "payment_settled" and d.get("via") != "escrow":
            payer, payee, amount = d.get("from"), d.get("to"), d.get("cents")
            if (not isinstance(payer, str) or not payer
                    or not isinstance(payee, str) or not payee
                    or type(amount) is not int):
                return _failed("ledger_conserved", _event_ids([e]),
                               f"malformed payment settlement {e.event_id}")
            balances[payer] = balances.get(payer, 0) - amount
            balances[payee] = balances.get(payee, 0) + amount
            evidence.extend(_event_ids([e]))
        if any(v < 0 for v in balances.values()):
            return _failed("ledger_conserved", _event_ids([e]),
                           f"negative balance after {e.event_id}")
    total = sum(balances.values()) + sum(escrow.values())
    if opened == 0 and not evidence:
        finished = _event_ids(trace.find("run_finished"))
        if not finished:
            return _missing(
                "ledger_conserved",
                "no completed-run evidence for a no-money ledger claim",
            )
        return _passed("ledger_conserved", finished,
                       "complete run recorded no money moved")
    if total != opened:
        return _failed("ledger_conserved", evidence,
                       f"opened {opened} cents but ended with {total}")
    return _passed("ledger_conserved", evidence,
                   f"{opened} cents conserved across every movement")


def privacy_clean(trace: Trace, redact_fields: list[str]) -> StageResult:
    if not redact_fields:
        return StageResult(name="privacy", status="not_tested",
                           note="no redaction declared by this scenario")

    def leaks(obj) -> bool:
        if isinstance(obj, dict):
            return any(
                (k in redact_fields and v != "[redacted]") or leaks(v)
                for k, v in obj.items())
        if isinstance(obj, list):
            return any(leaks(v) for v in obj)
        return False

    bad = [e.event_id for e in trace.events if leaks(e.detail)]
    if bad:
        return _failed("privacy", bad, "redacted fields leaked into events")
    finished = trace.ids("run_finished")
    if not finished:
        return _missing(
            "privacy",
            "no completed-run evidence for a declared-privacy claim",
        )
    return _passed("privacy", finished,
                   f"fields {sorted(redact_fields)} never left the run")


def reputation_consistent(trace: Trace) -> StageResult:
    """Replay the reference +1/-1 formula against attributed receipt events.

    This checks the recorded claim, not whether the reporter told the truth,
    held authority, or proved misconduct. Receipt signatures are not present
    in these events and are not cryptographically verified by this check.
    """
    reputation_events = [
        event for event in trace.events
        if event.kind in {"receipt_attested", "reputation_updated"}
    ]
    reputation_ids = _event_ids(reputation_events)
    if (len(reputation_ids) != len(reputation_events)
            or len(reputation_ids) != len(set(reputation_ids))):
        return _failed(
            "reputation", reputation_ids,
            "reputation evidence has malformed or ambiguous event IDs")

    receipts: dict[str, list[tuple[int, TownEvent]]] = {}
    for index, event in enumerate(trace.events):
        if event.kind == "receipt_attested":
            if (not isinstance(event.detail, dict)
                    or type(event.at) not in (int, float)
                    or not math.isfinite(event.at)):
                return _failed("reputation", _event_ids([event]),
                               "receipt event is malformed")
            record_id = event.detail.get("record_id")
            if isinstance(record_id, str) and record_id:
                receipts.setdefault(record_id, []).append((index, event))

    scores: dict[str, int] = {}
    used: set[str] = set()
    evidence: list[str] = []
    missing_receipt = False
    for index, event in enumerate(trace.events):
        if event.kind != "reputation_updated":
            continue
        detail = event.detail
        if (not isinstance(detail, dict)
                or not isinstance(event.subject, str) or not event.subject
                or type(event.at) not in (int, float)
                or not math.isfinite(event.at)):
            return _failed("reputation", _event_ids([event]),
                           "score update is malformed")
        outcome = detail.get("outcome")
        delta = 1 if outcome == "good" else -1
        score = scores.get(event.subject, 0) + delta
        if (outcome not in ("good", "bad")
                or type(detail.get("delta")) is not int
                or detail["delta"] != delta
                or type(detail.get("score")) is not int
                or detail["score"] != score):
            return _failed("reputation", [event.event_id],
                           "score update does not follow the reference +1/-1 formula")
        scores[event.subject] = score
        evidence.append(event.event_id)

        record_id = detail.get("receipt")
        if not isinstance(record_id, str) or not record_id:
            return _failed("reputation", [event.event_id],
                           "score update has no valid receipt reference")
        if record_id in used:
            return _failed("reputation", [event.event_id],
                           "one receipt was counted more than once")
        used.add(record_id)
        matches = receipts.get(record_id, [])
        if not matches:
            missing_receipt = True
            continue
        if len(matches) != 1:
            return _failed("reputation", [event.event_id],
                           "receipt reference is ambiguous")
        receipt_index, receipt = matches[0]
        refs = [receipt.event_id, event.event_id]
        if (receipt_index >= index or receipt.at > event.at
                or receipt.run_id != event.run_id
                or receipt.observer != event.observer
                or receipt.subject != event.subject
                or receipt.observer == receipt.subject
                or receipt.detail.get("claim") != "trade.outcome"
                or receipt.detail.get("value") != outcome):
            return _failed("reputation", refs,
                           "score update does not match a prior attributed trade receipt")
        evidence.append(receipt.event_id)

    if not evidence or missing_receipt:
        return _missing("reputation", "score updates or their receipt events are missing")
    return _passed("reputation", evidence,
                   "recorded receipt claims and reference score arithmetic agree; "
                   "claim truth and reporter authority are not tested")


def _marketplace_transactions(
        spec, trace: Trace) -> tuple[StageResult, StageResult, list[TownEvent]]:
    """Bind the two marketplace negotiations to their ledger movements."""
    buyers = [agent for agent in spec.agents if agent.role == "buyer"]
    seller_specs = [agent for agent in spec.agents if agent.role == "seller"]
    config_note = ("requires exactly one configured buyer and identifiable"
                   " configured sellers with integer price terms")
    if len(buyers) != 1 or not seller_specs:
        missing = _missing("negotiation", config_note)
        return missing, _missing("settlement", config_note), []

    buyer = buyers[0]
    buyer_config = buyer.config if isinstance(buyer.config, dict) else {}
    cap = buyer_config.get("cap_cents")
    quantity = buyer_config.get("quantity")
    sku = buyer_config.get("sku")
    if (not isinstance(buyer.name, str) or not buyer.name
            or type(cap) is not int or cap < 0
            or type(quantity) is not int or quantity < 1
            or not isinstance(sku, str) or not sku):
        missing = _missing("negotiation", config_note)
        return missing, _missing("settlement", config_note), []

    sellers = {}
    for seller in seller_specs:
        config = seller.config if isinstance(seller.config, dict) else {}
        floor = config.get("floor_cents")
        ask = config.get("ask_cents")
        seller_sku = config.get("sku")
        if (not isinstance(seller.name, str) or not seller.name
                or seller.name in sellers
                or type(floor) is not int or type(ask) is not int
                or not isinstance(seller_sku, str) or not seller_sku):
            missing = _missing("negotiation", config_note)
            return missing, _missing("settlement", config_note), []
        sellers[seller.name] = seller

    run_created = trace.find("run_created")
    starts = trace.find("negotiation_started")
    proposals = trace.find("offer_made") + trace.find("counter_made")
    accepted = trace.find("offer_accepted")
    held = trace.find("escrow_held")
    released = trace.find("escrow_released")
    settled = trace.find("payment_settled")
    orders = trace.find("message_sent", kind="purchase_order")
    positions = {id(event): index
                 for index, event in enumerate(trace.events)}

    def ordered_ids(records):
        return _event_ids(sorted(records, key=lambda event: positions[id(event)]))

    def count_records(records, label, problems, gaps):
        if len(records) < 2:
            gaps.append(f"missing {label} evidence for one of two transactions")
        elif len(records) > 2:
            problems.append(f"expected exactly two {label} records")

    def validate_metadata(records, problems, expected_run=None):
        trace_id_counts: dict[str, int] = {}
        for event in trace.events:
            if isinstance(event.event_id, str) and event.event_id:
                trace_id_counts[event.event_id] = (
                    trace_id_counts.get(event.event_id, 0) + 1)
        run_ids = set()
        for event in records:
            if (not isinstance(event.event_id, str) or not event.event_id
                    or trace_id_counts.get(event.event_id) != 1):
                problems.append("transaction evidence has ambiguous event IDs")
            if not isinstance(event.run_id, str) or not event.run_id:
                problems.append("transaction evidence has an invalid run ID")
            else:
                run_ids.add(event.run_id)
                if expected_run is not None and event.run_id != expected_run:
                    problems.append(
                        "transaction evidence does not match the recorded run")
        if len(run_ids) > 1:
            problems.append("transaction evidence must come from one run")

    def causally_ordered(records):
        for earlier, later in zip(records, records[1:]):
            if positions[id(earlier)] >= positions[id(later)]:
                return False
            if (type(earlier.at) not in (int, float)
                    or type(later.at) not in (int, float)
                    or not math.isfinite(earlier.at)
                    or not math.isfinite(later.at)
                    or earlier.at > later.at):
                return False
        return True

    negotiation_problems: list[str] = []
    negotiation_gaps: list[str] = []
    if not run_created:
        negotiation_gaps.append("missing run creation evidence")
    elif len(run_created) > 1:
        negotiation_problems.append("expected exactly one run creation record")
    expected_run = (trace.run_id
                    if isinstance(trace.run_id, str) and trace.run_id else None)
    if len(run_created) == 1:
        created = run_created[0]
        created_detail = (created.detail
                          if isinstance(created.detail, dict) else {})
        if (not isinstance(created.run_id, str) or not created.run_id
                or created.observer != "town"
                or created.subject != created.run_id
                or (expected_run is not None
                    and created.run_id != expected_run)
                or created_detail.get("scenario") != spec.name):
            negotiation_problems.append(
                "run creation does not identify this marketplace run")
        else:
            expected_run = created.run_id
    count_records(starts, "negotiation", negotiation_problems,
                  negotiation_gaps)
    count_records(accepted, "acceptance", negotiation_problems,
                  negotiation_gaps)
    negotiation_records = run_created + starts + proposals + accepted
    validate_metadata(negotiation_records, negotiation_problems, expected_run)
    nids = [event.subject for event in starts]
    if any(not isinstance(nid, str) or not nid for nid in nids):
        negotiation_problems.append("negotiations require valid IDs")
    elif len(nids) != len(set(nids)):
        negotiation_problems.append("negotiation IDs must be unique")
    if (len(starts) == 2
            and any(event.subject not in nids for event in proposals)):
        negotiation_problems.append(
            "each negotiation offer must name one of the two negotiation IDs")

    chains = []
    if len(starts) == len(accepted) == 2:
        ordered_starts = sorted(starts,
                                key=lambda event: positions[id(event)])
        for start in ordered_starts:
            matching_acceptances = [
                event for event in accepted if event.subject == start.subject
            ]
            if len(matching_acceptances) != 1:
                negotiation_problems.append(
                    "each negotiation ID needs exactly one acceptance")
                continue
            acceptance = matching_acceptances[0]
            start_detail = (start.detail
                            if isinstance(start.detail, dict) else {})
            acceptance_detail = (acceptance.detail
                                 if isinstance(acceptance.detail, dict) else {})
            chain_proposals = sorted(
                [event for event in proposals
                 if event.subject == start.subject],
                key=lambda event: positions[id(event)])
            seller_name = start_detail.get("seller")
            seller = (sellers.get(seller_name)
                      if isinstance(seller_name, str) else None)
            accepted_price = acceptance_detail.get("cents")
            if (start.observer != buyer.name
                    or seller is None
                    or seller.config["sku"] != sku
                    or start_detail.get("subject") != sku):
                negotiation_problems.append(
                    "negotiation does not name the configured buyer, seller,"
                    " and subject")
            participants = (buyer.name, seller_name)
            proposal_ok = bool(chain_proposals)
            previous_observer = None
            for proposal in chain_proposals:
                proposal_detail = (proposal.detail
                                   if isinstance(proposal.detail, dict) else {})
                expected_kind = ("offer_made"
                                 if proposal.observer == buyer.name
                                 else "counter_made")
                if (proposal.observer not in participants
                        or proposal.kind != expected_kind
                        or type(proposal_detail.get("cents")) is not int
                        or (previous_observer is not None
                            and proposal.observer == previous_observer)):
                    proposal_ok = False
                previous_observer = proposal.observer
            last_proposal_detail = (
                chain_proposals[-1].detail
                if (chain_proposals
                    and isinstance(chain_proposals[-1].detail, dict)) else {})
            if (not proposal_ok
                    or chain_proposals[0].observer != buyer.name
                    or acceptance.subject != start.subject
                    or acceptance.observer not in participants
                    or acceptance.observer == chain_proposals[-1].observer
                    or accepted_price != last_proposal_detail.get("cents")):
                negotiation_problems.append(
                    "acceptance does not follow the negotiation's alternating"
                    " buyer and seller offers")
            if type(accepted_price) is not int:
                negotiation_problems.append(
                    "accepted unit price must be an exact integer number of cents")
            elif seller is not None:
                floor = seller.config["floor_cents"]
                ask = seller.config["ask_cents"]
                if not floor <= accepted_price <= min(ask, cap):
                    negotiation_problems.append(
                        "accepted price is outside the negotiated seller and"
                        " buyer bounds")
            causal_records = ([run_created[0], start,
                               *chain_proposals, acceptance]
                              if len(run_created) == 1
                              else [start, *chain_proposals, acceptance])
            if not causally_ordered(causal_records):
                negotiation_problems.append(
                    "negotiation and acceptance must be in causal order")
            chains.append({
                "start": start,
                "accepted": acceptance,
                "seller": seller_name,
                "price": accepted_price,
            })

    negotiation_evidence = ordered_ids(negotiation_records)
    if negotiation_problems:
        negotiation_stage = _failed(
            "negotiation", negotiation_evidence, negotiation_problems[0])
    elif negotiation_gaps:
        negotiation_stage = _missing("negotiation", negotiation_gaps[0])
    else:
        negotiation_stage = _passed(
            "negotiation", negotiation_evidence,
            "two configured negotiations have bounded integer acceptances")

    settlement_problems = list(negotiation_problems)
    settlement_gaps = list(negotiation_gaps)
    for records, label in ((orders, "purchase order"),
                           (held, "escrow hold"),
                           (released, "escrow release"),
                           (settled, "payment settlement")):
        count_records(records, label, settlement_problems, settlement_gaps)
    settlement_records = negotiation_records + orders + held + released + settled
    validate_metadata(settlement_records, settlement_problems, expected_run)

    order_ids = []
    if (len(chains) == 2
            and all(len(records) == 2
                    for records in (orders, held, released, settled))):
        for chain in chains:
            nid = chain["start"].subject
            matching_orders = []
            for order in orders:
                detail = order.detail if isinstance(order.detail, dict) else {}
                body = detail.get("body")
                if isinstance(body, dict) and body.get("nid") == nid:
                    matching_orders.append(order)
            if len(matching_orders) != 1:
                settlement_problems.append(
                    "each negotiation ID needs exactly one purchase order")
                continue

            order = matching_orders[0]
            order_detail = (order.detail
                            if isinstance(order.detail, dict) else {})
            body = order_detail.get("body")
            body = body if isinstance(body, dict) else {}
            order_id = body.get("order_id")
            linked_records = []
            for label, records in (("escrow hold", held),
                                   ("escrow release", released),
                                   ("payment settlement", settled)):
                matches = [event for event in records
                           if event.subject == order_id]
                if len(matches) != 1:
                    settlement_problems.append(
                        f"each order ID needs exactly one {label}")
                    break
                linked_records.append(matches[0])
            if len(linked_records) != 3:
                continue
            hold, release, payment = linked_records
            sequence = [chain["start"], chain["accepted"], hold, order,
                        release, payment]
            if not causally_ordered(sequence):
                settlement_problems.append(
                    "transaction records must be in causal order")

            unit_cents = body.get("unit_cents")
            ordered_quantity = body.get("quantity")
            if not isinstance(order_id, str) or not order_id:
                settlement_problems.append(
                    "purchase order requires a valid order ID")
            else:
                order_ids.append(order_id)
            if (order.observer != buyer.name
                    or order_detail.get("to") != chain["seller"]
                    or order_detail.get("kind") != "purchase_order"):
                settlement_problems.append(
                    "purchase order does not name the configured buyer and seller")
            if (body.get("sku") != sku
                    or type(ordered_quantity) is not int
                    or ordered_quantity != quantity
                    or type(unit_cents) is not int
                    or unit_cents != chain["price"]
                    or unit_cents > cap):
                settlement_problems.append(
                    "purchase order does not match negotiated SKU, quantity, and price")

            total = (unit_cents * ordered_quantity
                     if (type(unit_cents) is int
                         and type(ordered_quantity) is int) else None)
            hold_detail = hold.detail if isinstance(hold.detail, dict) else {}
            release_detail = (release.detail
                              if isinstance(release.detail, dict) else {})
            payment_detail = (payment.detail
                              if isinstance(payment.detail, dict) else {})
            if (hold.observer != "town" or hold.subject != order_id
                    or hold_detail.get("from") != buyer.name
                    or type(hold_detail.get("cents")) is not int
                    or hold_detail.get("cents") != total):
                settlement_problems.append(
                    "escrow hold does not match the order, buyer, and exact total")
            if (release.observer != "town" or release.subject != order_id
                    or release_detail.get("to") != chain["seller"]
                    or type(release_detail.get("cents")) is not int
                    or release_detail.get("cents") != total):
                settlement_problems.append(
                    "escrow release does not match the order, seller, and exact total")
            if (payment.observer != "town" or payment.subject != order_id
                    or payment_detail.get("from") != buyer.name
                    or payment_detail.get("to") != chain["seller"]
                    or payment_detail.get("via") != "escrow"
                    or type(payment_detail.get("cents")) is not int
                    or payment_detail.get("cents") != total):
                settlement_problems.append(
                    "settlement does not match the order, ledger parties,"
                    " and exact total")

    if len(order_ids) == 2 and len(set(order_ids)) != 2:
        settlement_problems.append("order IDs must be unique")

    settlement_evidence = ordered_ids(settlement_records)
    if settlement_problems:
        settlement_stage = _failed(
            "settlement", settlement_evidence, settlement_problems[0])
    elif settlement_gaps:
        settlement_stage = _missing("settlement", settlement_gaps[0])
    else:
        settlement_stage = _passed(
            "settlement", settlement_evidence,
            "two orders match their negotiations and exact escrow settlements")
    return negotiation_stage, settlement_stage, released


@validator("marketplace")
def marketplace(spec, trace: Trace) -> list[StageResult]:
    stages = []
    registered = trace.ids("card_registered")
    quote_requests = trace.find("message_sent", kind="quote_request")
    stages.append(_check(
        "discovery", len(registered) >= 3 and len(quote_requests) == 3,
        registered + [q.event_id for q in quote_requests],
        "expected both sellers plus buyer registered and three quote"
        " requests (two in round one, one remembered-seller request in"
        " round two)"))

    negotiation, settlement, released = _marketplace_transactions(spec, trace)
    stages.extend((negotiation, settlement))

    dup_fault = trace.ids("message_duplicated")
    recognized = trace.ids("duplicate_recognized")
    stages.append(_check(
        "duplicate_recognized",
        bool(dup_fault) and bool(recognized) and len(released) == 2,
        dup_fault + recognized,
        "the duplicated delivery must be recognized and released once"))

    reps = trace.find("reputation_updated")
    reputation = reputation_consistent(trace)
    if reputation.status != "failed" and reps and not (
            len(reps) == 2 and reps[-1].detail["score"] == 2):
        reputation = _failed(
            "reputation", reputation.evidence,
            "expected the winning seller to end with reputation 2 from two good receipts")
    stages.append(reputation)

    remembered = trace.ids("memory_written")
    stages.append(_check(
        "memory_reuse", bool(remembered) and len(quote_requests) == 3,
        remembered,
        "round two should reuse the remembered seller instead of a fresh"
        " lookup"))
    return stages


def auction_settlement(spec, trace: Trace) -> StageResult:
    """Bind the single-auction payment to its recorded award and issuer.

    Conservation alone cannot detect crediting the wrong participant. These
    are correlated Lab records, not independent external account read-back;
    the separate award stage evaluates the bidding outcome.
    """
    issuers = [a for a in spec.agents if a.role == "auctioneer"]
    if len(issuers) != 1 or "item" not in issuers[0].config:
        return _missing("settlement", "requires one configured auctioneer and item")
    issuer = issuers[0]
    item = issuer.config["item"]
    task = f"auction-{item}"
    bidders = {a.name for a in spec.agents if a.role == "bidder"}
    kinds = ("run_created", "task_announced", "task_awarded", "payment_settled")
    records, problems, gaps = {}, [], []
    for kind in kinds:
        matches = trace.find(kind)
        if not matches:
            gaps.append(f"missing {kind} evidence")
        else:
            records[kind] = matches[0]
            if len(matches) != 1:
                problems.append(f"expected exactly one {kind} record")
    present = list(records.values())
    evidence = [e.event_id for e in present]
    if len(set(evidence)) != len(evidence):
        problems.append("auction records have ambiguous event IDs")

    for kind, event in records.items():
        expected_observer = ("town" if kind in {"run_created", "payment_settled"}
                             else issuer.name)
        expected_subject = event.run_id if kind == "run_created" else task
        if event.observer != expected_observer or event.subject != expected_subject:
            problems.append(f"{kind} names the wrong observer or task")
    for before, after in zip(present, present[1:]):
        if (before.run_id != after.run_id
                or trace.index(before) >= trace.index(after)
                or not before.at <= after.at):
            problems.append("auction records must be from one run and in causal order")

    announced = records.get("task_announced")
    if announced is not None:
        terms = announced.detail.get("spec")
        if (announced.detail.get("rule") != "highest"
                or not isinstance(terms, dict) or terms.get("item") != item):
            problems.append("announcement does not describe the configured auction")
    award = records.get("task_awarded")
    if award is not None:
        winner = award.detail.get("winner")
        if (not isinstance(winner, str) or winner not in bidders
                or type(award.detail.get("cents")) is not int
                or award.detail.get("rule") != "highest"):
            problems.append("award must name a configured bidder and integer amount")
    payment = records.get("payment_settled")
    if payment is not None:
        payer = payment.detail.get("from")
        if (payment.detail.get("to") != issuer.name
                or not isinstance(payer, str) or payer not in bidders
                or type(payment.detail.get("cents")) is not int):
            problems.append("payment must credit the auctioneer from a bidder in integer cents")
        if award is not None and (
                payer != award.detail.get("winner")
                or payment.detail.get("cents") != award.detail.get("cents")):
            problems.append("payment does not match the recorded winner and amount")
    # Known contradictions must not be hidden by a different missing record.
    if problems:
        return _failed("settlement", evidence, problems[0])
    if gaps:
        return _missing("settlement", gaps[0])
    return _passed("settlement", evidence,
                   "one payment to the auctioneer for this task's recorded award")


@validator("auction")
def auction(spec, trace: Trace) -> list[StageResult]:
    stages = []
    announced = trace.find("task_announced", rule="highest")
    stages.append(_check("announced", bool(announced),
                         [e.event_id for e in announced],
                         "no auction was announced"))

    bids = trace.find("bid_placed")
    rejected = trace.ids("bid_rejected")
    stages.append(_check(
        "bidding", len(bids) == 2 and bool(rejected),
        [e.event_id for e in bids] + rejected,
        "expected two on-time bids and the late bid rejected"))

    awards = trace.find("task_awarded")
    ok = False
    if awards and bids:
        top = max(b.detail["cents"] for b in bids)
        ok = awards[0].detail["cents"] == top
    stages.append(_check(
        "award", ok, [e.event_id for e in awards],
        "the award must go to the highest on-time bid"))

    stages.append(auction_settlement(spec, trace))

    delivered = trace.find("message_delivered", kind="item_delivery")
    stages.append(_check(
        "delivery",
        bool(delivered) and bool(awards)
        and delivered[0].detail["to"] == awards[0].detail["winner"],
        [e.event_id for e in delivered],
        "the item must be delivered to the winner"))
    return stages


@validator("voting")
def voting(spec, trace: Trace) -> list[StageResult]:
    stages = []
    voters = [a for a in spec.agents if a.role == "voter"]
    cast = trace.find("ballot_cast")
    stages.append(_check(
        "ballots", len(cast) == len(voters),
        [e.event_id for e in cast],
        f"expected one counted ballot per voter ({len(voters)})"))

    rejected = trace.find("ballot_rejected", reason="already voted")
    stages.append(_check(
        "one_agent_one_vote", bool(rejected),
        [e.event_id for e in rejected],
        "the double vote must be rejected"))

    results = trace.find("vote_result", subject="vote")
    counts_ok = False
    if results:
        expected: dict[str, int] = {}
        for v in voters:
            expected[v.config["choice"]] = expected.get(v.config["choice"],
                                                        0) + 1
        counts_ok = results[0].detail["counts"] == expected
    stages.append(_check(
        "tally", counts_ok, [e.event_id for e in results],
        "the tally must match the first ballot of every voter"))

    broadcast = trace.find("message_delivered", kind="vote_result")
    stages.append(_check(
        "result_broadcast", len(broadcast) == len(voters),
        [e.event_id for e in broadcast],
        "every voter must receive the result"))
    return stages


def quorum_commit(spec, trace: Trace) -> StageResult:
    """Check the Lab's single-proposer majority, not a BFT certificate.

    Delivery events omit sender/body, so follow message IDs back to sends
    and conversation IDs back to delivered prepares. Counting deliveries or
    trusting the proposer's acknowledgement list alone is insufficient.
    """
    committed = trace.find("consensus_committed")
    if not committed:
        return _missing("quorum_commit", "no consensus commit recorded")
    proposers = [a for a in spec.agents if a.role == "proposer"]
    acceptors = {a.name for a in spec.agents if a.role == "acceptor"}
    if len(proposers) != 1 or not acceptors or "value" not in proposers[0].config:
        return _missing("quorum_commit", "requires one configured proposer and acceptors")
    proposer, value = proposers[0].name, proposers[0].config["value"]
    quorum = len(acceptors) // 2 + 1
    sends = trace.find("message_sent")
    deliveries = trace.find("message_delivered")
    problems, gaps, evidence = [], [], [e.event_id for e in committed]

    def problem(event, note):
        problems.append(note)
        evidence.append(event.event_id)

    def precedes(first, second):
        return (first.run_id == second.run_id
                and trace.index(first) < trace.index(second)
                and first.at <= second.at)

    def delivered_send(delivery, kind, to, before):
        matches = [s for s in sends if s.subject == delivery.subject]
        if not matches:
            gaps.append(f"missing send for {delivery.subject}")
            return None
        if len(matches) != 1:
            problem(delivery, f"ambiguous send ID {delivery.subject}")
            return None
        sent = matches[0]
        if (not precedes(sent, delivery) or not precedes(delivery, before)
                or delivery.observer != "town"
                or delivery.detail.get("kind") != kind
                or delivery.detail.get("to") != to
                or sent.detail.get("kind") != kind
                or sent.detail.get("to") != to):
            problem(delivery, f"inconsistent or late {kind} delivery {delivery.subject}")
            return None
        rejected = [e for e in trace.events
                    if e.subject == sent.subject
                    and e.kind in {"signature_invalid", "delivery_failed"}
                    and precedes(sent, e) and precedes(e, before)]
        if rejected:
            problem(rejected[0], f"rejected message {sent.subject} cannot support quorum")
            return None
        return sent

    for commit in committed:
        claimed = commit.detail.get("acks")
        if (commit.observer != proposer or commit.subject != value
                or type(commit.detail.get("quorum")) is not int
                or commit.detail["quorum"] != quorum
                or not isinstance(claimed, list)
                or any(not isinstance(v, str) for v in claimed)
                or len(set(claimed)) != len(claimed)
                or not set(claimed) <= acceptors or len(claimed) < quorum):
            problem(commit, "commit must name the configured value and a distinct eligible majority")
            continue
        voters = set()
        for delivery in deliveries:
            referenced = [s for s in sends if s.subject == delivery.subject]
            # An uncounted response is not evidence for this commit. In
            # particular, noise from an outsider must not spoil a real quorum.
            if len(referenced) == 1 and referenced[0].observer not in claimed:
                continue
            if (trace.index(delivery) >= trace.index(commit)
                    or not (delivery.detail.get("kind") == "prepare_ack"
                            or any(s.detail.get("kind") == "prepare_ack" for s in referenced))):
                continue
            ack = delivered_send(delivery, "prepare_ack", proposer, commit)
            if ack is None:
                continue
            if (ack.observer not in acceptors
                    or not isinstance(ack.detail.get("body"), dict)
                    or ack.detail["body"].get("value") != value):
                problem(ack, "acknowledgement must come from an eligible voter for the proposed value")
                continue
            conversation = ack.detail.get("conversation")
            if not isinstance(conversation, str) or not conversation:
                problem(ack, "acknowledgement has no valid prepare conversation")
                continue
            matches = [s for s in sends if s.detail.get("kind") == "prepare"
                       and s.detail.get("conversation") == conversation]
            if not matches:
                gaps.append(f"missing prepare for conversation {conversation}")
                continue
            if len(matches) != 1:
                problem(ack, "acknowledgement has an ambiguous prepare conversation")
                continue
            prepare = matches[0]
            if (prepare.observer != proposer
                    or prepare.detail.get("to") != ack.observer
                    or not isinstance(prepare.detail.get("body"), dict)
                    or prepare.detail["body"].get("value") != value):
                problem(prepare, "prepare must carry the configured proposer's value")
                continue
            arrivals = [d for d in deliveries if d.subject == prepare.subject]
            if not arrivals:
                gaps.append(f"missing prior prepare delivery to {ack.observer}")
                continue
            if delivered_send(arrivals[0], "prepare", ack.observer, ack) is not None:
                voters.add(ack.observer)
        if not set(claimed) <= voters:
            late = [d for d in deliveries if trace.index(d) >= trace.index(commit)
                    and any(s.subject == d.subject and s.observer in set(claimed) - voters
                            and s.detail.get("kind") == "prepare_ack" for s in sends)]
            if late:
                problem(late[0], "claimed acknowledgement arrived after commit")
            else:
                gaps.append("not every claimed voter has a complete prepare/ack delivery chain")
    if problems:
        return _failed("quorum_commit", evidence, problems[0])
    if gaps:
        return _missing("quorum_commit", gaps[0])
    return _passed("quorum_commit", evidence,
                   f"each commit follows {quorum} distinct eligible acknowledgements for its value")


@validator("consensus")
def consensus(spec, trace: Trace) -> list[StageResult]:
    stages = [quorum_commit(spec, trace)]
    acceptors = [a.name for a in spec.agents if a.role == "acceptor"]
    proposers = [a for a in spec.agents if a.role == "proposer"]

    values = trace.find("value_committed")
    agree = (len(proposers) == 1 and "value" in proposers[0].config
             and {e.subject for e in values} == set(acceptors)
             and all(e.observer == e.subject
                     and e.detail.get("value") == proposers[0].config["value"]
                     for e in values))
    stages.append(_check(
        "agreement", agree, [e.event_id for e in values],
        "every acceptor must commit the configured proposed value"))

    dropped = trace.ids("message_dropped")
    retries = trace.ids("proposal_retry")
    prepares = trace.find("message_sent", kind="prepare")
    stages.append(_check(
        "fault_recovered",
        bool(dropped) and bool(retries) and len(prepares) > len(acceptors),
        dropped + retries,
        "the dropped acknowledgements must force a retry of the missing"
        " acceptors"))
    return stages


@validator("supply_chain")
def supply_chain(spec, trace: Trace) -> list[StageResult]:
    stages = []
    awards = trace.find("task_awarded")
    lowest_ok = bool(awards)
    for award in awards:
        bids = award.detail["bids"]
        if award.detail["cents"] != min(bids.values()):
            lowest_ok = False
    components = [a for a in spec.agents if a.role == "manufacturer"][0] \
        .config["components"]
    stages.append(_check(
        "procurement", lowest_ok and len(awards) == len(components),
        [e.event_id for e in awards],
        "every component must be awarded to the lowest bid"))

    releases = trace.find("escrow_released")
    award_refs = {e.subject: e.detail for e in awards}
    milestone_ok = all(
        any(r.subject == task for r in releases) for task in award_refs)
    delayed = trace.ids("message_delayed")
    stages.append(_check(
        "milestones", milestone_ok and bool(delayed),
        [e.event_id for e in releases] + delayed,
        "each awarded part must be paid through escrow, including the"
        " delayed delivery"))

    assembled = trace.find("product_assembled")
    final = trace.find("message_delivered", kind="product_delivery")
    order_ok = (bool(assembled) and bool(final)
                and trace.index(assembled[0]) < trace.index(final[0]))
    parts = trace.find("message_delivered", kind="part_delivery")
    if assembled and parts:
        order_ok = order_ok and all(
            trace.index(p) < trace.index(assembled[0]) for p in parts)
    stages.append(_check(
        "assembly_order", order_ok,
        [e.event_id for e in assembled + final],
        "all parts must arrive before assembly, and assembly before the"
        " final delivery"))

    customer_pay = [r for r in releases if r.subject.startswith("po-")]
    stages.append(_check(
        "customer_settled", len(customer_pay) == 1,
        [e.event_id for e in customer_pay],
        "the customer's escrow must be released exactly once"))
    return stages


@validator("capability_spoofing")
def capability_spoofing(spec, trace: Trace) -> list[StageResult]:
    stages = []
    spoofers = [a.name for a in spec.agents if a.role == "spoofer"]
    unverified = [e for e in trace.find("card_unverified")
                  if e.detail.get("publisher") in spoofers
                  or e.subject in spoofers]
    stages.append(_check(
        "spoof_detected", bool(unverified),
        [e.event_id for e in unverified],
        "the forged card must be recorded as unverified"))

    honest = trace.find("card_registered", verified=True)
    stages.append(_check(
        "honest_verified", bool(honest),
        [e.event_id for e in honest],
        "the honest seller's card must verify"))

    to_spoofer = [e for e in trace.find("message_sent")
                  if e.detail.get("to") in spoofers]
    paid_spoofer = [e for e in trace.find("escrow_released")
                    + trace.find("payment_settled")
                    if e.detail.get("to") in spoofers]
    containment_evidence = trace.ids("run_finished")
    stages.append(_check(
        "containment", not to_spoofer and not paid_spoofer,
        containment_evidence,
        "the spoofer must receive no traffic and no money"))

    trade = trace.find("escrow_released")
    stages.append(_check(
        "honest_trade_completed", bool(trade),
        [e.event_id for e in trade],
        "the buyer must still complete the trade with the honest seller"))
    return stages


COMPLETION_KINDS = ["offer_accepted", "vote_result",
                    "consensus_committed", "task_awarded",
                    "escrow_released", "receipt_attested"]


@validator("adapted")
def adapted(spec, trace: Trace) -> list[StageResult]:
    """Generic system fitness for scenarios adapted from upstream:
    the population came up, discovery worked, messages moved, and the
    task flow reached a completion fact. These checks do not establish
    the original upstream scenario's protocol or failure semantics."""
    stages = [StageResult(
        name="original_scenario", status="not_tested",
        note=("Only the adapted reference flow is evaluated. Original"
              " agent configuration, plugins, validators, and declared"
              " failure semantics are not validated by this run; see"
              " the profile's adaptation notes and effective faults."),
    )]
    joined = trace.find("participant_joined")
    stages.append(_check(
        "population_active", len(joined) == len(spec.agents),
        [e.event_id for e in joined[:8]],
        f"expected all {len(spec.agents)} adapted agents to join"))

    registered = trace.ids("card_registered")
    stages.append(_check(
        "discovery", bool(registered), registered,
        "no agent published a card to the town index"))

    sent = trace.find("message_sent")
    delivered = trace.find("message_delivered")
    stages.append(_check(
        "messages_flowed", bool(sent) and bool(delivered),
        [e.event_id for e in delivered[:6]],
        "no messages moved between agents"))

    completions = []
    for kind in COMPLETION_KINDS:
        completions.extend(trace.find(kind))
    stages.append(_check(
        "task_completed", bool(completions),
        [e.event_id for e in completions[:6]],
        "no completion fact (agreement, tally, award, settlement, or"
        " receipt) appears in the trace"))
    return stages


def evaluate_scenario(spec, run_id: str,
                      events: list[TownEvent]) -> EvidenceResult:
    trace = Trace(events, run_id)
    fn = VALIDATORS.get(spec.validator)
    if fn is None:
        stages = [_missing("validator",
                           f"no validator registered for"
                           f" {spec.validator!r}")]
    else:
        stages = fn(spec, trace)
        if not stages:
            stages = [StageResult(
                name="scenario_coverage", status="error",
                note=(f"selected validator {spec.validator!r} produced no"
                      " scenario checks"),
            )]
        elif all(stage.status == "not_tested" for stage in stages):
            stages.append(_missing(
                "scenario_coverage",
                f"selected validator {spec.validator!r} produced only"
                " not_tested checks",
            ))
    stages.append(ledger_conserved(trace))
    stages.append(privacy_clean(trace, spec.redact_fields))
    from ..evaluator import stage_verdict

    return EvidenceResult(run_id=run_id,
                          evaluator_version=LAB_EVALUATOR_VERSION,
                          stages=stages, verdict=stage_verdict(stages),
                          evaluated_at=time.time())
