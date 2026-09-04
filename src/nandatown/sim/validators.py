"""Scenario validators: stage checks computed from the trace alone.

Everything a validator asserts must be recoverable from events.jsonl,
so a bundle's result can be replayed and verified by anyone. Missing
evidence is reported as missing, never inferred.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from ..records import EvidenceResult, StageResult, TownEvent

LAB_EVALUATOR_VERSION = "lab-0.2.1"

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


def _check(name: str, ok: bool, evidence: list[str], fail_note: str,
           pass_note: str = "") -> StageResult:
    if not evidence:
        return _missing(name, fail_note)
    return (_passed(name, evidence, pass_note) if ok
            else _failed(name, evidence, fail_note))


class Trace:
    def __init__(self, events: list[TownEvent]):
        self.events = events

    def find(self, ekind: str, **conds) -> list[TownEvent]:
        out = []
        for e in self.events:
            if e.kind != ekind:
                continue
            if "observer" in conds and e.observer != conds["observer"]:
                continue
            if "subject" in conds and e.subject != conds["subject"]:
                continue
            ok = all(e.detail.get(k) == v for k, v in conds.items()
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
        if e.kind == "account_opened":
            balances[e.subject] = d["balance_cents"]
            opened += d["balance_cents"]
        elif e.kind == "escrow_held":
            balances[d["from"]] = balances.get(d["from"], 0) - d["cents"]
            escrow[e.subject] = d["cents"]
            evidence.append(e.event_id)
        elif e.kind == "escrow_released":
            escrow.pop(e.subject, None)
            balances[d["to"]] = balances.get(d["to"], 0) + d["cents"]
            evidence.append(e.event_id)
        elif e.kind == "escrow_refunded":
            escrow.pop(e.subject, None)
            balances[d["to"]] = balances.get(d["to"], 0) + d["cents"]
            evidence.append(e.event_id)
        elif e.kind == "payment_settled" and d.get("via") != "escrow":
            balances[d["from"]] = balances.get(d["from"], 0) - d["cents"]
            balances[d["to"]] = balances.get(d["to"], 0) + d["cents"]
            evidence.append(e.event_id)
        if any(v < 0 for v in balances.values()):
            return _failed("ledger_conserved", [e.event_id],
                           f"negative balance after {e.event_id}")
    total = sum(balances.values()) + sum(escrow.values())
    if opened == 0 and not evidence:
        finished = trace.ids("run_finished")
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

    accepted = trace.find("offer_accepted")
    floors = [a.config["floor_cents"] for a in spec.agents
              if a.role == "seller"]
    asks = [a.config["ask_cents"] for a in spec.agents if a.role == "seller"]
    price_ok = all(min(floors) <= e.detail["cents"] <= max(asks)
                   for e in accepted)
    stages.append(_check(
        "negotiation", len(accepted) == 2 and price_ok,
        [e.event_id for e in accepted],
        "expected two agreed negotiations at a price between the floor"
        " and the ask"))

    held = trace.ids("escrow_held")
    released = trace.ids("escrow_released")
    stages.append(_check(
        "settlement", len(held) == 2 and len(released) == 2,
        held + released,
        "expected exactly two escrow holds and two releases"))

    dup_fault = trace.ids("message_duplicated")
    recognized = trace.ids("duplicate_recognized")
    stages.append(_check(
        "duplicate_recognized",
        bool(dup_fault) and bool(recognized) and len(released) == 2,
        dup_fault + recognized,
        "the duplicated delivery must be recognized and released once"))

    reps = trace.find("reputation_updated")
    stages.append(_check(
        "reputation", len(reps) == 2 and reps[-1].detail["score"] == 2,
        [e.event_id for e in reps],
        "expected the winning seller to end with reputation 2 from two"
        " good receipts"))

    remembered = trace.ids("memory_written")
    stages.append(_check(
        "memory_reuse", bool(remembered) and len(quote_requests) == 3,
        remembered,
        "round two should reuse the remembered seller instead of a fresh"
        " lookup"))
    return stages


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

    payments = trace.find("payment_settled")
    pay_ok = (len(payments) == 1 and awards
              and payments[0].detail["cents"] == awards[0].detail["cents"]
              and payments[0].detail["from"] == awards[0].detail["winner"])
    stages.append(_check(
        "settlement", pay_ok, [e.event_id for e in payments],
        "exactly one payment, by the winner, for the winning amount"))

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


@validator("consensus")
def consensus(spec, trace: Trace) -> list[StageResult]:
    stages = []
    acceptors = [a.name for a in spec.agents if a.role == "acceptor"]
    quorum = len(acceptors) // 2 + 1

    committed = trace.find("consensus_committed")
    quorum_ok = False
    if committed:
        idx = trace.index(committed[0])
        acks_before = [e for e in trace.events[:idx]
                       if e.kind == "message_delivered"
                       and e.detail.get("kind") == "prepare_ack"]
        quorum_ok = (len(acks_before) >= quorum
                     and len(committed[0].detail["acks"]) >= quorum)
    stages.append(_check(
        "quorum_commit", quorum_ok,
        [e.event_id for e in committed],
        f"commit must follow at least {quorum} acknowledged prepares"))

    values = trace.find("value_committed")
    agree = ({e.subject for e in values} == set(acceptors)
             and len({e.detail["value"] for e in values}) == 1)
    stages.append(_check(
        "agreement", agree, [e.event_id for e in values],
        "every acceptor must commit the same value"))

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
    task flow reached a completion fact."""
    stages = []
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
    trace = Trace(events)
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
