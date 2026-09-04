"""Path A: test one already-running external agent against an exact
NANDA journey, and name the first boundary that broke.

The agent is already running; the developer migrates nothing, uploads
nothing, and supplies no model key. Town acts as a deterministic
counterpart and observer. Every observation is recorded as an
attributed event; the evaluator derives the stage results purely from
those events, so the bundle replays and verifies like every other run.

Result semantics are honest by construction: a broken boundary makes
later stages not tested rather than a pile of inconclusives, and a
malfunction in Town's own driver is an ERROR attributed to Town, never
to the subject.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from contextlib import ExitStack
from typing import Any

import httpx

from . import __version__
from .bundle import attest_bundle, write_bundle
from .evaluator import cascade_unreached, stage_verdict
from .a2a_transport import (
    DEFAULT_MAX_RESPONSE_BYTES, a2a_client, effective_policy,
    validate_response_budget,
)
from .path_profiles import (
    DEFAULT_PATH_PROFILE, QUOTE_INTENT_EVALUATOR, QUOTE_INTENT_FIELDS,
    PathProfile, get_path_profile,
)
from .records import (
    EvidenceResult,
    RunRecord,
    StageResult,
    TownEvent,
    fingerprint,
)

PATH_EVALUATOR_VERSION = "path-0.2"


def path_evaluator_version(profile: PathProfile) -> str:
    # Existing price-only profiles retain their evaluator and replay semantics.
    if profile.evaluator == QUOTE_INTENT_EVALUATOR:
        return "path-quote-intent-0.1"
    return PATH_EVALUATOR_VERSION


def _quote_intent_errors(profile: PathProfile, detail: dict[str, Any]) -> list[str]:
    """Compare observed quote terms, never filling omissions from the request."""
    errors = []
    observed = detail.get("quote")
    if not isinstance(observed, dict):
        observed = {}
    expected = profile.expected["quote"]
    for field in QUOTE_INTENT_FIELDS:
        value = observed.get(field)
        wanted = expected[field]
        # JSON booleans and floats are not integer item counts.
        if type(value) is not type(wanted) or value != wanted:
            errors.append(f"{field}: expected {wanted!r}, observed {value!r}")
    total = detail.get("total_cents")
    maximum = profile.expected["max_total_cents"]
    if type(total) is not int or not 0 <= total <= maximum:
        errors.append(f"total_cents: expected integer in [0, {maximum}],"
                      f" observed {total!r}")
    return errors


STAGE_ORDER = ["resolution", "agent_card_retrieval",
               "descriptor_consistency", "protocol_invocation",
               "semantic_result", "duplicate_request"]


class _Recorder:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.events: list[TownEvent] = []
        self.intents: list[dict[str, Any]] = []

    def emit(self, observer: str, kind: str, subject: str,
             detail: dict[str, Any] | None = None) -> None:
        self.events.append(TownEvent(
            event_id=f"ev-{len(self.events) + 1}", run_id=self.run_id,
            at=time.time(), observer=observer, kind=kind,
            subject=subject, detail=detail or {}))

    def intend(self, actor: str, action: str,
               payload: dict[str, Any]) -> None:
        self.intents.append({
            "intent_id": f"in-{len(self.intents) + 1}",
            "run_id": self.run_id, "at": time.time(), "actor": actor,
            "action": action, "payload": payload})


def _resolve(recorder: _Recorder, url: str | None, index_file: str | None,
             agent_name: str | None) -> tuple[str | None, str | None]:
    """Returns (subject_url, pinned_card_digest_from_index)."""
    if index_file:
        recorder.intend("town-requester", "resolve",
                        {"index": index_file, "agent": agent_name})
        try:
            with open(index_file) as f:
                index = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            recorder.emit("town-requester", "resolution_failed",
                          agent_name or "?",
                          {"reason": f"index unreadable: {exc}"})
            return None, None
        entry = (index.get("agents") or {}).get(agent_name or "")
        if not entry or "url" not in entry:
            recorder.emit("town-requester", "resolution_failed",
                          agent_name or "?",
                          {"reason": "missing card pointer: the pinned"
                                     " index has no entry for this"
                                     " agent"})
            return None, None
        recorder.emit("town-requester", "resolution_hop",
                      agent_name or "?",
                      {"kind": "pinned-index", "index": index_file,
                       "url": entry["url"]})
        return entry["url"], entry.get("card_digest")
    recorder.intend("town-requester", "resolve", {"url": url})
    recorder.emit("town-requester", "resolution_hop", url or "?",
                  {"kind": "direct", "url": url})
    return url, None


def run_path_test(subject_url: str | None, out_dir: str,
                  profile_ref: str | None = None,
                  pin_card_digest: str | None = None,
                  index_file: str | None = None,
                  agent_name: str | None = None,
                  http: httpx.Client | None = None
                  ) -> tuple[str, EvidenceResult]:
    from .a2a_adapter import artifact_text, fetch_card, send_message

    profile = get_path_profile(profile_ref or DEFAULT_PATH_PROFILE)
    run_id = "path-" + uuid.uuid4().hex[:12]
    nonce = uuid.uuid4().hex[:10]
    recorder = _Recorder(run_id)
    timeout = profile.limits.get("timeout_seconds", 15.0)
    response_budget = validate_response_budget(profile.limits.get(
        "max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES))

    url, index_digest = _resolve(recorder, subject_url, index_file,
                                 agent_name)
    pinned = pin_card_digest or index_digest

    with ExitStack() as clients:
        card_ok = False
        descriptor_mismatch = False
        if url is not None:
            recorder.intend("town-requester", "fetch_card", {"url": url})
            try:
                client = clients.enter_context(a2a_client(url, http, timeout))
                card = fetch_card(url, http=client,
                                  max_response_bytes=response_budget,
                                  timeout_seconds=timeout)
                observed_digest = fingerprint(card)
                recorder.emit("town-requester", "card_retrieved", url,
                              {"digest": observed_digest,
                               "name": card.get("name"),
                               "version": card.get("version")})
                card_ok = True
                if pinned:
                    recorder.emit("town-requester", "descriptor_expected",
                                  url, {"digest": pinned})
                    descriptor_mismatch = pinned != observed_digest
            except (ValueError, httpx.HTTPError) as exc:
                recorder.emit("town-requester", "card_fetch_failed", url,
                              {"reason": str(exc)})

        if card_ok and not descriptor_mismatch:
            order_id = f"order-{nonce}"
            request_body = dict(profile.request, request_id=order_id,
                                nonce=nonce)
            for attempt in (1, 2):
                if attempt == 2 and profile.controlled_condition \
                        != "duplicate_request":
                    break
                recorder.intend("town-requester", "message_send",
                                {"attempt": attempt, "body": request_body})
                try:
                    task = send_message(url, json.dumps(request_body),
                                        http=client,
                                        max_response_bytes=response_budget,
                                        timeout_seconds=timeout)
                    state = task.get("status", {}).get("state")
                    recorder.emit("town-requester", "protocol_exchange",
                                  order_id,
                                  {"attempt": attempt, "ok": True,
                                   "task_id": task.get("id"),
                                   "kind": task.get("kind"),
                                   "state": state})
                    text = artifact_text(task)
                    try:
                        fulfillment = json.loads(text)
                        if not isinstance(fulfillment, dict):
                            recorder.emit("town-requester", "fulfillment_unparseable",
                                          order_id, {"attempt": attempt,
                                                     "reason": "quote is not a JSON object"})
                            continue
                        detail = {
                            "attempt": attempt,
                            "total_cents": fulfillment.get("total_cents"),
                            "request_id": fulfillment.get("request_id"),
                            "content_digest": fingerprint(fulfillment)}
                        if profile.evaluator == QUOTE_INTENT_EVALUATOR:
                            detail["quote"] = {
                                field: fulfillment[field] for field in QUOTE_INTENT_FIELDS
                                if field in fulfillment}
                        recorder.emit(
                            "town-requester", "fulfillment_observed",
                            order_id, detail)
                    except json.JSONDecodeError:
                        recorder.emit("town-requester",
                                      "fulfillment_unparseable", order_id,
                                      {"attempt": attempt,
                                       "text": text[:200]})
                except (ValueError, httpx.HTTPError) as exc:
                    recorder.emit("town-requester", "protocol_exchange",
                                  order_id,
                                  {"attempt": attempt, "ok": False,
                                   "reason": str(exc)})
                    break
                except Exception as exc:
                    # Town's own driver misbehaved. That is Town's fault
                    # and must never read as a subject failure.
                    recorder.emit("town", "town_driver_error", order_id,
                                  {"attempt": attempt,
                                   "reason": f"{type(exc).__name__}: {exc}"})
                    break

    result = evaluate_path(profile, run_id, recorder.events)

    rerun = "nandatown test-agent"
    if index_file:
        rerun += f" --index {index_file} --agent-name {agent_name}"
    else:
        rerun += f" --url {subject_url}"
    rerun += f" --path-profile {profile.ref}"
    if pin_card_digest:
        rerun += f" --pin-card-digest {pin_card_digest}"

    run_record = RunRecord(
        run_id=run_id,
        profile_name=profile.ref,
        profile_fingerprint=profile.fingerprint(),
        created_at=time.time(),
        participants=[
            {"name": "town-requester", "role": "requester"},
            {"name": subject_url or agent_name or "?",
             "role": "subject"},
        ],
        releases={"nandatown": __version__,
                  "evaluator": path_evaluator_version(profile),
                  "python": sys.version.split()[0]},
        config={"mode": "path", "subject": subject_url or agent_name,
                "profile": profile.ref,
                "pinned_card_digest": pinned,
                "nonce": nonce,
                "a2a_transport_policy": effective_policy(
                    response_budget, timeout, injected=http is not None,
                    profile_budget="max_response_bytes" in profile.limits),
                "rerun_command": rerun},
    )
    bundle_dir = os.path.join(out_dir, run_id)
    write_bundle(bundle_dir, profile, run_record, recorder.intents,
                 recorder.events, result, mode="path")
    attest_bundle(bundle_dir)
    return bundle_dir, result


def evaluate_path(profile: PathProfile, run_id: str,
                  events: list[TownEvent]) -> EvidenceResult:
    """Stage results derived purely from the recorded observations, so
    any holder of the bundle can replay this judgment."""

    def find(kind: str, **conds) -> list[TownEvent]:
        out = []
        for e in events:
            if e.kind != kind:
                continue
            if all(e.detail.get(k) == v for k, v in conds.items()):
                out.append(e)
        return out

    stages: list[StageResult] = []

    hops = find("resolution_hop")
    failed_resolution = find("resolution_failed")
    if hops:
        stages.append(StageResult(name="resolution", status="passed",
                                  evidence=[hops[0].event_id]))
    elif failed_resolution:
        stages.append(StageResult(
            name="resolution", status="failed",
            evidence=[failed_resolution[0].event_id],
            note=failed_resolution[0].detail.get("reason", "")))
    else:
        stages.append(StageResult(name="resolution",
                                  status="not_enough_evidence",
                                  note="no resolution was attempted"))

    cards = find("card_retrieved")
    card_failures = find("card_fetch_failed")
    if cards:
        stages.append(StageResult(
            name="agent_card_retrieval", status="passed",
            evidence=[cards[0].event_id],
            note=f"observed card {cards[0].detail['digest'][:23]}"))
    elif card_failures:
        stages.append(StageResult(
            name="agent_card_retrieval", status="failed",
            evidence=[card_failures[0].event_id],
            note=card_failures[0].detail.get("reason", "")))
    else:
        stages.append(StageResult(name="agent_card_retrieval",
                                  status="not_enough_evidence",
                                  note="retrieval was never reached"))

    expected_descriptor = find("descriptor_expected")
    if expected_descriptor and cards:
        expected_digest = expected_descriptor[0].detail["digest"]
        observed_digest = cards[0].detail["digest"]
        if expected_digest == observed_digest:
            stages.append(StageResult(
                name="descriptor_consistency", status="passed",
                evidence=[expected_descriptor[0].event_id,
                          cards[0].event_id]))
        else:
            stages.append(StageResult(
                name="descriptor_consistency", status="failed",
                evidence=[expected_descriptor[0].event_id,
                          cards[0].event_id],
                note=f"expected card {expected_digest[:23]}, observed"
                     f" {observed_digest[:23]}; republish or align the"
                     " runtime AgentCard"))
    elif cards:
        stages.append(StageResult(
            name="descriptor_consistency", status="not_tested",
            note="no pinned digest to compare; observed card digest is"
                 " in the evidence"))
    else:
        stages.append(StageResult(name="descriptor_consistency",
                                  status="not_enough_evidence",
                                  note="no card to compare"))

    driver_errors = find("town_driver_error")
    first_exchange = find("protocol_exchange", attempt=1)
    if driver_errors:
        stages.append(StageResult(
            name="protocol_invocation", status="error",
            evidence=[driver_errors[0].event_id],
            note="Town's own driver malfunctioned: "
                 + driver_errors[0].detail.get("reason", "")
                 + "; this run is an error, not an agent failure"))
    elif first_exchange and first_exchange[0].detail.get("ok"):
        detail = first_exchange[0].detail
        if detail.get("kind") == "task" and detail.get("state"):
            stages.append(StageResult(
                name="protocol_invocation", status="passed",
                evidence=[first_exchange[0].event_id],
                note=f"task {detail.get('task_id')} state"
                     f" {detail.get('state')}"))
        else:
            stages.append(StageResult(
                name="protocol_invocation", status="failed",
                evidence=[first_exchange[0].event_id],
                note="the response was not a well-formed task"))
    elif first_exchange:
        stages.append(StageResult(
            name="protocol_invocation", status="failed",
            evidence=[first_exchange[0].event_id],
            note=first_exchange[0].detail.get("reason", "")))
    else:
        stages.append(StageResult(name="protocol_invocation",
                                  status="not_enough_evidence",
                                  note="invocation was never reached"))

    expected_total = profile.expected.get("total_cents")
    first_fulfillment = find("fulfillment_observed", attempt=1)
    if first_fulfillment:
        detail = first_fulfillment[0].detail
        observed_total = detail.get("total_cents")
        expected_request_id = first_fulfillment[0].subject
        observed_request_id = detail.get("request_id")
        request_ok = (isinstance(expected_request_id, str)
                      and bool(expected_request_id)
                      and isinstance(observed_request_id, str)
                      and observed_request_id == expected_request_id)
        quote_intent = profile.evaluator == QUOTE_INTENT_EVALUATOR
        errors = _quote_intent_errors(profile, detail) if quote_intent else []
        result_ok = not errors if quote_intent else observed_total == expected_total
        if result_ok and request_ok:
            stages.append(StageResult(
                name="semantic_result", status="passed",
                evidence=[first_fulfillment[0].event_id],
                note=(f"observed quote matches the item terms and budget;"
                      f" total_cents {observed_total}; no purchase or delivery tested"
                      if quote_intent else
                      f"exactly one fulfillment, total {observed_total}")))
        else:
            note = ("quote does not match the selected profile: " + "; ".join(errors)
                    if quote_intent else
                    f"protocol passed but the result is wrong:"
                    f" expected total {expected_total}, observed {observed_total}")
            if not request_ok:
                note += (f"; expected request_id {expected_request_id!r},"
                         f" observed request_id {observed_request_id!r}")
            stages.append(StageResult(
                name="semantic_result", status="failed",
                evidence=[first_fulfillment[0].event_id],
                note=note))
    elif find("fulfillment_unparseable", attempt=1):
        bad = find("fulfillment_unparseable", attempt=1)[0]
        stages.append(StageResult(
            name="semantic_result", status="failed",
            evidence=[bad.event_id],
            note="the fulfillment artifact is not parseable"))
    else:
        stages.append(StageResult(name="semantic_result",
                                  status="not_enough_evidence",
                                  note="no fulfillment was observed"))

    second = find("fulfillment_observed", attempt=2)
    if first_fulfillment and second:
        same = (second[0].detail.get("content_digest")
                == first_fulfillment[0].detail.get("content_digest"))
        if same:
            stages.append(StageResult(
                name="duplicate_request", status="passed",
                evidence=[second[0].event_id],
                note="the same logical order was delivered twice; no"
                     " second distinct fulfillment appeared"))
        else:
            stages.append(StageResult(
                name="duplicate_request", status="failed",
                evidence=[first_fulfillment[0].event_id,
                          second[0].event_id],
                note="idempotency defect: the duplicate produced a"
                     " second distinct fulfillment"))
    else:
        stages.append(StageResult(
            name="duplicate_request", status="not_enough_evidence",
            note="the controlled condition was never reached"))

    cascade_unreached(stages)
    return EvidenceResult(run_id=run_id,
                          evaluator_version=path_evaluator_version(profile),
                          stages=stages, verdict=stage_verdict(stages),
                          evaluated_at=time.time())
