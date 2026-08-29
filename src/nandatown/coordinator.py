"""The town coordinator: run lifecycle, directory, mailbox API, faults.

The coordinator owns coordination facts and records them as events. It
never holds participant runtime credentials. The participant tool
surface is deliberately small: join, find participants, wait for a
wake-up hint, claim work, send work, acknowledge work, inspect the run.
Run creation, fault plans, and event export are admin-only.

An HTTP success response is a coordination fact (the town accepted or
recorded something). It is never proof that an agent understood or
completed a task; that separation belongs to the evaluator.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import time
import uuid
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .db import IdentityReuse, StaleFence, TownDB
from .records import TestProfile, fingerprint

ACK_STATUSES = {"received", "processed", "rejected", "retryable", "failed"}
FAULT_TARGET_KIND = "quote_request"


class CreateRun(BaseModel):
    profile: TestProfile
    identities: dict[str, dict[str, str]] = {}


class JoinBody(BaseModel):
    name: str
    token: str = ""
    grant: dict[str, Any] | None = None
    grant_signature: str = ""
    session_proof: str = ""


class SendBody(BaseModel):
    message_id: str
    to: str
    kind: str
    body: dict[str, Any]


class AckBody(BaseModel):
    message_id: str
    fence: str
    status: str
    note: dict[str, Any] = {}


class EventBody(BaseModel):
    observer: str
    kind: str
    subject: str
    detail: dict[str, Any] = {}


def build_app(db_path: str, admin_token: str) -> FastAPI:
    app = FastAPI(title="nandatown coordinator", version="0.2.0")
    db = TownDB(db_path)
    # Fault bookkeeping per run: each fault fires at most once.
    faults: dict[str, dict[str, Any]] = {}

    def deny(run_id: str, name: str, permission: str, now: float) -> None:
        """A refused action is evidence: record it, then refuse."""
        db.record_event(run_id, observer="town",
                        kind="grant_permission_denied", subject=name,
                        at=now, detail={"permission": permission})
        raise HTTPException(
            status_code=403,
            detail={"error": "grant_permission_denied",
                    "permission": permission})

    def require_permission(run_id: str, name: str, permission: str,
                           now: float) -> None:
        """A grant-joined session acts only within its grant. The
        permissions live with the session in the database, as do the
        pinned identities, so both hold across a coordinator restart and
        across workers. A token-joined session carries no grant and is
        unrestricted; a role pinned to an identity cannot token-join."""
        permissions = db.session_permissions(run_id, name)
        if permissions is not None and permission not in permissions:
            deny(run_id, name, permission, now)

    def require_grant_for_pinned_role(run_id: str, name: str, token: str,
                                      now: float) -> None:
        """A role pinned to a portable identity joins only through its
        Run Grant; a bare token must not sidestep the grant's limits.
        Only the holder of the real token leaves a mark in the evidence;
        a wrong token is refused without writing anything, so nobody can
        pad an attested bundle knowing just the run id."""
        if db.pinned_identity(run_id, name) is None:
            return
        if token != db.join_token(run_id, name):
            raise HTTPException(status_code=403, detail="join rejected")
        db.record_event(run_id, observer="town", kind="grant_required",
                        subject=name, at=now,
                        detail={"attempted": "token join"})
        raise HTTPException(
            status_code=403,
            detail={"error": "grant_required",
                    "reason": "this role is pinned to a portable identity;"
                              " join with its run grant"})

    def fault_state(run_id: str) -> dict[str, Any]:
        if run_id not in faults:
            profile = db.run_profile(run_id) or {}
            faults[run_id] = {"fault": profile.get("fault", "none"),
                              "fired": False,
                              "lease": profile.get("lease_seconds", 5.0)}
        return faults[run_id]

    def require_admin(x_town_admin: str = Header(default="")):
        if x_town_admin != admin_token:
            raise HTTPException(status_code=401, detail="admin token required")

    def participant(run_id: str, x_town_session: str = Header(default="")):
        name = db.session_owner(run_id, x_town_session)
        if name is None:
            raise HTTPException(status_code=401, detail="valid session required")
        return name

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/runs", dependencies=[Depends(require_admin)])
    def create_run(body: CreateRun):
        now = time.time()
        profile = body.profile
        run_id = db.create_run(profile.model_dump_json(), now=now)
        join_tokens = {}
        for name, role in profile.roles.items():
            token = secrets.token_hex(16)
            db.add_participant(run_id, name, role,
                               profile.capabilities.get(name, []), token)
            join_tokens[name] = token
        if body.identities:
            db.pin_identities(run_id, body.identities)
        db.record_event(run_id, observer="town", kind="run_created",
                        subject=run_id, at=now,
                        detail={"profile": profile.name,
                                "profile_fingerprint":
                                    fingerprint(profile.model_dump()),
                                "fault": profile.fault,
                                "portable_identities":
                                    sorted(body.identities)})
        return {"run_id": run_id, "join_tokens": join_tokens}

    @app.post("/runs/{run_id}/join")
    def join(run_id: str, body: JoinBody):
        now = time.time()
        profile = db.run_profile(run_id)
        if profile is None:
            raise HTTPException(status_code=404, detail="unknown run")
        if body.grant is not None:
            from .identity_portable import IdentityError, verify_grant

            pinned = db.pinned_identity(run_id, body.name)
            if pinned is None:
                raise HTTPException(
                    status_code=403,
                    detail="no portable identity pinned for this role"
                           " in this run")
            try:
                verify_grant(body.grant, body.grant_signature,
                             pinned["controller_public"], run_id,
                             body.name, body.session_proof, now=now)
            except IdentityError as exc:
                db.record_event(run_id, observer="town",
                                kind="grant_rejected", subject=body.name,
                                at=now, detail={"reason": str(exc)})
                raise HTTPException(status_code=403,
                                    detail=f"grant rejected: {exc}")
            if "join" not in body.grant["permissions"]:
                deny(run_id, body.name, "join", now)
            row_token = db.join_token(run_id, body.name)
            if row_token is None:
                raise HTTPException(status_code=403,
                                    detail="unknown participant")
            session = db.authenticate(
                run_id, body.name, row_token, now=now,
                permissions=body.grant["permissions"],
                grant_issued_at=float(body.grant["issued_at"]))
            db.record_event(
                run_id, observer="town",
                kind="portable_identity_verified", subject=body.name,
                at=now,
                detail={"agent_id": pinned["agent_id"],
                        "session_public": body.grant["session_public"],
                        "permissions": body.grant["permissions"],
                        "expires_at": body.grant["expires_at"]})
        else:
            require_grant_for_pinned_role(run_id, body.name, body.token, now)
            session = db.authenticate(run_id, body.name, body.token,
                                      now=now)
        if session is None:
            raise HTTPException(status_code=403, detail="join rejected")
        db.record_event(run_id, observer="town", kind="participant_joined",
                        subject=body.name, at=now)
        return {
            "session": session,
            "participant_id": body.name,
            "run": {"run_id": run_id, "task": profile["task"],
                    "roles": profile["roles"],
                    "lease_seconds": profile["lease_seconds"]},
        }

    @app.get("/runs/{run_id}/participants")
    def directory(run_id: str, name: str = Depends(participant)):
        return db.directory(run_id)

    @app.post("/runs/{run_id}/messages", status_code=202)
    def send(run_id: str, body: SendBody, name: str = Depends(participant)):
        now = time.time()
        db.record_intent(run_id, actor=name, action="send",
                         payload=body.model_dump(), at=now)
        require_permission(run_id, name, "send", now)
        state = fault_state(run_id)
        suppress = False
        if (state["fault"] == "drop_wakeup" and not state["fired"]
                and body.kind == FAULT_TARGET_KIND):
            suppress = True
            state["fired"] = True
        try:
            accepted_at, replay = db.accept_message(
                run_id, sender=name, message_id=body.message_id, to=body.to,
                kind=body.kind, body=body.body,
                content_fingerprint=fingerprint(body.body), now=now,
                suppress_notify=suppress,
            )
        except IdentityReuse:
            raise HTTPException(
                status_code=409,
                detail={"error": "identity_reuse", "message_id": body.message_id},
            )
        if suppress and not replay:
            db.record_event(run_id, observer="town", kind="notify_suppressed",
                            subject=body.message_id, at=now,
                            detail={"fault": "drop_wakeup"})
        return {"message_id": body.message_id, "accepted_at": accepted_at,
                "replay": replay}

    @app.get("/runs/{run_id}/inbox/notify")
    async def notify(run_id: str, wait: float = 0.0,
                     name: str = Depends(participant)):
        deadline = time.time() + max(0.0, min(wait, 30.0))
        while True:
            if db.pop_notify(run_id, name):
                return {"hint": True}
            if time.time() >= deadline:
                return {"hint": False}
            await asyncio.sleep(0.05)

    @app.post("/runs/{run_id}/inbox/claim")
    def claim(run_id: str, name: str = Depends(participant)):
        now = time.time()
        db.record_intent(run_id, actor=name, action="claim", payload={}, at=now)
        require_permission(run_id, name, "claim", now)
        state = fault_state(run_id)
        result = db.claim_next(run_id, name, lease_seconds=state["lease"],
                               now=now)
        if result is None and state["fault"] == "duplicate_delivery" \
                and not state["fired"]:
            done = state.get("done_target")
            if done:
                result = db.reoffer(run_id, done, name,
                                    lease_seconds=state["lease"], now=now)
                if result is not None:
                    state["fired"] = True
                    db.record_event(run_id, observer="town",
                                    kind="duplicate_offered", subject=done,
                                    at=now, detail={"fault":
                                                    "duplicate_delivery"})
        if result is None:
            from fastapi import Response
            return Response(status_code=204)
        return result

    @app.post("/runs/{run_id}/inbox/ack")
    def ack(run_id: str, body: AckBody, name: str = Depends(participant)):
        now = time.time()
        db.record_intent(run_id, actor=name, action="ack",
                         payload=body.model_dump(), at=now)
        require_permission(run_id, name, "ack", now)
        if body.status not in ACK_STATUSES:
            raise HTTPException(status_code=422, detail="unknown ack status")
        state = fault_state(run_id)
        if (state["fault"] == "lost_ack" and not state["fired"]
                and body.status == "processed"):
            state["fired"] = True
            db.record_event(run_id, observer="town", kind="ack_dropped",
                            subject=body.message_id, at=now,
                            detail={"fault": "lost_ack",
                                    "participant": name})
            raise HTTPException(status_code=503,
                                detail={"error": "ack_lost"})
        try:
            db.ack(run_id, name, body.message_id, body.fence, body.status,
                   body.note, now=now)
        except StaleFence:
            raise HTTPException(
                status_code=409,
                detail={"error": "stale_fence", "message_id": body.message_id},
            )
        if (body.status == "processed"
                and state["fault"] == "duplicate_delivery"
                and db.message_kind(run_id, body.message_id)
                == FAULT_TARGET_KIND):
            state.setdefault("done_target", body.message_id)
        return {"recorded": True}

    @app.get("/runs/{run_id}/events", dependencies=[Depends(require_admin)])
    def events(run_id: str):
        return {"events": db.events(run_id)}

    @app.get("/runs/{run_id}/intents", dependencies=[Depends(require_admin)])
    def intents(run_id: str):
        return {"intents": db.intents(run_id)}

    @app.post("/runs/{run_id}/events", dependencies=[Depends(require_admin)])
    def post_event(run_id: str, body: EventBody):
        event_id = db.record_event(run_id, observer=body.observer,
                                   kind=body.kind, subject=body.subject,
                                   at=time.time(), detail=body.detail)
        return {"event_id": event_id}

    @app.post("/runs/{run_id}/finish", dependencies=[Depends(require_admin)])
    def finish(run_id: str):
        db.set_run_status(run_id, "finished")
        db.record_event(run_id, observer="town", kind="run_finished",
                        subject=run_id, at=time.time())
        return {"finished": True}

    return app


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(prog="nandatown-coordinator")
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8477)
    args = parser.parse_args()
    admin_token = os.environ.get("TOWN_ADMIN_TOKEN") or secrets.token_hex(16)
    if "TOWN_ADMIN_TOKEN" not in os.environ:
        print(f"admin token: {admin_token}")
    app = build_app(args.db, admin_token=admin_token)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
