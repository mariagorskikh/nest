"""Durable town state on SQLite.

The database is the source of operational truth. Accepted work and the
intent to notify the recipient are recorded in one transaction. Live
notifications are wake-up hints, never the only copy of the work.
Delivery is at-least-once: leases expire, claims are fenced, and a stale
fence can never acknowledge work.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Any

from .records import fingerprint


class IdentityReuse(Exception):
    """Same message identity resent with different content."""


class StaleFence(Exception):
    """An acknowledgement carried a fence that is no longer current."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    profile_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'created',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS participants (
    run_id TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    join_token TEXT NOT NULL,
    session TEXT,
    joined_at REAL,
    permissions_json TEXT,
    grant_issued_at REAL,
    PRIMARY KEY (run_id, name)
);
CREATE TABLE IF NOT EXISTS run_identities (
    run_id TEXT NOT NULL,
    name TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    controller_public TEXT NOT NULL,
    PRIMARY KEY (run_id, name)
);
CREATE TABLE IF NOT EXISTS messages (
    run_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    kind TEXT NOT NULL,
    body_json TEXT NOT NULL,
    content_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'accepted',
    accepted_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    done_status TEXT,
    PRIMARY KEY (run_id, message_id)
);
CREATE TABLE IF NOT EXISTS claims (
    claim_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    claimant TEXT NOT NULL,
    fence TEXT NOT NULL UNIQUE,
    lease_expires_at REAL NOT NULL,
    attempt INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS notifications (
    run_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    message_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS acks (
    run_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    participant TEXT NOT NULL,
    fence TEXT NOT NULL,
    status TEXT NOT NULL,
    note_json TEXT NOT NULL,
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    at REAL NOT NULL,
    observer TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intents (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    at REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
"""


def _not_older(issued_at: float | None, recorded: float | None) -> bool:
    """May a grant issued at issued_at replace the one recorded?"""
    if issued_at is None or recorded is None:
        return True
    return issued_at >= recorded


class TownDB:
    def __init__(self, path: str):
        self.path = path
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    _PARTICIPANT_COLUMNS_ADDED = (("permissions_json", "TEXT"),
                                  ("grant_issued_at", "REAL"))

    @classmethod
    def _migrate(cls, conn) -> None:
        """Bring a database created by an earlier release up to date."""
        columns = {row["name"] for row in
                   conn.execute("PRAGMA table_info(participants)")}
        for column, declared in cls._PARTICIPANT_COLUMNS_ADDED:
            if column not in columns:
                conn.execute(f"ALTER TABLE participants"
                             f" ADD COLUMN {column} {declared}")

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # -- runs and participants ------------------------------------------

    def create_run(self, profile_json: str, now: float = 0.0) -> str:
        run_id = "run-" + uuid.uuid4().hex[:12]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO runs (run_id, profile_json, created_at) VALUES (?,?,?)",
                (run_id, profile_json, now),
            )
        return run_id

    def run_profile(self, run_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT profile_json FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
        return json.loads(row["profile_json"]) if row else None

    def set_run_status(self, run_id: str, status: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE runs SET status=? WHERE run_id=?", (status, run_id))

    def add_participant(
        self, run_id: str, name: str, role: str,
        capabilities: list[str], join_token: str,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO participants (run_id, name, role, capabilities_json,"
                " join_token) VALUES (?,?,?,?,?)",
                (run_id, name, role, json.dumps(capabilities), join_token),
            )

    def authenticate(self, run_id: str, name: str, token: str,
                     now: float = 0.0,
                     permissions: list[str] | None = None,
                     grant_issued_at: float | None = None) -> str | None:
        """Exchange a join token for the participant's session, minting
        one on first join. A grant's permissions are written in the same
        transaction, so a session never exists without the restrictions
        its grant named; None means a token join, which carries no grant.
        A re-join with a newer grant replaces the permissions; an older
        grant never does, so a superseded wider grant cannot be replayed
        to re-widen a session the controller has since narrowed."""
        permissions_json = (None if permissions is None
                            else json.dumps(sorted(permissions)))
        with self._conn() as conn:
            row = conn.execute(
                "SELECT join_token, session, grant_issued_at"
                " FROM participants WHERE run_id=? AND name=?",
                (run_id, name),
            ).fetchone()
            if row is None or row["join_token"] != token:
                return None
            if row["session"]:
                if permissions_json is not None and _not_older(
                        grant_issued_at, row["grant_issued_at"]):
                    conn.execute(
                        "UPDATE participants SET permissions_json=?,"
                        " grant_issued_at=? WHERE run_id=? AND name=?",
                        (permissions_json, grant_issued_at, run_id, name),
                    )
                return row["session"]
            session = "ses-" + uuid.uuid4().hex
            conn.execute(
                "UPDATE participants SET session=?, joined_at=?,"
                " permissions_json=?, grant_issued_at=?"
                " WHERE run_id=? AND name=?",
                (session, now, permissions_json, grant_issued_at,
                 run_id, name),
            )
            return session

    def join_token(self, run_id: str, name: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT join_token FROM participants WHERE run_id=?"
                " AND name=?", (run_id, name)).fetchone()
        return row["join_token"] if row else None

    def pin_identities(self, run_id: str,
                       identities: dict[str, dict[str, str]]) -> None:
        """Pin each role's portable identity for this run. The town
        holds only the agent id and the controller's public key."""
        with self._conn() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO run_identities"
                " (run_id, name, agent_id, controller_public)"
                " VALUES (?, ?, ?, ?)",
                [(run_id, name, ident["agent_id"],
                  ident["controller_public"])
                 for name, ident in sorted(identities.items())],
            )

    def pinned_identity(self, run_id: str,
                        name: str) -> dict[str, str] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT agent_id, controller_public FROM run_identities"
                " WHERE run_id=? AND name=?", (run_id, name),
            ).fetchone()
        return dict(row) if row else None

    def session_permissions(self, run_id: str,
                            name: str) -> list[str] | None:
        """The permissions a grant-joined session carries, or None for
        a token-joined session, which carries no grant."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT permissions_json FROM participants"
                " WHERE run_id=? AND name=?",
                (run_id, name),
            ).fetchone()
        if row is None or row["permissions_json"] is None:
            return None
        return list(json.loads(row["permissions_json"]))

    def session_owner(self, run_id: str, session: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT name FROM participants WHERE run_id=? AND session=?",
                (run_id, session),
            ).fetchone()
        return row["name"] if row else None

    def directory(self, run_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT name, role, capabilities_json FROM participants"
                " WHERE run_id=? ORDER BY name",
                (run_id,),
            ).fetchall()
        return [
            {"name": r["name"], "role": r["role"],
             "capabilities": json.loads(r["capabilities_json"])}
            for r in rows
        ]

    # -- mailbox --------------------------------------------------------

    def accept_message(
        self, run_id: str, sender: str, message_id: str, to: str,
        kind: str, body: dict, content_fingerprint: str, now: float,
        suppress_notify: bool = False,
    ) -> tuple[float, bool]:
        """Accept work durably. Returns (accepted_at, replay).

        The message row and its notification row are written in one
        transaction. Retrying the same identity with identical content
        returns the original acceptance; different content raises
        IdentityReuse.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT accepted_at, content_fingerprint FROM messages"
                " WHERE run_id=? AND message_id=?",
                (run_id, message_id),
            ).fetchone()
            if row is not None:
                if row["content_fingerprint"] != content_fingerprint:
                    self._event(conn, run_id, now, "town",
                                "identity_reuse_rejected", message_id,
                                {"sender": sender})
                    reject = True
                else:
                    self._event(conn, run_id, now, "town", "replay_returned",
                                message_id, {"sender": sender})
                    reject = False
            else:
                reject = None
        if reject is True:
            raise IdentityReuse(message_id)
        if reject is False:
            return row["accepted_at"], True
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO messages (run_id, message_id, sender, recipient,"
                " kind, body_json, content_fingerprint, accepted_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (run_id, message_id, sender, to, kind,
                 json.dumps(body), content_fingerprint, now),
            )
            conn.execute(
                "INSERT INTO notifications (run_id, recipient, message_id,"
                " status) VALUES (?,?,?,?)",
                (run_id, to, message_id,
                 "suppressed" if suppress_notify else "pending"),
            )
            self._event(conn, run_id, now, "town", "message_accepted",
                        message_id,
                        {"sender": sender, "to": to, "kind": kind,
                         "content_fingerprint": content_fingerprint})
            return now, False

    def message_kind(self, run_id: str, message_id: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT kind FROM messages WHERE run_id=? AND message_id=?",
                (run_id, message_id),
            ).fetchone()
        return row["kind"] if row else None

    def pop_notify(self, run_id: str, recipient: str) -> bool:
        """Consume one pending wake-up hint, if any."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT rowid FROM notifications WHERE run_id=? AND recipient=?"
                " AND status='pending' LIMIT 1",
                (run_id, recipient),
            ).fetchone()
            if row is None:
                return False
            conn.execute(
                "UPDATE notifications SET status='consumed' WHERE rowid=?",
                (row["rowid"],),
            )
            return True

    def _expire_stale_claims(self, conn, run_id: str, now: float) -> None:
        rows = conn.execute(
            "SELECT claim_seq, message_id, claimant, fence FROM claims"
            " WHERE run_id=? AND active=1 AND lease_expires_at < ?",
            (run_id, now),
        ).fetchall()
        for r in rows:
            conn.execute("UPDATE claims SET active=0 WHERE claim_seq=?",
                         (r["claim_seq"],))
            conn.execute(
                "UPDATE messages SET status='accepted' WHERE run_id=?"
                " AND message_id=? AND status='claimed'",
                (run_id, r["message_id"]),
            )
            self._event(conn, run_id, now, "town", "claim_expired",
                        r["message_id"],
                        {"claimant": r["claimant"], "fence": r["fence"]})

    def claim_next(self, run_id: str, claimant: str, lease_seconds: float,
                   now: float) -> dict[str, Any] | None:
        """Claim one bounded piece of work for a limited time."""
        with self._conn() as conn:
            self._expire_stale_claims(conn, run_id, now)
            row = conn.execute(
                "SELECT * FROM messages WHERE run_id=? AND recipient=?"
                " AND status='accepted' ORDER BY accepted_at LIMIT 1",
                (run_id, claimant),
            ).fetchone()
            if row is None:
                return None
            attempt = row["attempts"] + 1
            fence = "fence-" + uuid.uuid4().hex
            lease_expires_at = now + lease_seconds
            conn.execute(
                "UPDATE messages SET status='claimed', attempts=? WHERE run_id=?"
                " AND message_id=?",
                (attempt, run_id, row["message_id"]),
            )
            conn.execute(
                "INSERT INTO claims (run_id, message_id, claimant, fence,"
                " lease_expires_at, attempt) VALUES (?,?,?,?,?,?)",
                (run_id, row["message_id"], claimant, fence,
                 lease_expires_at, attempt),
            )
            self._event(conn, run_id, now, "town", "message_claimed",
                        row["message_id"],
                        {"claimant": claimant, "attempt": attempt,
                         "fence": fence})
            return {
                "message_id": row["message_id"],
                "kind": row["kind"],
                "body": json.loads(row["body_json"]),
                "from": row["sender"],
                "attempt": attempt,
                "fence": fence,
                "lease_expires_at": lease_expires_at,
                "duplicate": False,
            }

    def reoffer(self, run_id: str, message_id: str, claimant: str,
                lease_seconds: float, now: float) -> dict[str, Any] | None:
        """Offer already-completed work one more time (duplicate delivery)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM messages WHERE run_id=? AND message_id=?"
                " AND recipient=?",
                (run_id, message_id, claimant),
            ).fetchone()
            if row is None:
                return None
            attempt = row["attempts"] + 1
            fence = "fence-" + uuid.uuid4().hex
            conn.execute(
                "UPDATE messages SET attempts=? WHERE run_id=? AND message_id=?",
                (attempt, run_id, message_id),
            )
            conn.execute(
                "INSERT INTO claims (run_id, message_id, claimant, fence,"
                " lease_expires_at, attempt) VALUES (?,?,?,?,?,?)",
                (run_id, message_id, claimant, fence, now + lease_seconds,
                 attempt),
            )
            return {
                "message_id": row["message_id"],
                "kind": row["kind"],
                "body": json.loads(row["body_json"]),
                "from": row["sender"],
                "attempt": attempt,
                "fence": fence,
                "lease_expires_at": now + lease_seconds,
                "duplicate": True,
            }

    def ack(self, run_id: str, participant: str, message_id: str, fence: str,
            status: str, note: dict, now: float) -> None:
        """Acknowledge claimed work. A stale or expired fence is rejected."""
        with self._conn() as conn:
            claim = conn.execute(
                "SELECT * FROM claims WHERE run_id=? AND message_id=?"
                " AND fence=? AND claimant=?",
                (run_id, message_id, fence, participant),
            ).fetchone()
            stale = (
                claim is None
                or claim["active"] == 0
                or claim["lease_expires_at"] < now
            )
            if stale:
                if claim is not None and claim["active"] == 1:
                    conn.execute(
                        "UPDATE claims SET active=0 WHERE claim_seq=?",
                        (claim["claim_seq"],),
                    )
                    conn.execute(
                        "UPDATE messages SET status='accepted' WHERE run_id=?"
                        " AND message_id=? AND status='claimed'",
                        (run_id, message_id),
                    )
                self._event(conn, run_id, now, "town", "stale_fence_rejected",
                            message_id,
                            {"participant": participant, "fence": fence})
        if stale:
            raise StaleFence(fence)
        with self._conn() as conn:
            conn.execute("UPDATE claims SET active=0 WHERE claim_seq=?",
                         (claim["claim_seq"],))
            if status == "retryable":
                new_status, done = "accepted", None
            else:
                new_status, done = "done", status
            conn.execute(
                "UPDATE messages SET status=?, done_status=? WHERE run_id=?"
                " AND message_id=? AND status IN ('claimed','done')",
                (new_status, done, run_id, message_id),
            )
            conn.execute(
                "INSERT INTO acks (run_id, message_id, participant, fence,"
                " status, note_json, at) VALUES (?,?,?,?,?,?,?)",
                (run_id, message_id, participant, fence, status,
                 json.dumps(note), now),
            )
            self._event(conn, run_id, now, participant, "ack_recorded",
                        message_id,
                        {"status": status, "note": note, "fence": fence,
                         "attempt": claim["attempt"]})

    # -- events and intents ---------------------------------------------

    def _event(self, conn, run_id: str, at: float, observer: str, kind: str,
               subject: str, detail: dict) -> str:
        cur = conn.execute(
            "INSERT INTO events (run_id, at, observer, kind, subject,"
            " detail_json) VALUES (?,?,?,?,?,?)",
            (run_id, at, observer, kind, subject, json.dumps(detail)),
        )
        return f"ev-{cur.lastrowid}"

    def record_event(self, run_id: str, observer: str, kind: str, subject: str,
                     at: float, detail: dict | None = None) -> str:
        with self._conn() as conn:
            return self._event(conn, run_id, at, observer, kind, subject,
                               detail or {})

    def events(self, run_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,)
            ).fetchall()
        return [
            {"event_id": f"ev-{r['seq']}", "run_id": r["run_id"],
             "at": r["at"], "observer": r["observer"], "kind": r["kind"],
             "subject": r["subject"], "detail": json.loads(r["detail_json"])}
            for r in rows
        ]

    def record_intent(self, run_id: str, actor: str, action: str,
                      payload: dict, at: float) -> str:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO intents (run_id, at, actor, action, payload_json)"
                " VALUES (?,?,?,?,?)",
                (run_id, at, actor, action, json.dumps(payload)),
            )
            return f"in-{cur.lastrowid}"

    def intents(self, run_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM intents WHERE run_id=? ORDER BY seq", (run_id,)
            ).fetchall()
        return [
            {"intent_id": f"in-{r['seq']}", "run_id": r["run_id"],
             "at": r["at"], "actor": r["actor"], "action": r["action"],
             "payload": json.loads(r["payload_json"])}
            for r in rows
        ]
