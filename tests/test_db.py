import json
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from nandatown.db import IdentityReuse, StaleFence, TownDB
from nandatown.records import fingerprint


@pytest.fixture()
def db(tmp_path):
    return TownDB(str(tmp_path / "town.db"))


@pytest.fixture()
def run(db):
    run_id = db.create_run(profile_json='{"name":"quote-clean"}')
    db.add_participant(run_id, "buyer", "buyer", [], "tok-b")
    db.add_participant(run_id, "seller", "seller", ["quote.read"], "tok-s")
    return run_id


BODY = {"sku": "widget", "quantity": 2, "unit_price_cents": 1995}
FP = fingerprint(BODY)


def accept(db, run_id, now=100.0, **changes):
    envelope = dict(sender="buyer", message_id="q-1", to="seller",
                    kind="quote_request", body=BODY, now=now)
    envelope.update(changes)
    envelope["content_fingerprint"] = fingerprint(envelope["body"])
    return db.accept_message(run_id, **envelope)


def stored_rows(db, table):
    with db._conn() as conn:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]


IDENTITY_CHANGES = [
    {"sender": "other-buyer"},
    {"to": "other-seller"},
    {"kind": "quote_response"},
    {"body": {"quantity": 3}},
]


@pytest.mark.parametrize("changes", IDENTITY_CHANGES,
                         ids=["sender", "recipient", "kind", "body"])
def test_complete_envelope_conflict_preserves_original_and_commits_rejection(db, run, changes):
    assert accept(db, run) == (100.0, False)
    original = stored_rows(db, "messages")
    notifications = stored_rows(db, "notifications")
    with pytest.raises(IdentityReuse):
        accept(db, run, now=200.0, **changes)
    reopened = TownDB(db.path)
    assert stored_rows(reopened, "messages") == original
    assert stored_rows(reopened, "notifications") == notifications
    events = reopened.events(run)
    assert [e["kind"] for e in events] == ["message_accepted", "identity_reuse_rejected"]
    assert events[-1]["at"] == 200.0
    assert events[-1]["subject"] == "q-1"
    assert events[-1]["detail"] == {"sender": changes.get("sender", "buyer")}


@pytest.mark.parametrize("state", ["accepted", "claimed", "done"])
@pytest.mark.parametrize("notification", ["pending", "consumed", "suppressed"])
def test_replay_preserves_work_and_notification_state(db, run, state, notification):
    accept(db, run, suppress_notify=notification == "suppressed")
    if notification == "consumed":
        assert db.pop_notify(run, "seller") is True
    if state != "accepted":
        claim = db.claim_next(run, "seller", lease_seconds=500.0, now=101.0)
        if state == "done":
            db.ack(run, "seller", "q-1", claim["fence"], "processed", {}, now=102.0)
    before = {t: stored_rows(db, t) for t in ("messages", "notifications", "claims", "acks")}
    reordered = {"unit_price_cents": 1995, "quantity": 2, "sku": "widget"}
    reopened = TownDB(db.path)
    assert accept(reopened, run, now=200.0, body=reordered,
                  suppress_notify=notification != "suppressed") == (100.0, True)
    assert {t: stored_rows(reopened, t) for t in before} == before
    assert before["messages"][0]["status"] == state
    assert before["messages"][0]["attempts"] == (0 if state == "accepted" else 1)
    assert before["messages"][0]["content_fingerprint"] == FP
    assert before["notifications"][0]["status"] == notification
    assert [e["kind"] for e in reopened.events(run)].count("message_accepted") == 1
    assert reopened.events(run)[-1]["kind"] == "replay_returned"
    if state != "accepted":
        assert reopened.claim_next(run, "seller", lease_seconds=5.0, now=201.0) is None


def test_same_message_id_is_independent_between_runs(db, run):
    other_run = db.create_run('{}')
    assert accept(db, run) == (100.0, False)
    assert accept(db, other_run, now=200.0, sender="other-buyer") == (200.0, False)
    assert len(stored_rows(db, "messages")) == 2
    assert len(stored_rows(db, "notifications")) == 2
    assert [e["kind"] for e in db.events(run)] == ["message_accepted"]
    assert [e["kind"] for e in db.events(other_run)] == ["message_accepted"]


def test_retry_from_fresh_process_preserves_acceptance(db, run):
    accept(db, run)
    script = """
import json, sys
from nandatown.db import TownDB
from nandatown.records import fingerprint
body = {"quantity": 2, "sku": "widget", "unit_price_cents": 1995}
print(json.dumps(TownDB(sys.argv[1]).accept_message(
    sys.argv[2], "buyer", "q-1", "seller", "quote_request", body,
    fingerprint(body), 200.0, suppress_notify=True)))
"""
    result = subprocess.run([sys.executable, "-c", script, db.path, run],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [100.0, True]
    assert len(stored_rows(db, "messages")) == 1
    assert [r["status"] for r in stored_rows(db, "notifications")] == ["pending"]
    assert [e["kind"] for e in db.events(run)] == ["message_accepted", "replay_returned"]


@pytest.mark.parametrize("table", ["notifications", "events"])
def test_acceptance_rolls_back_if_notification_or_event_insert_fails(db, run, table):
    with db._conn() as conn:
        conn.execute(f"CREATE TRIGGER fail_insert BEFORE INSERT ON {table} "
                     "BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="injected insert failure"):
        accept(db, run)
    assert stored_rows(db, "messages") == []
    assert stored_rows(db, "notifications") == []
    assert db.events(run) == []
    with db._conn() as conn:
        conn.execute("DROP TRIGGER fail_insert")
    assert accept(db, run, now=200.0) == (200.0, False)


@pytest.mark.parametrize("changes", [{}] + IDENTITY_CHANGES,
                         ids=["identical", "sender", "recipient", "kind", "body"])
def test_concurrent_acceptance_serializes_lookup_and_preserves_winner(db, run, monkeypatch, changes):
    # Start independent real SQLite connections together. For an unprotected
    # lookup only, finish both reads before either insert: this deterministically
    # exposes the old check/insert race. Never wait at a barrier while holding
    # a transaction/write lock; BEGIN IMMEDIATE makes the second barrier unused.
    start = threading.Barrier(2, timeout=10)
    unprotected_reads = threading.Barrier(2, timeout=10)

    class LookupCursor:
        def __init__(self, cursor, conn):
            self.cursor, self.conn = cursor, conn

        def fetchone(self):
            row = self.cursor.fetchone()
            if not self.conn.in_transaction:
                unprotected_reads.wait()
            return row

    class RacingConnection:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            cursor = self.conn.execute(sql, *args)
            if sql.startswith("SELECT") and "FROM messages" in sql:
                return LookupCursor(cursor, self.conn)
            return cursor

    def synchronize_first_connection(instance):
        original = instance._conn
        first = True

        @contextmanager
        def connection():
            nonlocal first
            with original() as conn:
                if first:
                    first = False
                    assert not conn.in_transaction
                    start.wait()
                yield RacingConnection(conn)
        monkeypatch.setattr(instance, "_conn", connection)

    contenders = [TownDB(db.path), TownDB(db.path)]
    for instance in contenders:
        synchronize_first_connection(instance)

    def send(index):
        try:
            return accept(contenders[index], run, now=100.0 + 100.0 * index,
                          suppress_notify=index == 0, **(changes if index else {}))
        except IdentityReuse:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(send, i) for i in range(2)]
        outcomes = [future.result(timeout=20) for future in futures]
    row, = stored_rows(db, "messages")
    winner = 0 if row["accepted_at"] == 100.0 else 1
    assert outcomes[winner] == (100.0 + 100.0 * winner, False)
    assert outcomes[1 - winner] == ("rejected" if changes else (row["accepted_at"], True))
    expected = dict(sender="buyer", to="seller", kind="quote_request", body=BODY)
    if winner:
        expected.update(changes)
    assert (row["sender"], row["recipient"], row["kind"], json.loads(row["body_json"])) == (
        expected["sender"], expected["to"], expected["kind"], expected["body"])
    assert row["status"] == "accepted" and row["attempts"] == 0
    notification, = stored_rows(db, "notifications")
    assert notification == dict(run_id=run, recipient=expected["to"], message_id="q-1",
                                status="suppressed" if winner == 0 else "pending")
    events = db.events(run)
    assert [e["kind"] for e in events] == ["message_accepted",
        "identity_reuse_rejected" if changes else "replay_returned"]
    assert events[0]["at"] == row["accepted_at"]


def test_accept_then_claim_returns_work_with_fence(db, run):
    accepted_at, replay = accept(db, run)
    assert accepted_at == 100.0 and replay is False
    claim = db.claim_next(run, "seller", lease_seconds=5.0, now=101.0)
    assert claim["message_id"] == "q-1"
    assert claim["attempt"] == 1
    assert claim["body"] == BODY
    assert claim["from"] == "buyer"
    assert claim["lease_expires_at"] == 106.0
    assert claim["fence"]


def test_concurrent_claim_issues_one_active_fence(db, run, monkeypatch):
    """Two SQLite connections must not both claim the same accepted work."""
    accept(db, run)
    start = threading.Barrier(2, timeout=10)
    unprotected_reads = threading.Barrier(2, timeout=10)

    class ClaimCursor:
        def __init__(self, cursor, conn):
            self.cursor, self.conn = cursor, conn

        def fetchone(self):
            row = self.cursor.fetchone()
            # On the broken implementation, both real connections finish the
            # accepted-row lookup before either writes. An immediate write
            # transaction deliberately makes this barrier unnecessary.
            if not self.conn.in_transaction:
                unprotected_reads.wait()
            return row

    class RacingConnection:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            cursor = self.conn.execute(sql, *args)
            if sql.startswith("SELECT * FROM messages") \
                    and "status='accepted'" in sql:
                return ClaimCursor(cursor, self.conn)
            return cursor

    def synchronize(instance):
        original = instance._conn
        first = True

        @contextmanager
        def connection():
            nonlocal first
            with original() as conn:
                if first:
                    first = False
                    start.wait()
                yield RacingConnection(conn)

        monkeypatch.setattr(instance, "_conn", connection)

    contenders = [TownDB(db.path), TownDB(db.path)]
    for contender in contenders:
        synchronize(contender)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(contender.claim_next, run, "seller", 5.0, 101.0)
            for contender in contenders
        ]
        outcomes = [future.result(timeout=20) for future in futures]

    assert sum(outcome is not None for outcome in outcomes) == 1
    message, = stored_rows(db, "messages")
    assert message["status"] == "claimed"
    assert message["attempts"] == 1
    claims = stored_rows(db, "claims")
    assert len(claims) == 1
    assert claims[0]["active"] == 1
    assert [event["kind"] for event in db.events(run)].count(
        "message_claimed") == 1


def test_idempotent_resend_and_identity_reuse(db, run):
    accept(db, run, now=100.0)
    accepted_at, replay = accept(db, run, now=200.0)
    assert accepted_at == 100.0 and replay is True
    with pytest.raises(IdentityReuse):
        db.accept_message(
            run, sender="buyer", message_id="q-1", to="seller",
            kind="quote_request", body={"quantity": 3},
            content_fingerprint=fingerprint({"quantity": 3}), now=201.0,
        )


def test_notification_written_in_same_transaction(db, run):
    accept(db, run)
    assert db.pop_notify(run, "seller") is True
    assert db.pop_notify(run, "seller") is False


def test_expired_lease_reclaim_and_stale_fence(db, run):
    accept(db, run)
    first = db.claim_next(run, "seller", lease_seconds=2.0, now=101.0)
    assert db.claim_next(run, "seller", lease_seconds=2.0, now=102.0) is None
    second = db.claim_next(run, "seller", lease_seconds=2.0, now=104.0)
    assert second["message_id"] == "q-1"
    assert second["attempt"] == 2
    assert second["fence"] != first["fence"]
    with pytest.raises(StaleFence):
        db.ack(run, "seller", "q-1", first["fence"], "processed", {}, now=104.5)
    kinds = [e["kind"] for e in db.events(run)]
    assert "claim_expired" in kinds
    assert "stale_fence_rejected" in kinds


def test_lease_expiry_inside_ack_is_stale(db, run):
    accept(db, run)
    first = db.claim_next(run, "seller", lease_seconds=2.0, now=101.0)
    with pytest.raises(StaleFence):
        db.ack(run, "seller", "q-1", first["fence"], "processed", {}, now=110.0)
    again = db.claim_next(run, "seller", lease_seconds=2.0, now=111.0)
    assert again["attempt"] == 2


def test_ack_and_reclaim_have_only_serial_outcomes(db, run, monkeypatch):
    """A fence cannot acknowledge after another connection reclaims it."""
    accept(db, run)
    first = db.claim_next(run, "seller", lease_seconds=2.0, now=101.0)
    ack_db = TownDB(db.path)
    reclaim_db = TownDB(db.path)
    claim_selected = threading.Event()
    reclaim_finished = threading.Event()

    class AckCursor:
        def __init__(self, cursor, conn):
            self.cursor, self.conn = cursor, conn

        def fetchone(self):
            row = self.cursor.fetchone()
            claim_selected.set()
            # Reproduce the check/use gap only when the lookup is not already
            # protected by a write transaction. With the repair, ack proceeds
            # atomically and the competing reclaim observes completed work.
            if not self.conn.in_transaction:
                assert reclaim_finished.wait(timeout=10)
            return row

    class AckConnection:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            cursor = self.conn.execute(sql, *args)
            if sql.startswith("SELECT * FROM claims") and "fence=?" in sql:
                return AckCursor(cursor, self.conn)
            return cursor

    original = ack_db._conn
    first_connection = True

    @contextmanager
    def synchronized_ack_connection():
        nonlocal first_connection
        with original() as conn:
            if first_connection:
                first_connection = False
                yield AckConnection(conn)
            else:
                yield conn

    monkeypatch.setattr(ack_db, "_conn", synchronized_ack_connection)

    def acknowledge():
        try:
            ack_db.ack(run, "seller", "q-1", first["fence"],
                       "processed", {}, now=102.0)
            return "acked"
        except StaleFence:
            return "stale"

    def reclaim():
        assert claim_selected.wait(timeout=10)
        try:
            return reclaim_db.claim_next(run, "seller", lease_seconds=2.0,
                                         now=104.0)
        finally:
            reclaim_finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        ack_future = pool.submit(acknowledge)
        reclaim_future = pool.submit(reclaim)
        ack_outcome = ack_future.result(timeout=20)
        reclaimed = reclaim_future.result(timeout=20)

    if reclaimed is None:
        assert ack_outcome == "acked"
        message, = stored_rows(db, "messages")
        assert message["status"] == "done"
        assert not [claim for claim in stored_rows(db, "claims")
                    if claim["active"]]
    else:
        assert ack_outcome == "stale"
        message, = stored_rows(db, "messages")
        assert message["status"] == "claimed"
        active = [claim for claim in stored_rows(db, "claims")
                  if claim["active"]]
        assert len(active) == 1
        assert active[0]["fence"] == reclaimed["fence"]
        assert stored_rows(db, "acks") == []


def test_ack_completes_message(db, run):
    accept(db, run)
    claim = db.claim_next(run, "seller", lease_seconds=5.0, now=101.0)
    db.ack(run, "seller", "q-1", claim["fence"], "processed",
           {"applied": True}, now=102.0)
    assert db.claim_next(run, "seller", lease_seconds=5.0, now=103.0) is None
    events = db.events(run)
    ack_events = [e for e in events if e["kind"] == "ack_recorded"]
    assert len(ack_events) == 1
    assert ack_events[0]["observer"] == "seller"
    assert ack_events[0]["detail"]["note"] == {"applied": True}


def test_retryable_ack_returns_work_to_inbox(db, run):
    accept(db, run)
    claim = db.claim_next(run, "seller", lease_seconds=5.0, now=101.0)
    db.ack(run, "seller", "q-1", claim["fence"], "retryable", {}, now=102.0)
    again = db.claim_next(run, "seller", lease_seconds=5.0, now=103.0)
    assert again["attempt"] == 2


def test_sessions_and_directory(db, run):
    session = db.authenticate(run, "seller", "tok-s")
    assert db.session_owner(run, session) == "seller"
    assert db.session_owner(run, "bogus") is None
    assert db.authenticate(run, "seller", "wrong") is None
    directory = db.directory(run)
    assert {d["name"] for d in directory} == {"buyer", "seller"}
    seller = next(d for d in directory if d["name"] == "seller")
    assert seller["capabilities"] == ["quote.read"]


def test_events_and_intents_are_ordered(db, run):
    db.record_event(run, observer="town", kind="run_created", subject=run, at=1.0)
    db.record_event(run, observer="town", kind="participant_joined",
                    subject="buyer", at=2.0)
    db.record_intent(run, actor="buyer", action="send",
                     payload={"message_id": "q-1"}, at=2.5)
    events = db.events(run)
    assert [e["kind"] for e in events] == ["run_created", "participant_joined"]
    assert events[0]["event_id"] == "ev-1"
    intents = db.intents(run)
    assert intents[0]["action"] == "send"
    assert intents[0]["intent_id"] == "in-1"
