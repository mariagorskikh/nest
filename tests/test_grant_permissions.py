"""A Run Grant's named permissions are enforced on every mailbox action.

The grant is verified at join; these tests pin down what happens after.
A grant-joined session may only join, claim, send, or ack when its grant
names that permission, and a role pinned to a portable identity cannot
sidestep its grant by joining with a bare token. A denial is evidence:
the requested action is recorded as an intent and the refusal as a
town-attributed event, so a bundle can show that an agent tried to do
something it was not authorized to do. Pinned identities and session
permissions live in the database, so both hold across a coordinator
restart. Token-joined sessions of unpinned roles carry no grant and are
unaffected.
"""

import os
import sqlite3
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient

from nandatown.coordinator import build_app
from nandatown.db import TownDB
from nandatown.identity_portable import Keystore, session_proof
from nandatown.records import TestProfile
from nandatown.runner import run_town

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ADMIN = {"X-Town-Admin": "secret"}
BODY = {"sku": "widget", "quantity": 2, "unit_price_cents": 1995}
ALL = ["join", "claim", "send", "ack"]


def _profile(fault: str = "none") -> dict:
    return TestProfile(
        name=f"quote-{fault}",
        task={"kind": "quote", "sku": "widget", "quantity": 2,
              "unit_price_cents": 1995, "expected_total_cents": 3990},
        roles={"buyer": "buyer", "seller": "seller"},
        capabilities={"buyer": [], "seller": ["quote.read"]},
        fault=fault,
        lease_seconds=5.0,
        evaluator="stage-evaluator",
    ).model_dump()


@pytest.fixture()
def town(tmp_path):
    app = build_app(str(tmp_path / "town.db"), admin_token="secret")
    keystore = Keystore(str(tmp_path / "keys"))
    with TestClient(app) as client:
        yield client, keystore


def _session_row(tmp_path, run_id: str, name: str):
    conn = sqlite3.connect(str(tmp_path / "town.db"))
    try:
        return conn.execute(
            "SELECT session, permissions_json FROM participants"
            " WHERE run_id=? AND name=?", (run_id, name)).fetchone()
    finally:
        conn.close()


def _create_run(client, keystore, granted_roles: list[str],
                fault: str = "none") -> dict:
    identities = {name: {k: v for k, v in keystore.new_identity(name).items()
                         if k in ("agent_id", "controller_public")}
                  for name in granted_roles}
    r = client.post("/runs", json={"profile": _profile(fault),
                                   "identities": identities},
                    headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def _post_grant_join(client, run_id: str, name: str, grant: dict,
                     signature: str, session_private: str):
    proof = session_proof(session_private, run_id, name)
    return client.post(f"/runs/{run_id}/join",
                       json={"name": name, "grant": grant,
                             "grant_signature": signature,
                             "session_proof": proof})


def _join_with_grant(client, keystore, run_id: str, name: str,
                     permissions: list[str]) -> dict:
    bundle = keystore.make_grant(name, run_id, permissions=permissions)
    r = _post_grant_join(client, run_id, name, bundle["grant"],
                         bundle["grant_signature"], bundle["session_private"])
    assert r.status_code == 200, r.text
    return {"X-Town-Session": r.json()["session"]}


def _post_token_join(client, run_id: str, name: str, token: str):
    return client.post(f"/runs/{run_id}/join",
                       json={"name": name, "token": token})


def _join_with_token(client, run_id: str, name: str, token: str) -> dict:
    r = _post_token_join(client, run_id, name, token)
    assert r.status_code == 200, r.text
    return {"X-Town-Session": r.json()["session"]}


def _send(client, run_id, headers, message_id="q-1", to="seller",
          kind="quote_request"):
    return client.post(f"/runs/{run_id}/messages",
                       json={"message_id": message_id, "to": to,
                             "kind": kind, "body": BODY},
                       headers=headers)


def _claim(client, run_id, headers):
    return client.post(f"/runs/{run_id}/inbox/claim", headers=headers)


def _ack(client, run_id, headers, work, status="processed"):
    return client.post(f"/runs/{run_id}/inbox/ack",
                       json={"message_id": work["message_id"],
                             "fence": work["fence"], "status": status},
                       headers=headers)


def _events(client, run_id):
    r = client.get(f"/runs/{run_id}/events", headers=ADMIN)
    return r.json()["events"]


def _kinds(client, run_id):
    return [e["kind"] for e in _events(client, run_id)]


def _intents(client, run_id):
    r = client.get(f"/runs/{run_id}/intents", headers=ADMIN)
    return r.json()["intents"]


def _denials(client, run_id):
    return [e["detail"]["permission"] for e in _events(client, run_id)
            if e["kind"] == "grant_permission_denied"]


# -- each permission gates its action ----------------------------------------

def test_send_denied_without_send_permission(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    buyer = _join_with_grant(client, keystore, run_id, "buyer",
                             permissions=["join", "claim", "ack"])

    r = _send(client, run_id, buyer)

    assert r.status_code == 403, r.text
    assert r.json()["detail"] == {"error": "grant_permission_denied",
                                  "permission": "send"}
    denials = [e for e in _events(client, run_id)
               if e["kind"] == "grant_permission_denied"]
    assert len(denials) == 1
    assert denials[0]["subject"] == "buyer"
    assert denials[0]["observer"] == "town"
    assert denials[0]["detail"]["permission"] == "send"
    # The attempt itself is evidence: the intent is recorded, then denied.
    assert any(i["actor"] == "buyer" and i["action"] == "send"
               for i in _intents(client, run_id))


def test_denied_send_is_never_delivered(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    buyer = _join_with_grant(client, keystore, run_id, "buyer",
                             permissions=["join"])
    seller = _join_with_token(client, run_id, "seller",
                              data["join_tokens"]["seller"])

    assert _send(client, run_id, buyer).status_code == 403

    assert _claim(client, run_id, seller).status_code == 204, \
        "nothing should be in the inbox"
    assert "message_accepted" not in _kinds(client, run_id)


def test_claim_denied_without_claim_permission_takes_no_lease(town):
    client, keystore = town
    data = _create_run(client, keystore, ["seller"])
    run_id = data["run_id"]
    buyer = _join_with_token(client, run_id, "buyer",
                             data["join_tokens"]["buyer"])
    seller = _join_with_grant(client, keystore, run_id, "seller",
                              permissions=["join", "send", "ack"])
    assert _send(client, run_id, buyer).status_code == 202

    r = _claim(client, run_id, seller)

    assert r.status_code == 403, r.text
    assert r.json()["detail"]["permission"] == "claim"
    assert _denials(client, run_id) == ["claim"]
    assert "message_claimed" not in _kinds(client, run_id)


def test_ack_denied_without_ack_permission(town):
    client, keystore = town
    data = _create_run(client, keystore, ["seller"])
    run_id = data["run_id"]
    buyer = _join_with_token(client, run_id, "buyer",
                             data["join_tokens"]["buyer"])
    seller = _join_with_grant(client, keystore, run_id, "seller",
                              permissions=["join", "claim", "send"])
    assert _send(client, run_id, buyer).status_code == 202
    claimed = _claim(client, run_id, seller)
    assert claimed.status_code == 200, claimed.text

    r = _ack(client, run_id, seller, claimed.json())

    assert r.status_code == 403, r.text
    assert r.json()["detail"]["permission"] == "ack"
    assert _denials(client, run_id) == ["ack"]


def test_join_denied_without_join_permission_creates_no_session(
        town, tmp_path):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    bundle = keystore.make_grant("buyer", run_id,
                                 permissions=["claim", "send", "ack"])

    r = _post_grant_join(client, run_id, "buyer", bundle["grant"],
                         bundle["grant_signature"], bundle["session_private"])

    assert r.status_code == 403, r.text
    assert r.json()["detail"] == {"error": "grant_permission_denied",
                                  "permission": "join"}
    kinds = _kinds(client, run_id)
    assert "grant_permission_denied" in kinds
    assert "participant_joined" not in kinds
    assert "portable_identity_verified" not in kinds
    assert _session_row(tmp_path, run_id, "buyer") == (None, None), \
        "a denied join must not mint a session"


def test_empty_permissions_mean_nothing_not_everything(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    bundle = keystore.make_grant("buyer", run_id, permissions=[])

    assert bundle["grant"]["permissions"] == []
    r = _post_grant_join(client, run_id, "buyer", bundle["grant"],
                         bundle["grant_signature"], bundle["session_private"])
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["permission"] == "join"


# -- the grant's permissions field is validated before it is trusted --------

@pytest.mark.parametrize("permissions",
                         [None, "acknowledged", ["ack", 3], {"send": True}])
def test_malformed_permissions_reject_the_grant(town, permissions):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    bundle = keystore.make_grant("buyer", run_id, permissions=ALL)
    # Controller-signed, so only the validation stands between this
    # grant and an unrestricted session.
    grant = {**bundle["grant"], "permissions": permissions}
    signature = keystore.sign("buyer", grant)

    r = _post_grant_join(client, run_id, "buyer", grant, signature,
                         bundle["session_private"])

    assert r.status_code == 403, r.text
    assert "grant rejected" in r.json()["detail"]
    kinds = _kinds(client, run_id)
    assert "grant_rejected" in kinds
    assert "participant_joined" not in kinds


# -- a pinned role cannot sidestep its grant ----------------------------------

def test_pinned_role_cannot_join_with_a_bare_token(town, tmp_path):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]

    r = _post_token_join(client, run_id, "buyer",
                         data["join_tokens"]["buyer"])

    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "grant_required"
    kinds = _kinds(client, run_id)
    assert "grant_required" in kinds
    assert "participant_joined" not in kinds
    assert _session_row(tmp_path, run_id, "buyer") == (None, None)
    # The grant is still the way in.
    buyer = _join_with_grant(client, keystore, run_id, "buyer", ALL)
    assert _send(client, run_id, buyer).status_code == 202


def test_grant_rejoin_returns_the_same_session_with_its_new_limits(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    first = _join_with_grant(client, keystore, run_id, "buyer",
                             permissions=["join"])
    assert _send(client, run_id, first).status_code == 403

    again = _join_with_grant(client, keystore, run_id, "buyer",
                             permissions=["join", "send"])

    assert again == first, "a re-join returns the same session"
    assert _send(client, run_id, again).status_code == 202, \
        "the controller widened the grant, and the session follows it"


# -- the control fails closed ---------------------------------------------------

def test_restrictions_and_pins_survive_a_coordinator_restart(tmp_path):
    db_path = str(tmp_path / "town.db")
    keystore = Keystore(str(tmp_path / "keys"))
    with TestClient(build_app(db_path, admin_token="secret")) as first:
        data = _create_run(first, keystore, ["buyer", "seller"])
        run_id = data["run_id"]
        buyer = _join_with_grant(first, keystore, run_id, "buyer",
                                 permissions=["join", "claim", "ack"])
        assert _send(first, run_id, buyer).status_code == 403

    with TestClient(build_app(db_path, admin_token="secret")) as restarted:
        directory = restarted.get(f"/runs/{run_id}/participants",
                                  headers=buyer)
        assert directory.status_code == 200, "the session is still valid"
        assert _send(restarted, run_id, buyer,
                     message_id="q-2").status_code == 403
        assert _denials(restarted, run_id) == ["send", "send"]
        # The pins survived too: the seller can still grant-join, and
        # neither role can fall back to a bare token.
        seller = _join_with_grant(restarted, keystore, run_id, "seller", ALL)
        assert _claim(restarted, run_id, seller).status_code == 204
        token_join = _post_token_join(restarted, run_id, "buyer",
                                      data["join_tokens"]["buyer"])
        assert token_join.status_code == 403
        assert token_join.json()["detail"]["error"] == "grant_required"


# -- a denial changes nothing else -------------------------------------------

def test_denied_send_leaves_drop_wakeup_fault_armed(town):
    client, keystore = town
    data = _create_run(client, keystore, ["seller"], fault="drop_wakeup")
    run_id = data["run_id"]
    buyer = _join_with_token(client, run_id, "buyer",
                             data["join_tokens"]["buyer"])
    seller = _join_with_grant(client, keystore, run_id, "seller",
                              permissions=["join", "claim", "ack"])

    assert _send(client, run_id, seller, message_id="r-0",
                 to="buyer").status_code == 403
    assert _send(client, run_id, buyer).status_code == 202

    assert "notify_suppressed" in _kinds(client, run_id), \
        "the one-shot fault must fire on the first accepted send"


def test_denied_ack_leaves_lost_ack_fault_armed(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"], fault="lost_ack")
    run_id = data["run_id"]
    buyer = _join_with_grant(client, keystore, run_id, "buyer",
                             permissions=["join", "claim", "send"])
    seller = _join_with_token(client, run_id, "seller",
                              data["join_tokens"]["seller"])
    assert _send(client, run_id, buyer).status_code == 202
    work = _claim(client, run_id, seller).json()
    assert _send(client, run_id, seller, message_id="r-1", to="buyer",
                 kind="quote_response").status_code == 202
    reply = _claim(client, run_id, buyer).json()

    assert _ack(client, run_id, buyer, reply).status_code == 403
    lost = _ack(client, run_id, seller, work)

    assert lost.status_code == 503, lost.text
    assert lost.json()["detail"] == {"error": "ack_lost"}


# -- what is deliberately not gated --------------------------------------------

def test_restricted_session_can_still_discover_and_poll(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    buyer = _join_with_grant(client, keystore, run_id, "buyer",
                             permissions=["join"])

    assert client.get(f"/runs/{run_id}/participants",
                      headers=buyer).status_code == 200
    polled = client.get(f"/runs/{run_id}/inbox/notify",
                        params={"wait": 0}, headers=buyer)
    assert polled.status_code == 200
    assert polled.json() == {"hint": False}
    assert _denials(client, run_id) == []


def test_default_grant_permits_the_whole_mailbox(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer", "seller"])
    run_id = data["run_id"]
    assert keystore.make_grant("buyer", run_id)["grant"]["permissions"] \
        == sorted(ALL), "an unspecified grant is the default, full set"
    buyer = _join_with_grant(client, keystore, run_id, "buyer", ALL)
    seller = _join_with_grant(client, keystore, run_id, "seller", ALL)

    assert _send(client, run_id, buyer).status_code == 202
    claimed = _claim(client, run_id, seller)
    assert claimed.status_code == 200, claimed.text
    acked = _ack(client, run_id, seller, claimed.json())

    assert acked.status_code == 200, acked.text
    assert _denials(client, run_id) == []


def test_unpinned_token_sessions_are_not_restricted(town):
    client, keystore = town
    data = _create_run(client, keystore, [])
    run_id = data["run_id"]
    buyer = _join_with_token(client, run_id, "buyer",
                             data["join_tokens"]["buyer"])
    seller = _join_with_token(client, run_id, "seller",
                              data["join_tokens"]["seller"])

    assert _send(client, run_id, buyer).status_code == 202
    assert _claim(client, run_id, seller).status_code == 200
    assert _denials(client, run_id) == []


# -- databases from before these columns exist in the field --------------------

def test_older_databases_gain_the_permissions_column(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE participants (
            run_id TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL,
            capabilities_json TEXT NOT NULL, join_token TEXT NOT NULL,
            session TEXT, joined_at REAL, PRIMARY KEY (run_id, name));
    """)
    conn.execute("INSERT INTO participants VALUES"
                 " ('run-1', 'buyer', 'buyer', '[]', 'tok', NULL, NULL)")
    conn.commit()
    conn.close()

    db = TownDB(path)

    assert db.session_permissions("run-1", "buyer") is None
    session = db.authenticate("run-1", "buyer", "tok",
                              permissions=["send", "join"])
    assert session and db.session_permissions("run-1", "buyer") \
        == ["join", "send"]
    # An empty list is a real (fully restricted) grant, not "no grant".
    assert db.authenticate("run-1", "buyer", "tok", permissions=[]) \
        == session
    assert db.session_permissions("run-1", "buyer") == []
    assert db.pinned_identity("run-1", "buyer") is None


# -- a superseded grant cannot be replayed -------------------------------------

def test_replayed_older_wider_grant_does_not_rewiden(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]
    t0 = time.time()
    wide = keystore.make_grant("buyer", run_id, permissions=ALL, now=t0)
    narrow = keystore.make_grant("buyer", run_id, permissions=["join"],
                                 now=t0 + 10)

    def join(bundle):
        r = _post_grant_join(client, run_id, "buyer", bundle["grant"],
                             bundle["grant_signature"],
                             bundle["session_private"])
        assert r.status_code == 200, r.text
        return {"X-Town-Session": r.json()["session"]}

    session = join(wide)
    assert _send(client, run_id, session).status_code == 202
    assert join(narrow) == session
    assert _send(client, run_id, session, message_id="q-2").status_code \
        == 403, "the controller narrowed the grant"

    assert join(wide) == session
    assert _send(client, run_id, session, message_id="q-3").status_code \
        == 403, "replaying the older, wider grant must not re-widen"


def test_wrong_token_on_pinned_role_leaves_no_mark(town):
    client, keystore = town
    data = _create_run(client, keystore, ["buyer"])
    run_id = data["run_id"]

    for _ in range(3):
        r = _post_token_join(client, run_id, "buyer", "not-the-token")
        assert r.status_code == 403
        assert r.json()["detail"] == "join rejected"

    assert "grant_required" not in _kinds(client, run_id), \
        "knowing a run id alone must not let anyone write into its evidence"
    real = _post_token_join(client, run_id, "buyer",
                            data["join_tokens"]["buyer"])
    assert real.json()["detail"]["error"] == "grant_required"
    assert _kinds(client, run_id).count("grant_required") == 1


# -- the runner hands pinned roles their grant, and gives up on a harness
#    that cannot present one --------------------------------------------------

def test_identity_handoff_gives_an_external_agent_its_grant(tmp_path):
    handed: dict[str, dict[str, str]] = {}
    procs: list[subprocess.Popen] = []

    stderr_path = tmp_path / "external-seller.err"

    def on_credentials(role, env):
        handed[role] = dict(env)
        # Play the role from outside the runner with the stock seller,
        # which joins through TOWN_GRANT when it is present.
        full_env = {**os.environ, **env, "FAULT": "none", "DEADLINE": "30"}
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "nandatown.participants.seller"],
            env=full_env, stdout=subprocess.DEVNULL,
            stderr=open(stderr_path, "w")))

    try:
        bundle_dir, result = run_town(
            "quote-clean", str(tmp_path / "runs"),
            external={"seller": None}, identity_dir=str(tmp_path / "keys"),
            on_credentials=on_credentials)
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()

    assert set(handed["seller"]) == {"TOWN_URL", "RUN_ID", "NAME", "TOKEN",
                                     "STATE_DIR", "TOWN_GRANT"}, \
        "the spawned participants' environment contract, plus the grant"
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", (detail, stderr_path.read_text())
    assert next(s for s in result.stages
                if s.name == "portable_identity").status == "passed"


def test_identity_run_ends_early_for_a_token_only_agent(tmp_path):
    example = os.path.join(REPO_ROOT, "examples", "byoa_seller.py")
    started = time.time()

    bundle_dir, result = run_town(
        "quote-clean", str(tmp_path / "runs"),
        external={"seller": [sys.executable, example]},
        identity_dir=str(tmp_path / "keys"), wait_timeout=45.0)

    assert time.time() - started < 20, \
        "the runner must not wait out the timeout on a harness that" \
        " can never join"
    assert result.verdict != "passed"
    with open(os.path.join(bundle_dir, "events.jsonl")) as f:
        kinds = [__import__("json").loads(line)["kind"] for line in f]
    assert "grant_required" in kinds
    assert "harness_refused_grant" in kinds
