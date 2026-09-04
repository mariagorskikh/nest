import pytest
from fastapi.testclient import TestClient

from nandatown.coordinator import build_app
from nandatown.records import TestProfile, fingerprint

ADMIN = {"X-Town-Admin": "secret"}


def profile(fault="none", lease=5.0) -> dict:
    return TestProfile(
        name=f"quote-{fault}",
        task={"kind": "quote", "sku": "widget", "quantity": 2,
              "unit_price_cents": 1995, "expected_total_cents": 3990},
        roles={"buyer": "buyer", "seller": "seller"},
        capabilities={"buyer": [], "seller": ["quote.read"]},
        fault=fault,
        lease_seconds=lease,
        evaluator="stage-evaluator",
    ).model_dump()


@pytest.fixture()
def client(tmp_path):
    app = build_app(str(tmp_path / "town.db"), admin_token="secret")
    with TestClient(app) as c:
        yield c


def make_run(client, fault="none", lease=5.0):
    r = client.post("/runs", json={"profile": profile(fault, lease)}, headers=ADMIN)
    assert r.status_code == 200, r.text
    data = r.json()
    run_id = data["run_id"]
    sessions = {}
    for name, token in data["join_tokens"].items():
        j = client.post(f"/runs/{run_id}/join", json={"name": name, "token": token})
        assert j.status_code == 200, j.text
        sessions[name] = {"X-Town-Session": j.json()["session"]}
    return run_id, sessions, data


BODY = {"sku": "widget", "quantity": 2, "unit_price_cents": 1995}


def send_q1(client, run_id, sessions):
    return client.post(
        f"/runs/{run_id}/messages",
        json={"message_id": "q-1", "to": "seller", "kind": "quote_request",
              "body": BODY},
        headers=sessions["buyer"],
    )


def event_kinds(client, run_id):
    r = client.get(f"/runs/{run_id}/events", headers=ADMIN)
    return [e["kind"] for e in r.json()["events"]]


def test_join_returns_run_context(client):
    run_id, sessions, data = make_run(client)
    j = client.post(
        f"/runs/{run_id}/join",
        json={"name": "buyer", "token": data["join_tokens"]["buyer"]},
    )
    ctx = j.json()["run"]
    assert ctx["run_id"] == run_id
    assert ctx["task"]["expected_total_cents"] == 3990
    bad = client.post(f"/runs/{run_id}/join", json={"name": "buyer", "token": "x"})
    assert bad.status_code == 403


def test_happy_path_over_http(client):
    run_id, sessions, _ = make_run(client)

    d = client.get(f"/runs/{run_id}/participants", headers=sessions["buyer"])
    seller = next(p for p in d.json() if "quote.read" in p["capabilities"])
    assert seller["name"] == "seller"

    r = send_q1(client, run_id, sessions)
    assert r.status_code == 202
    assert r.json()["replay"] is False

    n = client.get(f"/runs/{run_id}/inbox/notify", params={"wait": 0},
                   headers=sessions["seller"])
    assert n.json()["hint"] is True

    c = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    claim = c.json()
    assert claim["message_id"] == "q-1"
    assert claim["body"] == BODY

    a = client.post(
        f"/runs/{run_id}/inbox/ack",
        json={"message_id": "q-1", "fence": claim["fence"],
              "status": "processed", "note": {"applied": True}},
        headers=sessions["seller"],
    )
    assert a.status_code == 200

    c2 = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    assert c2.status_code == 204

    kinds = event_kinds(client, run_id)
    for k in ["run_created", "participant_joined", "message_accepted",
              "message_claimed", "ack_recorded"]:
        assert k in kinds, kinds
    events = client.get(f"/runs/{run_id}/events", headers=ADMIN).json()["events"]
    ack_ev = next(e for e in events if e["kind"] == "ack_recorded")
    assert ack_ev["observer"] == "seller"

    intents = client.get(f"/runs/{run_id}/intents", headers=ADMIN).json()["intents"]
    assert [i["action"] for i in intents] == ["send", "claim", "ack", "claim"]


def test_auth_is_required(client):
    run_id, sessions, _ = make_run(client)
    assert client.get(f"/runs/{run_id}/participants").status_code == 401
    assert client.get(f"/runs/{run_id}/events").status_code == 401
    bad = client.get(f"/runs/{run_id}/participants",
                     headers={"X-Town-Session": "nope"})
    assert bad.status_code == 401


def test_replay_and_identity_reuse(client):
    run_id, sessions, _ = make_run(client)
    send_q1(client, run_id, sessions)
    r2 = send_q1(client, run_id, sessions)
    assert r2.status_code == 202 and r2.json()["replay"] is True
    r3 = client.post(
        f"/runs/{run_id}/messages",
        json={"message_id": "q-1", "to": "seller", "kind": "quote_request",
              "body": {"quantity": 3}},
        headers=sessions["buyer"],
    )
    assert r3.status_code == 409
    assert r3.json()["detail"]["error"] == "identity_reuse"


@pytest.mark.parametrize("field", ["sender", "to", "kind", "body"])
@pytest.mark.parametrize("fault", ["none", "drop_wakeup"])
def test_envelope_conflicts_and_completed_replay_do_not_reschedule(client, field, fault):
    run_id, sessions, _ = make_run(client, fault=fault)
    first = send_q1(client, run_id, sessions)
    assert first.status_code == 202 and first.json()["replay"] is False
    notify_url = f"/runs/{run_id}/inbox/notify"
    claim_url = f"/runs/{run_id}/inbox/claim"
    assert client.get(notify_url, params={"wait": 0}, headers=sessions["seller"]).json() == {
        "hint": fault == "none"}
    claim = client.post(claim_url, headers=sessions["seller"]).json()
    ack = client.post(f"/runs/{run_id}/inbox/ack", headers=sessions["seller"],
                      json={"message_id": "q-1", "fence": claim["fence"],
                            "status": "processed", "note": {"applied": True}})
    assert ack.status_code == 200

    replay = send_q1(client, run_id, sessions)
    assert replay.status_code == 202
    assert replay.json() == {**first.json(), "replay": True}
    payload = {"message_id": "q-1", "to": "seller", "kind": "quote_request", "body": BODY}
    if field != "sender":
        payload[field] = {"to": "buyer", "kind": "quote_response", "body": {"quantity": 3}}[field]
    conflict = client.post(f"/runs/{run_id}/messages", json=payload,
                           headers=sessions["seller" if field == "sender" else "buyer"])
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == {"error": "identity_reuse", "message_id": "q-1"}
    for name in ["buyer", "seller"]:
        assert client.get(notify_url, params={"wait": 0}, headers=sessions[name]).json() == {"hint": False}
        assert client.post(claim_url, headers=sessions[name]).status_code == 204
    kinds = event_kinds(client, run_id)
    assert kinds.count("message_accepted") == 1
    assert kinds.count("replay_returned") == 1
    assert kinds.count("identity_reuse_rejected") == 1
    assert kinds.count("message_claimed") == 1
    assert kinds.count("ack_recorded") == 1
    assert kinds.count("notify_suppressed") == (1 if fault == "drop_wakeup" else 0)


def test_stale_fence_over_http(client):
    run_id, sessions, _ = make_run(client, lease=0.0)
    send_q1(client, run_id, sessions)
    c = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    a = client.post(
        f"/runs/{run_id}/inbox/ack",
        json={"message_id": "q-1", "fence": c.json()["fence"],
              "status": "processed", "note": {}},
        headers=sessions["seller"],
    )
    assert a.status_code == 409
    assert a.json()["detail"]["error"] == "stale_fence"
    assert "stale_fence_rejected" in event_kinds(client, run_id)


def test_drop_wakeup_fault(client):
    run_id, sessions, _ = make_run(client, fault="drop_wakeup")
    send_q1(client, run_id, sessions)
    n = client.get(f"/runs/{run_id}/inbox/notify", params={"wait": 0},
                   headers=sessions["seller"])
    assert n.json()["hint"] is False
    c = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    assert c.json()["message_id"] == "q-1"
    assert "notify_suppressed" in event_kinds(client, run_id)


def test_duplicate_delivery_fault(client):
    run_id, sessions, _ = make_run(client, fault="duplicate_delivery")
    send_q1(client, run_id, sessions)
    c = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    client.post(
        f"/runs/{run_id}/inbox/ack",
        json={"message_id": "q-1", "fence": c.json()["fence"],
              "status": "processed", "note": {"applied": True}},
        headers=sessions["seller"],
    )
    dup = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    assert dup.status_code == 200
    assert dup.json()["message_id"] == "q-1"
    assert dup.json()["duplicate"] is True
    a2 = client.post(
        f"/runs/{run_id}/inbox/ack",
        json={"message_id": "q-1", "fence": dup.json()["fence"],
              "status": "processed", "note": {"duplicate": True}},
        headers=sessions["seller"],
    )
    assert a2.status_code == 200
    again = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    assert again.status_code == 204
    assert "duplicate_offered" in event_kinds(client, run_id)


def test_lost_ack_fault(client):
    run_id, sessions, _ = make_run(client, fault="lost_ack")
    send_q1(client, run_id, sessions)
    c = client.post(f"/runs/{run_id}/inbox/claim", headers=sessions["seller"])
    ack_body = {"message_id": "q-1", "fence": c.json()["fence"],
                "status": "processed", "note": {"applied": True}}
    first = client.post(f"/runs/{run_id}/inbox/ack", json=ack_body,
                        headers=sessions["seller"])
    assert first.status_code == 503
    retry = client.post(f"/runs/{run_id}/inbox/ack", json=ack_body,
                        headers=sessions["seller"])
    assert retry.status_code == 200
    kinds = event_kinds(client, run_id)
    assert "ack_dropped" in kinds and "ack_recorded" in kinds


def test_finish_and_runner_event(client):
    run_id, sessions, _ = make_run(client)
    e = client.post(
        f"/runs/{run_id}/events",
        json={"observer": "runner", "kind": "participant_crashed",
              "subject": "seller", "detail": {"exit_code": 3}},
        headers=ADMIN,
    )
    assert e.status_code == 200
    f = client.post(f"/runs/{run_id}/finish", headers=ADMIN)
    assert f.status_code == 200
    kinds = event_kinds(client, run_id)
    assert "participant_crashed" in kinds and "run_finished" in kinds
