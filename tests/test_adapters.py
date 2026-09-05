import json
import os
import socket
import sys
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from nandatown import __version__
from nandatown.a2a_adapter import build_a2a_app, probe_endpoint
from nandatown.client import TownClient
from nandatown.coordinator import build_app
from nandatown.mcp_adapter import PROTOCOL_VERSION, MCPTownServer, probe
from nandatown.records import TestProfile

ADMIN = {"X-Town-Admin": "secret"}


def make_run(app_client):
    profile = TestProfile(
        name="quote-none",
        task={"kind": "quote", "sku": "widget", "quantity": 2,
              "unit_price_cents": 1995, "expected_total_cents": 3990},
        roles={"buyer": "buyer", "seller": "seller"},
        capabilities={"buyer": [], "seller": ["quote.read"]},
        fault="none", lease_seconds=5.0, evaluator="stage-evaluator",
    )
    r = app_client.post("/runs", json={"profile": profile.model_dump()},
                        headers=ADMIN)
    return r.json()["run_id"], r.json()["join_tokens"]


def rpc(server, method, params=None, message_id=1):
    return server.handle_message({"jsonrpc": "2.0", "id": message_id,
                                  "method": method,
                                  "params": params or {}})


def tool(server, name, arguments=None):
    response = rpc(server, "tools/call",
                   {"name": name, "arguments": arguments or {}})
    payload = response["result"]
    assert not payload.get("isError"), payload
    return json.loads(payload["content"][0]["text"])


def test_mcp_handshake_and_tools(tmp_path):
    server = MCPTownServer("http://dead", "run-x", "seller", "t")
    init = rpc(server, "initialize")
    assert init["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert init["result"]["serverInfo"]["name"] == "nandatown"
    assert server.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    listed = rpc(server, "tools/list")
    names = [t["name"] for t in listed["result"]["tools"]]
    for expected in ["town_claim", "town_send", "town_ack",
                     "town_participants"]:
        assert expected in names
    unknown = rpc(server, "nonsense/method")
    assert unknown["error"]["code"] == -32601


def test_mcp_client_completes_the_seller_role(tmp_path):
    app = build_app(str(tmp_path / "town.db"), admin_token="secret")
    admin = TestClient(app)
    run_id, tokens = make_run(admin)

    seller_town = TownClient("http://testserver", run_id,
                             http=TestClient(app))
    server = MCPTownServer("http://testserver", run_id, "seller",
                           tokens["seller"], client=seller_town)

    from nandatown.participants import buyer

    buyer_client = TownClient("http://testserver", run_id,
                              http=TestClient(app))
    buyer_dir = tmp_path / "buyer"
    buyer_dir.mkdir()
    thread = threading.Thread(
        target=buyer.run,
        args=(buyer_client, "buyer", tokens["buyer"], str(buyer_dir)),
        kwargs={"deadline_seconds": 10.0}, daemon=True)
    thread.start()

    # The MCP host plays seller through nothing but tool calls.
    status = tool(server, "town_status")
    assert status["run"]["task"]["expected_total_cents"] == 3990
    deadline = time.time() + 10
    done = False
    while time.time() < deadline and not done:
        claim = tool(server, "town_claim")
        if claim.get("work", "x") is None:
            tool(server, "town_notify", {"wait": 0.2})
            continue
        body = claim["body"]
        total = body["quantity"] * body["unit_price_cents"]
        tool(server, "town_send",
             {"message_id": "r-1", "to": claim["from"],
              "kind": "quote_response",
              "body": {"request_id": claim["message_id"],
                       "total_cents": total}})
        tool(server, "town_ack",
             {"message_id": claim["message_id"],
              "fence": claim["fence"], "status": "processed",
              "note": {"applied": True, "total_cents": total,
                       "runtime": "mcp-host"}})
        done = True
    thread.join(timeout=10)
    events = admin.get(f"/runs/{run_id}/events",
                       headers=ADMIN).json()["events"]
    buyer_acks = [e for e in events if e["kind"] == "ack_recorded"
                  and e["observer"] == "buyer"]
    assert buyer_acks and buyer_acks[-1]["detail"]["note"]["correct"]


def test_mcp_probe_against_own_server():
    report = probe([sys.executable, "-m", "nandatown.mcp_adapter",
                    "--url", "http://127.0.0.1:1", "--run", "x",
                    "--name", "seller", "--token", "t"])
    assert report["ok"], report
    assert report["protocolVersion"] == PROTOCOL_VERSION
    assert "town_claim" in report["tools"]


@pytest.mark.parametrize("partial", [False, True])
def test_mcp_probe_enforces_wall_deadline_and_reaps_child(
        tmp_path, partial):
    pid_path = tmp_path / ("partial.pid" if partial else "silent.pid")
    prelude = (
        "import os,pathlib,sys,time;"
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
    )
    if partial:
        prelude += "sys.stdout.write('{');sys.stdout.flush();"
    command = [sys.executable, "-c", prelude + "time.sleep(0.8)",
               str(pid_path)]

    started = time.monotonic()
    report = probe(command, timeout=0.15)
    elapsed = time.monotonic() - started

    assert elapsed < 0.65
    assert report["ok"] is False
    assert any("timed out" in problem for problem in report["problems"])
    pid = int(pid_path.read_text())
    if os.name == "posix":
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_mcp_probe_rejects_oversized_response_without_crashing():
    script = (
        "import sys;"
        "sys.stdin.readline();"
        "sys.stdout.write('x' * (1024 * 1024 + 1) + '\\n');"
        "sys.stdout.flush()"
    )

    report = probe([sys.executable, "-c", script], timeout=1.0)

    assert report["ok"] is False
    assert any("too large" in problem for problem in report["problems"])


def test_a2a_card_and_quote():
    app = build_a2a_app("http://testserver")
    client = TestClient(app)
    card = client.get("/.well-known/agent-card.json").json()
    assert card["name"] == "nandatown-quote-seller"
    assert card["skills"][0]["id"] == "quote"
    report = probe_endpoint("http://testserver", http=client)
    assert report["ok"], report
    assert report["task_state"] == "completed"
    assert "3990" in report["artifact"]


def test_a2a_bad_request_fails_the_task():
    client = TestClient(build_a2a_app("http://testserver"))
    response = client.post("/", json={
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": {"message": {"role": "user", "messageId": "m1",
                               "parts": [{"kind": "text",
                                          "text": "not json"}]}}})
    task = response.json()["result"]
    assert task["status"]["state"] == "failed"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_a2a_bridge_carries_a_track_run(tmp_path):
    import uvicorn

    from nandatown.runner import run_town

    port = _free_port()
    config = uvicorn.Config(build_a2a_app(f"http://127.0.0.1:{port}"),
                            host="127.0.0.1", port=port,
                            log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            httpx.get(f"http://127.0.0.1:{port}"
                      "/.well-known/agent-card.json", timeout=1)
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    try:
        secret = "a2a-query-secret-must-not-enter-evidence"
        bundle_dir, result = run_town(
            "quote-clean", str(tmp_path),
            harnesses={
                "seller": f"a2a:http://127.0.0.1:{port}?token={secret}"})
        detail = [(s.name, s.status, s.note) for s in result.stages]
        assert result.verdict == "passed", detail
        from nandatown.bundle import load_bundle
        bundle = load_bundle(bundle_dir)
        seller_acks = [e for e in bundle["events"]
                       if e.kind == "ack_recorded"
                       and e.observer == "seller"]
        assert seller_acks[0].detail["note"]["runtime"] == "a2a-bridge"
        run = bundle["run"]
        seller = next(p for p in run.participants
                      if p["name"] == "seller")
        assert seller["runtime"] == "a2a"
        assert seller["release"] == (
            "external A2A participant; immutable release not recorded")
        assert run.config["harnesses"] == {
            "seller": "a2a:<operator-supplied-endpoint>"}
        assert run.config["participant_provenance"]["seller"] == {
            "kind": "a2a",
            "identity_basis": (
                "operator-supplied A2A endpoint (URL not recorded)"),
            "release_basis": None,
            "release_basis_note": "immutable external release not supplied",
            "adapter_release": (
                f"nandatown.participants.a2a_bridge {__version__}"),
        }
        assert secret not in json.dumps(run.model_dump())
        assert "<operator-supplied-endpoint>" in (
            run.config["rerun_command"])
    finally:
        server.should_exit = True
        thread.join(timeout=5)
