"""External bytes are faked; parsing, policy and client ownership are real."""

import json
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from nandatown.a2a_adapter import fetch_card, send_message


class Chunks(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.reads += 1
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk

    def close(self):
        self.closed = True


@pytest.mark.parametrize("operation", ["card", "rpc"])
@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("length", [None, "1"])
def test_actual_bytes_enforce_exact_cap(operation, extra, length):
    body = b'{"result":{}}' if operation == "rpc" else b'{}'
    budget = len(body) + 4
    stream = Chunks([body, b' ' * (4 + extra)])
    headers = {} if length is None else {"content-length": length}
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, headers=headers, stream=stream)

    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(handle)) as client:
        def invoke():
            if operation == "rpc":
                return send_message("http://fixture.invalid", "hello", http=client, max_response_bytes=budget)
            return fetch_card("http://fixture.invalid", http=client, max_response_bytes=budget)
        if extra:
            with pytest.raises(ValueError, match="^a2a_response_budget_exceeded: selected local byte budget exceeded for this run$"):
                invoke()
        else:
            assert invoke() == {}
        assert not client.is_closed
    assert stream.closed
    assert len(requests) == 1
    assert requests[0].headers["accept-encoding"] == "identity"


@pytest.mark.parametrize("headers,category", [
    ({"content-length": "1048577"}, "a2a_response_budget_exceeded"),
    ({"content-encoding": "gzip"}, "a2a_unsupported_encoding"),
])
def test_header_rejection_does_not_read_body(headers, category):
    stream = Chunks([b"remote-secret-marker"])
    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers=headers, stream=stream))) as client:
        with pytest.raises(ValueError, match="^" + category) as error:
            fetch_card("http://fixture.invalid", http=client)
    assert "remote-secret-marker" not in str(error.value)
    assert stream.reads == 0
    assert stream.closed


@pytest.mark.parametrize("body,category", [
    (b'[]', "a2a_json_not_object"),
    (b'null', "a2a_json_not_object"),
    (b'bad remote-secret-marker', "a2a_invalid_json"),
    (b'{"error":{"message":"remote-secret-marker"}}', "a2a_rpc_error"),
    (b'{"result":[]}', "a2a_rpc_invalid_result"),
    (b'{}', "a2a_rpc_invalid_result"),
])
def test_rpc_parse_errors_are_stable_and_private(body, category):
    stream = Chunks([body])
    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream))) as client:
        with pytest.raises(ValueError, match="^" + category + "$"):
            send_message("http://fixture.invalid", "hello", http=client)
    assert stream.closed


@pytest.mark.parametrize("status", [301, 403, 500])
def test_http_error_does_not_fallback_or_read_remote_body(status):
    stream = Chunks([b"remote-secret-marker"])
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(status, headers={"location": "/elsewhere"}, stream=stream)
    with httpx.Client(base_url="http://fixture.invalid", follow_redirects=True,
                      transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError, match="^a2a_http_status_" + str(status) + "$"):
            fetch_card("http://fixture.invalid", http=client)
    assert len(calls) == 1
    assert stream.closed and stream.reads == 0


def test_only_missing_cards_fall_back_and_close_each_response():
    streams = [Chunks([b"missing"]), Chunks([b'{"name":"local"}'])]
    paths = []
    def handle(request):
        paths.append(request.url.path)
        return httpx.Response(404 if len(paths) == 1 else 200, stream=streams[len(paths)-1])
    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(handle)) as client:
        assert fetch_card("http://fixture.invalid", http=client) == {"name": "local"}
    assert paths == ["/.well-known/agent-card.json", "/.well-known/agent.json"]
    assert all(s.closed for s in streams)
    assert streams[0].reads == 0


@pytest.mark.parametrize("limit", [0, -1, 1.5, float("inf"), float("nan"), True, "12", None])
def test_invalid_byte_limit_is_rejected_before_request(limit):
    def handle(request):
        pytest.fail("invalid local budget reached transport")
    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError, match="^a2a_invalid_response_budget$"):
            fetch_card("http://fixture.invalid", http=client, max_response_bytes=limit)


def test_interrupted_stream_closes_and_hides_transport_exception():
    stream = Chunks([b'{', httpx.ReadError("remote-secret-marker")])
    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream))) as client:
        with pytest.raises(ValueError, match="^a2a_transport_error$"):
            send_message("http://fixture.invalid", "hello", http=client)
    assert stream.closed


def test_native_rpc_preserves_successful_non_200_status():
    stream = Chunks([b'{"result":{"kind":"task"}}'])
    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(
            lambda request: httpx.Response(201, stream=stream))) as client:
        assert send_message("http://fixture.invalid", "hello", http=client) == {"kind": "task"}
    assert stream.closed


@contextmanager
def loopback(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass


def test_owned_client_bypasses_ambient_proxy_and_accepts_local_agent(monkeypatch):
    proxy_hits = []
    requests = []
    class Proxy(QuietHandler):
        def do_GET(self):
            proxy_hits.append(self.path)
            self.send_error(502)
        do_POST = do_GET
    class Agent(QuietHandler):
        def do_GET(self):
            requests.append(("GET", self.headers.get("Accept-Encoding")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"name":"loopback"}')
        def do_POST(self):
            requests.append(("POST", self.headers.get("Accept-Encoding")))
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"result":{"kind":"task"}}')
    with loopback(Proxy) as proxy, loopback(Agent) as url:
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            monkeypatch.setenv(key, proxy)
        for key in ("NO_PROXY", "no_proxy"):
            monkeypatch.setenv(key, "")
        assert fetch_card(url) == {"name": "loopback"}
        assert send_message(url, "hello") == {"kind": "task"}
    assert proxy_hits == []
    assert requests == [("GET", "identity"), ("POST", "identity")]


def test_owned_client_refuses_redirect_and_does_not_retry_interrupted_post():
    requests = []
    class Agent(QuietHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()
        def do_POST(self):
            requests.append("POST")
            self.rfile.read(int(self.headers["Content-Length"]))
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
    with loopback(Agent) as url:
        with pytest.raises(ValueError, match="^a2a_http_status_302$"):
            fetch_card(url)
        with pytest.raises(ValueError, match="^a2a_transport_error$"):
            send_message(url, "hello")
    assert requests == ["/.well-known/agent-card.json", "POST"]


def test_slow_read_hits_phase_timeout_without_claiming_total_deadline():
    class Agent(QuietHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            time.sleep(0.15)
    with loopback(Agent) as url:
        with pytest.raises(ValueError, match="^a2a_timeout$"):
            fetch_card(url, timeout_seconds=0.02)


def test_real_cli_selects_shared_default_and_records_owned_policy(tmp_path):
    from nandatown.bundle import load_bundle, verify_bundle
    class Agent(QuietHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"name":"loopback"}')
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            order = json.loads(request["params"]["message"]["parts"][0]["text"])
            task = {"kind": "task", "id": "local-task", "status": {"state": "completed"},
                    "artifacts": [{"parts": [{"kind": "text", "text": json.dumps({
                        "request_id": order["request_id"], "total_cents": 3990})}]}]}
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"result": task}).encode())
    with loopback(Agent) as url:
        result = subprocess.run([sys.executable, "-m", "nandatown.cli", "test-agent", "--url", url,
                                 "--out", str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    directory, = tmp_path.glob("path-*")
    bundle = load_bundle(str(directory))
    assert bundle["run"].profile_name == "a2a-capability-fulfillment@0.3"
    policy = bundle["run"].config["a2a_transport_policy"]
    assert policy["trust_env"] is False
    assert policy["transport_retries"] == 0
    assert policy["client_ownership"] == "owned"
    assert policy["total_deadline_seconds"] is None
    assert verify_bundle(str(directory)) == []


@pytest.mark.parametrize("body", [b'{}', b'bad-json'])
def test_internally_owned_client_is_closed_on_success_and_failure(monkeypatch, body):
    import nandatown.a2a_transport as transport
    clients = []
    real_client = httpx.Client
    def client_factory(**kwargs):
        # Keep the real HTTPX client lifecycle; only external I/O is replaced.
        kwargs.pop("transport", None)
        client = real_client(**kwargs, transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Chunks([body]))))
        clients.append(client)
        return client
    monkeypatch.setattr(transport.httpx, "Client", client_factory)
    if body == b'{}':
        assert fetch_card("http://fixture.invalid") == {}
    else:
        with pytest.raises(ValueError, match="a2a_invalid_json"):
            fetch_card("http://fixture.invalid")
    assert len(clients) == 1 and clients[0].is_closed
