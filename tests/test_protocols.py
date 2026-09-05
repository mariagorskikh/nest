import base64
import json
import os

import httpx
import pytest

from nandatown.protocols import (
    ProtocolImportError,
    classify,
    fetch_pr,
    import_pr,
    protocol_entries,
)

PLUGIN_SOURCE = '''\
"""A contributed trust plugin."""
from nandatown.layers import register


@register("trust", "webweight.v2")
class WebWeight:
    def __init__(self, engine):
        self.engine = engine
'''

SCENARIO_SOURCE = """\
name: web-market
agents:
  - name: a
    role: buyer
    config: {}
"""


def fake_github(files: dict[str, str], title="Add webweight trust"):
    def responder(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/projnanda/nandatown/pulls/321":
            return httpx.Response(200, json={
                "title": title, "state": "open",
                "user": {"login": "contributor"},
                "head": {"sha": "abc123def4567890",
                         "repo": {"full_name": "contributor/nandatown"}},
            })
        if path == "/repos/projnanda/nandatown/pulls/321/files":
            return httpx.Response(200, json=[
                {"filename": name, "status": "added"} for name in files])
        for name, content in files.items():
            if path == f"/repos/contributor/nandatown/contents/{name}":
                return httpx.Response(200, json={
                    "size": len(content),
                    "content": base64.b64encode(
                        content.encode()).decode()})
        if path.endswith("/pulls/404"):
            return httpx.Response(404, json={})
        return httpx.Response(404, json={})

    return httpx.Client(transport=httpx.MockTransport(responder),
                        base_url="https://api.github.com")


FILES = {
    "plugins/webweight.py": PLUGIN_SOURCE,
    "scenarios/web-market.yaml": SCENARIO_SOURCE,
    "tests/test_webweight.py": "def test_ok():\n    assert True\n",
    "docs/notes.txt": "notes",
}


def test_fetch_and_classify():
    pr = fetch_pr("projnanda/nandatown", 321, http=fake_github(FILES))
    assert pr["head_repo"] == "contributor/nandatown"
    assert len(pr["files"]) == 4
    c = classify(pr["files"])
    assert c["plugins"][0]["registrations"] == [
        {"layer": "trust", "plugin_id": "webweight.v2"}]
    assert c["scenarios"][0]["path"] == "scenarios/web-market.yaml"
    assert c["tests"][0]["path"] == "tests/test_webweight.py"
    assert c["other"][0]["path"] == "docs/notes.txt"


def test_import_writes_snapshot_and_catalog(tmp_path):
    protocol_dir = import_pr(321, out_dir=str(tmp_path),
                             http=fake_github(FILES))
    assert os.path.exists(
        os.path.join(protocol_dir, "plugins", "webweight.py"))
    with open(os.path.join(protocol_dir, "metadata.json")) as f:
        metadata = json.load(f)
    assert metadata["status"] == "imported-untrusted"
    assert any("--layer trust=webweight.v2" in u
               for u in metadata["usage"])
    checks = [json.loads(line) for line in
              open(os.path.join(protocol_dir, "checks.jsonl"))]
    by_test = {c["test"]: c["result"] for c in checks}
    assert by_test["files-fetched"] == "passed"
    assert by_test["contribution-shape"] == "passed"
    assert by_test["tests-included"] == "passed"
    assert by_test["secret-scan"] == "passed"
    entries = protocol_entries(str(tmp_path))
    assert entries[0]["number"] == 321
    assert entries[0]["status"] == "imported-untrusted"


def test_imported_plugin_actually_runs_against_reference_agents(tmp_path):
    from nandatown.sim.runner import run_lab

    protocol_dir = import_pr(321, out_dir=str(tmp_path),
                             http=fake_github(FILES))
    plugin_path = os.path.join(protocol_dir, "plugins", "webweight.py")
    run_lab("voting", str(tmp_path / "runs"), plugins=[plugin_path])
    from nandatown.layers import resolve
    assert resolve("trust", "webweight.v2").plugin_id == "webweight.v2"


def test_secret_in_pr_is_flagged(tmp_path):
    tainted = dict(FILES)
    tainted["plugins/webweight.py"] = (
        PLUGIN_SOURCE + '\nKEY = "sk_live_AAAABBBBCCCCDDDD"\n')
    protocol_dir = import_pr(321, out_dir=str(tmp_path),
                             http=fake_github(tainted))
    checks = [json.loads(line) for line in
              open(os.path.join(protocol_dir, "checks.jsonl"))]
    scan = next(c for c in checks if c["test"] == "secret-scan")
    assert scan["result"] == "failed"


def test_path_traversal_is_blocked(tmp_path, monkeypatch):
    evil_pr = {
        "repo": "projnanda/nandatown", "number": 321, "title": "evil",
        "author": "attacker", "state": "open",
        "head_sha": "abc123def4567890", "head_repo": "a/n",
        "files": [{"path": "../../escape.py", "content": "print('out')"},
                  {"path": "ok.py", "content": "x = 1"}],
        "skipped": [],
    }
    monkeypatch.setattr("nandatown.protocols.fetch_pr",
                        lambda *a, **k: evil_pr)
    protocol_dir = import_pr(321, out_dir=str(tmp_path / "protocols"))
    assert not os.path.exists(tmp_path / "escape.py")
    assert os.path.exists(os.path.join(protocol_dir, "ok.py"))
    with open(os.path.join(protocol_dir, "metadata.json")) as f:
        metadata = json.load(f)
    assert any("escapes the snapshot" in s for s in metadata["skipped"])


def test_missing_pr_fails_cleanly():
    with pytest.raises(ProtocolImportError):
        fetch_pr("projnanda/nandatown", 404, http=fake_github(FILES))


def test_fetch_discloses_files_beyond_github_page_limit():
    contents_requested = []

    def responder(request):
        path = request.url.path
        if path.endswith("/pulls/321"):
            return httpx.Response(200, json={
                "title": "Large contribution", "state": "open", "changed_files": 100,
                "user": {"login": "contributor"},
                "head": {"sha": "abc123", "repo": {"full_name": "contributor/nandatown"}},
            })
        if path.endswith("/files"):
            page_size = int(request.url.params["per_page"])
            return httpx.Response(200, json=[
                {"filename": f"file-{n}.py", "status": "added"}
                for n in range(page_size)])
        contents_requested.append(path)
        return httpx.Response(200, json={"size": 3, "content": "eD0x"})

    with httpx.Client(transport=httpx.MockTransport(responder),
                      base_url="https://api.github.com") as client:
        pr = fetch_pr("projnanda/nandatown", 321, http=client)

    assert len(pr["files"]) == 50
    assert len(contents_requested) == 50
    assert any("50" in reason and "beyond" in reason for reason in pr["skipped"])


def test_import_check_does_not_call_partial_snapshot_complete():
    from nandatown.protocols import structural_checks

    pr = {"repo": "projnanda/nandatown", "number": 321, "head_sha": "abc123",
          "files": [{"path": "ok.py", "content": "x=1"}],
          "skipped": ["unreadable.py (unreadable at the head commit)"]}
    checks = structural_checks(pr, classify(pr["files"]))

    fetched = next(check for check in checks if check.test == "files-fetched")
    assert fetched.result == "not_enough_evidence"
    assert "unreadable.py" in str(fetched.evidence)


@pytest.mark.parametrize("number", [321, 404])
def test_fetch_closes_only_the_http_client_it_owns(monkeypatch, number):
    owned = fake_github(FILES)
    monkeypatch.setattr("nandatown.protocols._client", lambda supplied: owned)
    try:
        fetch_pr("projnanda/nandatown", number)
    except ProtocolImportError:
        assert number == 404
    assert owned.is_closed

    borrowed = fake_github(FILES)
    monkeypatch.setattr("nandatown.protocols._client", lambda supplied: supplied)
    with borrowed:
        try:
            fetch_pr("projnanda/nandatown", number, http=borrowed)
        except ProtocolImportError:
            assert number == 404
        assert not borrowed.is_closed
