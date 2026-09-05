import json
from html.parser import HTMLParser

from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_a2a_app
from nandatown.bundle import load_bundle
from nandatown.path_runner import run_path_test
from nandatown.sim.runner import run_lab
from nandatown.visualizer import render_visualizer


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.current = None
        self.title = ""
        self.data = ""
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "title" or (tag == "script" and dict(attrs).get("id") == "data"):
            self.current = tag

    def handle_endtag(self, tag):
        if tag == self.current:
            self.current = None

    def handle_data(self, data):
        if self.current == "title":
            self.title += data
        elif self.current == "script":
            self.data += data


def test_hostile_bundle_text_cannot_escape_page_data(tmp_path):
    directory, _ = run_lab("marketplace", str(tmp_path))
    bundle = load_bundle(directory)
    attack = '</title><script>window.attacked=true</script><img src=x onerror="alert(1)">'
    bundle["run"] = bundle["run"].model_copy(update={"run_id": attack})
    bundle["events"][0] = bundle["events"][0].model_copy(
        update={"subject": attack, "detail": {"text": "</script>&<>"}})

    page = Page(render_visualizer(bundle))

    assert page.title == "NANDA Town run " + attack
    assert not any(tag == "img" for tag, _ in page.tags)
    assert len([tag for tag, _ in page.tags if tag == "script"]) == 2
    data = json.loads(page.data)
    assert data["title"] == attack
    assert data["events"][0]["subject"] == attack
    assert data["events"][0]["detail"]["text"] == "</script>&<>"


def test_path_bundle_visualizes_with_its_actual_profile(tmp_path):
    with TestClient(build_a2a_app("http://testserver")) as client:
        directory, result = run_path_test(
            "http://testserver", str(tmp_path), http=client)

    bundle = load_bundle(directory)
    page = Page(render_visualizer(bundle))
    data = json.loads(page.data)

    assert result.verdict == "passed"
    assert f"Path profile {bundle['profile'].name}" in data["meta"]
    assert "quote" in data["meta"]
    assert data["result"]["verdict"] == "passed"
