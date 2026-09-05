import json
import os
import sys
import time

import httpx
import pytest

import nandatown.runner as runner_module
from nandatown.bundle import load_bundle, verify_bundle
from nandatown.participants.llm import (
    MESSAGE_BUDGET,
    TOOLS,
    LLMParticipant,
    ModelClient,
)
from nandatown.runner import (
    _participant_extra_env,
    _spawn_participant,
    run_town,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def stage(result, name):
    return next(s for s in result.stages if s.name == name)


def test_model_client_parses_openai_shape():
    def responder(request):
        payload = json.loads(request.content)
        assert payload["model"] == "qwen-test"
        assert any(t["function"]["name"] == "claim_work"
                   for t in payload["tools"])
        return httpx.Response(200, json={"choices": [{"message": {
            "content": "thinking",
            "tool_calls": [{"id": "c1", "function": {
                "name": "claim_work", "arguments": "{}"}}]}}]})

    client = ModelClient("qwen-test", "seller",
                         http=httpx.Client(
                             transport=httpx.MockTransport(responder),
                             base_url="http://model"))
    out = client.chat([{"role": "system", "content": "s"}], TOOLS)
    assert out["tool_calls"][0]["function"]["name"] == "claim_work"


def test_truncation_keeps_system_and_counts(tmp_path):
    p = LLMParticipant.__new__(LLMParticipant)
    p.fault = "context_truncation"
    p.truncations = 0
    p.messages = [{"role": "system", "content": "SYSTEM"}] + [
        {"role": "assistant", "content": f"m{i}", "tool_calls": []}
        for i in range(MESSAGE_BUDGET + 4)]
    p._maybe_truncate()
    assert p.truncations == 1
    assert p.messages[0]["content"] == "SYSTEM"
    assert len(p.messages) <= 5


def test_llm_profile_end_to_end_with_mock_brain(tmp_path):
    bundle_dir, result = run_town("quote-llm", str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail
    assert verify_bundle(bundle_dir) == []
    bundle = load_bundle(bundle_dir)
    assert bundle["run"].config["model"] == "mock:v1"
    assert bundle["run"].config["runtimes"] == {"buyer": "llm",
                                                "seller": "llm"}
    names = {r["name"] for r in bundle["run"].config["skill_releases"]}
    assert "town-protocol" in names


def test_llm_truncation_profile_end_to_end(tmp_path):
    bundle_dir, result = run_town("quote-llm-truncation", str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert stage(result, "truncation_survived").status == "passed", detail
    assert stage(result, "correct").status == "passed", detail
    assert result.verdict == "passed", detail
    assert verify_bundle(bundle_dir) == []


def test_byoa_external_seller_end_to_end(tmp_path):
    example = os.path.join(REPO_ROOT, "examples", "byoa_seller.py")
    secret = "external-command-secret-must-not-enter-evidence"
    bundle_dir, result = run_town(
        "quote-clean", str(tmp_path),
        external={"seller": [sys.executable, example, secret]})
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail
    bundle = load_bundle(bundle_dir)
    seller_acks = [e for e in bundle["events"]
                   if e.kind == "ack_recorded" and e.observer == "seller"]
    assert seller_acks[0].detail["note"].get("runtime") == "byoa-stdlib"
    run = bundle["run"]
    assert run.config["rerun_command"] == (
        "nandatown test-agent --profile quote-clean --role seller"
        " --cmd '<operator-supplied-command>'")
    serialized_run = json.dumps(run.model_dump())
    assert secret not in serialized_run
    assert example not in serialized_run
    assert verify_bundle(bundle_dir) == []


def _spawn_environment_probe(tmp_path, inherit_env=False):
    output = tmp_path / ("inherited.json" if inherit_env else "builtin.json")
    script = (
        "import json,os,pathlib,sys;"
        "pathlib.Path(sys.argv[1]).write_text(json.dumps(dict(os.environ)))"
    )
    process = _spawn_participant(
        [sys.executable, "-c", script, str(output)],
        "http://town.invalid", "run-1", "seller", "join-token",
        str(tmp_path / "state"), "none", "1",
        extra_env={"ROLE": "seller", "TOWN_MODEL_KEY": "explicit-key"},
        inherit_env=inherit_env)
    assert process.wait(timeout=5) == 0
    return json.loads(output.read_text())


def test_builtin_participant_gets_only_required_environment(
        tmp_path, monkeypatch):
    monkeypatch.setenv("NANDATOWN_TEST_AMBIENT_SECRET", "do-not-copy")

    child_env = _spawn_environment_probe(tmp_path)

    assert "NANDATOWN_TEST_AMBIENT_SECRET" not in child_env
    assert child_env["TOWN_URL"] == "http://town.invalid"
    assert child_env["TOKEN"] == "join-token"
    assert child_env["ROLE"] == "seller"
    assert child_env["TOWN_MODEL_KEY"] == "explicit-key"


def test_trusted_command_can_inherit_operator_environment(
        tmp_path, monkeypatch):
    monkeypatch.setenv("NANDATOWN_TEST_AMBIENT_SECRET", "operator-opt-in")

    child_env = _spawn_environment_probe(tmp_path, inherit_env=True)

    assert child_env["NANDATOWN_TEST_AMBIENT_SECRET"] == "operator-opt-in"


def test_model_credentials_only_reach_relevant_harnesses(monkeypatch):
    monkeypatch.setenv("TOWN_MODEL_URL", "https://model.invalid")
    monkeypatch.setenv("TOWN_MODEL_KEY", "paid-secret")

    scripted = _participant_extra_env("scripted", {}, "hosted:model")
    mock_llm = _participant_extra_env("llm", {"ROLE": "seller"},
                                      "mock:v1")
    hosted_llm = _participant_extra_env("llm", {"ROLE": "seller"},
                                        "hosted:model")

    assert "TOWN_MODEL_KEY" not in scripted
    assert "TOWN_MODEL_KEY" not in mock_llm
    assert hosted_llm["TOWN_MODEL_URL"] == "https://model.invalid"
    assert hosted_llm["TOWN_MODEL_KEY"] == "paid-secret"


@pytest.mark.skipif(os.name != "posix",
                    reason="descendant cleanup uses POSIX process groups")
def test_runner_stops_command_descendants_before_bundle_export(
        tmp_path, monkeypatch):
    ready = tmp_path / "descendant-ready"
    export_started = tmp_path / "export-started"
    late_write = tmp_path / "descendant-wrote-during-export"
    child = tmp_path / "late_writer.py"
    child.write_text(
        "import os, pathlib, sys, time\n"
        "ready, export_started, late_write = map(pathlib.Path, sys.argv[1:])\n"
        "ready.write_text(str(os.getpid()))\n"
        "deadline = time.monotonic() + 20\n"
        "while not export_started.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.005)\n"
        "if export_started.exists():\n"
        "    late_write.write_text('survived')\n"
    )
    wrapper = tmp_path / "seller_with_descendant.py"
    wrapper.write_text(
        "import subprocess, sys\n"
        "subprocess.Popen([sys.executable, *sys.argv[1:]])\n"
        "from nandatown.participants.seller import main\n"
        "main()\n"
    )
    original_write_bundle = runner_module.write_bundle

    def observed_write_bundle(*args, **kwargs):
        export_started.write_text("started")
        time.sleep(0.2)
        return original_write_bundle(*args, **kwargs)

    monkeypatch.setattr(runner_module, "write_bundle", observed_write_bundle)
    command = [sys.executable, str(wrapper), str(child), str(ready),
               str(export_started), str(late_write)]

    _, result = run_town("quote-clean", str(tmp_path / "runs"),
                         external={"seller": command})

    assert result.verdict == "passed"
    assert ready.exists(), "the real descendant never started"
    assert not late_write.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group ownership")
def test_process_cleanup_never_resignals_a_settled_group(monkeypatch):
    import subprocess

    process = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    process.wait(timeout=5)
    signals = []

    def missing_group(pgid, sig):
        signals.append((pgid, sig))
        raise ProcessLookupError

    monkeypatch.setattr(runner_module.os, "killpg", missing_group)
    assert runner_module._stop_process(process) == 0
    first_cleanup = list(signals)
    assert runner_module._stop_process(process) == 0
    assert signals == first_cleanup


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group ownership")
def test_cleanup_records_exit_observed_just_after_wait_timeout(monkeypatch):
    import subprocess

    class SlowReap:
        pid = 424242
        returncode = None
        polls = 0

        def poll(self):
            self.polls += 1
            if self.polls > 1:
                self.returncode = 0
            return self.returncode

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("slow-reap", timeout)

    process = SlowReap()
    signals = []
    monkeypatch.setattr(runner_module.os, "killpg", lambda *args: signals.append(args))
    assert runner_module._stop_process(process) == 0
    first_cleanup = list(signals)
    assert runner_module._stop_process(process) == 0
    assert signals == first_cleanup


def test_only_hosted_model_harness_preserves_explicit_proxy_environment(monkeypatch):
    keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy")
    for key in keys:
        monkeypatch.setenv(key, "http://proxy.invalid:8080")
    hosted = _participant_extra_env("llm", {}, "hosted:model")
    assert all(hosted.get(key) == "http://proxy.invalid:8080" for key in keys)
    for kind, model in (("scripted", "hosted:model"), ("a2a", "hosted:model"),
                        ("llm", "mock:v1")):
        assert all(key not in _participant_extra_env(kind, {}, model) for key in keys)
