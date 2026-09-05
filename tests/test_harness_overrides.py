import json
import os
import shlex
import subprocess
import sys

import pytest

from nandatown import __version__
import nandatown.runner as runner_module
from nandatown.bundle import load_bundle
from nandatown.cli import main
from nandatown.runner import RunnerError, parse_harness, run_town
from nandatown.sim.runner import run_lab

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(REPO_ROOT, "examples", "byoa_seller.py")


def test_parse_harness_specs():
    assert parse_harness("scripted") == {"kind": "scripted"}
    assert parse_harness("llm") == {"kind": "llm", "model": None}
    assert parse_harness("llm:qwen2.5") == {"kind": "llm",
                                            "model": "qwen2.5"}
    assert parse_harness('cmd:python my_agent.py --fast') == {
        "kind": "cmd", "command": ["python", "my_agent.py", "--fast"]}
    assert parse_harness("external") == {"kind": "external"}
    with pytest.raises(RunnerError):
        parse_harness("telepathy")
    with pytest.raises(RunnerError):
        parse_harness("cmd:")


@pytest.fixture
def reject_startup(monkeypatch):
    def fail_if_started():
        raise AssertionError("invalid role reached port allocation")

    monkeypatch.setattr(runner_module, "_free_port", fail_if_started)


@pytest.mark.parametrize(("override_name", "overrides", "role"), [
    ("harnesses", {"seler": "cmd:/does/not/exist"}, "seler"),
    ("harnesses", {"": "scripted"}, ""),
    ("external", {"seler": None}, "seler"),
    ("external", {"": None}, ""),
    ("harnesses", {"seller": "scripted", "seler": "external"},
     "seler"),
    ("external", {"seller": None, "seler": None}, "seler"),
])
def test_run_town_rejects_unknown_override_roles_before_startup(
        tmp_path, reject_startup, override_name, overrides, role):
    out_dir = tmp_path / "not-created"

    with pytest.raises(
            RunnerError,
            match=rf"unknown role {role!r}; supported roles: buyer, seller"):
        run_town("quote-clean", str(out_dir), **{override_name: overrides})

    assert not out_dir.exists()


@pytest.mark.parametrize(("agent", "role"), [
    ("seler=cmd:/does/not/exist", "seler"),
    ("=scripted", ""),
])
def test_cli_reports_unknown_harness_role_as_usage_error(
        tmp_path, capsys, reject_startup, agent, role):
    out_dir = tmp_path / "not-created"

    assert main(["run", "quote-clean", "--agent",
                 agent, "--out", str(out_dir)]) == 2

    assert f"unknown role {role!r}; supported roles: buyer, seller" in (
        capsys.readouterr().out)
    assert not out_dir.exists()


def test_cmd_harness_runs_external_agent(tmp_path):
    secret = "command-secret-must-not-enter-evidence"
    spec = "cmd:" + " ".join(shlex.quote(p)
                             for p in [sys.executable, EXAMPLE, secret])
    bundle_dir, result = run_town("quote-clean", str(tmp_path),
                                  harnesses={"seller": spec})
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail
    bundle = load_bundle(bundle_dir)
    run = bundle["run"]
    seller = next(p for p in run.participants if p["name"] == "seller")
    buyer = next(p for p in run.participants if p["name"] == "buyer")
    assert buyer["runtime"] == "scripted"
    assert buyer["release"] == (
        f"nandatown.participants.buyer {__version__}")
    assert seller["runtime"] == "cmd"
    assert seller["release"] == (
        "external command; immutable release not recorded")
    assert run.config["runtimes"]["seller"] == "cmd"
    assert run.config["harnesses"] == {
        "seller": "cmd:<operator-supplied-command>"}
    assert run.config["participant_provenance"]["seller"] == {
        "kind": "cmd",
        "identity_basis": "operator-supplied command (command not recorded)",
        "release_basis": None,
        "release_basis_note": "immutable external release not supplied",
    }
    assert run.config["rerun_required_inputs"] == {
        "seller": "original command (not recorded)"}
    assert "<operator-supplied-command>" in run.config["rerun_command"]
    serialized_run = json.dumps(run.model_dump())
    assert secret not in serialized_run
    assert EXAMPLE not in serialized_run


def test_wait_handoff_records_external_participant_and_reconnect_rerun(
        tmp_path):
    processes: list[subprocess.Popen] = []

    def connect(role, env):
        assert role == "seller"
        processes.append(subprocess.Popen(
            [sys.executable, EXAMPLE], env={**os.environ, **env},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    try:
        bundle_dir, result = run_town(
            "quote-clean", str(tmp_path), external={"seller": None},
            on_credentials=connect)
    finally:
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)

    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail
    run = load_bundle(bundle_dir)["run"]
    seller = next(p for p in run.participants if p["name"] == "seller")
    assert seller["runtime"] == "external"
    assert seller["release"] == (
        "external participant; immutable release not recorded")
    assert run.config["harnesses"] == {"seller": "external"}
    assert run.config["participant_provenance"]["seller"] == {
        "kind": "external",
        "identity_basis": (
            "operator-connected participant (software identity not supplied)"),
        "release_basis": None,
        "release_basis_note": "immutable external release not supplied",
    }
    assert run.config["rerun_command"] == (
        "nandatown test-agent --profile quote-clean --role seller --wait")
    assert run.config["rerun_required_inputs"] == {
        "seller": "external participant must reconnect with fresh credentials"}


def test_llm_harness_overrides_scripted_profile(tmp_path):
    bundle_dir, result = run_town("quote-clean", str(tmp_path),
                                  harnesses={"seller": "llm:mock:alt"})
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "passed", detail
    bundle = load_bundle(bundle_dir)
    assert bundle["run"].config["model"] == "mock:v1"
    assert bundle["run"].config["harnesses"]["seller"] == "llm:mock:alt"
    seller = next(p for p in bundle["run"].participants
                  if p["name"] == "seller")
    assert seller["runtime"] == "llm"
    assert seller["release"] == f"nandatown.participants.llm {__version__}"


def test_layer_override_reproduces_weak_auth_failure(tmp_path):
    bundle_dir, result = run_lab("capability_spoofing", str(tmp_path),
                                 layer_overrides={"auth": "plain.v1"})
    stages = {s.name: s.status for s in result.stages}
    assert result.verdict == "failed", stages
    assert stages["containment"] == "failed"
    bundle = load_bundle(bundle_dir)
    assert bundle["profile"].layers["auth"] == "plain.v1"


def test_plugin_flag_loads_scaffolded_plugin(tmp_path):
    from nandatown.new import scaffold

    path = scaffold("plugin", "memory", "scratch.v1", str(tmp_path))
    run_lab("voting", str(tmp_path / "runs"), plugins=[path])
    from nandatown.layers import resolve
    assert resolve("memory", "scratch.v1").plugin_id == "scratch.v1"


def test_cli_flag_scoping(tmp_path, capsys):
    assert main(["run", "voting", "--agent", "seller=llm",
                 "--out", str(tmp_path)]) == 2
    assert "Track profiles" in capsys.readouterr().out
    assert main(["run", "quote-clean", "--layer", "auth=plain.v1",
                 "--out", str(tmp_path)]) == 2
    assert "Lab scenarios" in capsys.readouterr().out
    assert main(["run", "capability_spoofing", "--layer",
                 "auth=plain.v1", "--out", str(tmp_path)]) == 1
    assert "FAILED" in capsys.readouterr().out
