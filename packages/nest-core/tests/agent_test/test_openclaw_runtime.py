# SPDX-License-Identifier: Apache-2.0
"""Contract and adversarial tests for the version-coherent OpenClaw runtime connector."""

from __future__ import annotations

import copy
import json
import math
import os
import sys
import textwrap
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import nest_core.agent_test.openclaw_runtime as openclaw_runtime
import pytest
from nest_core.agent_test.openclaw_runtime import OpenClawConnector
from nest_core.agent_test.runtime_connectors import (
    RuntimeConfigurationError,
    RuntimeDisplay,
    RuntimeExecutionError,
    RuntimeIncompleteError,
    RuntimeProbe,
    RuntimeTarget,
)

FIXTURE = Path(__file__).parent / "fixtures" / "openclaw-2026.7.1-2-success.json"
VERSION = "2026.7.1-2"
VERSION_BANNER = "OpenClaw 2026.7.1-2 (0790d9f)"
Mutation = Callable[[dict[str, Any]], object]

START_OBSERVATION = {
    "kind": "start",
    "logical_time": 0,
    "allowed_intents": ["declare_capability", "none"],
}
MESSAGE_OBSERVATION = {
    "kind": "message",
    "logical_time": 1,
    "allowed_intents": ["send_to_sender", "none"],
    "message": {
        "id": "message-001",
        "sender_id": "requester-0",
        "media_type": "text/plain; charset=utf-8",
        "text": "buy:widget:2",
    },
}
START_PROMPT = (
    "You are completing one basic local NANDA Town agent test.\n"
    "Return exactly one minified JSON object and no other characters.\n"
    "Do not return prose, Markdown, or code fences.\n"
    "Do not invoke tools, access files, memory, messages, channels, or perform any other "
    "action.\n"
    "This is the start event. Declare the sell capability by returning exactly "
    '{"capabilities":["sell"],"kind":"declare_capability"}.\n'
    'If you cannot do that, return exactly {"kind":"none"}.\n'
)
MESSAGE_PROMPT = (
    "You are completing one basic local NANDA Town agent test.\n"
    "Return exactly one minified JSON object and no other characters.\n"
    "Do not return prose, Markdown, or code fences.\n"
    "Do not invoke tools, access files, memory, messages, channels, or perform any other action.\n"
    "This is the message event.\n"
    'Input text: "buy:widget:2"\n'
    "If the text matches buy:<item>:<quantity>, return one canonical object shaped as "
    '{"kind":"send_to_sender","media_type":"text/plain; charset=utf-8",'
    '"text":"sold:<item>:<quantity>"}, replacing <item> and <quantity> with the input '
    "values.\n"
    'If you cannot do that, return exactly {"kind":"none"}.\n'
)


def _success_envelope(intent: dict[str, object] | None = None) -> dict[str, Any]:
    envelope = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if intent is not None:
        text = json.dumps(intent, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        payload = envelope["result"]["payloads"][0]
        meta = envelope["result"]["meta"]
        payload["text"] = text
        meta["finalAssistantVisibleText"] = text
        meta["finalAssistantRawText"] = text
    return envelope


def _gateway(*, version: str = VERSION) -> dict[str, Any]:
    """Sanitized v2026.7.1-2 status shape observed from the real Gateway CLI."""
    return {
        "cli": {"entrypoint": "/synthetic/openclaw.mjs", "version": version},
        "config": {
            "cli": {
                "controlUi": {},
                "exists": True,
                "path": "/synthetic/openclaw.json",
                "valid": True,
            },
            "daemon": {
                "controlUi": {},
                "exists": True,
                "path": "/synthetic/openclaw.json",
                "valid": True,
            },
        },
        "extraServices": [],
        "gateway": {
            "bindHost": "127.0.0.1",
            "bindMode": "loopback",
            "controlUiLinks": [],
            "port": 18789,
            "portSource": "config",
            "probeNote": "synthetic",
            "probeUrl": "ws://127.0.0.1:18789",
            "version": version,
        },
        "logFile": "/synthetic/openclaw.log",
        "pluginVersionDrift": {"drifts": [], "gatewayVersion": version},
        "port": {
            "hints": [],
            "listeners": [
                {
                    "address": "127.0.0.1:18789",
                    "command": "openclaw",
                    "commandLine": "openclaw gateway run --bind loopback",
                    "pid": 1234,
                }
            ],
            "port": 18789,
            "status": "busy",
        },
        "rpc": {
            "auth": {"capability": "operator", "role": "operator", "scopes": []},
            "capability": "operator",
            "kind": "read",
            "ok": True,
            "server": {"connId": "synthetic", "version": version},
            "url": "ws://127.0.0.1:18789",
            "version": version,
        },
        "service": {
            "command": [],
            "configAudit": {"issues": [], "ok": True},
            "label": "synthetic",
            "loaded": True,
            "loadedText": "loaded",
            "notLoadedText": "not loaded",
            "runtime": {},
        },
    }


def _agents() -> list[dict[str, Any]]:
    return [
        {
            "id": "buyer",
            "name": "Synthetic Buyer",
            "workspace": "/synthetic/workspace",
            "agentDir": "/synthetic/agent",
            "model": "provider/model",
            "isDefault": True,
            "bindings": 0,
        }
    ]


def _fake_openclaw(
    tmp_path: Path,
    *,
    version: str = VERSION_BANNER,
    gateway_mode: object = "local",
    config_env: object | None = None,
    record_gateway_url: bool = False,
    agents: object | None = None,
    gateway: object | None = None,
    responses: list[object] | None = None,
) -> tuple[Path, Path, Path]:
    state_path = tmp_path / "fake-state.json"
    log_path = tmp_path / "fake-log.jsonl"
    executable = tmp_path / "openclaw"
    state_path.write_text(
        json.dumps(
            {
                "version": version,
                "gateway_mode": gateway_mode,
                "config_env": config_env,
                "record_gateway_url": record_gateway_url,
                "agents": _agents() if agents is None else agents,
                "gateway": _gateway() if gateway is None else gateway,
                "responses": responses,
                "prompt_responses": {
                    START_PROMPT: _success_envelope(),
                    MESSAGE_PROMPT: _success_envelope(
                        {
                            "kind": "send_to_sender",
                            "media_type": "text/plain; charset=utf-8",
                            "text": "sold:widget:2",
                        }
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    executable.write_text(
        textwrap.dedent(
            f"""\
            #!{os.fspath(Path(sys.executable))}
            import json
            import os
            import pathlib
            import stat
            import sys
            import time

            state_path = pathlib.Path({str(state_path)!r})
            log_path = pathlib.Path({str(log_path)!r})
            state = json.loads(state_path.read_text())
            args = sys.argv[1:]
            record = {{
                "argv": args,
                "town_env": sorted(k for k in os.environ if k.startswith("TOWN_")),
            }}
            if state["record_gateway_url"]:
                record["gateway_url"] = os.environ.get("OPENCLAW_GATEWAY_URL")

            if args and args[0] == "agent":
                count = int(state.get("agent_count", 0))
                state["agent_count"] = count + 1
                message_path = pathlib.Path(args[args.index("--message-file") + 1])
                record.update({{
                    "message_path": str(message_path),
                    "message_mode": stat.S_IMODE(message_path.stat().st_mode),
                    "message": message_path.read_text(),
                    "stdin_closed": sys.stdin.buffer.read() == b"",
                }})
                responses = state["responses"]
                response = (
                    state["prompt_responses"].get(message_path.read_text(), {{"invalid": True}})
                    if responses is None
                    else responses[min(count, len(responses) - 1)]
                )
                if isinstance(response, dict) and response.get("fake") == "timeout":
                    state_path.write_text(json.dumps(state))
                    with log_path.open("a") as stream:
                        stream.write(json.dumps(record) + "\\n")
                    time.sleep(60)
                if isinstance(response, dict) and response.get("fake") == "transport_loss":
                    output = ""
                    exit_code = 9
                elif isinstance(response, dict) and response.get("fake") == "overflow":
                    output = "x" * 400000
                    exit_code = 0
                elif isinstance(response, str):
                    output = response
                    exit_code = 0
                else:
                    output = json.dumps(response)
                    exit_code = 0
                state_path.write_text(json.dumps(state))
            elif args == ["--version"]:
                output = state["version"]
                exit_code = 0
            elif args == ["config", "get", "gateway.mode", "--json"]:
                output = json.dumps(state["gateway_mode"])
                exit_code = 0
            elif args == ["config", "get", "env", "--json"]:
                output = "" if state["config_env"] is None else json.dumps(state["config_env"])
                exit_code = 1 if state["config_env"] is None else 0
            elif args == ["agents", "list", "--json"]:
                output = (
                    state["agents"]
                    if isinstance(state["agents"], str)
                    else json.dumps(state["agents"])
                )
                exit_code = 0
            elif args == ["gateway", "status", "--json", "--require-rpc"]:
                output = (
                    state["gateway"]
                    if isinstance(state["gateway"], str)
                    else json.dumps(state["gateway"])
                )
                exit_code = 0
            else:
                output = "unexpected argv"
                exit_code = 17

            with log_path.open("a") as stream:
                stream.write(json.dumps(record) + "\\n")
            if output:
                print(output)
            raise SystemExit(exit_code)
            """
        ),
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable, state_path, log_path


def _logs(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines()]


def _prepared(
    tmp_path: Path,
    *,
    agents: object | None = None,
    gateway: object | None = None,
    responses: list[object] | None = None,
    model_override: str | None = None,
) -> tuple[Any, Path]:
    executable, _, log_path = _fake_openclaw(
        tmp_path,
        agents=agents,
        gateway=gateway,
        responses=responses,
    )
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    targets = connector.list_targets(probe)
    prepared = connector.prepare(probe, targets[0], model_override)
    return prepared, log_path


def _turn(prepared: Any, *, town_run_id: str = "run-001") -> Any:
    run = prepared.open_run(town_run_id)
    return run.turn(START_OBSERVATION)


def _assert_code(error_type: type[Exception], code: str, callback: Any) -> None:
    with pytest.raises(error_type) as caught:
        callback()
    assert str(caught.value) == code, (
        repr(caught.value.__cause__),
        repr(caught.value.__cause__.__cause__) if caught.value.__cause__ else None,
    )
    assert caught.value.args == (code,)


def _traceback_locals(error: BaseException) -> str:
    values: list[str] = []
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.append(repr(current))
        traceback = current.__traceback__
        while traceback is not None:
            filename = traceback.tb_frame.f_code.co_filename
            if "/tests/" not in filename:
                values.extend(repr(value) for value in traceback.tb_frame.f_locals.values())
            traceback = traceback.tb_next
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return " ".join(values)


def test_fixture_matches_the_sanitized_characterized_success_envelope() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    envelope = json.loads(raw)
    meta = envelope["result"]["meta"]

    assert set(envelope) == {"runId", "status", "summary", "result"}
    assert len(envelope["result"]["payloads"]) == 1
    assert set(envelope["result"]["payloads"][0]) == {"text", "mediaUrl"}
    assert envelope["result"]["payloads"][0]["mediaUrl"] is None
    assert set(meta) == {
        "durationMs",
        "agentMeta",
        "aborted",
        "finalAssistantVisibleText",
        "finalAssistantRawText",
        "replayInvalid",
        "livenessState",
        "stopReason",
        "executionTrace",
        "completion",
    }
    assert meta["livenessState"] == "working"
    assert meta["stopReason"] == "stop"
    assert meta["executionTrace"]["fallbackUsed"] is False
    assert meta["executionTrace"]["runner"] == "embedded"
    assert "sessionKey" not in meta["agentMeta"]
    assert not any(
        marker in raw
        for marker in (
            "/Users/",
            "/home/",
            "Bearer ",
            "systemPrompt",
            "usage",
            "toolSummary",
            "pendingToolCalls",
            "transport",
            "fallbackFrom",
            "fallbackReason",
        )
    )


def test_turn_projects_exact_bounded_prompts_and_fake_output_depends_on_them(
    tmp_path: Path,
) -> None:
    prepared, log_path = _prepared(tmp_path)
    run = prepared.open_run("prompt-contract")

    start = run.turn(START_OBSERVATION)
    message = run.turn(MESSAGE_OBSERVATION)

    prompts = [entry["message"] for entry in _logs(log_path) if entry["argv"][0] == "agent"]
    assert prompts == [START_PROMPT, MESSAGE_PROMPT]
    assert start.intent == {"capabilities": ["sell"], "kind": "declare_capability"}
    assert message.intent == {
        "kind": "send_to_sender",
        "media_type": "text/plain; charset=utf-8",
        "text": "sold:widget:2",
    }
    assert "sold:widget:2" not in MESSAGE_PROMPT
    assert "run_id" not in START_PROMPT + MESSAGE_PROMPT
    assert "session" not in START_PROMPT.lower() + MESSAGE_PROMPT.lower()


def test_parser_accepts_safe_additive_characterized_metadata_without_returning_it(
    tmp_path: Path,
) -> None:
    response = _success_envelope()
    response["result"]["meta"].update(
        {
            "systemPromptReport": {
                "mode": "synthetic",
                "tools": ["configured-but-not-called"],
                "messages": {"context": 1},
            },
            "requestShaping": {"strategy": "none"},
        }
    )
    response["result"]["meta"]["agentMeta"].update(
        {
            "contextTokens": 114688,
            "usage": {"input": 22, "output": 8},
            "lastCallUsage": {"input": 22, "output": 8},
            "promptTokens": 22,
        }
    )
    prepared, _ = _prepared(tmp_path, responses=[response])

    turn = _turn(prepared)

    assert turn.intent == {"capabilities": ["sell"], "kind": "declare_capability"}
    assert not hasattr(turn, "usage")
    assert not hasattr(turn, "system_prompt_report")


def test_non_posix_platform_fails_as_configuration_before_any_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    executable, _, log_path = _fake_openclaw(tmp_path)
    connector = OpenClawConnector(executable=executable)
    monkeypatch.setattr(runtime_module.os, "name", "nt")

    _assert_code(
        RuntimeConfigurationError,
        "OPENCLAW_PLATFORM_UNSUPPORTED",
        connector.probe,
    )
    assert _logs(log_path) == []


_OBSERVATION_MUTATIONS: list[Mutation] = [
    lambda value: value.update(extra="not-profile-owned"),
    lambda value: value["message"].update(sender_id="other"),
    lambda value: value["message"].update(media_type="text/plain"),
    lambda value: value["message"].update(text="buy:other:1"),
]


@pytest.mark.parametrize("mutation", _OBSERVATION_MUTATIONS)
def test_altered_profile_observation_fails_before_an_agent_turn(
    tmp_path: Path, mutation: Mutation
) -> None:
    prepared, log_path = _prepared(tmp_path)
    run = prepared.open_run("observation-contract")
    observation = copy.deepcopy(MESSAGE_OBSERVATION)
    mutation(observation)

    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_OBSERVATION_INVALID",
        lambda: run.turn(observation),
    )
    assert not [entry for entry in _logs(log_path) if entry["argv"][0] == "agent"]


def test_fractional_duration_is_accepted_without_becoming_public_metadata(
    tmp_path: Path,
) -> None:
    response = _success_envelope()
    response["result"]["meta"]["durationMs"] = 42.5
    prepared, _ = _prepared(tmp_path, responses=[response])

    turn = _turn(prepared)

    assert turn.intent == {"capabilities": ["sell"], "kind": "declare_capability"}
    assert not hasattr(turn, "duration_ms")


def test_missing_executable_is_an_uninspectable_probe(tmp_path: Path) -> None:
    connector = OpenClawConnector(executable=tmp_path / "missing-openclaw")
    assert connector.probe() is None


@pytest.mark.parametrize("version", [VERSION_BANNER, f"OpenClaw {VERSION}"])
def test_probe_accepts_the_characterized_version_banner(
    tmp_path: Path,
    version: str,
) -> None:
    executable, _, _ = _fake_openclaw(tmp_path, version=version)
    connector = OpenClawConnector(executable=executable)

    assert connector.probe() == RuntimeProbe(
        "openclaw",
        executable,
        VERSION,
        RuntimeDisplay("OpenClaw", "openclaw gateway status"),
    )


@pytest.mark.parametrize(
    ("banner", "detected_version"),
    [
        ("2032.11.4-rc.2+build_7", "2032.11.4-rc.2+build_7"),
        ("OpenClaw 2032.11.4-rc.2+build_7 (abcdef0)", "2032.11.4-rc.2+build_7"),
    ],
)
def test_coherent_bare_and_branded_versions_prepare_run_and_record_detected_version(
    tmp_path: Path,
    banner: str,
    detected_version: str,
) -> None:
    executable, _, _ = _fake_openclaw(
        tmp_path,
        version=banner,
        gateway=_gateway(version=detected_version),
    )
    connector = OpenClawConnector(executable=executable)

    probe = connector.probe()

    assert probe is not None
    target = connector.list_targets(probe)[0]
    prepared = connector.prepare(probe, target, None)
    turn = _turn(prepared)

    assert probe.version == detected_version
    assert prepared.runtime_version == detected_version
    assert turn.intent == {"capabilities": ["sell"], "kind": "declare_capability"}


@pytest.mark.parametrize(
    "banner",
    [
        "",
        "OpenClaw",
        "OpenClaw 2032.11.4 unexpected",
        "OpenClaw " + "x" * 129,
    ],
)
def test_malformed_version_banners_fail_before_agent_inventory(
    tmp_path: Path,
    banner: str,
) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path, version=banner)
    connector = OpenClawConnector(executable=executable)

    _assert_code(
        RuntimeConfigurationError,
        "OPENCLAW_VERSION_UNSUPPORTED",
        connector.probe,
    )

    assert [entry["argv"] for entry in _logs(log_path)] == [["--version"]]


_MIXED_VERSION_MUTATIONS: list[Mutation] = [
    lambda gateway: gateway["cli"].update(version="2032.11.4-rc.3"),
    lambda gateway: gateway["gateway"].update(version="2032.11.4-rc.3"),
    lambda gateway: gateway["rpc"].update(version="2032.11.4-rc.3"),
    lambda gateway: gateway["rpc"]["server"].update(version="2032.11.4-rc.3"),
]


@pytest.mark.parametrize("mutate", _MIXED_VERSION_MUTATIONS)
def test_mixed_component_versions_are_rejected_against_detected_cli_version(
    tmp_path: Path,
    mutate: Mutation,
) -> None:
    detected_version = "2032.11.4-rc.2"
    gateway = _gateway(version=detected_version)
    mutate(gateway)
    executable, _, log_path = _fake_openclaw(
        tmp_path,
        version=f"OpenClaw {detected_version}",
        gateway=gateway,
    )
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()

    assert probe is not None
    target = connector.list_targets(probe)[0]
    _assert_code(
        RuntimeConfigurationError,
        "OPENCLAW_VERSION_MISMATCH",
        lambda: connector.prepare(probe, target, None),
    )
    assert [entry["argv"] for entry in _logs(log_path)][-1] == [
        "gateway",
        "status",
        "--json",
        "--require-rpc",
    ]


@pytest.mark.parametrize("gateway_mode", ["remote", None, "", "LOCAL", {"mode": "local"}])
def test_probe_rejects_any_gateway_mode_other_than_exact_local_before_inventory(
    tmp_path: Path,
    gateway_mode: object,
) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path, gateway_mode=gateway_mode)
    connector = OpenClawConnector(executable=executable)

    _assert_code(
        RuntimeConfigurationError,
        "OPENCLAW_REMOTE_DISPATCH",
        connector.probe,
    )

    assert [entry["argv"] for entry in _logs(log_path)] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
    ]


@pytest.mark.parametrize(
    "config_env",
    [
        {"OPENCLAW_GATEWAY_URL": "wss://remote.example"},
        {"vars": {"OPENCLAW_GATEWAY_URL": "wss://remote.example"}},
        {"vars": {" OPENCLAW_GATEWAY_URL ": "wss://remote.example"}},
        {"\ufeff OPENCLAW_GATEWAY_URL ": "wss://remote.example"},
        {"vars": {"\ufeffOPENCLAW_GATEWAY_URL": "wss://remote.example"}},
    ],
)
def test_probe_rejects_config_environment_gateway_url_before_inventory(
    tmp_path: Path,
    config_env: object,
) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path, config_env=config_env)
    connector = OpenClawConnector(executable=executable)

    _assert_code(
        RuntimeConfigurationError,
        "OPENCLAW_REMOTE_DISPATCH",
        connector.probe,
    )

    assert [entry["argv"] for entry in _logs(log_path)] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
    ]


def test_probe_accepts_absent_or_unrelated_config_environment(tmp_path: Path) -> None:
    config_environments = (
        None,
        {"vars": {"SAFE_KEY": "value"}},
        {"OPENCLAW_GATEWAY_URL_BACKUP": "wss://unused.example"},
        {"vars": {"MY_OPENCLAW_GATEWAY_URL": "wss://unused.example"}},
    )
    for index, config_env in enumerate(config_environments):
        case = tmp_path / str(index)
        case.mkdir()
        executable, _, _ = _fake_openclaw(case, config_env=config_env)

        assert OpenClawConnector(executable=executable).probe() is not None


@pytest.mark.parametrize("config_env", [[], "invalid", 1])
def test_probe_rejects_invalid_config_environment_before_inventory(
    tmp_path: Path,
    config_env: object,
) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path, config_env=config_env)
    connector = OpenClawConnector(executable=executable)

    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_CONFIG_ENV_INVALID",
        connector.probe,
    )

    assert [entry["argv"] for entry in _logs(log_path)] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
    ]


def test_config_environment_values_are_not_retained_on_route_rejection(tmp_path: Path) -> None:
    executable, _, _ = _fake_openclaw(
        tmp_path,
        config_env={"vars": {"OPENCLAW_GATEWAY_URL": "private-config-value-canary"}},
    )

    with pytest.raises(RuntimeConfigurationError) as caught:
        OpenClawConnector(executable=executable).probe()

    assert caught.value.code == "OPENCLAW_REMOTE_DISPATCH"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "private-config-value-canary" not in _traceback_locals(caught.value)


def test_every_openclaw_child_neutralizes_gateway_url_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENCLAW_GATEWAY_URL", "wss://remote-gateway-canary.example")
    executable, _, log_path = _fake_openclaw(tmp_path, record_gateway_url=True)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]
    prepared = connector.prepare(probe, target, None)

    _turn(prepared)

    records = _logs(log_path)
    assert [record["argv"] for record in records] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
        ["gateway", "status", "--json", "--require-rpc"],
        [
            "agent",
            "--agent",
            "buyer",
            "--session-key",
            "town-run-001",
            "--timeout",
            "0",
            "--message-file",
            records[-1]["argv"][-2],
            "--json",
        ],
    ]
    assert {record["gateway_url"] for record in records} == {""}
    assert "remote-gateway-canary" not in json.dumps(records)


def test_prepare_accepts_the_characterized_gateway_status_shape(tmp_path: Path) -> None:
    executable, _, _ = _fake_openclaw(tmp_path, gateway=_gateway())
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    prepared = connector.prepare(probe, target, None)

    assert prepared.runtime_version == VERSION


_OPTIONAL_GATEWAY_REMOVALS: list[Mutation] = [
    lambda value: value.pop("pluginVersionDrift"),
    lambda value: value.pop("port"),
    lambda value: value.pop("extraServices"),
    lambda value: value["cli"].pop("entrypoint"),
    lambda value: value["config"]["cli"].pop("controlUi"),
    lambda value: value["config"]["daemon"].pop("controlUi"),
    lambda value: (value["rpc"].pop("auth"), value["rpc"].pop("server")),
]


@pytest.mark.parametrize("remove", _OPTIONAL_GATEWAY_REMOVALS)
def test_prepare_allows_officially_optional_gateway_diagnostics(
    tmp_path: Path,
    remove: Mutation,
) -> None:
    gateway = _gateway()
    remove(gateway)
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    assert connector.prepare(probe, target, None).runtime_version == VERSION


def test_prepare_requests_only_the_read_rpc_gateway_status(tmp_path: Path) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    connector.prepare(probe, target, None)

    assert _logs(log_path)[-1]["argv"] == [
        "gateway",
        "status",
        "--json",
        "--require-rpc",
    ]


def test_prepare_does_not_police_gateway_listener_exposure(tmp_path: Path) -> None:
    gateway = _gateway()
    gateway["gateway"].update(bindHost="0.0.0.0", bindMode="lan")
    gateway["port"]["listeners"][0]["address"] = "TCP *:18789 (LISTEN)"
    gateway["extraServices"].append({"label": "user-managed-service"})
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    assert connector.prepare(probe, target, None).runtime_version == VERSION


@pytest.mark.parametrize("route", ["probe", "rpc"])
def test_prepare_still_requires_a_local_route_with_lan_listener_advisories(
    tmp_path: Path,
    route: str,
) -> None:
    gateway = _gateway()
    gateway["gateway"].update(bindHost="0.0.0.0", bindMode="lan")
    gateway["port"]["listeners"][0]["address"] = "TCP *:18789 (LISTEN)"
    gateway["extraServices"].append({"label": "user-managed-service"})
    if route == "probe":
        gateway["gateway"]["probeUrl"] = "ws://192.0.2.10:18789"
    else:
        gateway["rpc"]["url"] = "ws://192.0.2.10:18789"
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    _assert_code(
        RuntimeConfigurationError,
        "OPENCLAW_REMOTE_DISPATCH",
        lambda: connector.prepare(probe, target, None),
    )


def test_prepare_allows_official_additive_gateway_diagnostics(tmp_path: Path) -> None:
    gateway = _gateway()
    gateway["config"].update(mismatch=False, issues=[], warnings=[])
    gateway.update(issues=[], warnings=[])
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    assert connector.prepare(probe, target, None).runtime_version == VERSION


def test_invalid_utf8_version_output_is_code_only(tmp_path: Path) -> None:
    executable = tmp_path / "openclaw"
    executable.write_text(
        f"#!{os.fspath(Path(sys.executable))}\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'private-version\\xff')\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    connector = OpenClawConnector(executable=executable)

    with pytest.raises(RuntimeConfigurationError) as caught:
        connector.probe()

    assert caught.value.code == "OPENCLAW_VERSION_UNSUPPORTED"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "private-version" not in repr(caught.value)
    assert "private-version" not in _traceback_locals(caught.value)


def test_probe_and_agents_use_only_the_frozen_read_only_argv(tmp_path: Path) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe == RuntimeProbe(
        "openclaw",
        executable,
        VERSION,
        RuntimeDisplay("OpenClaw", "openclaw gateway status"),
    )
    assert probe is not None

    targets = connector.list_targets(probe)

    assert targets == (RuntimeTarget("buyer", "provider/model"),)
    assert _logs(log_path) == [
        {"argv": ["--version"], "town_env": []},
        {"argv": ["config", "get", "gateway.mode", "--json"], "town_env": []},
        {"argv": ["config", "get", "env", "--json"], "town_env": []},
        {"argv": ["agents", "list", "--json"], "town_env": []},
    ]
    assert not hasattr(targets[0], "workspace")
    assert not hasattr(targets[0], "agentDir")


def test_read_only_preflight_has_bounded_general_deadlines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, _, _ = _fake_openclaw(tmp_path)
    original = openclaw_runtime.run_bounded
    calls: list[tuple[tuple[str, ...], float]] = []

    def observe_deadline(argv: list[str], **kwargs: Any) -> Any:
        calls.append((tuple(argv[1:]), kwargs["deadline_seconds"]))
        return original(argv, **kwargs)

    monkeypatch.setattr(openclaw_runtime, "run_bounded", observe_deadline)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None

    target = connector.list_targets(probe)[0]
    connector.prepare(probe, target, None)

    assert calls == [
        (("--version",), 5),
        (("config", "get", "gateway.mode", "--json"), 5),
        (("config", "get", "env", "--json"), 5),
        (("agents", "list", "--json"), 30),
        (("gateway", "status", "--json", "--require-rpc"), 5),
    ]


@pytest.mark.parametrize(
    ("agents", "error_type", "code"),
    [
        (
            '[{"id":"buyer","id":"seller","model":"provider/model"}]',
            RuntimeExecutionError,
            "OPENCLAW_AGENTS_INVALID",
        ),
        ("not-json", RuntimeExecutionError, "OPENCLAW_AGENTS_INVALID"),
        ([{"id": "buyer", "model": 7}], RuntimeExecutionError, "OPENCLAW_AGENTS_INVALID"),
        (
            [{"id": "buyer", "model": None}, {"id": "buyer", "model": None}],
            RuntimeConfigurationError,
            "TARGET_AMBIGUOUS",
        ),
        (
            [{"id": "x" * 129, "model": None}],
            RuntimeExecutionError,
            "OPENCLAW_AGENTS_INVALID",
        ),
    ],
)
def test_agent_listing_rejects_duplicates_malformed_types_and_sizes(
    tmp_path: Path,
    agents: object,
    error_type: type[Exception],
    code: str,
) -> None:
    executable, _, _ = _fake_openclaw(tmp_path, agents=agents)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None

    _assert_code(error_type, code, lambda: connector.list_targets(probe))


def test_invalid_agent_listing_paths_are_not_retained(tmp_path: Path) -> None:
    agents = [
        {
            "id": 7,
            "model": "provider/model",
            "workspace": "/private-agent-workspace-canary",
        }
    ]
    executable, _, _ = _fake_openclaw(tmp_path, agents=agents)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None

    with pytest.raises(RuntimeExecutionError) as caught:
        connector.list_targets(probe)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "/private-agent-workspace-canary" not in _traceback_locals(caught.value)


_GATEWAY_MUTATIONS: list[tuple[Mutation, str]] = [
    (lambda value: value["cli"].update(version="2026.7.1-3"), "OPENCLAW_VERSION_MISMATCH"),
    (lambda value: value["gateway"].update(version="2026.7.1"), "OPENCLAW_VERSION_MISMATCH"),
    (lambda value: value["rpc"].update(version="unknown"), "OPENCLAW_VERSION_MISMATCH"),
    (
        lambda value: value["rpc"]["server"].update(version="unknown"),
        "OPENCLAW_VERSION_MISMATCH",
    ),
    (
        lambda value: value["config"]["daemon"].update(path="/synthetic/other.json"),
        "OPENCLAW_CONFIG_DRIFT",
    ),
    (lambda value: value["config"].update(mismatch=True), "OPENCLAW_CONFIG_DRIFT"),
    (lambda value: value["rpc"].update(ok=False), "OPENCLAW_RPC_UNHEALTHY"),
    (
        lambda value: value["gateway"].update(probeUrl="ws://192.0.2.10:18789"),
        "OPENCLAW_REMOTE_DISPATCH",
    ),
    (
        lambda value: value["rpc"].update(url="ws://example.test:18789"),
        "OPENCLAW_REMOTE_DISPATCH",
    ),
]


@pytest.mark.parametrize(("mutate", "code"), _GATEWAY_MUTATIONS)
def test_prepare_requires_version_config_coherence_rpc_and_loopback(
    tmp_path: Path, mutate: Mutation, code: str
) -> None:
    gateway = _gateway()
    mutate(gateway)
    executable, _, log_path = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    _assert_code(
        RuntimeConfigurationError,
        code,
        lambda: connector.prepare(probe, target, None),
    )
    assert [entry["argv"] for entry in _logs(log_path)] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
        ["gateway", "status", "--json", "--require-rpc"],
    ]


@pytest.mark.parametrize("gateway", ["not-json", '{"cliVersion":"x","cliVersion":"y"}', []])
def test_prepare_rejects_malformed_or_duplicate_gateway_output(
    tmp_path: Path, gateway: object
) -> None:
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_GATEWAY_INVALID",
        lambda: connector.prepare(probe, target, None),
    )


def test_prepared_openclaw_owns_safe_display_label_and_issue_policy(tmp_path: Path) -> None:
    prepared, _ = _prepared(tmp_path)

    assert prepared.runtime_id == "openclaw"
    assert prepared.display == RuntimeDisplay("OpenClaw", "openclaw gateway status")
    assert prepared.target_label == "openclaw:buyer"
    assert OpenClawConnector.issue_policy is prepared.issue_policy
    assert prepared.issue_policy.code_for(
        RuntimeIncompleteError("OPENCLAW_GATEWAY_UNAVAILABLE")
    ) == ("OPENCLAW_GATEWAY_UNAVAILABLE")
    assert prepared.issue_policy.code_for(RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID")) == (
        "OPENCLAW_GATEWAY_INVALID"
    )
    assert prepared.issue_policy.code_for(RuntimeExecutionError("OPENCLAW_TIMEOUT")) == (
        "OPENCLAW_TIMEOUT"
    )
    assert prepared.issue_policy.code_for(RuntimeExecutionError("UNKNOWN_OPENCLAW_CODE")) == (
        "RUNTIME_EXECUTION_FAILED"
    )


def test_gateway_structural_output_failure_is_execution_not_user_configuration(
    tmp_path: Path,
) -> None:
    gateway = _gateway()
    del gateway["gateway"]
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_GATEWAY_INVALID",
        lambda: connector.prepare(probe, target, None),
    )


def test_invalid_gateway_paths_are_not_retained(tmp_path: Path) -> None:
    gateway = _gateway()
    gateway["gateway"]["version"] = "invalid"
    gateway["config"]["cli"]["path"] = "/private-config-canary"
    gateway["config"]["daemon"]["path"] = "/private-config-canary"
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    with pytest.raises(RuntimeConfigurationError) as caught:
        connector.prepare(probe, target, None)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "/private-config-canary" not in _traceback_locals(caught.value)


def test_nonfinite_json_is_malformed_not_a_version_mismatch(tmp_path: Path) -> None:
    executable, _, _ = _fake_openclaw(tmp_path, gateway='{"cliVersion":NaN}')
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_GATEWAY_INVALID",
        lambda: connector.prepare(probe, target, None),
    )


def test_oversized_json_integer_is_rejected_before_gateway_validation(tmp_path: Path) -> None:
    gateway = _gateway()
    gateway["unknownCounter"] = 2**80
    executable, _, _ = _fake_openclaw(tmp_path, gateway=gateway)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_GATEWAY_INVALID",
        lambda: connector.prepare(probe, target, None),
    )


def test_empty_model_override_does_not_fall_back_to_configured_model(tmp_path: Path) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    target = connector.list_targets(probe)[0]

    _assert_code(
        RuntimeConfigurationError,
        "OPENCLAW_MODEL_INVALID",
        lambda: connector.prepare(probe, target, ""),
    )
    assert [entry["argv"] for entry in _logs(log_path)] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
    ]


def test_prepare_rejects_unknown_target_without_running_gateway(tmp_path: Path) -> None:
    executable, _, log_path = _fake_openclaw(tmp_path)
    connector = OpenClawConnector(executable=executable)
    probe = connector.probe()
    assert probe is not None
    connector.list_targets(probe)

    _assert_code(
        RuntimeConfigurationError,
        "TARGET_NOT_FOUND",
        lambda: connector.prepare(probe, RuntimeTarget("unknown", None), None),
    )
    assert [entry["argv"] for entry in _logs(log_path)] == [
        ["--version"],
        ["config", "get", "gateway.mode", "--json"],
        ["config", "get", "env", "--json"],
        ["agents", "list", "--json"],
    ]


def test_turn_uses_exact_argv_private_prompt_and_no_town_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOWN_BEARER", "private-bearer-canary")
    prepared, log_path = _prepared(tmp_path)
    turn = _turn(prepared)
    agent_log = _logs(log_path)[-1]
    message_path = Path(agent_log["message_path"])

    assert agent_log["argv"][:6] == [
        "agent",
        "--agent",
        "buyer",
        "--session-key",
        "town-run-001",
        "--timeout",
    ]
    assert agent_log["argv"][6] == "0"
    assert agent_log["argv"][7] == "--message-file"
    assert agent_log["argv"][8] == agent_log["message_path"]
    assert agent_log["argv"][9:] == ["--json"]
    assert not ({"--deliver", "--local", "--channel"} & set(agent_log["argv"]))
    assert agent_log["message_mode"] == 0o600
    assert agent_log["stdin_closed"] is True
    assert agent_log["town_env"] == []
    assert "private-bearer-canary" not in json.dumps(agent_log)
    assert not message_path.exists()
    assert turn.intent == {"capabilities": ["sell"], "kind": "declare_capability"}
    assert turn.provider == "provider"
    assert turn.model == "model"
    assert turn.activity == "unknown"
    assert "town-run-001" not in turn.session_ref_digest


def test_every_openclaw_child_explicitly_requests_only_its_connector_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    real_run_bounded = runtime_module.run_bounded
    policies: list[frozenset[str]] = []
    environments: list[dict[str, str]] = []

    def capture_policy(argv: list[str], **kwargs: Any) -> Any:
        policies.append(kwargs["allowed_environment_keys"])
        environments.append(kwargs["environment"])
        return real_run_bounded(argv, **kwargs)

    monkeypatch.setattr(runtime_module, "run_bounded", capture_policy)
    prepared, _ = _prepared(tmp_path)
    _turn(prepared)

    expected_policy = frozenset(
        {"OPENCLAW_CONFIG_PATH", "OPENCLAW_GATEWAY_URL", "OPENCLAW_STATE_DIR"}
    )
    assert policies == [expected_policy] * 6
    assert environments == [{"OPENCLAW_GATEWAY_URL": ""}] * 6


def test_message_file_setup_failure_closes_fd_removes_path_and_is_code_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    prepared, log_path = _prepared(tmp_path)
    run = prepared.open_run("file-failure")
    created: dict[str, object] = {}
    real_mkstemp = runtime_module.tempfile.mkstemp

    def tracked_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        descriptor, path = cast("tuple[int, str]", real_mkstemp(*args, **kwargs))
        created.update(descriptor=descriptor, path=path)
        return descriptor, path

    def fail_fchmod(_descriptor: int, _mode: int) -> None:
        raise OSError

    monkeypatch.setattr(runtime_module.tempfile, "mkstemp", tracked_mkstemp)
    monkeypatch.setattr(runtime_module.os, "fchmod", fail_fchmod)

    with pytest.raises(RuntimeExecutionError) as caught:
        run.turn(START_OBSERVATION)

    assert caught.value.code == "OPENCLAW_MESSAGE_FILE_FAILED"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert not Path(cast("str", created["path"])).exists()
    assert cast("str", created["path"]) not in _traceback_locals(caught.value)
    with pytest.raises(OSError):
        os.fstat(cast("int", created["descriptor"]))
    assert not [entry for entry in _logs(log_path) if entry["argv"][0] == "agent"]


def test_invalid_observation_retains_no_prompt_or_parser_context(tmp_path: Path) -> None:
    prepared, _ = _prepared(tmp_path)
    run = prepared.open_run("invalid-observation")

    class Unserializable:
        def __repr__(self) -> str:
            return "raw-observation-canary"

    observation = {
        "privatePrompt": "raw-observation-canary",
        "value": Unserializable(),
    }
    with pytest.raises(RuntimeExecutionError) as caught:
        run.turn(observation)

    assert caught.value.code == "OPENCLAW_OBSERVATION_INVALID"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "raw-observation-canary" not in _traceback_locals(caught.value)


def test_hostile_mapping_failure_retains_no_observation_or_exception_data(tmp_path: Path) -> None:
    prepared, _ = _prepared(tmp_path)
    run = prepared.open_run("hostile-observation")

    class HostileMapping(Mapping[str, object]):
        def __getitem__(self, _key: str) -> object:
            raise KeyError

        def __iter__(self) -> Any:
            raise RuntimeError("hostile-observation-canary")

        def __len__(self) -> int:
            return 1

    with pytest.raises(RuntimeExecutionError) as caught:
        run.turn(HostileMapping())

    assert caught.value.code == "OPENCLAW_OBSERVATION_INVALID"
    assert str(caught.value) == "OPENCLAW_OBSERVATION_INVALID"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "hostile-observation-canary" not in _traceback_locals(caught.value)


def test_failed_turn_traceback_retains_no_prompt_envelope_or_message_path(tmp_path: Path) -> None:
    response = _success_envelope()
    response["privateEnvelope"] = "raw-envelope-canary"
    prepared, log_path = _prepared(tmp_path, responses=[response])
    run = prepared.open_run("traceback")

    with pytest.raises(RuntimeExecutionError) as caught:
        run.turn(START_OBSERVATION)

    retained = _traceback_locals(caught.value)
    message_path = _logs(log_path)[-1]["message_path"]
    assert START_PROMPT not in retained
    assert "raw-envelope-canary" not in retained
    assert message_path not in retained


def test_message_file_is_removed_when_turn_is_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    prepared, _ = _prepared(tmp_path)
    run = prepared.open_run("cancelled")
    created: dict[str, str] = {}
    real_mkstemp = runtime_module.tempfile.mkstemp

    def tracked_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        descriptor, path = cast("tuple[int, str]", real_mkstemp(*args, **kwargs))
        created["path"] = path
        return descriptor, path

    def cancel(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime_module.tempfile, "mkstemp", tracked_mkstemp)
    monkeypatch.setattr(runtime_module, "run_bounded", cancel)

    with pytest.raises(KeyboardInterrupt):
        run.turn(START_OBSERVATION)

    assert not Path(created["path"]).exists()


def test_unlink_failure_leaves_only_an_erased_message_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    prepared, _ = _prepared(tmp_path)
    run = prepared.open_run("unlink-failure")
    created: dict[str, str] = {}
    real_mkstemp = runtime_module.tempfile.mkstemp
    real_unlink = runtime_module.Path.unlink

    def tracked_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        descriptor, path = cast("tuple[int, str]", real_mkstemp(*args, **kwargs))
        created["path"] = path
        return descriptor, path

    def fail_private_unlink(path: Path, *, missing_ok: bool = False) -> None:
        if os.fspath(path) == created.get("path"):
            raise OSError
        real_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(runtime_module.tempfile, "mkstemp", tracked_mkstemp)
    monkeypatch.setattr(runtime_module.Path, "unlink", fail_private_unlink)

    try:
        with pytest.raises(RuntimeExecutionError) as caught:
            run.turn(START_OBSERVATION)

        message_path = Path(created["path"])
        assert caught.value.code == "OPENCLAW_MESSAGE_FILE_CLEANUP_FAILED"
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert message_path.exists()
        assert message_path.read_bytes() == b""
        assert START_PROMPT not in _traceback_locals(caught.value)
    finally:
        if "path" in created:
            real_unlink(Path(created["path"]), missing_ok=True)


def test_setup_cancellation_closes_fd_and_removes_message_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    prepared, _ = _prepared(tmp_path)
    run = prepared.open_run("setup-cancelled")
    created: dict[str, object] = {}
    real_mkstemp = runtime_module.tempfile.mkstemp

    def tracked_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        descriptor, path = cast("tuple[int, str]", real_mkstemp(*args, **kwargs))
        created.update(descriptor=descriptor, path=path)
        return descriptor, path

    def cancel_fchmod(_descriptor: int, _mode: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime_module.tempfile, "mkstemp", tracked_mkstemp)
    monkeypatch.setattr(runtime_module.os, "fchmod", cancel_fchmod)

    with pytest.raises(KeyboardInterrupt):
        run.turn(START_OBSERVATION)

    assert not Path(cast("str", created["path"])).exists()
    with pytest.raises(OSError):
        os.fstat(cast("int", created["descriptor"]))


def test_parser_cancellation_retains_no_raw_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    response = _success_envelope()
    response["privateEnvelope"] = "parser-cancellation-envelope-canary"
    prepared, _ = _prepared(tmp_path, responses=[response])
    run = prepared.open_run("parser-cancelled")

    def cancel_parser(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime_module, "_envelope_turn", cancel_parser)

    with pytest.raises(KeyboardInterrupt) as caught:
        run.turn(START_OBSERVATION)

    assert "parser-cancellation-envelope-canary" not in _traceback_locals(caught.value)


def test_optional_model_override_is_the_only_extra_agent_flag(tmp_path: Path) -> None:
    prepared, log_path = _prepared(tmp_path, model_override="provider/model")

    _turn(prepared)

    argv = _logs(log_path)[-1]["argv"]
    assert argv[-3:] == ["--json", "--model", "provider/model"]


def test_two_turns_share_one_fresh_session_and_close_does_not_delete_transcript(
    tmp_path: Path,
) -> None:
    first = _success_envelope()
    second = _success_envelope({"kind": "none"})
    prepared, log_path = _prepared(tmp_path, responses=[first, second])
    run = prepared.open_run("fresh-run")

    run.turn(START_OBSERVATION)
    turn = run.turn(MESSAGE_OBSERVATION)
    run.close()

    agent_argv = [entry["argv"] for entry in _logs(log_path) if entry["argv"][0] == "agent"]
    assert [argv[4] for argv in agent_argv] == ["town-fresh-run", "town-fresh-run"]
    assert turn.intent == {"kind": "none"}
    assert not any("delete" in argument for argv in agent_argv for argument in argv)


def test_second_turn_requires_the_exact_same_reported_session_id(tmp_path: Path) -> None:
    first = _success_envelope()
    second = _success_envelope()
    second["result"]["meta"]["agentMeta"]["sessionId"] = "session-synthetic-002"
    prepared, log_path = _prepared(tmp_path, responses=[first, second])
    run = prepared.open_run("session-lineage")

    run.turn(START_OBSERVATION)
    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_SESSION_MISMATCH",
        lambda: run.turn(MESSAGE_OBSERVATION),
    )
    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_RUN_CLOSED",
        lambda: run.turn(MESSAGE_OBSERVATION),
    )
    assert len([entry for entry in _logs(log_path) if entry["argv"][0] == "agent"]) == 2


_ENVELOPE_MUTATIONS: list[tuple[Mutation, type[Exception], str]] = [
    (
        lambda value: value["result"]["meta"].update(toolSummary=[]),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(pendingToolCalls=[]),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"].update(delivery={"ok": True}),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(automation={"kind": "cron"}),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(spawnedSession={"id": "synthetic"}),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(didSendViaMessagingTool=True),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(acceptedSessionSpawns=1),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(successfulCronAdds=1),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(error="synthetic"),
        RuntimeIncompleteError,
        "OPENCLAW_RUN_ERROR",
    ),
    (
        lambda value: value["result"]["meta"].update(failureSignal="synthetic"),
        RuntimeIncompleteError,
        "OPENCLAW_RUN_ERROR",
    ),
    (
        lambda value: value["result"]["meta"]["executionTrace"].update(toolCalls=[]),
        RuntimeIncompleteError,
        "OPENCLAW_ACTIVITY_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"]["executionTrace"].update(fallbackUsed=True),
        RuntimeIncompleteError,
        "OPENCLAW_FALLBACK_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(fallback=True),
        RuntimeIncompleteError,
        "OPENCLAW_FALLBACK_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"]["agentMeta"].update(modelFallback="x"),
        RuntimeIncompleteError,
        "OPENCLAW_FALLBACK_REPORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(aborted=True),
        RuntimeIncompleteError,
        "OPENCLAW_ABORTED",
    ),
    (
        lambda value: value["result"]["meta"].update(replayInvalid=True),
        RuntimeIncompleteError,
        "OPENCLAW_REPLAY_INVALID",
    ),
    (lambda value: value.update(status="error"), RuntimeIncompleteError, "OPENCLAW_RUN_ERROR"),
    (
        lambda value: value["result"]["meta"].update(transport={}),
        RuntimeIncompleteError,
        "OPENCLAW_TRANSPORT_AMBIGUOUS",
    ),
    (
        lambda value: value["result"]["meta"].update(finalAssistantVisibleText="wrong"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"].update(finalAssistantRawText="wrong"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["payloads"][0].update(mediaUrl="https://example.invalid"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"]["agentMeta"].update(sessionKey="town-other"),
        RuntimeExecutionError,
        "OPENCLAW_SESSION_MISMATCH",
    ),
    (
        lambda value: value["result"]["meta"]["agentMeta"].update(provider="other"),
        RuntimeExecutionError,
        "OPENCLAW_MODEL_MISMATCH",
    ),
    (
        lambda value: value["result"]["meta"]["agentMeta"].update(model="other"),
        RuntimeExecutionError,
        "OPENCLAW_MODEL_MISMATCH",
    ),
    (
        lambda value: value["result"]["meta"]["executionTrace"].update(winnerModel="other"),
        RuntimeExecutionError,
        "OPENCLAW_MODEL_MISMATCH",
    ),
    (
        lambda value: value["result"]["meta"]["executionTrace"].update(attempts=[]),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"]["executionTrace"].update(runner="other"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"]["agentMeta"].update(agentHarnessId="not safe"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"].update(durationMs=False),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"].update(durationMs=-1),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"].update(durationMs=math.inf),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"].update(unknownMeta="synthetic"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"]["agentMeta"].update(unknownAgentMeta="synthetic"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
    (
        lambda value: value["result"]["meta"]["executionTrace"].update(unknownTrace="synthetic"),
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
    ),
]


@pytest.mark.parametrize(("mutation", "error_type", "code"), _ENVELOPE_MUTATIONS)
def test_envelope_rejects_activity_fallback_abort_replay_transport_and_lineage(
    tmp_path: Path, mutation: Mutation, error_type: type[Exception], code: str
) -> None:
    response = _success_envelope()
    mutation(response)
    prepared, _ = _prepared(tmp_path, responses=[response])

    _assert_code(error_type, code, lambda: _turn(prepared))


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ('{ "kind": "none" }', "OPENCLAW_INTENT_NONCANONICAL"),
        ('```json\n{"kind":"none"}\n```', "OPENCLAW_INTENT_INVALID"),
        ('{"command":"id","kind":"shell"}', "OPENCLAW_INTENT_FORBIDDEN"),
        ('{"extra":true,"kind":"none"}', "OPENCLAW_INTENT_FORBIDDEN"),
        (
            '{"kind":"send_to_sender","media_type":"text/html","text":"x"}',
            "OPENCLAW_INTENT_FORBIDDEN",
        ),
        (
            '{"kind":"send_to_sender","media_type":"text/plain; charset=utf-8","text":"x"}',
            "OPENCLAW_MODEL_MISMATCH",
        ),
        ("not-json", "OPENCLAW_INTENT_INVALID"),
    ],
)
def test_intent_must_be_canonical_bounded_and_forbidden_actions_stay_closed(
    tmp_path: Path, text: str, code: str
) -> None:
    response = _success_envelope()
    response["result"]["payloads"][0]["text"] = text
    response["result"]["meta"]["finalAssistantVisibleText"] = text
    response["result"]["meta"]["finalAssistantRawText"] = text
    if code == "OPENCLAW_MODEL_MISMATCH":
        response["result"]["meta"]["agentMeta"]["model"] = "different"
    prepared, _ = _prepared(tmp_path, responses=[response])

    _assert_code(RuntimeExecutionError, code, lambda: _turn(prepared))


def test_semantic_none_remains_evaluator_input_not_transport_failure(tmp_path: Path) -> None:
    response = _success_envelope()
    text = '{"kind":"none"}'
    response["result"]["payloads"][0]["text"] = text
    response["result"]["meta"]["finalAssistantVisibleText"] = text
    response["result"]["meta"]["finalAssistantRawText"] = text
    prepared, _ = _prepared(tmp_path, responses=[response])

    turn = _turn(prepared)

    assert turn.intent == {"kind": "none"}


@pytest.mark.parametrize(
    ("response", "code"),
    [
        ("not-json", "OPENCLAW_ENVELOPE_INVALID"),
        ('{"runId":"one","runId":"two"}', "OPENCLAW_ENVELOPE_INVALID"),
        ("", "OPENCLAW_ENVELOPE_INVALID"),
        ({"fake": "overflow"}, "OPENCLAW_OUTPUT_LIMIT"),
        ({"fake": "timeout"}, "OPENCLAW_TIMEOUT"),
        ({"fake": "transport_loss"}, "OPENCLAW_TRANSPORT_LOSS"),
    ],
)
def test_failed_turn_starts_exactly_one_child_and_never_retries_or_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: object,
    code: str,
) -> None:
    import nest_core.agent_test.openclaw_runtime as runtime_module

    if response == {"fake": "timeout"}:
        monkeypatch.setattr(runtime_module, "TURN_DEADLINE_SECONDS", 0.05)
        monkeypatch.setattr(runtime_module, "TERMINATE_GRACE_SECONDS", 0.05)
        monkeypatch.setattr(runtime_module, "KILL_REAP_SECONDS", 0.2)
    prepared, _ = _prepared(tmp_path, responses=[response])
    real_run_bounded = runtime_module.run_bounded
    message_paths: list[Path] = []

    def counted_run_bounded(argv: list[str], **kwargs: Any) -> Any:
        if len(argv) > 1 and argv[1] == "agent":
            message_paths.append(Path(argv[argv.index("--message-file") + 1]))
        return real_run_bounded(argv, **kwargs)

    monkeypatch.setattr(runtime_module, "run_bounded", counted_run_bounded)
    run = prepared.open_run("one-shot")
    _assert_code(RuntimeExecutionError, code, lambda: run.turn(START_OBSERVATION))
    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_RUN_CLOSED",
        lambda: run.turn(START_OBSERVATION),
    )

    assert len(message_paths) == 1
    assert not message_paths[0].exists()


def test_invalid_child_json_is_code_only_without_a_raw_parser_cause(tmp_path: Path) -> None:
    prepared, _ = _prepared(tmp_path, responses=["private-child-output-not-json"])
    run = prepared.open_run("sanitized")

    with pytest.raises(RuntimeExecutionError) as caught:
        run.turn(START_OBSERVATION)

    assert caught.value.code == "OPENCLAW_ENVELOPE_INVALID"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "private-child-output" not in repr(caught.value)
    assert "private-child-output" not in _traceback_locals(caught.value)


def test_invalid_intent_json_is_code_only_without_a_raw_parser_cause(tmp_path: Path) -> None:
    response = _success_envelope()
    text = "private-intent-output-not-json"
    response["result"]["payloads"][0]["text"] = text
    response["result"]["meta"]["finalAssistantVisibleText"] = text
    response["result"]["meta"]["finalAssistantRawText"] = text
    prepared, _ = _prepared(tmp_path, responses=[response])

    with pytest.raises(RuntimeExecutionError) as caught:
        _turn(prepared)

    assert caught.value.code == "OPENCLAW_INTENT_INVALID"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "private-intent-output" not in repr(caught.value)
    assert "private-intent-output" not in _traceback_locals(caught.value)


def test_duplicate_keys_and_oversized_nested_values_are_rejected(tmp_path: Path) -> None:
    oversized = copy.deepcopy(_success_envelope())
    oversized["summary"] = "x" * 1025
    prepared, _ = _prepared(tmp_path, responses=[oversized])

    _assert_code(
        RuntimeExecutionError,
        "OPENCLAW_ENVELOPE_INVALID",
        lambda: _turn(prepared),
    )
