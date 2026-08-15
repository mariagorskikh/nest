# SPDX-License-Identifier: Apache-2.0
"""Version-coherent, same-host OpenClaw connector for Town's managed runtime seam."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import tempfile
import uuid
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit

from .runtime_connectors import (
    RuntimeConfigurationError,
    RuntimeDisplay,
    RuntimeExecutionError,
    RuntimeIncompleteError,
    RuntimeIssuePolicy,
    RuntimeProbe,
    RuntimeTarget,
    RuntimeTurn,
)
from .runtime_subprocess import (
    DEFAULT_OUTPUT_LIMIT_BYTES,
    KILL_REAP_SECONDS,
    PROBE_DEADLINE_SECONDS,
    TERMINATE_GRACE_SECONDS,
    TURN_DEADLINE_SECONDS,
    ProcessError,
    run_bounded,
)

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 4096
_MAX_STRING_BYTES = 16 * 1024
_MAX_SUMMARY_BYTES = 1024
_MAX_INTENT_TEXT_BYTES = 4096
_AGENT_INVENTORY_DEADLINE_SECONDS = 30
_ECMASCRIPT_TRIM_CHARACTERS = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_ACTIVITY_KEYS = frozenset(
    {
        "channel",
        "channels",
        "acceptedsessionspawns",
        "automation",
        "automations",
        "cron",
        "cronjobs",
        "delivered",
        "deliveries",
        "delivery",
        "didsendviamessagingtool",
        "messages",
        "pendingtoolcalls",
        "spawn",
        "spawnedsession",
        "spawnedsessions",
        "spawns",
        "successfulcronadds",
        "tool",
        "toolcalls",
        "toolresults",
        "toolsummary",
        "tools",
    }
)
_ERROR_KEYS = frozenset({"error", "failuresignal"})
_CLI_VERSION_BANNER = re.compile(
    r"(?:OpenClaw )?([A-Za-z0-9][A-Za-z0-9._+-]{0,127})(?: \([0-9a-f]{7}\))?\Z"
)
_OPENCLAW_ENVIRONMENT_KEYS = frozenset(
    {"OPENCLAW_CONFIG_PATH", "OPENCLAW_GATEWAY_URL", "OPENCLAW_STATE_DIR"}
)
_OPENCLAW_ENVIRONMENT = {"OPENCLAW_GATEWAY_URL": ""}
_OPENCLAW_DISPLAY = RuntimeDisplay("OpenClaw", "openclaw gateway status")
_OPENCLAW_ISSUE_POLICY = RuntimeIssuePolicy(
    configuration=frozenset(
        {
            "OPENCLAW_CONFIG_DRIFT",
            "OPENCLAW_MODEL_INVALID",
            "OPENCLAW_PLATFORM_UNSUPPORTED",
            "OPENCLAW_PROBE_MISMATCH",
            "OPENCLAW_REMOTE_DISPATCH",
            "OPENCLAW_RPC_UNHEALTHY",
            "OPENCLAW_RUN_DUPLICATE",
            "OPENCLAW_RUN_ID_INVALID",
            "OPENCLAW_VERSION_MISMATCH",
            "OPENCLAW_VERSION_UNSUPPORTED",
            "TARGET_AMBIGUOUS",
            "TARGET_NOT_FOUND",
        }
    ),
    incomplete=frozenset(
        {
            "OPENCLAW_ABORTED",
            "OPENCLAW_ACTIVITY_REPORTED",
            "OPENCLAW_FALLBACK_REPORTED",
            "OPENCLAW_GATEWAY_UNAVAILABLE",
            "OPENCLAW_REPLAY_INVALID",
            "OPENCLAW_RUN_ERROR",
            "OPENCLAW_TRANSPORT_AMBIGUOUS",
        }
    ),
    execution=frozenset(
        {
            "OPENCLAW_AGENTS_INVALID",
            "OPENCLAW_AGENTS_UNAVAILABLE",
            "OPENCLAW_ENVELOPE_INVALID",
            "OPENCLAW_EXECUTION_FAILED",
            "OPENCLAW_CONFIG_MODE_INVALID",
            "OPENCLAW_CONFIG_MODE_UNAVAILABLE",
            "OPENCLAW_CONFIG_ENV_INVALID",
            "OPENCLAW_CONFIG_ENV_UNAVAILABLE",
            "OPENCLAW_GATEWAY_INVALID",
            "OPENCLAW_INTENT_FORBIDDEN",
            "OPENCLAW_INTENT_INVALID",
            "OPENCLAW_INTENT_NONCANONICAL",
            "OPENCLAW_MESSAGE_FILE_CLEANUP_FAILED",
            "OPENCLAW_MESSAGE_FILE_FAILED",
            "OPENCLAW_MODEL_MISMATCH",
            "OPENCLAW_OBSERVATION_INVALID",
            "OPENCLAW_OUTPUT_LIMIT",
            "OPENCLAW_PROBE_FAILED",
            "OPENCLAW_RUN_CLOSED",
            "OPENCLAW_SESSION_MISMATCH",
            "OPENCLAW_TIMEOUT",
            "OPENCLAW_TRANSPORT_LOSS",
        }
    ),
)


class _DuplicateKeyError(ValueError):
    pass


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError


def _validate_tree(value: object, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _MAX_JSON_NODES:
        raise ValueError
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > 2**63 - 1:
            raise ValueError
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError
        return
    if type(value) is str:
        if len(value.encode("utf-8")) > _MAX_STRING_BYTES:
            raise ValueError
        return
    if type(value) is list:
        for item in cast("list[object]", value):
            _validate_tree(item, depth=depth + 1, counter=counter)
        return
    if type(value) is dict:
        for key, item in cast("dict[object, object]", value).items():
            if type(key) is not str or len(key.encode("utf-8")) > 128:
                raise ValueError
            _validate_tree(item, depth=depth + 1, counter=counter)
        return
    raise ValueError


def _parse_json(raw: bytes, *, code: str, error_type: type[RuntimeError]) -> object:
    invalid = False
    text = ""
    value: object = None
    try:
        if not raw or len(raw) > DEFAULT_OUTPUT_LIMIT_BYTES:
            raise ValueError
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
        _validate_tree(value)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        invalid = True
    if invalid:
        raw = b""
        text = ""
        value = None
        raise error_type(code)
    return value


def _dictionary(value: object, *, code: str, error_type: type[RuntimeError]) -> dict[str, object]:
    if type(value) is not dict:
        raise error_type(code)
    return cast("dict[str, object]", value)


def _list(value: object, *, code: str, error_type: type[RuntimeError]) -> list[object]:
    if type(value) is not list:
        raise error_type(code)
    return cast("list[object]", value)


def _string(
    value: object,
    *,
    code: str,
    error_type: type[RuntimeError],
    maximum: int = 128,
) -> str:
    if type(value) is not str:
        raise error_type(code)
    result = value
    if (
        not result
        or result != result.strip()
        or len(result.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in result)
    ):
        raise error_type(code)
    return result


def _safe_id(value: object, *, code: str, error_type: type[RuntimeError]) -> str:
    result = _string(value, code=code, error_type=error_type)
    if _SAFE_ID.fullmatch(result) is None:
        raise error_type(code)
    return result


def _bounded_text(value: object, *, maximum: int, code: str) -> str:
    if type(value) is not str:
        raise RuntimeExecutionError(code)
    result = value
    if not result or len(result.encode("utf-8")) > maximum or "\x00" in result:
        raise RuntimeExecutionError(code)
    return result


def _process(
    argv: list[str],
    *,
    deadline_seconds: float,
    unavailable_code: str,
    error_type: type[RuntimeError],
) -> bytes:
    failed = False
    output = b""
    try:
        output = run_bounded(
            argv,
            deadline_seconds=deadline_seconds,
            environment=_OPENCLAW_ENVIRONMENT,
            allowed_environment_keys=_OPENCLAW_ENVIRONMENT_KEYS,
        ).stdout
    except ProcessError:
        failed = True
    if failed:
        del argv
        raise error_type(unavailable_code)
    return output


def _version_string(raw: bytes) -> str:
    invalid = False
    version = ""
    try:
        version = raw.decode("utf-8").strip("\n")
    except UnicodeDecodeError:
        invalid = True
    match = None if invalid else _CLI_VERSION_BANNER.fullmatch(version)
    if match is None or match.group(1) == "OpenClaw":
        raw = b""
        version = ""
        raise RuntimeConfigurationError("OPENCLAW_VERSION_UNSUPPORTED")
    return match.group(1)


def _require_local_gateway_mode(raw: bytes) -> None:
    invalid_code: str | None = None
    mode: object = None
    try:
        mode = _parse_json(
            raw,
            code="OPENCLAW_CONFIG_MODE_INVALID",
            error_type=RuntimeExecutionError,
        )
    except RuntimeExecutionError as error:
        invalid_code = error.code
    raw = b""
    if invalid_code is not None:
        mode = None
        raise RuntimeExecutionError(invalid_code)
    if mode != "local":
        mode = None
        raise RuntimeConfigurationError("OPENCLAW_REMOTE_DISPATCH")


def _gateway_url_config_issue(raw: bytes) -> str | None:
    invalid = False
    value: object = None
    try:
        value = _parse_json(
            raw,
            code="OPENCLAW_CONFIG_ENV_INVALID",
            error_type=RuntimeExecutionError,
        )
    except RuntimeExecutionError:
        invalid = True
    raw = b""
    if invalid:
        value = None
        return "OPENCLAW_CONFIG_ENV_INVALID"
    if type(value) is not dict:
        value = None
        return "OPENCLAW_CONFIG_ENV_INVALID"

    configured = False
    env = cast("dict[object, object]", value)
    for key in env:
        if type(key) is str and key.strip(_ECMASCRIPT_TRIM_CHARACTERS) == "OPENCLAW_GATEWAY_URL":
            configured = True
            break
    variables = env.get("vars")
    if not configured and type(variables) is dict:
        for key in cast("dict[object, object]", variables):
            if (
                type(key) is str
                and key.strip(_ECMASCRIPT_TRIM_CHARACTERS) == "OPENCLAW_GATEWAY_URL"
            ):
                configured = True
                break
    variables = None
    value = None
    env = {}
    if configured:
        return "OPENCLAW_REMOTE_DISPATCH"
    return None


def _require_no_gateway_url_config(executable: Path) -> None:
    failed = False
    result = None
    try:
        result = run_bounded(
            [os.fspath(executable), "config", "get", "env", "--json"],
            deadline_seconds=PROBE_DEADLINE_SECONDS,
            environment=_OPENCLAW_ENVIRONMENT,
            allowed_environment_keys=_OPENCLAW_ENVIRONMENT_KEYS,
            accept_empty_exit_one=True,
        )
    except ProcessError:
        failed = True
    if failed:
        result = None
        raise RuntimeExecutionError("OPENCLAW_CONFIG_ENV_UNAVAILABLE")
    assert result is not None
    if result.returncode == 1:
        result = None
        return
    raw = result.stdout
    result = None
    issue = _gateway_url_config_issue(raw)
    raw = b""
    if issue == "OPENCLAW_REMOTE_DISPATCH":
        raise RuntimeConfigurationError(issue)
    if issue is not None:
        raise RuntimeExecutionError(issue)


def _targets_from_output_unchecked(raw: bytes) -> tuple[RuntimeTarget, ...]:
    values = _list(
        _parse_json(
            raw,
            code="OPENCLAW_AGENTS_INVALID",
            error_type=RuntimeExecutionError,
        ),
        code="OPENCLAW_AGENTS_INVALID",
        error_type=RuntimeExecutionError,
    )
    targets: list[RuntimeTarget] = []
    seen: set[str] = set()
    for value in values:
        agent = _dictionary(
            value,
            code="OPENCLAW_AGENTS_INVALID",
            error_type=RuntimeExecutionError,
        )
        target_id = _safe_id(
            agent.get("id"),
            code="OPENCLAW_AGENTS_INVALID",
            error_type=RuntimeExecutionError,
        )
        if target_id in seen:
            raise RuntimeConfigurationError("TARGET_AMBIGUOUS")
        seen.add(target_id)
        configured_model = agent.get("model")
        if configured_model is not None:
            configured_model = _string(
                configured_model,
                code="OPENCLAW_AGENTS_INVALID",
                error_type=RuntimeExecutionError,
            )
            _model_pair(configured_model)
        targets.append(RuntimeTarget(target_id, configured_model))
    return tuple(targets)


def _targets_from_output(raw: bytes) -> tuple[RuntimeTarget, ...]:
    targets: tuple[RuntimeTarget, ...] | None = None
    configuration_code: str | None = None
    execution_code: str | None = None
    try:
        targets = _targets_from_output_unchecked(raw)
    except RuntimeConfigurationError as error:
        configuration_code = error.code
    except RuntimeExecutionError as error:
        execution_code = error.code
    raw = b""
    if configuration_code is not None:
        raise RuntimeConfigurationError(configuration_code)
    if execution_code is not None:
        raise RuntimeExecutionError(execution_code)
    assert targets is not None
    return targets


def _require_probe(probe: RuntimeProbe, executable: Path, detected_version: str) -> None:
    if (
        probe.runtime_id != "openclaw"
        or probe.executable != executable
        or probe.version != detected_version
        or probe.display != _OPENCLAW_DISPLAY
    ):
        raise RuntimeConfigurationError("OPENCLAW_PROBE_MISMATCH")


def _model_pair(value: str | None) -> tuple[str, str] | None:
    if value is None:
        return None
    if value.count("/") != 1:
        raise RuntimeConfigurationError("OPENCLAW_MODEL_INVALID")
    provider, model = value.split("/", 1)
    return (
        _safe_id(provider, code="OPENCLAW_MODEL_INVALID", error_type=RuntimeConfigurationError),
        _safe_id(model, code="OPENCLAW_MODEL_INVALID", error_type=RuntimeConfigurationError),
    )


def _is_loopback_url(value: object) -> bool:
    if type(value) is not str or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme in {"ws", "wss"}
            and parsed.hostname in _LOOPBACK_HOSTS
            and parsed.port is not None
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _walk_key_paths(value: object, *, prefix: tuple[str, ...] = ()) -> set[tuple[str, ...]]:
    paths: set[tuple[str, ...]] = set()
    if type(value) is dict:
        for key, item in cast("dict[str, object]", value).items():
            path = (*prefix, key)
            paths.add(path)
            paths.update(_walk_key_paths(item, prefix=path))
    elif type(value) is list:
        for item in cast("list[object]", value):
            paths.update(_walk_key_paths(item, prefix=prefix))
    return paths


def _raise_envelope_condition(value: dict[str, object]) -> None:
    allowed_fallback_path = ("result", "meta", "executionTrace", "fallbackUsed")
    opaque_report_prefixes = (
        ("result", "meta", "systemPromptReport"),
        ("result", "meta", "requestShaping"),
        ("result", "meta", "agentMeta", "usage"),
        ("result", "meta", "agentMeta", "lastCallUsage"),
    )
    activity_reported = False
    error_reported = False
    fallback_reported = False
    transport_reported = False
    for path in _walk_key_paths(value):
        if any(path[: len(prefix)] == prefix for prefix in opaque_report_prefixes):
            continue
        key = path[-1].lower()
        if key in _ACTIVITY_KEYS:
            activity_reported = True
        if key in _ERROR_KEYS:
            error_reported = True
        if "transport" in key:
            transport_reported = True
        if "fallback" in key and path != allowed_fallback_path:
            fallback_reported = True
    if fallback_reported:
        raise RuntimeIncompleteError("OPENCLAW_FALLBACK_REPORTED")
    if transport_reported:
        raise RuntimeIncompleteError("OPENCLAW_TRANSPORT_AMBIGUOUS")
    if activity_reported:
        raise RuntimeIncompleteError("OPENCLAW_ACTIVITY_REPORTED")
    if error_reported:
        raise RuntimeIncompleteError("OPENCLAW_RUN_ERROR")


def _canonical_intent(text: str) -> dict[str, object]:
    try:
        raw = text.encode("utf-8")
        if len(raw) > _MAX_INTENT_TEXT_BYTES:
            raise ValueError
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
        _validate_tree(value)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise RuntimeExecutionError("OPENCLAW_INTENT_INVALID") from None
    intent = _dictionary(
        value,
        code="OPENCLAW_INTENT_INVALID",
        error_type=RuntimeExecutionError,
    )
    if json.dumps(intent, ensure_ascii=False, sort_keys=True, separators=(",", ":")) != text:
        raise RuntimeExecutionError("OPENCLAW_INTENT_NONCANONICAL")
    kind = intent.get("kind")
    if kind == "none":
        if set(intent) != {"kind"}:
            raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
    elif kind == "declare_capability":
        if set(intent) != {"kind", "capabilities"}:
            raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
        capabilities = _list(
            intent.get("capabilities"),
            code="OPENCLAW_INTENT_FORBIDDEN",
            error_type=RuntimeExecutionError,
        )
        if not capabilities or len(capabilities) > 64:
            raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
        for capability in capabilities:
            _safe_id(
                capability,
                code="OPENCLAW_INTENT_FORBIDDEN",
                error_type=RuntimeExecutionError,
            )
    elif kind == "send_to_sender":
        if set(intent) != {"kind", "media_type", "text"}:
            raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
        if intent.get("media_type") != "text/plain; charset=utf-8":
            raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
        message = intent.get("text")
        if type(message) is not str or not message:
            raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
        if len(message.encode("utf-8")) > _MAX_INTENT_TEXT_BYTES:
            raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
    else:
        raise RuntimeExecutionError("OPENCLAW_INTENT_FORBIDDEN")
    return intent


def _prompt_bytes(observation: Mapping[str, object]) -> bytes:
    value = dict(observation)
    kind = value.get("kind")
    logical_time = value.get("logical_time")
    allowed_intents = value.get("allowed_intents")
    if type(logical_time) is not int or logical_time < 0 or type(allowed_intents) is not list:
        raise ValueError

    common = (
        "You are completing one basic local NANDA Town agent test.\n"
        "Return exactly one minified JSON object and no other characters.\n"
        "Do not return prose, Markdown, or code fences.\n"
        "Do not invoke tools, access files, memory, messages, channels, or perform any "
        "other action.\n"
    )
    if kind == "start":
        if set(value) != {"kind", "logical_time", "allowed_intents"} or allowed_intents != [
            "declare_capability",
            "none",
        ]:
            raise ValueError
        prompt = (
            common
            + "This is the start event. Declare the sell capability by returning exactly "
            + '{"capabilities":["sell"],"kind":"declare_capability"}.\n'
            + 'If you cannot do that, return exactly {"kind":"none"}.\n'
        )
    elif kind == "message":
        if set(value) != {"kind", "logical_time", "allowed_intents", "message"} or (
            allowed_intents != ["send_to_sender", "none"]
        ):
            raise ValueError
        message = value.get("message")
        if type(message) is not dict:
            raise ValueError
        message = cast("dict[str, object]", message)
        if set(message) != {"id", "sender_id", "media_type", "text"}:
            raise ValueError
        if (
            type(message.get("id")) is not str
            or _SAFE_ID.fullmatch(cast("str", message["id"])) is None
            or message.get("sender_id") != "requester-0"
            or message.get("media_type") != "text/plain; charset=utf-8"
        ):
            raise ValueError
        text = message.get("text")
        if (
            text != "buy:widget:2"
            or type(text) is not str
            or len(text.encode("utf-8")) > _MAX_INTENT_TEXT_BYTES
        ):
            raise ValueError
        encoded_text = json.dumps(text, ensure_ascii=False)
        prompt = (
            common
            + "This is the message event.\n"
            + f"Input text: {encoded_text}\n"
            + "If the text matches buy:<item>:<quantity>, return one canonical object shaped as "
            + '{"kind":"send_to_sender","media_type":"text/plain; charset=utf-8",'
            + '"text":"sold:<item>:<quantity>"}, replacing <item> and <quantity> with the '
            + "input values.\n"
            + 'If you cannot do that, return exactly {"kind":"none"}.\n'
        )
    else:
        raise ValueError
    raw = prompt.encode("utf-8")
    if not raw or len(raw) > 64 * 1024:
        raise ValueError
    return raw


def _envelope_turn(
    raw: bytes,
    *,
    session_key: str,
    expected_model: tuple[str, str] | None,
    expected_session_id_digest: str | None,
) -> tuple[RuntimeTurn, tuple[str, str], str]:
    value = _parse_json(
        raw,
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    envelope = _dictionary(
        value,
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    _raise_envelope_condition(envelope)
    if set(envelope) != {"runId", "status", "summary", "result"}:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    _safe_id(
        envelope.get("runId"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if envelope.get("status") != "ok":
        raise RuntimeIncompleteError("OPENCLAW_RUN_ERROR")
    if envelope.get("summary") != "completed":
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    if len(cast("str", envelope["summary"]).encode("utf-8")) > _MAX_SUMMARY_BYTES:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    result = _dictionary(
        envelope.get("result"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if set(result) != {"payloads", "meta"}:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    payloads = _list(
        result.get("payloads"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if len(payloads) != 1:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    payload = _dictionary(
        payloads[0],
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if set(payload) != {"text", "mediaUrl"} or payload.get("mediaUrl") is not None:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    text = _bounded_text(
        payload.get("text"),
        maximum=_MAX_INTENT_TEXT_BYTES,
        code="OPENCLAW_ENVELOPE_INVALID",
    )
    meta = _dictionary(
        result.get("meta"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    required_meta = {
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
    allowed_meta = required_meta | {"systemPromptReport", "requestShaping"}
    if not required_meta.issubset(meta) or not set(meta).issubset(allowed_meta):
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    for report_key in ("systemPromptReport", "requestShaping"):
        if report_key in meta and type(meta[report_key]) is not dict:
            raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    duration = meta.get("durationMs")
    if (
        type(duration) not in (int, float)
        or cast("int | float", duration) < 0
        or (type(duration) is float and not math.isfinite(duration))
    ):
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    if meta.get("aborted") is True:
        raise RuntimeIncompleteError("OPENCLAW_ABORTED")
    if meta.get("aborted") is not False:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    if meta.get("replayInvalid") is True:
        raise RuntimeIncompleteError("OPENCLAW_REPLAY_INVALID")
    if meta.get("replayInvalid") is not False:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    if (
        meta.get("finalAssistantVisibleText") != text
        or meta.get("finalAssistantRawText") != text
        or meta.get("livenessState") != "working"
        or meta.get("stopReason") != "stop"
    ):
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    trace = _dictionary(
        meta.get("executionTrace"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    required_trace = {"winnerProvider", "winnerModel", "attempts", "fallbackUsed", "runner"}
    if set(trace) != required_trace:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    if trace.get("fallbackUsed") is True:
        raise RuntimeIncompleteError("OPENCLAW_FALLBACK_REPORTED")
    if trace.get("fallbackUsed") is not False or trace.get("runner") != "embedded":
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    completion = _dictionary(
        meta.get("completion"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if completion != {"stopReason": "stop", "finishReason": "stop"}:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    agent_meta = _dictionary(
        meta.get("agentMeta"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    required_agent_meta = {"sessionId", "provider", "model", "agentHarnessId"}
    allowed_agent_meta = required_agent_meta | {
        "contextTokens",
        "usage",
        "lastCallUsage",
        "promptTokens",
        "sessionKey",
    }
    if not required_agent_meta.issubset(agent_meta) or not set(agent_meta).issubset(
        allowed_agent_meta
    ):
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    for counter_key in ("contextTokens", "promptTokens"):
        if counter_key in agent_meta and (
            type(agent_meta[counter_key]) is not int or cast("int", agent_meta[counter_key]) < 0
        ):
            raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    for usage_key in ("usage", "lastCallUsage"):
        if usage_key in agent_meta and type(agent_meta[usage_key]) is not dict:
            raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    if "sessionKey" in agent_meta and agent_meta.get("sessionKey") != session_key:
        raise RuntimeExecutionError("OPENCLAW_SESSION_MISMATCH")
    session_id = _safe_id(
        agent_meta.get("sessionId"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    session_id_digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    if expected_session_id_digest is not None and session_id_digest != expected_session_id_digest:
        raise RuntimeExecutionError("OPENCLAW_SESSION_MISMATCH")
    provider = _safe_id(
        agent_meta.get("provider"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    model = _safe_id(
        agent_meta.get("model"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    reported_model = (provider, model)
    if expected_model is not None and reported_model != expected_model:
        raise RuntimeExecutionError("OPENCLAW_MODEL_MISMATCH")
    _safe_id(
        agent_meta.get("agentHarnessId"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if trace.get("winnerProvider") != provider or trace.get("winnerModel") != model:
        raise RuntimeExecutionError("OPENCLAW_MODEL_MISMATCH")
    attempts = _list(
        trace.get("attempts"),
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if len(attempts) != 1:
        raise RuntimeExecutionError("OPENCLAW_ENVELOPE_INVALID")
    attempt = _dictionary(
        attempts[0],
        code="OPENCLAW_ENVELOPE_INVALID",
        error_type=RuntimeExecutionError,
    )
    if attempt != {
        "provider": provider,
        "model": model,
        "result": "success",
        "stage": "assistant",
    }:
        raise RuntimeExecutionError("OPENCLAW_MODEL_MISMATCH")
    intent = _canonical_intent(text)
    digest = "sha256:" + session_id_digest
    return (
        RuntimeTurn(intent, provider, model, digest, "unknown"),
        reported_model,
        session_id_digest,
    )


class OpenClawConnector:
    runtime_id = "openclaw"
    issue_policy = _OPENCLAW_ISSUE_POLICY

    def __init__(self, *, executable: str | os.PathLike[str] = "openclaw") -> None:
        self._requested_executable = os.fspath(executable)
        self._executable: Path | None = None
        self._detected_version: str | None = None
        self._listed_targets: tuple[RuntimeTarget, ...] | None = None

    def probe(self) -> RuntimeProbe | None:
        self._executable = None
        self._detected_version = None
        self._listed_targets = None
        if os.name != "posix":
            raise RuntimeConfigurationError("OPENCLAW_PLATFORM_UNSUPPORTED")
        requested = self._requested_executable
        resolved = shutil.which(requested) if os.sep not in requested else requested
        if resolved is None:
            return None
        executable = Path(resolved)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            return None
        version = _version_string(
            _process(
                [os.fspath(executable), "--version"],
                deadline_seconds=PROBE_DEADLINE_SECONDS,
                unavailable_code="OPENCLAW_PROBE_FAILED",
                error_type=RuntimeExecutionError,
            )
        )
        _require_local_gateway_mode(
            _process(
                [
                    os.fspath(executable),
                    "config",
                    "get",
                    "gateway.mode",
                    "--json",
                ],
                deadline_seconds=PROBE_DEADLINE_SECONDS,
                unavailable_code="OPENCLAW_CONFIG_MODE_UNAVAILABLE",
                error_type=RuntimeExecutionError,
            )
        )
        _require_no_gateway_url_config(executable)
        self._executable = executable
        self._detected_version = version
        return RuntimeProbe(self.runtime_id, executable, version, _OPENCLAW_DISPLAY)

    def list_targets(self, probe: RuntimeProbe) -> tuple[RuntimeTarget, ...]:
        if self._executable is None or self._detected_version is None:
            raise RuntimeConfigurationError("OPENCLAW_PROBE_MISMATCH")
        _require_probe(probe, self._executable, self._detected_version)
        self._listed_targets = _targets_from_output(
            _process(
                [os.fspath(self._executable), "agents", "list", "--json"],
                deadline_seconds=_AGENT_INVENTORY_DEADLINE_SECONDS,
                unavailable_code="OPENCLAW_AGENTS_UNAVAILABLE",
                error_type=RuntimeExecutionError,
            )
        )
        return self._listed_targets

    def prepare(
        self,
        probe: RuntimeProbe,
        target: RuntimeTarget,
        model_override: str | None,
    ) -> _PreparedOpenClaw:
        if (
            self._executable is None
            or self._detected_version is None
            or self._listed_targets is None
        ):
            raise RuntimeConfigurationError("OPENCLAW_PROBE_MISMATCH")
        _require_probe(probe, self._executable, self._detected_version)
        matches = tuple(listed for listed in self._listed_targets if listed.id == target.id)
        if not matches or target not in matches:
            raise RuntimeConfigurationError("TARGET_NOT_FOUND")
        if len(matches) != 1:
            raise RuntimeConfigurationError("TARGET_AMBIGUOUS")
        expected_model = _model_pair(
            model_override if model_override is not None else target.configured_model
        )
        self._validate_gateway_output(
            _process(
                [
                    os.fspath(self._executable),
                    "gateway",
                    "status",
                    "--json",
                    "--require-rpc",
                ],
                deadline_seconds=PROBE_DEADLINE_SECONDS,
                unavailable_code="OPENCLAW_GATEWAY_UNAVAILABLE",
                error_type=RuntimeIncompleteError,
            ),
            detected_version=self._detected_version,
        )
        return _PreparedOpenClaw(
            executable=self._executable,
            runtime_version=self._detected_version,
            target=target,
            model_override=model_override,
            expected_model=expected_model,
        )

    @staticmethod
    def _validate_gateway_output(raw: bytes, *, detected_version: str) -> None:
        gateway: dict[str, object] = {}
        configuration_code: str | None = None
        execution_code: str | None = None
        try:
            gateway = _dictionary(
                _parse_json(
                    raw,
                    code="OPENCLAW_GATEWAY_INVALID",
                    error_type=RuntimeExecutionError,
                ),
                code="OPENCLAW_GATEWAY_INVALID",
                error_type=RuntimeExecutionError,
            )
            OpenClawConnector._validate_gateway(gateway, detected_version=detected_version)
        except RuntimeConfigurationError as error:
            configuration_code = error.code
        except RuntimeExecutionError as error:
            execution_code = error.code
        raw = b""
        gateway = {}
        if configuration_code is not None:
            raise RuntimeConfigurationError(configuration_code)
        if execution_code is not None:
            raise RuntimeExecutionError(execution_code)

    @staticmethod
    def _validate_gateway(status: dict[str, object], *, detected_version: str) -> None:
        if not {"cli", "config", "gateway", "rpc"}.issubset(status):
            raise RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID")
        cli = _dictionary(
            status.get("cli"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
        )
        if "version" not in cli:
            raise RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID")
        if "entrypoint" in cli:
            _string(
                cli.get("entrypoint"),
                code="OPENCLAW_GATEWAY_INVALID",
                error_type=RuntimeExecutionError,
                maximum=2048,
            )
        gateway = _dictionary(
            status.get("gateway"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
        )
        if cli.get("version") != detected_version or gateway.get("version") != detected_version:
            raise RuntimeConfigurationError("OPENCLAW_VERSION_MISMATCH")
        if "pluginVersionDrift" in status:
            plugin_drift = _dictionary(
                status.get("pluginVersionDrift"),
                code="OPENCLAW_GATEWAY_INVALID",
                error_type=RuntimeExecutionError,
            )
            if not {"drifts", "gatewayVersion"}.issubset(plugin_drift):
                raise RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID")
            if plugin_drift.get("gatewayVersion") != detected_version:
                raise RuntimeConfigurationError("OPENCLAW_VERSION_MISMATCH")
            drifts = _list(
                plugin_drift.get("drifts"),
                code="OPENCLAW_GATEWAY_INVALID",
                error_type=RuntimeExecutionError,
            )
            if drifts:
                raise RuntimeConfigurationError("OPENCLAW_CONFIG_DRIFT")
        if "logFile" in status:
            _string(
                status.get("logFile"),
                code="OPENCLAW_GATEWAY_INVALID",
                error_type=RuntimeExecutionError,
                maximum=2048,
            )
        config = _dictionary(
            status.get("config"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
        )
        cli_config = _dictionary(
            config.get("cli"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
        )
        daemon_config = _dictionary(
            config.get("daemon"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
        )
        required_config_keys = {"exists", "path", "valid"}
        if (
            not {"cli", "daemon"}.issubset(config)
            or not required_config_keys.issubset(cli_config)
            or not required_config_keys.issubset(daemon_config)
        ):
            raise RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID")
        if config.get("mismatch") is True:
            raise RuntimeConfigurationError("OPENCLAW_CONFIG_DRIFT")
        for value in (cli_config, daemon_config):
            if value.get("exists") is not True or value.get("valid") is not True:
                raise RuntimeConfigurationError("OPENCLAW_CONFIG_DRIFT")
            if "controlUi" in value:
                _dictionary(
                    value.get("controlUi"),
                    code="OPENCLAW_GATEWAY_INVALID",
                    error_type=RuntimeExecutionError,
                )
        cli_path = _string(
            cli_config.get("path"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
            maximum=2048,
        )
        daemon_path = _string(
            daemon_config.get("path"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
            maximum=2048,
        )
        if cli_path != daemon_path:
            raise RuntimeConfigurationError("OPENCLAW_CONFIG_DRIFT")
        rpc = _dictionary(
            status.get("rpc"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
        )
        if rpc.get("version") != detected_version:
            raise RuntimeConfigurationError("OPENCLAW_VERSION_MISMATCH")
        if rpc.get("ok") is not True:
            raise RuntimeConfigurationError("OPENCLAW_RPC_UNHEALTHY")
        if not {"capability", "kind", "ok", "url", "version"}.issubset(rpc):
            raise RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID")
        if "auth" in rpc:
            _dictionary(
                rpc.get("auth"),
                code="OPENCLAW_GATEWAY_INVALID",
                error_type=RuntimeExecutionError,
            )
        _string(
            rpc.get("capability"),
            code="OPENCLAW_GATEWAY_INVALID",
            error_type=RuntimeExecutionError,
        )
        if rpc.get("kind") != "read":
            raise RuntimeExecutionError("OPENCLAW_GATEWAY_INVALID")
        if "server" in rpc:
            server = _dictionary(
                rpc.get("server"),
                code="OPENCLAW_GATEWAY_INVALID",
                error_type=RuntimeExecutionError,
            )
            if server.get("version") != detected_version:
                raise RuntimeConfigurationError("OPENCLAW_VERSION_MISMATCH")
        if not _is_loopback_url(gateway.get("probeUrl")) or not _is_loopback_url(rpc.get("url")):
            raise RuntimeConfigurationError("OPENCLAW_REMOTE_DISPATCH")


class _PreparedOpenClaw:
    runtime_id = "openclaw"
    display = _OPENCLAW_DISPLAY
    issue_policy = _OPENCLAW_ISSUE_POLICY

    def __init__(
        self,
        *,
        executable: Path,
        runtime_version: str,
        target: RuntimeTarget,
        model_override: str | None,
        expected_model: tuple[str, str] | None,
    ) -> None:
        self.runtime_version = runtime_version
        self.target = target
        self.target_label = self._target_label(target.id)
        self.adapter_instance_id = "openclaw-" + uuid.uuid4().hex
        self._executable = executable
        self._model_override = model_override
        self._expected_model = expected_model
        self._opened_run_digests: set[str] = set()

    @staticmethod
    def _target_label(target_id: str) -> str:
        label = f"openclaw:{target_id}"
        if len(label) <= 128:
            return label
        suffix = hashlib.sha256(target_id.encode("ascii")).hexdigest()[:16]
        return f"openclaw:{target_id[:102]}:{suffix}"

    def open_run(self, town_run_id: str) -> _OpenClawRun:
        run_id = _safe_id(
            town_run_id,
            code="OPENCLAW_RUN_ID_INVALID",
            error_type=RuntimeConfigurationError,
        )
        session_key = f"town-{run_id}"
        if len(session_key) > 128:
            raise RuntimeConfigurationError("OPENCLAW_RUN_ID_INVALID")
        digest = hashlib.sha256(session_key.encode("utf-8")).hexdigest()
        if digest in self._opened_run_digests:
            raise RuntimeConfigurationError("OPENCLAW_RUN_DUPLICATE")
        self._opened_run_digests.add(digest)
        return _OpenClawRun(
            executable=self._executable,
            target=self.target,
            session_key=session_key,
            model_override=self._model_override,
            expected_model=self._expected_model,
        )


class _OpenClawRun:
    def __init__(
        self,
        *,
        executable: Path,
        target: RuntimeTarget,
        session_key: str,
        model_override: str | None,
        expected_model: tuple[str, str] | None,
    ) -> None:
        self._executable = executable
        self._target = target
        self._session_key = session_key
        self._model_override = model_override
        self._expected_model = expected_model
        self._session_id_digest: str | None = None
        self._closed = False
        self._turns = 0

    @staticmethod
    def _process_code(error: ProcessError) -> str:
        codes = {
            "PROCESS_TIMEOUT": "OPENCLAW_TIMEOUT",
            "PROCESS_OUTPUT_LIMIT": "OPENCLAW_OUTPUT_LIMIT",
            "PROCESS_EXIT_NONZERO": "OPENCLAW_TRANSPORT_LOSS",
        }
        return codes.get(error.code, "OPENCLAW_EXECUTION_FAILED")

    @staticmethod
    def _erase_and_close_descriptor(descriptor: int) -> bool:
        if descriptor < 0:
            return True
        erased = True
        try:
            os.ftruncate(descriptor, 0)
            os.fsync(descriptor)
        except OSError:
            erased = False
        finally:
            with suppress(OSError):
                os.close(descriptor)
        return erased

    @staticmethod
    def _write_descriptor(descriptor: int, content: bytes) -> None:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(descriptor)

    @staticmethod
    def _remove_message_file(path: Path | None) -> bool:
        if path is None:
            return True
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    def turn(self, observation: Mapping[str, object]) -> RuntimeTurn:
        if self._closed or self._turns >= 2:
            raise RuntimeExecutionError("OPENCLAW_RUN_CLOSED")
        try:
            observation_invalid = False
            prompt = b""
            try:
                prompt = _prompt_bytes(observation)
            except Exception:
                observation_invalid = True
            if observation_invalid:
                del observation, prompt
                raise RuntimeExecutionError("OPENCLAW_OBSERVATION_INVALID")
            del observation

            descriptor = -1
            name: str | None = None
            path: Path | None = None
            argv: list[str] | None = None
            raw: bytes | None = None
            setup_failed = False
            process_code: str | None = None
            unexpected: BaseException | None = None
            removed = True
            try:
                descriptor, name = tempfile.mkstemp(prefix="town-openclaw-", suffix=".json")
                path = Path(name)
                os.fchmod(descriptor, 0o600)
                self._write_descriptor(descriptor, prompt)
                argv = [
                    os.fspath(self._executable),
                    "agent",
                    "--agent",
                    self._target.id,
                    "--session-key",
                    self._session_key,
                    "--timeout",
                    "0",
                    "--message-file",
                    os.fspath(path),
                    "--json",
                ]
                if self._model_override is not None:
                    argv.extend(("--model", self._model_override))
                raw = run_bounded(
                    argv,
                    deadline_seconds=TURN_DEADLINE_SECONDS,
                    environment=_OPENCLAW_ENVIRONMENT,
                    allowed_environment_keys=_OPENCLAW_ENVIRONMENT_KEYS,
                    terminate_grace_seconds=TERMINATE_GRACE_SECONDS,
                    kill_reap_seconds=KILL_REAP_SECONDS,
                ).stdout
            except ProcessError as error:
                process_code = self._process_code(error)
            except (OSError, ValueError):
                setup_failed = True
            except BaseException as error:
                unexpected = error
            finally:
                erased = self._erase_and_close_descriptor(descriptor)
                removed = self._remove_message_file(path)
            del argv, descriptor, name, path, prompt
            if not erased or not removed:
                del raw, process_code, setup_failed, unexpected
                raise RuntimeExecutionError("OPENCLAW_MESSAGE_FILE_CLEANUP_FAILED") from None
            if setup_failed:
                del raw, process_code, unexpected
                raise RuntimeExecutionError("OPENCLAW_MESSAGE_FILE_FAILED")
            if unexpected is not None:
                error = unexpected
                del raw, process_code, setup_failed, unexpected
                raise error
            if process_code is not None:
                del raw
                raise RuntimeExecutionError(process_code) from None
            assert raw is not None

            parsed: tuple[RuntimeTurn, tuple[str, str], str] | None = None
            incomplete_code: str | None = None
            execution_code: str | None = None
            parser_unexpected: BaseException | None = None
            try:
                parsed = _envelope_turn(
                    raw,
                    session_key=self._session_key,
                    expected_model=self._expected_model,
                    expected_session_id_digest=self._session_id_digest,
                )
            except RuntimeIncompleteError as error:
                incomplete_code = error.code
            except RuntimeExecutionError as error:
                execution_code = error.code
            except BaseException as error:
                parser_unexpected = error.with_traceback(None)
                parser_unexpected.__cause__ = None
                parser_unexpected.__context__ = None
            del raw
            if parser_unexpected is not None:
                error = parser_unexpected
                del parser_unexpected
                raise error
            if incomplete_code is not None:
                raise RuntimeIncompleteError(incomplete_code)
            if execution_code is not None:
                raise RuntimeExecutionError(execution_code)
            assert parsed is not None
            turn, reported_model, session_id_digest = parsed
            del parsed
            if self._expected_model is None:
                self._expected_model = reported_model
            if self._session_id_digest is None:
                self._session_id_digest = session_id_digest
            self._turns += 1
            return turn
        except BaseException:
            self._closed = True
            raise

    def close(self) -> None:
        self._closed = True
