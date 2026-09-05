"""Versioned regressions for exact terminal-output Path evaluation."""

import json

import httpx
import pytest

import nandatown.path_profiles as path_profiles
from nandatown.a2a_adapter import build_agent_card
from nandatown.bundle import load_bundle, verify_bundle
from nandatown.path_runner import path_evaluator_version, run_path_test


SUBJECT = "http://testserver"
STRICT_PRICE_PROFILE = "a2a-capability-fulfillment@0.3"
STRICT_QUOTE_PROFILE = "a2a-quote-intent@0.2"


def _proposed_profile(ref, monkeypatch):
    """Let the RED tests exercise old dispatch before the catalog exists."""
    if ref in path_profiles.PATH_PROFILES:
        return path_profiles.get_path_profile(ref)
    if ref == STRICT_PRICE_PROFILE:
        base_ref = "a2a-capability-fulfillment@0.2"
        changes = {"version": "0.3", "evaluator": "path-evaluator@0.2"}
    else:
        base_ref = "a2a-quote-intent@0.1"
        changes = {
            "version": "0.2",
            "evaluator": "quote-intent-evaluator@0.2",
        }
    profile = path_profiles.get_path_profile(base_ref).model_copy(
        update=changes)
    monkeypatch.setitem(path_profiles.PATH_PROFILES, profile.ref, profile)
    return profile


def _quote(order):
    return {
        "request_id": order["request_id"],
        "total_cents": 3990,
        "sku": "widget",
        "quantity": 2,
        "color": "blue",
        "merchant_id": "town-reference",
        "currency": "USD",
    }


def shaped_client(*, state="completed", second_state=None, layout="single"):
    attempts = 0

    def handle(request):
        nonlocal attempts
        if request.method == "GET":
            return httpx.Response(200, json=build_agent_card(SUBJECT))
        attempts += 1
        envelope = json.loads(request.content)
        order = json.loads(
            envelope["params"]["message"]["parts"][0]["text"])
        first = {"kind": "text", "text": json.dumps(_quote(order))}
        extra = {"kind": "text", "text": json.dumps({"hidden": True})}
        selected_layout = (
            "multiple_artifacts"
            if layout == "second_attempt_multiple" and attempts == 2
            else "single" if layout == "second_attempt_multiple" else layout
        )
        if selected_layout == "multiple_artifacts":
            artifacts = [
                {"artifactId": "quote", "parts": [first]},
                {"artifactId": "hidden", "parts": [extra]},
            ]
        elif selected_layout == "multiple_parts":
            artifacts = [{"artifactId": "quote", "parts": [first, extra]}]
        else:
            artifacts = [{"artifactId": "quote", "parts": [first]}]
        task = {
            "id": f"task-{attempts}",
            "kind": "task",
            "status": {
                "state": second_state
                if attempts == 2 and second_state is not None else state
            },
            "artifacts": artifacts,
        }
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": envelope["id"], "result": task,
        })

    return httpx.Client(
        base_url=SUBJECT, transport=httpx.MockTransport(handle))


def _run(tmp_path, profile_ref, **shape):
    with shaped_client(**shape) as http:
        return run_path_test(
            SUBJECT, str(tmp_path), profile_ref=profile_ref, http=http)


def _stage(result, name):
    return next(stage for stage in result.stages if stage.name == name)


def test_new_profiles_are_explicit_without_relabeling_legacy_evidence():
    legacy = {
        "a2a-capability-fulfillment@0.1": (
            "sha256:80d238c2de68dbe3de577ad88ae5eb742daeaf2628dc7802be2b11e68b8d4b83",
            "path-0.2",
        ),
        "a2a-capability-fulfillment@0.2": (
            "sha256:92b5a2337f362a0eb6d6baf2810d42e58283a6d352921a4bf875764b74aeca3b",
            "path-0.2",
        ),
        "a2a-quote-intent@0.1": (
            "sha256:7d9ecb75a3c2d6b1f5abff6a28d218d2532fea3a491b4fd9f5ef7ae6b8342997",
            "path-quote-intent-0.1",
        ),
    }
    for ref, (profile_fingerprint, evaluator_version) in legacy.items():
        profile = path_profiles.get_path_profile(ref)
        assert profile.fingerprint() == profile_fingerprint
        assert path_evaluator_version(profile) == evaluator_version

    strict_price = path_profiles.get_path_profile(STRICT_PRICE_PROFILE)
    strict_quote = path_profiles.get_path_profile(STRICT_QUOTE_PROFILE)
    assert strict_price.evaluator == "path-evaluator@0.2"
    assert strict_quote.evaluator == "quote-intent-evaluator@0.2"
    assert path_evaluator_version(strict_price) == "path-0.3"
    assert path_evaluator_version(strict_quote) == "path-quote-intent-0.2"
    assert path_profiles.DEFAULT_PATH_PROFILE == STRICT_PRICE_PROFILE


@pytest.mark.parametrize("state", ["failed", "working", "input-required"])
def test_strict_profile_requires_successful_terminal_state(
        tmp_path, monkeypatch, state):
    profile = _proposed_profile(STRICT_PRICE_PROFILE, monkeypatch)

    directory, result = _run(tmp_path, profile.ref, state=state)

    invocation = _stage(result, "protocol_invocation")
    assert invocation.status == "failed"
    assert "completed" in invocation.note
    assert state in invocation.note
    assert _stage(result, "semantic_result").status == "not_tested"
    assert result.verdict == "failed"
    bundle = load_bundle(directory)
    assert len([event for event in bundle["events"]
                if event.kind == "protocol_exchange"]) == 1
    assert not any(event.kind == "fulfillment_observed"
                   for event in bundle["events"])
    assert verify_bundle(directory) == []


@pytest.mark.parametrize("profile_ref", [
    STRICT_PRICE_PROFILE,
    STRICT_QUOTE_PROFILE,
])
@pytest.mark.parametrize("layout", ["multiple_artifacts", "multiple_parts"])
def test_strict_profile_counts_every_terminal_text_output(
        tmp_path, monkeypatch, profile_ref, layout):
    profile = _proposed_profile(profile_ref, monkeypatch)

    directory, result = _run(tmp_path, profile.ref, layout=layout)

    assert _stage(result, "protocol_invocation").status == "passed"
    semantic = _stage(result, "semantic_result")
    assert semantic.status == "failed"
    assert "exactly one terminal text output" in semantic.note
    assert "observed 2" in semantic.note
    assert result.verdict == "failed"
    bundle = load_bundle(directory)
    exchanges = [event for event in bundle["events"]
                 if event.kind == "protocol_exchange"]
    assert len(exchanges) == 1
    first_exchange = exchanges[0]
    assert first_exchange.detail["terminal_output_count"] == 2
    assert verify_bundle(directory) == []


def test_strict_profile_rejects_extra_output_on_duplicate_attempt(
        tmp_path, monkeypatch):
    profile = _proposed_profile(STRICT_PRICE_PROFILE, monkeypatch)

    directory, result = _run(
        tmp_path, profile.ref, layout="second_attempt_multiple")

    assert _stage(result, "semantic_result").status == "passed"
    duplicate = _stage(result, "duplicate_request")
    assert duplicate.status == "failed"
    assert "exactly one terminal text output" in duplicate.note
    assert "observed 2" in duplicate.note
    assert result.verdict == "failed"
    assert verify_bundle(directory) == []


def test_strict_profile_requires_duplicate_attempt_to_complete(
        tmp_path, monkeypatch):
    profile = _proposed_profile(STRICT_PRICE_PROFILE, monkeypatch)

    directory, result = _run(
        tmp_path, profile.ref, second_state="working")

    assert _stage(result, "semantic_result").status == "passed"
    duplicate = _stage(result, "duplicate_request")
    assert duplicate.status == "failed"
    assert "completed" in duplicate.note
    assert "working" in duplicate.note
    assert result.verdict == "failed"
    assert verify_bundle(directory) == []


def test_strict_quote_profile_passes_and_replays(tmp_path, monkeypatch):
    profile = _proposed_profile(STRICT_QUOTE_PROFILE, monkeypatch)

    directory, result = _run(tmp_path, profile.ref)

    assert result.verdict == "passed"
    assert result.evaluator_version == "path-quote-intent-0.2"
    assert verify_bundle(directory) == []


def test_explicit_legacy_profile_retains_first_output_and_state_semantics(
        tmp_path):
    directory, result = _run(
        tmp_path,
        "a2a-capability-fulfillment@0.2",
        state="failed",
        layout="multiple_artifacts",
    )

    assert result.verdict == "passed"
    assert result.evaluator_version == "path-0.2"
    bundle = load_bundle(directory)
    exchanges = [event for event in bundle["events"]
                 if event.kind == "protocol_exchange"]
    assert all("terminal_output_count" not in event.detail
               for event in exchanges)
    assert verify_bundle(directory) == []
