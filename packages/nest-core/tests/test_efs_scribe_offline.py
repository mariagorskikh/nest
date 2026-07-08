# SPDX-License-Identifier: Apache-2.0
"""Tests for the offline EFS Scribe scenario and validators."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.scenarios_builtin.efs_scribe_offline import ScribeAgent
from nest_core.sim.agent import AgentContext
from nest_core.types import AgentId, Token
from nest_core.validators import (
    validate_efs_scribe_delegation_tree,
    validate_efs_scribe_receipts_verified,
    validate_efs_scribe_rejects_adversarial_writes,
    validate_trace,
)
from nest_plugins_reference.auth.delegatable import DelegatableAuth
from nest_plugins_reference.identity.did_key import DidKeyIdentity

type Event = dict[str, Any]


def _send(msg: str, *, agent: str = "scribe-0", to: str = "verifier-0") -> Event:
    return {"ts": 0.0, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _mock_uid(*parts: str) -> str:
    return "0x" + hashlib.sha256("|".join(parts).encode()).hexdigest()


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _without_signature(request: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in request.items() if key != "signature"}


def _subject_path(subject: str) -> str:
    leaf_idx = int(subject.removeprefix("leaf-"))
    intermediary_idx = leaf_idx // 4
    return f"/agents/intermediary-{intermediary_idx}/{subject}/report.json"


def _leaf_scopes(subject: str) -> list[str]:
    return [
        f"efs.write:{_subject_path(subject).rsplit('/', 1)[0]}/*",
        "scribe:publish",
        "scribe:verify",
    ]


async def _leaf_token_async(subject: str) -> Token:
    leaf_idx = int(subject.removeprefix("leaf-"))
    intermediary = AgentId(f"intermediary-{leaf_idx // 4}")
    auth = DelegatableAuth(clock=0.0)
    root = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*", "scribe:*"])
    intermediary_token = await auth.delegate(
        root,
        audience=intermediary,
        scopes_subset=[
            f"efs.write:/agents/{intermediary}/*",
            "scribe:publish",
            "scribe:verify",
        ],
        ttl=100.0,
    )
    return await auth.delegate(
        intermediary_token,
        audience=AgentId(subject),
        scopes_subset=_leaf_scopes(subject),
        ttl=50.0,
    )


def _leaf_token(subject: str) -> Token:
    return asyncio.run(_leaf_token_async(subject))


def _sign_request(request: dict[str, Any]) -> None:
    request.pop("signature", None)
    subject = str(request["agent_id"])
    identity = DidKeyIdentity(AgentId(subject), seed=b"efs-scribe-offline")
    sig = identity.sign(_canonical(request).encode())
    request["signature"] = {
        "algorithm": sig.algorithm,
        "signer": str(sig.signer),
        "value": sig.value.hex(),
    }


def _verifier_identity(*subjects: str) -> DidKeyIdentity:
    identity = DidKeyIdentity(AgentId("scribe-0"), seed=b"efs-scribe-offline")
    for subject in subjects:
        peer = DidKeyIdentity(AgentId(subject), seed=b"efs-scribe-offline")
        identity.register_peer(AgentId(subject), peer.public_key)
    return identity


def _request(subject: str) -> dict[str, Any]:
    path = _subject_path(subject)
    payload = {"agent": subject, "body": {"ok": True, "path": path}, "schema": "efs-scribe-demo/v1"}
    request = {
        "type": "efs.scribe.request",
        "version": "1",
        "request_id": f"req-{subject}",
        "op": "file.upsert",
        "agent_id": subject,
        "capability_token": str(_leaf_token(subject)),
        "path": path,
        "payload": payload,
        "payload_hash": _sha256(_canonical(payload)),
        "nonce": f"nonce-{subject}-1",
        "tick": 3,
    }
    _sign_request(request)
    return request


def _request_events(requests: list[dict[str, Any]]) -> list[Event]:
    return [
        _send(
            "scribe_request|" + json.dumps(request, sort_keys=True, separators=(",", ":")),
            agent=str(request["agent_id"]),
            to="scribe-0",
        )
        for request in requests
    ]


def _receipt(subject: str, *, request: dict[str, Any] | None = None) -> dict[str, Any]:
    req = request or _request(subject)
    payload_sha256 = str(req["payload_hash"])
    request_id = f"req-{subject}"
    return {
        "type": "efs.scribe.verification_receipt",
        "version": "1",
        "request_id": request_id,
        "subject_url": "mock-eas:" + _mock_uid(request_id, payload_sha256),
        "ok": True,
        "efs": {
            "network": "offline",
            "chain_id": 0,
            "tx_hashes": [],
            "data_uid": _mock_uid("data", payload_sha256),
            "path": _subject_path(subject),
        },
        "checks": {
            "auth": True,
            "content_hash": True,
            "lens": True,
            "mode": True,
            "nonce": True,
            "signature": True,
        },
        "integrity": {
            "payload_sha256": payload_sha256,
            "canonical_request_sha256": _sha256(_canonical(_without_signature(req))),
        },
        "auth_context": {
            "subject": subject,
            "service": "efs-scribe",
            "scopes": _leaf_scopes(subject),
        },
    }


def _receipt_events(receipts: list[dict[str, Any]]) -> list[Event]:
    return [
        _send("scribe_receipt|" + json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        for receipt in receipts
    ]


def _valid_request_receipt_events() -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[Event]
]:
    requests = [_request(f"leaf-{idx}") for idx in range(12)]
    receipts = [_receipt(f"leaf-{idx}", request=req) for idx, req in enumerate(requests)]
    return requests, receipts, [*_request_events(requests), *_receipt_events(receipts)]


def test_receipt_validator_passes_for_verified_receipts() -> None:
    _requests, _receipts, events = _valid_request_receipt_events()

    result = validate_efs_scribe_receipts_verified(events)[0]

    assert result.passed, result.detail


def test_receipt_validator_fails_without_receipts() -> None:
    result = validate_efs_scribe_receipts_verified([])[0]

    assert not result.passed


def test_receipt_validator_fails_without_matching_requests() -> None:
    events = _receipt_events([_receipt(f"leaf-{idx}") for idx in range(12)])

    result = validate_efs_scribe_receipts_verified(events)[0]

    assert not result.passed
    assert "matching request" in result.detail


def test_receipt_validator_fails_shape_only_receipts() -> None:
    requests, forged, _events = _valid_request_receipt_events()
    for receipt in forged:
        receipt.pop("integrity")
        receipt["subject_url"] = "mock-eas:" + ("0x" + "a" * 64)
        receipt["efs"]["data_uid"] = "0x" + "b" * 64

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(forged)]
    )[0]

    assert not result.passed
    assert "integrity missing" in result.detail


def test_receipt_validator_fails_spoofed_trace_sender() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    forged_receipt_events = [{**event, "agent": "leaf-0"} for event in _receipt_events(receipts)]

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *forged_receipt_events]
    )[0]

    assert not result.passed
    assert "no receipts" in result.detail


def test_receipt_validator_fails_uid_binding_mismatch() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    receipts[0]["efs"]["data_uid"] = "0x" + "c" * 64

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "data uid mismatch" in result.detail


def test_receipt_validator_fails_payload_digest_mismatch() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["payload_hash"] = "sha256:" + ("0" * 64)
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "payload digest mismatch" in result.detail


def test_receipt_validator_fails_payload_body_path_mismatch() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["payload"]["body"]["path"] = "/agents/intermediary-0/leaf-1/report.json"
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "payload path mismatch" in result.detail


def test_receipt_validator_fails_non_string_nonce() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["nonce"] = {"value": "nonce-leaf-0-1"}
    _sign_request(requests[0])
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "request nonce missing" in result.detail


def test_receipt_validator_fails_payload_agent_mismatch() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["payload"]["agent"] = "leaf-1"
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "payload agent mismatch" in result.detail


def test_receipt_validator_fails_bad_signature_signer() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["signature"]["signer"] = "leaf-1"
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "signature signer mismatch" in result.detail


def test_receipt_validator_fails_bad_signature_value() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["signature"]["value"] = "00"
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "signature invalid" in result.detail


def test_receipt_validator_fails_bad_capability_token() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["capability_token"] = "test-token"
    _sign_request(requests[0])
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "capability token invalid" in result.detail


def test_receipt_validator_fails_unexpected_request_op() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["op"] = "file.delete"
    _sign_request(requests[0])
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "unexpected request envelope" in result.detail


def test_receipt_validator_allows_same_nonce_for_different_agents() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[1]["nonce"] = requests[0]["nonce"]
    _sign_request(requests[1])
    receipts[1] = _receipt("leaf-1", request=requests[1])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert result.passed, result.detail


def test_receipt_validator_fails_duplicate_receipt() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    receipts.append(dict(receipts[0]))

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "duplicate receipt" in result.detail


def test_receipt_validator_fails_mode_confusion_request() -> None:
    requests, receipts, _events = _valid_request_receipt_events()
    requests[0]["mode"] = "sepolia"
    receipts[0] = _receipt("leaf-0", request=requests[0])

    result = validate_efs_scribe_receipts_verified(
        [*_request_events(requests), *_receipt_events(receipts)]
    )[0]

    assert not result.passed
    assert "request mode confusion" in result.detail


def _attack_request_events() -> list[Event]:
    good = _request("leaf-0")

    cross_lens = _request("leaf-0")
    cross_lens["path"] = "/agents/intermediary-0/leaf-1/report.json"
    cross_lens["payload"]["body"]["path"] = cross_lens["path"]
    cross_lens["payload_hash"] = _sha256(_canonical(cross_lens["payload"]))
    cross_lens["nonce"] = "nonce-leaf-0-cross-lens"
    _sign_request(cross_lens)

    traversal = _request("leaf-0")
    traversal["path"] = "/agents/intermediary-0/leaf-0/../leaf-1/report.json"
    traversal["payload"]["body"]["path"] = traversal["path"]
    traversal["payload_hash"] = _sha256(_canonical(traversal["payload"]))
    traversal["nonce"] = "nonce-leaf-0-traversal"
    _sign_request(traversal)

    payload_path = _request("leaf-0")
    payload_path["payload"]["body"]["path"] = "/agents/intermediary-0/leaf-1/report.json"
    payload_path["payload_hash"] = _sha256(_canonical(payload_path["payload"]))
    payload_path["nonce"] = "nonce-leaf-0-payload-path"
    _sign_request(payload_path)

    bad_hash = _request("leaf-0")
    bad_hash["payload_hash"] = "sha256:" + ("0" * 64)
    bad_hash["nonce"] = "nonce-leaf-0-bad-hash"
    _sign_request(bad_hash)

    wrong_sig = _request("leaf-0")
    wrong_sig["signature"]["signer"] = "leaf-1"
    wrong_sig["nonce"] = "nonce-leaf-0-wrong-sig"

    mode_confusion = _request("leaf-0")
    mode_confusion["mode"] = "sepolia"
    mode_confusion["nonce"] = "nonce-leaf-0-mode"
    _sign_request(mode_confusion)

    attacks = {
        "nonce_replay": good,
        "cross_lens": cross_lens,
        "path_traversal": traversal,
        "payload_path_mismatch": payload_path,
        "payload_hash_mismatch": bad_hash,
        "wrong_signature": wrong_sig,
        "mode_confusion": mode_confusion,
    }
    return [
        _send(f"scribe_attack_request|{name}|{_canonical(request)}", agent="leaf-0", to="scribe-0")
        for name, request in attacks.items()
    ]


def test_attack_validator_requires_all_attacks_rejected() -> None:
    auth_attacks = ["scope_escalation", "revoked_parent", "audience_confusion"]
    write_attacks = [
        "cross_lens",
        "nonce_replay",
        "payload_hash_mismatch",
        "path_traversal",
        "payload_path_mismatch",
        "mode_confusion",
        "wrong_signature",
    ]
    events = [
        *[
            _send(f"scribe_auth_attack|{name}|rejected", agent="coordinator-0")
            for name in auth_attacks
        ],
        *_attack_request_events(),
        *[
            _send(
                f"scribe_attack|{name}|rejected",
                agent="coordinator-0" if name in auth_attacks else "scribe-0",
            )
            for name in [*auth_attacks, *write_attacks]
        ],
    ]

    result = validate_efs_scribe_rejects_adversarial_writes(events)[0]

    assert result.passed, result.detail


def test_attack_validator_fails_without_attack_evidence() -> None:
    attacks = [
        "scope_escalation",
        "revoked_parent",
        "audience_confusion",
        "cross_lens",
        "nonce_replay",
        "payload_hash_mismatch",
        "path_traversal",
        "payload_path_mismatch",
        "mode_confusion",
        "wrong_signature",
    ]
    events = [_send(f"scribe_attack|{name}|rejected") for name in attacks]

    result = validate_efs_scribe_rejects_adversarial_writes(events)[0]

    assert not result.passed
    assert "missing attack evidence" in result.detail


def test_attack_validator_fails_shape_only_attack_requests() -> None:
    auth_attacks = ["scope_escalation", "revoked_parent", "audience_confusion"]
    write_attacks = [
        "cross_lens",
        "nonce_replay",
        "payload_hash_mismatch",
        "path_traversal",
        "payload_path_mismatch",
        "mode_confusion",
        "wrong_signature",
    ]
    events = [
        *[
            _send(f"scribe_auth_attack|{name}|rejected", agent="coordinator-0")
            for name in auth_attacks
        ],
        *[
            _send(f"scribe_attack_request|{name}|{{}}", agent="leaf-0", to="scribe-0")
            for name in write_attacks
        ],
        *[
            _send(
                f"scribe_attack|{name}|rejected",
                agent="coordinator-0" if name in auth_attacks else "scribe-0",
            )
            for name in [*auth_attacks, *write_attacks]
        ],
    ]

    result = validate_efs_scribe_rejects_adversarial_writes(events)[0]

    assert not result.passed
    assert "malformed attack evidence" in result.detail


def test_attack_validator_fails_minimal_nonce_replay_evidence() -> None:
    auth_attacks = ["scope_escalation", "revoked_parent", "audience_confusion"]
    write_attacks = [
        "cross_lens",
        "nonce_replay",
        "payload_hash_mismatch",
        "path_traversal",
        "payload_path_mismatch",
        "mode_confusion",
        "wrong_signature",
    ]
    events = [
        *[
            _send(f"scribe_auth_attack|{name}|rejected", agent="coordinator-0")
            for name in auth_attacks
        ],
        *_attack_request_events(),
        _send(
            'scribe_attack_request|nonce_replay|{"agent_id":"leaf-0","nonce":"nonce-leaf-0-1"}',
            agent="leaf-0",
            to="scribe-0",
        ),
        *[
            _send(
                f"scribe_attack|{name}|rejected",
                agent="coordinator-0" if name in auth_attacks else "scribe-0",
            )
            for name in [*auth_attacks, *write_attacks]
        ],
    ]

    result = validate_efs_scribe_rejects_adversarial_writes(events)[0]

    assert not result.passed
    assert "malformed attack evidence" in result.detail


def test_attack_validator_fails_if_attack_accepted() -> None:
    events = [
        _send("scribe_auth_attack|scope_escalation|rejected", agent="coordinator-0"),
        _send("scribe_auth_attack|revoked_parent|accepted", agent="coordinator-0"),
        _send("scribe_attack|scope_escalation|rejected", agent="coordinator-0"),
        _send("scribe_attack|revoked_parent|accepted", agent="coordinator-0"),
    ]

    result = validate_efs_scribe_rejects_adversarial_writes(events)[0]

    assert not result.passed
    assert "revoked_parent" in result.detail


def test_attack_validator_fails_if_accepted_attack_is_later_rejected() -> None:
    auth_attacks = ["scope_escalation", "revoked_parent", "audience_confusion"]
    write_attacks = [
        "cross_lens",
        "nonce_replay",
        "payload_hash_mismatch",
        "path_traversal",
        "payload_path_mismatch",
        "mode_confusion",
        "wrong_signature",
    ]
    events = [
        *[
            _send(f"scribe_auth_attack|{name}|rejected", agent="coordinator-0")
            for name in auth_attacks
        ],
        *_attack_request_events(),
        _send("scribe_attack|cross_lens|accepted"),
        *[
            _send(
                f"scribe_attack|{name}|rejected",
                agent="coordinator-0" if name in auth_attacks else "scribe-0",
            )
            for name in [*auth_attacks, *write_attacks]
        ],
    ]

    result = validate_efs_scribe_rejects_adversarial_writes(events)[0]

    assert not result.passed
    assert "cross_lens" in result.detail


def test_scribe_rejects_unexpected_request_op() -> None:
    request = _request("leaf-0")
    request["op"] = "file.delete"
    _sign_request(request)
    leaf = DidKeyIdentity(AgentId("leaf-0"), seed=b"efs-scribe-offline")

    class Ctx:
        plugins = {"auth": DelegatableAuth(clock=3.0), "identity": leaf}

    ok, reason = asyncio.run(
        ScribeAgent(AgentId("verifier-0")).validate_request(cast("AgentContext", Ctx()), request)
    )

    assert not ok
    assert reason == "unexpected request envelope"


def test_scribe_allows_same_nonce_for_different_agents() -> None:
    leaf_0 = _request("leaf-0")
    leaf_1 = _request("leaf-1")
    leaf_1["nonce"] = str(leaf_0["nonce"])
    _sign_request(leaf_1)

    class Ctx:
        plugins = {
            "auth": DelegatableAuth(clock=3.0),
            "identity": _verifier_identity("leaf-0", "leaf-1"),
        }

    scribe = ScribeAgent(AgentId("verifier-0"))
    ok_0, _receipt_0 = asyncio.run(scribe.validate_request(cast("AgentContext", Ctx()), leaf_0))
    ok_1, _receipt_1 = asyncio.run(scribe.validate_request(cast("AgentContext", Ctx()), leaf_1))

    assert ok_0
    assert ok_1


def test_scribe_rejects_same_agent_nonce_replay() -> None:
    request = _request("leaf-0")

    class Ctx:
        plugins = {
            "auth": DelegatableAuth(clock=3.0),
            "identity": _verifier_identity("leaf-0"),
        }

    scribe = ScribeAgent(AgentId("verifier-0"))
    ok_0, _receipt_0 = asyncio.run(scribe.validate_request(cast("AgentContext", Ctx()), request))
    ok_1, reason_1 = asyncio.run(scribe.validate_request(cast("AgentContext", Ctx()), request))

    assert ok_0
    assert not ok_1
    assert reason_1 == "nonce replay"


def test_scribe_rejects_non_string_nonce() -> None:
    request = _request("leaf-0")
    request["nonce"] = {"value": "nonce-leaf-0-1"}
    _sign_request(request)

    class Ctx:
        plugins = {
            "auth": DelegatableAuth(clock=3.0),
            "identity": _verifier_identity("leaf-0"),
        }

    ok, reason = asyncio.run(
        ScribeAgent(AgentId("verifier-0")).validate_request(
            cast("AgentContext", Ctx()),
            request,
        )
    )

    assert not ok
    assert reason == "nonce malformed"


def _run(out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml")
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


def test_scenario_runs_and_passes_all_validators(tmp_path: Path) -> None:
    out = tmp_path / "delegated_auth.jsonl"
    _run(out)

    results = validate_trace(out, "delegated_auth")
    assert results, "expected validators to run"
    assert all(r.passed for r in results), [r.detail for r in results if not r.passed]


def test_jwt_baseline_runs_but_fails_validators(tmp_path: Path) -> None:
    out = tmp_path / "delegated_auth_jwt_baseline.jsonl"
    cfg = ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml")
    cfg.layers.auth = "jwt"
    cfg.output.trace = str(out)

    asyncio.run(ScenarioRunner(cfg).run())

    results = validate_trace(out, "delegated_auth")
    assert results, "expected validators to run"
    assert any(not r.passed for r in results), "jwt baseline should fail delegation checks"


def test_scenario_is_deterministic(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"

    _run(a)
    _run(b)

    assert a.read_bytes() == b.read_bytes()


def test_delegation_tree_validator_fails_for_missing_leaves() -> None:
    events = [_send("scribe_delegation|coordinator-0|intermediary-0|ok")]

    result = validate_efs_scribe_delegation_tree(events)[0]

    assert not result.passed


def test_delegation_tree_validator_rejects_wrong_leaf_partition() -> None:
    events = [
        *[_send(f"scribe_delegation|coordinator-0|intermediary-{idx}|ok") for idx in range(3)],
        *[_send(f"scribe_delegation|intermediary-999|leaf-{idx}|ok") for idx in range(12)],
    ]

    result = validate_efs_scribe_delegation_tree(events)[0]

    assert not result.passed
