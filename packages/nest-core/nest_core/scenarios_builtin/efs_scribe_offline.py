# SPDX-License-Identifier: Apache-2.0
"""Offline EFS Scribe scenario for delegated write intents."""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Signature, Token


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _payload_hash(payload: dict[str, Any]) -> str:
    return _sha256(_canonical(payload))


def _mock_uid(*parts: str) -> str:
    return "0x" + hashlib.sha256("|".join(parts).encode()).hexdigest()


def _without_signature(request: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in request.items() if key != "signature"}


def _scope_allows(scopes: list[str], path: str) -> bool:
    desired = f"efs.write:{path}"
    for scope in scopes:
        if scope == desired:
            return True
        if not scope.endswith("*"):
            continue
        prefix = scope[:-1]
        if scope.startswith("efs.write:") and not prefix.endswith("/"):
            continue
        if desired.startswith(prefix):
            return True
    return False


def _normalized_path(path: str) -> bool:
    if not path.startswith("/") or "//" in path:
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/")[1:])


def _signature_from_json(raw: dict[str, Any]) -> Signature:
    return Signature(
        signer=AgentId(str(raw["signer"])),
        value=bytes.fromhex(str(raw["value"])),
        algorithm=str(raw["algorithm"]),
    )


def _supports_delegatable_auth(auth: Any) -> bool:
    return callable(getattr(auth, "delegate", None)) and callable(getattr(auth, "verify_for", None))


class CoordinatorAgent(StateMachineAgent):
    def __init__(self, intermediaries: dict[AgentId, list[AgentId]], verifier: AgentId) -> None:
        self._intermediaries = intermediaries
        self._verifier = verifier

    async def on_start(self, ctx: AgentContext) -> None:
        auth = ctx.plugins["auth"]
        if not _supports_delegatable_auth(auth):
            await ctx.send(
                self._verifier,
                b"scribe_attack|delegatable_auth_required|accepted",
            )
            return
        root = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*", "scribe:*"])
        for intermediary in self._intermediaries:
            token = await auth.delegate(
                root,
                audience=intermediary,
                scopes_subset=[
                    f"efs.write:/agents/{intermediary}/*",
                    "scribe:publish",
                    "scribe:verify",
                ],
                ttl=100.0,
            )
            await ctx.send(intermediary, f"delegate|{token}".encode())
            await ctx.send(
                self._verifier,
                f"scribe_delegation|coordinator-0|{intermediary}".encode(),
            )
        await self._record_auth_attacks(ctx, root)

    async def _record_auth_attacks(self, ctx: AgentContext, root: Token) -> None:
        auth = ctx.plugins["auth"]
        try:
            await auth.delegate(
                root,
                audience=AgentId("attacker-0"),
                scopes_subset=["efs.write:/private/*"],
                ttl=10.0,
            )
            scope_result = "accepted"
        except ValueError:
            scope_result = "rejected"
        await ctx.send(
            self._verifier, f"scribe_auth_attack|scope_escalation|{scope_result}".encode()
        )
        await ctx.send(self._verifier, f"scribe_attack|scope_escalation|{scope_result}".encode())

        revocable_parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
        revoked_child = await auth.delegate(
            revocable_parent,
            audience=AgentId("leaf-0"),
            scopes_subset=["efs.write:/agents/intermediary-0/leaf-0/*"],
            ttl=10.0,
        )
        await auth.revoke(revocable_parent)
        try:
            await auth.verify(revoked_child)
            revoked_result = "accepted"
        except ValueError:
            revoked_result = "rejected"
        await ctx.send(
            self._verifier, f"scribe_auth_attack|revoked_parent|{revoked_result}".encode()
        )
        await ctx.send(self._verifier, f"scribe_attack|revoked_parent|{revoked_result}".encode())

        audience_child = await auth.delegate(
            root,
            audience=AgentId("leaf-0"),
            scopes_subset=["efs.write:/agents/intermediary-0/leaf-0/*"],
            ttl=10.0,
        )
        try:
            await auth.verify_for(audience_child, AgentId("attacker-0"))
            audience_result = "accepted"
        except ValueError:
            audience_result = "rejected"
        await ctx.send(
            self._verifier,
            f"scribe_auth_attack|audience_confusion|{audience_result}".encode(),
        )
        await ctx.send(
            self._verifier,
            f"scribe_attack|audience_confusion|{audience_result}".encode(),
        )


class IntermediaryAgent(StateMachineAgent):
    def __init__(self, agent_id: AgentId, leaves: list[AgentId], verifier: AgentId) -> None:
        self._id = agent_id
        self._leaves = leaves
        self._verifier = verifier

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode()
        if not msg.startswith("delegate|"):
            return
        parent = Token(msg.split("|", 1)[1])
        auth = ctx.plugins["auth"]
        for leaf in self._leaves:
            token = await auth.delegate(
                parent,
                audience=leaf,
                scopes_subset=[
                    f"efs.write:/agents/{self._id}/{leaf}/*",
                    "scribe:publish",
                    "scribe:verify",
                ],
                ttl=50.0,
            )
            await ctx.send(leaf, f"delegate|{token}".encode())
            await ctx.send(self._verifier, f"scribe_delegation|{self._id}|{leaf}".encode())


class LeafAgent(StateMachineAgent):
    def __init__(self, agent_id: AgentId, intermediary: AgentId, scribe: AgentId) -> None:
        self._id = agent_id
        self._intermediary = intermediary
        self._scribe = scribe

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode()
        if not msg.startswith("delegate|"):
            return
        token = Token(msg.split("|", 1)[1])
        await ctx.send(
            self._scribe,
            ("scribe_request|" + self._signed_request(ctx, token)).encode(),
        )
        if self._id == AgentId("leaf-0"):
            await self._send_leaf_attacks(ctx, token)

    async def _send_leaf_attacks(self, ctx: AgentContext, token: Token) -> None:
        good = json.loads(self._signed_request(ctx, token))
        await ctx.send(
            self._scribe,
            ("scribe_attack_request|nonce_replay|" + _canonical(good)).encode(),
        )

        cross_lens = json.loads(
            self._signed_request(
                ctx,
                token,
                path="/agents/intermediary-0/leaf-1/report.json",
                nonce="nonce-leaf-0-cross-lens",
            )
        )
        await ctx.send(
            self._scribe,
            ("scribe_attack_request|cross_lens|" + _canonical(cross_lens)).encode(),
        )

        traversal = json.loads(
            self._signed_request(
                ctx,
                token,
                path="/agents/intermediary-0/leaf-0/../leaf-1/report.json",
                nonce="nonce-leaf-0-traversal",
            )
        )
        await ctx.send(
            self._scribe,
            ("scribe_attack_request|path_traversal|" + _canonical(traversal)).encode(),
        )

        payload_path_mismatch = json.loads(
            self._signed_request(
                ctx,
                token,
                body_path="/agents/intermediary-0/leaf-1/report.json",
                nonce="nonce-leaf-0-payload-path",
            )
        )
        await ctx.send(
            self._scribe,
            (
                "scribe_attack_request|payload_path_mismatch|" + _canonical(payload_path_mismatch)
            ).encode(),
        )

        mismatch = json.loads(
            self._signed_request(ctx, token, force_bad_hash=True, nonce="nonce-leaf-0-bad-hash")
        )
        await ctx.send(
            self._scribe,
            ("scribe_attack_request|payload_hash_mismatch|" + _canonical(mismatch)).encode(),
        )

        wrong_sig = json.loads(self._signed_request(ctx, token, nonce="nonce-leaf-0-wrong-sig"))
        wrong_sig["signature"] = {
            "algorithm": "sim-rsa-sha256",
            "signer": "leaf-1",
            "value": str(good["signature"]["value"]),
        }
        await ctx.send(
            self._scribe,
            ("scribe_attack_request|wrong_signature|" + _canonical(wrong_sig)).encode(),
        )

        mode_confusion = json.loads(
            self._signed_request(ctx, token, mode="sepolia", nonce="nonce-leaf-0-mode")
        )
        await ctx.send(
            self._scribe,
            ("scribe_attack_request|mode_confusion|" + _canonical(mode_confusion)).encode(),
        )

    def _signed_request(
        self,
        ctx: AgentContext,
        token: Token,
        *,
        path: str | None = None,
        body_path: str | None = None,
        force_bad_hash: bool = False,
        mode: str | None = None,
        nonce: str | None = None,
    ) -> str:
        actual_path = path or f"/agents/{self._intermediary}/{self._id}/report.json"
        body = {"ok": True, "path": body_path or actual_path}
        payload = {"agent": str(self._id), "body": body, "schema": "efs-scribe-demo/v1"}
        request: dict[str, Any] = {
            "type": "efs.scribe.request",
            "version": "1",
            "request_id": f"req-{self._id}",
            "op": "file.upsert",
            "agent_id": str(self._id),
            "capability_token": str(token),
            "path": actual_path,
            "payload": payload,
            "payload_hash": "sha256:" + ("0" * 64) if force_bad_hash else _payload_hash(payload),
            "nonce": nonce or f"nonce-{self._id}-1",
            "tick": 3,
        }
        if mode is not None:
            request["mode"] = mode
        sig = ctx.plugins["identity"].sign(_canonical(request).encode())
        request["signature"] = {
            "algorithm": sig.algorithm,
            "signer": str(sig.signer),
            "value": sig.value.hex(),
        }
        return _canonical(request)


class ScribeAgent(StateMachineAgent):
    def __init__(self, verifier: AgentId) -> None:
        self._verifier = verifier
        self._seen_nonces: set[tuple[AgentId, str]] = set()

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode()
        if msg.startswith("scribe_request|"):
            request = json.loads(msg.split("|", 1)[1])
            ok, receipt_or_reason = await self.validate_request(
                ctx, cast("dict[str, Any]", request)
            )
            if ok:
                await ctx.send(self._verifier, ("scribe_receipt|" + receipt_or_reason).encode())
            return
        if msg.startswith("scribe_attack_request|"):
            _, attack, raw = msg.split("|", 2)
            request = json.loads(raw)
            ok, _receipt_or_reason = await self.validate_request(
                ctx, cast("dict[str, Any]", request)
            )
            outcome = "accepted" if ok else "rejected"
            await ctx.send(self._verifier, f"scribe_attack|{attack}|{outcome}".encode())

    async def validate_request(
        self, ctx: AgentContext, request: dict[str, Any]
    ) -> tuple[bool, str]:
        try:
            auth = ctx.plugins["auth"]
            identity = ctx.plugins["identity"]
            if (
                request.get("type") != "efs.scribe.request"
                or request.get("version") != "1"
                or request.get("op") != "file.upsert"
            ):
                return False, "unexpected request envelope"
            agent = AgentId(str(request["agent_id"]))
            auth_ctx = await auth.verify_for(Token(str(request["capability_token"])), agent)
            if request.get("mode", "offline") != "offline":
                return False, "mode confusion"
            if "scribe:publish" not in auth_ctx.scopes:
                return False, "missing publish scope"
            if not _scope_allows(auth_ctx.scopes, str(request["path"])):
                return False, "scope does not cover path"
            path = str(request["path"])
            if not _normalized_path(path):
                return False, "path traversal"
            nonce_obj = request["nonce"]
            if not isinstance(nonce_obj, str) or not nonce_obj:
                return False, "nonce malformed"
            nonce = nonce_obj
            nonce_key = (agent, nonce)
            if nonce_key in self._seen_nonces:
                return False, "nonce replay"
            payload = cast("dict[str, Any]", request["payload"])
            body_obj = payload.get("body")
            if payload.get("agent") != str(agent):
                return False, "payload agent mismatch"
            if not isinstance(body_obj, dict):
                return False, "payload path mismatch"
            body = cast("dict[str, Any]", body_obj)
            if body.get("path") != path:
                return False, "payload path mismatch"
            if request["payload_hash"] != _payload_hash(payload):
                return False, "payload hash mismatch"
            signature = _signature_from_json(cast("dict[str, Any]", request["signature"]))
            signed_payload = _canonical(_without_signature(request)).encode()
            if not identity.verify(signed_payload, signature, agent):
                return False, "bad signature"
            self._seen_nonces.add(nonce_key)
            payload_hash = str(request["payload_hash"])
            receipt: dict[str, Any] = {
                "type": "efs.scribe.verification_receipt",
                "version": "1",
                "request_id": str(request["request_id"]),
                "subject_url": "mock-eas:" + _mock_uid(str(request["request_id"]), payload_hash),
                "ok": True,
                "efs": {
                    "network": "offline",
                    "chain_id": 0,
                    "tx_hashes": [],
                    "data_uid": _mock_uid("data", payload_hash),
                    "path": str(request["path"]),
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
                    "payload_sha256": payload_hash,
                    "canonical_request_sha256": _sha256(_canonical(_without_signature(request))),
                },
                "auth_context": {
                    "subject": str(auth_ctx.subject),
                    "service": "efs-scribe",
                    "scopes": auth_ctx.scopes,
                },
            }
            return True, _canonical(receipt)
        except (KeyError, TypeError, ValueError):
            return False, "invalid request"


class VerifierAgent(StateMachineAgent):
    """Passive sink for trace messages."""


def _agent_ids() -> tuple[AgentId, dict[AgentId, list[AgentId]], AgentId, AgentId]:
    coordinator = AgentId("coordinator-0")
    intermediaries: dict[AgentId, list[AgentId]] = {}
    counter = 0
    for idx in range(3):
        intermediary = AgentId(f"intermediary-{idx}")
        leaves: list[AgentId] = []
        for _ in range(4):
            leaves.append(AgentId(f"leaf-{counter}"))
            counter += 1
        intermediaries[intermediary] = leaves
    return coordinator, intermediaries, AgentId("scribe-0"), AgentId("verifier-0")


def efs_scribe_offline_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the offline EFS Scribe delegation scenario.

    Example::

        agents = efs_scribe_offline_factory(config, plugins)
        assert "scribe-0" in agents
    """
    coordinator, intermediaries, scribe, verifier = _agent_ids()
    all_ids = [coordinator, scribe, verifier, *intermediaries.keys()]
    for leaves in intermediaries.values():
        all_ids.extend(leaves)

    identity_cls = plugins.get("identity")
    identities: dict[AgentId, Any] = {}
    if identity_cls is not None and isinstance(identity_cls, type):
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"efs-scribe-offline")
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)

    auth_cls = plugins.get("auth")
    auth = auth_cls(clock=0.0) if isinstance(auth_cls, type) else auth_cls

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    for aid in all_ids:
        overrides: dict[str, Any] = {"auth": auth}
        if aid in identities:
            overrides["identity"] = identities[aid]
        agent_plugins[aid] = overrides

    agents: dict[AgentId, StateMachineAgent] = {
        coordinator: CoordinatorAgent(intermediaries, verifier),
        scribe: ScribeAgent(verifier),
        verifier: VerifierAgent(),
    }
    for intermediary, leaves in intermediaries.items():
        agents[intermediary] = IntermediaryAgent(intermediary, leaves, verifier)
        for leaf in leaves:
            agents[leaf] = LeafAgent(leaf, intermediary, scribe)
    return agents
