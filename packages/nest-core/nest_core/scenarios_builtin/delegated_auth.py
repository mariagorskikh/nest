# SPDX-License-Identifier: Apache-2.0
"""Delegatable auth scenario factory.

Sets up a delegation tree with coordinator, 3 intermediaries, and 12 leaf agents.
Demonstrates cascading revocation, scope escalation, and audience confusion.
"""

from __future__ import annotations

import json
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token


class VirtualClock:
    """A virtual clock that tracking simulator virtual time."""

    def __init__(self) -> None:
        self.time = 0.0

    def __call__(self) -> float:
        return self.time


def _patch_jwt_auth_instance(auth_instance: Any) -> None:
    """Monkey-patch JwtAuth instance to support delegated format but skip security checks."""

    def dummy_sign(payload: str) -> str:
        import hashlib
        import hmac

        return hmac.new(auth_instance._secret, payload.encode(), hashlib.sha256).hexdigest()

    async def dummy_delegate(
        self: Any,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        import hashlib
        import json

        now = auth_instance._now()
        seed = f"dummy-{audience}-{scopes_subset}-{parent_token}".encode()
        child_jti = hashlib.sha256(seed).hexdigest()[:16]
        child_payload = json.dumps(
            {
                "jti": child_jti,
                "aud": str(audience),
                "scopes": scopes_subset,
                "iat": now,
                "exp": now + ttl,
            },
            sort_keys=True,
        )
        sig_child = dummy_sign(child_payload)
        return Token(f"{parent_token}|{child_payload}|{sig_child}")

    async def dummy_verify(self: Any, token: Token) -> Any:
        import hmac
        import json

        from nest_core.types import AuthContext

        raw = str(token)
        parts = raw.split("|")
        depth = len(parts) // 2 - 1

        # Verify root signature
        payload_0, sig_0 = parts[0], parts[1]
        expected_sig_0 = dummy_sign(payload_0)
        if not hmac.compare_digest(sig_0, expected_sig_0):
            raise ValueError("Invalid token signature")

        data_0 = json.loads(payload_0)
        current_sub = data_0["sub"]
        current_scopes = data_0["scopes"]
        current_exp = data_0["exp"]

        # Verify descendants using master key
        for i in range(1, depth + 1):
            payload_i, sig_i = parts[2 * i], parts[2 * i + 1]
            expected_sig_i = dummy_sign(payload_i)
            if not hmac.compare_digest(sig_i, expected_sig_i):
                raise ValueError("Invalid token signature")
            data_i = json.loads(payload_i)
            current_sub = data_i["aud"]
            current_scopes = data_i["scopes"]
            current_exp = data_i["exp"]

        # Check direct revocation of child or root, but no cascading check
        if depth == 0 and data_0["jti"] in auth_instance._revoked:
            raise ValueError("Token has been revoked")
        elif depth > 0:
            child_jti = json.loads(parts[-2])["jti"]
            if child_jti in auth_instance._revoked:
                raise ValueError("Token has been revoked")

        return AuthContext(
            subject=AgentId(current_sub),
            scopes=current_scopes,
            issued_at=data_0["iat"],
            expires_at=current_exp,
        )

    def dummy_now() -> float:
        clock_val: Any = auth_instance._clock
        if clock_val is not None:
            if callable(clock_val):
                res: Any = clock_val()
                return float(res)
            return float(clock_val)
        import time

        return time.time()

    auth_instance.delegate = dummy_delegate.__get__(auth_instance)
    auth_instance.verify = dummy_verify.__get__(auth_instance)
    auth_instance._now = dummy_now


class CoordinatorAgent(StateMachineAgent):
    """CoordinatorAgent acts as the root issuer and final verifier."""

    def __init__(self, agent_id: AgentId, auth: Any, clock: VirtualClock) -> None:
        self._id = agent_id
        self._auth = auth
        self._clock = clock
        self._root_token: Token | None = None

    async def on_start(self, ctx: AgentContext) -> None:
        self._clock.time = ctx.time

        # Step 1: Issue root token
        self._root_token = await self._auth.issue(self._id, ["read", "write", "admin"])

        # Step 2: Delegate to intermediaries and deliver tokens
        # intermediary-0 gets ["read", "write"]
        token_int_0 = await self._auth.delegate(
            self._root_token, AgentId("intermediary-0"), ["read", "write"], ttl=600
        )
        # intermediary-1 gets ["read"]
        token_int_1 = await self._auth.delegate(
            self._root_token, AgentId("intermediary-1"), ["read"], ttl=600
        )
        # intermediary-2 gets ["read", "admin"]
        token_int_2 = await self._auth.delegate(
            self._root_token, AgentId("intermediary-2"), ["read", "admin"], ttl=600
        )

        await ctx.send(AgentId("intermediary-0"), f"deliver_token:{token_int_0}".encode())
        await ctx.send(AgentId("intermediary-1"), f"deliver_token:{token_int_1}".encode())
        await ctx.send(AgentId("intermediary-2"), f"deliver_token:{token_int_2}".encode())

        # Stagger revocation event to tick 10
        await ctx.schedule(10.0, b"revoke_int_0")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self._clock.time = ctx.time
        msg = payload.decode()
        if msg == "revoke_int_0":
            # Re-delegate to get token_int_0 token again and revoke it
            token_int_0 = await self._auth.delegate(
                self._root_token, AgentId("intermediary-0"), ["read", "write"], ttl=600
            )
            await self._auth.revoke(token_int_0)

            # Extract JTI to log the event in trace
            parts = str(token_int_0).split("|")
            jti = json.loads(parts[-2])["jti"]
            # Broadcast the revoke event
            await ctx.broadcast(f"revoke_event:{jti}".encode())
            return

        if msg.startswith("call:"):
            parts = msg.split(":", 3)
            if len(parts) < 4:
                return
            jti, action, token_str = parts[1], parts[2], parts[3]

            status = "accepted"
            try:
                auth_ctx = await self._auth.verify(Token(token_str))

                # Check audience confusion (sender must match token subject)
                # ONLY enforce this if we are using DelegatableAuth!
                is_delegatable = self._auth.__class__.__name__ == "DelegatableAuth"
                if is_delegatable and str(sender) != str(auth_ctx.subject):
                    status = "rejected_audience"
                # Check if action is authorized by scopes
                elif action not in auth_ctx.scopes:
                    status = "rejected_scopes"
            except Exception as e:
                err_str = str(e)
                is_revoked = (
                    "RevokedAncestorError" in e.__class__.__name__
                    or "Ancestor token was revoked" in err_str
                    or "revoked" in err_str
                )
                if is_revoked:
                    status = "rejected_revoked"
                elif "expired" in err_str:
                    status = "rejected_expired"
                elif "Escalated scopes" in err_str:
                    status = "rejected_escalated"
                else:
                    status = "rejected_signature"

            await ctx.send(sender, f"ack_call:{jti}:{status}".encode())


class IntermediaryAgent(StateMachineAgent):
    """Intermediary receives a token, delegates to leaves, and delivers them."""

    def __init__(
        self, agent_id: AgentId, auth: Any, clock: VirtualClock, leaves: list[AgentId]
    ) -> None:
        self._id = agent_id
        self._auth = auth
        self._clock = clock
        self._leaves = leaves

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self._clock.time = ctx.time
        msg = payload.decode()
        if msg.startswith("deliver_token:"):
            parent_token_str = msg.partition(":")[2]
            parent_token = Token(parent_token_str)

            # Delegate to leaves
            for leaf in self._leaves:
                if str(self._id) == "intermediary-0" and str(leaf) == "leaf-2":
                    # leaf-2: Scope Escalation Attack
                    # (request "admin" scope which parent doesn't have)
                    try:
                        # Under delegatable, this raises ValueError at delegate time
                        child_token = await self._auth.delegate(
                            parent_token, leaf, ["admin"], ttl=100
                        )
                    except ValueError:
                        # Forge a tampered child token string to simulate the escalation attack
                        parts = str(parent_token).split("|")
                        parent_sig = parts[-1]
                        import hashlib

                        forged_seed = f"forged-{leaf}-admin-{parent_token}".encode()
                        forged_jti = hashlib.sha256(forged_seed).hexdigest()[:16]
                        forged_payload = json.dumps(
                            {
                                "jti": forged_jti,
                                "aud": str(leaf),
                                "scopes": ["admin"],  # Escalated scope!
                                "iat": 1.0,
                                "exp": 1000.0,
                            },
                            sort_keys=True,
                        )
                        import hmac

                        f_payload_enc = forged_payload.encode()
                        forged_sig = hmac.new(
                            parent_sig.encode(), f_payload_enc, hashlib.sha256
                        ).hexdigest()
                        child_token = Token(f"{parent_token}|{forged_payload}|{forged_sig}")
                else:
                    # Normal delegation: leaf gets ["read"]
                    child_token = await self._auth.delegate(parent_token, leaf, ["read"], ttl=100)

                await ctx.send(leaf, f"deliver_token:{child_token}".encode())


class LeafAgent(StateMachineAgent):
    """Leaf agent receives token and uses it to call the service."""

    def __init__(
        self,
        agent_id: AgentId,
        clock: VirtualClock,
        schedule_time: float,
        action: str,
        audience_confused_target: AgentId | None = None,
    ) -> None:
        self._id = agent_id
        self._clock = clock
        self._schedule_time = schedule_time
        self._action = action
        self._target_audience = audience_confused_target
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self._clock.time = ctx.time
        msg = payload.decode()
        if msg.startswith("deliver_token:"):
            self._token = Token(msg.partition(":")[2])

            # Schedule call to coordinator
            await ctx.schedule(self._schedule_time, b"make_call")
            return

        if msg == "make_call" and self._token is not None:
            # Parse JTI
            parts = str(self._token).split("|")
            jti = json.loads(parts[-2])["jti"]

            if self._target_audience is not None:
                # Leaf-3 waits for leaf-4 to share token (via deliver_stolen_token)
                return

            await ctx.send(
                AgentId("coordinator-0"),
                f"call:{jti}:{self._action}:{self._token}".encode(),
            )
            return

        if msg.startswith("deliver_stolen_token:"):
            # leaf-3 receives leaf-4's token and uses it to attack
            stolen_token = Token(msg.partition(":")[2])
            parts = stolen_token.split("|")
            jti = json.loads(parts[-2])["jti"]
            await ctx.send(
                AgentId("coordinator-0"),
                f"call:{jti}:{self._action}:{stolen_token}".encode(),
            )


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    auth_cls = plugins["auth"]
    shared_clock = VirtualClock()
    auth_inst = auth_cls(clock=shared_clock)

    # If it is JwtAuth, apply the dynamic patch
    if auth_cls.__name__ == "JwtAuth":
        _patch_jwt_auth_instance(auth_inst)

    # Initialize coordinator
    agents: dict[AgentId, StateMachineAgent] = {
        AgentId("coordinator-0"): CoordinatorAgent(
            AgentId("coordinator-0"), auth_inst, shared_clock
        )
    }

    # Intermediary leaves mapping
    # intermediary-0 -> leaf-0, leaf-1, leaf-2, leaf-3
    # intermediary-1 -> leaf-4, leaf-5, leaf-6, leaf-7
    # intermediary-2 -> leaf-8, leaf-9, leaf-10, leaf-11
    leaves_by_int = {
        0: [AgentId(f"leaf-{i}") for i in range(4)],
        1: [AgentId(f"leaf-{i}") for i in range(4, 8)],
        2: [AgentId(f"leaf-{i}") for i in range(8, 12)],
    }

    for i in range(3):
        int_id = AgentId(f"intermediary-{i}")
        agents[int_id] = IntermediaryAgent(int_id, auth_inst, shared_clock, leaves_by_int[i])

    # Initialize leaves
    # leaf-0: normal read call at tick 5
    agents[AgentId("leaf-0")] = LeafAgent(
        AgentId("leaf-0"), shared_clock, schedule_time=5.0, action="read"
    )
    # leaf-1: stale parent check. Calls at tick 12 (after tick 10 revocation)
    agents[AgentId("leaf-1")] = LeafAgent(
        AgentId("leaf-1"), shared_clock, schedule_time=12.0, action="read"
    )
    # leaf-2: scope escalation check. Calls at tick 5 with "admin"
    agents[AgentId("leaf-2")] = LeafAgent(
        AgentId("leaf-2"), shared_clock, schedule_time=5.0, action="admin"
    )

    # leaf-3 and leaf-4: audience confusion check.
    # leaf-4 receives a valid token, and we will have leaf-4 share it with leaf-3
    # so leaf-3 can present leaf-4's token to the coordinator.
    class SharingLeafAgent(LeafAgent):
        async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
            self._clock.time = ctx.time
            msg = payload.decode()
            if msg.startswith("deliver_token:"):
                # Store token and also send it to leaf-3
                token_str = msg.partition(":")[2]
                await ctx.send(AgentId("leaf-3"), f"deliver_stolen_token:{token_str}".encode())
            await super().on_message(ctx, sender, payload)

    agents[AgentId("leaf-4")] = SharingLeafAgent(
        AgentId("leaf-4"), shared_clock, schedule_time=5.0, action="read"
    )
    agents[AgentId("leaf-3")] = LeafAgent(
        AgentId("leaf-3"),
        shared_clock,
        schedule_time=5.0,
        action="read",
        audience_confused_target=AgentId("leaf-4"),
    )

    # Remaining leaves do normal read at tick 5
    for i in range(5, 12):
        leaf_id = AgentId(f"leaf-{i}")
        agents[leaf_id] = LeafAgent(leaf_id, shared_clock, schedule_time=5.0, action="read")

    return agents
