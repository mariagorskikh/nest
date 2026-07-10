# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegation adversarial validators.

Synthetic audit streams model the two plugins' behaviour: the
``jwt``-shaped stream (attacks succeed) must FAIL all three checks and
the ``delegatable``-shaped stream (attacks refused) must PASS them —
the charter's bar for an adversarial validator.  An end-to-end test
also drives the real scenario agents under both auth plugins.
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_plugins_reference.validators.delegation_validators import (
    AuditEvent,
    check_audience_binding,
    check_no_scope_escalation,
    check_no_stale_ancestor_use,
    extract_delegation_audits,
)


def _jwt_shaped_audits() -> list[AuditEvent]:
    """Audits as they come out of the scenario under ``auth: jwt``."""
    return [
        {
            "type": "delegation_audit",
            "tick": 3,
            "op": "delegate",
            "delegator": "intermediary-2",
            "audience": "leaf-8",
            "parent_scopes": ["read", "write"],
            "child_scopes": ["read", "admin"],
            "granted": True,
        },
        {
            "type": "delegation_audit",
            "tick": 20,
            "op": "revoke",
            "tid": "aa11",
            "target": "intermediary-1",
        },
        {
            "type": "delegation_audit",
            "tick": 25,
            "op": "verify",
            "presenter": "leaf-4",
            "audience": "leaf-4",
            "chain_tids": ["root0", "aa11", "bb22"],
            "verified": True,
        },
        {
            "type": "delegation_audit",
            "tick": 5,
            "op": "verify",
            "presenter": "leaf-1",
            "audience": "leaf-0",
            "chain_tids": ["root0", "cc33", "dd44"],
            "verified": True,
        },
    ]


def _delegatable_shaped_audits() -> list[AuditEvent]:
    """Audits as they come out of the scenario under ``auth: delegatable``."""
    return [
        {
            "type": "delegation_audit",
            "tick": 3,
            "op": "delegate",
            "delegator": "intermediary-2",
            "audience": "leaf-8",
            "parent_scopes": ["read", "write"],
            "child_scopes": ["read", "admin"],
            "granted": False,
        },
        {
            "type": "delegation_audit",
            "tick": 20,
            "op": "revoke",
            "tid": "aa11",
            "target": "intermediary-1",
        },
        {
            "type": "delegation_audit",
            "tick": 25,
            "op": "verify",
            "presenter": "leaf-4",
            "audience": "leaf-4",
            "chain_tids": ["root0", "aa11", "bb22"],
            "verified": False,
        },
        {
            "type": "delegation_audit",
            "tick": 15,
            "op": "verify",
            "presenter": "leaf-4",
            "audience": "leaf-4",
            "chain_tids": ["root0", "aa11", "bb22"],
            "verified": True,
        },
        {
            "type": "delegation_audit",
            "tick": 5,
            "op": "verify",
            "presenter": "leaf-1",
            "audience": "leaf-0",
            "chain_tids": ["root0", "cc33", "dd44"],
            "verified": False,
        },
    ]


def test_validators_fail_against_jwt_shaped_trace() -> None:
    audits = _jwt_shaped_audits()
    assert not check_no_scope_escalation(audits).passed
    assert not check_no_stale_ancestor_use(audits).passed
    assert not check_audience_binding(audits).passed


def test_validators_pass_against_delegatable_shaped_trace() -> None:
    audits = _delegatable_shaped_audits()
    assert check_no_scope_escalation(audits).passed
    assert check_no_stale_ancestor_use(audits).passed
    assert check_audience_binding(audits).passed


def test_verify_before_revocation_is_legitimate() -> None:
    audits = _delegatable_shaped_audits()
    report = check_no_stale_ancestor_use(audits)
    assert report.passed, "pre-revocation verification must not be flagged"


def test_extract_from_raw_trace_events() -> None:
    raw: list[dict[str, Any]] = [
        {"msg": json.dumps(_jwt_shaped_audits()[0])},
        {"msg": "not json"},
        {"msg": json.dumps({"type": "other"})},
        {"no_msg": True},
    ]
    audits = extract_delegation_audits(raw)
    assert len(audits) == 1
    assert audits[0]["op"] == "delegate"


def test_end_to_end_scenario_agents_under_both_plugins() -> None:
    """Drive the real scenario agents in-process under both auth plugins.

    A minimal in-memory harness delivers messages and scheduled
    callbacks in deterministic tick order, collects the audit stream,
    and asserts the validator verdicts flip between plugins.
    """
    import asyncio
    import heapq
    import itertools

    from nest_core.scenario import RoleConfig, ScenarioConfig, TaskConfig
    from nest_core.scenarios_builtin.delegated_auth import delegated_auth_factory
    from nest_core.types import AgentId
    from nest_plugins_reference.auth.delegatable import DelegatableAuth
    from nest_plugins_reference.auth.jwt_auth import JwtAuth

    class _Ctx:
        def __init__(self, agent_id: AgentId, harness: _Harness) -> None:
            self._agent_id = agent_id
            self._harness = harness

        @property
        def agent_id(self) -> AgentId:
            return self._agent_id

        @property
        def time(self) -> float:
            return self._harness.now

        @property
        def plugins(self) -> dict[str, Any]:
            return {}

        async def send(self, to: AgentId, payload: bytes) -> None:
            self._harness.push(self._harness.now, self._agent_id, to, payload)

        async def broadcast(self, payload: bytes) -> None:  # pragma: no cover
            for aid in self._harness.agents:
                await self.send(aid, payload)

        async def schedule(self, delay: float, payload: bytes) -> None:
            self._harness.push(self._harness.now + delay, self._agent_id, self._agent_id, payload)

    class _Harness:
        def __init__(self, agents: dict[AgentId, Any]) -> None:
            self.agents = agents
            self.now: float = 0.0
            self._seq = itertools.count()
            self._queue: list[tuple[float, int, AgentId, AgentId, bytes]] = []

        def push(self, at: float, sender: AgentId, to: AgentId, payload: bytes) -> None:
            heapq.heappush(self._queue, (at, next(self._seq), sender, to, payload))

        def run(self, until: float) -> list[AuditEvent]:
            async def _run() -> list[AuditEvent]:
                audits: list[AuditEvent] = []
                for aid, agent in self.agents.items():
                    await agent.on_start(_Ctx(aid, self))
                while self._queue and self._queue[0][0] <= until:
                    at, _, sender, to, payload = heapq.heappop(self._queue)
                    self.now = at
                    loaded: object = json.loads(payload.decode())
                    if isinstance(loaded, dict):
                        data = cast("AuditEvent", loaded)
                        if data.get("type") == "delegation_audit":
                            audits.append(data)
                            continue
                    agent = self.agents.get(to)
                    if agent is not None:
                        await agent.on_message(_Ctx(to, self), sender, payload)
                return audits

            return asyncio.run(_run())

    def _run_scenario(auth_cls: type) -> list[AuditEvent]:
        config = ScenarioConfig(
            name="delegated_auth",
            task=TaskConfig(
                type="delegated_auth",
                config={"revoke_tick": 20, "presents": 4, "present_interval": 10},
            ),
        )
        config.agents.roles = [
            RoleConfig(name="coordinator", count=1),
            RoleConfig(name="intermediary", count=3),
            RoleConfig(name="leaf", count=12),
        ]
        agents = delegated_auth_factory(config, {"auth": auth_cls})
        return _Harness(dict(agents)).run(until=100.0)

    jwt_audits = _run_scenario(JwtAuth)
    assert not check_no_scope_escalation(jwt_audits).passed
    assert not check_no_stale_ancestor_use(jwt_audits).passed
    assert not check_audience_binding(jwt_audits).passed

    good_audits = _run_scenario(DelegatableAuth)
    assert check_no_scope_escalation(good_audits).passed
    assert check_no_stale_ancestor_use(good_audits).passed
    assert check_audience_binding(good_audits).passed
