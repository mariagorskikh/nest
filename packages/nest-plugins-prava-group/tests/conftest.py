# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures. Every test here runs with no network and no keys.

Example::

    def test_something(fresh_state): ...
"""

from __future__ import annotations

from typing import Any

import pytest
from nanda_town_prava import reset_shared_state
from nanda_town_prava._simulator import SimulatedEngine
from nanda_town_prava.client import EngineTransportError

JsonDict = dict[str, Any]


@pytest.fixture(autouse=True)
def fresh_state() -> Any:
    """Drop the process-wide engine cache around every test."""
    reset_shared_state()
    yield
    reset_shared_state()


@pytest.fixture(autouse=True)
def no_ambient_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test may accidentally pick up a real engine or a real token."""
    for name in (
        "NANDA_PRAVA_MODE",
        "GMP_API",
        "ENGINE_API_TOKEN",
        "NANDA_PRAVA_AUTO_APPROVE_MOCK",
        "NANDA_PRAVA_AWAIT_SECONDS",
        "NANDA_PRAVA_TOLERANCE_BPS",
        "NANDA_PRAVA_CURRENCY",
        "NANDA_PRAVA_CREDIT_MINOR_UNITS",
    ):
        monkeypatch.delenv(name, raising=False)


class RailOverrideEngine(SimulatedEngine):
    """A simulator that forces a settlement rail, whatever the plugin asked for.

    Models an engine that downgraded to ``at_venue`` because the merchant is
    not reachable — the case where a receipt describes an agreement rather
    than a charge.

    Example::

        engine = RailOverrideEngine(rail="at_venue")
    """

    def __init__(self, *, rail: str) -> None:
        super().__init__()
        self._forced_rail = rail

    async def create_group(self, body: JsonDict) -> JsonDict:
        return await super().create_group({**body, "rail": self._forced_rail})


class StatusOverrideEngine(SimulatedEngine):
    """A simulator that reports a group status the plugin has never heard of.

    Example::

        engine = StatusOverrideEngine(status="quantum_superposition")
    """

    def __init__(self, *, status: str, member_status: str | None = None) -> None:
        super().__init__()
        self._forced_status = status
        self._forced_member_status = member_status

    async def get_group(self, group_id: str) -> JsonDict:
        view = await super().get_group(group_id)
        view["status"] = self._forced_status
        if self._forced_member_status is not None:
            for member in view["members"]:
                member["status"] = self._forced_member_status
        return view


class NoReceiptEngine(SimulatedEngine):
    """Terminal groups, but the signed receipt is never available.

    Example::

        engine = NoReceiptEngine()
    """

    async def get_receipt(self, group_id: str) -> JsonDict | None:
        return None


class UnreachableEngine(SimulatedEngine):
    """Reachable long enough to authorize, then gone.

    Example::

        engine = UnreachableEngine()
        engine.go_dark()
    """

    def __init__(self) -> None:
        super().__init__()
        self._dark = False

    def go_dark(self) -> None:
        self._dark = True

    async def get_group(self, group_id: str) -> JsonDict:
        if self._dark:
            msg = "GET /v1/groups did not complete: connection refused"
            raise EngineTransportError(msg)
        return await super().get_group(group_id)


class HostileEngine(SimulatedEngine):
    """An engine that tries to hand the plugin secret material.

    Example::

        engine = HostileEngine()
    """

    async def get_group(self, group_id: str) -> JsonDict:
        view = await super().get_group(group_id)
        view["api_key"] = "sk_" + "live_totally_real_key"
        view["debug"] = {"authorization": "Bearer abcdef123456", "wallet_secret": "hunter2"}
        return view


class RequotingEngine:
    """An engine that runs a GMP/1 requote cascade, like the real one does.

    ``_simulator.py`` deliberately does not implement requote rounds, so this
    path was invisible until ``live`` mode was pointed at the deployed engine
    and the group stalled forever in ``collecting`` — see
    ``docs/NANDA-EVIDENCE.md``. This is the regression test's engine.

    The cascade it models is the real one (GMP/1 §4.1): a quorum locks a
    subset, the unlocked member is dropped, the remaining shares are
    recomputed **upward**, the new share exceeds the cap the survivors
    already consented to, so their mandates are cancelled and they are put
    back to ``viewed`` at a larger cap. Nothing moves again until fresh
    sessions are minted and approved.

    Three members, ``quorum(2)``, a cart of 100: shares 33 / caps 35, then
    50 / 53 for the two survivors after the third is dropped.

    Example::

        engine = RequotingEngine()
    """

    QUORUM = 2

    def __init__(self) -> None:
        self._members: list[dict[str, Any]] = []
        self._status = "collecting"
        self._approved: set[str] = set()
        self._round = 0
        self.opens: list[str] = []

    async def create_group(self, body: JsonDict) -> JsonDict:
        for index, raw in enumerate(body["members"]):
            self._members.append(
                {
                    "member_id": f"mi_{index}",
                    "name": str(raw["name"]),
                    "role": str(raw.get("role", "payer")),
                    "status": "invited",
                    "share_amount": 33,
                    "cap_amount": 35,
                    "charged_amount": 0,
                    "requote_round": 0,
                }
            )
        return {
            "group_id": "g_requote",
            "board_url": "https://example.test/board",
            "members": [
                {"member_id": m["member_id"], "name": m["name"], "role": m["role"]}
                for m in self._members
            ],
        }

    async def get_group(self, group_id: str) -> JsonDict:
        return {
            "group_id": group_id,
            "status": self._status,
            "members": [dict(m) for m in self._members],
        }

    async def cancel_group(self, group_id: str) -> JsonDict:
        self._status = "aborted"
        return await self.get_group(group_id)

    async def open_member(self, member_id: str) -> JsonDict:
        member = self._member(member_id)
        # The real engine mints a session only from `invited` or `viewed`.
        # Opening a dropped or already-charged member is a no-op that returns
        # no approval URL — the plugin must not publish one it cannot use.
        if member["status"] not in ("invited", "viewed"):
            return dict(member)
        self.opens.append(member_id)
        member["status"] = "awaiting_approval"
        return {
            "member_id": member_id,
            "name": member["name"],
            "approval_url": f"https://example.test/mock/pay/sess_{member_id}_r{self._round}",
        }

    async def get_member(self, member_id: str) -> JsonDict:
        return dict(self._member(member_id))

    async def approve_member(self, member_id: str) -> bool:
        member = self._member(member_id)
        if member["status"] != "awaiting_approval":
            return False
        member["status"] = "approved"
        self._approved.add(member_id)
        self._decide()
        return True

    async def get_receipt(self, group_id: str) -> JsonDict | None:
        if self._status != "committed":
            return None
        charged = sum(m["charged_amount"] for m in self._members)
        return {
            "rail": "prava_mandates",
            "totals": {"quoted": 100, "charged": charged, "owed": 100},
            "entries": [
                {
                    "name": m["name"],
                    "mandate_id": f"mdt_{m['member_id']}",
                    "charge_txn_id": f"txn_{m['member_id']}",
                    "charged_amount": m["charged_amount"],
                }
                for m in self._members
                if m["charged_amount"]
            ],
        }

    # -- the cascade ---------------------------------------------------------

    def _decide(self) -> None:
        if len(self._approved) < self.QUORUM:
            return
        locked = set(self._approved)
        if self._round == 0:
            # The quorum locks the approvers and drops everyone else. The
            # survivors now owe more than the cap they consented to, so their
            # consent is cancelled and re-requested at the new number.
            for member in self._members:
                if member["member_id"] in locked:
                    member.update(status="viewed", share_amount=50, cap_amount=53, requote_round=1)
                else:
                    member.update(status="dropped")
            self._approved.clear()
            self._round = 1
            return
        # Round 1: the fresh mandates cover the new shares. Commit.
        for member in self._members:
            if member["member_id"] in locked:
                member.update(status="charged", charged_amount=50)
        self._status = "committed"

    def _member(self, member_id: str) -> dict[str, Any]:
        for member in self._members:
            if member["member_id"] == member_id:
                return member
        msg = f"no such member: {member_id}"
        raise KeyError(msg)
