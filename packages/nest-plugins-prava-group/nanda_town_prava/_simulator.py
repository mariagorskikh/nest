# SPDX-License-Identifier: Apache-2.0
"""An in-process GMP/1 engine, for ``mode="simulated"``.

This is not a stub that returns canned dicts. It runs the parts of the
protocol the plugin depends on — share allocation by largest remainder,
tolerance-derived caps, commit-policy evaluation, per-member mandate
sessions, the hosted-ceremony approval flip, commit with ``charge =
min(share, cap)``, pre-commit cancellation, and the signed-shaped
receipt — and it emits the exact JSON shapes that
``engine/src/routes.ts`` emits, so ``plugin.py`` cannot tell it apart
from the real thing.

Why it exists: the real engine's ``PRAVA_ENV=mock`` mode still needs a
Node process listening on a port. ``nest run`` has no such process, and
neither does CI. This gives the plugin a zero-network, zero-key default
so ``nest run bench.yaml`` works the moment the package is installed.

What it deliberately does NOT do: pretend to be a card network. Nothing
in here touches money. It models the *coordination*, and every amount it
reports as charged is labelled ``simulated`` all the way out to the
receipt's settlement disclosure.

Example::

    engine = SimulatedEngine()
    created = await engine.create_group({...})
    await engine.approve_member(created["members"][0]["member_id"])
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Incoming GMP payloads are JSON dictionaries whose nested values are only
# narrowed while the simulator validates and materializes them.
# pyright: reportUnknownVariableType=false

JsonDict = dict[str, Any]

_PAYING_ROLES = frozenset({"payer", "sponsor", "backstop"})
_GROUP_TERMINAL = frozenset({"committed", "partial", "aborted", "expired"})

SIMULATED_DISCLOSURE = (
    "SIMULATED. No card was charged and no money moved. This receipt was produced by the "
    "in-process GMP/1 simulator so the plugin can run with no network and no keys. Amounts "
    "shown as charged are what the card network would have been asked to authorize."
)


@dataclass
class _Member:
    id: str
    group_id: str
    name: str
    role: str
    weight: int
    share_amount: int
    cap_amount: int
    backstop_cap: int = 0
    status: str = "invited"
    session_id: str | None = None
    approval_url: str | None = None
    mandate_id: str | None = None
    charge_txn_id: str | None = None
    charged_amount: int = 0
    failure_reason: str | None = None


@dataclass
class _Group:
    id: str
    title: str
    merchant: JsonDict
    cart: JsonDict
    cart_hash: str
    currency: str
    policy: JsonDict
    tolerance_bps: int
    rail: str
    total: int
    status: str = "collecting"
    decision_note: str | None = None
    members: list[_Member] = field(default_factory=list)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def cart_total(cart: JsonDict) -> int:
    """Sum a GMP/1 cart in integer minor units.

    Example::

        cart_total({"items": [{"unit_amount": 100, "qty": 2}], "fees": []})  # 200
    """
    items = sum(int(i.get("unit_amount", 0)) * int(i.get("qty", 1)) for i in cart.get("items", []))
    fees = sum(int(f.get("amount", 0)) for f in cart.get("fees", []))
    return items + fees


def allocate_shares(total: int, weights: list[int]) -> list[int]:
    """Split *total* across *weights* by largest remainder. Sums exactly.

    Integer minor units throughout — the one arithmetic rule that keeps a
    split from quietly inventing or destroying a cent.

    Example::

        allocate_shares(100, [1, 1, 1])  # [34, 33, 33]
    """
    if not weights:
        return []
    weight_sum = sum(weights)
    if weight_sum <= 0:
        return [0] * len(weights)
    exact = [total * w / weight_sum for w in weights]
    floors = [math.floor(v) for v in exact]
    remainder = total - sum(floors)
    order = sorted(range(len(weights)), key=lambda i: (-(exact[i] - floors[i]), i))
    for idx in order[:remainder]:
        floors[idx] += 1
    return floors


def cap_for(share: int, tolerance_bps: int) -> int:
    """cap = share x (1 + tolerance_bps/10^4), rounded up (GMP/1 §1).

    Example::

        cap_for(1000, 500)  # 1050
    """
    return share + math.ceil(share * tolerance_bps / 10_000)


def evaluate_policy(policy: JsonDict, members: list[_Member]) -> str:
    """Return ``satisfied`` | ``open`` | ``unsatisfiable`` (GMP/1 §4).

    Example::

        evaluate_policy({"type": "all_of"}, members)
    """
    paying = [m for m in members if m.role in _PAYING_ROLES and m.role != "backstop"]
    approved = [m for m in paying if m.status in ("approved", "charging", "charged")]
    pending = [m for m in paying if m.status in ("invited", "viewed", "awaiting_approval")]
    kind = policy.get("type", "all_of")

    if kind == "all_of":
        # Anyone who has left the set for good makes `all_of` unreachable,
        # even while others are still deciding.
        if len(approved) + len(pending) < len(paying):
            return "unsatisfiable"
        if paying and len(approved) == len(paying):
            return "satisfied"
        return "open" if pending else "unsatisfiable"

    if kind == "quorum":
        need = int(policy.get("m", len(paying)))
        if len(approved) >= need:
            return "satisfied"
        return "open" if len(approved) + len(pending) >= need else "unsatisfiable"

    if kind == "weighted":
        threshold = int(policy.get("threshold", 0))
        have = sum(m.weight for m in approved)
        if have >= threshold:
            return "satisfied"
        possible = have + sum(m.weight for m in pending)
        return "open" if possible >= threshold else "unsatisfiable"

    if kind in ("required", "veto"):
        named = policy.get("member")
        target = next((m for m in paying if m.name == named), None)
        inner = policy.get("inner", {"type": "all_of"})
        if target is None:
            return "unsatisfiable"
        if kind == "required" and target.status in ("declined", "expired", "dropped"):
            return "unsatisfiable"
        if kind == "veto" and target.status == "declined":
            return "unsatisfiable"
        if kind == "required" and target.status not in ("approved", "charging", "charged"):
            return "open"
        return evaluate_policy(inner, members)

    # An unrecognised policy is not quietly treated as `all_of`. Guessing at
    # a commit rule is precisely the class of bug that charges the wrong
    # people, so the simulator refuses instead.
    msg = f"simulator does not implement commit policy {kind!r}"
    raise NotImplementedError(msg)


class SimulatedEngine:
    """In-process GMP/1 engine speaking the real REST payloads.

    Example::

        engine = SimulatedEngine()
        created = await engine.create_group(body)
    """

    def __init__(self, *, app_base_url: str = "sim+gmp://engine") -> None:
        self._app_base_url = app_base_url.rstrip("/")
        self._groups: dict[str, _Group] = {}
        self._members: dict[str, _Member] = {}
        self._ids = itertools.count(1)

    def _next(self, prefix: str) -> str:
        return f"{prefix}_{next(self._ids):06d}"

    # -- transport surface (mirrors GmpHttpClient) ---------------------------

    async def create_group(self, body: JsonDict) -> JsonDict:
        """``POST /v1/groups``."""
        cart: JsonDict = body["cart"]
        currency = str(cart.get("currency", "USD"))
        total = cart_total(cart)
        tolerance_bps = int(body.get("tolerance_bps", 500))
        rail = str(body.get("rail") or "prava_mandates")
        group_id = self._next("g")

        raw_members: list[JsonDict] = list(body["members"])
        paying_idx = [
            i
            for i, m in enumerate(raw_members)
            if str(m.get("role", "payer")) in _PAYING_ROLES
            and str(m.get("role", "payer")) != "backstop"
        ]
        weights = [int(raw_members[i].get("weight", 1)) for i in paying_idx]
        shares = allocate_shares(total, weights)
        share_by_index = dict(zip(paying_idx, shares, strict=True))

        members: list[_Member] = []
        for i, raw in enumerate(raw_members):
            role = str(raw.get("role", "payer"))
            share = share_by_index.get(i, 0)
            member = _Member(
                id=self._next("mi"),
                group_id=group_id,
                name=str(raw["name"]),
                role=role,
                weight=int(raw.get("weight", 1)),
                share_amount=share,
                cap_amount=cap_for(share, tolerance_bps),
                backstop_cap=int(raw.get("backstop_cap") or 0),
            )
            members.append(member)
            self._members[member.id] = member

        group = _Group(
            id=group_id,
            title=str(body.get("title", "")),
            merchant=dict(body.get("merchant", {})),
            cart=cart,
            cart_hash=hashlib.sha256(
                json.dumps(cart, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            currency=currency,
            policy=dict(body.get("policy") or {"type": "all_of"}),
            tolerance_bps=tolerance_bps,
            rail=rail,
            total=total,
            members=members,
        )
        self._groups[group_id] = group

        return {
            "group_id": group_id,
            "board_url": f"{self._app_base_url}/g/{group_id}/board",
            "members": [
                {
                    "member_id": m.id,
                    "name": m.name,
                    "role": m.role,
                    "share_amount": m.share_amount,
                    "approval_page_url": f"{self._app_base_url}/a/{m.id}",
                }
                for m in members
            ],
        }

    async def get_group(self, group_id: str) -> JsonDict:
        """``GET /v1/groups/{id}``."""
        return self._group_view(self._must_group(group_id))

    async def cancel_group(self, group_id: str) -> JsonDict:
        """``POST /v1/groups/{id}/cancel`` — pre-commit only."""
        group = self._must_group(group_id)
        if group.status in _GROUP_TERMINAL:
            msg = f"group {group_id} is already {group.status}"
            raise ValueError(msg)
        for member in group.members:
            if member.status != "charged":
                # Cancelling the mandate is what makes this a void and not a
                # refund: the authorization is released before any capture.
                member.mandate_id = None
                member.session_id = None
                member.approval_url = None
                member.status = "dropped"
        group.status = "aborted"
        group.decision_note = "cancelled by organizer before commit"
        return self._group_view(group)

    async def open_member(self, member_id: str) -> JsonDict:
        """``POST /v1/members/{id}/open`` — mints this member's mandate session."""
        member = self._must_member(member_id)
        group = self._must_group(member.group_id)
        if member.status == "invited":
            member.status = "viewed"
        if group.status in _GROUP_TERMINAL or member.role not in _PAYING_ROLES:
            return self._member_view(member)
        if group.rail != "prava_mandates":
            # No merchant to scope a mandate to, so there is nothing to mint
            # and no ceremony to send anyone to (engine/src/rails.ts).
            if member.status == "viewed" and member.share_amount > 0:
                member.status = "awaiting_approval"
            return self._member_view(member)
        if member.status in ("viewed", "awaiting_approval") and member.session_id is None:
            member.session_id = self._next("sess")
            member.approval_url = f"sim+prava://ceremony/{member.session_id}"
            member.status = "awaiting_approval"
        return self._member_view(member)

    async def get_member(self, member_id: str) -> JsonDict:
        """``GET /v1/members/{id}``."""
        return self._member_view(self._must_member(member_id))

    async def approve_member(self, member_id: str) -> bool:
        """Stand in for the member's passkey tap on the hosted ceremony."""
        member = self._must_member(member_id)
        group = self._must_group(member.group_id)
        if group.status in _GROUP_TERMINAL:
            return False
        if member.status != "awaiting_approval":
            await self.open_member(member_id)
            member = self._must_member(member_id)
        if member.status != "awaiting_approval":
            return False
        if group.rail == "prava_mandates":
            member.mandate_id = self._next("md")
        member.status = "approved"
        self._decide(group)
        return True

    async def decline_member(self, member_id: str) -> JsonDict:
        """``POST /v1/members/{id}/decline``."""
        member = self._must_member(member_id)
        group = self._must_group(member.group_id)
        if group.status not in _GROUP_TERMINAL:
            member.status = "declined"
            member.mandate_id = None
            self._decide(group)
        return self._member_view(member)

    async def get_receipt(self, group_id: str) -> JsonDict | None:
        """``GET /v1/groups/{id}/receipt`` — ``None`` until the group is terminal."""
        group = self._must_group(group_id)
        if group.status not in _GROUP_TERMINAL:
            return None
        entries: list[JsonDict] = []
        prev = "0" * 64
        for member in group.members:
            entry = {
                "kind": "consent",
                "member_id": member.id,
                "name": member.name,
                "role": member.role,
                "cart_hash": group.cart_hash,
                "cap_amount": member.cap_amount,
                "quoted_share": member.share_amount,
                "charged_amount": member.charged_amount,
                "owed_amount": member.share_amount,
                "mandate_id": member.mandate_id,
                "charge_txn_id": member.charge_txn_id,
                "outcome": member.status,
                "prev_hash": prev,
            }
            digest = hashlib.sha256(
                json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            entry["hash"] = digest
            prev = digest
            entries.append(entry)
        return {
            "gmp_version": "GMP/1",
            "group_id": group.id,
            "title": group.title,
            "merchant": group.merchant,
            "currency": group.currency,
            "cart_hash": group.cart_hash,
            "policy": group.policy,
            "decision_narrative": group.decision_note or "",
            "status": group.status,
            "rail": group.rail,
            "settlement_disclosure": SIMULATED_DISCLOSURE,
            "simulated": True,
            "totals": {
                "quoted": sum(m.share_amount for m in group.members),
                "charged": sum(m.charged_amount for m in group.members),
                "owed": sum(m.share_amount for m in group.members),
            },
            "entries": entries,
            "chain_head": prev,
            "issued_at": _now(),
        }

    # -- decision + commit ---------------------------------------------------

    def _decide(self, group: _Group) -> None:
        if group.status in _GROUP_TERMINAL:
            return
        verdict = evaluate_policy(group.policy, group.members)
        if verdict == "open":
            return
        if verdict == "unsatisfiable":
            for member in group.members:
                if member.status != "charged":
                    member.mandate_id = None
                    if member.status != "declined":
                        member.status = "dropped"
            group.status = "aborted"
            group.decision_note = "policy became unsatisfiable — no card was charged"
            return
        self._commit(group)

    def _commit(self, group: _Group) -> None:
        group.status = "committing"
        locked = [
            m
            for m in group.members
            if m.status == "approved" and m.role in _PAYING_ROLES and m.role != "backstop"
        ]
        # Re-pro-rate over the locked set: dropped members' shares do not
        # vanish, they redistribute (GMP/1 §4.1). Anyone not locked owes
        # nothing, so the receipt's `owed` total stays truthful.
        for member in group.members:
            if member not in locked and member.status != "charged":
                member.share_amount = 0
        shares = allocate_shares(group.total, [m.weight for m in locked])
        charged_any = False
        for member, target in zip(locked, shares, strict=True):
            if group.rail != "prava_mandates":
                # Nothing is charged on this rail. `settled` is not `charged`,
                # and the receipt must never conflate them.
                member.share_amount = target
                member.status = "settled"
                continue
            # Consent cannot stretch: the cap the member passkey-approved is a
            # hard ceiling, enforced at the network in production.
            amount = min(target, member.cap_amount)
            member.share_amount = target
            member.status = "charged"
            member.charged_amount = amount
            member.charge_txn_id = self._next("txn")
            charged_any = True

        shortfall = group.total - sum(m.charged_amount for m in locked)
        if group.rail == "prava_mandates" and shortfall > 0:
            for backstop in group.members:
                if backstop.role != "backstop" or backstop.status != "approved":
                    continue
                absorbed = min(shortfall, backstop.backstop_cap)
                if absorbed <= 0:
                    continue
                backstop.status = "charged"
                backstop.charged_amount = absorbed
                backstop.charge_txn_id = self._next("txn")
                shortfall -= absorbed
                charged_any = True

        dropped = [m for m in group.members if m.status in ("declined", "dropped", "expired")]
        group.status = "partial" if (dropped and charged_any and shortfall > 0) else "committed"
        group.decision_note = (
            f"policy satisfied; {len(locked)} principal(s) charged on their own cards"
        )

    # -- views ---------------------------------------------------------------

    def _must_group(self, group_id: str) -> _Group:
        group = self._groups.get(group_id)
        if group is None:
            msg = f"no such group: {group_id}"
            raise KeyError(msg)
        return group

    def _must_member(self, member_id: str) -> _Member:
        member = self._members.get(member_id)
        if member is None:
            msg = f"no such member: {member_id}"
            raise KeyError(msg)
        return member

    def _group_view(self, group: _Group) -> JsonDict:
        return {
            "group_id": group.id,
            "title": group.title,
            "status": group.status,
            "merchant": group.merchant,
            "cart": group.cart,
            "cart_hash": group.cart_hash,
            "total": group.total,
            "currency": group.currency,
            "policy": group.policy,
            "tolerance_bps": group.tolerance_bps,
            "decision_note": group.decision_note,
            "terminal": group.status in _GROUP_TERMINAL,
            "members": [
                {
                    "member_id": m.id,
                    "name": m.name,
                    "role": m.role,
                    "status": m.status,
                    "share_amount": m.share_amount,
                    "cap_amount": m.cap_amount,
                    "backstop_cap": m.backstop_cap,
                    "charged_amount": m.charged_amount,
                    "requote_round": 0,
                    "on_hold": False,
                }
                for m in group.members
            ],
        }

    def _member_view(self, member: _Member) -> JsonDict:
        group = self._must_group(member.group_id)
        return {
            "member_id": member.id,
            "group_id": group.id,
            "name": member.name,
            "role": member.role,
            "status": member.status,
            "share_amount": member.share_amount,
            "cap_amount": member.cap_amount,
            "charged_amount": member.charged_amount,
            "approval_url": member.approval_url,
            "requote_round": 0,
            "group": {
                "title": group.title,
                "status": group.status,
                "merchant": group.merchant,
                "currency": group.currency,
                "total": group.total,
                "terminal": group.status in _GROUP_TERMINAL,
            },
        }
