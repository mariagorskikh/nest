# SPDX-License-Identifier: Apache-2.0
"""The small policy decision core used to clamp manifest-bound scopes.

:func:`decide` is a pure read over a
:class:`~nest_plugins_reference.policy.manifest.PolicyManifest` and the current
:class:`PolicyState`. It never mutates state and never raises, which lets the
``delegatable`` Auth plugin use it safely while issuing root capability tokens.
Callers that model runtime spend or approvals record those effects after a
successful action, then ask again.

Example::

    state = PolicyState()
    d = decide(manifest, "pay", {"amount": 100, "currency": "credits"}, state)
    if d.allowed:
        state.record_spend("credits", 100)
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from nest_plugins_reference.policy.manifest import PolicyManifest


def approval_key(op: str, amount: int) -> str:
    """Return the canonical approval key for an amount-bound *op*.

    The single source of the key string checked by :func:`decide`.

    Example::

        assert approval_key("pay", 500) == "pay:500"
    """
    return f"{op}:{amount}"


@dataclass
class Decision:
    """Outcome of a policy check: ``allowed`` plus a ``reason`` when denied.

    Example::

        d = Decision(allowed=False, reason="tool not in allowlist")
    """

    allowed: bool
    reason: str = ""


@dataclass
class PolicyState:
    """Mutable per-agent runtime state the decision core reads.

    Tracks cumulative spend per currency and the set of granted approval keys.
    :func:`decide` only *reads* this; the enforcement surface mutates it after a
    successful action.

    Example::

        state = PolicyState()
        state.record_spend("credits", 100)
        state.grant("pay:500")  # use approval_key("pay", 500)
    """

    spent: dict[str, int] = field(default_factory=lambda: dict[str, int]())
    approvals: set[str] = field(default_factory=lambda: set[str]())

    def record_spend(self, currency: str, amount: int) -> None:
        """Add *amount* to cumulative spend for *currency*.

        Example::

            state.record_spend("credits", 50)
        """
        self.spent[currency] = self.spent.get(currency, 0) + amount

    def grant(self, key: str) -> None:
        """Record that approval *key* has been granted.

        Use :func:`approval_key` to build the key, e.g.
        ``state.grant(approval_key("pay", 500))``.

        Example::

            state.grant("pay:500")
        """
        self.approvals.add(key)


def decide(
    manifest: PolicyManifest,
    op: str,
    args: Mapping[str, Any],
    state: PolicyState,
) -> Decision:
    """Decide whether *op* with *args* is permitted by *manifest* given *state*.

    Covers all four governance dimensions:

    - ``"tool"`` — ``args["name"]`` must be in ``manifest.tools``.
    - ``"register"`` — every capability in ``args["capabilities"]`` must be in
      ``manifest.tools``.
    - ``"expose"`` — ``args["audience"]`` must be a subset of the audiences
      declared for ``args["data_class"]`` in ``manifest.data`` (``"*"`` = any).
    - ``"pay"`` — requires a ``manifest.budget``; cumulative spend may not
      exceed the cap, the currency must match, and an amount over a matching
      :class:`Approval` threshold requires a granted approval.

    Returns a :class:`Decision`; never raises, never mutates *state*.

    Example::

        d = decide(manifest, "tool", {"name": "buy"}, PolicyState())
    """
    if op == "tool":
        name = str(args.get("name", ""))
        if name in manifest.tools:
            return Decision(True)
        return Decision(False, f"tool {name!r} not in allowlist")

    if op == "register":
        caps_raw = args.get("capabilities", [])
        if not isinstance(caps_raw, list):
            return Decision(False, "capabilities must be a list")
        caps = [str(c) for c in cast("list[object]", caps_raw)]
        bad = [c for c in caps if c not in manifest.tools]
        if bad:
            return Decision(False, f"capabilities not in allowlist: {bad}")
        return Decision(True)

    if op == "expose":
        data_class = str(args.get("data_class", ""))
        audience_raw = args.get("audience", [])
        if not isinstance(audience_raw, list):
            return Decision(False, "audience must be a list")
        audience = [str(a) for a in cast("list[object]", audience_raw)]
        allowed = manifest.data.get(data_class)
        if allowed is None:
            return Decision(False, f"data class {data_class!r} not declared")
        if "*" in allowed:
            return Decision(True)
        bad = [a for a in audience if a not in allowed]
        if bad:
            return Decision(False, f"audience not permitted for {data_class!r}: {bad}")
        return Decision(True)

    if op == "pay":
        if manifest.budget is None:
            return Decision(False, "no budget declared")
        amount = _coerce_amount(args.get("amount", 0))
        if amount is None:
            return Decision(False, f"invalid amount {args.get('amount')!r}")
        currency = str(args.get("currency", manifest.budget.currency))
        if amount < 0:
            return Decision(False, "negative amount")
        if currency != manifest.budget.currency:
            return Decision(False, f"currency {currency!r} != {manifest.budget.currency!r}")
        spent = state.spent.get(currency, 0)
        if spent + amount > manifest.budget.cap:
            return Decision(
                False,
                f"budget exceeded: {spent}+{amount} > {manifest.budget.cap}",
            )
        # Approval is bound to the specific amount, so one grant cannot authorise
        # unlimited future large pays. When several rules match, the strictest
        # (lowest threshold) wins regardless of declaration order.
        thresholds = [a.threshold for a in manifest.approvals if a.op == "pay"]
        if thresholds:
            threshold = min(thresholds)
            if amount > threshold and approval_key("pay", amount) not in state.approvals:
                return Decision(
                    False,
                    f"requires authorization: amount {amount} > threshold {threshold}",
                )
        return Decision(True)

    return Decision(False, f"unknown op {op!r}")


def _coerce_amount(raw: Any) -> int | None:
    """Coerce a payment amount to a non-fractional ``int``, or ``None`` if invalid.

    Money is integer credits. Floats, strings, booleans, and ``None`` are
    rejected (return ``None``) rather than silently truncated — ``int(100.9)``
    would otherwise slip a fractional overspend past an integer cap, and
    ``bool`` is an ``int`` subclass that must not be read as ``0``/``1``.

    Example::

        assert _coerce_amount(100) == 100
        assert _coerce_amount(100.9) is None
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    return None
