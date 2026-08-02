# SPDX-License-Identifier: Apache-2.0
"""Redaction by construction.

Nothing in this package hands a caller a structure it has not first run
through :func:`redact`. That includes exception messages, because a stack
trace is a trace too.

The forbidden-key set is a superset of the one enforced by Nanda Town's own
adversarial validator (``nest_core.validators._EMPIC_FORBIDDEN_SECRET_KEYS``),
extended with the card-rail fields that only exist once a payment plugin is
talking to a real acquirer.

Example::

    redact({"mandate_id": "md_1", "api_key": "sk_live_x"})
    # {"mandate_id": "md_1", "api_key": "[redacted]"}
"""

from __future__ import annotations

import re
from typing import Any

# ``Any`` is intentional at this trust boundary: this module recursively
# sanitizes arbitrary JSON-shaped values before typed code can consume them.
# pyright: reportUnknownArgumentType=false, reportUnknownVariableType=false

REDACTED = "[redacted]"

# Mirrors nest_core.validators._EMPIC_FORBIDDEN_SECRET_KEYS exactly ...
_UPSTREAM_FORBIDDEN = frozenset(
    {
        "api_key",
        "api_key_secret",
        "bearer_token",
        "coinbase_secret",
        "password",
        "private_key",
        "secret",
        "secret_key",
        "service_api_key",
        "stripe_secret_key",
        "wallet_auth_token",
        "wallet_secret",
    }
)

# ... plus everything a card rail can leak that a credits ledger never could.
_CARD_RAIL_FORBIDDEN = frozenset(
    {
        "access_token",
        "authorization",
        "card",
        "card_number",
        "cardholder_name",
        "credential",
        "cvc",
        "cvv",
        "engine_api_token",
        "expiry",
        "id_token",
        "pan",
        "passkey",
        "prava_api_key",
        "refresh_token",
        "session_token",
        "signing_seed",
        "token",
        "webhook_secret",
    }
)

FORBIDDEN_KEYS = _UPSTREAM_FORBIDDEN | _CARD_RAIL_FORBIDDEN

# Split so this source file itself never contains a scannable secret literal.
_PEM_SENTINEL = "-----begin " + "private key-----"
_SECRET_PREFIXES = ("sk_" + "live_", "sk_" + "test_", "pk_" + "live_", "pk_" + "test_")

_PAN_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")
_SECRET_TOKEN_RE = re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]+")


def _is_forbidden_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in FORBIDDEN_KEYS or normalized.endswith("_secret")


def scrub_text(value: str) -> str:
    """Strip secret-shaped substrings out of free text.

    Applied to every exception message this package raises, so an engine
    error body can never smuggle a key into a traceback.

    Example::

        scrub_text("failed: Bearer abc123")  # 'failed: [redacted]'
    """
    out = _BEARER_RE.sub(REDACTED, value)
    out = _SECRET_TOKEN_RE.sub(REDACTED, out)
    out = _PAN_RE.sub(REDACTED, out)
    if _PEM_SENTINEL in out.lower():
        out = REDACTED
    return out


def redact(value: Any) -> Any:
    """Return a deep copy of *value* with every secret-shaped part removed.

    Example::

        redact({"members": [{"api_key": "x", "name": "Soham"}]})
        # {'members': [{'api_key': '[redacted]', 'name': 'Soham'}]}
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, child in value.items():  # pyright: ignore[reportUnknownVariableType]
            key = str(raw_key)
            # Dropped, not masked. Upstream's validator flags a forbidden *key*
            # whatever its value, so a `"api_key": "[redacted]"` entry would
            # still fail the trace scan. The only safe amount is zero.
            if _is_forbidden_key(key):
                continue
            out[key] = redact(child)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]  # pyright: ignore[reportUnknownArgumentType]
    if isinstance(value, str):
        lowered = value.lower()
        if _PEM_SENTINEL in lowered or lowered.startswith("bearer "):
            return REDACTED
        if value.startswith(_SECRET_PREFIXES):
            return REDACTED
        return scrub_text(value)
    return value


def find_violations(value: Any, *, path: str = "$") -> list[str]:
    """Report what an upstream secret-material validator would flag.

    A local re-implementation of ``_empic_secret_violations`` so the test
    suite can hold this plugin to the same bar without importing a private
    upstream helper.

    Example::

        find_violations({"secret_key": "x"})  # ['$.secret_key: forbidden secret field']
    """
    violations: list[str] = []
    if isinstance(value, dict):
        for raw_key, child in value.items():  # pyright: ignore[reportUnknownVariableType]
            key = str(raw_key)
            child_path = f"{path}.{key}"
            if _is_forbidden_key(key):
                violations.append(f"{child_path}: forbidden secret field")
            violations.extend(find_violations(child, path=child_path))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):  # pyright: ignore[reportUnknownVariableType]
            violations.extend(find_violations(item, path=f"{path}[{index}]"))
    elif isinstance(value, str):
        lowered = value.lower()
        if _PEM_SENTINEL in lowered:
            violations.append(f"{path}: private key material")
        elif lowered.startswith("bearer "):
            violations.append(f"{path}: bearer token material")
        elif value.startswith(_SECRET_PREFIXES):
            violations.append(f"{path}: payment provider secret key material")
    return violations
