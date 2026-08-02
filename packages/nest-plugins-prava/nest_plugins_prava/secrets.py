# SPDX-License-Identifier: Apache-2.0
"""Secret scrubbing helpers — keep credentials out of traces and receipts.

Example::

    from nest_plugins_prava.secrets import assert_no_secrets, redact
    safe = redact({"token": "4111111111111111", "ok": True})
"""

from __future__ import annotations

import re
from typing import Any, cast

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|secret|token|password|authorization|bearer|cvv|pan|card_number|sk_test|sk_live|pk_test|pk_live)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(sk_(test|live)_[A-Za-z0-9]+|pk_(test|live)_[A-Za-z0-9]+|Bearer\s+\S+|"
    r"\b4[0-9]{12}(?:[0-9]{3})?\b)"
)

REDACTED = "***REDACTED***"


def looks_like_secret_key(key: str) -> bool:
    """Return True when a mapping key name suggests a credential field."""
    return bool(_SECRET_KEY_RE.search(key))


def redact(value: Any) -> Any:
    """Recursively redact secret-looking keys and credential-shaped strings.

    Example::

        redact({"session_token": "abc", "amount": 1})
    """
    if isinstance(value, dict):
        mapping = cast("dict[Any, Any]", value)
        out: dict[Any, Any] = {}
        for key, item in mapping.items():
            if isinstance(key, str) and looks_like_secret_key(key):
                out[key] = REDACTED
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        items = cast("list[Any]", value)
        return [redact(item) for item in items]
    if isinstance(value, str):
        if _SECRET_VALUE_RE.search(value):
            return REDACTED
        return value
    return value


def contains_secret(value: Any) -> bool:
    """Return True if *value* still contains a credential-shaped string."""
    if isinstance(value, dict):
        mapping = cast("dict[Any, Any]", value)
        for key, item in mapping.items():
            if isinstance(key, str) and looks_like_secret_key(key) and item != REDACTED:
                return True
            if contains_secret(item):
                return True
        return False
    if isinstance(value, list):
        items = cast("list[Any]", value)
        return any(contains_secret(item) for item in items)
    if isinstance(value, str):
        return bool(_SECRET_VALUE_RE.search(value))
    return False


def assert_no_secrets(value: Any, *, label: str = "payload") -> None:
    """Raise ValueError if a secret-shaped value is present.

    Example::

        assert_no_secrets({"status": "confirmed"})
    """
    if contains_secret(value):
        msg = f"Secret-like material detected in {label}"
        raise ValueError(msg)
