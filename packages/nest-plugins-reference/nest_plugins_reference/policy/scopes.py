# SPDX-License-Identifier: Apache-2.0
"""The shared scope grammar mapping token scope strings to decision ops.

A governed capability is expressed as a structured scope string. This module is
the single source of that grammar for manifest-bound auth plugins and trace
validators.

Grammar (anything else parses to ``None`` and is treated as not-grantable):

- ``tool:<name>``                    -> ("tool",   {"name": ...})
- ``spend:<int>``                    -> ("pay",    {"amount": ...})  (per-action cap)
- ``expose:<class>:<aud1,aud2,...>`` -> ("expose", {"data_class", "audience"})

``spend`` is a per-action authorization: a single amount checked against the
manifest cap. Cumulative spend and approval grants are stateful, so they are not
represented by durable token scopes. ``register`` is similarly a runtime action
and has no token-scope form by design.

Example::

    assert scope_to_op("tool:buy") == ("tool", {"name": "buy"})
    assert scope_to_op("read") is None
"""

from __future__ import annotations

from typing import Any


def scope_to_op(scope: str) -> tuple[str, dict[str, Any]] | None:
    """Parse a structured scope string into a ``decide`` ``(op, args)`` pair.

    Returns ``None`` for an ungoverned or malformed scope (including an
    ``expose`` scope with an empty audience, which authorises nothing), which
    callers treat as not-grantable.

    Example::

        assert scope_to_op("spend:100") == ("pay", {"amount": 100})
        assert scope_to_op("expose:pii:") is None
    """
    parts = scope.split(":")
    kind = parts[0]
    if kind == "tool" and len(parts) == 2:
        return ("tool", {"name": parts[1]})
    if kind == "spend" and len(parts) == 2:
        try:
            return ("pay", {"amount": int(parts[1])})
        except ValueError:
            return None
    if kind == "expose" and len(parts) == 3:
        audience = [a for a in parts[2].split(",") if a]
        if not audience:
            return None
        return ("expose", {"data_class": parts[1], "audience": audience})
    return None
