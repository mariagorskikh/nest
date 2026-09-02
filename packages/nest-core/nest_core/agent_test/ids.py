# SPDX-License-Identifier: Apache-2.0
"""Small local ULID generation without a third-party identifier dependency."""

from __future__ import annotations

import secrets
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode(value: int, length: int) -> str:
    out = ["0"] * length
    for index in range(length - 1, -1, -1):
        out[index] = _CROCKFORD[value & 31]
        value >>= 5
    return "".join(out)


def new_ulid(*, timestamp_ms: int | None = None) -> str:
    """Return a sortable Town ULID using wall-clock milliseconds and fresh entropy."""
    milliseconds = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    if not 0 <= milliseconds < 1 << 48:
        raise ValueError("timestamp_ms must fit the ULID 48-bit timestamp")
    return _encode(milliseconds, 10) + _encode(secrets.randbits(80), 16)
