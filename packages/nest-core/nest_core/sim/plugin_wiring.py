# SPDX-License-Identifier: Apache-2.0
"""Wire live plugin instances to the simulation runtime (virtual clock, secrets)."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from nest_plugins_reference.auth.jwt_auth import KNOWN_WEAK_SECRET, JwtAuth


def wire_auth_to_sim_clock(plugins: dict[str, Any], clock_now: Callable[[], float]) -> None:
    """Instantiate JwtAuth (if still a class) and bind it to the simulator clock."""
    auth = plugins.get("auth")
    if auth is None:
        return
    secret_raw = os.environ.get("NEST_JWT_SECRET", KNOWN_WEAK_SECRET.decode("utf-8"))
    secret = secret_raw.encode("utf-8")
    if isinstance(auth, type) and issubclass(auth, JwtAuth):
        plugins["auth"] = auth(secret=secret, clock=clock_now)
        return
    if isinstance(auth, JwtAuth):
        auth.set_clock(clock_now)
