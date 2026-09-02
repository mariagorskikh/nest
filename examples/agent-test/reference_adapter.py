#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Minimal deterministic local adapter for NANDA Town's frozen Generation 1 profile.

Generation 1 is the first frozen agent-test contract/profile generation, not a
Town or nest-core 1.0 release.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from http.server import ThreadingHTTPServer
from typing import Any

from nest_core.agent_test.local_adapter_server import create_local_adapter_server

TOKEN_ENV = "TOWN_AGENT_TOKEN"
ADAPTER_INSTANCE_ID = "town-reference-adapter"
_TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z")


def decide_intent(observation: dict[str, Any]) -> dict[str, Any]:
    """Deterministic replace point: map one validated observation to one intent."""
    kind = observation["kind"]
    if kind == "start":
        return {"kind": "declare_capability", "capabilities": ["sell"]}
    if kind == "message":
        return {
            "kind": "send_to_sender",
            "media_type": "text/plain; charset=utf-8",
            "text": "sold:widget:2",
        }
    return {"kind": "none"}


def _read_and_remove_token() -> str:
    token = os.environ.get(TOKEN_ENV)
    try:
        if token is None or _TOKEN_RE.fullmatch(token) is None:
            raise RuntimeError(
                f"{TOKEN_ENV} must contain exactly 64 lowercase hexadecimal characters"
            )
        os.environ.pop(TOKEN_ENV)
        return token
    finally:
        del token


def create_server(*, port: int = 8787) -> ThreadingHTTPServer:
    """Create a literal-loopback server using only the documented token variable."""
    token = _read_and_remove_token()
    try:
        return create_local_adapter_server(
            token=token,
            adapter_instance_id=ADAPTER_INSTANCE_ID,
            decide_intent=lambda _context, observation: decide_intent(dict(observation)),
            port=port,
        )
    finally:
        del token


def main(argv: list[str] | None = None) -> int:
    """Run the local reference process without accepting credentials in arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        type=int,
        default=8787,
        help="literal 127.0.0.1 port (default: 8787; use 0 to select a free test port)",
    )
    arguments = parser.parse_args(argv)
    try:
        server = create_server(port=arguments.port)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Reference adapter could not start: {error}", file=sys.stderr)
        return 2
    print(
        f"Reference adapter listening on http://127.0.0.1:{server.server_port}",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
