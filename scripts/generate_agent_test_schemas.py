#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate or verify the seven packaged NANDA Town agent-test schemas."""

from __future__ import annotations

import argparse

from nest_core.agent_test.schema_contracts import check_packaged_schemas, write_packaged_schemas


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail without writing when checked-in schemas differ from deterministic output",
    )
    args = parser.parse_args()
    if args.check:
        check_packaged_schemas()
    else:
        write_packaged_schemas()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
