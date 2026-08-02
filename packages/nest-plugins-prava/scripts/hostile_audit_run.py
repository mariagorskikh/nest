#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run hostile production audit suite and print evidence."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TESTS = ROOT / "packages" / "nest-plugins-prava" / "tests"

AUDIT_FILES = [
    "test_duplicate_payment_ref.py",
    "test_concurrent_payments.py",
    "test_prava_api_failures.py",
    "test_state_machine.py",
    "test_refund_safety.py",
    "test_no_secret_leak.py",
    "test_mock_live_consistency.py",
]


def main() -> int:
    env = os.environ.copy()
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *[str(TESTS / f) for f in AUDIT_FILES],
        "-v",
        "-s",
        "--tb=short",
        "-m",
        "not live",
    ]
    print("COMMAND:", " ".join(cmd))
    print("=" * 72)
    p1 = subprocess.run(cmd, cwd=str(ROOT), env=env, check=False)

    live_cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(TESTS / "test_sandbox_proof.py"),
        "-v",
        "-s",
        "--tb=short",
        "-m",
        "live",
    ]
    print("\n" + "=" * 72)
    print("LIVE COMMAND:", " ".join(live_cmd))
    print(f"PRAVA_API_KEY set: {bool(env.get('PRAVA_API_KEY'))}")
    p2 = subprocess.run(live_cmd, cwd=str(ROOT), env=env, check=False)

    print("\n" + "=" * 72)
    print(f"NON_LIVE_EXIT={p1.returncode}")
    print(f"LIVE_EXIT={p2.returncode}")
    if p1.returncode != 0:
        return p1.returncode
    # Live may fail without key — surface that explicitly.
    return 0 if p2.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
