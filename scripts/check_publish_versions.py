#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify publishable package versions are internally consistent."""

from __future__ import annotations
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / "packages"
# Packages published by .github/workflows/publish.yml in dependency order.
PUBLISH_ORDER = (
    "nest-core",
    "nest-sdk",
    "nest-plugins-reference",
    "nest-cli",
    "nest-shell",
    "nest-scenarios",
    "nest-mocks",
)


def _read_version(name: str) -> str:
    path = PACKAGES / name / "pyproject.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def main() -> int:
    versions = {name: _read_version(name) for name in PUBLISH_ORDER}
    core_version = versions["nest-core"]
    init_path = PACKAGES / "nest-core" / "nest_core" / "__init__.py"
    init_text = init_path.read_text(encoding="utf-8")
    for line in init_text.splitlines():
        if line.startswith("__version__"):
            _, _, rhs = line.partition("=")
            module_version = rhs.strip().strip('"').strip("'")
            if module_version != core_version:
                print(
                    f"nest-core pyproject version {core_version!r} "
                    f"!= __init__.__version__ {module_version!r}",
                    file=sys.stderr,
                )
                return 1
            break
    else:
        print("nest-core __version__ not found", file=sys.stderr)
        return 1
    sdk_version = versions["nest-sdk"]
    plugins_version = versions["nest-plugins-reference"]
    if sdk_version != plugins_version:
        print(
            f"warning: nest-sdk ({sdk_version}) != nest-plugins-reference ({plugins_version})",
            file=sys.stderr,
        )
    print("Publish version checks passed:")
    for name, version in versions.items():
        print(f"  {name}: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
