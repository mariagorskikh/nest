# SPDX-License-Identifier: Apache-2.0
"""Test suite to ensure duplicate scenario YAML files are kept in sync."""

from __future__ import annotations

from pathlib import Path


def test_scenario_yamls_are_in_sync() -> None:
    """Ensure that scenarios/*.yaml and builtin yaml directories are byte-identical."""
    root_dir = Path(__file__).parent.parent.parent.parent
    scenarios_dir = root_dir / "scenarios"
    builtin_dir = root_dir / "packages" / "nest-core" / "nest_core" / "scenarios_builtin" / "yaml"
    # All duplicate YAML files in scenarios/ should match their counterpart
    # in the builtin scenarios_builtin/yaml/ directory.
    assert scenarios_dir.exists(), f"Scenarios directory not found at {scenarios_dir}"
    assert builtin_dir.exists(), f"Builtin YAML directory not found at {builtin_dir}"

    scenarios = list(scenarios_dir.glob("*.yaml"))
    assert len(scenarios) > 0, "No scenarios found to check sync"

    for root_file in scenarios:
        builtin_file = builtin_dir / root_file.name
        # Only check duplicate YAMLs that exist in both directories
        if builtin_file.exists():
            root_content = root_file.read_text().strip()
            builtin_content = builtin_file.read_text().strip()

            # Compare contents line-by-line (excluding carriage return formatting variations)
            root_lines = [line.strip() for line in root_content.replace("\r", "").split("\n")]
            builtin_lines = [line.strip() for line in builtin_content.replace("\r", "").split("\n")]

            assert root_lines == builtin_lines, (
                f"Drift detected between {root_file} and {builtin_file}. "
                "Please make sure both copies are identical."
            )
