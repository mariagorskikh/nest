# SPDX-License-Identifier: Apache-2.0
"""The bundled scenario selects this plugin and stays loadable.

Runs offline: it validates wiring, not money. Real settlement is covered
by ``test_sandbox_live.py``.
"""

from __future__ import annotations

import pathlib

import yaml

SCENARIO_RELATIVE = pathlib.Path("scenarios") / "prava_marketplace.yaml"


def _find_scenario() -> pathlib.Path:
    """Locate the scenario by walking up, so the test is layout-agnostic.

    The plugin sits beside the scenario in the adapter repo and under
    ``packages/`` in the Nanda Town tree; both are found this way.
    """
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / SCENARIO_RELATIVE
        if candidate.is_file():
            return candidate
    msg = f"could not find {SCENARIO_RELATIVE} above {__file__}"
    raise AssertionError(msg)


SCENARIO = _find_scenario()


def test_scenario_file_exists() -> None:
    """The scenario ships with the plugin."""
    assert SCENARIO.is_file(), f"missing scenario at {SCENARIO}"


def test_scenario_selects_the_prava_payments_layer() -> None:
    """Swapping the payments layer is the whole point of the plugin."""
    config = yaml.safe_load(SCENARIO.read_text())
    assert config["layers"]["payments"] == "prava"
    assert config["tier"] == 1
    assert config["name"] == "prava_marketplace"


def test_scenario_documents_the_passkey_precondition() -> None:
    """A human approves the envelope before any simulation spends."""
    text = SCENARIO.read_text().lower()
    assert "passkey" in text
    assert "never automated" in text
