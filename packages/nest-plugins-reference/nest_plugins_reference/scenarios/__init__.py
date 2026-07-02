# SPDX-License-Identifier: Apache-2.0
"""Scenario factories for the reference plugins.

Importing this package registers the scenarios it provides with the core
``register_scenario`` registry, so a scenario YAML can select them by
``task.type`` once the package is imported.
"""

from __future__ import annotations

from .resonance_bft_consensus import resonance_bft_consensus_factory

__all__ = ["resonance_bft_consensus_factory"]
