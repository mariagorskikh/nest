# SPDX-License-Identifier: Apache-2.0
"""Emit a one-time warning when simulation-only reference plugins are used."""

from __future__ import annotations

import warnings


def warn_simulation_only(plugin: str, detail: str) -> None:
    """Warn that a reference plugin must not be used in production."""
    warnings.warn(
        f"{plugin} is a simulation-only reference plugin ({detail}). "
        "Do not use in production deployments.",
        UserWarning,
        stacklevel=3,
    )
