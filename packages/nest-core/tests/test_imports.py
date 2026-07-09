# SPDX-License-Identifier: Apache-2.0
"""Smoke tests: verify that nest-core packages import correctly."""

import importlib.metadata


def test_nest_core_imports() -> None:
    """Importing nest_core should succeed and expose a version string."""
    import nest_core

    assert nest_core.__version__ == importlib.metadata.version("nest-core")


def test_layers_package_imports() -> None:
    """The layers sub-package should be importable."""
    import nest_core.layers

    assert hasattr(nest_core.layers, "Transport")


def test_sim_package_imports() -> None:
    """The sim sub-package should be importable."""
    import nest_core.sim

    assert nest_core.sim.__doc__ is not None


def test_types_module_imports() -> None:
    """The types module should be importable."""
    import nest_core.types

    assert hasattr(nest_core.types, "AgentId")
