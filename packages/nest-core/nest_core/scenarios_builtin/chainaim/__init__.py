# SPDX-License-Identifier: Apache-2.0
"""ChainAim scenario drivers for Nanda Town — re-exports only.

Example::

    from nest_core.scenarios_builtin.chainaim import identity_prerotation_factory
"""

from __future__ import annotations

from nest_core.scenarios_builtin.chainaim.identity_prerotation import (
    identity_prerotation_factory,
)

__all__ = ["identity_prerotation_factory"]
