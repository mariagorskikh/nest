# SPDX-License-Identifier: Apache-2.0
"""Reference policy plugins.

Example::

    from nest_plugins_reference.policy.strict import StrictPolicy
"""

from nest_plugins_reference.policy.allow_all import AllowAllPolicy
from nest_plugins_reference.policy.strict import StrictPolicy

__all__ = ["AllowAllPolicy", "StrictPolicy"]
