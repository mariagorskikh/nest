# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators shipped alongside reference plugins.

Each validator targets a specific failure mode the corresponding reference
plugin would silently allow.  They are designed to **fail against the
reference plugin** and **pass against the hardened plugin** the validator
ships next to.

Example::

    from nest_plugins_reference.validators import (
        check_no_cross_partition_leak,
        check_converged,
    )
"""

from __future__ import annotations

from nest_plugins_reference.validators.gossip_validators import (
    ConvergenceFailureError,
    PartitionLeakError,
    ValidatorReport,
    check_converged,
    check_no_partition_view_leak,
)
from nest_plugins_reference.validators.privacy_validators import (
    check_eavesdropper_blocked,
    check_field_injection_rejected,
    check_replay_rejected,
    check_stale_revocation_blocked,
    corrupt_proof,
)

__all__ = [
    "ConvergenceFailureError",
    "PartitionLeakError",
    "ValidatorReport",
    "check_converged",
    "check_eavesdropper_blocked",
    "check_field_injection_rejected",
    "check_no_partition_view_leak",
    "check_replay_rejected",
    "check_stale_revocation_blocked",
    "corrupt_proof",
]
