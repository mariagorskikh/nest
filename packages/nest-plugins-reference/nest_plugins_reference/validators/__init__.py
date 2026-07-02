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

from nest_plugins_reference.validators.bft_validators import (
    BftValidationResult,
    build_equivocation_certificate,
    collect_equivocation_certificates,
    validate_bft_liveness_view_progress,
    validate_bft_no_conflicting_commits,
    validate_bft_no_equivocation,
    validate_bft_no_forged_quorum,
    validate_genuine_consensus,
    validate_no_axis_deadlock,
    verify_equivocation_certificate,
)
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
    "BftValidationResult",
    "ConvergenceFailureError",
    "PartitionLeakError",
    "ValidatorReport",
    "build_equivocation_certificate",
    "check_converged",
    "check_eavesdropper_blocked",
    "check_field_injection_rejected",
    "check_no_partition_view_leak",
    "check_replay_rejected",
    "check_stale_revocation_blocked",
    "collect_equivocation_certificates",
    "corrupt_proof",
    "validate_bft_liveness_view_progress",
    "validate_bft_no_conflicting_commits",
    "validate_bft_no_equivocation",
    "validate_bft_no_forged_quorum",
    "validate_genuine_consensus",
    "validate_no_axis_deadlock",
    "verify_equivocation_certificate",
]
