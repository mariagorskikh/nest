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
from nest_plugins_reference.validators.resolver_validators import (
    check_heartbeat_keeps_alive,
    check_negative_cache_is_consistent,
    check_stale_records_expire,
    run_all_resolver_checks,
)
from nest_plugins_reference.validators.trust_gate_validators import (
    check_denial_receipt_auditable,
    check_gate_tamper_rejected,
    check_low_trust_blocked,
    check_partial_redaction_enforced,
    forge_tier_upgrade,
)

__all__ = [
    "ConvergenceFailureError",
    "PartitionLeakError",
    "ValidatorReport",
    "check_converged",
    "check_denial_receipt_auditable",
    "check_eavesdropper_blocked",
    "check_field_injection_rejected",
    "check_heartbeat_keeps_alive",
    "check_negative_cache_is_consistent",
    "check_gate_tamper_rejected",
    "check_low_trust_blocked",
    "check_no_partition_view_leak",
    "check_partial_redaction_enforced",
    "check_replay_rejected",
    "check_stale_records_expire",
    "check_stale_revocation_blocked",
    "corrupt_proof",
    "run_all_resolver_checks",
    "forge_tier_upgrade",
]
