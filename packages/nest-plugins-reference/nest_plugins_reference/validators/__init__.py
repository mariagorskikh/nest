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
        check_no_substitution,
    )
"""

from __future__ import annotations

from nest_plugins_reference.validators.datafacts_validators import (
    BrokenProvenanceError,
    DataFactsValidatorReport,
    StaleFreshnessError,
    SubstitutionError,
    check_no_stale_freshness,
    check_no_substitution,
    check_provenance_chain_intact,
)
from nest_plugins_reference.validators.gossip_validators import (
    ConvergenceFailureError,
    PartitionLeakError,
    ValidatorReport,
    check_converged,
    check_no_partition_view_leak,
)

__all__ = [
    "BrokenProvenanceError",
    "ConvergenceFailureError",
    "DataFactsValidatorReport",
    "PartitionLeakError",
    "StaleFreshnessError",
    "SubstitutionError",
    "ValidatorReport",
    "check_converged",
    "check_no_partition_view_leak",
    "check_no_stale_freshness",
    "check_no_substitution",
    "check_provenance_chain_intact",
]
