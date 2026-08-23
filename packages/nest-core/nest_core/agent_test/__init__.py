# SPDX-License-Identifier: Apache-2.0
"""Frozen 1 contracts for NANDA Town agent-test workflows."""

from .aggregation import Aggregation, aggregate
from .attestation import (
    ATTESTATION_SCHEMA_VERSION,
    AttestationError,
    AttestationVerdict,
    MutableDependency,
    build_attestation,
    result_digest,
    verify_attestation,
)
from .ids import new_ulid
from .models import TestObservation, TestProfile, TestResult
from .profiles import (
    ResolvedTestProfile,
    load_profile,
    profile_digest,
    resolve_profile,
    resolve_test_profile,
)

__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "Aggregation",
    "AttestationError",
    "AttestationVerdict",
    "MutableDependency",
    "ResolvedTestProfile",
    "TestObservation",
    "TestProfile",
    "TestResult",
    "aggregate",
    "build_attestation",
    "load_profile",
    "new_ulid",
    "profile_digest",
    "result_digest",
    "resolve_profile",
    "resolve_test_profile",
    "verify_attestation",
]
