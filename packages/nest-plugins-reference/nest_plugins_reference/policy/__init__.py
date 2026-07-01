# SPDX-License-Identifier: Apache-2.0
"""Policy primitives package — manifests, scope grammar, and decision core.

Exports the full public surface of the three policy modules so callers can
import from one place without knowing the internal file split.

Example::

    from nest_plugins_reference.policy import (
        PolicyManifest, Budget, Approval, ManifestSigner,
        sign_manifest, verify_manifest,
        decide, Decision, PolicyState, approval_key, scope_to_op,
    )
    manifest = PolicyManifest(agent_id=AgentId("a1"), tools=["buy"])
    op = scope_to_op("tool:buy")
    d = decide(manifest, "tool", {"name": "buy"}, PolicyState())
    assert d.allowed
"""

from __future__ import annotations

from nest_plugins_reference.policy.decide import (
    Decision,
    PolicyState,
    approval_key,
    decide,
)
from nest_plugins_reference.policy.manifest import (
    Approval,
    Budget,
    ManifestSigner,
    PolicyManifest,
    sign_manifest,
    verify_manifest,
)
from nest_plugins_reference.policy.scopes import scope_to_op

__all__ = [
    "Approval",
    "Budget",
    "Decision",
    "ManifestSigner",
    "PolicyManifest",
    "PolicyState",
    "approval_key",
    "decide",
    "scope_to_op",
    "sign_manifest",
    "verify_manifest",
]
