# SPDX-License-Identifier: Apache-2.0
"""ChainAim identity plugins: KERI-style pre-rotation over Ed25519.

Re-exports only — all implementation lives in layout-independent modules so
the package can be flattened without touching public names.

Example::

    from nest_plugins_reference.identity.chainaim import Ed25519PreRotatingIdentity
"""

from nest_plugins_reference.identity.chainaim.ed25519_prerotation import (
    ALGORITHM,
    DEFAULT_DIGEST_ALG,
    Ed25519PreRotatingIdentity,
    KeyId,
    KeyRecord,
    RotationRecord,
)

__all__ = [
    "ALGORITHM",
    "DEFAULT_DIGEST_ALG",
    "Ed25519PreRotatingIdentity",
    "KeyId",
    "KeyRecord",
    "RotationRecord",
]
