# SPDX-License-Identifier: Apache-2.0
"""Packaged immutable Test Profile resolution and exact-byte codec binding."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib import resources
from typing import Any, cast

from .capability_profile import (
    CAPABILITY_PROFILE_CODEC,
    CapabilityProfileReference,
    TestProfile,
)
from .contracts import ProfileReference, StrictModel
from .profile_codecs import DEFAULT_PROFILE_CODECS, BoundProfileCodec

_PROFILE_PACKAGE = "nest_core.agent_test.resources.profiles"
_REFERENCES = {
    "capability-fulfillment": "capability-fulfillment-1.json",
    "nanda/agent/capability-fulfillment@1": "capability-fulfillment-1.json",
}
_CANONICAL_RESOURCE_NAMES = frozenset(_REFERENCES.values())


class ResolvedTestProfile(ABC):
    """Read-only packaged profile snapshot accepted by the agent-test runtime."""

    @property
    @abstractmethod
    def content(self) -> bytes:
        """Return the exact immutable packaged bytes captured during resolution."""

    @property
    @abstractmethod
    def document(self) -> StrictModel:
        """Return a defensive copy of the strictly parsed profile document."""

    @property
    @abstractmethod
    def reference(self) -> ProfileReference:
        """Return a defensive copy of the exact profile identity."""

    @property
    @abstractmethod
    def codec(self) -> BoundProfileCodec:
        """Return the immutable codec context bound to the snapshot bytes."""


@dataclass(frozen=True, slots=True)
class _PackagedResolvedTestProfile(ResolvedTestProfile):
    _content: bytes
    _document: StrictModel
    _reference: ProfileReference
    _codec: BoundProfileCodec

    @property
    def content(self) -> bytes:
        return self._content

    @property
    def document(self) -> StrictModel:
        return self._document.model_copy(deep=True)

    @property
    def reference(self) -> ProfileReference:
        return self._reference.model_copy(deep=True)

    @property
    def codec(self) -> BoundProfileCodec:
        return self._codec


def _require_canonical_resource_name(resource_name: str) -> str:
    if resource_name not in _CANONICAL_RESOURCE_NAMES:
        raise ValueError(f"unknown canonical Test Profile resource: {resource_name}")
    return resource_name


def _validated_document(content: bytes) -> StrictModel:
    try:
        data: Any = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("packaged Test Profile is not valid JSON") from exc
    document = DEFAULT_PROFILE_CODECS.validate_profile(data)
    if not isinstance(document, StrictModel):
        raise TypeError("packaged Test Profile codec returned an invalid domain model")
    return document


def _resolved_test_profile_from_resource(resource_name: str) -> ResolvedTestProfile:
    resource_name = _require_canonical_resource_name(resource_name)
    content = bytes(resources.files(_PROFILE_PACKAGE).joinpath(resource_name).read_bytes())
    document = _validated_document(content)
    identity = document.model_dump(mode="json")
    reference = ProfileReference(
        id=cast("str", identity["id"]),
        version=cast("str", identity["version"]),
        digest="sha256:" + hashlib.sha256(content).hexdigest(),
    )
    binding = DEFAULT_PROFILE_CODECS.bind(reference)
    return _PackagedResolvedTestProfile(
        _content=content,
        _document=document,
        _reference=reference,
        _codec=binding,
    )


def resolve_profile(reference: str) -> bytes:
    """Return immutable packaged bytes for a supported alias or exact reference."""
    try:
        name = _REFERENCES[reference]
    except KeyError as exc:
        raise KeyError(f"unknown Test Profile reference: {reference}") from exc
    return bytes(resources.files(_PROFILE_PACKAGE).joinpath(name).read_bytes())


def profile_bytes(reference: str) -> bytes:
    """Alias for the exact packaged profile bytes used in the digest."""
    return resolve_profile(reference)


def profile_digest(reference: str) -> str:
    """Return lowercase SHA-256 over the package resource, including its final LF."""
    return "sha256:" + hashlib.sha256(resolve_profile(reference)).hexdigest()


def load_profile(reference: str) -> TestProfile:
    """Load and strictly validate a packaged profile before any execution begins."""
    document = _validated_document(resolve_profile(reference))
    if not isinstance(document, TestProfile):
        raise TypeError("requested profile is not the capability-fulfillment profile")
    return document


def capability_profile_document(resolved: ResolvedTestProfile) -> TestProfile:
    """Narrow a generic resolved snapshot at the capability feature boundary."""
    document = resolved.document
    if resolved.codec.codec is not CAPABILITY_PROFILE_CODEC or not isinstance(
        document, TestProfile
    ):
        raise TypeError("resolved profile is not the capability-fulfillment profile")
    return document


def capability_profile_reference(
    resolved: ResolvedTestProfile,
) -> CapabilityProfileReference:
    """Narrow the generic exact reference at the capability feature boundary."""
    capability_profile_document(resolved)
    return CapabilityProfileReference.model_validate(resolved.reference.model_dump(mode="json"))


def resolve_test_profile(reference: str) -> ResolvedTestProfile:
    """Resolve Alpha execution's capability profile; codec registration does not enable runs."""
    try:
        resource_name = _REFERENCES[reference]
    except KeyError as exc:
        raise KeyError(f"unknown Test Profile reference: {reference}") from exc
    return _resolved_test_profile_from_resource(resource_name)
