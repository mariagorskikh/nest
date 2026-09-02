# SPDX-License-Identifier: Apache-2.0
"""Immutable explicit registry for profile-bound driver and profile codecs."""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, cast, get_args

from pydantic import BaseModel, RootModel, ValidationError

from .capability_profile import CAPABILITY_PROFILE_CODEC
from .contracts import ProfileCodec, ProfileReference, StrictModel


def _string_mapping(value: object, message: str) -> Mapping[str, object]:
    if isinstance(value, BaseModel):
        return cast("dict[str, object]", value.model_dump(mode="json"))
    if not isinstance(value, Mapping):
        raise ValueError(message)
    return cast("Mapping[str, object]", value)


def _profile_fields(value: object) -> tuple[str, str, str]:
    mapping = _string_mapping(value, "profile identity is malformed")
    profile_id = mapping.get("id")
    version = mapping.get("version")
    digest = mapping.get("digest")
    try:
        reference = ProfileReference.model_validate(
            {"id": profile_id, "version": version, "digest": digest}
        )
    except ValidationError as exc:
        raise ValueError("profile identity is malformed") from exc
    return reference.id, reference.version, reference.digest


def _request_profile(value: object) -> tuple[str, str, str]:
    mapping = _string_mapping(value, "driver request is malformed")
    return _profile_fields(mapping.get("profile"))


def _result_profile(value: object) -> tuple[str, str, str]:
    mapping = _string_mapping(value, "Test Result is malformed")
    return _profile_fields(mapping.get("profile"))


def _document_profile(value: object) -> tuple[str, str]:
    mapping = _string_mapping(value, "Test Profile document is malformed")
    profile_id = mapping.get("id")
    version = mapping.get("version")
    if not isinstance(profile_id, str) or not isinstance(version, str):
        raise ValueError("Test Profile identity is malformed")
    return profile_id, version


def _schema_prefix(codec: ProfileCodec) -> str:
    identity = f"{codec.profile_id}\0{codec.profile_version}".encode("ascii")
    encoded = base64.urlsafe_b64encode(identity).decode("ascii").rstrip("=")
    return f"profile_{encoded}"


_CODEC_MODEL_ATTRIBUTES = (
    "profile_model",
    "request_model",
    "response_model",
    "observation_model",
    "result_model",
)


def _require_strict_model_family(codec: ProfileCodec, model_attribute: str) -> None:
    root = getattr(codec, model_attribute)
    if not isinstance(root, type) or not issubclass(root, BaseModel):
        raise TypeError(f"{model_attribute} must be a Pydantic model")
    is_observation_root = model_attribute == "observation_model" and issubclass(root, RootModel)
    if not issubclass(root, StrictModel) and not is_observation_root:
        raise TypeError(f"{model_attribute} must have a closed StrictModel root")

    pending: list[object] = [root]
    seen: set[type[BaseModel]] = set()
    while pending:
        candidate = pending.pop()
        if candidate is Any or candidate is object:
            raise TypeError(f"{model_attribute} contains an unconstrained annotation")
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            if candidate in seen:
                continue
            seen.add(candidate)
            is_strict_root = (
                candidate is root
                and is_observation_root
                and candidate.model_config.get("strict") is True
            )
            is_strict_object = (
                issubclass(candidate, StrictModel)
                and candidate.model_config.get("strict") is True
                and candidate.model_config.get("extra") == "forbid"
            )
            if not is_strict_root and not is_strict_object:
                raise TypeError(
                    f"{model_attribute} must use a strict closed StrictModel family; "
                    f"{candidate.__module__}.{candidate.__qualname__} is not strict and closed"
                )
            pending.extend(field.annotation for field in candidate.model_fields.values())
            continue
        pending.extend(get_args(candidate))

    schema_stack: list[tuple[object, bool]] = [(root.model_json_schema(), True)]
    while schema_stack:
        schema_node, is_schema = schema_stack.pop()
        if is_schema and schema_node is True:
            raise TypeError(f"{model_attribute} contains an unconstrained schema")
        if isinstance(schema_node, dict):
            mapping = cast("dict[str, object]", schema_node)
            if is_schema and not mapping:
                raise TypeError(f"{model_attribute} contains an unconstrained schema")
            if (
                is_schema
                and mapping.get("type") == "object"
                and mapping.get("additionalProperties") is not False
            ):
                raise TypeError(
                    f"{model_attribute} must use a strict closed StrictModel family; "
                    "open object schemas are not allowed"
                )
            for key in ("$defs", "properties", "patternProperties", "dependentSchemas"):
                children = mapping.get(key)
                if isinstance(children, dict):
                    child_mapping = cast("dict[str, object]", children)
                    schema_stack.extend((child, True) for child in child_mapping.values())
            for key in (
                "additionalProperties",
                "contains",
                "else",
                "if",
                "items",
                "not",
                "propertyNames",
                "then",
            ):
                child = mapping.get(key)
                if isinstance(child, dict):
                    schema_stack.append((cast("dict[str, object]", child), True))
            for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
                children = mapping.get(key)
                if isinstance(children, list):
                    child_list = cast("list[object]", children)
                    schema_stack.extend((child, True) for child in child_list)


def _composed_schema(
    codecs: tuple[ProfileCodec, ...],
    *,
    model_attribute: str,
    title: str,
    combinator: Literal["oneOf", "anyOf"] = "oneOf",
    semantic_validation: list[str] | None = None,
) -> dict[str, Any]:
    branches: list[dict[str, Any]] = []
    definitions: dict[str, Any] = {}
    for codec in codecs:
        prefix = _schema_prefix(codec)
        model = getattr(codec, model_attribute)
        raw = model.model_json_schema(ref_template=f"#/$defs/{prefix}__{{model}}")
        branch_definitions = raw.pop("$defs", {})
        for name, definition in branch_definitions.items():
            namespaced = f"{prefix}__{name}"
            if namespaced in definitions:
                raise ValueError(f"duplicate generated schema definition: {namespaced}")
            definitions[namespaced] = definition
        branches.append(raw)
    schema: dict[str, Any] = {"title": title, combinator: branches}
    if definitions:
        schema["$defs"] = definitions
    if semantic_validation:
        schema["x-town-semantic-validation"] = semantic_validation
    return schema


@dataclass(frozen=True, slots=True)
class BoundProfileCodec:
    """Immutable codec context selected from one exact profile reference."""

    profile_id: str
    profile_version: str
    profile_digest: str
    codec: ProfileCodec

    @property
    def reference(self) -> ProfileReference:
        """Return a defensive copy of the exact bound profile identity."""
        return ProfileReference(
            id=self.profile_id,
            version=self.profile_version,
            digest=self.profile_digest,
        )

    def validate_request(self, value: object) -> Any:
        """Return a typed request only when its complete profile context is unchanged."""
        if _request_profile(value) != (
            self.profile_id,
            self.profile_version,
            self.profile_digest,
        ):
            raise ValueError("profile context changed after codec binding")
        return self.codec.request_model.model_validate(value)

    def validate_response(self, value: object) -> Any:
        """Decode a response only with the originating request's profile codec."""
        return self.codec.response_model.model_validate(value)

    def validate_observation(self, value: object) -> Any:
        """Decode evidence only with the immutable run profile codec."""
        return self.codec.observation_model.model_validate(value)

    def validate_result(self, value: object) -> Any:
        """Validate profile-owned result semantics under this immutable codec context."""
        if _result_profile(value) != (
            self.profile_id,
            self.profile_version,
            self.profile_digest,
        ):
            raise ValueError("result profile context changed after codec binding")
        return self.codec.result_model.model_validate(
            _string_mapping(value, "Test Result is malformed")
        )


@dataclass(frozen=True, slots=True, init=False)
class ProfileCodecRegistry:
    """Persistent registry: profile additions return a new immutable value."""

    _codecs: tuple[ProfileCodec, ...]
    _by_key: Mapping[tuple[str, str], ProfileCodec]

    def __init__(self, codecs: Iterable[ProfileCodec] = ()) -> None:
        ordered: list[ProfileCodec] = []
        by_key: dict[tuple[str, str], ProfileCodec] = {}
        for codec in codecs:
            for model_attribute in _CODEC_MODEL_ATTRIBUTES:
                _require_strict_model_family(codec, model_attribute)
            key = (codec.profile_id, codec.profile_version)
            if key in by_key:
                raise ValueError(
                    "Test Profile codec already registered: "
                    f"{codec.profile_id}@{codec.profile_version}"
                )
            ordered.append(codec)
            by_key[key] = codec
        object.__setattr__(self, "_codecs", tuple(ordered))
        object.__setattr__(self, "_by_key", MappingProxyType(by_key))

    def with_codec(self, codec: ProfileCodec) -> ProfileCodecRegistry:
        """Explicitly return a new registry containing one additional codec."""
        if (codec.profile_id, codec.profile_version) in self._by_key:
            raise ValueError(
                f"Test Profile codec already registered: {codec.profile_id}@{codec.profile_version}"
            )
        return ProfileCodecRegistry((*self._codecs, codec))

    def require(self, profile_id: str, profile_version: str) -> ProfileCodec:
        """Fail closed when no exact profile codec was explicitly registered."""
        try:
            return self._by_key[(profile_id, profile_version)]
        except KeyError as exc:
            raise KeyError(f"unknown Test Profile codec: {profile_id}@{profile_version}") from exc

    def bind(self, reference: object) -> BoundProfileCodec:
        """Bind one immutable codec context to an exact profile digest."""
        profile_id, version, digest = _profile_fields(reference)
        codec = self.require(profile_id, version)
        if digest != codec.profile_digest:
            raise ValueError("profile context changed from the registered canonical digest")
        return BoundProfileCodec(profile_id, version, digest, codec)

    def validate_profile(self, value: object) -> Any:
        """Dispatch a profile document to its exact registered strict model."""
        profile_id, version = _document_profile(value)
        codec = self.require(profile_id, version)
        return codec.profile_model.model_validate(value)

    def validate_request(self, value: object) -> Any:
        """Select by profile identity, bind the canonical digest, and return a typed request."""
        profile_id, version, digest = _request_profile(value)
        codec = self.require(profile_id, version)
        binding = BoundProfileCodec(profile_id, version, codec.profile_digest, codec)
        if digest != codec.profile_digest:
            raise ValueError("profile context changed from the registered canonical digest")
        return binding.validate_request(value)

    def validate_result(self, value: object) -> Any:
        """Dispatch and validate a result through its exact registered profile codec."""
        profile_id, version, digest = _result_profile(value)
        codec = self.require(profile_id, version)
        binding = BoundProfileCodec(profile_id, version, codec.profile_digest, codec)
        if digest != codec.profile_digest:
            raise ValueError("result profile context changed from the canonical digest")
        return binding.validate_result(value)

    def driver_request_schema(self) -> dict[str, Any]:
        """Compose all registered strict request branches without changing wire version."""
        return _composed_schema(
            self._codecs,
            model_attribute="request_model",
            title="DriverRequest",
            semantic_validation=[
                "event sequence is valid for the selected profile observation kind",
            ],
        )

    def driver_response_schema(self) -> dict[str, Any]:
        """Compose registered response shapes while documenting contextual profile binding."""
        return _composed_schema(
            self._codecs,
            model_attribute="response_model",
            title="DriverResponse",
            combinator="anyOf",
            semantic_validation=[
                "intent validated with the originating request profile codec",
                "intent text is at most the profile UTF-8 byte limit",
            ],
        )

    def test_profile_schema(self) -> dict[str, Any]:
        """Compose the strict document branch for each explicitly registered profile."""
        return _composed_schema(
            self._codecs,
            model_attribute="profile_model",
            title="TestProfile",
        )

    def test_observation_schema(self) -> dict[str, Any]:
        """Compose profile evidence shapes for schema consumers without runtime trust."""
        return _composed_schema(
            self._codecs,
            model_attribute="observation_model",
            title="TestObservation",
            combinator="anyOf",
            semantic_validation=[
                "observation validated with the run profile codec",
            ],
        )


DEFAULT_PROFILE_CODECS = ProfileCodecRegistry((CAPABILITY_PROFILE_CODEC,))

__all__ = [
    "BoundProfileCodec",
    "DEFAULT_PROFILE_CODECS",
    "ProfileCodec",
    "ProfileCodecRegistry",
]
