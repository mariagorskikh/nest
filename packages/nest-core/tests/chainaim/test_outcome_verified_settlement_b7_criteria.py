# SPDX-License-Identifier: Apache-2.0
"""Iteration-7 (outcome_verified_settlement_b7) unit tests for the criterion library.

Frozen, real-payload-shaped fixtures for ``json_schema`` and ``artifact_match``
-- standalone (no Gate, no Simulator, no ScenarioRunner): these functions are
real and independently unit-tested here, but deliberately NOT routed through
``Gate.from_name`` / scenario YAML in this iteration (see ``gates.py``'s module
docstring for why).

Three fixtures below encode explicit scope decisions, called out rather than
buried:

* ``PRICE_WRONG_TYPE`` -- strict typing, no coercion (a permissive gate that
  accepts stringified numbers is a real exploit surface).
* ``PRICE_EXTRA_FIELDS`` -- additional, non-required fields are allowed.
* ``PRICE_NEGATIVE`` -- documents that ``json_schema`` is deliberately
  shape-only in this iteration: it does NOT bound field values, so a negative
  price currently passes. This is a live, not-yet-revisited scope decision,
  not an oversight -- the test exists so a future change to add a bound is a
  deliberate, visible diff to this test, not a silent behavior change.
"""

from __future__ import annotations

import hashlib

from nest_core.scenarios_builtin.chainaim.gates import (
    UnitContext,
    artifact_match,
    json_schema,
    reference_match,
)

# -- json_schema fixtures: GPU-hour price-quote contract --------------------

PRICE_OK = b'{"name": "GPU-hour", "price": 2.50, "currency": "USD"}'
PRICE_REFUSAL = b"I'm unable to provide pricing information for this item."
PRICE_ERROR = b'{"error": "rate_limited", "retry_after": 30}'
PRICE_MISSING = b'{"name": "GPU-hour", "currency": "USD"}'
PRICE_WRONG_TYPE = b'{"name": "GPU-hour", "price": "2.50", "currency": "USD"}'
PRICE_NULL_FIELD = b'{"name": "GPU-hour", "price": null, "currency": "USD"}'
PRICE_TRAILING_GARBAGE = b'{"name": "GPU-hour", "price": 2.50, "currency": "USD"}  <-- best!'
PRICE_EXTRA_FIELDS = b'{"name": "GPU-hour", "price": 2.50, "currency": "USD", "notes": "spot"}'
PRICE_NEGATIVE = b'{"name": "GPU-hour", "price": -5.0, "currency": "USD"}'

_REQUIRED = ("name", "price", "currency")
_TYPES: dict[str, type | tuple[type, ...]] = {"price": (int, float)}


def _price_ctx(chunk: bytes) -> UnitContext:
    """Build a UnitContext carrying *chunk* as the delivered content.

    Example::

        ctx = _price_ctx(PRICE_OK)
    """
    return UnitContext(ref="quote-stream", seq=0, chunk=chunk)


def _passes(chunk: bytes) -> bool:
    """json_schema check against the GPU-hour price-quote contract (name/price/currency).

    Example::

        assert _passes(PRICE_OK) is True
    """
    return json_schema(_price_ctx(chunk), required_fields=_REQUIRED, field_types=_TYPES)


def _passes_shape_only(chunk: bytes) -> bool:
    """Same as :func:`_passes` but with field_types=None (presence check only).

    Example::

        assert _passes_shape_only(PRICE_WRONG_TYPE) is True
    """
    return json_schema(_price_ctx(chunk), required_fields=_REQUIRED)


def test_outcome_verified_settlement_b7_json_schema_ok_passes() -> None:
    """A well-formed, fully-typed quote passes."""
    assert _passes(PRICE_OK) is True


def test_outcome_verified_settlement_b7_json_schema_refusal_fails() -> None:
    """Prose refusal is not JSON at all."""
    assert _passes(PRICE_REFUSAL) is False


def test_outcome_verified_settlement_b7_json_schema_error_object_fails() -> None:
    """Valid JSON, but the wrong shape (no name/price/currency)."""
    assert _passes(PRICE_ERROR) is False


def test_outcome_verified_settlement_b7_json_schema_missing_field_fails() -> None:
    """Valid JSON, right shape, but one required field absent."""
    assert _passes(PRICE_MISSING) is False


def test_outcome_verified_settlement_b7_json_schema_wrong_type_fails() -> None:
    """Scope decision (applied): price as a string fails -- no coercion."""
    assert _passes(PRICE_WRONG_TYPE) is False


def test_outcome_verified_settlement_b7_json_schema_null_field_fails() -> None:
    """A present-but-null field is not a valid value for its declared type."""
    assert _passes(PRICE_NULL_FIELD) is False


def test_outcome_verified_settlement_b7_json_schema_trailing_garbage_fails() -> None:
    """Valid JSON plus trailing text (e.g. markdown/prose wrapping) is rejected
    outright by json.loads -- the single most realistic LLM failure mode."""
    assert _passes(PRICE_TRAILING_GARBAGE) is False


def test_outcome_verified_settlement_b7_json_schema_extra_fields_pass() -> None:
    """Scope decision (applied): additional, non-required fields are allowed."""
    assert _passes(PRICE_EXTRA_FIELDS) is True


def test_outcome_verified_settlement_b7_json_schema_negative_price_currently_passes() -> None:
    """Documents the NOT-YET-DECIDED scope boundary: shape-only, no value bound."""
    assert _passes(PRICE_NEGATIVE) is True


def test_outcome_verified_settlement_b7_json_schema_no_field_types_checks_shape_only() -> None:
    """field_types=None (the default) checks required-field presence only."""
    assert _passes_shape_only(PRICE_WRONG_TYPE) is True


# -- artifact_match fixtures: provenance vs. a buyer-known-good hash --------

_FRESH_RESULT = b'{"task_id": "task-42", "result": "42 GPU-hours available"}'
_STALE_RESULT = b'{"task_id": "task-41", "result": "cached from yesterday"}'


def test_outcome_verified_settlement_b7_artifact_match_fresh_passes() -> None:
    """Delivered bytes match a buyer-known-good hash AND carry the committed task id."""
    ctx = UnitContext(ref="r", seq=0, chunk=_FRESH_RESULT)
    expected = hashlib.sha256(_FRESH_RESULT).hexdigest()
    assert artifact_match(ctx, expected_sha256=expected, task_id="task-42") is True


def test_outcome_verified_settlement_b7_artifact_match_stale_cache_fails() -> None:
    """Real, self-consistent bytes from a DIFFERENT task -- self-consistency
    (what ChecksumGate checks) would not catch this; artifact_match does,
    because it checks against the buyer's independently-known-good hash, not
    the seller's own claim."""
    ctx = UnitContext(ref="r", seq=0, chunk=_STALE_RESULT)
    expected_for_current_task = hashlib.sha256(_FRESH_RESULT).hexdigest()
    assert artifact_match(ctx, expected_sha256=expected_for_current_task) is False


def test_outcome_verified_settlement_b7_artifact_match_wrong_task_fails() -> None:
    """Hash matches (bytes weren't tampered) but the committed task id is absent."""
    ctx = UnitContext(ref="r", seq=0, chunk=_STALE_RESULT)
    expected = hashlib.sha256(_STALE_RESULT).hexdigest()
    assert artifact_match(ctx, expected_sha256=expected, task_id="task-42") is False


def test_outcome_verified_settlement_b7_artifact_match_neither_param_fails() -> None:
    """No expected_sha256 and no task_id is a caller error, not a vacuous pass."""
    ctx = UnitContext(ref="r", seq=0, chunk=_FRESH_RESULT)
    assert artifact_match(ctx) is False


def test_outcome_verified_settlement_b7_artifact_match_task_id_only() -> None:
    """task_id alone (no hash pinned) is sufficient when that's the only check wanted."""
    ctx = UnitContext(ref="r", seq=0, chunk=_FRESH_RESULT)
    assert artifact_match(ctx, task_id="task-42") is True
    assert artifact_match(ctx, task_id="task-99") is False


# -- reference_match: exhaustively covered in b5; one reachability smoke test -


def test_outcome_verified_settlement_b7_reference_match_smoke() -> None:
    """reference_match's full behavior is covered in b5 -- this just confirms
    it is reachable from this file's criterion-library import surface."""
    ctx = UnitContext(ref="quote-stream", seq=0, chunk=b"quote-stream#0")
    assert reference_match(ctx) is True
