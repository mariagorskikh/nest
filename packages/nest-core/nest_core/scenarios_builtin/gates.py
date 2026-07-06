# SPDX-License-Identifier: Apache-2.0
"""Settlement gates for the outcome-verified settlement scenario.

A *gate* is the pure decision seam that decides whether one metered unit (one
``tick``/``seq`` of a stream) is allowed to settle. It maps a per-unit context
to a :class:`Verdict`. Every gate is a pure function of its :class:`UnitContext`
-- no RNG, no wall-clock, no model calls, no I/O, no per-call mutable state.

Three settlement disciplines, cumulative by composition:

* :class:`AckReceivedGate` (default, L1 -- delivery-gated) reproduces today's
  billing exactly: a unit settles iff its ``ack`` was received (see ``_on_ack``
  in ``outcome_verified_settlement.py``).
* :class:`ChecksumGate` (L2 -- integrity-gated) settles iff a checksum
  recomputed over the delivered chunk bytes equals the declared checksum --
  proves the seller delivered exactly what it claimed to send.
* :class:`EvaluatorGate` (L3 -- conformance-gated) composes
  :class:`ChecksumGate` (when ``require_integrity=True``, the default) and
  additionally requires a named criterion from the ``_CRITERIA`` library to
  pass -- proves the delivered content is what the buyer's *committed*
  acceptance criterion says it should be, not merely that the seller's own
  checksum claim is internally consistent. A unit can pass L2 (honest
  checksum) and still fail L3 (wrong content) -- see
  ``test_outcome_verified_settlement_b5_checksum_passes_criterion_fails``.

Only ``"reference_match"`` is wired into ``_CRITERIA`` / :meth:`Gate.from_name`
in this iteration. ``json_schema`` and ``artifact_match`` are real,
independently unit-tested criterion functions (see
``test_outcome_verified_settlement_b7_criteria.py``) that are deliberately not
routed through the wire-level scenario config in this iteration -- they take
extra parameters :meth:`Gate.from_name` does not forward (keeps criterion
parameters off the wire for now; see the DESIGN session records for the
``criterion_hash``-on-wire roadmap item).

Example::

    from nest_core.scenarios_builtin.chainaim.gates import Gate, UnitContext

    gate = Gate.from_name("evaluator", criterion="reference_match")
    verdict = gate.should_settle(
        UnitContext(ref="buyer-0-stream", seq=0, chunk=b"buyer-0-stream#0",
                    declared_checksum="<sha256 hex of that chunk>")
    )
"""

from __future__ import annotations

import hashlib
import hmac
import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Verdict:
    """The pure result of a gate decision for one metered unit.

    ``passed`` says whether the unit may settle; ``ref`` and ``seq`` echo the
    stream ref and tick sequence the decision was made for, so a caller can
    attribute the verdict back to a trace line without re-parsing it.

    Example::

        verdict = Verdict(passed=True, ref="buyer-0-stream", seq=0)
    """

    passed: bool
    ref: str
    seq: int


@dataclass(frozen=True, slots=True)
class UnitContext:
    """Everything a gate is allowed to see about one metered unit.

    This is the gate seam's only input. ``ref`` and ``seq`` identify the unit;
    ``ack_received`` feeds the delivery gate; ``chunk`` and ``declared_checksum``
    feed the content and conformance gates. All fields are plain data with safe
    defaults so a caller need only populate what a given gate consumes.

    Example::

        ctx = UnitContext(ref="buyer-0-stream", seq=0, ack_received=True)
    """

    ref: str
    seq: int
    ack_received: bool = False
    chunk: bytes = b""
    declared_checksum: str | None = None


class Gate(ABC):
    """The settlement seam: decide whether one metered unit may settle.

    Concrete gates implement :meth:`should_settle` as a pure function of a
    :class:`UnitContext`. Use :meth:`from_name` to build a gate by its config
    name (the value a scenario's ``task.config`` carries), defaulting to the
    delivery-gated behavior that matches today.

    Example::

        gate = Gate.from_name("ack_received")
    """

    @abstractmethod
    def should_settle(self, unit_ctx: UnitContext) -> Verdict:
        """Return the settle/withhold :class:`Verdict` for ``unit_ctx``.

        Implementations must be pure: no RNG, no wall-clock, no model calls, no
        I/O, and no per-call mutable state.

        Example::

            verdict = gate.should_settle(UnitContext(ref="r", seq=0, ack_received=True))
        """
        ...

    @classmethod
    def from_name(cls, name: str = "ack_received", **kwargs: Any) -> Gate:
        """Build a gate by config name; defaults to :class:`AckReceivedGate`.

        ``"ack_received"`` builds the delivery gate; ``"checksum"`` builds the
        content gate and forwards keyword flags (e.g. ``algo``) to it;
        ``"evaluator"`` builds the conformance gate and forwards ``criterion``,
        ``algo``, and ``require_integrity``. An unknown name raises
        :class:`ValueError` rather than silently degrading.

        Example::

            gate = Gate.from_name("evaluator", criterion="reference_match")
        """
        if name == "ack_received":
            return AckReceivedGate(**kwargs)
        if name == "checksum":
            return ChecksumGate(**kwargs)
        if name == "evaluator":
            return EvaluatorGate(**kwargs)
        known = ["ack_received", "checksum", "evaluator"]
        raise ValueError(f"unknown gate {name!r}; known: {known}")


class AckReceivedGate(Gate):
    """Delivery gate: settle a unit iff its ``ack`` was received.

    This reproduces the current ack-gated billing exactly — a unit settles when
    (and only when) the payee acknowledged delivery — so swapping it in for the
    implicit gate today leaves behavior byte-identical.

    Example::

        gate = AckReceivedGate()
    """

    def should_settle(self, unit_ctx: UnitContext) -> Verdict:
        """Pass iff ``unit_ctx.ack_received`` is set.

        Example::

            verdict = AckReceivedGate().should_settle(
                UnitContext(ref="r", seq=0, ack_received=True)
            )
        """
        return Verdict(passed=unit_ctx.ack_received, ref=unit_ctx.ref, seq=unit_ctx.seq)


class ChecksumGate(Gate):
    """Content gate: settle a unit iff its delivered chunk matches its checksum.

    Recomputes a checksum over ``unit_ctx.chunk`` using ``algo`` and compares it
    (in constant time) to ``unit_ctx.declared_checksum``. A unit with no declared
    checksum never settles. ``algo`` is validated at construction so a bad
    algorithm fails fast rather than at decision time.

    Example::

        gate = ChecksumGate(algo="sha256")
    """

    def __init__(self, *, algo: str = "sha256") -> None:
        """Store the (validated) digest algorithm name.

        Example::

            gate = ChecksumGate(algo="sha256")
        """
        if algo not in hashlib.algorithms_available:
            raise ValueError(f"unknown hash algorithm {algo!r}")
        self._algo = algo

    def should_settle(self, unit_ctx: UnitContext) -> Verdict:
        """Pass iff ``digest(algo, chunk)`` equals the declared checksum.

        Example::

            chunk = b"unit-payload"
            ctx = UnitContext(ref="r", seq=0, chunk=chunk, declared_checksum="...")
            verdict = ChecksumGate().should_settle(ctx)
        """
        declared = unit_ctx.declared_checksum
        passed = declared is not None and hmac.compare_digest(
            hashlib.new(self._algo, unit_ctx.chunk).hexdigest(), declared
        )
        return Verdict(passed=passed, ref=unit_ctx.ref, seq=unit_ctx.seq)


def canonical_chunk(ref: str, seq: int) -> bytes:
    """Deterministic canonical payload bytes for one metered unit.

    Single source of truth for "what this unit's content should be" -- used by
    :func:`reference_match` here and (starting in iteration b6) imported by the
    scenario driver instead of being redefined there. Public (no leading
    underscore) because it is deliberately consumed across module boundaries;
    ``pyright --strict``'s ``reportPrivateUsage`` would flag an underscore-
    prefixed name imported into another module.

    Example::

        expected = canonical_chunk("buyer-0-stream", 0)
    """
    return f"{ref}#{seq}".encode()


def reference_match(unit_ctx: UnitContext) -> bool:
    """Conformance criterion: delivered bytes equal the canonical bytes for
    this unit's ``(ref, seq)``.

    Catches a seller that delivers *some other unit's* real, honestly
    checksummed content at this unit's slot (replay, stale-first, or any other
    cross-unit substitution) -- a case :class:`ChecksumGate` alone cannot see,
    because the checksum is honest for the bytes actually sent.

    Example::

        reference_match(UnitContext(ref="r", seq=0, chunk=b"r#0"))
    """
    return unit_ctx.chunk == canonical_chunk(unit_ctx.ref, unit_ctx.seq)


_CRITERIA: dict[str, Callable[[UnitContext], bool]] = {
    "reference_match": reference_match,
}


class EvaluatorGate(Gate):
    """Conformance gate (L3): settle a unit iff delivered, intact, AND conforming.

    Composes :class:`ChecksumGate` internally when ``require_integrity=True``
    (the default): a unit only reaches the criterion check after its declared
    checksum has been verified against the delivered bytes. The composition is
    explicit and short-circuiting -- an integrity failure is reported before the
    criterion function is ever called, so a criterion never has to re-derive
    integrity itself, and an ``EvaluatorGate`` pass means delivered AND intact
    AND conforming.

    Example::

        gate = EvaluatorGate(criterion="reference_match")
    """

    def __init__(
        self,
        *,
        criterion: str = "reference_match",
        algo: str = "sha256",
        require_integrity: bool = True,
    ) -> None:
        """Build the (optional) inner checksum gate and resolve the named criterion.

        ``criterion`` must be a key in ``_CRITERIA`` (currently only
        ``"reference_match"``); an unknown name raises :class:`ValueError` at
        construction, matching :meth:`Gate.from_name`'s fail-fast style.

        Example::

            gate = EvaluatorGate(criterion="reference_match", algo="sha256")
        """
        self._inner = ChecksumGate(algo=algo) if require_integrity else None
        if criterion not in _CRITERIA:
            msg = f"unknown criterion {criterion!r}; known: {sorted(_CRITERIA)}"
            raise ValueError(msg)
        self._criterion_name = criterion
        self._criterion = _CRITERIA[criterion]

    def should_settle(self, unit_ctx: UnitContext) -> Verdict:
        """Pass iff integrity holds (when required) AND the criterion passes.

        An integrity failure short-circuits: the criterion is never evaluated.

        Example::

            verdict = EvaluatorGate().should_settle(
                UnitContext(ref="r", seq=0, chunk=b"r#0", declared_checksum="...")
            )
        """
        if self._inner is not None:
            integrity = self._inner.should_settle(unit_ctx)
            if not integrity.passed:
                return Verdict(passed=False, ref=unit_ctx.ref, seq=unit_ctx.seq)
        passed = self._criterion(unit_ctx)
        return Verdict(passed=passed, ref=unit_ctx.ref, seq=unit_ctx.seq)


def json_schema(
    unit_ctx: UnitContext,
    *,
    required_fields: tuple[str, ...],
    field_types: dict[str, type | tuple[type, ...]] | None = None,
) -> bool:
    """Shape-conformance criterion: delivered bytes parse as a JSON object with
    the required fields present and, where specified, correctly typed.

    Not wired through :meth:`Gate.from_name` / scenario YAML in this iteration
    -- call directly (see ``test_outcome_verified_settlement_b7_criteria.py``).
    Deliberately shape-only: does not evaluate field *values* (e.g. a negative
    or zero price still passes) -- a value-range bound would extend
    "conformance" into semantic/business validation, which is an explicit,
    not-yet-made scope decision, not a default this function assumes silently.

    Example::

        json_schema(ctx, required_fields=("name", "price", "currency"),
                     field_types={"price": (int, float)})
    """
    try:
        obj = json.loads(unit_ctx.chunk)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(obj, dict):
        return False
    if any(field not in obj for field in required_fields):
        return False
    if field_types is None:
        return True
    return all(
        isinstance(obj[field], expected) for field, expected in field_types.items() if field in obj
    )


def artifact_match(
    unit_ctx: UnitContext,
    *,
    expected_sha256: str | None = None,
    task_id: str | None = None,
) -> bool:
    """Provenance criterion: delivered bytes match a buyer-known-good hash
    and/or contain a committed task identifier.

    Differs from :class:`ChecksumGate` (L2): L2 checks the seller's bytes
    against the seller's *own* declared checksum (self-consistency -- catches
    corruption in transit). This checks against a hash the *buyer*
    independently knows to be correct (catches a seller honestly serving
    stale-but-self-consistent bytes, e.g. a cached response to a different
    task). Not wired through :meth:`Gate.from_name` in this iteration -- call
    directly. At least one of ``expected_sha256``/``task_id`` must be given.

    Example::

        artifact_match(ctx, expected_sha256="...", task_id="task-42")
    """
    if expected_sha256 is None and task_id is None:
        return False
    if expected_sha256 is not None:
        digest = hashlib.sha256(unit_ctx.chunk).hexdigest()
        if digest != expected_sha256:
            return False
    return not (task_id is not None and task_id.encode() not in unit_ctx.chunk)
