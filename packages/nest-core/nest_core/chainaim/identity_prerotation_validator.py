# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator for KERI-style pre-rotation identity traces.

Threat model (what this validator catches, replayed purely from the trace):

1. **Post-rotation forgery** — a stale, rotated-out key signs after its
   window closed. Caught by the window check (observed tick).
2. **Backdating** — a new key claims a tick inside its predecessor's
   window. Caught by the window check (claimed tick).
3. **Rotation hijack** — an attacker holding the *current* key publishes a
   rotation to an attacker-chosen successor. Reactive continuity accepts
   this (the old key's signature verifies); pre-rotation rejects it because
   the revealed successor's digest does not match the digest that was
   pre-committed one event earlier. Caught by the commitment check, plus
   the guarantee that the hijacked key never becomes window-valid and that
   the victim provably recovers with the genuinely pre-committed key.

Trace grammar (additive over the ``identity_rotation`` grammar; ``rotate:``
and ``signed:`` lines keep their merged shapes so existing validators run
unchanged on these traces):

- ``rotate:<agent>:<old_key_id>:<new_key_id>:<tick>``
- ``signed:<agent>:<key_id>:<claimed_tick>:<ok|forge|backdate>``
- ``commit:<agent>:<key_id>:<alg>:<hex>:<tick>`` — pre-rotation commitment
  published by ``key_id`` for its successor (inception and every rotation).
- ``rotate_attempt:<agent>:<old_key_id>:<alg>:<hex>:<alg>:<hex>:<tick>:hijack``
  — a rejected hijack: revealed digest, then the prior commitment it failed
  to match.

Commitments are algorithm-prefixed (``sha256:<hex>``). At the trace level a
commitment is bound to the revealed key through the repo-wide convention
that ``key_id`` **is** the SHA-256 hexdigest of the public key, so a
``sha256`` commitment is verifiable by direct recompute against the
``new_key_id`` named in the ``rotate:`` line. Commitments under any other
algorithm cannot be recomputed from a trace (traces carry key ids, not key
bytes) and are reported as unverifiable — strictness by design; there is no
permissive path.

Window semantics are re-expressed here (not imported from the merged
validator's private helpers) so the two spec-mandated checks are visible in
this diff and immune to upstream refactors.

Example::

    from nest_core.chainaim import validate_identity_prerotation

    results = validate_identity_prerotation(events)
    assert results[0].passed
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # runtime import is deferred: see _result()
    from nest_core.validators import ValidationResult

_INF = float("inf")
_SHA256 = "sha256"
_NAME = "identity_prerotation"


def _result(passed: bool, detail: str) -> ValidationResult:
    """Build a ``ValidationResult``, importing it lazily.

    The registry seam in ``nest_core.validators`` imports this module; a
    module-level import back into ``nest_core.validators`` would make that
    cycle order-dependent. By the time any validator runs, the registry
    module is fully initialized, so the deferred import is always safe.

    Example::

        r = _result(True, "ok")
    """
    from nest_core.validators import ValidationResult

    return ValidationResult(_NAME, passed, detail)


def _payload(ev: dict[str, Any]) -> str:
    """Return the payload text without any ``|sig:`` suffix.

    Example::

        assert _payload({"msg": "rotate:a:K0:K1:2.0|sig:ab"}) == "rotate:a:K0:K1:2.0"
    """
    return str(ev.get("msg", "")).rsplit("|sig:", 1)[0]


def _tick(raw: object) -> float | None:
    """Parse a tick token to ``float``; ``None`` if unparseable.

    Example::

        assert _tick("3.0") == 3.0 and _tick("None") is None
    """
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


class _Window:
    """Half-open validity window ``[issued_at, rotated_out)`` for one key.

    Example::

        w = _Window(0.0, 10.0)
        assert w.contains(5.0) and not w.contains(10.0)
    """

    def __init__(self, issued_at: float, rotated_out: float = _INF) -> None:
        self.issued_at = issued_at
        self.rotated_out = rotated_out

    def contains(self, tick: float) -> bool:
        """Return whether *tick* falls inside the window.

        Example::

            assert _Window(0.0).contains(1.0)
        """
        return self.issued_at <= tick < self.rotated_out


def validate_identity_prerotation(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """All three attacks rejected and every rotation commitment-bound.

    Checks, replayed purely from the trace:

    (a) every honest ``ok`` signature is window-valid — its key's window
        contains **both** the externally observed event tick (``ev["ts"]``)
        and the claimed tick;
    (b) every ``forge`` / ``backdate`` signature is window-**invalid**;
    (c) every applied rotation reveals a key whose digest equals the digest
        its predecessor pre-committed (``sha256`` recompute against the
        ``new_key_id``; a rotation with no known prior commitment, or a
        commitment this trace cannot recompute, is a failure — strict);
    (d) every ``hijack`` attempt revealed a digest that does **not** match
        the prior commitment, and the hijacked key never becomes
        window-valid for any signed line nor appears as an applied
        rotation's successor;
    (e) after every hijack attempt the victim **recovers**: a later applied
        (hence commitment-bound) rotation from the same key, followed by at
        least one window-valid honest signature under the recovery key.

    Example::

        results = validate_identity_prerotation(events)
        for r in results:
            print(r)
    """
    problems: list[str] = []

    # --- pass 1: structure -------------------------------------------------
    # commitments[key_id] = alg-prefixed digest that key committed for its
    # successor; rotations = applied rotate: lines in trace order;
    # hijacks = rejected rotate_attempt lines; signed = signature lines.
    commitments: dict[str, str] = {}
    rotations: list[tuple[str, str, str, float]] = []  # agent, old, new, tick
    hijacks: list[tuple[str, str, str, str, float]] = []  # agent, old, revealed, prior, tick
    signed: list[tuple[str, str, float | None, float | None, str]] = []
    windows: dict[str, _Window] = {}

    for ev in events:
        if ev.get("kind") != "send":
            continue
        msg = _payload(ev)
        parts = msg.split(":")
        if msg.startswith("commit:") and len(parts) == 6:
            digest_tick = _tick(parts[5])
            if digest_tick is None:
                continue
            commitments[parts[2]] = f"{parts[3]}:{parts[4]}"
        elif msg.startswith("rotate:") and len(parts) == 5:
            rotate_tick = _tick(parts[4])
            if rotate_tick is None:
                continue
            rotations.append((parts[1], parts[2], parts[3], rotate_tick))
            old = windows.setdefault(parts[2], _Window(issued_at=0.0))
            old.rotated_out = rotate_tick
            windows[parts[3]] = _Window(issued_at=rotate_tick)
        elif msg.startswith("rotate_attempt:") and len(parts) == 9 and parts[8] == "hijack":
            attempt_tick = _tick(parts[7])
            if attempt_tick is None:
                continue
            revealed = f"{parts[3]}:{parts[4]}"
            prior = f"{parts[5]}:{parts[6]}"
            hijacks.append((parts[1], parts[2], revealed, prior, attempt_tick))
        elif msg.startswith("signed:") and len(parts) == 5:
            signed.append((parts[1], parts[2], _tick(str(ev.get("ts"))), _tick(parts[3]), parts[4]))

    # Key ids of hijack-revealed successors (recomputable only for sha256,
    # where key_id == the revealed hexdigest by repo convention).
    hijacked_key_ids = {
        revealed.split(":", 1)[1]
        for _, _, revealed, _, _ in hijacks
        if revealed.startswith(_SHA256 + ":")
    }

    # --- (c) applied rotations are commitment-bound ------------------------
    bound = 0
    for agent, old_key, new_key, _rt in rotations:
        commitment = commitments.get(old_key)
        if commitment is None:
            problems.append(f"{agent} rotation to {new_key[:8]} has no prior commitment")
            continue
        alg, _, digest = commitment.partition(":")
        if alg != _SHA256:
            problems.append(f"{agent} commitment alg {alg!r} not recomputable from trace")
        elif digest != new_key:
            problems.append(f"{agent} revealed key {new_key[:8]} does not match commitment")
        else:
            bound += 1

    # --- (d) hijack attempts rejected ---------------------------------------
    applied_successors = {new_key for _, _, new_key, _ in rotations}
    for agent, _old, revealed, prior, _at in hijacks:
        if revealed == prior:
            problems.append(f"{agent} hijack digest matched the commitment (accepted)")
        hijacked_id = revealed.split(":", 1)[1] if ":" in revealed else revealed
        if hijacked_id in applied_successors:
            problems.append(f"{agent} hijacked key {hijacked_id[:8]} was applied as a rotation")

    # --- (a)+(b) window checks; hijacked keys never lazily trusted ---------
    ok_count = 0
    attack_count = 0
    for agent, key_id, observed, claimed, verdict in signed:
        window = windows.get(key_id)
        if (
            window is None
            and verdict == "ok"
            and key_id
            and key_id != "None"
            and key_id not in hijacked_key_ids
        ):
            # First, never-rotated key of an honest agent: open window from 0.
            window = windows.setdefault(key_id, _Window(issued_at=0.0))
        window_valid = (
            window is not None
            and observed is not None
            and claimed is not None
            and window.contains(observed)
            and window.contains(claimed)
        )
        if key_id in hijacked_key_ids:
            # An ``ok`` verdict here means the protocol vouched for the
            # attacker's key; window validity means the trace granted it a
            # lifetime. Either is acceptance of the hijack.
            if verdict == "ok" or window_valid:
                problems.append(f"{agent} signature under hijacked key {key_id[:8]} accepted")
            else:
                attack_count += 1
            continue
        if verdict == "ok":
            ok_count += 1
            if not window_valid:
                problems.append(
                    f"{agent} honest sig key={key_id[:8]} "
                    f"observed={observed} claimed={claimed} not in a valid window"
                )
        else:
            attack_count += 1
            if window_valid:
                problems.append(
                    f"{agent} {verdict} sig key={key_id[:8]} "
                    f"observed={observed} claimed={claimed} accepted"
                )

    # --- (e) recovery after every hijack ------------------------------------
    recovered = 0
    for agent, old_key, _revealed, _prior, at in hijacks:
        recovery = next(
            (r for r in rotations if r[0] == agent and r[1] == old_key and r[3] >= at),
            None,
        )
        if recovery is None:
            problems.append(f"{agent} never recovered after hijack at tick {at}")
            continue
        recovery_key, recovery_tick = recovery[2], recovery[3]
        window = windows.get(recovery_key)
        proved = any(
            key_id == recovery_key
            and verdict == "ok"
            and window is not None
            and observed is not None
            and claimed is not None
            and observed >= recovery_tick
            and window.contains(observed)
            and window.contains(claimed)
            for _sig_agent, key_id, observed, claimed, verdict in signed
        )
        if not proved:
            problems.append(f"{agent} recovery key {recovery_key[:8]} never signed validly")
        else:
            recovered += 1

    if problems:
        return [_result(False, "; ".join(problems))]
    return [
        _result(
            True,
            f"{ok_count} honest signatures valid, {attack_count} attacks rejected, "
            f"{bound} rotations commitment-bound, {len(hijacks)} hijacks rejected, "
            f"{recovered} recoveries verified",
        )
    ]
