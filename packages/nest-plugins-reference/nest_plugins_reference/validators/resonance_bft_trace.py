# SPDX-License-Identifier: Apache-2.0
"""Trace-level adversarial validators for the ``resonance_bft_consensus`` scenario (LI-08).

The charter's mandatory deliverable is an adversarial validator that runs *against the JSONL
trace a scenario produces and passes*.  These functions do exactly that: they read the tagged
messages the driver emits into the trace — ``P|`` (leader proposal), ``O|`` (committed Outcome),
``E|`` (sealed evaluation record), ``V|`` (signed prepare/commit vote), and the machine-readable
``result:<round_no>:<view>:committed:<winner>`` line every committing replica broadcasts — and
reconstruct the protocol objects so the object-level invariants in :mod:`bft_validators` can be
checked on a real run.

**They re-run the cryptography, not just the tags.**  Charter class 3 is a commit "not backed by
≥ 2f+1 *signed* votes from distinct agents", so :func:`validate_resonance_vote_agreement` and the
forged-quorum / stuck-view checks count a ``V|`` vote only when its ed25519 signature verifies
under :meth:`ResonanceBFT.verify_vote` over exactly ``(round_id, view, phase, winner)``, the
voter is a roster member, and the vote is scoped to the *committed round* (``round_no``) — a
fabricated or replayed vote with a garbage signature, a non-roster ``aid``, or a foreign
``round_id`` does not count.  The four mandated adversarial classes are all covered:

* **conflicting commits** — :func:`validate_resonance_no_conflicting_commits`
* **leader equivocation** (a leader sending different proposals) —
  :func:`validate_resonance_no_leader_equivocation` (reads ``P|``; the charter's class 2, and its
  anti-pattern "don't skip the equivocation check by assuming an honest leader")
* **forged quorum** — :func:`validate_resonance_vote_agreement` (the signature backstop) +
  :func:`validate_resonance_no_forged_quorum` (the Outcome-membership check, cross-checked against
  the signature-verified voters)
* **stuck view** — :func:`validate_resonance_no_stuck_view`

plus a bonus **follower equivocation** check (:func:`validate_resonance_no_equivocation`, two
distinct sealed commitments from one agent — distinct from a single tampered record, which the
byzantine scenario legitimately contains and which resolve() detects and excludes).

All are **fail-closed**: a trace with no commit is a failure (no quorum-backed progress was ever
observed), which is precisely why they also FAIL against a ``contract_net``-coordinated trace,
whose messages carry no ``result:``/``O|``/``V|``/``P|`` lines at all — the "FAILS against
contract_net, PASSES against your plugin" requirement.

Threat model.  A trace validator validates a *trace*; identity↔key binding lives in the identity
layer, so a party that hand-authors an entire JSONL file with self-generated keys can always
produce a self-consistent one.  What these checks guarantee is the charter's actual ask: an
attack that manifests in a trace produced by a *real run* — a Byzantine agent that emits an
unsigned/garbage/replayed vote, proposes a second winner, votes for an un-proposed value, or uses
a foreign ``aid``/``round_id`` — is caught, because the signature and roster/round binding fail.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, cast

from nest_core.types import Outcome
from nest_core.validators import ValidationResult

from ..coordination.resonance_bft import ResonanceBFT
from .bft_validators import validate_bft_no_forged_quorum


def _msgs(events: list[dict[str, Any]], prefix: str) -> list[str]:
    """All message bodies in the trace that start with *prefix* (broadcast/send/receive)."""
    out: list[str] = []
    for ev in events:
        msg = str(ev.get("msg", ""))
        if msg.startswith(prefix):
            out.append(msg)
    return out


def _roster(events: list[dict[str, Any]]) -> set[str]:
    """Every agent id that produced an event — the trace's membership set."""
    return {str(ev.get("agent")) for ev in events if ev.get("agent")} - {"None", ""}


def _committed_results(events: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    """Parse ``result:<round_no>:<view>:committed:<winner>`` → ``(round_no, view, winner)``.

    Uses ``split(":", 4)`` so a winner that itself contains ``:`` is kept whole rather than
    truncated to its prefix (which would let two distinct winners collapse into one).
    """
    out: list[tuple[str, str, str]] = []
    for msg in _msgs(events, "result:"):
        parts = msg.split(":", 4)  # result, round_no, view, committed, winner
        if len(parts) == 5 and parts[3] == "committed":
            out.append((parts[1], parts[2], parts[4]))
    return out


class _VerifiedVotes:
    """Signature-verified COMMIT voters, keyed two ways for the two correlation needs.

    * ``by_rrvw[(round_no, view, winner)]`` — correlate to a ``result:`` line (which carries
      ``round_no``/``view``, not ``round_id``).
    * ``by_ridw[(round_id, winner)]`` — correlate to an ``O|`` Outcome (which carries ``round_id``).

    A vote is counted only if: its ed25519 signature verifies over ``(round_id, view, "commit",
    winner)``; the voter ``aid`` is a roster member; and the ``aid`` uses one consistent public key
    across the trace (an ``aid`` presenting two different keys, or a key shared across ``aid``s, is
    an identity forgery and is dropped).  Distinct *agents* are then the distinct counted ``aid``s.
    """

    def __init__(self, events: list[dict[str, Any]]) -> None:
        roster = _roster(events)
        self.by_rrvw: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self.by_ridw: dict[tuple[str, str], set[str]] = defaultdict(set)
        aid_key: dict[str, str] = {}  # aid -> pub (identity must be consistent)
        key_aid: dict[str, str] = {}  # pub -> aid (a key belongs to one aid)
        for msg in _msgs(events, "V|"):
            try:
                parsed = json.loads(msg[2:])
            except (ValueError, TypeError, RecursionError):
                continue
            if not isinstance(parsed, dict):
                continue
            v = cast("dict[str, Any]", parsed)
            if v.get("phase") != "commit":
                continue
            rid, r_no, view = v.get("round_id"), v.get("round_no"), v.get("view")
            winner, aid, sig, pub = v.get("winner"), v.get("aid"), v.get("sig"), v.get("pub")
            if not (isinstance(rid, str) and isinstance(r_no, int) and isinstance(view, int)):
                continue
            if not all(isinstance(x, str) for x in (winner, aid, sig, pub)):
                continue
            winner, aid, sig, pub = (
                cast("str", winner),
                cast("str", aid),
                cast("str", sig),
                cast("str", pub),
            )
            if roster and aid not in roster:
                continue  # foreign / fabricated voter id
            if aid_key.setdefault(aid, pub) != pub or key_aid.setdefault(pub, aid) != aid:
                continue  # inconsistent aid↔key binding — identity forgery
            if not ResonanceBFT.verify_vote(rid, view, "commit", winner, sig, pub):
                continue  # unsigned / replayed / wrong-value vote
            self.by_rrvw[(str(r_no), str(view), winner)].add(aid)
            self.by_ridw[(rid, winner)].add(aid)


def validate_resonance_no_conflicting_commits(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No two replicas commit conflicting winners for the same round (Problem #10 #4b).

    Every committing replica independently emits ``result:<round_no>:<view>:committed:<winner>``
    (backed by the 2f+1 commit-vote quorum that authorised it), so this reads them directly and
    fails if any round shows more than one distinct winner.  Fail-closed: zero commits => FAIL.
    """
    name = "resonance_no_conflicting_commits"
    by_round: dict[str, set[str]] = defaultdict(set)
    for round_no, _view, winner in _committed_results(events):
        by_round[round_no].add(winner)
    if not by_round:
        return [
            ValidationResult(name, False, "no committed rounds observed in trace (fail-closed)")
        ]
    violations = [
        f"round {r}: conflicting winners {sorted(ws)}" for r, ws in by_round.items() if len(ws) > 1
    ]
    if violations:
        return [ValidationResult(name, False, "; ".join(violations))]
    return [
        ValidationResult(name, True, f"{len(by_round)} committed round(s), each a single winner")
    ]


def validate_resonance_no_leader_equivocation(
    events: list[dict[str, Any]],
) -> list[ValidationResult]:
    """No leader proposes two different values for one ``(round_id, view)`` — the charter's class 2
    equivocation ("a leader sending different proposals to different followers"), and its
    anti-pattern "don't skip the equivocation check by assuming an honest leader".

    Reads the ``P|`` proposals off the bus and flags any ``(round_id, view)`` that carries more than
    one distinct proposed ``winner``, or more than one distinct sender-side proposer (only the
    round-robin leader that minted the ``round_id`` may propose for it).  Fail-closed: a trace with
    no ``P|`` proposal (e.g. ``contract_net``) is a failure.
    """
    name = "resonance_no_leader_equivocation"
    winners: dict[tuple[str, int], set[str]] = defaultdict(set)
    proposers: dict[tuple[str, int], set[str]] = defaultdict(set)
    for ev in events:
        msg = str(ev.get("msg", ""))
        if not msg.startswith("P|"):
            continue
        try:
            parsed = json.loads(msg[2:])
        except (ValueError, TypeError, RecursionError):
            continue
        if not isinstance(parsed, dict):
            continue
        p = cast("dict[str, Any]", parsed)
        rid, view, winner = p.get("round_id"), p.get("view"), p.get("winner")
        if not (isinstance(rid, str) and isinstance(view, int) and isinstance(winner, str)):
            continue
        winners[(rid, view)].add(winner)
        # Only sender-side events identify the proposer; receive events carry the recipient's id.
        if ev.get("kind") in ("broadcast", "send"):
            proposers[(rid, view)].add(str(ev.get("agent")))
    if not winners:
        return [ValidationResult(name, False, "no leader proposals (P|) in trace (fail-closed)")]
    violations = [
        f"(round_id {rid[:8]}, view {view}): proposed winners {sorted(ws)}"
        for (rid, view), ws in winners.items()
        if len(ws) > 1
    ]
    violations += [
        f"(round_id {rid[:8]}, view {view}): {len(who)} distinct proposers {sorted(who)}"
        for (rid, view), who in proposers.items()
        if len(who) > 1
    ]
    if violations:
        return [ValidationResult(name, False, "leader equivocation: " + "; ".join(violations))]
    return [ValidationResult(name, True, f"{len(winners)} proposal(s), no leader equivocated")]


def _decode_outcomes(events: list[dict[str, Any]]) -> list[Outcome]:
    seen: dict[str, Outcome] = {}
    for msg in _msgs(events, "O|"):
        try:
            outcome = Outcome.model_validate_json(msg[2:])
        except Exception:  # noqa: BLE001 - a garbled O| is simply not a valid outcome
            continue
        seen[outcome.round_id] = outcome  # one committed outcome per round_id
    return list(seen.values())


def validate_resonance_no_forged_quorum(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """Every committed Outcome in the trace satisfies quorum_size >= quorum_needed (n-f), with the
    recomputed-from-membership check in :func:`validate_bft_no_forged_quorum`, AND is cross-checked
    against the *signature-verified* commit voters: an ``O|`` claiming a quorum whose members did
    not cast verifiable ``V|`` commit votes for that ``round_id``/winner is a forged quorum.
    Fail-closed."""
    name = "resonance_no_forged_quorum"
    outcomes = _decode_outcomes(events)
    if not outcomes:
        return [ValidationResult(name, False, "no committed Outcome (O|) in trace (fail-closed)")]
    r = validate_bft_no_forged_quorum(outcomes)
    if not r.passed:
        return [ValidationResult(name, False, r.detail)]
    # Cross-check the self-reported Outcome against cryptographically-verified commit votes.
    verified = _VerifiedVotes(events)
    for o in outcomes:
        need = int(o.metadata.get("quorum_needed", 0))
        voters = verified.by_ridw.get((o.round_id, str(o.winner)), set())
        if len(voters) < need:
            return [
                ValidationResult(
                    name,
                    False,
                    f"round_id {o.round_id[:8]} winner {o.winner}: only {len(voters)} "
                    f"signature-verified commit votes < quorum_needed {need}",
                )
            ]
    return [ValidationResult(name, True, r.detail + "; each cross-checked against verified votes")]


def validate_resonance_no_equivocation(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """No agent submits TWO distinct sealed commitments for one round — equivocation (Problem #10).

    Reads the sealed ``E|`` records off the bus and flags any ``(round_id, aid)`` that appears with
    more than one distinct ``commitment``.  This is equivocation proper (an agent signing two
    different beliefs for the same round) — distinct from a single tampered record (one commitment
    that fails its seal), which resolve() already detects and excludes and which the byzantine
    scenario legitimately contains.  Fail-closed: a trace with no sealed records is a failure.
    """
    name = "resonance_no_equivocation"
    commitments: dict[tuple[str, str], set[str]] = defaultdict(set)
    for msg in _msgs(events, "E|"):
        try:
            rec = json.loads(msg[2:])
        except (ValueError, TypeError, RecursionError):
            continue
        if not isinstance(rec, dict):
            continue
        recd = cast("dict[str, Any]", rec)
        rid, aid, body = recd.get("round_id"), recd.get("aid"), recd.get("rec")
        if isinstance(rid, str) and isinstance(aid, str) and isinstance(body, dict):
            commit = cast("dict[str, Any]", body).get("commitment")
            if isinstance(commit, str):
                commitments[(rid, aid)].add(commit)
    if not commitments:
        return [
            ValidationResult(
                name, False, "no sealed evaluation records (E|) in trace (fail-closed)"
            )
        ]
    violations = [
        f"round {rid} agent {aid}: {len(cs)} distinct commitments (equivocation)"
        for (rid, aid), cs in commitments.items()
        if len(cs) > 1
    ]
    if violations:
        return [ValidationResult(name, False, "; ".join(violations))]
    return [
        ValidationResult(name, True, f"{len(commitments)} sealed record(s), no agent equivocated")
    ]


def validate_resonance_vote_agreement(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """Every committed round is backed by >= 2f+1 **signature-verified** commit votes from DISTINCT
    roster agents, scoped to that round (LI-09, the spec's "backed by 2f+1 signed votes from
    distinct agents" — the charter's class-3 forged-quorum backstop).

    Counts a ``V|`` commit vote only when :meth:`ResonanceBFT.verify_vote` accepts its ed25519
    signature over ``(round_id, view, "commit", winner)``, the ``aid`` is a roster member with a
    consistent key, and the vote's ``round_no``/``view``/``winner`` match the committed round.  A
    commit that appears without such a quorum — a garbage-signature vote, a foreign ``aid``, or
    votes borrowed from a different round — is a forged quorum.  Fail-closed on no commits.
    """
    name = "resonance_vote_agreement"
    n = max(len(_roster(events)), 1)
    quorum = 2 * ((n - 1) // 3) + 1
    verified = _VerifiedVotes(events)
    committed = _committed_results(events)
    if not committed:
        return [ValidationResult(name, False, "no committed rounds in trace (fail-closed)")]
    violations: list[str] = []
    for round_no, view, winner in committed:
        voters = verified.by_rrvw.get((round_no, view, winner), set())
        if len(voters) < quorum:
            violations.append(
                f"round {round_no}: {len(voters)} verified commit votes < {quorum} (2f+1) "
                f"for winner {winner}"
            )
    if violations:
        return [ValidationResult(name, False, "; ".join(violations))]
    return [
        ValidationResult(
            name, True, f"all {len(committed)} commit(s) backed by >= {quorum} verified votes"
        )
    ]


def validate_resonance_no_stuck_view(events: list[dict[str, Any]]) -> list[ValidationResult]:
    """Commit progress resumes after the network heals (LI-10, the "stuck view" invariant).

    If the trace contains a ``partition_healed`` marker, a *quorum-backed, signature-verified*
    commit must follow it — the progress evidence is a real 2f+1-vote commit, not merely the
    presence of a ``result:`` string (which would be forgeable).  With no partition/heal in the
    trace the check is not applicable and passes (a permanently-partitioned minority legitimately
    never commits — liveness, not a stuck view).
    """
    name = "resonance_no_stuck_view"
    heal_ts = [ev.get("ts") for ev in events if ev.get("kind") == "partition_healed"]
    if not heal_ts:
        return [
            ValidationResult(name, True, "no partition-heal in trace; stuck-view not applicable")
        ]
    healed_at = min(t for t in heal_ts if isinstance(t, (int, float)))
    n = max(len(_roster(events)), 1)
    quorum = 2 * ((n - 1) // 3) + 1
    verified = _VerifiedVotes(events)
    # A committing result: line after the heal, whose commit is backed by a verified 2f+1 quorum.
    for ev in events:
        msg = str(ev.get("msg", ""))
        ts = ev.get("ts")
        if not (msg.startswith("result:") and ":committed:" in msg):
            continue
        if not (isinstance(ts, (int, float)) and ts >= healed_at):
            continue
        parts = msg.split(":", 4)
        if len(parts) != 5:
            continue
        voters = verified.by_rrvw.get((parts[1], parts[2], parts[4]), set())
        if len(voters) >= quorum:
            return [
                ValidationResult(
                    name, True, "quorum-backed commit resumed after the network healed"
                )
            ]
    return [
        ValidationResult(name, False, "STUCK: no quorum-backed commit after the partition healed")
    ]


# Registered under the scenario's task type so ``validate_trace(trace, "resonance_bft_consensus")``
# runs the full suite (see nest_core.validators.VALIDATORS wiring).  These are Problem #10's four
# mandated adversarial classes — conflicting-commits, LEADER equivocation, forged-quorum
# (signature-verified vote agreement + Outcome cross-check), stuck-view — plus a bonus follower
# equivocation check.
RESONANCE_BFT_TRACE_VALIDATORS = [
    validate_resonance_no_conflicting_commits,
    validate_resonance_no_leader_equivocation,
    validate_resonance_no_forged_quorum,
    validate_resonance_no_equivocation,
    validate_resonance_vote_agreement,
    validate_resonance_no_stuck_view,
]
