# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the PBFT coordination plugin.

Persona note (distributed-systems engineer): these four checks are the audit a
BFT protocol has to survive. Each targets one attack, and each verifies exactly
what its attack is about — no more, no less:

- **Conflicting commits** is an attack on *agreement*: two honest replicas
  commit different values for the same ``(view, seq)``. Visible in the committed
  values themselves, so this check is a plain comparison — the safety headline.
- **Forged quorum** is an attack on *signature validity*: a commit certificate
  claims ``2f+1`` votes but does not actually carry ``2f+1`` distinct valid
  signatures. This check re-verifies signatures (via an injected ``verify_fn``)
  — the one validator that must do crypto.
- **Equivocation** is an attack on *vote consistency*: one replica signs two
  different values for the same slot and phase. Visible in the recorded votes.
- **Stuck view** is an attack on *liveness*: rounds are attempted but no commit
  and no view-change ever appear, so the system hangs instead of rotating the
  leader. A timing/progress check, no crypto.

All four are pure functions over recorded data and return a
:class:`ValidatorReport`. Each is tested in both directions: it must *catch* a
byzantine trace and *pass* an honest one.

Example::

    report = check_no_conflicting_commits(commit_records)
    assert report.passed, report.detail
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from nest_core.types import AgentId

from nest_plugins_reference.coordination.pbft import (
    SignedVote,
    fault_tolerance,
    quorum_size,
    signing_payload,
)


@dataclass
class ValidatorReport:
    """Pass/fail report with a short human-readable explanation.

    Example::

        report = ValidatorReport(passed=True, detail="no conflicting commits")
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: dict[str, object] = field(default_factory=dict[str, object])


class ConflictingCommitError(AssertionError):
    """Raised when two replicas commit different values for one slot.

    Example::

        raise ConflictingCommitError("(0,1): r0=X r1=Y")
    """


class ForgedQuorumError(AssertionError):
    """Raised when a commit certificate lacks 2f+1 valid distinct signatures.

    Example::

        raise ForgedQuorumError("commit by r0 has 2 valid sigs, needs 3")
    """


class EquivocationError(AssertionError):
    """Raised when one replica signs two values for the same slot and phase.

    Example::

        raise EquivocationError("r2 voted X and Y for (0,1,prepare)")
    """


class StuckViewError(AssertionError):
    """Raised when rounds are attempted but no progress is ever made.

    Example::

        raise StuckViewError("5 rounds attempted, 0 commits, 0 view-changes")
    """


def check_no_conflicting_commits(commits: list[dict[str, Any]]) -> ValidatorReport:
    """No two commit records may disagree on the value for one ``(view, seq)``.

    This is the cardinal BFT safety property. A correct protocol makes a
    conflicting commit impossible; this check is the proof obligation.

    Each commit record is ``{agent, view, seq, value, ...}``.

    Example::

        assert check_no_conflicting_commits(commits).passed
    """
    by_slot: dict[tuple[int, int], dict[str, str]] = {}
    for c in commits:
        slot = (int(c["view"]), int(c["seq"]))
        agent = str(c["agent"])
        value = str(c["value"])
        seen = by_slot.setdefault(slot, {})
        seen[agent] = value

    for slot, agent_values in by_slot.items():
        distinct = set(agent_values.values())
        if len(distinct) > 1:
            return ValidatorReport(
                False,
                f"conflicting commits at view={slot[0]} seq={slot[1]}: {agent_values}",
                {"slot": slot, "values": agent_values},
            )
    return ValidatorReport(
        True,
        f"no conflicting commits across {len(by_slot)} slots",
        {"slots": len(by_slot)},
    )


def check_no_forged_quorum(
    commits: list[dict[str, Any]],
    verify_fn: Callable[[bytes, SignedVote], bool],
    n: int,
) -> ValidatorReport:
    """Every commit's certificate must carry ``2f+1`` distinct valid signatures.

    ``verify_fn(payload, signed_vote)`` returns True iff the vote's signature
    verifies against the voter's key. A certificate that is short, padded with
    duplicates, or signed with garbage is rejected here — the forged-quorum
    defence.

    Example::

        ok = check_no_forged_quorum(commits, verify, n=4).passed
    """
    quorum = quorum_size(n)
    for c in commits:
        certificate = c.get("certificate", [])
        value = str(c["value"])
        valid_voters: set[AgentId] = set()
        for raw in certificate:
            sv = SignedVote.from_metadata(raw)
            if sv.value != value:
                continue
            payload = signing_payload(sv.view, sv.seq, sv.phase, sv.value)
            if verify_fn(payload, sv):
                valid_voters.add(sv.voter)
        if len(valid_voters) < quorum:
            return ValidatorReport(
                False,
                (
                    f"forged quorum: commit by {c.get('agent')} for {value!r} "
                    f"has {len(valid_voters)} valid sigs, needs {quorum}"
                ),
                {"agent": c.get("agent"), "valid": len(valid_voters), "quorum": quorum},
            )
    return ValidatorReport(
        True,
        f"all {len(commits)} commit certificates carry a valid {quorum}-signature quorum",
        {"checked": len(commits), "quorum": quorum},
    )


def check_no_equivocation(votes: list[dict[str, Any]]) -> ValidatorReport:
    """No replica may sign two different values for the same slot and phase.

    Each vote record is the ``SignedVote.to_metadata()`` shape. A byzantine
    replica that double-votes (equivocates) is caught here.

    Example::

        assert check_no_equivocation(votes).passed
    """
    # (voter, view, seq, phase) -> value
    seen: dict[tuple[str, int, int, str], str] = {}
    for v in votes:
        key = (str(v["voter"]), int(v["view"]), int(v["seq"]), str(v["phase"]))
        value = str(v["value"])
        if key in seen and seen[key] != value:
            return ValidatorReport(
                False,
                (
                    f"equivocation: {key[0]} signed {seen[key]!r} and {value!r} "
                    f"for view={key[1]} seq={key[2]} phase={key[3]}"
                ),
                {"voter": key[0], "slot": key[1:3], "values": [seen[key], value]},
            )
        seen[key] = value
    return ValidatorReport(
        True,
        f"no equivocation across {len(seen)} (voter, slot, phase) entries",
        {"entries": len(seen)},
    )


def check_no_stuck_view(
    commits: list[dict[str, Any]],
    rounds_attempted: int,
    view_changes: int = 0,
) -> ValidatorReport:
    """Liveness: attempted rounds must yield progress (a commit or a view-change).

    A "stuck view" is rounds attempted with zero commits and zero view-changes —
    the leader stalled and no one rotated it. Progress is either a commit or a
    recorded view-change request.

    Example::

        assert check_no_stuck_view(commits, rounds_attempted=3, view_changes=1).passed
    """
    if rounds_attempted == 0:
        return ValidatorReport(True, "no rounds attempted", {"rounds": 0})
    progress = len(commits) + view_changes
    if progress == 0:
        return ValidatorReport(
            False,
            (f"stuck view: {rounds_attempted} rounds attempted, 0 commits, 0 view-changes"),
            {"rounds": rounds_attempted},
        )
    return ValidatorReport(
        True,
        f"progress made: {len(commits)} commits, {view_changes} view-changes",
        {"commits": len(commits), "view_changes": view_changes},
    )


def validate_coordination(
    commits: list[dict[str, Any]],
    votes: list[dict[str, Any]],
    verify_fn: Callable[[bytes, SignedVote], bool],
    n: int,
    rounds_attempted: int,
    view_changes: int = 0,
) -> list[ValidatorReport]:
    """Run all four adversarial coordination validators.

    Example::

        reports = validate_coordination(commits, votes, verify, 4, 3)
        assert all(r.passed for r in reports)
    """
    _ = fault_tolerance(n)  # documents the f the quorum derives from
    return [
        check_no_conflicting_commits(commits),
        check_no_forged_quorum(commits, verify_fn, n),
        check_no_equivocation(votes),
        check_no_stuck_view(commits, rounds_attempted, view_changes),
    ]
