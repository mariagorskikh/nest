# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for ResonanceBFT — four BFT safety/liveness checks.

Each validator is designed to:
  - **FAIL** against a protocol that does NOT implement BFT invariants
    (e.g. ``contract_net``, which lacks commitment seals and quorum metadata).
  - **PASS** against ``ResonanceBFT``, which guarantees all four properties.

The validators operate on ``Outcome`` and ``Round`` objects from the simulator
rather than raw JSONL trace events, following the same pattern as the gossip
validators in this package.

Invariants checked
------------------
1. **no_conflicting_commits** — Two ``Outcome`` objects for the same round cannot
   both be "committed" with different winners (safety: agreement).
2. **no_equivocation** — Every sealed commitment in a ``Round`` must verify:
   ``sha256(belief || nonce) == commitment`` over all five sealed belief axes.
   A mismatch means a leader sent a different proposal to different followers
   (equivocation).
3. **no_forged_quorum** — A "committed" ``Outcome`` must satisfy
   ``quorum_size >= quorum_needed``.  A forged quorum is one that bypasses
   the ``n − f`` threshold.
4. **liveness_view_progress** — The view number must not grow beyond
   ``max_view`` aborts without a commit in between.  This detects a stuck
   protocol that never makes progress after healing.

Equivocation accountability
---------------------------
When ``no_equivocation`` catches an agent that signed two distinct commitments for one
``(round_id, aid)``, it also emits an **equivocation conflict certificate**
(``BftValidationResult.certificates``): a self-contained, third-party-verifiable bundle of
the conflicting *signed* records.  ``build_/verify_/collect_equivocation_certificate`` turn
"we detected a liar" into "here is an irrefutable proof anyone can check with only the
agent's public key" — the clean, provable slice of BFT accountability (Sheng et al. 2021,
*BFT Protocol Forensics*; see REFERENCES.md).

Example::

    from nest_plugins_reference.validators.bft_validators import (
        validate_bft_no_conflicting_commits,
        validate_bft_no_equivocation,
        validate_bft_no_forged_quorum,
        validate_bft_liveness_view_progress,
        BftValidationResult,
    )
    result = validate_bft_no_forged_quorum(outcomes)
    assert result.passed, result.detail
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any, cast

from nest_core.types import Outcome, Round

# ── Result type ───────────────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class BftValidationResult:
    """Outcome of a single BFT invariant check.

    Attributes
    ----------
    name:
        Short identifier for the invariant (matches validator function suffix).
    passed:
        ``True`` iff the invariant holds across all provided objects.
    detail:
        Human-readable explanation — what was verified on pass, what violated
        on fail.
    """

    name: str
    passed: bool
    detail: str
    certificates: tuple[dict[str, Any], ...] = ()
    """Transferable equivocation proofs, when this check found any (empty otherwise).

    Each is a third-party-verifiable certificate (see ``build_equivocation_certificate``)
    bundling the conflicting signed records of one equivocating agent.
    """

    def __bool__(self) -> bool:  # noqa: D105
        return self.passed


# ── Internal helpers ──────────────────────────────────────────────────────────


def _is_bft_outcome(outcome: Outcome) -> bool:
    """Return True iff outcome carries ResonanceBFT protocol metadata."""
    meta = outcome.metadata or {}
    return "status" in meta and "quorum_size" in meta and "quorum_needed" in meta


def _is_bft_round(rnd: Round) -> bool:
    """Return True iff round carries ResonanceBFT evaluation metadata."""
    meta = rnd.metadata or {}
    evals = meta.get("evaluations", {})
    if not evals:
        return False
    first = next(iter(evals.values()))
    return "commitment" in first and "nonce" in first and "semantic" in first


def _belief_vec(rec: dict[str, Any]) -> list[float]:
    """Return the belief vector that is sealed at participate() time.

    The commitment covers ALL five immutable belief axes — semantic + affective +
    epistemic + behavioral + relational_sealed (the participate-time relational, never
    the deliberate()-mutated rec["relational"]).  Combined is intentionally excluded
    because deliberate() is allowed to modify it (legitimate position update).  This
    mirrors _protocol._sealed_belief so the validator's seal check matches the protocol's.
    """
    belief: list[float] = []
    for ax in ("semantic", "affective", "epistemic", "behavioral"):
        belief.extend(rec.get(ax, []))
    belief.extend(rec.get("relational_sealed", rec.get("relational", [])))
    return belief


def _verify_commitment(
    belief: list[float], nonce: str, stored: str, basis: list[str] | None = None
) -> bool:
    """Re-derive the SHA-256 commitment and compare to the stored value.

    ``basis`` is the record's bag-of-words ``vocab`` (the semantic coordinate basis), folded in
    exactly as ``_protocol._commitment`` does, so relabelling the basis is caught here too.
    """
    payload = f"{belief}:{nonce}"
    if basis:
        payload += ":" + "\x00".join(basis)
    expected = "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
    return expected == stored


def _verify_eval_signature(rec: dict[str, Any], round_id: str = "", aid: str = "") -> bool:
    """Verify the ed25519 signature over the belief — text, commitment, round_id and aid —
    the same cryptographic authorship check resolve() performs, so the validator is not
    strictly weaker than the protocol it audits.  Binding the commitment catches a swapped
    vector; binding (round_id, aid) catches a record replayed across rounds or swapped
    between agents.  Records that predate signatures (no pubkey/signature) are treated as
    signature-absent and fail the equivocation check.
    """
    from nest_plugins_reference.coordination.resonance_bft._vectors import (
        _belief_digest,
        _verify_signature,
    )

    pubkey = rec.get("pubkey", "")
    signature = rec.get("signature", "")
    if not pubkey or not signature:
        return False
    digest = _belief_digest(rec.get("eval_text", ""), rec.get("commitment", ""), round_id, aid)
    return _verify_signature(pubkey, digest, signature)


# ── Equivocation conflict certificate (transferable accountability) ───────────


def build_equivocation_certificate(
    round_id: str,
    aid: str,
    records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Bundle an agent's conflicting signed records into a transferable proof of equivocation.

    Equivocation — signing two *different* beliefs for the same ``(round_id, aid)`` — is the
    one Byzantine fault that admits clean, provable attribution (Sheng et al. 2021, *BFT
    Protocol Forensics*; see REFERENCES.md). Each ResonanceBFT record carries an ed25519
    signature over ``(eval_text ‖ commitment ‖ round_id ‖ aid)``, so a pair of validly-signed
    records with **distinct commitments** under the **same public key** is irrefutable: the
    key-holder demonstrably signed two contradictory statements.

    Returns a certificate ``{kind, round_id, aid, pubkey, entries:[{commitment, eval_text,
    signature}, …]}`` with ≥ 2 distinct validly-signed commitments, or ``None`` if the records
    do not constitute equivocation (fewer than two distinct, validly-signed commitments under a
    single key). The certificate is **self-contained**: it needs only the agent's public key to
    verify, so any third party — who was never present — can confirm it (``verify_equivocation_
    certificate``) without trusting the accuser. Identity↔pubkey binding is the identity layer's
    job, as elsewhere; this certifies that *the holder of this key* equivocated.
    """
    from nest_plugins_reference.coordination.resonance_bft._vectors import (
        _belief_digest,
        _verify_signature,
    )

    rid, said = str(round_id), str(aid)
    pubkey = ""
    by_commitment: dict[str, dict[str, str]] = {}
    for rec in records:
        pk = rec.get("pubkey", "")
        commitment = rec.get("commitment", "")
        signature = rec.get("signature", "")
        eval_text = rec.get("eval_text", "")
        if not pk or not commitment or not signature:
            continue
        if pubkey and pk != pubkey:
            continue  # a different key is impersonation, not single-agent equivocation
        digest = _belief_digest(eval_text, commitment, rid, said)
        if not _verify_signature(pk, digest, signature):
            continue
        pubkey = pubkey or pk
        by_commitment.setdefault(
            commitment, {"commitment": commitment, "eval_text": eval_text, "signature": signature}
        )

    if not pubkey or len(by_commitment) < 2:
        return None
    return {
        "kind": "equivocation",
        "round_id": rid,
        "aid": said,
        "pubkey": pubkey,
        "entries": [by_commitment[c] for c in sorted(by_commitment)],
    }


def verify_equivocation_certificate(cert: dict[str, Any]) -> bool:
    """Independently verify an equivocation certificate from the certificate alone.

    Returns ``True`` iff it bundles ≥ 2 entries with **distinct commitments**, each carrying a
    valid ed25519 signature over ``(eval_text ‖ commitment ‖ round_id ‖ aid)`` under the
    certificate's single public key. Needs no access to the original rounds and no trust in
    whoever produced it — the math alone convicts. A forged certificate (e.g. a swapped
    commitment string) fails because the signature no longer matches.
    """
    from nest_plugins_reference.coordination.resonance_bft._vectors import (
        _belief_digest,
        _verify_signature,
    )

    if cert.get("kind") != "equivocation":
        return False
    pubkey = str(cert.get("pubkey", ""))
    rid, said = str(cert.get("round_id", "")), str(cert.get("aid", ""))
    raw_entries = cert.get("entries", [])
    if not pubkey or not isinstance(raw_entries, list):
        return False
    entries = cast("list[Any]", raw_entries)
    if len(entries) < 2:
        return False
    distinct: set[str] = set()
    for raw in entries:
        entry = cast("dict[str, Any]", raw)
        commitment = str(entry.get("commitment", ""))
        signature = str(entry.get("signature", ""))
        eval_text = str(entry.get("eval_text", ""))
        if not commitment or not signature:
            return False
        digest = _belief_digest(eval_text, commitment, rid, said)
        if not _verify_signature(pubkey, digest, signature):
            return False
        distinct.add(commitment)
    return len(distinct) >= 2


def collect_equivocation_certificates(rounds: list[Round]) -> tuple[dict[str, Any], ...]:
    """Scan rounds for equivocating agents and return a verified certificate for each.

    Groups every record by ``(round_id, aid)`` across all provided ``Round`` snapshots (two
    snapshots of the same round id — e.g. each side of a partition — are where conflicting
    commitments for one agent show up), then emits a ``build_equivocation_certificate`` for any
    agent that signed ≥ 2 distinct commitments. Only certificates that independently verify are
    returned.
    """
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for rnd in rounds:
        evaluations: dict[str, Any] = rnd.metadata.get("evaluations", {})
        for aid, rec in evaluations.items():
            by_key.setdefault((str(rnd.id), str(aid)), []).append(rec)

    certs: list[dict[str, Any]] = []
    for (rid, aid), recs in by_key.items():
        cert = build_equivocation_certificate(rid, aid, recs)
        if cert is not None and verify_equivocation_certificate(cert):
            certs.append(cert)
    return tuple(certs)


# ── Validator 1: no conflicting commits ───────────────────────────────────────


def validate_bft_no_conflicting_commits(
    outcomes: list[Outcome],
) -> BftValidationResult:
    """No two committed outcomes for one round may fork the SHARED CORE.

    The BFT safety property honest agents actually guarantee here is *approximate agreement
    on a shared core*, not a byte-identical certificate.  Two honest resolvers that see
    different ``n−f`` subsets of the same round legitimately form **different (overlapping)
    quorums** — and, because the winner is only a per-view representative, may even name
    different winners — without any safety violation, *provided every agent visible to BOTH
    of them is classified the same way* (in-quorum in both, or excluded in both).  That is
    exactly what ``test_divergent_quorum_views_do_not_fork_shared_core`` exercises.

    A real fork is therefore either (a) an agent PRESENT in both commits (in its quorum,
    outlier, or tampered set) that one commit puts in the quorum and the other excludes, or
    (b) an IDENTICAL quorum that commits two different winners (same evidence → same decision
    must hold).  Merely-different overlapping quorum sets or representative winners are NOT a
    fork.  (An earlier version fingerprinted the whole ``(winner, quorum set, quorum_needed)``
    certificate and wrongly flagged the legitimate divergent-view case above.)  ``contract_net``
    produces outcomes without a ``status`` key, so the metadata-absent path returns a failure.

    Example::

        result = validate_bft_no_conflicting_commits(outcomes)
        assert result.passed
    """
    name = "bft_no_conflicting_commits"

    non_bft = [o for o in outcomes if not _is_bft_outcome(o)]
    if non_bft:
        ids = [str(o.round_id) for o in non_bft[:3]]
        return BftValidationResult(
            name,
            False,
            f"outcomes missing BFT metadata (protocol mismatch?): {ids}",
        )

    by_round: dict[str, list[Outcome]] = {}
    for outcome in outcomes:
        if outcome.metadata.get("status") == "committed":
            by_round.setdefault(outcome.round_id, []).append(outcome)

    def _quorum(o: Outcome) -> set[str]:
        return {str(a) for a in o.metadata.get("quorum_agents", [])}

    def _present(o: Outcome) -> set[str]:
        m = o.metadata
        return (
            _quorum(o)
            | {str(a) for a in m.get("outlier_agents", [])}
            | {str(a) for a in m.get("tampered_agents", [])}
        )

    conflicts: list[str] = []
    for rid, outs in by_round.items():
        for i in range(len(outs)):
            for j in range(i + 1, len(outs)):
                oa, ob = outs[i], outs[j]
                qa, qb = _quorum(oa), _quorum(ob)
                split = sorted(a for a in _present(oa) & _present(ob) if (a in qa) != (a in qb))
                if split:
                    conflicts.append(
                        f"round {rid}: agents {split} are present in both commits but "
                        f"classified inconsistently (fork on the shared core)"
                    )
                elif qa == qb and str(oa.winner) != str(ob.winner):
                    conflicts.append(
                        f"round {rid}: an identical quorum {sorted(qa)} committed different "
                        f"winners ({oa.winner!s} vs {ob.winner!s})"
                    )

    if conflicts:
        return BftValidationResult(name, False, "; ".join(conflicts))
    return BftValidationResult(
        name,
        True,
        f"no conflicts across {len(by_round)} committed round(s)",
    )


# ── Validator 2: no equivocation ──────────────────────────────────────────────


def validate_bft_no_equivocation(
    rounds: list[Round],
) -> BftValidationResult:
    """Every sealed commitment must verify against the stored five-axis belief.

    Re-derives ``sha256(semantic+affective+epistemic+behavioral+relational_sealed ‖
    nonce)`` and also checks the ed25519 signature.  If a leader equivocates (sends
    different proposals to different followers), at least one agent's commitment will not
    match the belief it claims to have submitted.  ``contract_net`` rounds carry no
    commitment seals, so the metadata-absent path returns a failure.

    Example::

        result = validate_bft_no_equivocation(rounds)
        assert result.passed
    """
    name = "bft_no_equivocation"

    non_bft = [r for r in rounds if not _is_bft_round(r)]
    if non_bft:
        ids = [str(r.id) for r in non_bft[:3]]
        return BftValidationResult(
            name,
            False,
            f"rounds missing BFT commitment seals (protocol mismatch?): {ids}",
        )

    violations: list[str] = []
    checked = 0
    # Cross-round equivocation: an agent that submits TWO different (validly signed)
    # commitments for the SAME round (e.g. one to each side of a partition / to different
    # resolver views) is equivocating, even though each record verifies internally. Track
    # the distinct commitments seen per (round_id, aid) across ALL rounds and flag any with
    # more than one.
    seen_commitments: dict[tuple[str, str], set[str]] = {}
    for rnd in rounds:
        evaluations: dict[str, Any] = rnd.metadata.get("evaluations", {})
        for aid, rec in evaluations.items():
            commitment = rec.get("commitment", "")
            nonce = rec.get("nonce", "")
            belief = _belief_vec(rec)
            checked += 1
            if not _verify_commitment(belief, nonce, commitment, rec.get("vocab")):
                violations.append(f"round {rnd.id} agent {aid}: commitment seal mismatch")
            elif not _verify_eval_signature(rec, str(rnd.id), aid):
                violations.append(f"round {rnd.id} agent {aid}: invalid/absent ed25519 signature")
            else:
                key = (str(rnd.id), str(aid))
                seen_commitments.setdefault(key, set()).add(commitment)

    for (rid, aid), commits in seen_commitments.items():
        if len(commits) > 1:
            violations.append(
                f"round {rid} agent {aid}: EQUIVOCATION — {len(commits)} distinct signed "
                f"commitments for the same round"
            )

    if violations:
        # Attach transferable proofs for the cleanly-attributable case (equivocation), so a
        # caller can act on / forward an irrefutable certificate rather than just a message.
        return BftValidationResult(
            name,
            False,
            "; ".join(violations[:5]),
            certificates=collect_equivocation_certificates(rounds),
        )

    return BftValidationResult(
        name,
        True,
        f"all {checked} commitment seal(s) verified",
    )


# ── Validator 3: no forged quorum ─────────────────────────────────────────────


def validate_bft_no_forged_quorum(
    outcomes: list[Outcome],
) -> BftValidationResult:
    """A committed outcome must have quorum_size >= quorum_needed (n − f).

    A "forged" quorum commits with fewer than n − f signatures, violating BFT
    safety.  ``contract_net`` outcomes lack quorum_size/quorum_needed metadata
    entirely, so the metadata-absent path returns a failure.

    Example::

        result = validate_bft_no_forged_quorum(outcomes)
        assert result.passed
    """
    name = "bft_no_forged_quorum"

    non_bft = [o for o in outcomes if not _is_bft_outcome(o)]
    if non_bft:
        ids = [str(o.round_id) for o in non_bft[:3]]
        return BftValidationResult(
            name,
            False,
            f"outcomes missing BFT quorum metadata (protocol mismatch?): {ids}",
        )

    violations: list[str] = []
    checked = 0
    for outcome in outcomes:
        meta = outcome.metadata
        if meta.get("status") != "committed":
            continue
        checked += 1
        # RECOMPUTE the quorum size and threshold from the actual membership, instead
        # of trusting the self-reported quorum_size/quorum_needed — a forged quorum
        # could simply lie about those numbers.
        quorum_agents = meta.get("quorum_agents", [])
        outlier_agents = meta.get("outlier_agents", [])
        tampered_agents = meta.get("tampered_agents", [])
        # total_participants is itself self-reported, so a forger could UNDER-report it
        # to shrink f and lower the quorum bar.  Establish an independent floor from the
        # membership lists: every agent that actually appears (quorum ∪ outlier ∪
        # tampered) is a real participant the committer cannot deny.  We take the max of
        # the claimed n and this observed floor, so under-reporting is either caught (n
        # disagrees → tampering below) or harmless (the floor restores the real bar).
        # NOTE: this still cannot recover the *configured* membership when honest nodes
        # are partitioned away (expected_n > present); that defence lives in the protocol
        # (max(present, expected_n)) and is unit-tested there.
        observed_n = len(set(quorum_agents) | set(outlier_agents) | set(tampered_agents))
        claimed_n = meta.get("total_participants", 0)
        claimed_n = claimed_n if isinstance(claimed_n, int) else 0
        n = max(claimed_n, observed_n)
        f = (n - 1) // 3 if n > 0 else 0
        # Count DISTINCT quorum members: padding the list with duplicates must not inflate
        # the quorum size and let a sub-quorum masquerade as meeting the n − f bar (LI-05/V2).
        qs_real = len(set(quorum_agents))
        qn_real = n - f if n > 0 else meta.get("quorum_needed", 1)
        qs_claimed = meta.get("quorum_size", 0)
        qn_claimed = meta.get("quorum_needed", 1)
        if claimed_n < observed_n:
            violations.append(
                f"round {outcome.round_id}: total_participants {claimed_n} < observed "
                f"{observed_n} distinct agents (under-reported membership)"
            )
        elif qs_claimed != qs_real or qn_claimed != qn_real:
            violations.append(
                f"round {outcome.round_id}: claimed quorum {qs_claimed}/{qn_claimed} "
                f"!= recomputed {qs_real}/{qn_real} (metadata tampering)"
            )
        elif qs_real < qn_real:
            violations.append(
                f"round {outcome.round_id}: committed with {qs_real}/{qn_real} (forged quorum)"
            )

    if violations:
        return BftValidationResult(name, False, "; ".join(violations))

    return BftValidationResult(
        name,
        True,
        f"all {checked} committed outcome(s) satisfy quorum_size >= quorum_needed",
    )


# ── Validator 4: liveness — view makes progress ───────────────────────────────


def validate_bft_liveness_view_progress(
    outcomes: list[Outcome],
    *,
    max_consecutive_aborts: int = 3,
) -> BftValidationResult:
    """View number must not grow beyond *max_consecutive_aborts* without a commit.

    A stuck protocol keeps aborting (view_number climbs) but never commits.
    This detects a liveness failure: after a partition heals, the protocol
    must eventually make progress.

    ``contract_net`` outcomes carry no view_number metadata, so the metadata-
    absent path returns a failure.

    Parameters
    ----------
    outcomes:
        Ordered list of outcomes (earliest first) from the simulator run.
    max_consecutive_aborts:
        Maximum number of consecutive aborts before the validator reports a
        liveness violation.  Default 3 (generous for slow simulators).

    Example::

        result = validate_bft_liveness_view_progress(outcomes, max_consecutive_aborts=3)
        assert result.passed
    """
    name = "bft_liveness_view_progress"

    non_bft = [o for o in outcomes if not _is_bft_outcome(o)]
    if non_bft:
        ids = [str(o.round_id) for o in non_bft[:3]]
        return BftValidationResult(
            name,
            False,
            f"outcomes missing BFT view metadata (protocol mismatch?): {ids}",
        )

    consecutive_aborts = 0
    max_seen = 0
    committed_count = 0

    for outcome in outcomes:
        meta = outcome.metadata
        status = meta.get("status", "unknown")
        view = meta.get("view_number", 0)
        max_seen = max(max_seen, view)

        if status == "committed":
            committed_count += 1
            consecutive_aborts = 0
        else:
            consecutive_aborts += 1
            if consecutive_aborts > max_consecutive_aborts:
                return BftValidationResult(
                    name,
                    False,
                    f"{consecutive_aborts} consecutive aborts (max view={max_seen}); "
                    f"protocol appears stuck — liveness violated",
                )

    return BftValidationResult(
        name,
        True,
        f"{committed_count} commit(s); max view={max_seen}; "
        f"no run of > {max_consecutive_aborts} consecutive aborts",
    )


def validate_genuine_consensus(
    outcomes: list[Outcome],
    *,
    allow_fragile: bool = False,
    require_deliberation: bool = False,
) -> BftValidationResult:
    """Validate that committed outcomes reflect genuine deliberative consensus.

    A committed outcome is **not genuine** if its ``consensus_type`` (set by
    :meth:`ResonanceBFT.deliberate`) signals that agreement was reached through
    a process that does not reflect authentic alignment:

    * ``"capitulated"`` — one side moved almost entirely while the other held
      still.  The quorum threshold was met, but the minority was effectively
      coerced into agreement rather than persuaded.
    * ``"coerced"`` — convergence was too fast relative to the trust levels
      of the participants, suggesting social pressure rather than genuine
      persuasion.
    * ``"logrolled"`` — axes moved in opposite directions, indicating a
      cross-axis trade rather than holistic alignment.  Logrolling is not
      inherently illegitimate, but it means the pentadic vector does not
      reflect a single coherent position.
    * ``"fragile"`` — the quorum threshold was barely met; a small perturbation
      would break consensus.  Flagged only when ``allow_fragile=False``
      (default).

    ``"genuine"`` always passes.  ``"unknown"`` (deliberate() was not called, so
    authenticity was never measured) passes by default but is flagged when
    ``require_deliberation=True`` — use that to assert every commit had its consensus
    quality actually evaluated, rather than silently accepting un-measured commits.
    ``"polarized"`` and ``"deadlock"`` cannot be committed outcomes, so they
    are not checked here; see ``validate_bft_no_conflicting_commits``.

    This validator **fails** against ``contract_net`` outcomes (missing
    ``conflict`` metadata) and passes against honest ResonanceBFT runs where
    ``deliberate()`` was called.

    Parameters
    ----------
    outcomes:
        List of ``Outcome`` objects to check.
    allow_fragile:
        If ``True``, fragile consensus is not flagged (default ``False``).

    Example::

        result = validate_genuine_consensus(outcomes)
        assert result.passed, result.detail
        # "3 committed outcomes: 3 genuine, 0 suspicious"

        result = validate_genuine_consensus(contract_net_outcomes)
        assert not result.passed
        # "outcomes missing conflict metadata (protocol mismatch?)"
    """
    name = "validate_genuine_consensus"

    if not outcomes:
        return BftValidationResult(name, True, "no outcomes to validate")

    # deadlock/polarized are included: although the trajectory classifier derives them from
    # the deliberation mean_sim, the COMMIT gate uses the per-axis pentadic similarity — the
    # two can disagree, so a committed outcome CAN carry a deadlock/polarized label, and that
    # is exactly the non-genuine consensus this validator must flag.
    suspicious_types = {"capitulated", "coerced", "logrolled", "deadlock", "polarized"}
    if not allow_fragile:
        suspicious_types.add("fragile")

    # Check for protocol mismatch across ALL outcomes (not just committed)
    if not any("conflict" in o.metadata for o in outcomes):
        return BftValidationResult(
            name,
            False,
            "outcomes missing conflict metadata (protocol mismatch?)",
        )

    committed = [o for o in outcomes if o.metadata.get("status") == "committed"]
    if not committed:
        return BftValidationResult(name, True, "no committed outcomes to validate")

    flagged: list[str] = []
    genuine_count = 0

    for outcome in committed:
        ctype = outcome.metadata.get("consensus_type", "unknown")
        if ctype in suspicious_types or (require_deliberation and ctype == "unknown"):
            flagged.append(f"round {outcome.round_id[:8]}: consensus_type={ctype!r}")
        else:
            genuine_count += 1

    if flagged:
        return BftValidationResult(
            name,
            False,
            f"{len(flagged)} committed outcome(s) with suspicious consensus_type: "
            + "; ".join(flagged),
        )

    return BftValidationResult(
        name,
        True,
        f"{len(committed)} committed outcome(s): {genuine_count} genuine, 0 suspicious",
    )


def validate_no_axis_deadlock(
    outcomes: list[Outcome],
) -> BftValidationResult:
    """Validate that no committed outcome hides an unresolved axis deadlock.

    An axis deadlock occurs when agents have split into two opposing clusters
    on at least one dimension (inter-cluster cosine similarity < −0.1).
    A committed outcome with a hidden deadlock means the quorum threshold
    was met globally, but a structural conflict was masked by the aggregate
    score — the two clusters agree on enough other axes to pass the pentadic
    test while remaining genuinely opposed on one.

    Flags any committed outcome where
    ``outcome.metadata["conflict"]["deadlocked_axes"]`` is non-empty.

    This validator **fails** against ``contract_net`` outcomes and passes
    against honest ResonanceBFT runs with no polarized axes.

    Example::

        result = validate_no_axis_deadlock(outcomes)
        assert result.passed, result.detail
        # "7 outcomes checked; 0 hidden axis deadlocks"
    """
    name = "validate_no_axis_deadlock"

    if not outcomes:
        return BftValidationResult(name, True, "no outcomes to validate")

    if not any("conflict" in o.metadata for o in outcomes):
        return BftValidationResult(
            name,
            False,
            "outcomes missing conflict metadata (protocol mismatch?)",
        )

    hidden_deadlocks: list[str] = []

    for outcome in outcomes:
        conflict = outcome.metadata.get("conflict", {})
        deadlocked = conflict.get("deadlocked_axes", [])
        status = outcome.metadata.get("status", "unknown")
        if status == "committed" and deadlocked:
            axes = [d["axis"] for d in deadlocked]
            hidden_deadlocks.append(f"round {outcome.round_id[:8]}: deadlock on {axes}")

    if hidden_deadlocks:
        return BftValidationResult(
            name,
            False,
            f"{len(hidden_deadlocks)} committed outcome(s) hiding axis deadlock: "
            + "; ".join(hidden_deadlocks),
        )

    return BftValidationResult(
        name,
        True,
        f"{len(outcomes)} outcome(s) checked; 0 hidden axis deadlocks",
    )
