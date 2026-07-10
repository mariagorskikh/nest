# SPDX-License-Identifier: Apache-2.0
"""End-to-end ResonanceBFT consensus scenario — the plugin actually drives rounds.

The built-in ``consensus`` scenario is a toy leader/follower vote that ignores the
coordination plugin entirely.  This scenario instead drives the **real**
ResonanceBFT protocol over the simulator's message transport, for as many rounds as
configured, so a town run produces a genuine multi-round consensus trace
(propose → participate → resolve → commit), not just agent-lifecycle events.  It
closes the long-standing "the runner never exercises consensus" gap.

Per round, over the in-memory transport (n agents):

  1. The current view's leader (round-robin ``roster[view % n]``) builds a Task
     carrying each agent's stance text in ``metadata["eval_<aid>"]``, calls
     ``propose`` + ``participate`` to seal its own evaluation, and broadcasts the
     serialized Round (message tag ``R``).
  2. Each follower deserializes the Round, ``participate``s (sealing its pentadic
     evaluation, including a dense semantic vector when an ``embed_fn`` is active),
     and returns just its sealed record (tag ``E``).
  3. The leader collects an n−f quorum of records, ``resolve``s them to a winner, and
     PROPOSES that value (tag ``P``, carrying the fixed record set) instead of committing
     unilaterally.  Every replica re-runs the same deterministic ``resolve`` on that set
     and, if it agrees, BROADCASTS a signed ``prepare`` vote (tag ``V``); each replica
     counts votes locally, and ``2f+1`` distinct prepare votes make it LOCK on the winner
     and broadcast a signed ``commit`` vote; ``2f+1`` commit votes commit the outcome it
     recomputed.  The leader also broadcasts ``status / quorum / tampered / false_agreement``
     (tag ``C``) and the committed Outcome (tag ``O``), and every committing replica emits a
     ``result:<round>:<view>:committed:<winner>`` line.  This two-phase vote (LI-07) makes
     "no two honest agents commit conflicting values for the same round" a literal guarantee,
     not just a property of a deterministic resolve — votes are broadcast and counted locally
     (no forgeable certificate), bound to roster identities and the current round, and a
     STRICT lock forbids a locked replica from ever voting a conflicting winner.  The round
     then advances, so trust adaptation (L3) and the stance audit run across the whole run.

View-change (LI-06): every replica arms a logical-clock timeout (``ctx.schedule``)
when a round/view begins.  If the current leader fails to drive a commit before it
fires, each replica advances to the next view and its round-robin leader re-proposes
— recording the rotation as an ``NV`` (new-view) message, the required trace
evidence.  With an honest, responsive view-0 leader the timeout never fires, so the
happy path is byte-for-byte what a plain leader/follower split produced.  Rotation is
BOUNDED (``max_view_changes`` per round, default 2n) so an unhealable partition ends
in a stuck (un-committed) round rather than looping forever.

Embedding path (``task.config.embed``):
  * ``none`` (default) — bag-of-words semantic axis, zero dependencies.
  * ``demo`` — a deterministic, no-dependency *structured* encoder (below) that has
    the stance-linear-direction property, so the antonym-anchored polarity probe and
    the ``false_agreement`` audit actually fire end-to-end in a town run.
  * ``model2vec`` — real static embeddings (numpy only, no torch) if installed; the
    honest production-shaped path.  Falls back to ``demo`` if the package is absent.

The scenario config exercises every fault mode end-to-end via three knobs (composable):
``silent`` (last k followers never respond — a crash, tolerated at n−f), ``byzantine``
(first k followers submit a TAMPERED record — detected by the seal check, excluded, honest
quorum still commits), and a network partition (the leader cannot gather a quorum → the
view rotates, and with no heal the round stays un-committed).  With no faults the round
simply commits at the n−f quorum.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.scenarios import register_scenario
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Outcome, Round, Task
from pydantic import ValidationError

# Topics cycled across rounds; each is a one-hot dimension in the demo encoder.
_TOPICS = ("budget", "timeout", "rollout", "schema", "indexing", "caching")
_PRO = frozenset(
    {"approve", "accept", "agree", "support", "endorse", "favor", "yes", "proceed", "keep"}
)
_CON = frozenset(
    {"reject", "oppose", "deny", "refuse", "veto", "disagree", "no", "against", "block"}
)

# Default logical-clock view timeout (ticks).  The happy path commits far sooner, so this
# only bounds how long a failed leader may stall a round before rotation.
_DEFAULT_VIEW_TIMEOUT = 40


def _demo_stance_embedding(text: str) -> list[float]:
    """Deterministic, dependency-free encoder with a *linear stance direction*.

    NOT a real language model — a structured stand-in for one.  Layout:
      * dim 0: signed stance (pro − con word count), small magnitude;
      * dims 1..len(_TOPICS): a large one-hot topic component, so two utterances on
        the same topic are cosine-close *regardless of stance* (reproducing the
        topic/stance conflation real embeddings exhibit);
      * 4 trailing hash dims: light texture so unrelated text is not identical.
    This is enough for the antonym-anchored polarity probe to recover stance and for
    the ``false_agreement`` audit to fire.  Swap in ``model2vec`` for a real encoder.
    """
    words = set(re.findall(r"[a-z]+", text.lower()))
    stance = float(len(words & _PRO) - len(words & _CON))
    vec = [0.5 * stance]
    vec.extend(3.0 if topic in words else 0.0 for topic in _TOPICS)
    digest = hashlib.sha256(text.encode()).digest()
    vec.extend(digest[i] / 255.0 for i in range(4))
    return vec


def _resolve_embed_fn(mode: str) -> Callable[[str], list[float]] | None:
    if mode == "demo":
        return _demo_stance_embedding
    if mode == "model2vec":
        import importlib

        try:
            m2v = importlib.import_module("model2vec")  # optional dep, not a core requirement
        except ImportError:
            return _demo_stance_embedding  # graceful fallback keeps the run reproducible
        model: Any = m2v.StaticModel.from_pretrained("minishlab/potion-base-8M")
        return lambda t: [float(x) for x in model.encode([t])[0].tolist()]
    return None


def _roster(config: ScenarioConfig) -> tuple[str, list[str]]:
    follower_count = 0
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "follower":
                follower_count = role.count
    if follower_count == 0:
        follower_count = max(config.agents.count - 1, 1)
    leader = "leader-0"
    return leader, [leader] + [f"follower-{i}" for i in range(follower_count)]


def _round_task(round_no: int, roster: list[str], opinions: dict[str, str] | None = None) -> Task:
    """Build the Task for one round, with each agent's stance text.

    Default (``opinions`` is None): scripted stances — odd rounds everyone approves
    (genuine consensus, false_agreement → 0); even rounds split approve/reject on the
    SAME topic (false consensus the stance audit flags). This is the shipped behavior.

    When ``opinions`` is supplied (aid → free text), each agent seals THAT text instead
    of the scripted stance — the hook the live evidence harness uses to drive the real
    town agents with LLM-generated opinions, without changing the default path or adding
    any runtime dependency.
    """
    topic = _TOPICS[(round_no - 1) % len(_TOPICS)]
    task = Task(
        id=f"rbft-consensus-r{round_no}",
        description=f"ratify the {topic} change for the next release",
        metadata={"expected_participants": len(roster), "round_no": round_no, "topic": topic},
    )
    for i, aid in enumerate(roster):
        if opinions and aid in opinions:
            task.metadata[f"eval_{aid}"] = opinions[aid]
            continue
        unanimous = round_no % 2 == 1
        stance = "approve" if (unanimous or i % 2 == 0) else "reject"
        task.metadata[f"eval_{aid}"] = f"{stance} the {topic} change"
    return task


class ResonanceReplicaAgent(StateMachineAgent):
    """A unified ResonanceBFT replica: leads its views, participates in every round.

    Each replica is the round-robin leader for the views where ``roster[view % n]``
    is itself; otherwise it is a follower.  A logical-clock timeout (``ctx.schedule``)
    rotates leadership when the current leader fails to drive a commit, so a crashed or
    partitioned leader cannot stall a round — every rotation is recorded as an ``NV``
    (new-view) message, the view-change evidence Problem #10 requires.  With an honest,
    responsive view-0 leader the timeout never fires and the round commits at the n−f
    quorum exactly as a plain leader/follower split would.

    Rotation is BOUNDED to ``max_view_changes`` per round (default 2n, a full double
    round-robin).  Past that the round is left un-committed — a genuinely unhealable
    partition — which the stuck-view validator can observe.  ``silent`` models a crash
    (fully inert); ``byzantine`` submits a tampered record.
    """

    def __init__(
        self,
        agent_id: AgentId,
        coord: Any,
        roster: list[str],
        rounds: int,
        opinions: dict[str, str] | None = None,
        *,
        silent: bool = False,
        byzantine: bool = False,
        view_timeout_ticks: int = _DEFAULT_VIEW_TIMEOUT,
        max_view_changes: int | None = None,
    ) -> None:
        self._id = agent_id
        self._me = str(agent_id)
        self._coord = coord
        self._roster = roster
        self._n = len(roster)
        self._rounds = rounds
        self._opinions = opinions  # aid → LLM opinion text (live evidence); None = scripted
        self._silent = silent  # a crashed / partitioned agent — fully inert
        self._byzantine = byzantine  # submits a TAMPERED (broken-seal) record
        self._view_timeout_ticks = view_timeout_ticks
        self._max_view_changes = max_view_changes if max_view_changes is not None else 2 * self._n
        self._round_no = 0  # current task round (1-based); 0 = not started
        self._view = 0  # monotonic leader-election view; leader = roster[view % n]
        self._round_start_view = 0  # the view the current round_no began at (bounds rotation)
        self._round: Round | None = None  # the Round object this replica currently holds
        self._committed: set[int] = set()  # round_nos already committed (self or via O|)
        self._proposed: set[tuple[int, int]] = set()  # (round_no, view) already proposed
        # Distinct senders that announced each (round_no, view) via NV|.  A view is adopted from
        # the network only once f+1 distinct peers vouch for it (so ≥1 is honest) — a single
        # Byzantine peer cannot shove a victim to an arbitrary view.  (Own-timeout advancement
        # is independent of this and drives liveness; NV| quorum only gates catch-up.)
        self._nv_votes: dict[tuple[int, int], set[str]] = {}
        self._f = (self._n - 1) // 3
        self._quorum = 2 * self._f + 1  # BFT vote quorum (2f+1 of n=3f+1)
        # ── two-phase agreement (LI-07) ──────────────────────────────────────
        # Lock: the (view, winner) this replica is committed to defend across view-changes.  Once
        # locked, it prepare-votes ONLY that winner (a STRICT lock, unconditional on view) — the
        # rule that makes cross-view agreement hold ("no two honest commit conflicting").  This
        # trades away automatic post-view-change liveness (re-proposing a locked value needs
        # value-carrying new-view messages, a documented extension); safety holds without it.
        self._locked_view = -1
        self._locked_winner: str | None = None
        # Signed-vote pools the leader aggregates, keyed (round_id, view, phase, winner).
        self._votes: dict[tuple[str, int, str, str], dict[str, tuple[str, str]]] = {}
        # The outcome each replica recomputed from the leader's fixed evaluation set, to commit
        # once the commit-QC forms: (round_id, view) -> Outcome.
        self._value_outcome: dict[tuple[str, int], Outcome] = {}
        self._proposed_value: set[tuple[str, int]] = set()  # (round_id, view) leader broadcast P|
        self._voted: set[tuple[str, int, str]] = set()  # (round_id, view, phase) voted once
        # The winner we were proposed for each (round_id, view): a vote is only counted if it
        # matches a proposed winner, bounding the pool to real proposals (no fabricated winners).
        self._proposed_winner: dict[tuple[str, int], str] = {}
        # Bind each (round_no, view) to the FIRST round_id we accept for it.  A Byzantine leader
        # that mints two Round objects for one view (to gather two conflicting quorums) is refused
        # the second — one decision slot per view, the anti-equivocation key.
        self._view_round_id: dict[tuple[int, int], str] = {}
        self._roster_set = set(roster)  # for O(1) "is this a real roster member" checks on votes
        # A proposal for a FUTURE round_no (the leader commits via its own quorum and proposes the
        # next round before a slower replica has advanced) is buffered and replayed on advance, so
        # the round_no binding does not drop it as a liveness casualty.
        self._pending_round: dict[int, tuple[str, bytes]] = {}

    # ── leadership + timers ──────────────────────────────────────────────────
    def _leader_for(self, view: int) -> str:
        return self._roster[view % self._n]

    def _is_leader(self, view: int) -> bool:
        return self._leader_for(view) == self._me

    async def _arm_timeout(self, ctx: AgentContext) -> None:
        # Self-scheduled logical-clock deadline for the CURRENT (round_no, view).  Delivered
        # back as a T| self-message; a stale one (round/view moved on) is ignored on arrival.
        await ctx.schedule(
            float(self._view_timeout_ticks),
            f"T|{self._round_no}|{self._view}".encode(),
        )

    async def on_start(self, ctx: AgentContext) -> None:
        if self._silent:
            return  # a crashed agent does nothing at all
        self._round_no = 1
        self._round_start_view = self._view
        await self._arm_timeout(ctx)
        if self._is_leader(self._view):
            await self._propose(ctx)

    async def _propose(self, ctx: AgentContext) -> None:
        key = (self._round_no, self._view)
        if key in self._proposed:
            return  # never propose the same (round, view) twice
        self._proposed.add(key)
        task = _round_task(self._round_no, self._roster, self._opinions)
        rnd = await self._coord.propose(task, view_number=self._view, all_agents=self._roster)
        await self._coord.participate(rnd)  # leader seals its own evaluation
        self._round = rnd
        payload = b"R|" + rnd.model_dump_json().encode()
        for aid in self._roster:
            if aid != self._me:
                await ctx.send(AgentId(aid), payload)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if self._silent:
            return
        tag, _, body = payload.partition(b"|")
        if tag == b"T":
            # Timeouts are self-scheduled (ctx.schedule stamps sender == self); a T| that
            # arrives from any other agent is a forged timeout and must be ignored, else a peer
            # could force premature view rotation on demand.
            if str(sender) == self._me:
                await self._handle_timeout(ctx, body)
        elif tag == b"NV":
            await self._handle_new_view(ctx, sender, body)
        elif tag == b"R":
            await self._handle_round(ctx, sender, body)
        elif tag == b"E":
            await self._handle_eval(ctx, sender, body)
        elif tag == b"P":
            await self._handle_propose_value(ctx, sender, body)
        elif tag == b"V":
            await self._handle_vote(ctx, sender, body)
        # tag == b"O" (committed Outcome, observers commit via their own 2f+1 commit quorum),
        # b"C" (human summary), and unknown tags: recorded in the trace but not acted on

    # ── follower side ────────────────────────────────────────────────────────
    async def _handle_round(self, ctx: AgentContext, sender: AgentId, body: bytes) -> None:
        try:
            rnd = Round.model_validate_json(body)
        except (ValueError, ValidationError):
            return  # garbled / schema-invalid proposal — drop, never crash (LI-02)
        view = rnd.metadata.get("view_number", 0)
        if not isinstance(view, int):
            return
        # The proposal must be for the round this replica is CURRENTLY on.  Without this, a
        # replica returning from a partition (still stuck on an old round_no, at a high view)
        # could re-propose that stale round and — because it is the round-robin leader for some
        # high view — overwrite every peer's in-progress later round, wiping real evaluations and
        # letting a stale round masquerade as the current one (safety + liveness violation).
        r_no_meta = rnd.task.metadata.get("round_no")
        if (
            isinstance(r_no_meta, int)
            and self._round_no < r_no_meta <= self._rounds
            and r_no_meta not in self._committed
            and str(sender) == self._leader_for(view)
        ):
            # A proposal for a near-FUTURE round from the legitimate leader (it raced ahead after
            # its own commit): buffer it and replay when we advance to that round, rather than
            # dropping it (liveness).  Authenticated (real leader) and bounded to the configured
            # round count so a peer cannot flood the buffer with fabricated future rounds (DoS).
            self._pending_round[r_no_meta] = (str(sender), body)
            return
        if r_no_meta != self._round_no:
            return
        # Only the round-robin leader for the proposal's view may propose it, and only for the
        # current or a newer view — a stale proposal from a superseded view is dropped, and a
        # non-leader (Byzantine) cannot inject a forged round.
        if str(sender) != self._leader_for(view) or view < self._view:
            return
        # Bound how far a single proposal may jump us forward: a Byzantine agent is the
        # round-robin leader for infinitely many views and must not be able to yank a victim to
        # an arbitrary future view (past the rotation budget) with one crafted R|.
        if view - self._round_start_view > self._max_view_changes:
            return
        if view > self._view:
            self._view = view
            await self._arm_timeout(ctx)
        self._round = rnd
        await self._coord.participate(rnd)
        my_rec = rnd.metadata.get("evaluations", {}).get(self._me)
        if my_rec is None:
            return
        if self._byzantine:
            # Tamper the sealed belief AFTER participate() WITHOUT recomputing the seal, so the
            # leader's resolve() detects the mismatch, flags this record tampered, and still
            # commits with the honest n−f quorum.  A real Byzantine (lying) fault, not a crash.
            my_rec = dict(my_rec)
            my_rec["semantic"] = [x + 999.0 for x in my_rec.get("semantic", [0.0])]
        reply = json.dumps({"aid": self._me, "round_id": rnd.id, "rec": my_rec}).encode()
        await ctx.send(AgentId(self._leader_for(view)), b"E|" + reply)

    # ── leader side ──────────────────────────────────────────────────────────
    async def _handle_eval(self, ctx: AgentContext, sender: AgentId, body: bytes) -> None:
        if self._round is None or not self._is_leader(self._view):
            return
        if self._round_no in self._committed:
            return  # this round already committed once — do not re-commit on a late record
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            return  # garbled body (Byzantine byte-XOR / deeply nested) — drop (LI-02)
        if not isinstance(parsed, dict):
            return
        record = cast("dict[str, Any]", parsed)
        if record.get("round_id") != self._round.id:
            return  # a stale record from a previous round/view
        # Authenticate the claimed aid against the transport sender and require a dict rec
        # (LI-02): blocks a Byzantine follower from crashing resolve() with a non-string aid or
        # non-dict rec, flooding fake aids to inflate the quorum bar, or overwriting a peer's vote.
        aid = record.get("aid")
        rec = record.get("rec")
        if not isinstance(aid, str) or aid != str(sender) or not isinstance(rec, dict):
            return
        evaluations = self._round.metadata.setdefault("evaluations", {})
        evaluations[aid] = rec
        await self._try_propose_value(ctx)

    # ── two-phase agreement (LI-07): propose → prepare vote (lock) → commit vote ──
    #
    # Votes are BROADCAST and each replica counts them locally — there is no separately broadcast
    # quorum certificate for a Byzantine leader to forge.  A vote is counted only when it is
    # (a) signed by its author over (round_id, view, phase, winner), (b) authenticated to the
    # transport sender, (c) from a real roster member, (d) bound to THIS round, and (e) for a
    # winner that was actually proposed for this (round_id, view).  So 2f+1 counted votes are
    # 2f+1 DISTINCT roster members — no single agent can fabricate a quorum or a lock.
    #
    # SAFETY ("no two honest agents commit conflicting values for the same round"): a value
    # commits only with a 2f+1 commit quorum, and every commit-voter first LOCKED on the value via
    # a 2f+1 prepare quorum.  The lock rule is STRICT — once locked on W a replica never
    # prepare-votes a different winner — so any 2f+1 quorum for a second value W' would need f+1
    # lock-holders of W to vote W', which they refuse; with n=3f+1 that quorum cannot form.  (The
    # strict lock trades away automatic LIVENESS after a view-change: re-proposing a locked value
    # in a later view needs value-carrying new-view messages, a documented extension; safety holds
    # regardless.)
    async def _try_propose_value(self, ctx: AgentContext) -> None:
        """Leader: once an n−f quorum of sealed evaluations has arrived, resolve them to a winner
        and PROPOSE that value (tag P|) for the cohort to vote on — instead of committing
        unilaterally.  The fixed evaluation set travels in P| so every replica re-runs the same
        deterministic resolve() and only votes if it independently agrees on the winner."""
        if self._round is None or not self._is_leader(self._view):
            return
        key = (self._round.id, self._view)
        if key in self._proposed_value or self._round_no in self._committed:
            return
        evaluations = self._round.metadata.setdefault("evaluations", {})
        if len(evaluations) < self._n - self._f:
            return  # not enough to resolve the n−f quorum yet
        probe = self._round.model_copy(deep=True)
        outcome = await self._coord.resolve(probe)
        if outcome.metadata["status"] != "committed":
            return  # resolve aborted (partition/tampered-exceeds-f) — nothing to propose; time out
        self._proposed_value.add(key)
        winner = str(outcome.winner)
        payload = {
            "round_no": self._round_no,
            "view": self._view,
            "round_id": self._round.id,
            "winner": winner,
            "evaluations": evaluations,
        }
        await ctx.broadcast(b"P|" + json.dumps(payload).encode())
        # broadcast() excludes self, so the leader accepts its own proposal directly.
        await self._accept_value(
            ctx, self._round.id, self._round_no, self._view, winner, evaluations
        )

    async def _handle_propose_value(self, ctx: AgentContext, sender: AgentId, body: bytes) -> None:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            return
        if not isinstance(parsed, dict):
            return
        p = cast("dict[str, Any]", parsed)
        r_no, view, round_id = p.get("round_no"), p.get("view"), p.get("round_id")
        winner, evals = p.get("winner"), p.get("evaluations")
        if not (isinstance(r_no, int) and isinstance(view, int) and isinstance(round_id, str)):
            return
        if not isinstance(winner, str) or not isinstance(evals, dict):
            return
        # An honest evaluation set never exceeds the roster; a larger one is a resolve() DoS
        # (relational padding is O(len(evals)^2)) — reject it.
        if len(cast("dict[str, Any]", evals)) > self._n:
            return
        # Only the round's leader may propose a value, for the round/view we are on.
        if str(sender) != self._leader_for(view) or r_no != self._round_no or view != self._view:
            return
        if self._round is None or round_id != self._round.id:
            return
        await self._accept_value(ctx, round_id, r_no, view, winner, cast("dict[str, Any]", evals))

    async def _accept_value(
        self,
        ctx: AgentContext,
        round_id: str,
        r_no: int,
        view: int,
        winner: str,
        evaluations: dict[str, Any],
    ) -> None:
        if self._round is None or self._round_no in self._committed or round_id != self._round.id:
            return
        # Anti-equivocation: bind (round_no, view) to ONE round_id.  A Byzantine leader that minted
        # a second Round object for this view (to farm a conflicting quorum) is refused here.
        bound = self._view_round_id.get((r_no, view))
        if bound is not None and bound != round_id:
            return
        # A REPEAT proposal for the same (round_id, view) with a DIFFERENT winner is also
        # equivocation (a leader can pick two different valid n−f subsets of real records that
        # resolve to different winners): reject it, rather than overwriting our proposed-winner /
        # value cache — that overwrite would strand this replica (it already voted the first).
        prior = self._proposed_winner.get((round_id, view))
        if prior is not None and prior != winner:
            return
        # STRICT lock rule (see class-level note): once locked on a winner, never prepare-vote a
        # different one — this is what forbids conflicting cross-view commits.
        if self._locked_winner is not None and winner != self._locked_winner:
            return
        # Independently re-run resolve() on the leader's fixed set: only vote if THIS replica
        # computes the same winner (a lying/equivocating leader cannot get an honest vote for a
        # value the deterministic resolve() does not produce).
        probe = self._round.model_copy(deep=True)
        probe.metadata["evaluations"] = evaluations
        outcome = await self._coord.resolve(probe)
        if outcome.metadata["status"] != "committed" or str(outcome.winner) != winner:
            return
        self._view_round_id[(r_no, view)] = round_id
        self._value_outcome[(round_id, view)] = outcome
        self._proposed_winner[(round_id, view)] = winner
        await self._cast_vote(ctx, round_id, view, "prepare", winner)

    async def _cast_vote(
        self, ctx: AgentContext, round_id: str, view: int, phase: str, winner: str
    ) -> None:
        if (round_id, view, phase) in self._voted:
            return  # one vote per (round, view, phase)
        self._voted.add((round_id, view, phase))
        sig, pub = self._coord.sign_vote(round_id, view, phase, winner)
        vote = json.dumps(
            {
                "round_no": self._round_no,
                "view": view,
                "round_id": round_id,
                "phase": phase,
                "winner": winner,
                "aid": self._me,
                "sig": sig,
                "pub": pub,
            }
        ).encode()
        await ctx.broadcast(b"V|" + vote)
        # broadcast() excludes self, so count our own vote locally.
        await self._record_vote(ctx, self._me, round_id, view, phase, winner, sig, pub)

    async def _handle_vote(self, ctx: AgentContext, sender: AgentId, body: bytes) -> None:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            return
        if not isinstance(parsed, dict):
            return
        v = cast("dict[str, Any]", parsed)
        round_id, view, phase = v.get("round_id"), v.get("view"), v.get("phase")
        r_no, winner = v.get("round_no"), v.get("winner")
        aid, sig, pub = v.get("aid"), v.get("sig"), v.get("pub")
        if not (isinstance(round_id, str) and isinstance(view, int) and isinstance(phase, str)):
            return
        if not (isinstance(r_no, int) and all(isinstance(x, str) for x in (winner, aid, sig, pub))):
            return
        if phase not in ("prepare", "commit"):
            return
        # Roster + round binding: count a vote only from a real member, authenticated to the
        # transport sender, for THIS round, and for a winner we were actually proposed for this
        # (round_id, view) — this bounds the vote pool and defeats fabricated aids / winners.
        if aid != str(sender) or aid not in self._roster_set:
            return
        if self._round is None or round_id != self._round.id or r_no != self._round_no:
            return
        if self._proposed_winner.get((round_id, view)) != winner:
            return
        await self._record_vote(
            ctx,
            cast("str", aid),
            round_id,
            view,
            phase,
            cast("str", winner),
            cast("str", sig),
            cast("str", pub),
        )

    async def _record_vote(
        self,
        ctx: AgentContext,
        aid: str,
        round_id: str,
        view: int,
        phase: str,
        winner: str,
        sig: str,
        pub: str,
    ) -> None:
        # A vote counts only if its ed25519 signature verifies over exactly (round_id, view, phase,
        # winner) — a forged, replayed, or wrong-value vote is dropped.
        if not self._coord.verify_vote(round_id, view, phase, winner, sig, pub):
            return
        pool = self._votes.setdefault((round_id, view, phase, winner), {})
        pool[aid] = (sig, pub)
        if len(pool) < self._quorum:
            return
        if phase == "prepare":
            # 2f+1 prepare votes = a prepare quorum: LOCK on (view, winner) and cast the commit
            # vote once.  The strict lock (in _accept_value) then defends this winner across views.
            if (round_id, view, "commit") not in self._voted:
                if view >= self._locked_view:
                    self._locked_view = view
                    self._locked_winner = winner
                await self._cast_vote(ctx, round_id, view, "commit", winner)
        elif phase == "commit" and self._round_no not in self._committed:
            # 2f+1 commit votes = a commit quorum: commit the outcome THIS replica recomputed.
            await self._commit_value(ctx, round_id, view, winner)

    async def _commit_value(self, ctx: AgentContext, round_id: str, view: int, winner: str) -> None:
        outcome = self._value_outcome.get((round_id, view))
        if outcome is None or self._round is None or self._round_no in self._committed:
            return
        await self._coord.commit(outcome)  # adapts THIS replica's trust for the next round (L3)
        if self._is_leader(view):
            # The leader also broadcasts the Outcome + human summary for the trace / observers;
            # every replica already commits its own recomputed outcome via its own commit quorum.
            await ctx.broadcast(b"O|" + outcome.model_dump_json().encode())
            m = outcome.metadata
            cq = m.get("consensus_quality", {})
            summary = (
                f"round={self._round.task.metadata.get('round_no')} "
                f"topic={self._round.task.metadata.get('topic')} "
                f"status={m['status']} "
                f"quorum={m['quorum_size']}/{m['quorum_needed']} "
                f"tampered={len(m['tampered_agents'])} "
                f"consensus_type={m.get('consensus_type', 'unknown')} "
                f"false_agreement={cq.get('false_agreement_rate', 'n/a')}"
            )
            await ctx.broadcast(b"C|" + summary.encode())
        # Every committing replica announces its own commit — round, view, winner — so the
        # trace-level validators can check "no two honest agents commit conflicting values for the
        # same round" directly (LI-08/09), backed by the 2f+1 commit quorum that authorised it.
        await ctx.broadcast(f"result:{self._round_no}:{view}:committed:{winner}".encode())
        self._committed.add(self._round_no)
        self._round = None
        await self._advance_round(ctx)

    # ── round / view progression ──────────────────────────────────────────────
    async def _advance_round(self, ctx: AgentContext) -> None:
        if self._round_no >= self._rounds:
            return  # all configured rounds done
        self._round_no += 1
        self._round = None
        self._round_start_view = self._view  # rotation budget is per-round
        # The lock defends the value of ONE round; a new round starts unlocked.  The vote pools /
        # value cache are keyed by round_id so they cannot collide across rounds, but clear them
        # to bound memory.
        self._locked_view = -1
        self._locked_winner = None
        self._votes.clear()
        self._value_outcome.clear()
        self._voted.clear()
        self._proposed_value.clear()
        self._proposed_winner.clear()
        self._view_round_id.clear()
        await self._arm_timeout(ctx)
        if self._is_leader(self._view):
            await self._propose(ctx)
        # Replay a proposal for this round that the leader sent before we advanced (buffered above).
        pend = self._pending_round.pop(self._round_no, None)
        if pend is not None:
            await self._handle_round(ctx, AgentId(pend[0]), pend[1])

    async def _handle_timeout(self, ctx: AgentContext, body: bytes) -> None:
        parts = body.split(b"|")
        try:
            r_no = int(parts[0])
            view = int(parts[1])
        except (IndexError, ValueError):
            return
        if r_no != self._round_no or view != self._view or r_no in self._committed:
            return  # stale timeout (round/view moved on) or the round already committed
        await self._advance_view(ctx)

    async def _advance_view(self, ctx: AgentContext) -> None:
        if self._view - self._round_start_view >= self._max_view_changes:
            return  # bounded: stop rotating on an unhealable round (stuck view)
        self._view += 1
        # NV| is the view-change EVIDENCE in the trace (ctx.schedule itself is untraced), and it
        # lets a lagging replica adopt the new view so the cohort stays aligned.
        nv = json.dumps({"round_no": self._round_no, "view": self._view, "by": self._me}).encode()
        for aid in self._roster:
            if aid != self._me:
                await ctx.send(AgentId(aid), b"NV|" + nv)
        await self._arm_timeout(ctx)
        if self._is_leader(self._view):
            await self._propose(ctx)

    async def _handle_new_view(self, ctx: AgentContext, sender: AgentId, body: bytes) -> None:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            return
        if not isinstance(parsed, dict):
            return
        nv = cast("dict[str, Any]", parsed)
        r_no = nv.get("round_no")
        view = nv.get("view")
        if not isinstance(r_no, int) or not isinstance(view, int):
            return
        # Authenticate: the announcement must come FROM the agent it names (no spoofing the
        # "by" field), be for THIS round, be ahead of us, not already committed, and — crucially
        # — stay within the rotation budget so a crafted huge view cannot wedge the round past
        # the point where own-timeout advancement (also bounded) can ever catch up.
        if nv.get("by") != str(sender) or r_no != self._round_no or view <= self._view:
            return
        if r_no in self._committed or view - self._round_start_view > self._max_view_changes:
            return
        # Adopt a network-announced view only once f+1 DISTINCT peers vouch for it, so at least
        # one honest agent genuinely reached it — a single Byzantine peer cannot advance us.
        voters = self._nv_votes.setdefault((r_no, view), set())
        voters.add(str(sender))
        if len(voters) < self._f + 1:
            return
        self._view = view
        await self._arm_timeout(ctx)
        if self._is_leader(self._view):
            await self._propose(ctx)


def resonance_bft_consensus_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create one ResonanceBFT-driving replica per roster slot.

    ``plugins["coordination"]`` is the coordination CLASS the runner resolved; we
    instantiate it per agent (the protocol is per-agent), seeded deterministically,
    told the cluster size for the n−f quorum, and given the configured ``embed_fn``.
    Every agent is a unified :class:`ResonanceReplicaAgent` so any of them can lead a
    view when leadership rotates (``task.config.view_timeout_ticks`` /
    ``max_view_changes`` tune the rotation).
    """
    coord_cls = plugins["coordination"]
    _leader, roster = _roster(config)
    n = len(roster)
    rounds = int(config.task.config.get("rounds", 1))
    embed_fn = _resolve_embed_fn(str(config.task.config.get("embed", "none")))
    view_timeout = int(config.task.config.get("view_timeout_ticks", _DEFAULT_VIEW_TIMEOUT))
    raw_mvc = config.task.config.get("max_view_changes")
    max_view_changes = int(raw_mvc) if raw_mvc is not None else None
    # The last `silent` followers never respond — crashed/partitioned agents whose absence
    # the n−f quorum must tolerate. Demonstrates fault tolerance through the runner.
    silent = int(config.task.config.get("silent", 0))
    silent_ids: set[str] = set(roster[n - silent :]) if silent > 0 else set()
    # `crash_leader`: the view-0 leader (leader-0) is crashed/inert, so it never proposes —
    # the cohort must time out and rotate leadership to commit. Demonstrates view-change +
    # liveness under leader failure (the trace records the rotation as NV messages).
    if bool(config.task.config.get("crash_leader", False)):
        silent_ids.add(roster[0])
    # `byzantine` followers submit a tampered record. They are the FIRST followers (right
    # after the leader) so their tampered records arrive within the quorum-gathering window
    # and resolve() genuinely has to detect+exclude them before it can commit — otherwise the
    # commit-at-n−f liveness would simply race past late Byzantine records. Disjoint from the
    # silent set (which sits at the end): a node is silent XOR lying, never both.
    byzantine = int(config.task.config.get("byzantine", 0))
    byzantine_ids: set[str] = set(roster[1 : 1 + byzantine]) if byzantine > 0 else set()
    # Optional externally-supplied opinions (aid → text). Default None = scripted stances, so
    # the shipped scenario is unchanged; the live evidence harness passes real LLM opinions here.
    raw_opinions = config.task.config.get("opinions")
    opinions: dict[str, str] | None = (
        {str(k): str(v) for k, v in cast("dict[Any, Any]", raw_opinions).items()}
        if isinstance(raw_opinions, dict)
        else None
    )

    agents: dict[AgentId, StateMachineAgent] = {}
    for i, name in enumerate(roster):
        aid = AgentId(name)
        coord = coord_cls(aid, seed=i, expected_n=n, embed_fn=embed_fn)
        agents[aid] = ResonanceReplicaAgent(
            aid,
            coord,
            roster,
            rounds,
            opinions,
            silent=name in silent_ids,
            byzantine=name in byzantine_ids,
            view_timeout_ticks=view_timeout,
            max_view_changes=max_view_changes,
        )
    return agents


register_scenario("resonance_bft_consensus", resonance_bft_consensus_factory)
