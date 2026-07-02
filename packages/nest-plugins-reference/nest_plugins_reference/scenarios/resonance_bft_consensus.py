# SPDX-License-Identifier: Apache-2.0
"""End-to-end ResonanceBFT consensus scenario — the plugin actually drives rounds.

The built-in ``consensus`` scenario is a toy leader/follower vote that ignores the
coordination plugin entirely.  This scenario instead drives the **real**
ResonanceBFT protocol over the simulator's message transport, for as many rounds as
configured, so a town run produces a genuine multi-round consensus trace
(propose → participate → resolve → commit), not just agent-lifecycle events.  It
closes the long-standing "the runner never exercises consensus" gap.

Per round, over the in-memory transport (n agents):

  1. The leader builds a Task carrying each agent's stance text in
     ``metadata["eval_<aid>"]``, calls ``propose`` + ``participate`` to seal its own
     evaluation, and broadcasts the serialized Round (message tag ``R``).
  2. Each follower deserializes the Round, ``participate``s (sealing its pentadic
     evaluation, including a dense semantic vector when an ``embed_fn`` is active),
     and returns just its sealed record (tag ``E``).
  3. The leader collects every record, ``resolve``s the n−f quorum, ``commit``s
     (which adapts trust for the next round), and broadcasts the protocol's own
     ``status / quorum / tampered / false_agreement`` (tag ``C``).  Then it starts
     the next round, so trust adaptation (L3) and the stance audit are exercised
     across the whole run.

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
quorum still commits), and a network partition (the leader cannot gather a quorum → no
commit).  With no faults the round simply commits at the n−f quorum.
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

# Topics cycled across rounds; each is a one-hot dimension in the demo encoder.
_TOPICS = ("budget", "timeout", "rollout", "schema", "indexing", "caching")
_PRO = frozenset(
    {"approve", "accept", "agree", "support", "endorse", "favor", "yes", "proceed", "keep"}
)
_CON = frozenset(
    {"reject", "oppose", "deny", "refuse", "veto", "disagree", "no", "against", "block"}
)


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


class ResonanceLeaderAgent(StateMachineAgent):
    """Proposes each round, gathers sealed evaluations, resolves + commits, repeats."""

    def __init__(
        self,
        agent_id: AgentId,
        coord: Any,
        roster: list[str],
        rounds: int,
        opinions: dict[str, str] | None = None,
    ) -> None:
        self._id = agent_id
        self._coord = coord
        self._roster = roster
        self._rounds = rounds
        self._opinions = opinions  # aid → LLM opinion text (live evidence); None = scripted
        self._round_no = 0
        self._round: Round | None = None

    async def _start_round(self, ctx: AgentContext) -> None:
        self._round_no += 1
        task = _round_task(self._round_no, self._roster, self._opinions)
        rnd = await self._coord.propose(task, all_agents=self._roster)
        await self._coord.participate(rnd)  # leader seals its own evaluation
        self._round = rnd
        payload = b"R|" + rnd.model_dump_json().encode()
        for aid in self._roster:
            if aid != str(self._id):
                await ctx.send(AgentId(aid), payload)

    async def on_start(self, ctx: AgentContext) -> None:
        await self._start_round(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        tag, _, body = payload.partition(b"|")
        if tag != b"E" or self._round is None:
            return
        record = json.loads(body)
        if record.get("round_id") != self._round.id:
            return  # a stale record from a previous round
        evaluations = self._round.metadata.setdefault("evaluations", {})
        evaluations[record["aid"]] = record["rec"]

        # Resolve at the n−f QUORUM, not at unanimity: as soon as enough sealed
        # evaluations to possibly form the quorum have arrived, try to resolve and
        # commit the FIRST time it succeeds. This is real BFT liveness — the round
        # commits without waiting for slow or silent (crashed/partitioned) agents, so
        # the runner genuinely demonstrates the n−f fault tolerance. If the quorum is
        # not yet met and stragglers may still arrive, keep waiting; once everyone has
        # responded, finalize whatever resolve() decides (commit or abort).
        n = len(self._roster)
        quorum_needed = n - (n - 1) // 3
        present = len(evaluations)
        if present < quorum_needed:
            return
        # resolve() is NOT pure: on the non-commit branch it bumps view_number and appends to
        # `aborts` on the round handed to it. We call it SPECULATIVELY here — a probe at the
        # n−f quorum, before every straggler is in, that we may abandon (below) to wait for
        # more. Resolve on a deep copy so those side effects never leak into the shared round:
        # the committed outcome then carries a clean view_number/abort history, and each probe
        # (incl. its trust-free auto-deliberation) is recomputed fresh from the CURRENT
        # evaluation set instead of a cached early subset.
        probe = self._round.model_copy(deep=True)
        outcome = await self._coord.resolve(probe)
        if outcome.metadata["status"] != "committed" and present < n:
            return  # a straggler might still complete the quorum
        await self._coord.commit(outcome)  # adapts the leader's trust for the next round (L3)
        # Broadcast the committed Outcome so EVERY agent applies commit() and adapts its own
        # trust — genuine multi-agent L3 adaptation, not leader-only.
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

        self._round = None
        if self._round_no < self._rounds:
            await self._start_round(ctx)


class ResonanceFollowerAgent(StateMachineAgent):
    """Seals its own pentadic evaluation on each proposed round and returns it."""

    def __init__(
        self,
        agent_id: AgentId,
        coord: Any,
        leader: str,
        *,
        silent: bool = False,
        byzantine: bool = False,
    ) -> None:
        self._id = agent_id
        self._coord = coord
        self._leader = leader
        self._silent = silent  # a crashed / partitioned agent that never responds
        self._byzantine = byzantine  # submits a TAMPERED (broken-seal) record

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if self._silent:
            return  # simulate an unresponsive agent — the round must still commit at n−f
        tag, _, body = payload.partition(b"|")
        # Only the round's leader legitimately PROPOSES rounds (R|) and broadcasts the
        # committed Outcome (O|).  Reject those control messages from any other sender: a
        # Byzantine follower must not be able to inject a forged round, or a forged committed
        # Outcome that would poison every follower's L3 trust/reputation via commit().  (L1
        # safety never depended on this — the commit uses fixed weights/threshold — but L3
        # shapes future deliberation, so we authenticate the source of control messages.)
        if tag in (b"O", b"R") and str(sender) != self._leader:
            return
        if tag == b"O":
            # The leader's committed Outcome: apply commit() locally so THIS agent adapts its
            # own trust (L3), making the adaptation genuinely multi-agent, not leader-only.
            await self._coord.commit(Outcome.model_validate_json(body))
            return
        if tag != b"R":
            return
        rnd = Round.model_validate_json(body)
        await self._coord.participate(rnd)
        my_id = str(ctx.agent_id)
        record = rnd.metadata.get("evaluations", {}).get(my_id)
        if record is None:
            return
        if self._byzantine:
            # Tamper the sealed belief AFTER participate() WITHOUT recomputing the SHA-256
            # seal / ed25519 signature. The leader's resolve() must detect the seal mismatch,
            # flag this record `tampered`, exclude it from the centroid, and still commit with
            # the honest n−f quorum. This is a real Byzantine (lying) fault, not a crash.
            record = dict(record)
            record["semantic"] = [x + 999.0 for x in record.get("semantic", [0.0])]
        reply = json.dumps({"aid": my_id, "round_id": rnd.id, "rec": record}).encode()
        await ctx.send(AgentId(self._leader), b"E|" + reply)


def resonance_bft_consensus_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create one ResonanceBFT-driving agent per roster slot.

    ``plugins["coordination"]`` is the coordination CLASS the runner resolved; we
    instantiate it per agent (the protocol is per-agent), seeded deterministically,
    told the cluster size for the n−f quorum, and given the configured ``embed_fn``.
    """
    coord_cls = plugins["coordination"]
    leader, roster = _roster(config)
    n = len(roster)
    rounds = int(config.task.config.get("rounds", 1))
    embed_fn = _resolve_embed_fn(str(config.task.config.get("embed", "none")))
    # The last `silent` followers never respond — crashed/partitioned agents whose absence
    # the n−f quorum must tolerate. Demonstrates fault tolerance through the runner.
    silent = int(config.task.config.get("silent", 0))
    silent_ids: set[str] = set(roster[n - silent :]) if silent > 0 else set()
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
        if name == leader:
            agents[aid] = ResonanceLeaderAgent(aid, coord, roster, rounds, opinions)
        else:
            agents[aid] = ResonanceFollowerAgent(
                aid,
                coord,
                leader,
                silent=name in silent_ids,
                byzantine=name in byzantine_ids,
            )
    return agents


register_scenario("resonance_bft_consensus", resonance_bft_consensus_factory)
