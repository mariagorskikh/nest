# SPDX-License-Identifier: Apache-2.0
# Authors: Puja Ivaturi, Mahesh Gottam
"""Screening-evaluation delivery: a screening service hands a signed verdict to a company.

This is the real pipeline of a *verified-screening* business modelled on-protocol.
OGHA is the filter at the front of the funnel: it decides only ``PASSED``/``FAILED``;
candidates who pass move on to the client's own rounds. The interview is a *human,
off-protocol* event **recorded on video**; the video is transcribed, and the report
delivered to the company carries the verdict, the interviewer's gist notes, and
supporting question/answer excerpts **pulled verbatim from the transcript** so the
client can see exactly what was asked and answered::

        company-acme                          (1) posts a job + filtered candidate
             |
             v
        ogha-orchestrator  --publishes-->  interview_recording  (the video)
             |                                      |
             |                             --publishes--> transcript  (parent = recording)
             | (2) assigns (recording + transcript)
             v
        interviewer-7      --publishes-->  evaluation   parents=[transcript]
             |                             (PASSED/FAILED + gist notes + Q&A pulled
             | (3) returns verdict          verbatim from the transcript)
             v
        ogha-orchestrator  --delivers-->   company-acme   (4) verify + attack

Chain of evidence: ``report -> transcript -> recording``. Every verdict is bound by
provenance to a real recording, and every cited Q&A is checkable against the
transcript, so nothing is fabricated.

``company-acme`` plays verifier **and** adversary. As verifier it walks the chain,
scans the report for PII, confirms access, and checks that every cited Q&A is
verbatim in the transcript. As adversary it runs five attacks:

* *Substitution* — republish a tampered verdict (``FAILED``->``PASSED``) under the
  interviewer's name; does it land on the real evaluation's URL?
* *Forged freshness* — republish signed by the attacker; does it read as fresh?
* *Broken provenance* — publish a verdict whose transcript was never published.
* *ACL bypass* — a rival company requests the candidate's private verdict.
* *Fabricated quote* — attach a Q&A the candidate never gave AND tamper the
  transcript to cover it. Content-addressing keeps the report's cited transcript
  immutable, so the lie is caught; a name-addressed store (``datafacts_v1``) lets
  the tampered transcript overwrite the original and the fabrication slips through.

Point ``layers.datafacts`` at ``ogha_facts`` and every validator passes. Point it at
``datafacts_v1`` and the adversarial ones fail.

Every step is reported as a ``|``-delimited trace message, read by
``validate_trace(..., "interview_evaluation_delivery")``.

Example::

    agents = interview_evaluation_delivery_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any, cast

from nest_plugins_reference.datafacts.ogha_facts import (
    VERDICT_FAILED,
    VERDICT_PASSED,
    evaluation_dataset,
    scan_pii,
    ungrounded_quotes,
)

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata

COMPANY = AgentId("company-acme")
OGHA = AgentId("ogha-orchestrator")
INTERVIEWER = AgentId("interviewer-7")
CANDIDATE = AgentId("candidate-a")
RIVAL = AgentId("rival-corp")
_JOB_ID = "job_42"
_CANDIDATE_ID = "candidate-a"
_PHANTOM_PARENT = "df://sha256-" + "0" * 64

# What a speech-to-text system would return for the interview audio (a stand-in for
# the real transcriber). The supporting Q&A below are verbatim excerpts of this.
_TRANSCRIPT = (
    "Interviewer: How would you design a distributed rate limiter? "
    "Candidate: I'd start with a token bucket per client stored in Redis, "
    "and a sliding window log for accuracy. "
    "Interviewer: How do you shard that across regions? "
    "Candidate: Honestly I'm not fully sure; I'd probably just replicate Redis "
    "and hope it stays consistent. "
    "Interviewer: Walk me through idempotency for the payment API. "
    "Candidate: I'd attach an idempotency key per request and dedupe on the server "
    "before applying the charge. "
    "Interviewer: Thanks, that's helpful."
)

# The interviewer's ROUGH notes - their own words, a gist (with PII -> auto-scrubbed).
_RAW_NOTES = (
    "Gave a correct, well-structured answer to the rate-limiter design question "
    "(token-bucket + sliding-window). Clearly weak on cross-region sharding. Solid on "
    "payment idempotency. Volunteered SSN 123-45-6789 and DOB 1994-03-12 during small talk. "
    "Leaning FAIL for a senior role."
)

# Supporting Q&A auto-pulled to back the notes - each must be verbatim in the transcript.
_SUPPORTING_QA: list[dict[str, str]] = [
    {
        "q": "How would you design a distributed rate limiter?",
        "a": (
            "I'd start with a token bucket per client stored in Redis, "
            "and a sliding window log for accuracy."
        ),
        "supports": "backs the note: correct rate-limiter answer",
    },
    {
        "q": "How do you shard that across regions?",
        "a": (
            "Honestly I'm not fully sure; I'd probably just replicate Redis "
            "and hope it stays consistent."
        ),
        "supports": "backs the note: weak on cross-region sharding",
    },
    {
        "q": "Walk me through idempotency for the payment API.",
        "a": (
            "I'd attach an idempotency key per request and dedupe on the server "
            "before applying the charge."
        ),
        "supports": "backs the note: solid on idempotency",
    },
]

# A fabricated answer the candidate never gave. The question IS real (so only the
# answer decides grounding), letting the attack isolate transcript-tampering.
_FABRICATED_Q = "How do you shard that across regions?"
_FABRICATED_A = "I would use consistent hashing with virtual nodes and per-region quorums."


def _parents_of(meta: DatasetMetadata) -> list[str]:
    """Read declared provenance parents off a dataset as plain URL strings.

    Example::

        parents = _parents_of(meta)
    """
    raw: object = meta.metadata.get("parents", [])
    if not isinstance(raw, list):
        return []
    return [str(p) for p in cast("list[Any]", raw)]


class CompanyAgent(StateMachineAgent):
    """Posts the job, then verifies and attacks the delivered evaluation.

    Example::

        company = CompanyAgent(COMPANY, ogha=OGHA)
    """

    def __init__(self, agent_id: AgentId, ogha: AgentId) -> None:
        self._id = agent_id
        self._ogha = ogha

    async def on_start(self, ctx: AgentContext) -> None:
        """Post a job with a pre-filtered candidate to the screening service.

        Example::

            await company.on_start(ctx)
        """
        await ctx.send(self._ogha, f"job_posted|{_JOB_ID}|{_CANDIDATE_ID}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On delivery, verify chain + PII + access + quote-grounding, then run five attacks.

        Example::

            await company.on_message(ctx, OGHA, b"delivery|df://sha256-x|job_42|candidate-a")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("delivery|"):
            return
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        _, eval_url, _job, _cand = msg.split("|", 3)

        root_url = await self._verify_chain(ctx, facts, eval_url)
        await self._scan_pii(ctx, facts, eval_url)
        await self._check_access(ctx, facts, eval_url)
        await self._check_quote_grounding(ctx, facts, eval_url)
        if root_url is not None:
            await self._attack_substitution(ctx, facts, eval_url)
            await self._attack_forged_freshness(ctx, facts, eval_url)
        await self._attack_provenance(ctx, facts)
        await self._attack_fabricated_quote(ctx, facts, eval_url)

    async def _verify_chain(self, ctx: AgentContext, facts: Any, leaf_url: str) -> str | None:
        """Walk the provenance DAG report -> transcript -> recording back to the root.

        Reports ``chain_ok|leaf|depth`` on success (returns the root) or
        ``chain_broken|leaf|url`` if any hop fails to resolve.
        """
        seen: set[str] = set()
        roots: list[str] = []
        stack: list[str] = [leaf_url]
        while stack:
            url = stack.pop()
            if url in seen:
                continue
            seen.add(url)
            try:
                meta: DatasetMetadata = await facts.fetch(url)
            except KeyError:
                await ctx.send(self._id, f"chain_broken|{leaf_url}|{url}".encode())
                return None
            parents = _parents_of(meta)
            if parents:
                stack.extend(parents)
            else:
                roots.append(url)
        await ctx.send(self._id, f"chain_ok|{leaf_url}|{len(seen)}".encode())
        return sorted(roots)[0] if roots else None

    async def _scan_pii(self, ctx: AgentContext, facts: Any, eval_url: str) -> None:
        """Fetch the delivered evaluation and count any PII surviving in the notes."""
        meta = await facts.fetch(eval_url)
        notes = str(meta.metadata.get("notes", ""))
        found = sum(scan_pii(notes).values())
        await ctx.send(self._id, f"pii_scan|{eval_url}|{found}".encode())

    async def _check_access(self, ctx: AgentContext, facts: Any, eval_url: str) -> None:
        """Confirm the ACL: the poster reads content; a rival gets metadata only."""
        meta = await facts.fetch(eval_url)
        acl = {str(x) for x in meta.metadata.get("acl", [])}
        for requester in (self._id, RIVAL):
            expected = "read" if str(requester) in acl or requester == meta.owner else "metadata"
            grant = await facts.request_access(eval_url, requester)
            await ctx.send(
                self._id,
                f"acl_result|{eval_url}|{requester}|{grant.tier}|{expected}".encode(),
            )

    async def _check_quote_grounding(self, ctx: AgentContext, facts: Any, eval_url: str) -> None:
        """Every cited Q&A must be verbatim in the transcript the report was built on."""
        report = await facts.fetch(eval_url)
        transcript_url = str(report.metadata.get("transcript", ""))
        try:
            transcript = await facts.fetch(cast("DataFactsUrl", transcript_url))
        except KeyError:
            await ctx.send(self._id, f"quote_grounding|{eval_url}|0".encode())
            return
        qa = cast("list[dict[str, str]]", report.metadata.get("qa", []))
        missing = ungrounded_quotes(qa, str(transcript.metadata.get("text", "")))
        all_grounded = int(not missing)
        await ctx.send(self._id, f"quote_grounding|{eval_url}|{all_grounded}".encode())

    async def _attack_substitution(self, ctx: AgentContext, facts: Any, eval_url: str) -> None:
        """Republish a tampered verdict (FAILED -> PASSED) under the interviewer's name."""
        real = await facts.fetch(eval_url)
        forged = DatasetMetadata(
            name=real.name,
            owner=real.owner,
            description="tampered-verdict",
            access_tier=real.access_tier,
            metadata={**real.metadata, "verdict": VERDICT_PASSED},
        )
        attacker_url = await facts.publish(forged)
        collided = int(str(attacker_url) == str(eval_url))
        await ctx.send(
            self._id, f"attack_substitution|{eval_url}|{attacker_url}|{collided}".encode()
        )

    async def _attack_forged_freshness(self, ctx: AgentContext, facts: Any, eval_url: str) -> None:
        """Republish the verdict as the attacker while claiming the interviewer owns it."""
        real = await facts.fetch(eval_url)
        forged = DatasetMetadata(
            name=real.name, owner=real.owner, access_tier=real.access_tier, metadata=real.metadata
        )
        forged_url = await facts.publish(forged)
        fresh = await facts.verify_freshness(forged_url)
        await ctx.send(self._id, f"attack_forged_freshness|{forged_url}|{int(fresh)}".encode())

    async def _attack_provenance(self, ctx: AgentContext, facts: Any) -> None:
        """Publish a verdict whose transcript was never published (a fabrication)."""
        phantom = evaluation_dataset(
            interviewer=INTERVIEWER,
            candidate_id=_CANDIDATE_ID,
            job_id=_JOB_ID,
            company_id=str(COMPANY),
            ogha_id=str(OGHA),
            verdict=VERDICT_PASSED,
            notes="fabricated verdict with no interview behind it",
            transcript=cast("DataFactsUrl", _PHANTOM_PARENT),
            qa=[],
        )
        try:
            await facts.publish(phantom)
            rejected = 0
        except ValueError:
            rejected = 1
        await ctx.send(self._id, f"attack_provenance|{_PHANTOM_PARENT}|{rejected}".encode())

    async def _attack_fabricated_quote(self, ctx: AgentContext, facts: Any, eval_url: str) -> None:
        """Fabricate a Q&A the candidate never gave AND tamper the transcript to cover it.

        Under content-addressing the report's cited transcript URL is immutable, so
        re-fetching it still yields the original (no fabricated line) and the lie is
        caught. Under a name-addressed store the tampered transcript overwrites the
        original at the same URL, so the fabricated answer appears "grounded".
        """
        report = await facts.fetch(eval_url)
        transcript_url = str(report.metadata.get("transcript", ""))
        try:
            real_tx = await facts.fetch(cast("DataFactsUrl", transcript_url))
        except KeyError:
            await ctx.send(self._id, f"attack_fabricated_quote|{transcript_url}|0".encode())
            return
        tampered = DatasetMetadata(
            name=real_tx.name,
            owner=real_tx.owner,
            access_tier=real_tx.access_tier,
            metadata={
                **real_tx.metadata,
                "text": str(real_tx.metadata.get("text", "")) + " " + _FABRICATED_A,
            },
        )
        await facts.publish(tampered)
        cited = await facts.fetch(cast("DataFactsUrl", transcript_url))
        fabricated_qa = [{"q": _FABRICATED_Q, "a": _FABRICATED_A}]
        missing = ungrounded_quotes(fabricated_qa, str(cited.metadata.get("text", "")))
        caught = int(bool(missing))
        await ctx.send(self._id, f"attack_fabricated_quote|{transcript_url}|{caught}".encode())


class OghaAgent(StateMachineAgent):
    """The screening service: records + transcribes the interview, assigns it, delivers the verdict.

    Example::

        ogha = OghaAgent(OGHA, interviewer=INTERVIEWER, company=COMPANY)
    """

    def __init__(self, agent_id: AgentId, interviewer: AgentId, company: AgentId) -> None:
        self._id = agent_id
        self._interviewer = interviewer
        self._company = company

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle a job posting (publish recording + transcript, assign) or deliver the verdict.

        Example::

            await ogha.on_message(ctx, COMPANY, b"job_posted|job_42|candidate-a")
        """
        msg = payload.decode("utf-8", errors="replace")
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        if msg.startswith("job_posted|"):
            _, job_id, candidate_id = msg.split("|", 2)
            audience = sorted({str(self._id), str(self._interviewer), str(self._company)})
            recording = DatasetMetadata(
                name=f"interview-recording-{candidate_id}-{job_id}",
                owner=self._id,
                description="Screening interview conducted in person and recorded on video",
                access_tier="restricted",
                metadata={
                    "kind": "interview_recording",
                    "candidate_id": candidate_id,
                    "job_id": job_id,
                    "media": "video",
                    "acl": audience,
                },
            )
            recording_url = await facts.publish(recording)
            transcript = DatasetMetadata(
                name=f"transcript-{candidate_id}-{job_id}",
                owner=self._id,
                description="Transcript of the recorded interview (speech-to-text)",
                access_tier="restricted",
                metadata={
                    "kind": "transcript",
                    "text": _TRANSCRIPT,
                    "candidate_id": candidate_id,
                    "job_id": job_id,
                    "acl": audience,
                    "parents": [str(recording_url)],
                },
            )
            transcript_url = await facts.publish(transcript)
            await ctx.send(
                self._interviewer,
                f"assignment|{job_id}|{candidate_id}|{recording_url}|{transcript_url}".encode(),
            )
        elif msg.startswith("evaluation|"):
            _, eval_url = msg.split("|", 1)
            await ctx.send(
                self._company,
                f"delivery|{eval_url}|{_JOB_ID}|{_CANDIDATE_ID}".encode(),
            )


class InterviewerAgent(StateMachineAgent):
    """Publishes a signed evaluation built on the transcript (verdict + notes + grounded Q&A).

    Example::

        interviewer = InterviewerAgent(INTERVIEWER, ogha=OGHA, verdict=VERDICT_FAILED)
    """

    def __init__(self, agent_id: AgentId, ogha: AgentId, verdict: str) -> None:
        self._id = agent_id
        self._ogha = ogha
        self._verdict = verdict

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On assignment, publish the evaluation grounded in the transcript and return it.

        Example::

            await interviewer.on_message(ctx, OGHA, b"assignment|job_42|candidate-a|df://a|df://b")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("assignment|"):
            return
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        _, job_id, candidate_id, _recording_url, transcript_url = msg.split("|", 4)
        dataset = evaluation_dataset(
            interviewer=self._id,
            candidate_id=candidate_id,
            job_id=job_id,
            company_id=str(COMPANY),
            ogha_id=str(OGHA),
            verdict=self._verdict,
            notes=_RAW_NOTES,
            transcript=cast("DataFactsUrl", transcript_url),
            qa=_SUPPORTING_QA,
            scores={"system_design": 2, "coding": 4, "communication": 4},
        )
        eval_url = await facts.publish(dataset)
        acl = ",".join(str(x) for x in dataset.metadata["acl"])
        await ctx.send(self._id, f"eval_published|{eval_url}|{acl}".encode())
        await ctx.send(self._ogha, f"evaluation|{eval_url}".encode())


class PassiveAgent(StateMachineAgent):
    """A party with an identity but no protocol actions (candidate, rival company).

    Present so the town has real, registered identities for the ACL audience and the
    rival attacker, without driving any messages.

    Example::

        candidate = PassiveAgent(CANDIDATE)
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id


def _per_agent_datafacts(
    datafacts_cls: type[Any],
    identities: dict[AgentId, Any],
    all_ids: list[AgentId],
) -> dict[AgentId, Any]:
    """Give each agent a datafacts handle over one shared store (mirrors provenance builder).

    Plugins taking ``(identity, datasets=, proofs=, clock=)`` (``cid_facts`` /
    ``ogha_facts``) get one handle per agent over shared dicts and a shared logical
    clock, so every party sees the same published datasets. Plugins with a no-arg
    constructor (``datafacts_v1``) get one shared instance.

    Example::

        handles = _per_agent_datafacts(OghaFacts, identities, all_ids)
    """
    shared_datasets: dict[Any, Any] = {}
    shared_proofs: dict[Any, Any] = {}
    shared_clock: Any = None
    shared_instance: Any = None
    handles: dict[AgentId, Any] = {}
    for aid in all_ids:
        try:
            kwargs: dict[str, Any] = {"datasets": shared_datasets, "proofs": shared_proofs}
            if shared_clock is not None:
                kwargs["clock"] = shared_clock
            handle = datafacts_cls(identities[aid], **kwargs)
            shared_clock = getattr(handle, "clock", shared_clock)
            handles[aid] = handle
        except TypeError:
            if shared_instance is None:
                shared_instance = datafacts_cls()
            handles[aid] = shared_instance
    return handles


def interview_evaluation_delivery_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Wire the five-party screening-evaluation delivery pipeline.

    Reads an optional ``config.task.config["verdict"]`` (``PASSED``/``FAILED``,
    default ``FAILED`` — the harder case to protect: a rejection an attacker would
    love to flip to ``PASSED``). Instantiates per-agent identities (each party signs
    as itself) and per-agent datafacts handles over one shared store.

    Example::

        agents = interview_evaluation_delivery_factory(config, plugins)
    """
    all_ids = [COMPANY, OGHA, INTERVIEWER, CANDIDATE, RIVAL]

    task_config = config.task.config or {}
    verdict = task_config.get("verdict", VERDICT_FAILED)

    identity_cls = plugins.get("identity")
    identities: dict[AgentId, Any] = {}
    if identity_cls is not None and isinstance(identity_cls, type):
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"sim-seed")
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    datafacts_cls = plugins.get("datafacts")
    if datafacts_cls is not None and isinstance(datafacts_cls, type) and identities:
        handles = _per_agent_datafacts(datafacts_cls, identities, all_ids)
        for aid, handle in handles.items():
            agent_plugins.setdefault(aid, {})["datafacts"] = handle
    plugins.pop("datafacts", None)
    plugins.pop("identity", None)

    return {
        COMPANY: CompanyAgent(COMPANY, ogha=OGHA),
        OGHA: OghaAgent(OGHA, interviewer=INTERVIEWER, company=COMPANY),
        INTERVIEWER: InterviewerAgent(INTERVIEWER, ogha=OGHA, verdict=verdict),
        CANDIDATE: PassiveAgent(CANDIDATE),
        RIVAL: PassiveAgent(RIVAL),
    }
