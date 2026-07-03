# SPDX-License-Identifier: Apache-2.0
# Authors: Puja Ivaturi, Mahesh Gottam
"""Screening-evaluation delivery: a screening service hands a signed verdict to a company.

This is the real pipeline of a *verified-screening* business modelled on-protocol.
OGHA is the filter at the front of the funnel: it decides only ``PASSED``/``FAILED``;
candidates who pass move on to the client's own rounds. The interview itself is a
*human, off-protocol* event that is **recorded on video**; what goes on the wire is
the recording reference, the evaluation artifact, and its delivery::

        company-acme                         (1) posts a job + filtered candidate
             |
             v
        ogha-orchestrator   --publishes-->   interview_recording  (the video: the
             |                               screening actually happened)
             | (2) assigns
             v
        interviewer-7       --publishes-->   evaluation           parents=[recording]
             |                               (PASSED/FAILED verdict + report drawn
             | (3) returns verdict            from the recording)
             v
        ogha-orchestrator   --delivers-->    company-acme         (4) verify + attack

Every verdict is bound by provenance to the recording it came from, so nothing is
fabricated: there is no evaluation without a real, published interview behind it.

``company-acme`` plays verifier **and** adversary. As verifier it walks the
provenance chain back to the interview recording, scans the delivered content for
PII, and confirms it (an authorized reader) gets ``read`` access. As adversary it
runs four attacks an untrustworthy pipeline would silently allow:

* *Substitution* — republish a **tampered verdict** under the interviewer's exact
  name; does it land on the real evaluation's URL? (A ``FAILED`` flipped to
  ``PASSED`` with no new URL is a screening-integrity forgery.)
* *Forged freshness* — republish the verdict signed by the attacker while
  claiming the interviewer as owner; does it read as freshly attested?
* *Broken provenance* — publish an evaluation whose interview recording was never
  published (a verdict with no real interview behind it); is it rejected?
* *ACL bypass* — a **rival company** that did not post the job requests the
  candidate's private verdict; do they get ``read`` (a leak) or ``metadata`` only?

Point ``layers.datafacts`` at ``ogha_facts`` and every validator passes. Point it
at ``datafacts_v1`` and they fail: that reference plugin is name-addressed (so the
tampered verdict overwrites the real one), trusts any recent writer for freshness,
has no provenance concept, keeps raw PII in the permanent record, and grants
``read`` to whoever asks (so the rival reads the verdict).

Every step is reported as a ``|``-delimited trace message (``:`` collides with the
``df://`` URL scheme), read by ``validate_trace(..., "interview_evaluation_delivery")``.

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
)

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata

# A candidate's own words in a screening write-up routinely carry PII that has no
# business in a permanent, company-readable record. This report embeds four
# categories (salary, e-mail, phone, DOB) so the redaction validator has teeth.
_RAW_REPORT = (
    "Candidate performed strongly on system design and coding in the recording. "
    "Currently earning $185,000 and reachable at alex.candidate@example.com "
    "or 555-987-6543. DOB 1994-03-12. Clears screening."
)
_PHANTOM_PARENT = "df://sha256-" + "0" * 64

COMPANY = AgentId("company-acme")
OGHA = AgentId("ogha-orchestrator")
INTERVIEWER = AgentId("interviewer-7")
CANDIDATE = AgentId("candidate-a")
RIVAL = AgentId("rival-corp")
_JOB_ID = "job_42"
_CANDIDATE_ID = "candidate-a"


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
        """On delivery, verify the chain + PII + access, then run four attacks.

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

        record_url = await self._verify_chain(ctx, facts, eval_url)
        await self._scan_pii(ctx, facts, eval_url)
        await self._check_access(ctx, facts, eval_url)
        if record_url is not None:
            await self._attack_substitution(ctx, facts, eval_url)
            await self._attack_forged_freshness(ctx, facts, eval_url)
        await self._attack_provenance(ctx, facts)

    async def _verify_chain(self, ctx: AgentContext, facts: Any, leaf_url: str) -> str | None:
        """Walk the provenance DAG from the evaluation back to the interview record.

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
        """Fetch the delivered evaluation and count any PII that survived into the hash."""
        meta = await facts.fetch(eval_url)
        report = str(meta.metadata.get("report", ""))
        found = sum(scan_pii(report).values())
        await ctx.send(self._id, f"pii_scan|{eval_url}|{found}".encode())

    async def _check_access(self, ctx: AgentContext, facts: Any, eval_url: str) -> None:
        """Confirm the ACL: the poster reads content; a rival gets metadata only.

        ``expected`` is derived from the dataset's own content-bound ``acl``
        (present under every plugin, since it is stored metadata), so the check
        is independent of the plugin under test. ``actual`` is whatever tier the
        plugin's ``request_access`` returns. A mismatch is the leak.
        """
        meta = await facts.fetch(eval_url)
        acl = {str(x) for x in meta.metadata.get("acl", [])}
        for requester in (self._id, RIVAL):
            expected = "read" if str(requester) in acl or requester == meta.owner else "metadata"
            grant = await facts.request_access(eval_url, requester)
            await ctx.send(
                self._id,
                f"acl_result|{eval_url}|{requester}|{grant.tier}|{expected}".encode(),
            )

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
        """Publish a verdict whose interview recording was never published (a fabrication)."""
        phantom = evaluation_dataset(
            interviewer=INTERVIEWER,
            candidate_id=_CANDIDATE_ID,
            job_id=_JOB_ID,
            company_id=str(COMPANY),
            ogha_id=str(OGHA),
            verdict=VERDICT_PASSED,
            report="fabricated verdict with no interview behind it",
            interview_recording=cast("DataFactsUrl", _PHANTOM_PARENT),
        )
        try:
            await facts.publish(phantom)
            rejected = 0
        except ValueError:
            rejected = 1
        await ctx.send(self._id, f"attack_provenance|{_PHANTOM_PARENT}|{rejected}".encode())


class OghaAgent(StateMachineAgent):
    """The screening service: records the interview, assigns it, and delivers the verdict.

    Example::

        ogha = OghaAgent(OGHA, interviewer=INTERVIEWER, company=COMPANY)
    """

    def __init__(self, agent_id: AgentId, interviewer: AgentId, company: AgentId) -> None:
        self._id = agent_id
        self._interviewer = interviewer
        self._company = company

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle a job posting (publish record + assign) or a returned verdict (deliver).

        Example::

            await ogha.on_message(ctx, COMPANY, b"job_posted|job_42|candidate-a")
        """
        msg = payload.decode("utf-8", errors="replace")
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        if msg.startswith("job_posted|"):
            _, job_id, candidate_id = msg.split("|", 2)
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
                    "acl": sorted({str(self._id), str(self._interviewer), str(self._company)}),
                },
            )
            recording_url = await facts.publish(recording)
            await ctx.send(
                self._interviewer,
                f"assignment|{job_id}|{candidate_id}|{recording_url}".encode(),
            )
        elif msg.startswith("evaluation|"):
            _, eval_url = msg.split("|", 1)
            await ctx.send(
                self._company,
                f"delivery|{eval_url}|{_JOB_ID}|{_CANDIDATE_ID}".encode(),
            )


class InterviewerAgent(StateMachineAgent):
    """Publishes a signed evaluation grounded in (parented on) the interview recording.

    Example::

        interviewer = InterviewerAgent(INTERVIEWER, ogha=OGHA, verdict=VERDICT_FAILED)
    """

    def __init__(self, agent_id: AgentId, ogha: AgentId, verdict: str) -> None:
        self._id = agent_id
        self._ogha = ogha
        self._verdict = verdict

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On assignment, publish the evaluation grounded in the recording and return it.

        Example::

            await interviewer.on_message(ctx, OGHA, b"assignment|job_42|candidate-a|df://sha256-x")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("assignment|"):
            return
        facts = ctx.plugins.get("datafacts")
        if facts is None:
            return
        _, job_id, candidate_id, recording_url = msg.split("|", 3)
        dataset = evaluation_dataset(
            interviewer=self._id,
            candidate_id=candidate_id,
            job_id=job_id,
            company_id=str(COMPANY),
            ogha_id=str(OGHA),
            verdict=self._verdict,
            report=_RAW_REPORT,
            scores={"system_design": 4, "coding": 5, "communication": 4},
            interview_recording=cast("DataFactsUrl", recording_url),
        )
        eval_url = await facts.publish(dataset)
        acl = ",".join(str(x) for x in dataset.metadata["acl"])
        await ctx.send(self._id, f"eval_published|{eval_url}|{acl}".encode())
        await ctx.send(self._ogha, f"evaluation|{eval_url}".encode())


class PassiveAgent(StateMachineAgent):
    """A party with an identity but no protocol actions (candidate, rival company).

    Present so the town has real, registered identities for the ACL audience and
    the rival attacker, without driving any messages.

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
    ``ogha_facts``) get one handle per agent over shared dicts and a shared
    logical clock, so every party sees the same published datasets. Plugins with
    a no-arg constructor (``datafacts_v1``) get one shared instance.

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
    default ``FAILED`` — the harder case to protect: a rejection an attacker
    would love to flip to ``PASSED``). Instantiates per-agent identities (each
    party signs as itself) and per-agent datafacts handles over one shared store.

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
