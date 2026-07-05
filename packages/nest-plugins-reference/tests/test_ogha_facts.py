# SPDX-License-Identifier: Apache-2.0
# Authors: Puja Ivaturi, Mahesh Gottam
"""Tests for the ``ogha_facts`` screening-evaluation DataFacts plugin.

Covers the capabilities it adds over the merged ``cid_facts`` — audience ACLs,
pre-hash PII redaction, as-of freshness that composes with the rotating identity,
and verbatim quote-grounding of a report against its transcript — plus the
content-addressing / provenance it inherits. Property-based tests pin the
invariants: redaction is a fixpoint (no PII survives into the permanent hash),
publishing is idempotent, the ACL decision is exactly "audience reads, everyone
else gets metadata", and every verdict is bound by provenance to a real
transcript (nothing fabricated).
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.cid_facts import ProvenanceError
from nest_plugins_reference.datafacts.ogha_facts import (
    VERDICT_FAILED,
    VERDICT_PASSED,
    VERDICTS,
    OghaFacts,
    evaluation_dataset,
    redact_pii,
    scan_pii,
    ungrounded_quotes,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity

_IV = AgentId("interviewer-7")
_FAKE_TX = DataFactsUrl("df://sha256-" + "a" * 64)
_TRANSCRIPT_TEXT = "Q: rate limiter? A: token bucket in Redis with a sliding window log."
_QA = [{"q": "rate limiter?", "a": "token bucket in Redis with a sliding window log"}]


def _facts(agent: AgentId = _IV) -> OghaFacts:
    return OghaFacts(DidKeyIdentity(agent, seed=b"sim-seed"))


def _eval(
    *,
    interviewer: AgentId = _IV,
    verdict: str = VERDICT_FAILED,
    notes: str = "clean notes",
    company: str = "acme",
    transcript: DataFactsUrl = _FAKE_TX,
    qa: list[dict[str, str]] | None = None,
) -> DatasetMetadata:
    return evaluation_dataset(
        interviewer=interviewer,
        candidate_id="cand_a",
        job_id="job_42",
        company_id=company,
        ogha_id="ogha",
        verdict=verdict,
        notes=notes,
        transcript=transcript,
        qa=_QA if qa is None else qa,
    )


async def _recording(facts: OghaFacts, owner: AgentId = _IV) -> DataFactsUrl:
    return await facts.publish(
        DatasetMetadata(name="interview-recording", owner=owner, metadata={})
    )


async def _transcript(facts: OghaFacts, owner: AgentId = _IV) -> DataFactsUrl:
    rec = await _recording(facts, owner)
    return await facts.publish(
        DatasetMetadata(
            name="transcript", owner=owner, metadata={"text": _TRANSCRIPT_TEXT, "parents": [rec]}
        )
    )


async def _pub_eval(
    facts: OghaFacts,
    *,
    owner: AgentId = _IV,
    verdict: str = VERDICT_FAILED,
    notes: str = "clean notes",
    company: str = "acme",
) -> DataFactsUrl:
    """Publish recording -> transcript -> evaluation grounded in it; return the eval URL."""
    tx = await _transcript(facts, owner)
    return await facts.publish(
        _eval(interviewer=owner, verdict=verdict, notes=notes, company=company, transcript=tx)
    )


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------


class TestVerdict:
    def test_only_passed_and_failed_are_valid(self) -> None:
        assert {"PASSED", "FAILED"} == VERDICTS

    def test_dataset_stamps_verdict(self) -> None:
        assert _eval(verdict=VERDICT_PASSED).metadata["verdict"] == "PASSED"
        assert _eval(verdict=VERDICT_FAILED).metadata["verdict"] == "FAILED"

    def test_invalid_verdict_rejected(self) -> None:
        with pytest.raises(ValueError, match="verdict must be one of"):
            _eval(verdict="HIRED")

    def test_transcript_is_bound_as_parent(self) -> None:
        ds = _eval(transcript=_FAKE_TX)
        assert ds.metadata["transcript"] == str(_FAKE_TX)
        assert ds.metadata["parents"] == [str(_FAKE_TX)]


# ---------------------------------------------------------------------------
# PII scanning + redaction
# ---------------------------------------------------------------------------


class TestPii:
    @pytest.mark.parametrize(
        ("text", "category"),
        [
            ("SSN 123-45-6789", "SSN"),
            ("card 1234 5678 9012 3456", "CARD"),
            ("mail alex@example.com", "EMAIL"),
            ("call 555-987-6543", "PHONE"),
            ("earns $185,000 base", "SALARY"),
            ("dob 1994-03-12", "DOB"),
        ],
    )
    def test_each_category_detected_and_redacted(self, text: str, category: str) -> None:
        assert scan_pii(text).get(category) == 1
        redacted, counts = redact_pii(text)
        assert counts.get(category) == 1
        assert f"[REDACTED-{category}]" in redacted
        assert scan_pii(redacted) == {}

    def test_clean_text_untouched(self) -> None:
        text = "Strong system design. Clears screening."
        assert scan_pii(text) == {}
        assert redact_pii(text) == (text, {})

    def test_multiple_occurrences_all_removed(self) -> None:
        redacted, counts = redact_pii("SSNs 123-45-6789 and 987-65-4321 on file")
        assert scan_pii(redacted) == {}
        assert counts["SSN"] == 2

    async def test_publish_redacts_notes_before_hashing(self) -> None:
        facts = _facts()
        url = await _pub_eval(
            facts, notes="Reach at a@b.com, 555-987-6543, SSN 123-45-6789, $185,000."
        )
        stored = await facts.fetch(url)
        assert scan_pii(stored.metadata["notes"]) == {}
        assert "[REDACTED-" in stored.metadata["notes"]


# ---------------------------------------------------------------------------
# Content addressing / provenance
# ---------------------------------------------------------------------------


class TestContentAddressing:
    async def test_publish_is_idempotent(self) -> None:
        facts = _facts()
        tx = await _transcript(facts)
        ds = _eval(notes="Reach at a@b.com. SSN 123-45-6789.", transcript=tx)
        assert await facts.publish(ds) == await facts.publish(ds)

    async def test_verdict_flip_changes_url(self) -> None:
        facts = _facts()
        tx = await _transcript(facts)
        failed = await facts.publish(_eval(verdict=VERDICT_FAILED, transcript=tx))
        passed = await facts.publish(_eval(verdict=VERDICT_PASSED, transcript=tx))
        assert failed != passed

    async def test_verdict_with_no_real_interview_is_rejected(self) -> None:
        facts = _facts()
        phantom = DataFactsUrl("df://sha256-" + "0" * 64)
        with pytest.raises(ProvenanceError):
            await facts.publish(_eval(transcript=phantom))

    async def test_transcript_is_provenance_parent(self) -> None:
        facts = _facts()
        tx = await _transcript(facts)
        eval_url = await facts.publish(_eval(transcript=tx))
        assert tx in facts.ancestors(eval_url)


# ---------------------------------------------------------------------------
# Quote grounding
# ---------------------------------------------------------------------------


class TestGrounding:
    def test_grounded_quote_returns_empty(self) -> None:
        qa = [{"q": "rate limiter?", "a": "token bucket in Redis"}]
        assert ungrounded_quotes(qa, "Q: rate limiter? A: token bucket in Redis, plus a log.") == []

    def test_fabricated_quote_flagged(self) -> None:
        # The question was really asked, but the answer was never given.
        qa = [{"q": "rate limiter?", "a": "consistent hashing with virtual nodes"}]
        missing = ungrounded_quotes(qa, "Q: rate limiter? A: token bucket in Redis")
        assert missing == ["consistent hashing with virtual nodes"]

    def test_matching_is_whitespace_and_case_insensitive(self) -> None:
        qa = [{"a": "Token   Bucket\n in Redis"}]
        assert ungrounded_quotes(qa, "we used token bucket in redis") == []

    def test_paraphrase_is_not_grounded(self) -> None:
        # A paraphrase (not the actual words) must NOT count as grounded.
        qa = [{"a": "the candidate proposed a bucketed token approach"}]
        assert ungrounded_quotes(qa, "I'd use a token bucket in Redis") != []


# ---------------------------------------------------------------------------
# Audience ACL
# ---------------------------------------------------------------------------


class TestAcl:
    async def test_owner_and_audience_read_outsider_metadata(self) -> None:
        facts = _facts()
        url = await _pub_eval(facts, company="acme")
        for who in ("interviewer-7", "acme", "ogha", "cand_a"):
            grant = await facts.request_access(url, AgentId(who))
            assert grant.tier == "read", who
        rival = await facts.request_access(url, AgentId("rival-corp"))
        assert rival.tier == "metadata"

    async def test_outsider_is_not_denied_but_downgraded(self) -> None:
        facts = _facts()
        url = await _pub_eval(facts)
        grant = await facts.request_access(url, AgentId("rival-corp"))
        assert grant.grantee == AgentId("rival-corp")
        assert grant.tier == "metadata"

    async def test_public_tier_reads_for_all(self) -> None:
        facts = _facts()
        ds = DatasetMetadata(name="public-note", owner=_IV, access_tier="public", metadata={})
        url = await facts.publish(ds)
        grant = await facts.request_access(url, AgentId("anyone"))
        assert grant.tier == "read"


# ---------------------------------------------------------------------------
# Freshness, incl. as-of verification across key rotation
# ---------------------------------------------------------------------------


class TestFreshness:
    async def test_fresh_after_publish(self) -> None:
        facts = _facts()
        url = await _pub_eval(facts)
        assert await facts.verify_freshness(url) is True

    async def test_forged_owner_not_fresh(self) -> None:
        attacker = OghaFacts(DidKeyIdentity(AgentId("rival-corp"), seed=b"sim-seed"))
        tx = await _transcript(attacker, owner=_IV)
        url = await attacker.publish(_eval(interviewer=_IV, transcript=tx))
        assert await attacker.verify_freshness(url) is False

    async def test_survives_legitimate_key_rotation(self) -> None:
        ident = Ed25519RotatingIdentity(_IV, seed=b"seed")
        facts = OghaFacts(ident)
        url = await _pub_eval(facts)
        assert await facts.verify_freshness(url) is True
        ident.set_clock(facts.clock.tick)
        ident.rotate_key(b"new-seed")
        assert facts.freshness_proof(url) is not None


# ---------------------------------------------------------------------------
# Property-based invariants
# ---------------------------------------------------------------------------

_TEXT = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126),
    max_size=120,
)


class TestProperties:
    @given(_TEXT)
    def test_redaction_leaves_no_detectable_pii(self, text: str) -> None:
        redacted, _counts = redact_pii(text)
        assert scan_pii(redacted) == {}

    @given(_TEXT)
    def test_redaction_is_idempotent(self, text: str) -> None:
        once, _ = redact_pii(text)
        twice, counts = redact_pii(once)
        assert twice == once
        assert counts == {}

    @given(st.sampled_from([VERDICT_PASSED, VERDICT_FAILED]), _TEXT)
    async def test_publish_idempotent_over_notes(self, verdict: str, notes: str) -> None:
        facts = _facts()
        tx = await _transcript(facts)
        ds = _eval(verdict=verdict, notes=notes, transcript=tx)
        assert await facts.publish(ds) == await facts.publish(ds)

    @given(st.text(alphabet="abcdefghij-", min_size=1, max_size=10))
    async def test_acl_read_iff_audience(self, requester: str) -> None:
        facts = _facts()
        url = await _pub_eval(facts, company="acme")
        meta = await facts.fetch(url)
        acl = {str(x) for x in meta.metadata["acl"]}
        grant = await facts.request_access(url, AgentId(requester))
        expected = "read" if requester in acl or requester == "interviewer-7" else "metadata"
        assert grant.tier == expected
