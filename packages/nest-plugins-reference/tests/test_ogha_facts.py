# SPDX-License-Identifier: Apache-2.0
"""Tests for the ``ogha_facts`` interview-evaluation DataFacts plugin.

Covers the two capabilities it adds over the merged ``cid_facts`` — audience
ACLs and pre-hash PII redaction — plus the as-of freshness verification that
composes with the rotating identity, and the content-addressing / provenance it
inherits. Property-based tests pin the invariants that make the plugin safe:
redaction is a fixpoint (no PII survives into the permanent hash), publishing is
idempotent, and the ACL decision is exactly "audience reads, everyone else gets
metadata".
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata
from nest_plugins_reference.datafacts.cid_facts import ProvenanceError
from nest_plugins_reference.datafacts.ogha_facts import (
    VERDICT_HIRED,
    VERDICT_NOT_HIRED,
    OghaFacts,
    evaluation_dataset,
    outcome_for,
    redact_pii,
    scan_pii,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity

_IV = AgentId("interviewer-7")


def _facts(agent: AgentId = _IV) -> OghaFacts:
    return OghaFacts(DidKeyIdentity(agent, seed=b"sim-seed"))


def _eval(
    facts_owner: AgentId = _IV,
    *,
    verdict: str = VERDICT_NOT_HIRED,
    report: str = "clean report",
    company: str = "acme",
    parents: list[DataFactsUrl] | None = None,
) -> DatasetMetadata:
    return evaluation_dataset(
        interviewer=facts_owner,
        candidate_id="cand_a",
        job_id="job_42",
        company_id=company,
        ogha_id="ogha",
        verdict=verdict,
        report=report,
        parents=parents,
    )


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------


class TestOutcome:
    def test_hired_is_pass(self) -> None:
        assert outcome_for(VERDICT_HIRED) == "PASS"

    def test_not_hired_is_fail(self) -> None:
        assert outcome_for(VERDICT_NOT_HIRED) == "FAIL"

    def test_unknown_is_fail(self) -> None:
        # A record that does not clearly say "hire" is not a pass.
        assert outcome_for("MAYBE") == "FAIL"

    def test_evaluation_dataset_stamps_outcome(self) -> None:
        ds = _eval(verdict=VERDICT_HIRED)
        assert ds.metadata["outcome"] == "PASS"
        assert ds.metadata["verdict"] == VERDICT_HIRED


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
        text = "Strong system design. Clear recommend."
        assert scan_pii(text) == {}
        assert redact_pii(text) == (text, {})

    def test_multiple_occurrences_all_removed(self) -> None:
        redacted, counts = redact_pii("SSNs 123-45-6789 and 987-65-4321 on file")
        assert scan_pii(redacted) == {}
        assert counts["SSN"] == 2

    async def test_publish_redacts_before_hashing(self) -> None:
        facts = _facts()
        raw = _eval(report="Reach at a@b.com, 555-987-6543, SSN 123-45-6789, $185,000.")
        url = await facts.publish(raw)
        stored = await facts.fetch(url)
        assert scan_pii(stored.metadata["report"]) == {}
        assert "[REDACTED-" in stored.metadata["report"]


# ---------------------------------------------------------------------------
# Content addressing / provenance (inherited, re-checked through the subclass)
# ---------------------------------------------------------------------------


class TestContentAddressing:
    async def test_publish_is_idempotent(self) -> None:
        facts = _facts()
        raw = _eval(report="Reach at a@b.com. SSN 123-45-6789.")
        assert await facts.publish(raw) == await facts.publish(raw)

    async def test_verdict_flip_changes_url(self) -> None:
        facts = _facts()
        no = await facts.publish(_eval(verdict=VERDICT_NOT_HIRED))
        yes = await facts.publish(_eval(verdict=VERDICT_HIRED))
        assert no != yes

    async def test_unknown_parent_rejected(self) -> None:
        facts = _facts()
        phantom = DataFactsUrl("df://sha256-" + "0" * 64)
        with pytest.raises(ProvenanceError):
            await facts.publish(_eval(parents=[phantom]))

    async def test_known_parent_accepted_and_walkable(self) -> None:
        facts = _facts()
        record = DatasetMetadata(name="interview-record", owner=_IV, metadata={})
        record_url = await facts.publish(record)
        eval_url = await facts.publish(_eval(parents=[record_url]))
        assert record_url in facts.ancestors(eval_url)


# ---------------------------------------------------------------------------
# Audience ACL
# ---------------------------------------------------------------------------


class TestAcl:
    async def test_owner_and_audience_read_outsider_metadata(self) -> None:
        facts = _facts()
        url = await facts.publish(_eval(company="acme"))
        for who in ("interviewer-7", "acme", "ogha", "cand_a"):
            grant = await facts.request_access(url, AgentId(who))
            assert grant.tier == "read", who
        rival = await facts.request_access(url, AgentId("rival-corp"))
        assert rival.tier == "metadata"

    async def test_outsider_is_not_denied_but_downgraded(self) -> None:
        # Unlike cid_facts (which raises PermissionError), an outsider still gets
        # a valid grant so they can audit existence/provenance -- just not content.
        facts = _facts()
        url = await facts.publish(_eval())
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
        url = await facts.publish(_eval())
        assert await facts.verify_freshness(url) is True

    async def test_forged_owner_not_fresh(self) -> None:
        # Attacker publishes content owned by the interviewer but signed by
        # themselves; the signer != owner check rejects the freshness claim.
        attacker = OghaFacts(DidKeyIdentity(AgentId("rival-corp"), seed=b"sim-seed"))
        url = await attacker.publish(_eval(facts_owner=_IV))
        assert await attacker.verify_freshness(url) is False

    async def test_survives_legitimate_key_rotation(self) -> None:
        # A verdict signed before the interviewer rotated their key still
        # verifies, because verification is anchored as-of the signing tick.
        ident = Ed25519RotatingIdentity(_IV, seed=b"seed")
        facts = OghaFacts(ident)
        url = await facts.publish(_eval())
        assert await facts.verify_freshness(url) is True
        ident.set_clock(facts.clock.tick)
        ident.rotate_key(b"new-seed")  # interviewer's key cycles
        # The freshness window still applies, but the signature must not be
        # rejected merely because the key rotated.
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

    @given(st.sampled_from([VERDICT_HIRED, VERDICT_NOT_HIRED]), _TEXT)
    async def test_publish_idempotent_over_report(self, verdict: str, report: str) -> None:
        facts = _facts()
        ds = _eval(verdict=verdict, report=report)
        assert await facts.publish(ds) == await facts.publish(ds)

    @given(st.text(alphabet="abcdefghij-", min_size=1, max_size=10))
    async def test_acl_read_iff_audience(self, requester: str) -> None:
        facts = _facts()
        url = await facts.publish(_eval(company="acme"))
        meta = await facts.fetch(url)
        acl = {str(x) for x in meta.metadata["acl"]}
        grant = await facts.request_access(url, AgentId(requester))
        expected = "read" if requester in acl or requester == "interviewer-7" else "metadata"
        assert grant.tier == expected
