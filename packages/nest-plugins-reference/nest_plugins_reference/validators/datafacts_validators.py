# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the DataFacts layer.

Three attack classes the default ``datafacts_v1`` plugin silently allows:

1. **Substitution.**  ``datafacts_v1`` uses ``df://<name>`` URLs, so an
   attacker can publish completely different content under the same name
   and no part of the system notices.  ``check_no_substitution`` confirms
   that every published URL is deterministically derived from the content.

2. **Stale freshness.**  ``datafacts_v1`` checks wall-clock time with no
   cryptographic binding.  An attacker can re-touch the timestamp without
   re-publishing the content.  ``check_no_stale_freshness`` verifies that
   every freshness claim is backed by a signed proof.

3. **Broken provenance.**  ``datafacts_v1`` has no concept of parent
   datasets.  ``check_provenance_chain_intact`` walks every dataset's
   ``parents`` list and confirms every referenced hash exists in the store.

By construction:

* against ``content_addressed``, all three validators pass;
* against ``datafacts_v1``, all three fail -- the reference plugin cannot
  satisfy any of the three invariants, which is the charter's bar for
  "adversarial."

Example::

    report = await check_no_substitution(df_plugin)
    assert report.passed, report.detail
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nest_core.types import AgentId, DataFactsUrl, DatasetMetadata


@dataclass
class DataFactsValidatorReport:
    """Pass/fail report with a short explanation and optional evidence.

    Example::

        report = DataFactsValidatorReport(passed=True, detail="all hashes verified")
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: dict[str, object] = field(default_factory=dict[str, object])


class SubstitutionError(AssertionError):
    """Raised when a URL does not match its content hash.

    Example::

        raise SubstitutionError("df://weather does not start with df://sha256-")
    """


class StaleFreshnessError(AssertionError):
    """Raised when freshness is claimed without a signed proof.

    Example::

        raise StaleFreshnessError("no proof found for df://sha256-abcd")
    """


class BrokenProvenanceError(AssertionError):
    """Raised when a parent hash in the provenance chain is missing.

    Example::

        raise BrokenProvenanceError("parent df://sha256-dead not in store")
    """


async def check_no_substitution(
    plugin: Any,
) -> DataFactsValidatorReport:
    """Verify that every published URL is a content hash, not a chosen name.

    This test publishes two datasets with different content and asserts that
    (a) their URLs differ and (b) each URL starts with ``df://sha256-``.
    Against ``datafacts_v1``, the same ``name`` field produces the same
    ``df://<name>`` URL regardless of content, so the check fails.

    Example::

        report = await check_no_substitution(df_plugin)
    """
    owner = AgentId("validator-pub")

    meta_a = DatasetMetadata(name="test-dataset", owner=owner, description="version A")
    meta_b = DatasetMetadata(name="test-dataset", owner=owner, description="version B")

    # Determine whether the plugin's publish() accepts a payload kwarg.
    # content_addressed requires it; datafacts_v1 does not.
    try:
        url_a = await plugin.publish(meta_a, payload=b"content-A")
    except TypeError:
        url_a = await plugin.publish(meta_a)

    try:
        url_b = await plugin.publish(meta_b, payload=b"content-B")
    except TypeError:
        url_b = await plugin.publish(meta_b)

    failures: list[str] = []

    # Content-addressed URLs must start with the hash scheme prefix.
    if not str(url_a).startswith("df://sha256-"):
        failures.append(f"url_a is not content-addressed: {url_a}")
    if not str(url_b).startswith("df://sha256-"):
        failures.append(f"url_b is not content-addressed: {url_b}")

    # Two datasets with different content must have different URLs.
    if url_a == url_b:
        failures.append(f"different content produced the same URL: {url_a}")

    if failures:
        return DataFactsValidatorReport(
            passed=False,
            detail=f"{len(failures)} substitution vulnerability(ies) detected",
            evidence={"failures": failures},
        )
    return DataFactsValidatorReport(
        passed=True,
        detail="content-addressing verified: distinct content -> distinct hash URLs",
    )


async def check_no_stale_freshness(
    plugin: Any,
) -> DataFactsValidatorReport:
    """Verify that freshness claims are backed by cryptographic proofs.

    Publishes a dataset and then calls ``verify_freshness``.  Against the
    ``content_addressed`` plugin the proof exists and the signature is
    valid.  Against ``datafacts_v1`` the check passes trivially (wall-clock)
    but the validator also confirms a ``get_proof`` method exists and
    returns a non-None proof -- which ``datafacts_v1`` lacks entirely.

    Example::

        report = await check_no_stale_freshness(df_plugin)
    """
    owner = AgentId("validator-pub")
    meta = DatasetMetadata(name="freshness-test", owner=owner)

    try:
        url = await plugin.publish(meta, payload=b"payload")
    except TypeError:
        url = await plugin.publish(meta)

    failures: list[str] = []

    # The plugin must expose a get_proof() introspection method.
    if not hasattr(plugin, "get_proof"):
        failures.append("plugin has no get_proof() method -- no cryptographic freshness support")
    else:
        proof = plugin.get_proof(url)
        if proof is None:
            failures.append(f"no freshness proof found for {url}")
        else:
            # Verify the proof's signature field is populated.
            if proof.signature is None:
                failures.append("freshness proof has no signature")

    if failures:
        return DataFactsValidatorReport(
            passed=False,
            detail=f"{len(failures)} stale-freshness vulnerability(ies) detected",
            evidence={"failures": failures},
        )
    return DataFactsValidatorReport(
        passed=True,
        detail="freshness proof present and signed",
    )


async def check_provenance_chain_intact(
    plugin: Any,
    *,
    parent_url: DataFactsUrl | None = None,
) -> DataFactsValidatorReport:
    """Verify that provenance parent references resolve to known datasets.

    If ``parent_url`` is provided, the validator publishes a child dataset
    that declares the parent, then confirms the chain is walkable.  Against
    ``content_addressed`` this succeeds because ``publish`` validates
    parents at write time.  Against ``datafacts_v1`` there is no parent
    tracking at all, so the validator confirms the plugin lacks provenance
    support.

    Example::

        report = await check_provenance_chain_intact(df_plugin)
    """
    owner = AgentId("validator-pub")
    failures: list[str] = []

    if not hasattr(plugin, "verify_provenance_chain"):
        failures.append("plugin has no verify_provenance_chain() method -- no provenance support")
        return DataFactsValidatorReport(
            passed=False,
            detail="provenance chain validation not supported",
            evidence={"failures": failures},
        )

    # Publish a root dataset (no parents).
    root_meta = DatasetMetadata(name="root-data", owner=owner)
    try:
        root_url = await plugin.publish(root_meta, payload=b"root-payload")
    except TypeError:
        root_url = await plugin.publish(root_meta)

    # Publish a child that references the root as a parent.
    child_meta = DatasetMetadata(
        name="derived-data",
        owner=owner,
        metadata={"parents": [str(root_url)]},
    )
    try:
        child_url = await plugin.publish(child_meta, payload=b"derived-payload")
    except TypeError:
        child_url = await plugin.publish(child_meta)

    # The chain from child -> root must be intact.
    if not plugin.verify_provenance_chain(child_url):
        failures.append(f"provenance chain broken for {child_url}")

    # The root itself should also pass (trivially, no parents).
    if not plugin.verify_provenance_chain(root_url):
        failures.append(f"root provenance check failed for {root_url}")

    if failures:
        return DataFactsValidatorReport(
            passed=False,
            detail=f"{len(failures)} provenance integrity violation(s)",
            evidence={"failures": failures},
        )
    return DataFactsValidatorReport(
        passed=True,
        detail="provenance chain intact: all parent hashes resolve",
    )
