# SPDX-License-Identifier: Apache-2.0

"""Intent-Gated DataFacts plugin — pre-publication intent registry.

The ``cid_facts`` reference plugin establishes content-addressing and signed
freshness, but it places no constraint on *when* or *whether* an agent may
publish.  Any agent can call ``publish()`` at any moment without prior
announcement, making it impossible to detect surprise or unauthorised
publications in a trace.

This plugin extends ``CidFacts`` with a lightweight **intent registry**:

* Before calling ``publish(name=X, ...)``, the owning agent must call
  ``register_publish_intent(X)`` on its own instance.
* Intents are one-time-use and expire after a configurable number of logical
  ticks (``intent_ttl``).
* An ``IntentError`` is raised if the agent tries to publish without a live
  intent, or after the intent has expired.

Three attacks that ``datafacts_v1`` and ``cid_facts`` both miss are blocked:

Surprise-publication attack
    An agent publishes a dataset with no prior announcement.  The validator
    checks that every ``publish`` event in the trace is preceded by a matching
    ``register_publish_intent`` event for the same ``(agent_id, name)`` pair.

Expired-intent replay attack
    An agent re-publishes using an intent that elapsed several ticks ago.
    Intents are consumed on first use and expire if unused, so replaying a
    stale intent is impossible.

Intent-hijack attack
    Agent *B* tries to publish on behalf of agent *A* by sharing *A*'s
    CidFacts instance state.  Because each ``IntentGatedFacts`` instance is
    bound to a single ``Identity``, the intent is checked against the
    *instance* owner, not the ``DatasetMetadata.owner`` field alone.

Example::

    clock = SharedClock()
    ident = DidKeyIdentity(AgentId("a1"), seed=b"seed")
    facts = IntentGatedFacts(ident, clock=clock, intent_ttl=5.0)

    facts.register_publish_intent("weather-data")
    url = await facts.publish(
        DatasetMetadata(name="weather-data", owner=AgentId("a1"))
    )

    result = await facts.verify_freshness(url)   # True
    log = facts.intent_log()                     # [{"status": "fulfilled", ...}]
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from nest_core.types import DataFactsUrl, DatasetMetadata

from nest_plugins_reference.datafacts.cid_facts import CidFacts, FreshnessProof, SharedClock

if TYPE_CHECKING:
    from nest_core.layers.identity import Identity


class IntentError(ValueError):
    """Raised when a publish is attempted without a valid pre-registered intent."""


@dataclass
class IntentRecord:
    """Audit record for a single publish intent."""

    agent_id: str
    dataset_name: str
    registered_at: float
    expires_at: float
    status: Literal["pending", "fulfilled", "expired"] = "pending"
    fulfilled_at: float | None = None


class IntentGatedFacts(CidFacts):
    """Content-addressed DataFacts with a mandatory pre-publication intent gate.

    Extends :class:`~nest_plugins_reference.datafacts.cid_facts.CidFacts` with
    an intent registry.  Each call to :meth:`publish` requires the instance
    owner to have previously called :meth:`register_publish_intent` for the
    same dataset name, and for that intent to still be within its TTL window.

    Example::

        clock = SharedClock()
        ident = DidKeyIdentity(AgentId("publisher"), seed=b"s")
        facts = IntentGatedFacts(ident, clock=clock, intent_ttl=10.0)

        facts.register_publish_intent("prices")
        url = await facts.publish(
            DatasetMetadata(name="prices", owner=AgentId("publisher"))
        )
    """

    def __init__(
        self,
        identity: Identity,
        *,
        intent_ttl: float = 10.0,
        datasets: dict[DataFactsUrl, DatasetMetadata] | None = None,
        proofs: dict[DataFactsUrl, FreshnessProof] | None = None,
        clock: SharedClock | None = None,
        freshness_window: float = 1.0,
    ) -> None:
        super().__init__(
            identity,
            datasets=datasets,
            proofs=proofs,
            clock=clock,
            freshness_window=freshness_window,
        )
        self._intent_ttl = intent_ttl
        # Cache agent_id string — DidKeyIdentity stores it as _agent_id.
        self._owner_str: str = str(identity._agent_id)  # type: ignore[attr-defined]
        # (agent_id_str, dataset_name) -> expiry tick
        self._pending_intents: dict[tuple[str, str], float] = {}
        self._intent_log: list[IntentRecord] = []

    def register_publish_intent(self, dataset_name: str) -> None:
        """Declare intent to publish *dataset_name* within *intent_ttl* ticks.

        The intent is one-time-use: it is consumed when ``publish()`` succeeds,
        or marked expired if the TTL elapses before ``publish()`` is called.
        Registering a new intent for the same name while one is already pending
        replaces the old one.

        Example::

            facts.register_publish_intent("prices")
        """
        agent_str = self._owner_str
        now = self._clock.tick
        expiry = now + self._intent_ttl
        key = (agent_str, dataset_name)
        # Replace any existing pending intent for this (agent, name) pair.
        self._pending_intents[key] = expiry
        self._intent_log.append(
            IntentRecord(
                agent_id=agent_str,
                dataset_name=dataset_name,
                registered_at=now,
                expires_at=expiry,
            )
        )

    def _consume_intent(self, dataset_name: str) -> None:
        """Validate and consume the pending intent for *dataset_name*.

        Marks the matching audit record as ``"fulfilled"`` and removes it from
        the pending dict.

        Raises:
            IntentError: if no intent is registered, or if the intent has
                expired.
        """
        agent_str = self._owner_str
        key = (agent_str, dataset_name)
        expiry = self._pending_intents.get(key)

        if expiry is None:
            raise IntentError(
                f"Agent {agent_str!r} has no registered intent to publish "
                f"{dataset_name!r}. Call register_publish_intent() first."
            )

        now = self._clock.tick
        if now > expiry:
            del self._pending_intents[key]
            self._mark_log_expired(agent_str, dataset_name)
            raise IntentError(
                f"Agent {agent_str!r}'s intent to publish {dataset_name!r} "
                f"expired at tick {expiry} (current tick {now})."
            )

        del self._pending_intents[key]
        self._mark_log_fulfilled(agent_str, dataset_name, now)

    def _mark_log_fulfilled(self, agent_str: str, dataset_name: str, tick: float) -> None:
        for record in reversed(self._intent_log):
            if (
                record.agent_id == agent_str
                and record.dataset_name == dataset_name
                and record.status == "pending"
            ):
                record.status = "fulfilled"
                record.fulfilled_at = tick
                return

    def _mark_log_expired(self, agent_str: str, dataset_name: str) -> None:
        for record in reversed(self._intent_log):
            if (
                record.agent_id == agent_str
                and record.dataset_name == dataset_name
                and record.status == "pending"
            ):
                record.status = "expired"
                return

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish *dataset* after consuming the agent's pre-registered intent.

        Delegates to :meth:`CidFacts.publish` for content-addressing and
        freshness-proof generation once the intent check passes.

        Raises:
            IntentError: if no live intent exists for ``dataset.name``.
            ProvenanceError: if declared parents are unknown (inherited from
                CidFacts).

        Example::

            facts.register_publish_intent("prices")
            url = await facts.publish(
                DatasetMetadata(name="prices", owner=AgentId("a1"))
            )
        """
        self._consume_intent(dataset.name)
        return await super().publish(dataset)

    def has_live_intent(self, dataset_name: str) -> bool:
        """Return ``True`` if this instance has a live (unexpired) intent for *dataset_name*.

        Example::

            facts.register_publish_intent("prices")
            assert facts.has_live_intent("prices")
        """
        key = (self._owner_str, dataset_name)
        expiry = self._pending_intents.get(key)
        if expiry is None:
            return False
        return self._clock.tick <= expiry

    def intent_log(self) -> list[IntentRecord]:
        """Return the full audit log of all intents (pending / fulfilled / expired).

        Useful for validators and post-hoc trace analysis.

        Example::

            log = facts.intent_log()
            fulfilled = [r for r in log if r.status == "fulfilled"]
        """
        return list(self._intent_log)

    def pending_intents(self) -> list[tuple[str, str]]:
        """Return list of ``(agent_id, dataset_name)`` pairs with live intents.

        Example::

            facts.register_publish_intent("prices")
            assert ("a1", "prices") in facts.pending_intents()
        """
        now = self._clock.tick
        return [k for k, exp in self._pending_intents.items() if exp >= now]
