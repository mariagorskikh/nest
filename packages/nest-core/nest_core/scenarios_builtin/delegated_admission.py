# SPDX-License-Identifier: Apache-2.0
"""Delegated-admission trust scenario — five reporter roles stress a live-grant gate.

A single ``observer`` maintains the reputation of one ``victim`` and admits
evidence about that victim iff the reporter holds a live, unrevoked,
in-scope delegation from a trusted principal — the property enforced by
:mod:`nest_plugins_reference.trust.delegated_admission` (the Python port of
``nexartis-nanda-node/src/lib/server/delegation-grants.ts``).

Five reporter roles stress five distinct failure modes of the gate:

* **honest** — holds a fresh grant from the fixture principal covering
  ``trust.report``. Verdict ``admitted``; files a *positive* report so the
  victim's admitted-evidence average sits at 1.0.
* **sybil** — no grant at all in the plugin's store. Verdict ``no-grant``.
  Its *negative* report is quarantined; under a baseline plugin the same
  reporter's negatives are admitted and drag the victim's score under 0.5.
* **revoked** — child of a chain-root that the observer revokes mid-scenario.
  A cascade line in the trace surfaces the exact ``(root_id, n_descendants)``
  the plugin computed; every descendant's later report is quarantined.
* **escalator** — grant with an in-scope tool string that does **not** contain
  the required scope ``trust.report``. Verdict ``scope-mismatch``.
* **stale** — grant issued at a logical clock in the past; by report time the
  proof's freshness window has closed. Verdict ``puh-proof-stale``.

The agents resolve their trust plugin from ``ctx.plugins["trust"]`` and
capability-gate the grant surface on ``hasattr(trust, "revoke")``. Swapping
``trust: delegated_admission`` for ``trust: score_average`` in the YAML
genuinely changes behaviour: without a gate every reporter — including all
four attack classes — is admitted, the victim's score collapses under 0.5,
and no cascade line ever appears. This is what the flip test in
``test_delegated_admission.py`` catches.

Trace line protocol (message bodies, ``:``-delimited; the observer emits its
audit lines by sending them to the passive ``victim`` sink so they land in
the trace as ordinary ``send`` events the validators parse):

* ``cascade:<root_id>:<n_descendants>`` — emitted once, in the observer's
  ``on_start``, after the plugin performs the cascade revocation. Under a
  baseline plugin (no ``revoke``) this line is absent, so the cascade
  validator fails on baseline.
* ``admission:<reporter>:<live|no-grant|revoked|scope-invalid|stale-proof>:<admitted|quarantined>``
  — the role label the scenario assigned this reporter, plus what the
  configured plugin actually did with its report. Under the delegated
  plugin, only ``live`` ever comes with ``admitted``; under a baseline
  plugin every kind comes with ``admitted``.
* ``report:<reporter>:<subject>:<kind>:<admitted|quarantined>`` — the fate
  of one evidence report (structurally identical to attested_peering).
* ``repscore:<victim>:<score>:<samples>`` — the victim's final reputation,
  formatted to six decimals.

Example::

    agents = delegated_admission_factory(config, plugins)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Evidence

if TYPE_CHECKING:
    from nest_plugins_reference.trust.delegated_admission import (
        DelegatedAdmissionTrust,
    )

# A fixed logical epoch (ms) at which the observer's trust plugin operates.
# The plugin's PuhProof freshness comparisons subtract this value from the
# proof's ``bound_at_ms``; the constant is far enough in the future that no
# real-world reference date bleeds in and small enough that the ``expires_at``
# unix-seconds field never overflows a reasonable integer window.
_NOW_MS: int = 1_700_000_000_000
_NOW_S: int = _NOW_MS // 1000

# Roles the trace admission line surfaces (role → machine string). Public
# so both the factory and :mod:`nest_core.validators` can import a single
# truth (both live in ``nest-core``; the plugin's own reason strings —
# ``no-grant``, ``revoked``, ``puh-proof-stale`` etc. — are a different
# vocabulary owned by the plugin module).
ADMISSION_KIND_LIVE = "live"
"""Role tag stamped on trace ``admission:`` lines for honest reporters.

Example::

    assert ADMISSION_KIND_LIVE == "live"
"""

ADMISSION_KIND_NO_GRANT = "no-grant"
"""Role tag for reporters with no grant at all (Sybil swarm).

Example::

    assert ADMISSION_KIND_NO_GRANT == "no-grant"
"""

ADMISSION_KIND_REVOKED = "revoked"
"""Role tag for reporters whose grant was revoked (cascade victims).

Example::

    assert ADMISSION_KIND_REVOKED == "revoked"
"""

ADMISSION_KIND_SCOPE_INVALID = "scope-invalid"
"""Role tag for reporters whose grant lacks the required scope.

Example::

    assert ADMISSION_KIND_SCOPE_INVALID == "scope-invalid"
"""

ADMISSION_KIND_STALE = "stale-proof"
"""Role tag for reporters whose proof-of-human aged out of the freshness window.

Example::

    assert ADMISSION_KIND_STALE == "stale-proof"
"""

# Factory magic numbers → named constants.
_GRANT_TTL_S = 3600
"""One-hour TTL applied to every scenario-seeded grant, in seconds."""

_STALE_SLACK_MS = 60_000
"""Extra past-slack (ms) applied on top of ``PUH_FRESHNESS_MS`` to place
``bound_at`` firmly outside the freshness window for stale reporters."""

# Scope strings used across the factory. Kept as module constants so the
# admission policy and grant issuance can't drift.
_REQUIRED_SCOPE = "trust.report"
"""The scope every admitted grant must carry."""

_OFF_SCOPE_ESCALATOR = "tool.echo"
"""The escalator role's grant carries this in-scope tool; because it is not
``_REQUIRED_SCOPE``, admission fails with ``scope-mismatch``."""

_VICTIM_CONFIG_KEY = "victim"
"""``task.config`` key holding the victim agent id (default: ``"victim"``)."""

_DEFAULT_VICTIM_ID = "victim"
"""Default victim id when ``task.config`` omits ``victim``."""


class ReporterAgent(StateMachineAgent):
    """A reporter that files one evidence report about the victim.

    The reporter is stateless: on start it sends a single ``claim:<kind>``
    message to the observer and never speaks again. The observer decides
    the fate of the report — the reporter never inspects its own grant, so
    the same agent class works under every role.

    Example::

        agent = ReporterAgent(AgentId("honest-0"), AgentId("observer"), "positive")
    """

    def __init__(self, agent_id: AgentId, observer: AgentId, report_kind: str) -> None:
        self._id = agent_id
        self._observer = observer
        self._report_kind = report_kind

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit the one claim message this reporter will ever send.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.send(self._observer, f"claim:{self._report_kind}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ignore any inbound traffic — reporters do not participate further.

        Example::

            await agent.on_message(ctx, observer, b"anything")
        """
        return


class ObserverAgent(StateMachineAgent):
    """Runs the delegated-admission plugin and records the victim's reputation.

    On start it performs the cascade revocation of the pre-seeded chain-root
    (if the configured trust plugin exposes ``revoke``) and emits a single
    ``cascade:<root_id>:<n_descendants>`` line reflecting exactly what the
    plugin returned. On each inbound ``claim:<kind>`` from a reporter it
    files evidence through the trust plugin, looks up the verdict via
    ``last_verdict`` when available, and emits paired
    ``admission:``/``report:`` lines with the reporter's role kind and the
    plugin's actual admission fate. When the last expected reporter has been
    processed it emits the final ``repscore:`` line.

    Example::

        observer = ObserverAgent(AgentId("observer"), AgentId("victim"), {}, None, 32)
    """

    def __init__(
        self,
        agent_id: AgentId,
        victim: AgentId,
        role_map: dict[AgentId, str],
        cascade_root_id: str | None,
        expected: int,
    ) -> None:
        self._id = agent_id
        self._victim = victim
        self._role_map = role_map
        self._cascade_root_id = cascade_root_id
        self._expected = expected
        self._processed = 0
        self._done = False

    async def _log(self, ctx: AgentContext, line: str) -> None:
        await ctx.send(self._victim, line.encode())

    async def on_start(self, ctx: AgentContext) -> None:
        """Perform the cascade revocation and log its footprint.

        Example::

            await observer.on_start(ctx)
        """
        trust = ctx.plugins.get("trust")
        if trust is None:
            return
        # Reaffirm the clock in case a future runner ever resets it — the
        # plugin's freshness/expiry gates all key off this millisecond value.
        if hasattr(trust, "set_clock"):
            trust.set_clock(_NOW_MS)
        if self._cascade_root_id is None or not hasattr(trust, "revoke"):
            return
        result = trust.revoke(self._cascade_root_id)
        # ``cascaded`` includes the root itself; descendants are the remainder.
        cascaded = getattr(result, "cascaded", ())
        n_descendants = max(0, len(cascaded) - 1)
        await self._log(ctx, f"cascade:{self._cascade_root_id}:{n_descendants}")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ingest one reporter's claim, file evidence, and log the fate.

        Example::

            await observer.on_message(ctx, sender, b"claim:positive")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("claim:"):
            return
        trust = ctx.plugins.get("trust")
        if trust is None:
            return
        kind = msg[len("claim:") :]
        # The plugin's ``report`` is defensive: it never raises on adversarial
        # input; it appends to its quarantine list and records a verdict we
        # can query below.
        evidence = Evidence(reporter=sender, subject=self._victim, kind=kind)
        await trust.report(self._victim, evidence)

        last_verdict = getattr(trust, "last_verdict", None)
        if callable(last_verdict):
            verdict = last_verdict(sender)
            admitted = verdict is not None and bool(getattr(verdict, "admitted", False))
        else:
            # Baseline path — score_average admits every report unconditionally,
            # so the trace faithfully reports that behaviour.
            admitted = True
        fate = "admitted" if admitted else "quarantined"
        role_kind = self._role_map.get(sender, ADMISSION_KIND_LIVE)
        await self._log(ctx, f"admission:{sender}:{role_kind}:{fate}")
        await self._log(ctx, f"report:{sender}:{self._victim}:{kind}:{fate}")

        self._processed += 1
        await self._maybe_finish(ctx, trust)

    async def _maybe_finish(self, ctx: AgentContext, trust: Any) -> None:
        if self._done or self._processed < self._expected:
            return
        self._done = True
        score = await trust.score(self._victim)
        await self._log(ctx, f"repscore:{self._victim}:{score.score:.6f}:{score.sample_count}")


class SinkAgent(StateMachineAgent):
    """The victim: a passive sink that absorbs the observer's audit lines.

    Example::

        victim = SinkAgent(AgentId("victim"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ignore all incoming audit lines.

        Example::

            await victim.on_message(ctx, observer, b"repscore:...")
        """
        return


def _role_counts(config: ScenarioConfig) -> dict[str, int]:
    """Resolve reporter role counts from the scenario's ``agents.roles`` block.

    Example::

        counts = _role_counts(config)
    """
    defaults = {"honest": 8, "sybil": 20, "revoked": 2, "escalator": 1, "stale": 1}
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name in defaults:
                defaults[role.name] = role.count
    return defaults


def _issue_grant_or_raise(
    trust: DelegatedAdmissionTrust,
    principal_id: str,
    principal_key: Any,
    delegate_id: str,
    *,
    scope: tuple[str, ...],
    parent_delegation_id: str | None,
    now_ms: int,
) -> str:
    """Mint one grant against *trust*'s current clock; return its delegation id.

    Example::

        did = _issue_grant_or_raise(
            trust, pid, priv, "honest-0",
            scope=("trust.report",), parent_delegation_id=None, now_ms=NOW,
        )
    """
    from nest_plugins_reference.trust.delegated_admission import (
        DelegationSubject,
        build_proof,
        envelope_hash,
    )

    subject = DelegationSubject(
        delegate_id=delegate_id,
        granted_scope=scope,
        expires_at=_NOW_S + _GRANT_TTL_S,
        parent_delegation_id=parent_delegation_id,
        revocable=True,
    )
    envelope, proof = build_proof(principal_id, principal_key, subject, now_ms=now_ms)
    result = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    if not result.ok or result.delegation_id is None:
        msg = f"scenario setup failed: grant({delegate_id}) rejected with reason={result.reason!r}"
        raise RuntimeError(msg)
    return result.delegation_id


def _provision_trust(
    plugins: dict[str, Any],
    observer_id: AgentId,
    honest_ids: list[AgentId],
    revoked_ids: list[AgentId],
    escalator_ids: list[AgentId],
    stale_ids: list[AgentId],
) -> str | None:
    """Instantiate the observer's trust plugin and seed every grant.

    Returns the chain-root delegation id when the configured plugin exposes
    the delegated-admission surface; ``None`` under a baseline plugin (no
    grants exist, so nothing to cascade). Mirrors the capability-gated
    per-agent provisioning attested_peering uses.

    Example::

        root_id = _provision_trust(plugins, observer_id, honest, revoked, escalator, stale)
    """
    trust_cls = plugins.get("trust")
    if trust_cls is None or not isinstance(trust_cls, type):
        return None

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})

    # Capability gate: baseline plugins (score_average) have no grant surface.
    if not (
        hasattr(trust_cls, "grant")
        and hasattr(trust_cls, "revoke")
        and hasattr(trust_cls, "set_clock")
    ):
        agent_plugins.setdefault(observer_id, {})["trust"] = trust_cls()
        plugins.pop("trust", None)
        return None

    from nest_plugins_reference.trust.delegated_admission import (
        PUH_FRESHNESS_MS,
        AdmissionPolicy,
        _public_raw,  # pyright: ignore[reportPrivateUsage]  # scenario setup only
        derive_principal,
    )

    principal_id, principal_key = derive_principal(b"delegated-admission:scenario:principal")
    policy = AdmissionPolicy(
        trusted_principals={principal_id: _public_raw(principal_key)},
        required_scope=_REQUIRED_SCOPE,
    )
    trust = trust_cls(
        agent_id=observer_id,
        seed=b"delegated-admission",
        policy=policy,
    )
    trust.set_clock(_NOW_MS)

    # Chain root — a grant with a synthetic delegate id nobody will report as,
    # used exclusively as the parent to revoke for the cascade demonstration.
    root_id = _issue_grant_or_raise(
        trust,
        principal_id,
        principal_key,
        "chain-root",
        scope=(_REQUIRED_SCOPE,),
        parent_delegation_id=None,
        now_ms=_NOW_MS,
    )

    # Honest grants (direct from the principal, in scope, fresh).
    for aid in honest_ids:
        _issue_grant_or_raise(
            trust,
            principal_id,
            principal_key,
            str(aid),
            scope=(_REQUIRED_SCOPE,),
            parent_delegation_id=None,
            now_ms=_NOW_MS,
        )

    # Revoked grants (children of chain-root — cascade will kill them).
    for aid in revoked_ids:
        _issue_grant_or_raise(
            trust,
            principal_id,
            principal_key,
            str(aid),
            scope=(_REQUIRED_SCOPE,),
            parent_delegation_id=root_id,
            now_ms=_NOW_MS,
        )

    # Escalator grants (in-scope for something else, missing the required scope).
    for aid in escalator_ids:
        _issue_grant_or_raise(
            trust,
            principal_id,
            principal_key,
            str(aid),
            scope=(_OFF_SCOPE_ESCALATOR,),
            parent_delegation_id=None,
            now_ms=_NOW_MS,
        )

    # Stale grants: mint them at a clock in the past so the proof's
    # ``bound_at_ms`` falls outside PUH_FRESHNESS_MS when reports arrive.
    stale_now_ms = _NOW_MS - PUH_FRESHNESS_MS - _STALE_SLACK_MS
    trust.set_clock(stale_now_ms)
    for aid in stale_ids:
        _issue_grant_or_raise(
            trust,
            principal_id,
            principal_key,
            str(aid),
            scope=(_REQUIRED_SCOPE,),
            parent_delegation_id=None,
            now_ms=stale_now_ms,
        )
    trust.set_clock(_NOW_MS)

    agent_plugins.setdefault(observer_id, {})["trust"] = trust
    plugins.pop("trust", None)
    return root_id


def delegated_admission_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the observer, victim sink, and honest + four adversarial reporter roles.

    Role counts come from ``agents.roles`` (defaults: 8 honest, 20 sybil, 2
    revoked, 1 escalator, 1 stale). Honest reporters file *positive* evidence;
    every attacker files *negative* evidence but is quarantined by the
    delegated-admission gate — under a baseline plugin those negatives are
    admitted and the victim's score collapses.

    Example::

        agents = delegated_admission_factory(config, plugins)
    """
    counts = _role_counts(config)
    observer_id = AgentId("observer")
    task_config = config.task.config
    victim_id = AgentId(str(task_config.get(_VICTIM_CONFIG_KEY, _DEFAULT_VICTIM_ID)))

    honest_ids = [AgentId(f"honest-{i}") for i in range(counts["honest"])]
    sybil_ids = [AgentId(f"sybil-{i}") for i in range(counts["sybil"])]
    revoked_ids = [AgentId(f"revoked-{i}") for i in range(counts["revoked"])]
    escalator_ids = [AgentId(f"escalator-{i}") for i in range(counts["escalator"])]
    stale_ids = [AgentId(f"stale-{i}") for i in range(counts["stale"])]
    reporter_ids = honest_ids + sybil_ids + revoked_ids + escalator_ids + stale_ids

    role_map: dict[AgentId, str] = {}
    for aid in honest_ids:
        role_map[aid] = ADMISSION_KIND_LIVE
    for aid in sybil_ids:
        role_map[aid] = ADMISSION_KIND_NO_GRANT
    for aid in revoked_ids:
        role_map[aid] = ADMISSION_KIND_REVOKED
    for aid in escalator_ids:
        role_map[aid] = ADMISSION_KIND_SCOPE_INVALID
    for aid in stale_ids:
        role_map[aid] = ADMISSION_KIND_STALE

    cascade_root_id = _provision_trust(
        plugins, observer_id, honest_ids, revoked_ids, escalator_ids, stale_ids
    )

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in honest_ids:
        agents[aid] = ReporterAgent(aid, observer_id, "positive")
    for aid in sybil_ids + revoked_ids + escalator_ids + stale_ids:
        agents[aid] = ReporterAgent(aid, observer_id, "negative")

    agents[observer_id] = ObserverAgent(
        observer_id,
        victim_id,
        role_map=role_map,
        cascade_root_id=cascade_root_id,
        expected=len(reporter_ids),
    )
    agents[victim_id] = SinkAgent(victim_id)
    return agents
