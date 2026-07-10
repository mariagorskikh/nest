# SPDX-License-Identifier: Apache-2.0
"""Attested-peering trust scenario — a Sybil swarm tries to defame one victim.

A single ``observer`` maintains the reputation of one honest ``victim``.
Reporters file evidence about the victim; the observer admits a report only
if the reporter first clears the attested-peering handshake
(:mod:`nest_plugins_reference.trust.attested_peering`). Four reporter roles
stress the gate:

* **honest** — a real passport delegated by a trusted operator, a valid boot
  quote, and genuine key possession. Verdict ``ALLOW``; files a *positive*
  report (the victim behaved well).
* **sybil** — a freshly minted self-asserted identity with no operator
  delegation. Verdict ``DENY`` at "who do you work for?"; its *negative*
  report is quarantined.
* **impostor** — presents the honest agent's stolen passport but signs the
  session transcript with its *own* key. Verdict ``DENY`` at "friend or foe?"
  (key possession fails).
* **replayer** — presents the honest passport plus a *real* honest seal
  captured from an earlier session, replayed against a fresh nonce. Verdict
  ``DENY`` at "friend or foe?" (the stale signature does not cover this
  transcript).

The agents resolve their trust plugin from ``ctx.plugins["trust"]`` and
capability-gate the handshake on ``hasattr(trust, "make_hail")``. Swapping
``trust: score_average`` in the YAML genuinely changes behaviour: with no
handshake the observer admits *every* report, so the Sybil swarm drags the
victim's score to the floor — exactly what the
``validate_attested_sybil_quarantined`` validator fails on. Under
``trust: attested_peering`` only the honest positives count and the victim's
score stays high.

Trace line protocol (message bodies, ``:``-delimited; the observer emits its
audit lines by sending them to the passive ``victim`` sink):

* ``verdict:<reporter>:<claimed_id>:<ALLOW|DENY>:<foe>:<data>:<work>`` — the
  handshake verdict for one reporter (``foe``/``data``/``work`` are ``1``/``0``).
* ``report:<reporter>:<subject>:<kind>:<admitted|quarantined>`` — the fate of
  one evidence report.
* ``repscore:<subject>:<score>:<sample_count>`` — the victim's final
  reputation, formatted to six decimals.

Example::

    agents = attested_peering_factory(config, plugins)
"""

from __future__ import annotations

import base64
import json
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Evidence

_OPERATOR_SEED = b"attested-peering:honest-operator"
_SCENARIO_SEED = b"attested-peering"


def _encode(obj: dict[str, Any]) -> str:
    """Encode a handshake message dict as a compact base64 token.

    Example::

        token = _encode({"op": "hail"})
    """
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _decode(token: str) -> dict[str, Any]:
    """Decode a base64 token produced by :func:`_encode`.

    Example::

        obj = _decode(token)
    """
    return json.loads(base64.b64decode(token.encode("ascii")).decode("utf-8"))


class ReporterAgent(StateMachineAgent):
    """A reporter that files one evidence report about the victim.

    ``role`` selects the attack: ``honest`` behaves correctly, ``sybil`` has no
    operator delegation, ``impostor`` presents a stolen passport, ``replayer``
    replays a captured honest seal. When the configured trust plugin has no
    ``make_hail`` (e.g. ``score_average``) the agent skips the handshake and
    sends its evidence directly — the baseline path the discrimination
    validator catches.

    Example::

        agent = ReporterAgent(AgentId("honest-0"), AgentId("observer"), "honest")
    """

    def __init__(
        self,
        agent_id: AgentId,
        observer: AgentId,
        role: str,
        report_kind: str,
        stolen_card: dict[str, Any] | None = None,
        replay_seal: dict[str, Any] | None = None,
    ) -> None:
        self._id = agent_id
        self._observer = observer
        self._role = role
        self._report_kind = report_kind
        self._stolen_card = stolen_card
        self._replay_seal = replay_seal

    def _present_card(self, trust: Any) -> Any:
        """Return the passport to present (stolen for impostor/replayer)."""
        if self._role in ("impostor", "replayer") and self._stolen_card is not None:
            from nest_plugins_reference.trust.attested_peering import AgentFactsCard

            return AgentFactsCard.from_dict(self._stolen_card)
        return None

    async def on_start(self, ctx: AgentContext) -> None:
        """Open the handshake, or send evidence directly under a baseline plugin.

        Example::

            await agent.on_start(ctx)
        """
        trust = ctx.plugins.get("trust")
        if trust is not None and hasattr(trust, "make_hail"):
            hail = trust.make_hail(
                report_kind=self._report_kind, present_card=self._present_card(trust)
            )
            await ctx.send(self._observer, f"hail:{_encode(hail)}".encode())
        else:
            await ctx.send(self._observer, f"claim:{self._report_kind}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Answer a vouch with a seal (honest, forged, or replayed).

        Example::

            await agent.on_message(ctx, observer, b"vouch:...")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("vouch:"):
            return
        trust = ctx.plugins.get("trust")
        if trust is None or not hasattr(trust, "make_seal"):
            return
        vouch = _decode(msg[len("vouch:") :])
        if self._role == "replayer" and self._replay_seal is not None:
            # Replay a genuine honest seal captured from an earlier session; it
            # cannot cover this session's fresh transcript.
            seal = self._replay_seal
        else:
            # honest / sybil / impostor all sign the live transcript with their
            # OWN key (the impostor's key does not match the stolen passport).
            seal = trust.make_seal(vouch)
        await ctx.send(self._observer, f"seal:{_encode(seal)}".encode())


class ObserverAgent(StateMachineAgent):
    """Runs the verifier trust plugin and records the victim's reputation.

    For each reporter it completes the handshake (or accepts a direct claim
    under a baseline plugin), files the reporter's evidence about the victim
    through the trust plugin, and emits ``verdict``/``report`` audit lines. Once
    every reporter has been processed it emits the final ``repscore`` line.

    Example::

        observer = ObserverAgent(AgentId("observer"), AgentId("victim"), 30)
    """

    def __init__(self, agent_id: AgentId, victim: AgentId, expected: int) -> None:
        self._id = agent_id
        self._victim = victim
        self._expected = expected
        self._processed = 0
        self._done = False

    async def _log(self, ctx: AgentContext, line: str) -> None:
        await ctx.send(self._victim, line.encode())

    async def _record_report(
        self, ctx: AgentContext, reporter: AgentId, kind: str, trust: Any
    ) -> None:
        evidence = Evidence(reporter=reporter, subject=self._victim, kind=kind)
        await trust.report(self._victim, evidence)
        is_attested = getattr(trust, "is_attested", None)
        admitted = True if is_attested is None else bool(is_attested(reporter))
        fate = "admitted" if admitted else "quarantined"
        await self._log(ctx, f"report:{reporter}:{self._victim}:{kind}:{fate}")
        self._processed += 1
        await self._maybe_finish(ctx, trust)

    async def _maybe_finish(self, ctx: AgentContext, trust: Any) -> None:
        if self._done or self._processed < self._expected:
            return
        self._done = True
        score = await trust.score(self._victim)
        await self._log(ctx, f"repscore:{self._victim}:{score.score:.6f}:{score.sample_count}")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Drive the handshake and evidence intake for each reporter.

        Example::

            await observer.on_message(ctx, reporter, b"hail:...")
        """
        msg = payload.decode("utf-8", errors="replace")
        trust = ctx.plugins.get("trust")
        if trust is None:
            return

        if msg.startswith("hail:") and hasattr(trust, "make_vouch"):
            hail = _decode(msg[len("hail:") :])
            vouch = trust.make_vouch(hail, session_key=sender)
            await ctx.send(sender, f"vouch:{_encode(vouch)}".encode())
            return

        if msg.startswith("seal:") and hasattr(trust, "evaluate_seal"):
            seal = _decode(msg[len("seal:") :])
            verdict = trust.evaluate_seal(sender, seal)
            await self._log(
                ctx,
                (
                    f"verdict:{sender}:{verdict.peer_id}:{verdict.decision}:"
                    f"{int(verdict.friend_or_foe.ok)}:{int(verdict.trust_my_data.ok)}:"
                    f"{int(verdict.who_you_work_for.ok)}"
                ),
            )
            kind = trust.session_report_kind(sender)
            await self._record_report(ctx, sender, kind, trust)
            return

        if msg.startswith("claim:"):
            kind = msg[len("claim:") :]
            await self._record_report(ctx, sender, kind, trust)


class SinkAgent(StateMachineAgent):
    """The victim: a passive sink that absorbs the observer's audit lines.

    The observer emits its ``verdict``/``report``/``repscore`` lines by sending
    them here so they land in the trace as ordinary ``send`` events the
    validators parse. The sink itself does nothing.

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
    defaults = {"honest": 8, "sybil": 20, "impostor": 1, "replayer": 1}
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name in defaults:
                defaults[role.name] = role.count
    return defaults


def _capture_replay_seal(observer_id: AgentId, honest_id: AgentId) -> dict[str, Any]:
    """Capture a genuine honest seal from a throwaway session, for the replayer.

    Uses instances seeded on a distinct RNG stream so their handshake nonces
    can never coincide with the live session — the captured seal is a *valid*
    honest signature that simply does not cover the live transcript.

    Example::

        seal = _capture_replay_seal(AgentId("observer"), AgentId("honest-0"))
    """
    import random

    from nest_plugins_reference.trust.attested_peering import AttestedPeeringTrust

    cap_honest = AttestedPeeringTrust(
        agent_id=honest_id,
        seed=_SCENARIO_SEED,
        operator_seed=_OPERATOR_SEED,
        offer_env=True,
        rng=random.Random("attested-peering:capture:honest"),
    )
    cap_obs = AttestedPeeringTrust(
        agent_id=observer_id,
        seed=_SCENARIO_SEED,
        rng=random.Random("attested-peering:capture:observer"),
    )
    hail = cap_honest.make_hail(report_kind="positive")
    vouch = cap_obs.make_vouch(hail, session_key=honest_id)
    return cap_honest.make_seal(vouch)


def _provision_trust(
    plugins: dict[str, Any],
    observer_id: AgentId,
    honest_ids: list[AgentId],
    reporter_ids: list[AgentId],
) -> None:
    """Instantiate one trust plugin per agent from the configured class.

    Mirrors ``identity_rotation``'s per-agent provisioning. For the
    attested-peering plugin every agent gets its own keyed instance and the
    observer is told which operator + boot state to trust. For a baseline trust
    plugin (e.g. ``score_average``, no ``make_hail``) only the observer gets a
    single shared instance; reporters send evidence directly. No-op when no
    trust plugin is configured.

    Example::

        _provision_trust(plugins, AgentId("observer"), honest, reporters)
    """
    from nest_plugins_reference.trust.attested_peering import PeeringPolicy

    trust_cls = plugins.get("trust")
    if trust_cls is None or not isinstance(trust_cls, type):
        return

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    is_attested = hasattr(trust_cls, "make_hail")

    if not is_attested:
        agent_plugins.setdefault(observer_id, {})["trust"] = trust_cls()
        plugins.pop("trust", None)
        return

    observer_trust = trust_cls(
        agent_id=observer_id,
        seed=_SCENARIO_SEED,
        policy=PeeringPolicy(require_trusted_operator=True, require_env_quote=False),
        principal_name="Reputation Observer",
    )

    for aid in reporter_ids:
        is_honest = aid in honest_ids
        reporter_trust = trust_cls(
            agent_id=aid,
            seed=_SCENARIO_SEED,
            operator_seed=_OPERATOR_SEED if is_honest else None,
            offer_env=is_honest,
            principal_name="Community Node" if is_honest else str(aid),
        )
        agent_plugins.setdefault(aid, {})["trust"] = reporter_trust
        if is_honest:
            observer_trust.trust_operator(
                reporter_trust.operator_id, reporter_trust.operator_public_key
            )

    observer_trust.allow_boot_state()
    agent_plugins.setdefault(observer_id, {})["trust"] = observer_trust
    plugins.pop("trust", None)


def attested_peering_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the observer, victim sink, and honest + adversarial reporters.

    Role counts come from ``agents.roles`` (defaults: 8 honest, 20 sybil, 1
    impostor, 1 replayer). Honest reporters file *positive* evidence; every
    attacker files *negative* evidence but is denied and quarantined under the
    attested-peering plugin.

    Example::

        agents = attested_peering_factory(config, plugins)
    """
    counts = _role_counts(config)
    observer_id = AgentId("observer")
    victim_id = AgentId("victim")

    honest_ids = [AgentId(f"honest-{i}") for i in range(counts["honest"])]
    sybil_ids = [AgentId(f"sybil-{i}") for i in range(counts["sybil"])]
    impostor_ids = [AgentId(f"impostor-{i}") for i in range(counts["impostor"])]
    replayer_ids = [AgentId(f"replayer-{i}") for i in range(counts["replayer"])]
    reporter_ids = honest_ids + sybil_ids + impostor_ids + replayer_ids

    _provision_trust(plugins, observer_id, honest_ids, reporter_ids)

    # The impostor and replayer both target the first honest identity.
    stolen_card: dict[str, Any] | None = None
    replay_seal: dict[str, Any] | None = None
    agent_plugins = plugins.get("_agent_plugins", {})
    honest_head = honest_ids[0] if honest_ids else None
    if honest_head is not None:
        head_trust = agent_plugins.get(honest_head, {}).get("trust")
        if head_trust is not None and hasattr(head_trust, "card"):
            stolen_card = head_trust.card.to_dict()
            replay_seal = _capture_replay_seal(observer_id, honest_head)

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in honest_ids:
        agents[aid] = ReporterAgent(aid, observer_id, "honest", "positive")
    for aid in sybil_ids:
        agents[aid] = ReporterAgent(aid, observer_id, "sybil", "negative")
    for aid in impostor_ids:
        agents[aid] = ReporterAgent(
            aid, observer_id, "impostor", "negative", stolen_card=stolen_card
        )
    for aid in replayer_ids:
        agents[aid] = ReporterAgent(
            aid,
            observer_id,
            "replayer",
            "negative",
            stolen_card=stolen_card,
            replay_seal=replay_seal,
        )

    agents[observer_id] = ObserverAgent(observer_id, victim_id, expected=len(reporter_ids))
    agents[victim_id] = SinkAgent(victim_id)
    return agents
