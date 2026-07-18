# SPDX-License-Identifier: Apache-2.0
"""Consulting marketplace scenario — clients negotiating with AI consultants.

Each client negotiates exclusively with a paired consultant over three
attributes of a consulting engagement:

``p``  — price premium (0–100 credits/token, integer)
         Clients prefer low rates; consultants prefer high rates.
``n``  — token budget (expected tokens to complete the task, integer)
         A static estimate agreed at contract time; it is not recalculated
         against any real workload.  Clients prefer smaller budgets (lower
         total cost = p * n); consultants prefer larger committed volumes
         (more revenue).  The integrative potential: the joint-optimal
         token budget differs from both parties' opening positions.
``q``  — quality tier (0.0–1.0 float, static per pair)
         Represents the service tier (0.60 = standard, 0.80 = premium,
         0.90 = enterprise).  Quality is fixed at the start of each session
         by the pair's service-tier constant; it is never moved during
         bargaining but gates feasibility (a client's min_quality sets the
         minimum tier they will accept).

Persona mapping
---------------
``client-i``     — an organisation looking to hire an AI consulting firm.
                   Prefers low price per token and a bounded token budget,
                   has a hard ceiling on total budget encoded as max_p.
``consultant-i`` — an AI consulting firm offering its services.
                   Prefers high price per token and a large committed
                   volume, has a floor rate encoded as min_p.

The integrative quantity axis
-----------------------------
Clients have a *convex* kappa penalty on token budget:

    v_n(n) = 1 - kappa * (n - target_n)^2

Their ideal budget is ``target_n`` — they dislike over-engineering
(too many tokens) as much as under-engineering (too few).

Consultants have a *linear* volume benefit:

    v_n(n) = min(n / capacity, 1.0)

More committed tokens always improves consultant utility (up to capacity).

Because the client's ideal n and the consultant's ideal n differ, and because
both utility functions respond in opposite directions to n, there exists a
joint-optimal token budget that is strictly better for BOTH parties than
either opening offer.  The Pareto strategies find this; alternating_offers
does not (it never moves n).

Opening offer design
--------------------
A key correctness requirement: the opening offer must be inside the joint
feasible zone so that neither agent immediately breaks down.  The factory
computes the joint zone per pair and opens at the midpoint price with the
client's ideal token budget, clamped to the joint range.

Agents also clamp every outgoing counter-proposal to their own reservation
bounds before sending — this prevents TTT and Zeuthen from proposing values
outside their own range that the opponent would immediately reject.

Trace line protocol
-------------------
``config:<agent_id>:<json_params>``
    Emitted once in ``on_start``.

``offer:<from>:<to>:r<round>:p=<p>,n=<n>,q=<q>:<strategy_id>``
    Emitted on every outgoing offer/counter-offer.

``close:agreed:<session_id>:p=<p>,n=<n>,q=<q>``
    Emitted on agreement.

``close:breakdown:<session_id>``
    Emitted on breakdown (quality-tier mismatch, no mutual gain, round limit).

Example::

    agents = multi_attribute_market_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, Terms

# ---------------------------------------------------------------------------
# Quality tiers per pair (token-budget negotiation has a fixed service tier)
# ---------------------------------------------------------------------------
# Pairs 0–6 and 9: normal negotiation, agreements expected.
# Pair 7: genuine price-gap breakdown — client's max_p is tightened so the
#   client and consultant can never bridge the price gap within 10 rounds.
#   At least 3 rounds of genuine bargaining occur before rounds are exhausted.
# Pair 8: quality-tier breakdown — pair quality (0.55) is below client-8's
#   min_quality (0.75), so respond() rejects on the quality gate immediately.
_QUALITY_BY_PAIR = [0.80, 0.75, 0.85, 0.90, 0.65, 0.78, 0.82, 0.80, 0.55, 0.88]

# Pair 7: price-gap breakdown — client's max_p is set very low so the joint
# zone is too narrow to bridge within the round budget.
_PRICE_GAP_BREAKDOWN_PAIR = 7
_PRICE_GAP_MAX_P = 30  # joint zone p=[24,30] is tight; consultant target_p=44 >> 30
# so after some rounds the consultant refuses to concede below its target and
# the client cannot go above 30 — rounds are exhausted without agreement.

# Pair 8: quality-tier breakdown — client's min_quality is raised above pair quality.
_QUALITY_BREAKDOWN_PAIR = 8
_QUALITY_BREAKDOWN_MIN_QUALITY = 0.75  # client-8 requires >= 0.75; pair-8 offers 0.55


# ---------------------------------------------------------------------------
# Consulting marketplace agent
# ---------------------------------------------------------------------------


class ConsultingNegotiatorAgent(StateMachineAgent):
    """A client or consultant that bargains over price/token-budget/quality tier.

    The ``plugin`` is a ParetoNegotiator (or AlternatingOffers for the
    adversarial control run).  All utility params live inside the plugin;
    the agent is a thin message-passing shell.

    Opening offer design
    --------------------
    The client opens at the midpoint of the joint feasible price range and
    the client's ideal token budget, clamped to the joint n range.  This
    guarantees the opening offer is feasible for both parties so neither
    agent enters a breakdown on the very first message.

    Counter-proposal clamping
    -------------------------
    Before sending any counter-proposal the agent clamps (p, n) to its own
    reservation bounds.  This prevents TTT from proposing p=0 (below
    consultant floor) or p=100 (above client ceiling) after mirroring a
    large movement delta.

    Example::

        agent = ConsultingNegotiatorAgent(
            agent_id=AgentId("client-3"),
            role="client",
            partner_id=AgentId("consultant-3"),
            plugin=neg_plugin,
            rounds=10,
            pair_quality=0.80,
            strategy_id="ttt_directional",
            open_p=48,
            open_n=20,
            own_min_p=0,
            own_max_p=73,
            own_min_n=4,
            own_max_n=42,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        role: str,
        partner_id: AgentId,
        plugin: Any,
        rounds: int,
        pair_quality: float,
        strategy_id: str,
        open_p: int,
        open_n: int,
        own_min_p: int,
        own_max_p: int,
        own_min_n: int,
        own_max_n: int,
    ) -> None:
        self._id = agent_id
        self._role = role
        self._partner_id = partner_id
        self._plugin = plugin
        self._rounds = rounds
        self._pair_quality = pair_quality
        self._strategy_id = strategy_id
        self._open_p = open_p
        self._open_n = open_n
        self._own_min_p = own_min_p
        self._own_max_p = own_max_p
        self._own_min_n = own_min_n
        self._own_max_n = own_max_n
        self._session: Any = None
        self._round_count = 0

    def _clamp(self, p: int, n: int) -> tuple[int, int]:
        """Clamp (p,n) to own reservation bounds before sending."""
        return (
            max(self._own_min_p, min(self._own_max_p, p)),
            max(self._own_min_n, min(self._own_max_n, n)),
        )

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit sealed config; client opens the session at the joint midpoint."""
        params = getattr(self._plugin, "params", None)
        if params is not None:
            config_json = json.dumps(params.to_dict(), separators=(",", ":"))
            await ctx.send(
                self._partner_id,
                f"config:{ctx.agent_id}:{config_json}".encode(),
            )

        if self._role == "client":
            initial_terms = Terms(
                price=Money(amount=self._open_p),
                conditions={"quantity": self._open_n, "quality": self._pair_quality},
            )
            self._session = await self._plugin.open(self._partner_id, initial_terms)
            await ctx.send(
                self._partner_id,
                self._encode_offer(self._open_p, self._open_n, self._pair_quality, 0),
            )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle incoming config announcements and offers."""
        msg = payload.decode("utf-8", errors="replace")

        if msg.startswith("config:"):
            return  # informational only

        if not msg.startswith("offer:"):
            return

        result = _decode_offer(msg)
        if result is None:
            return

        raw_p, raw_n, q = result
        # Clamp the incoming offer to own reservation before presenting to plugin.
        # This converts "opponent quoted outside my budget" into "here is the most
        # I can offer on that axis" — real negotiation rather than immediate breakdown.
        p, n = self._clamp(raw_p, raw_n)
        self._round_count += 1

        if self._session is None:
            # Consultant creates its session on first client message
            self._session = await self._plugin.open(
                sender,
                Terms(price=Money(amount=p), conditions={"quantity": n, "quality": q}),
            )
        else:
            await self._plugin.offer(
                self._session,
                Terms(price=Money(amount=p), conditions={"quantity": n, "quality": q}),
            )

        if self._round_count >= self._rounds:
            await self._finalize(ctx, q)
            return

        resp = await self._plugin.respond(self._session)

        if resp.accepted:
            await self._finalize(ctx, q)
            return

        if resp.counter_terms is None:
            await self._emit_breakdown(ctx)
            return

        ct = resp.counter_terms
        raw_p = ct.price.amount if ct.price else p
        raw_n = int(ct.conditions.get("quantity", n))
        # Clamp to own reservation so we never propose outside our range
        cp, cn = self._clamp(raw_p, raw_n)
        cq = float(ct.conditions.get("quality", q))

        await ctx.send(sender, self._encode_offer(cp, cn, cq, self._round_count))

    async def _finalize(self, ctx: AgentContext, q: float) -> None:
        if self._session is None:
            return
        agreement = await self._plugin.close(self._session)
        if agreement is not None:
            terms = agreement.terms
            p = terms.price.amount if terms.price else 0
            n = int(terms.conditions.get("quantity", 0))
            await ctx.send(
                self._partner_id,
                f"close:agreed:{agreement.session_id}:p={p},n={n},q={q:.4f}".encode(),
            )
        else:
            await self._emit_breakdown(ctx)

    async def _emit_breakdown(self, ctx: AgentContext) -> None:
        sid = self._session.id if self._session else "unknown"
        await ctx.send(self._partner_id, f"close:breakdown:{sid}".encode())

    def _encode_offer(self, p: int, n: int, q: float, rnd: int) -> bytes:
        label = "tokens"  # human-readable name for quantity in consulting context
        msg = (
            f"offer:{self._id}:{self._partner_id}:r{rnd}:"
            f"p={p},n={n},q={q:.4f}:{self._strategy_id}"
            f" # {self._role} proposes {p} cr/token × {n} {label} @ tier {q:.2f}"
        )
        return msg.encode()


def _decode_offer(msg: str) -> tuple[int, int, float] | None:
    """Parse ``offer:…:p=<p>,n=<n>,q=<q>:…`` message."""
    # Strip human-readable comment suffix before splitting
    msg = msg.split(" # ")[0]
    parts = msg.split(":")
    if len(parts) < 6:
        return None
    attrs_part = parts[4]
    try:
        kv = dict(item.split("=") for item in attrs_part.split(","))
        return int(kv["p"]), int(kv["n"]), float(kv["q"])
    except (ValueError, KeyError):
        return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def multi_attribute_market_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create 10 client-consultant pairs for the consulting marketplace.

    For each pair the factory:

    1.  Derives per-agent ParetoParams deterministically from (agent_id, seed).
    2.  Computes the joint feasible zone (p, n) — the intersection of both
        agents' reservation bounds.
    3.  Opens at the midpoint of the joint price range with the client's ideal
        token budget (clamped to the joint n range).  This guarantees the
        opening is feasible for both parties.
    4.  Passes each agent its own reservation bounds so it can clamp outgoing
        counter-proposals before sending (preventing TTT/Zeuthen from proposing
        outside the joint zone).

    Example::

        agents = multi_attribute_market_factory(config, plugins)
    """
    from nest_plugins_reference.negotiation.pareto import ParetoNegotiator, ParetoParams

    task_cfg = config.task.config
    rounds = task_cfg.get("rounds", 10)
    n_pairs = task_cfg.get("pairs", 10)
    seed = config.seed

    negotiation_cls = plugins.get("negotiation")
    agents: dict[AgentId, StateMachineAgent] = {}

    for i in range(n_pairs):
        # Persona names: client-i looks for a consultant; consultant-i provides services
        client_id = AgentId(f"client-{i}")
        consultant_id = AgentId(f"consultant-{i}")
        quality = _QUALITY_BY_PAIR[i % len(_QUALITY_BY_PAIR)]

        if negotiation_cls is not None and (
            negotiation_cls is ParetoNegotiator
            or (isinstance(negotiation_cls, type) and issubclass(negotiation_cls, ParetoNegotiator))
        ):
            client_params = ParetoParams.for_buyer(client_id, seed, pair_index=i)
            consultant_params = ParetoParams.for_seller(consultant_id, seed, pair_index=i)

            # Pair 7: price-gap breakdown — tighten client's ceiling so the
            # joint price zone is too narrow to bridge in 10 rounds.
            # The consultant's min_p for pair 7 will be derived from the seed;
            # we force client's max_p low enough that joint_p_lo ≈ joint_p_hi,
            # leaving only 1–2 feasible price points.  Agents will negotiate
            # for several rounds but exhaust the round budget without agreement.
            if i == _PRICE_GAP_BREAKDOWN_PAIR:
                client_params.max_p = _PRICE_GAP_MAX_P

            # Pair 8: quality-tier breakdown — client requires enterprise tier
            # but the pair's fixed quality is standard tier → immediate rejection.
            if i == _QUALITY_BREAKDOWN_PAIR:
                client_params.min_quality = _QUALITY_BREAKDOWN_MIN_QUALITY

            client_plugin = ParetoNegotiator(client_id, client_params)
            consultant_plugin = ParetoNegotiator(consultant_id, consultant_params)
            client_strategy = client_params.strategy_id
            consultant_strategy = consultant_params.strategy_id
        else:
            if negotiation_cls is not None and isinstance(negotiation_cls, type):
                client_plugin = negotiation_cls(client_id)
                consultant_plugin = negotiation_cls(consultant_id)
            else:
                from nest_plugins_reference.negotiation.alternating_offers import AlternatingOffers

                client_plugin = AlternatingOffers(client_id)
                consultant_plugin = AlternatingOffers(consultant_id)
            # Derive ParetoParams for joint zone calculation even when using alt-offers
            client_params = ParetoParams.for_buyer(client_id, seed, pair_index=i)
            consultant_params = ParetoParams.for_seller(consultant_id, seed, pair_index=i)
            if i == _PRICE_GAP_BREAKDOWN_PAIR:
                client_params.max_p = _PRICE_GAP_MAX_P
            if i == _QUALITY_BREAKDOWN_PAIR:
                client_params.min_quality = _QUALITY_BREAKDOWN_MIN_QUALITY
            client_strategy = "alternating_offers"
            consultant_strategy = "alternating_offers"

        # Compute joint feasible zone
        joint_p_lo = max(client_params.min_p, consultant_params.min_p)
        joint_p_hi = min(client_params.max_p, 100)
        joint_n_lo = max(client_params.min_n, consultant_params.min_n)
        joint_n_hi = min(client_params.max_n, consultant_params.max_n)

        # Opening offer: midpoint price, client's ideal token budget clamped to joint n
        mid_p = (joint_p_lo + joint_p_hi) // 2
        open_n = max(joint_n_lo, min(joint_n_hi, client_params.target_n))
        open_p = max(joint_p_lo, min(joint_p_hi, mid_p))

        agents[client_id] = ConsultingNegotiatorAgent(
            agent_id=client_id,
            role="client",
            partner_id=consultant_id,
            plugin=client_plugin,
            rounds=rounds,
            pair_quality=quality,
            strategy_id=client_strategy,
            open_p=open_p,
            open_n=open_n,
            own_min_p=client_params.min_p,
            own_max_p=client_params.max_p,
            own_min_n=client_params.min_n,
            own_max_n=client_params.max_n,
        )
        agents[consultant_id] = ConsultingNegotiatorAgent(
            agent_id=consultant_id,
            role="consultant",
            partner_id=client_id,
            plugin=consultant_plugin,
            rounds=rounds,
            pair_quality=quality,
            strategy_id=consultant_strategy,
            open_p=open_p,
            open_n=open_n,
            own_min_p=consultant_params.min_p,
            own_max_p=100,
            own_min_n=consultant_params.min_n,
            own_max_n=consultant_params.max_n,
        )

    return agents
