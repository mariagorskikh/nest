# SPDX-License-Identifier: Apache-2.0
"""The Dealmakers — multi-attribute bargaining over price and quantity.

Agents negotiate simultaneously over two axes:

``p``  — price (credits, integer 0–100)
         Buyers prefer low; sellers prefer high.
``q``  — quantity (units, integer 1–50)
         Buyers have a convex sweet-spot (target_q); sellers prefer larger volumes.

The integrative tension
-----------------------
A buyer's ideal quantity differs from a seller's preferred quantity, and both
utility functions respond in opposite directions.  The Pareto-optimal contract
is strictly better for BOTH parties than either side's opening position, but
only strategies that move both axes simultaneously find it.

Trace line protocol
-------------------
``config:<agent_id>:<json_params>``
    Emitted once in ``on_start``.

``offer:<from>:<to>:r<round>:p=<p>,q=<q>:<strategy>``
    Emitted on every outgoing offer/counter-offer.

``close:agreed:<session_id>:p=<p>,q=<q>``
    Emitted on agreement.

``close:breakdown:<session_id>``
    Emitted on breakdown (round limit, no mutual gain, or reservation clash).

Example::

    agents = dealmakers_factory(config, plugins)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, Terms

# ---------------------------------------------------------------------------
# Deterministic per-agent parameters derived from (agent_id, seed, pair_index)
# ---------------------------------------------------------------------------

_P_MAX = 100  # price ceiling
_Q_MAX = 50  # quantity ceiling


def _hash_scalar(agent_id: str, seed: int, salt: str) -> float:
    """Return a deterministic float in [0, 1) from agent_id + seed + salt.

    Example::

        v = _hash_scalar("buyer-0", 42, "min_p")
        assert 0.0 <= v < 1.0
    """
    raw = f"{agent_id}:{seed}:{salt}".encode()
    digest = hashlib.sha256(raw).digest()
    return int.from_bytes(digest[:4], "big") / 0x1_0000_0000


class DealParams:
    """Utility parameters for one Dealmakers agent.

    Buyers minimise price and have a convex sweet-spot on quantity:

        u(p, q) = w_p * (1 - p/P_MAX) + w_q * (1 - kappa*(q - target_q)**2)

    Sellers maximise price and prefer larger volumes:

        u(p, q) = w_p * (p/P_MAX) + w_q * min(q/capacity, 1.0)

    Example::

        params = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        assert params.role == "buyer"
    """

    def __init__(
        self,
        agent_id: AgentId,
        role: str,
        w_p: float,
        w_q: float,
        min_p: int,
        max_p: int,
        target_p: int,
        min_q: int,
        max_q: int,
        target_q: int,
        capacity: int,
        kappa: float,
        strategy_id: str,
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self.w_p = w_p
        self.w_q = w_q
        self.min_p = min_p
        self.max_p = max_p
        self.target_p = target_p
        self.min_q = min_q
        self.max_q = max_q
        self.target_q = target_q
        self.capacity = capacity
        self.kappa = kappa
        self.strategy_id = strategy_id

    def utility(self, p: int, q: int) -> float:
        """Compute normalised utility in [0, 1] for offer (p, q).

        Example::

            u = params.utility(40, 20)
            assert 0.0 <= u <= 1.0
        """
        if self.role == "buyer":
            u_p = 1.0 - p / _P_MAX
            ideal = self.target_q
            span = max(self.max_q - self.min_q, 1)
            dev = (q - ideal) / span
            u_q = max(0.0, 1.0 - self.kappa * dev * dev)
        else:
            u_p = p / _P_MAX
            u_q = min(q / max(self.capacity, 1), 1.0)
        total_w = self.w_p + self.w_q
        return (self.w_p * u_p + self.w_q * u_q) / max(total_w, 1e-9)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict for the trace config line.

        Example::

            d = params.to_dict()
            assert d["role"] == params.role
        """
        return {
            "role": self.role,
            "w_p": self.w_p,
            "w_q": self.w_q,
            "min_p": self.min_p,
            "max_p": self.max_p,
            "target_p": self.target_p,
            "min_q": self.min_q,
            "max_q": self.max_q,
            "target_q": self.target_q,
            "capacity": self.capacity,
            "kappa": self.kappa,
            "strategy_id": self.strategy_id,
        }

    @classmethod
    def for_buyer(cls, agent_id: AgentId, seed: int, pair_index: int = 0) -> DealParams:
        """Derive buyer params deterministically from agent_id + seed + pair_index.

        Example::

            p = DealParams.for_buyer(AgentId("buyer-3"), 7, pair_index=3)
            assert p.role == "buyer"
        """
        aid = str(agent_id)
        _base_seed = seed + pair_index * 17

        def h(salt: str) -> float:
            return _hash_scalar(aid, _base_seed, salt)

        min_p = 10 + int(h("min_p") * 20)
        max_p = 55 + int(h("max_p") * 30)
        target_q = 10 + int(h("target_q") * 25)
        min_q = max(1, target_q - 5 - int(h("min_q_off") * 5))
        max_q = min(_Q_MAX, target_q + 5 + int(h("max_q_off") * 10))
        kappa = 0.05 + h("kappa") * 0.15
        strategies = ["logrolling", "ttt_mirror", "nash_split"]
        strategy_id = strategies[int(h("strategy") * len(strategies)) % len(strategies)]
        return cls(
            agent_id=agent_id,
            role="buyer",
            w_p=0.55 + h("w_p") * 0.20,
            w_q=0.25 + h("w_q") * 0.20,
            min_p=min_p,
            max_p=max_p,
            target_p=min_p + int(h("target_p") * (max_p - min_p) * 0.4),
            min_q=min_q,
            max_q=max_q,
            target_q=target_q,
            capacity=max_q,
            kappa=kappa,
            strategy_id=strategy_id,
        )

    @classmethod
    def for_seller(cls, agent_id: AgentId, seed: int, pair_index: int = 0) -> DealParams:
        """Derive seller params deterministically from agent_id + seed + pair_index.

        Example::

            p = DealParams.for_seller(AgentId("seller-3"), 7, pair_index=3)
            assert p.role == "seller"
        """
        aid = str(agent_id)
        _base_seed = seed + pair_index * 17

        def h(salt: str) -> float:
            return _hash_scalar(aid, _base_seed, salt)

        min_p = 20 + int(h("min_p") * 25)
        max_p = 65 + int(h("max_p") * 30)
        capacity = 25 + int(h("capacity") * 20)
        min_q = 5 + int(h("min_q") * 10)
        max_q = min(_Q_MAX, min_q + 15 + int(h("max_q_span") * 20))
        strategies = ["logrolling", "ttt_mirror", "nash_split"]
        strategy_id = strategies[int(h("strategy") * len(strategies)) % len(strategies)]
        return cls(
            agent_id=agent_id,
            role="seller",
            w_p=0.50 + h("w_p") * 0.25,
            w_q=0.25 + h("w_q") * 0.25,
            min_p=min_p,
            max_p=max_p,
            target_p=min_p + 10 + int(h("target_p") * (max_p - min_p - 10)),
            min_q=min_q,
            max_q=max_q,
            target_q=min_q + int(h("target_q") * (max_q - min_q)),
            capacity=capacity,
            kappa=0.02,
            strategy_id=strategy_id,
        )


# ---------------------------------------------------------------------------
# Inline negotiation logic (three strategies)
# ---------------------------------------------------------------------------


def logrolling_counter(
    own: DealParams,
    opp_p: int,
    opp_q: int,
    own_last_p: int,
    own_last_q: int,
    est_w_p: float,
    est_w_q: float,
    rnd: int,
) -> tuple[int, int]:
    """Log-rolling: stay on iso-utility contour, maximise estimated opponent utility.

    Move price toward opponent's offer proportionally; adjust quantity to hold
    own utility constant while improving estimated opponent utility.

    Example::

        cp, cq = logrolling_counter(params, 40, 20, 50, 18, 0.6, 0.4, 1)
    """
    # Concede a fraction of the price gap toward opponent
    concession = max(0.1, 0.5 - rnd * 0.04)
    if own.role == "buyer":
        new_p = own_last_p + int((opp_p - own_last_p) * concession)
        new_p = max(own.min_p, min(own.max_p, new_p))
        # On quantity: move toward opponent's q proportional to their estimated weight
        q_pull = est_w_q / max(est_w_p + est_w_q, 1e-6)
        new_q = own_last_q + int((opp_q - own_last_q) * q_pull * concession)
        new_q = max(own.min_q, min(own.max_q, new_q))
    else:
        new_p = own_last_p + int((opp_p - own_last_p) * concession)
        new_p = max(own.min_p, min(own.max_p, new_p))
        q_pull = est_w_q / max(est_w_p + est_w_q, 1e-6)
        new_q = own_last_q + int((opp_q - own_last_q) * q_pull * concession)
        new_q = max(own.min_q, min(own.max_q, new_q))
    return new_p, new_q


def ttt_mirror_counter(
    own: DealParams,
    opp_p: int,
    opp_q: int,
    own_last_p: int,
    own_last_q: int,
    opp_prev_p: int,
    opp_prev_q: int,
) -> tuple[int, int]:
    """TTT mirror: mirror the opponent's last move on each axis.

    Example::

        cp, cq = ttt_mirror_counter(params, 40, 20, 50, 18, 45, 22)
    """
    delta_p = opp_p - opp_prev_p
    delta_q = opp_q - opp_prev_q
    new_p = own_last_p + delta_p
    new_q = own_last_q + delta_q
    new_p = max(own.min_p, min(own.max_p, new_p))
    new_q = max(own.min_q, min(own.max_q, new_q))
    return new_p, new_q


def nash_split_counter(
    own: DealParams,
    opp_p: int,
    opp_q: int,
    own_last_p: int,
    own_last_q: int,
    rnd: int,
) -> tuple[int, int]:
    """Nash split: propose the midpoint between own last and opponent offer.

    Slightly biased toward own reservation bounds with increasing rounds.

    Example::

        cp, cq = nash_split_counter(params, 40, 20, 50, 18, 2)
    """
    bias = 0.5 + rnd * 0.03
    bias = min(bias, 0.75)
    new_p = int(own_last_p * bias + opp_p * (1.0 - bias))
    new_q = int(own_last_q * bias + opp_q * (1.0 - bias))
    new_p = max(own.min_p, min(own.max_p, new_p))
    new_q = max(own.min_q, min(own.max_q, new_q))
    return new_p, new_q


# ---------------------------------------------------------------------------
# Dealmaker agent
# ---------------------------------------------------------------------------


class DealmakerAgent(StateMachineAgent):
    """A buyer or seller that bargains over price and quantity.

    Uses one of three built-in strategies to generate counter-proposals.
    All state is local to a single session; no information persists across
    sessions.

    Example::

        agent = DealmakerAgent(
            agent_id=AgentId("buyer-0"),
            role="buyer",
            partner_id=AgentId("seller-0"),
            params=params,
            rounds=10,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        role: str,
        partner_id: AgentId,
        params: DealParams,
        rounds: int,
        open_p: int,
        open_q: int,
    ) -> None:
        self._id = agent_id
        self._role = role
        self._partner_id = partner_id
        self._params = params
        self._rounds = rounds
        self._open_p = open_p
        self._open_q = open_q

        # Within-session state
        self._session: Any = None
        self._round_count = 0
        self._own_last_p = open_p
        self._own_last_q = open_q
        self._opp_prev_p = open_p
        self._opp_prev_q = open_q

    def _counter(self, opp_p: int, opp_q: int) -> tuple[int, int]:
        """Compute a counter-proposal using the agent's configured strategy.

        Example::

            cp, cq = agent._counter(40, 20)
        """
        p = self._params
        est_wp, est_wq = 0.5, 0.5
        if p.strategy_id == "logrolling":
            return logrolling_counter(
                p,
                opp_p,
                opp_q,
                self._own_last_p,
                self._own_last_q,
                est_wp,
                est_wq,
                self._round_count,
            )
        if p.strategy_id == "ttt_mirror":
            return ttt_mirror_counter(
                p,
                opp_p,
                opp_q,
                self._own_last_p,
                self._own_last_q,
                self._opp_prev_p,
                self._opp_prev_q,
            )
        # default: nash_split
        return nash_split_counter(
            p,
            opp_p,
            opp_q,
            self._own_last_p,
            self._own_last_q,
            self._round_count,
        )

    def _accept(self, opp_p: int, opp_q: int) -> bool:
        """Return True if the opponent's offer meets or beats own target.

        Example::

            assert not agent._accept(99, 1)
        """
        p = self._params
        if p.role == "buyer":
            return opp_p <= p.target_p and p.min_q <= opp_q <= p.max_q
        return opp_p >= p.target_p and opp_q >= p.min_q

    def _encode_offer(self, p: int, q: int, rnd: int) -> bytes:
        label = "units"
        msg = (
            f"offer:{self._id}:{self._partner_id}:r{rnd}:"
            f"p={p},q={q}:{self._params.strategy_id}"
            f" # {self._role} proposes {p} cr × {q} {label}"
        )
        return msg.encode()

    async def on_start(self, ctx: AgentContext) -> None:
        """Emit sealed config; buyer opens the session.

        Example::

            await agent.on_start(ctx)
        """
        config_json = json.dumps(self._params.to_dict(), separators=(",", ":"))
        await ctx.send(
            self._partner_id,
            f"config:{ctx.agent_id}:{config_json}".encode(),
        )

        if self._role == "buyer":
            self._session = await self._plugin_open(
                self._partner_id,
                Terms(
                    price=Money(amount=self._open_p),
                    conditions={"quantity": self._open_q},
                ),
            )
            await ctx.send(
                self._partner_id,
                self._encode_offer(self._open_p, self._open_q, 0),
            )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle config announcements and offers.

        Example::

            await agent.on_message(ctx, AgentId("seller-0"), b"offer:...")
        """
        msg = payload.decode("utf-8", errors="replace")

        if msg.startswith("config:"):
            return

        if not msg.startswith("offer:"):
            return

        result = decode_offer(msg)
        if result is None:
            return

        opp_p, opp_q = result
        self._round_count += 1

        if self._session is None:
            # Seller creates session on first buyer message
            self._session = await self._plugin_open(
                sender,
                Terms(price=Money(amount=opp_p), conditions={"quantity": opp_q}),
            )
        self._opp_prev_p, self._opp_prev_q = self._own_last_p, self._own_last_q

        if self._round_count >= self._rounds or self._accept(opp_p, opp_q):
            await self._finalize(ctx, sender, opp_p, opp_q)
            return

        cp, cq = self._counter(opp_p, opp_q)
        self._own_last_p, self._own_last_q = cp, cq
        await ctx.send(sender, self._encode_offer(cp, cq, self._round_count))

    async def _finalize(
        self, ctx: AgentContext, partner: AgentId, final_p: int, final_q: int
    ) -> None:
        sid = str(self._session.id) if self._session is not None else "unknown"
        if self._accept(final_p, final_q):
            await ctx.send(
                partner,
                f"close:agreed:{sid}:p={final_p},q={final_q}".encode(),
            )
        else:
            await ctx.send(partner, f"close:breakdown:{sid}".encode())

    async def _plugin_open(self, partner: AgentId, terms: Terms) -> Any:
        """Open a lightweight in-agent session (no external plugin required).

        Example::

            session = await agent._plugin_open(AgentId("seller-0"), terms)
        """
        return _InlineSession(initiator=self._id, partner=partner, terms=terms)

    async def on_stop(self, ctx: AgentContext) -> None:
        """No-op; sessions are finalised in on_message.

        Example::

            await agent.on_stop(ctx)
        """


class _InlineSession:
    """Minimal session stub — carries partner and opening terms.

    Session ID is derived deterministically from (initiator, partner) so that
    two runs with the same inputs produce the same trace.

    Example::

        s = _InlineSession(AgentId("buyer-0"), AgentId("seller-0"), terms=terms)
        assert s.id.startswith("sess-")
    """

    def __init__(self, initiator: AgentId, partner: AgentId, terms: Terms) -> None:
        raw = f"{initiator}:{partner}".encode()
        digest = hashlib.sha256(raw).hexdigest()[:12]
        self.id = f"sess-{digest}"
        self.partner = partner
        self.terms = terms


def decode_offer(msg: str) -> tuple[int, int] | None:
    """Parse ``offer:…:p=<p>,q=<q>:…`` message, returning (p, q) or None.

    Example::

        decode_offer("offer:buyer-0:seller-0:r1:p=40,q=20:logrolling") == (40, 20)
    """
    msg = msg.split(" # ")[0]
    parts = msg.split(":")
    if len(parts) < 6:
        return None
    attrs_part = parts[4]
    try:
        kv = dict(item.split("=") for item in attrs_part.split(","))
        return int(kv["p"]), int(kv["q"])
    except (ValueError, KeyError):
        return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def dealmakers_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create paired buyer-seller Dealmaker agents.

    For each pair the factory:

    1.  Derives per-agent DealParams deterministically from (agent_id, seed).
    2.  Computes the joint feasible zone on price and quantity.
    3.  Opens at the midpoint of the joint feasible ranges.

    Example::

        agents = dealmakers_factory(config, plugins)
    """
    task_cfg = config.task.config
    rounds: int = task_cfg.get("rounds", 10)
    n_pairs: int = task_cfg.get("pairs", 8)
    seed: int = config.seed

    agents: dict[AgentId, StateMachineAgent] = {}

    for i in range(n_pairs):
        buyer_id = AgentId(f"buyer-{i}")
        seller_id = AgentId(f"seller-{i}")

        buyer_params = DealParams.for_buyer(buyer_id, seed, pair_index=i)
        seller_params = DealParams.for_seller(seller_id, seed, pair_index=i)

        # Joint feasible zone
        joint_p_lo = max(buyer_params.min_p, seller_params.min_p)
        joint_p_hi = min(buyer_params.max_p, seller_params.max_p)
        joint_q_lo = max(buyer_params.min_q, seller_params.min_q)
        joint_q_hi = min(buyer_params.max_q, seller_params.max_q)

        # Clamp zone in case reservations don't overlap — fallback to buyer's range
        if joint_p_lo > joint_p_hi:
            joint_p_lo = buyer_params.min_p
            joint_p_hi = buyer_params.max_p
        if joint_q_lo > joint_q_hi:
            joint_q_lo = buyer_params.min_q
            joint_q_hi = buyer_params.max_q

        open_p = (joint_p_lo + joint_p_hi) // 2
        # Buyer opens at their ideal quantity; seller's internal anchor is their own target.
        # This guarantees both parties start from different q positions, ensuring the
        # quantity axis is contested from round 1 (any strategy that moves q will do so).
        buyer_open_q = max(joint_q_lo, min(joint_q_hi, buyer_params.target_q))
        seller_open_q = max(joint_q_lo, min(joint_q_hi, seller_params.target_q))

        agents[buyer_id] = DealmakerAgent(
            agent_id=buyer_id,
            role="buyer",
            partner_id=seller_id,
            params=buyer_params,
            rounds=rounds,
            open_p=open_p,
            open_q=buyer_open_q,
        )
        agents[seller_id] = DealmakerAgent(
            agent_id=seller_id,
            role="seller",
            partner_id=buyer_id,
            params=seller_params,
            rounds=rounds,
            open_p=open_p,
            open_q=seller_open_q,
        )

    return agents
