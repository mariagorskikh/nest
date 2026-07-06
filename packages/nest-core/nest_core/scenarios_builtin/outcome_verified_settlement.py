# SPDX-License-Identifier: Apache-2.0
"""Outcome-verified settlement scenario: buyers open per-tick streams to sellers.

Each buyer opens one payment stream to a seller, then drives the stream one
logical tick at a time. Billing is **outcome-gated**: each delivered tick is run
through a settlement :class:`~nest_core.scenarios_builtin.gates.Gate`
before one unit is billed. The default gate (``ack_received``) reproduces today's
delivery-gated billing exactly -- a tick bills once the seller acknowledges it --
so a retried or delayed delivery never over-bills and a partition bills nothing.
The ``checksum`` gate is content-gated: the seller delivers the metered bytes plus
a declared checksum, and the buyer settles a unit only when a checksum recomputed
over the delivered bytes matches the declared one. The ``evaluator`` gate is also
content-gated and additionally requires a named criterion (``criterion``, default
``"reference_match"``) to pass -- see
``nest_core.scenarios_builtin.gates`` for what each gate actually checks.

The ``bill_on_send`` flag (default ``False`` = correct) flips delivery billing to
happen on send instead of on ack; with it ``True`` the buyer over-bills under
partition. The ``bill_regardless`` flag (default ``False`` = correct) is the
content-gate bug variant: it bills even on a failing verdict, over-billing past
what was verified.

``streams_per_buyer`` (default ``1`` = the legacy single stream, byte-identical
trace) turns the run into *rolling* streams: after each close -- for any reason,
including a failed verdict -- the buyer reopens a fresh stream at the next tick
under a new ref (cycle 1 keeps ``{buyer}-stream``; cycle c >= 2 uses
``{buyer}-stream-r{c}``) with the same rate/cap/gate/criterion and cycle length.
Each cycle's seq restarts at 0, so seller-side failure injections recur at the
same relative offset in every cycle, and each cycle's cap and billing are
independent (the validators group stream lines per ref). Self-scheduled
control messages (``nexttick`` / ``timeout`` / ``reopen``) travel the same
lossy delivery path as agent traffic, so in rolling mode the clock and the
roll are drop-tolerant: nextticks are armed redundantly, residual ack
timeouts double as watchdogs, and reopens are scheduled in triplicate behind
an idempotent target-cycle guard. The legacy single-stream path schedules
exactly one of each and stays byte-identical.

From ``nonconform_at_tick`` onward (independent of, and mutually exclusive in
effect with, ``degrade_at_tick``), the seller delivers a *different, real* unit's
canonical bytes -- honestly checksummed -- instead of this unit's bytes
(``nonconform_mode``: ``replay_previous`` | ``stale_first`` | ``empty``). This
passes :class:`~...gates.ChecksumGate` (the bytes match their own declared
checksum) but fails ``reference_match`` (wrong unit's content) -- the case that
requires the ``evaluator`` gate; ``checksum`` alone cannot catch it.

Trace grammar emitted (colon-delimited, like the marketplace scenario):

* ``stream-open:<ref>:<payer>:<payee>:<rate>:<max_total>:<opened_tick>``
* ``tick:<ref>:<seq>:<rate>:<now_tick>``      (buyer -> seller, metered request)
* ``ack:<ref>:<seq>``                          (seller -> buyer, delivery confirm)
  or, under a content gate,
  ``ack:<ref>:<seq>:<chunk_hex>:<declared_checksum>`` (delivered bytes + claim)
* ``gate:<ref>:<seq>:pass|fail``               (content gate only: settle verdict)
* ``stream-close:<ref>:<seq>:<drained>:<close_tick>:<reason>``

The content-gate lines appear only when ``gate != "ack_received"``; the default
delivery-gated path emits a byte-identical trace to the pre-gate scenario.

Example::

    agents = outcome_verified_settlement_factory(config, plugins)
"""

from __future__ import annotations

import hashlib
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.scenarios_builtin.gates import Gate, UnitContext, canonical_chunk
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef

_GATE_ALGO = "sha256"
_NONCONFORM_MODES = ("replay_previous", "stale_first", "empty")


class OutcomeVerifiedSettlementBuyerAgent(StateMachineAgent):
    """A buyer that opens one outcome-gated payment stream to a seller.

    Drives ticks via ``ctx.schedule`` and settles each delivered tick through a
    :class:`~nest_core.scenarios_builtin.gates.Gate`. The default
    delivery gate bills exactly one unit per delivered ``ack`` (via a logical
    counter, so a retry never over-bills); the ``checksum``/``evaluator``
    content gates bill only when their verdict passes and otherwise close the
    stream deterministically. ``criterion`` is forwarded only when
    ``gate="evaluator"``. ``bill_on_send`` and ``bill_regardless`` are the two
    injected over-bill bugs. ``streams_per_buyer`` (default ``1`` = legacy
    single stream) rolls a fresh stream under a new ref after each close while
    cycles remain.

    Example::

        agent = OutcomeVerifiedSettlementBuyerAgent(AgentId("buyer-0"), AgentId("seller-0"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        seller: AgentId,
        *,
        rate_per_tick: int = 1,
        max_total: int = 20,
        close_at_tick: int = 5,
        tick_interval: float = 1.0,
        ack_timeout: float = 2.0,
        bill_on_send: bool = False,
        max_retries: int = 2,
        streams_per_buyer: int = 1,
        gate: str = "ack_received",
        criterion: str = "reference_match",
        bill_regardless: bool = False,
        gate_algo: str = _GATE_ALGO,
    ) -> None:
        self._id = agent_id
        self._seller = seller
        self._rate = rate_per_tick
        self._max_total = max_total
        self._close_at_tick = close_at_tick
        self._tick_interval = tick_interval
        self._ack_timeout = ack_timeout
        self._bill_on_send = bill_on_send
        self._max_retries = max_retries
        self._content_gated = gate != "ack_received"
        if gate == "evaluator":
            self._gate = Gate.from_name(gate, criterion=criterion, algo=gate_algo)
        elif self._content_gated:
            self._gate = Gate.from_name(gate, algo=gate_algo)
        else:
            self._gate = Gate.from_name(gate)
        self._bill_regardless = bill_regardless
        if streams_per_buyer < 1:
            msg = f"streams_per_buyer must be >= 1, got {streams_per_buyer}"
            raise ValueError(msg)
        self._streams_per_buyer = streams_per_buyer
        self._rolling = streams_per_buyer > 1
        self._cycle: int = 1
        self._ref = self._cycle_ref(1)
        self._seq = 0
        self._retries = 0
        self._billed = 0
        self._awaiting = False
        self._closed = False

    def _cycle_ref(self, cycle: int) -> PaymentRef:
        """Payment ref for one rolling cycle; cycle 1 keeps the legacy single-stream ref.

        Example::

            ref = agent._cycle_ref(2)  # PaymentRef("buyer-0-stream-r2")
        """
        if cycle == 1:
            return PaymentRef(f"{self._id}-stream")
        return PaymentRef(f"{self._id}-stream-r{cycle}")

    async def on_start(self, ctx: AgentContext) -> None:
        """Open the first cycle's stream, announce it, and schedule the first tick.

        Example::

            await agent.on_start(ctx)
        """
        await self._open_stream(ctx)

    async def _open_stream(self, ctx: AgentContext) -> None:
        """Open the current cycle's stream on the ledger, announce it, schedule tick 0."""
        payments = ctx.plugins.get("payments")
        if payments is None:
            return
        opened = int(ctx.time)
        self._billed = opened
        await payments.open_stream(
            self._seller,
            self._rate,
            self._max_total,
            self._ref,
            opened_at_tick=opened,
        )
        msg = (
            f"stream-open:{self._ref}:{ctx.agent_id}:{self._seller}"
            f":{self._rate}:{self._max_total}:{opened}"
        )
        await ctx.send(self._seller, msg.encode())
        await self._schedule_nexttick(ctx)

    async def _schedule_nexttick(self, ctx: AgentContext) -> None:
        """Arm the next clock tick; in rolling mode also arm a redundant backup.

        Self-scheduled messages can be dropped like any other message, so a
        lone ``nexttick`` is a single point of failure that stalls the state
        machine forever. In rolling mode a second copy one interval later
        (plus the timeout watchdog in ``on_message``) makes a permanent stall
        require several independent drops; ``_send_tick`` deduplicates, so
        redundant delivery never double-sends. The legacy single-stream path
        schedules exactly one copy -- byte-identical to before.

        Example::

            await agent._schedule_nexttick(ctx)
        """
        payload = f"nexttick:{self._ref}".encode()
        await ctx.schedule(self._tick_interval, payload)
        if self._rolling:
            await ctx.schedule(self._tick_interval * 2, payload)

    async def _reopen(self, ctx: AgentContext, target_cycle: int) -> None:
        """Open the next rolling cycle's stream: fresh ref, same terms, seq reset to 0.

        A close for ANY reason ("done", "degrade", "timeout") rolls to the next
        cycle while cycles remain -- a failed verdict closes only that cycle's
        stream, and the next cycle still opens. The seller keys its failure
        injections off the per-message seq, so they recur at the same RELATIVE
        offset in every cycle. Idempotent under redundant delivery: only a
        ``target_cycle`` of exactly ``current + 1`` rolls; stale or duplicate
        reopen copies are no-ops.

        Example::

            await agent._reopen(ctx, target_cycle=2)
        """
        if not self._closed or self._cycle >= self._streams_per_buyer:
            return
        if target_cycle != self._cycle + 1:
            return  # stale or duplicate reopen for a cycle that already rolled
        self._cycle += 1
        self._ref = self._cycle_ref(self._cycle)
        self._seq = 0
        self._retries = 0
        self._awaiting = False
        self._closed = False
        await self._open_stream(ctx)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Dispatch self-scheduled ticks/timeouts/reopens and seller acks.

        Example::

            await agent.on_message(ctx, AgentId("seller-0"), b"ack:buyer-0-stream:0")
        """
        msg = payload.decode("utf-8", errors="replace")
        parts = msg.split(":")
        kind = parts[0]
        if kind == "reopen":
            target = int(parts[2]) if len(parts) > 2 else self._cycle + 1
            await self._reopen(ctx, target)
            return
        if self._closed:
            if (
                self._rolling
                and kind == "timeout"
                and len(parts) > 1
                and parts[1] == str(self._ref)
            ):
                # Watchdog: every scheduled reopen copy was dropped; a residual
                # ack timeout for the closed stream re-triggers the roll
                # (idempotent via the target-cycle guard in _reopen).
                await self._reopen(ctx, self._cycle + 1)
            return
        if kind == "nexttick":
            await self._send_tick(ctx)
        elif kind == "timeout":
            ref = parts[1] if len(parts) > 1 else ""
            seq = int(parts[2]) if len(parts) > 2 else -1
            if ref == str(self._ref) and self._awaiting and seq == self._seq:
                await self._on_timeout(ctx)
            elif self._rolling and ref == str(self._ref) and not self._awaiting:
                # Watchdog: a dropped nexttick would otherwise stall the cycle;
                # any residual timeout for the live stream re-drives the clock
                # (_send_tick deduplicates, so this never double-sends).
                await self._send_tick(ctx)
        elif kind == "ack":
            await self._on_ack(ctx, parts)

    async def _bill_one(self, ctx: AgentContext) -> None:
        """Bill exactly one tick via a logical counter (gap-proof under retries)."""
        payments = ctx.plugins.get("payments")
        if payments is not None:
            self._billed += 1
            await payments.advance(self._ref, now_tick=self._billed)

    def _unit_ctx(self, seq: int, parts: list[str]) -> UnitContext:
        """Build the gate input for one delivered unit from the ack-line fields."""
        chunk = bytes.fromhex(parts[3]) if len(parts) > 3 else b""
        declared = parts[4] if len(parts) > 4 else None
        return UnitContext(
            ref=str(self._ref),
            seq=seq,
            ack_received=True,
            chunk=chunk,
            declared_checksum=declared,
        )

    async def _settle_via_gate(self, ctx: AgentContext, seq: int, parts: list[str]) -> bool:
        """Settle one delivered unit through the gate; return True to keep streaming.

        The default delivery gate bills one unit unconditionally (== today). A
        content gate (``checksum`` or ``evaluator``) emits a ``gate:`` verdict,
        then bills one unit on a pass and, on a fail, bills nothing and closes
        the stream deterministically -- unless ``bill_regardless`` is set (the
        injected over-bill bug), which bills anyway and keeps streaming. Returns
        False only when a failing verdict closed the stream.
        """
        if not self._content_gated:
            await self._bill_one(ctx)
            return True
        verdict = self._gate.should_settle(self._unit_ctx(seq, parts))
        outcome = "pass" if verdict.passed else "fail"
        await ctx.send(self._seller, f"gate:{self._ref}:{seq}:{outcome}".encode())
        if verdict.passed or self._bill_regardless:
            await self._bill_one(ctx)
            return True
        await self._close(ctx, "degrade")
        return False

    async def _emit_tick(self, ctx: AgentContext) -> None:
        """(Re)send the current metered tick request and arm the ack timeout."""
        now = int(ctx.time)
        await ctx.send(self._seller, f"tick:{self._ref}:{self._seq}:{self._rate}:{now}".encode())
        self._awaiting = True
        await ctx.schedule(self._ack_timeout, f"timeout:{self._ref}:{self._seq}".encode())

    async def _send_tick(self, ctx: AgentContext) -> None:
        """Start the next metered tick. Bills on send only if misconfigured (the bug)."""
        if self._closed:
            return
        if self._rolling and self._awaiting:
            return  # tick already in flight; its timeout ladder drives retries
        if self._seq >= self._close_at_tick:
            await self._close(ctx, "done")
            return
        self._retries = 0
        if self._bill_on_send:
            await self._bill_one(ctx)
        await self._emit_tick(ctx)

    async def _on_timeout(self, ctx: AgentContext) -> None:
        """Retry the current tick up to ``max_retries`` times, then close deterministically."""
        if self._closed:
            return
        if self._retries < self._max_retries:
            self._retries += 1
            if self._bill_on_send:
                await self._bill_one(ctx)
            await self._emit_tick(ctx)
        else:
            await self._close(ctx, "timeout")

    async def _on_ack(self, ctx: AgentContext, parts: list[str]) -> None:
        """Settle the delivered tick through the gate, then advance or degrade-close."""
        if not self._awaiting:
            return
        if len(parts) > 1 and parts[1] != str(self._ref):
            return  # stale ack addressed to a previous rolling cycle's stream ref
        seq = int(parts[2]) if len(parts) > 2 else -1
        if seq != self._seq:
            return
        if not self._bill_on_send and not await self._settle_via_gate(ctx, seq, parts):
            return  # a failing verdict closed the stream deterministically
        self._awaiting = False
        self._retries = 0
        self._seq += 1
        if self._seq >= self._close_at_tick:
            await self._close(ctx, "done")
        else:
            await self._schedule_nexttick(ctx)

    async def _close(self, ctx: AgentContext, reason: str) -> None:
        """Close the stream deterministically and announce the final drained total.

        When rolling cycles remain (``streams_per_buyer``), schedule the next
        cycle's reopen one tick interval after the close.
        """
        if self._closed:
            return
        payments = ctx.plugins.get("payments")
        drained = 0
        if payments is not None:
            receipt = await payments.close_stream(self._ref, now_tick=int(ctx.time))
            drained = receipt.amount.amount
        self._closed = True
        msg = f"stream-close:{self._ref}:{self._seq}:{drained}:{int(ctx.time)}:{reason}"
        await ctx.send(self._seller, msg.encode())
        if self._cycle < self._streams_per_buyer:
            # Triplicate: any single copy can be dropped in transit; _reopen's
            # target-cycle guard makes extra deliveries a no-op. Unreachable
            # when streams_per_buyer == 1, so the legacy path is untouched.
            reopen = f"reopen:{self._id}:{self._cycle + 1}".encode()
            await ctx.schedule(self._tick_interval, reopen)
            await ctx.schedule(self._tick_interval * 2, reopen)
            await ctx.schedule(self._tick_interval * 3, reopen)


class OutcomeVerifiedSettlementSellerAgent(StateMachineAgent):
    """A seller that acknowledges each delivered tick.

    Receiving a ``tick`` means the metered unit was delivered, so the seller
    replies with an ``ack``; that ack is what authorizes the buyer to bill. Under
    a content gate the ack also carries the delivered bytes and a declared
    checksum. Two independent, mutually-exclusive-in-effect fault modes:

    * ``degrade_at_tick``: from that tick onward, delivered bytes are corrupted
      (``intended + b"!"``) while the declared checksum stays honest about the
      *intended* bytes -- checksum mismatch, caught by :class:`ChecksumGate`.
    * ``nonconform_at_tick``: from that tick onward, delivered bytes are a
      *different real unit's* canonical content (per ``nonconform_mode``), with
      an HONEST checksum of what was actually sent -- checksum matches, but the
      content is wrong for this unit's slot; only ``reference_match`` (via the
      ``evaluator`` gate) catches this.

    Example::

        agent = OutcomeVerifiedSettlementSellerAgent(AgentId("seller-0"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        content_gated: bool = False,
        degrade_at_tick: int | None = None,
        nonconform_at_tick: int | None = None,
        nonconform_mode: str = "replay_previous",
        algo: str = _GATE_ALGO,
    ) -> None:
        self._id = agent_id
        self._content_gated = content_gated
        self._degrade_at_tick = degrade_at_tick
        if nonconform_mode not in _NONCONFORM_MODES:
            msg = f"unknown nonconform_mode {nonconform_mode!r}; known: {list(_NONCONFORM_MODES)}"
            raise ValueError(msg)
        self._nonconform_at_tick = nonconform_at_tick
        self._nonconform_mode = nonconform_mode
        self._algo = algo

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Acknowledge delivered ticks; attach delivered bytes + checksum when content-gated.

        Example::

            await agent.on_message(ctx, AgentId("buyer-0"), b"tick:buyer-0-stream:0:1:1")
        """
        msg = payload.decode("utf-8", errors="replace")
        if not msg.startswith("tick:"):
            return
        parts = msg.split(":")
        if len(parts) < 3:
            return
        ref = parts[1]
        seq = parts[2]
        if not self._content_gated:
            await ctx.send(sender, f"ack:{ref}:{seq}".encode())
            return
        await ctx.send(sender, self._content_ack(ref, seq).encode())

    def _nonconform_chunk(self, ref: str, seq: int) -> bytes:
        """Return the (wrong, but honestly deliverable) bytes for a nonconforming unit.

        Stateless and pure -- derived directly from ``(ref, seq, mode)`` via the
        same canonical-chunk formula every other unit's content uses, so no
        sent-history tracking is needed. Edge case, noted rather than hidden: if
        ``nonconform_at_tick`` is configured as 0, ``replay_previous`` falls back
        to seq 0's own (correct) canonical bytes -- i.e. it would not actually be
        nonconforming. Scenarios should set ``nonconform_at_tick >= 1``.

        Example::

            chunk = seller._nonconform_chunk("buyer-0-stream", 3)
        """
        if self._nonconform_mode == "stale_first":
            return canonical_chunk(ref, 0)
        if self._nonconform_mode == "empty":
            return b""
        return canonical_chunk(ref, max(seq - 1, 0))  # replay_previous (default)

    def _content_ack(self, ref: str, seq: str) -> str:
        """Build a content-gated ack: delivered bytes + a declared checksum.

        Nonconforming units (from ``nonconform_at_tick`` onward) declare an
        HONEST checksum of the wrong-unit bytes actually sent. Degraded units
        (from ``degrade_at_tick`` onward, existing behavior, unchanged) declare
        the checksum of the *intended* bytes while delivering corrupted ones.
        Otherwise, both delivered bytes and declared checksum are correct.
        """
        try:
            seq_n = int(seq)
        except ValueError:
            seq_n = -1
        if self._nonconform_at_tick is not None and seq_n >= self._nonconform_at_tick:
            delivered = self._nonconform_chunk(ref, seq_n)
            declared = hashlib.new(self._algo, delivered).hexdigest()
            return f"ack:{ref}:{seq}:{delivered.hex()}:{declared}"
        intended = canonical_chunk(ref, seq_n)
        declared = hashlib.new(self._algo, intended).hexdigest()
        delivered = intended
        if self._degrade_at_tick is not None and seq_n >= self._degrade_at_tick:
            delivered = intended + b"!"
        return f"ack:{ref}:{seq}:{delivered.hex()}:{declared}"


def outcome_verified_settlement_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create buyer and seller agents for the outcome-verified-settlement scenario.

    Wires per-agent payments handles over a single shared ledger (balances,
    streams, and receipts), mirroring the marketplace scenario, so ``advance``
    debits the calling buyer and credits the seller against balances every
    participant observes. Reads tunables from ``task.config``: ``rate_per_tick``,
    ``max_total``, ``close_at_tick``, ``tick_interval``, ``ack_timeout``,
    ``bill_on_send``, ``max_retries``, ``streams_per_buyer`` (default ``1`` = the
    legacy single stream, byte-identical), ``initial_balance``, and the gate controls
    ``gate`` (default ``"ack_received"``), ``criterion`` (default
    ``"reference_match"``, only meaningful when ``gate="evaluator"``),
    ``degrade_at_tick`` (default ``None``), ``nonconform_at_tick`` (default
    ``None``), ``nonconform_mode`` (default ``"replay_previous"``), and
    ``bill_regardless`` (default ``False``).

    Example::

        agents = outcome_verified_settlement_factory(config, plugins)
    """
    tc = config.task.config
    rate_per_tick = int(tc.get("rate_per_tick", 1))
    max_total = int(tc.get("max_total", 20))
    close_at_tick = int(tc.get("close_at_tick", 5))
    tick_interval = float(tc.get("tick_interval", 1.0))
    ack_timeout = float(tc.get("ack_timeout", 2.0))
    bill_on_send = bool(tc.get("bill_on_send", False))
    max_retries = int(tc.get("max_retries", 2))
    initial_balance = int(tc.get("initial_balance", 1000))
    gate = str(tc.get("gate", "ack_received"))
    criterion = str(tc.get("criterion", "reference_match"))
    degrade_raw = tc.get("degrade_at_tick")
    degrade_at_tick = int(degrade_raw) if degrade_raw is not None else None
    nonconform_raw = tc.get("nonconform_at_tick")
    nonconform_at_tick = int(nonconform_raw) if nonconform_raw is not None else None
    nonconform_mode = str(tc.get("nonconform_mode", "replay_previous"))
    bill_regardless = bool(tc.get("bill_regardless", False))
    streams_per_buyer = int(tc.get("streams_per_buyer", 1))
    content_gated = gate != "ack_received"

    if config.agents.roles:
        buyer_count = 0
        seller_count = 0
        for role in config.agents.roles:
            if role.name == "buyer":
                buyer_count = role.count
            elif role.name == "seller":
                seller_count = role.count
    else:
        buyer_count = config.agents.count // 2
        seller_count = config.agents.count - buyer_count

    seller_ids = [AgentId(f"seller-{i}") for i in range(seller_count)]
    buyer_ids = [AgentId(f"buyer-{i}") for i in range(buyer_count)]
    all_ids = seller_ids + buyer_ids

    _instantiate_outcome_verified_settlement_payments(plugins, all_ids, initial_balance)

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in seller_ids:
        agents[aid] = OutcomeVerifiedSettlementSellerAgent(
            aid,
            content_gated=content_gated,
            degrade_at_tick=degrade_at_tick,
            nonconform_at_tick=nonconform_at_tick,
            nonconform_mode=nonconform_mode,
        )
    for i, aid in enumerate(buyer_ids):
        seller = seller_ids[i % seller_count] if seller_count else aid
        agents[aid] = OutcomeVerifiedSettlementBuyerAgent(
            aid,
            seller,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            close_at_tick=close_at_tick,
            tick_interval=tick_interval,
            ack_timeout=ack_timeout,
            bill_on_send=bill_on_send,
            max_retries=max_retries,
            streams_per_buyer=streams_per_buyer,
            gate=gate,
            criterion=criterion,
            bill_regardless=bill_regardless,
        )
    return agents


def _instantiate_outcome_verified_settlement_payments(
    plugins: dict[str, Any],
    all_ids: list[AgentId],
    initial_balance: int,
) -> None:
    """Instantiate the payments plugin into per-agent handles over a shared ledger.

    Replaces the resolved payments class in *plugins* with a shared ``system``
    handle and stores per-agent handles under ``plugins["_agent_plugins"]`` for
    the runner to apply as overrides. Safe to call when *plugins* is empty.

    Example::

        _instantiate_outcome_verified_settlement_payments(plugins, [AgentId("buyer-0")], 1000)
    """
    if not plugins:
        return

    payments_cls = plugins.get("payments")
    if payments_cls is None or not isinstance(payments_cls, type):
        return

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    balances: dict[AgentId, int] = {aid: initial_balance for aid in all_ids}
    streams: dict[PaymentRef, Any] = {}
    payment_records: dict[PaymentRef, Any] = {}
    system_id = AgentId("system")

    try:
        plugins["payments"] = payments_cls(
            system_id,
            initial_balance=0,
            balances=balances,
            streams=streams,
            payments=payment_records,
        )
        for aid in all_ids:
            agent_plugins.setdefault(aid, {})["payments"] = payments_cls(
                aid,
                initial_balance=0,
                balances=balances,
                streams=streams,
                payments=payment_records,
            )
    except TypeError:
        plugins["payments"] = payments_cls(system_id, initial_balance=0)
