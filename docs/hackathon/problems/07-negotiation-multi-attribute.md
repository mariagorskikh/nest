---
title: Multi-attribute negotiation with Pareto-frontier search
layer: negotiation
difficulty: medium
status: solved
---

> **Status: SOLVED** — implemented in `scenarios/multi_attribute_market.yaml` with the `pareto` negotiation plugin.

# Multi-attribute negotiation with Pareto-frontier search

## Motivation

The default negotiation plugin
[`nest_plugins_reference/negotiation/alternating_offers.py`](../../../packages/nest-plugins-reference/nest_plugins_reference/negotiation/alternating_offers.py)
is 99 lines of single-attribute Rubinstein bargaining: the `respond`
method (line 66-81) compares **one number** —
`session.current_terms.price.amount` — against a patience-discounted
threshold and accepts or rejects. The `Terms` model in
[`nest_core/types.py`](../../../packages/nest-core/nest_core/types.py)
in fact has more dimensions (delivery time, quality, quantity), but
the reference plugin uses only `price`. That collapses any
multi-attribute negotiation (deadline-sensitive deliveries, quality-
price tradeoffs, bundle deals) into a one-dimensional fight over
price.

Real markets are multi-attribute. A buyer trading off price against
delivery date is the most common case in
[`scenarios/marketplace.yaml`](../../../scenarios/marketplace.yaml)
(catalogue size 200, 10 rounds, 50 buyers vs. 50 sellers) — and yet
the reference plugin has no way to express "I'd accept a higher price
if you ship tomorrow instead of next week." Zero PRs in the first
round touched negotiation.
[`docs/layers/negotiation.md`](../../../docs/layers/negotiation.md)
explicitly wants "multi-attribute negotiation, multi-party
negotiation, agenda-based bargaining, learning-based bidding."

Anyone modelling supply chains, agent SLAs, or any market where
"price" alone is a poor proxy benefits.

## Success criteria

- Ship a negotiation plugin (suggested name: `multi_attribute` or
  `pareto`) registered as `(\"negotiation\", \"<your_name>\")` in
  [`nest_core/plugins.py`](../../../packages/nest-core/nest_core/plugins.py).
- Negotiation runs over ≥ 2 attributes from `Terms` (e.g. price +
  deadline; price + quantity). Each agent has a private utility
  function over those attributes; the plugin's job is to converge to
  a **Pareto-optimal** agreement, not just any agreement.
- API additions: extend `respond` to evaluate the *full* `Terms`, and
  let agents pass a utility function (or weights) at construction
  time without changing the `Negotiation` protocol's surface (i.e.
  pass it via constructor, not method signature).
- Ship an adversarial validator that, given a trace of negotiations,
  computes the Pareto frontier from observed bids and **fails** if
  any agreement is Pareto-dominated by some other concession both
  parties exchanged during the same session. The validator must FAIL
  against `alternating_offers` when run with multi-attribute terms
  (because it ignores all but `price`) and PASS against yours.
- Ship `scenarios/multi_attribute_market.yaml` with 10 buyer-seller
  pairs negotiating over price + deadline. Each pair has a
  deterministic utility weight from the per-agent seeded RNG.

## Suggested approach pointers

- The simplest multi-attribute strategy is "trade-off in the
  direction my opponent indicated." If they conceded on price but
  not deadline last round, you concede on deadline this round.
- Look up "monotonic concession protocol" — useful framing without
  needing to fully implement it.
- Negotiation can fail (no agreement is Pareto-optimal *for the
  buyer*). Returning `None` from `close` is acceptable; the validator
  should distinguish "negotiation broke down" from "negotiation
  closed Pareto-dominated."
- Patience discounts still apply, but per-attribute.
- Encode utility weights deterministically from the agent's seed so
  traces replay.

## Anti-patterns

- Don't ship a plugin that pretends to be multi-attribute but
  collapses to a weighted-sum scalar internally and never explores
  the frontier.
- Don't require global knowledge of all participants' utility
  functions. Each agent knows only its own.
- Don't make agreement deterministic from initial offers — agents
  must *exchange* offers to converge.
- Don't break `alternating_offers`; ship alongside it.

## Out of scope

- Multi-party (3+ agent) negotiation. Bilateral is enough.
- Learning across negotiation sessions (no inter-session state).
- Sealed-bid mechanisms — PR #5 already covers that under
  *coordination*.
- LLM-driven bargaining (Tier 2). Tier 1 only.
