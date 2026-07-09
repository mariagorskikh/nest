# Negotiation layer

**What it does.** Bilateral bargaining: open a session, exchange
offers, respond, close with an `Agreement` (or `None` on breakdown).

## Interface

```python
class Negotiation(Protocol):
    async def open(self, partner: AgentId, terms: Terms) -> NegotiationSession: ...
    async def offer(self, session: NegotiationSession, terms: Terms) -> None: ...
    async def respond(self, session: NegotiationSession) -> NegotiationResponse: ...
    async def close(self, session: NegotiationSession) -> Agreement | None: ...
```

Full definition: [`nest_core/layers/negotiation.py`](../../packages/nest-core/nest_core/layers/negotiation.py).

## Default plugin

`alternating_offers` — Rubinstein-style bargaining with a patience
discount.

Source: [`nest_plugins_reference/negotiation/alternating_offers.py`](../../packages/nest-plugins-reference/nest_plugins_reference/negotiation/alternating_offers.py).

## Also available: `pareto`

`ParetoNegotiation` — multi-attribute bargaining over price and deadline using
Keeney-Raiffa MAUT and Faratin–Sierra–Jennings trade-off moves. Scenario:
`scenarios/multi_attribute_market.yaml`.

Source: [`nest_plugins_reference/negotiation/pareto.py`](../../packages/nest-plugins-reference/nest_plugins_reference/negotiation/pareto.py).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.negotiation`.

Good fits to test here: multi-attribute negotiation, multi-party
negotiation, agenda-based bargaining, learning-based bidding.
