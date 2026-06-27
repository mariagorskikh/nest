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

Implementations may accept an optional `session_id` kwarg in `open()` to
allow callers to supply a deterministic ID for reproducible traces. This does
not change the protocol surface — callers that omit it get a plugin-generated
ID.

## Default plugin

`alternating_offers` — Rubinstein-style bargaining with a patience
discount.

Source: [`nest_plugins_reference/negotiation/alternating_offers.py`](../../packages/nest-plugins-reference/nest_plugins_reference/negotiation/alternating_offers.py).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.negotiation`.

Good fits to test here: multi-attribute negotiation, multi-party
negotiation, agenda-based bargaining, learning-based bidding.

## pareto plugin

`pareto` — multi-attribute Pareto-frontier bargaining over price, quantity,
and quality.

Source: [`nest_plugins_reference/negotiation/pareto.py`](../../packages/nest-plugins-reference/nest_plugins_reference/negotiation/pareto.py).

### Attribute model

| Attribute | `Terms` field | Type | Notes |
|-----------|--------------|------|-------|
| price premium | `price.amount` | `int` 0–100 | Distributive axis |
| quantity | `conditions["quantity"]` | `int` | Integrative axis |
| quality | `conditions["quality"]` | `float` 0–1 | Static; gates feasibility only |

Buyer prefers **low** price, moderate quantity (convex kappa penalty).
Seller prefers **high** price, high quantity (linear up to capacity).
This structure guarantees a genuine win-win trade on the quantity axis.

### Utility function

```
u_i(p, n, q) = w_p * v_p(p) + w_n * v_n(n) + w_q * v_q(q)
```

All weights sum to 1 and are derived deterministically from `(agent_id, seed)`.
The quality value `v_q(q)` is constant per session (quality never moves).

### Strategy catalog

Six pluggable strategies (same `counter()` interface):

| Strategy ID | Concession rule |
|-------------|----------------|
| `ttt_directional` | Mirror a bounded fraction `rho` of the opponent's per-issue movement on each axis (directional tit-for-tat, spec eq. 10) |
| `zeuthen_concede` | Zeuthen risk-ratio rule: concede when own risk `R_i <= R_j`; lower utility target `tau` by `tau_step` and propose best feasible point above new `tau` (spec eq. 11a) |
| `rubinstein_discount` | Rubinstein patience discount: accept when `u_i(x_j) >= delta_i * V_i^{t+1}`; counter with highest-utility own-feasible point that still beats the discounted continuation value (spec eq. 11b) |
| `logrolling_tradeoff` | Stay on own iso-utility contour; maximise estimated opponent utility using inferred opponent weights updated from offer history (spec eq. 12a) |
| `nash_bargaining` | Asymmetric Nash bargaining solution: `argmax (u_i - d_i)^beta * (uhat_j - d_j)^(1-beta)` over own feasible grid (spec eq. 12b) |
| `ks_bargaining` | Kalai-Smorodinsky proportional concession: maximise `lambda = (u_i - d_i)/(m_i - d_i)` subject to opponent's proportional gain also being high (spec eq. 12c) |

Strategies are assigned deterministically from `pair_index`:
buyer gets `STRATEGY_IDS[(pair_index * 2) % 6]`,
seller gets `STRATEGY_IDS[(pair_index * 2 + 1) % 6]`.
Because buyer and seller always use even and odd indices respectively,
they always receive different strategies within a pair.

### Validator: `validate_pareto_efficiency`

The offline referee reads the immutable trace and:

1. Reconstructs both agents' utility configs from `config:agent_id:json` lines.
2. Builds the joint Pareto-nondominated set over the feasible `(p, n)` grid at
   the session's fixed quality.
3. **FAILS** any agreed agreement that is strictly dominated — i.e. a feasible
   point exists where both agents are weakly better and one is strictly better.
4. **Excludes** breakdown sessions (`close:breakdown:…`) from the dominated
   check.

`alternating_offers` **FAILS** this validator: it never moves the quantity
axis, so the fixed opening `n` is always dominated by a different `n` where
both agents gain (guaranteed by the convex/linear kappa asymmetry). All 10
sessions are flagged as quantity-dominated.

`pareto` produces **strictly fewer** violations than `alternating_offers`
because it actively moves both axes and converges toward the frontier. Finite
integer-grid rounds mean it may not land exactly on the frontier for every
pair, but the violation count is always lower than the single-axis baseline.

### Trace line protocol

Agents using this plugin emit:

```
config:<agent_id>:<json_params>       # sealed utility config (on_start)
offer:<from>:<to>:r<round>:p=<p>,n=<n>,q=<q>:<strategy_id>
close:agreed:<session_id>:p=<p>,n=<n>,q=<q>
close:breakdown:<session_id>
```

### Anti-patterns avoided

- **No global knowledge**: each `ParetoNegotiator` holds only its own
  `ParetoParams`; opponent params are never shared during the session.
- **No scalar collapse**: utility is used only to build iso-contours and test
  acceptance — the strategies search the grid, not a weighted sum.
- **No deterministic agreement**: agents must exchange offers to converge; the
  outcome depends on both agents' params and the strategy assigned.
- **No protocol breakage**: `alternating_offers` is unchanged and co-exists.
