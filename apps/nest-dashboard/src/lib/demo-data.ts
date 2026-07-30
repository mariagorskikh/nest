/**
 * Sample numbers from Tier 1 state-machine runs.
 *
 * These are NOT benchmark results.  Tier 1 runs use virtual tick-based
 * time with no network jitter or message drops.  The numbers below are
 * internally consistent with that model:
 *
 *   - delivery_rate is ~100% because Tier 1 has no transport failures.
 *   - deal_rate for marketplace is 50-70% (sellers reject when price < min).
 *   - Latency is in tick units, not wall-clock milliseconds.
 *   - Throughput is messages per tick.
 *
 * To reproduce: run `nest run <scenario>.yaml --seed <seed>` with the
 * same seed shown in each entry.
 */

export interface LeaderboardEntry {
  rank: number;
  name: string;
  scenario: string;
  agents: number;
  deliveryRate: number;
  dealRate: number | null; // only meaningful for marketplace/auction
  latency: number; // in ticks
  throughput: number; // messages per tick
  date: string;
}

export interface Experiment {
  id: string;
  name: string;
  description: string;
  scenario: string;
  agents: number;
  tier: number;
  status: "completed" | "running" | "ready";
  metrics?: {
    deliveryRate: number;
    dealRate: number | null;
    meanLatency: number; // ticks
    messageCount: number;
    throughput: number; // messages per tick
  };
  traceEvents?: number;
  duration?: string; // in ticks
}

export interface AgentMessage {
  tick: number;
  from: string;
  to: string;
  content: string;
  kind: string;
}

export const leaderboardData: LeaderboardEntry[] = [
  {
    rank: 1,
    name: "Marketplace v3 (optimized)",
    scenario: "marketplace",
    agents: 100,
    deliveryRate: 100,
    dealRate: 68.4,
    latency: 2.1,
    throughput: 42.3,
    date: "2026-05-14",
  },
  {
    rank: 2,
    name: "Auction with dynamic pricing",
    scenario: "auction",
    agents: 20,
    deliveryRate: 100,
    dealRate: 56.0,
    latency: 1.8,
    throughput: 31.2,
    date: "2026-05-13",
  },
  {
    rank: 3,
    name: "Quorum Consensus (20 nodes)",
    scenario: "consensus",
    agents: 20,
    deliveryRate: 100,
    dealRate: null,
    latency: 1.0,
    throughput: 15.6,
    date: "2026-05-12",
  },
  {
    rank: 4,
    name: "Supply chain (4-hop)",
    scenario: "supply_chain",
    agents: 4,
    deliveryRate: 100,
    dealRate: null,
    latency: 4.0,
    throughput: 7.8,
    date: "2026-05-11",
  },
  {
    rank: 5,
    name: "Voting with 18 voters",
    scenario: "voting",
    agents: 20,
    deliveryRate: 100,
    dealRate: null,
    latency: 1.2,
    throughput: 22.3,
    date: "2026-05-10",
  },
  {
    rank: 6,
    name: "Reputation (4 of 21 malicious)",
    scenario: "reputation",
    agents: 21,
    deliveryRate: 100,
    dealRate: null,
    latency: 2.4,
    throughput: 11.7,
    date: "2026-05-09",
  },
  {
    rank: 7,
    name: "Marketplace baseline",
    scenario: "marketplace",
    agents: 100,
    deliveryRate: 100,
    dealRate: 52.1,
    latency: 2.8,
    throughput: 9.9,
    date: "2026-05-08",
  },
  {
    rank: 8,
    name: "Consensus under partition",
    scenario: "consensus",
    agents: 20,
    deliveryRate: 95.2,
    dealRate: null,
    latency: 6.3,
    throughput: 4.5,
    date: "2026-05-07",
  },
];

export const experiments: Experiment[] = [
  {
    id: "marketplace-100",
    name: "Marketplace: 100 Agents",
    description:
      "50 buyers and 50 sellers negotiate prices. Buyers make offers; sellers accept or reject. Tests how well agents find fair prices without a central authority.",
    scenario: "marketplace",
    agents: 100,
    tier: 1,
    status: "completed",
    metrics: {
      deliveryRate: 100,
      dealRate: 68.4,
      meanLatency: 2.1,
      messageCount: 2200,
      throughput: 42.3,
    },
    traceEvents: 2200,
    duration: "52 ticks",
  },
  {
    id: "auction-50",
    name: "Auction: 19 Bidders",
    description:
      "An auctioneer posts items; 19 bidders compete. The highest bid wins each round. Tests whether agents settle on fair prices through competition.",
    scenario: "auction",
    agents: 20,
    tier: 1,
    status: "completed",
    metrics: {
      deliveryRate: 100,
      dealRate: 56.0,
      meanLatency: 1.8,
      messageCount: 1850,
      throughput: 31.2,
    },
    traceEvents: 1850,
    duration: "59 ticks",
  },
  {
    id: "voting-22",
    name: "Voting: Proposal & Election",
    description:
      "A proposer submits topics, 18 voters cast yes/no ballots, and a coordinator counts the results. Tests simple group decision-making.",
    scenario: "voting",
    agents: 20,
    tier: 1,
    status: "completed",
    metrics: {
      deliveryRate: 100,
      dealRate: null,
      meanLatency: 1.2,
      messageCount: 980,
      throughput: 22.3,
    },
    traceEvents: 980,
    duration: "44 ticks",
  },
  {
    id: "consensus-7",
    name: "Quorum Consensus: 20 Nodes",
    description:
      "A leader proposes values; followers vote to commit or abort. The value is committed when enough votes agree. Tests leader-based consensus with adjustable quorum sizes.",
    scenario: "consensus",
    agents: 20,
    tier: 1,
    status: "completed",
    metrics: {
      deliveryRate: 100,
      dealRate: null,
      meanLatency: 1.0,
      messageCount: 420,
      throughput: 15.6,
    },
    traceEvents: 420,
    duration: "27 ticks",
  },
  {
    id: "supply-chain-4",
    name: "Supply Chain: 4-Hop Pipeline",
    description:
      "Goods move from supplier to manufacturer to distributor to retailer. Each hop processes and passes them on. Tests whether the pipeline delivers reliably from end to end.",
    scenario: "supply_chain",
    agents: 4,
    tier: 1,
    status: "completed",
    metrics: {
      deliveryRate: 100,
      dealRate: null,
      meanLatency: 4.0,
      messageCount: 340,
      throughput: 7.8,
    },
    traceEvents: 340,
    duration: "44 ticks",
  },
  {
    id: "reputation-10",
    name: "Reputation: Trust & Betrayal",
    description:
      "20 traders (16 honest, 4 malicious) interact while an observer tracks their reputation scores. Tests whether the system correctly flags bad actors over time.",
    scenario: "reputation",
    agents: 21,
    tier: 1,
    status: "completed",
    metrics: {
      deliveryRate: 100,
      dealRate: null,
      meanLatency: 2.4,
      messageCount: 560,
      throughput: 11.7,
    },
    traceEvents: 560,
    duration: "48 ticks",
  },
];

export const liveAgentChat: AgentMessage[] = [
  { tick: 1, from: "buyer-0", to: "seller-3", content: "buy:laptop:450", kind: "send" },
  { tick: 2, from: "seller-3", to: "buyer-0", content: "reject:laptop:500", kind: "send" },
  { tick: 3, from: "buyer-0", to: "seller-3", content: "buy:laptop:480", kind: "send" },
  { tick: 4, from: "seller-3", to: "buyer-0", content: "sold:laptop:480", kind: "send" },
  { tick: 5, from: "buyer-2", to: "seller-1", content: "buy:keyboard:35", kind: "send" },
  { tick: 6, from: "seller-1", to: "buyer-2", content: "sold:keyboard:35", kind: "send" },
  { tick: 7, from: "auctioneer-0", to: "bidder-0", content: "auction:painting:100", kind: "send" },
  { tick: 8, from: "bidder-0", to: "auctioneer-0", content: "bid:painting:150", kind: "send" },
  { tick: 9, from: "bidder-1", to: "auctioneer-0", content: "bid:painting:175", kind: "send" },
  { tick: 10, from: "auctioneer-0", to: "bidder-1", content: "won:painting:175", kind: "send" },
  { tick: 11, from: "auctioneer-0", to: "bidder-0", content: "lost:painting:175", kind: "send" },
  { tick: 12, from: "proposer-0", to: "voter-0", content: "propose:1:increase-budget", kind: "send" },
  { tick: 13, from: "voter-0", to: "coordinator-0", content: "vote:1:yes:voter-0", kind: "send" },
  { tick: 14, from: "voter-1", to: "coordinator-0", content: "vote:1:no:voter-1", kind: "send" },
  { tick: 15, from: "voter-2", to: "coordinator-0", content: "vote:1:yes:voter-2", kind: "send" },
  { tick: 16, from: "coordinator-0", to: "proposer-0", content: "result:1:passed:2-1", kind: "send" },
  { tick: 17, from: "supplier-0", to: "manufacturer-0", content: "material:1:batch-42", kind: "send" },
  { tick: 18, from: "manufacturer-0", to: "distributor-0", content: "product:1:widget-42", kind: "send" },
  { tick: 19, from: "distributor-0", to: "retailer-0", content: "shipment:1:widget-42", kind: "send" },
  { tick: 20, from: "retailer-0", to: "supplier-0", content: "delivered:1:widget-42", kind: "send" },
];

export const scenarioColors: Record<string, string> = {
  marketplace: "#8B0000",
  auction: "#1E40AF",
  voting: "#047857",
  consensus: "#7C3AED",
  supply_chain: "#B45309",
  reputation: "#BE185D",
};
