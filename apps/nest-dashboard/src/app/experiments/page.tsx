'use client';

import { useState } from 'react';
import Link from 'next/link';
import { experiments, scenarioColors } from '@/lib/demo-data';
import { ImagePlaceholder } from '@/components/image-placeholder';

const scenarioFilters = [
  'All',
  'Marketplace',
  'Auction',
  'Voting',
  'Consensus',
  'Supply Chain',
  'Reputation',
] as const;

function scenarioFilterKey(label: string): string {
  if (label === 'All') return 'all';
  if (label === 'Supply Chain') return 'supply_chain';
  return label.toLowerCase();
}

function formatScenarioLabel(scenario: string): string {
  return scenario
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/* ------------------------------------------------------------------
 *  Image prompts per scenario — surfaced inside the card image box
 *  so each card has its own placeholder ready to hand to an
 *  image-generation model.
 * ------------------------------------------------------------------ */
const scenarioImagePrompts: Record<string, string> = {
  marketplace:
    'Abstract editorial illustration of an open-air market reduced to geometry: warm rust circles trading positions with soft cream squares on a beige paper background. Calm, hand-drawn, light grain. Palette #F0EDE4, #C45A3C, #E8E4D6.',
  auction:
    'Abstract composition suggesting a sealed-bid auction: a vertical stack of folded warm-orange paper rectangles on cream, only one slightly larger. Quiet, editorial, ink-and-wash. Palette cream #F0EDE4, rust #C45A3C, ink #221F1A.',
  voting:
    'Abstract scene of small dots gathering toward a centroid in warm rust on cream, like sand drawn to a magnet. Sparse, calm, hand-illustrated. No text. Palette #F0EDE4, #C45A3C, #4D4940.',
  consensus:
    'Abstract concentric circles of warm orange ink radiating outward across cream paper, suggesting agreement spreading from a leader. Hand-drawn, slightly imperfect. Palette #F0EDE4, #C45A3C, #6B6557.',
  supply_chain:
    'Abstract horizontal pipeline: four warm rust nodes connected by hand-drawn cream-paper lines, slight watercolour bloom at each node. Editorial scientific feel. Palette #F0EDE4, #C45A3C, #E8E4D6.',
  reputation:
    'Abstract field of warm orange dots of varying opacity on cream, some clustered tightly, some isolated, suggesting reputation drift. Subtle paper grain, ink-wash style. Palette #F0EDE4, #C45A3C, #221F1A.',
};

/* ------------------------------------------------------------------
 *  Per-scenario illustration assets and accessible descriptions.
 *  Files live in /public/illustrations/. Each card pulls its image
 *  from this map; if a scenario is missing here, the ImagePlaceholder
 *  falls back to its prompt-overlay placeholder mode.
 * ------------------------------------------------------------------ */
const scenarioImages: Record<string, { src: string; alt: string }> = {
  marketplace: {
    src: '/illustrations/img_05_marketplace.png',
    alt: 'Warm rust circles trading positions with cream squares on beige paper — geometry of an open-air market.',
  },
  auction: {
    src: '/illustrations/img_06_auction.png',
    alt: 'A vertical stack of folded warm-orange paper rectangles on cream, only one slightly larger — sealed-bid auction.',
  },
  voting: {
    src: '/illustrations/img_07_voting.png',
    alt: 'Small rust-orange dots gathering toward a centroid on cream paper, like iron filings to a magnet.',
  },
  consensus: {
    src: '/illustrations/img_08_consensus.png',
    alt: 'Concentric circles of warm orange ink radiating outward across cream paper.',
  },
  supply_chain: {
    src: '/illustrations/img_09_supply_chain.png',
    alt: 'Horizontal pipeline of four warm rust nodes connected by hand-drawn cream-paper lines with watercolour bloom at each node.',
  },
  reputation: {
    src: '/illustrations/img_10_reputation.png',
    alt: 'Field of warm-orange dots of varying opacity on cream paper, some clustered tightly, some isolated — reputation drift.',
  },
};

const yamlSnippets: Record<string, string> = {
  marketplace: `scenario: marketplace
agents:
  buyers: 50
  sellers: 50
rounds: 10
protocol: negotiation
metrics:
  - delivery_rate
  - deal_rate
  - mean_latency
  - throughput`,
  auction: `scenario: auction
agents:
  auctioneer: 1
  bidders: 49
rounds: 5
protocol: sealed_bid
reserve_price: 100
metrics:
  - delivery_rate
  - deal_rate
  - mean_rounds_to_deal`,
  voting: `scenario: voting
agents:
  proposer: 1
  voters: 20
  coordinator: 1
rounds: 3
protocol: majority_vote
quorum: 0.5
metrics:
  - delivery_rate
  - duration`,
  consensus: `scenario: consensus
agents:
  leader: 1
  followers: 6
quorum: 0.667
rounds: 10
metrics:
  - delivery_rate
  - message_count
  - agent_count`,
  supply_chain: `scenario: supply_chain
agents:
  supplier: 1
  manufacturer: 1
  distributor: 1
  retailer: 1
hops: 4
protocol: pipeline
metrics:
  - mean_latency
  - delivery_rate`,
  reputation: `scenario: reputation
agents:
  honest_traders: 6
  malicious_traders: 2
  observer: 1
  coordinator: 1
malicious_ratio: 0.2
protocol: reputation_tracking
metrics:
  - delivery_rate
  - unique_pairs`,
};

export default function ExperimentsPage() {
  const [activeFilter, setActiveFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered =
    activeFilter === 'all'
      ? experiments
      : experiments.filter((e) => e.scenario === activeFilter);

  return (
    <div className="min-h-screen bg-cream-100">
      {/* Header */}
      <section className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-16">
          <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr] lg:items-end">
            <h1 className="font-display animate-fade-in stagger-1 text-[clamp(2.6rem,6vw,5rem)] leading-[1.02] tracking-tight text-ink-900">
              Pre-built<br />
              <span className="italic text-ink-700">scenarios</span> to<br />
              probe behaviour.
            </h1>
            <p className="animate-fade-in stagger-2 text-[1.1rem] leading-[1.6] text-ink-500 max-w-md">
              Explore the scenarios that ship with Nanda Town. Each one ran with
              the reference plugins &mdash; every metric here is reproducible
              from the seed in the YAML.
            </p>
          </div>
        </div>
      </section>

      {/* Filters */}
      <section className="border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-6">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 mr-3">
              Filter
            </span>
            {scenarioFilters.map((label) => {
              const key = scenarioFilterKey(label);
              const isActive = activeFilter === key;
              return (
                <button
                  key={key}
                  onClick={() => setActiveFilter(key)}
                  className={`px-3.5 py-1.5 text-[0.85rem] font-medium rounded-full transition-colors ${
                    isActive
                      ? 'bg-ink-900 text-cream-50'
                      : 'text-ink-500 hover:text-ink-900 border border-cream-400/70 hover:border-ink-300'
                  }`}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* Cards */}
      <section>
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-14">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {filtered.map((exp, idx) => {
              const color = scenarioColors[exp.scenario] ?? '#6B6557';
              const isExpanded = expandedId === exp.id;
              const staggerClass = `stagger-${(idx % 6) + 1}`;
              const prompt =
                scenarioImagePrompts[exp.scenario] ??
                'Abstract editorial illustration in warm cream and rust.';
              const image = scenarioImages[exp.scenario];

              return (
                <article
                  key={exp.id}
                  className={`animate-fade-in ${staggerClass} group rounded-2xl bg-cream-200 overflow-hidden transition-colors hover:bg-cream-300 flex flex-col`}
                >
                  <ImagePlaceholder
                    id={exp.id.slice(0, 4).toUpperCase()}
                    ratio="16/10"
                    prompt={prompt}
                    src={image?.src}
                    alt={image?.alt}
                    sizes="(min-width: 1024px) 33vw, (min-width: 768px) 50vw, 100vw"
                    className="-mb-px"
                  />

                  <div className="p-7 flex flex-col gap-4 flex-1">
                    <div className="flex items-center justify-between">
                      <span
                        className="font-mono text-[10px] uppercase tracking-[0.22em]"
                        style={{ color }}
                      >
                        {formatScenarioLabel(exp.scenario)}
                      </span>
                      <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
                        {exp.agents} agents
                      </span>
                    </div>

                    <h2 className="font-display text-[1.8rem] leading-[1.1] text-ink-900">
                      {exp.name}
                    </h2>

                    <p className="text-[0.95rem] leading-[1.55] text-ink-500 line-clamp-3">
                      {exp.description}
                    </p>

                    {/* Metric strip */}
                    {exp.metrics && (
                      <div className="mt-3 grid grid-cols-3 gap-4 border-t border-cream-400/70 pt-5">
                        <Metric label="Delivery" value={`${exp.metrics.deliveryRate}%`} />
                        <Metric
                          label="Latency"
                          value={`${exp.metrics.meanLatency}t`}
                        />
                        <Metric
                          label="Msgs"
                          value={exp.metrics.messageCount.toLocaleString()}
                        />
                      </div>
                    )}

                    <div className="mt-auto pt-5 flex items-center justify-between">
                      <button
                        onClick={() =>
                          setExpandedId(isExpanded ? null : exp.id)
                        }
                        className="text-[0.85rem] font-medium text-ink-900 hover:text-rust transition-colors"
                      >
                        {isExpanded ? 'Hide details' : 'View details'} &nbsp;
                        <span className="inline-block transition-transform" style={{
                          transform: isExpanded ? 'rotate(180deg)' : 'none',
                        }}>
                          &darr;
                        </span>
                      </button>
                      <Link
                        href="/visualizer"
                        className="text-[0.85rem] text-ink-400 hover:text-ink-900 transition-colors"
                      >
                        Visualize &rarr;
                      </Link>
                    </div>
                  </div>

                  {/* Expanded */}
                  {isExpanded && exp.metrics && (
                    <div className="border-t border-cream-400/70 bg-cream-50 p-7 animate-fade-in">
                      <h3 className="eyebrow">Full metrics</h3>
                      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
                        <Cell label="Delivery rate" value={`${exp.metrics.deliveryRate}%`} />
                        {exp.metrics.dealRate !== null && (
                          <Cell label="Deal rate" value={`${exp.metrics.dealRate}%`} />
                        )}
                        <Cell label="Mean latency" value={`${exp.metrics.meanLatency} ticks`} />
                        <Cell label="Messages" value={exp.metrics.messageCount.toLocaleString()} />
                        <Cell label="Throughput" value={`${exp.metrics.throughput} m/t`} />
                      </div>

                      <h3 className="mt-8 eyebrow">Metric comparison</h3>
                      <div className="mt-4 space-y-3">
                        <Bar
                          label="Delivery"
                          value={exp.metrics.deliveryRate}
                          max={100}
                          color={color}
                          suffix="%"
                        />
                        {exp.metrics.dealRate !== null && (
                          <Bar
                            label="Deal"
                            value={exp.metrics.dealRate}
                            max={100}
                            color={color}
                            suffix="%"
                          />
                        )}
                        <Bar
                          label="Latency"
                          value={exp.metrics.meanLatency}
                          max={10}
                          color={color}
                          suffix=" t"
                        />
                        <Bar
                          label="Throughput"
                          value={exp.metrics.throughput}
                          max={50}
                          color={color}
                          suffix=" m/t"
                        />
                      </div>

                      <h3 className="mt-8 eyebrow">Scenario config</h3>
                      <pre className="mt-3 overflow-x-auto rounded-lg bg-ink-900 text-cream-100 p-4 text-[0.78rem] leading-relaxed font-mono">
                        <code>
                          {yamlSnippets[exp.scenario] ?? '# No config available'}
                        </code>
                      </pre>

                      <Link
                        href="/visualizer"
                        className="mt-6 inline-flex items-center text-[0.85rem] font-medium text-ink-900 hover:text-rust transition-colors"
                      >
                        Open in visualizer &rarr;
                      </Link>
                    </div>
                  )}
                </article>
              );
            })}
          </div>

          {filtered.length === 0 && (
            <div className="mt-16 text-center animate-fade-in">
              <p className="font-display text-[1.4rem] italic text-ink-400">
                No experiments found for this scenario.
              </p>
            </div>
          )}
        </div>
      </section>

      {/* Run your own */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.5fr] lg:items-center">
            <ImagePlaceholder
              id="D"
              ratio="4/5"
              src="/illustrations/img_04_experiments.png"
              alt="Stacked YAML-like horizontal lines flowing into a single warm rust beam of light on cream paper, with slight ink bleed."
              sizes="(min-width: 1024px) 40vw, 100vw"
              prompt="Abstract illustration of stacked YAML-like horizontal lines flowing into a single warm rust beam of light on cream paper. Slight ink bleed at the edges, hand-drawn feel. Editorial science aesthetic. Palette #F0EDE4, #C45A3C, #221F1A."
              caption="Image — run your own"
            />
            <div>
              <p className="eyebrow">Bring your own scenario</p>
              <h2 className="font-display mt-5 text-[clamp(2rem,4vw,3.2rem)] leading-tight text-ink-900">
                Run Nanda Town<br />
                <span className="italic text-ink-700">on your laptop.</span>
              </h2>
              <p className="mt-6 text-[1.05rem] leading-[1.6] text-ink-500 max-w-lg">
                Install the CLI and run any scenario with a single command.
                Define your own agents, protocols, and metrics in YAML &mdash;
                use the reference plugins or write your own.
              </p>

              <pre className="mt-8 overflow-x-auto rounded-lg bg-ink-900 text-cream-100 px-5 py-4 text-[0.88rem] leading-relaxed font-mono">
                <code>$ pip install &quot;nest-core[plugins]&quot;
$ nest run marketplace</code>
              </pre>

              <div className="mt-8">
                <Link href="/docs" className="btn-secondary">
                  Read the full guide &rarr;
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

/* ---------------------------------------------------------------- */
/*  Small components                                                  */
/* ---------------------------------------------------------------- */

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-ink-300">
        {label}
      </p>
      <p className="mt-1.5 font-display text-[1.3rem] leading-none text-ink-900">
        {value}
      </p>
    </div>
  );
}

function Cell({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-cream-200 px-4 py-3">
      <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-ink-400">
        {label}
      </p>
      <p className="mt-2 font-display text-[1.3rem] leading-none text-ink-900">
        {value}
      </p>
    </div>
  );
}

function Bar({
  label,
  value,
  max,
  color,
  suffix = '',
}: {
  label: string;
  value: number;
  max: number;
  color: string;
  suffix?: string;
}) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="flex items-center gap-3">
      <span className="w-20 shrink-0 text-[0.78rem] font-medium text-ink-400 text-right">
        {label}
      </span>
      <div className="flex-1 h-1.5 rounded-full bg-cream-300 overflow-hidden">
        <div
          className="h-1.5 rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="w-20 shrink-0 text-[0.78rem] font-mono text-ink-700 text-right tabular-nums">
        {value.toLocaleString()}
        {suffix}
      </span>
    </div>
  );
}
