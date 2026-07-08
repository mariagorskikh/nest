'use client';

import { useState, useMemo } from 'react';
import { leaderboardData, scenarioColors } from '@/lib/demo-data';

type SortField = 'rank' | 'deliveryRate' | 'dealRate' | 'latency' | 'agents';
type SortDirection = 'asc' | 'desc';

const scenarios = [
  'All',
  'Marketplace',
  'Auction',
  'Voting',
  'Consensus',
  'Supply Chain',
  'Reputation',
] as const;

const scenarioKeyMap: Record<string, string> = {
  Marketplace: 'marketplace',
  Auction: 'auction',
  Voting: 'voting',
  Consensus: 'consensus',
  'Supply Chain': 'supply_chain',
  Reputation: 'reputation',
};

const scenarioLabel: Record<string, string> = {
  marketplace: 'Marketplace',
  auction: 'Auction',
  voting: 'Voting',
  consensus: 'Consensus',
  supply_chain: 'Supply chain',
  reputation: 'Reputation',
};

export default function LeaderboardPage() {
  const [activeFilter, setActiveFilter] = useState<string>('All');
  const [sortField, setSortField] = useState<SortField>('rank');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection(field === 'rank' ? 'asc' : 'desc');
    }
  };

  const filteredAndSorted = useMemo(() => {
    let data = [...leaderboardData];
    if (activeFilter !== 'All') {
      const key = scenarioKeyMap[activeFilter];
      data = data.filter((entry) => entry.scenario === key);
    }
    data.sort((a, b) => {
      let aVal: number;
      let bVal: number;
      switch (sortField) {
        case 'rank':
          aVal = a.rank; bVal = b.rank; break;
        case 'deliveryRate':
          aVal = a.deliveryRate; bVal = b.deliveryRate; break;
        case 'dealRate':
          aVal = a.dealRate ?? -1; bVal = b.dealRate ?? -1; break;
        case 'latency':
          aVal = a.latency; bVal = b.latency; break;
        case 'agents':
          aVal = a.agents; bVal = b.agents; break;
        default:
          aVal = a.rank; bVal = b.rank;
      }
      return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
    });
    return data;
  }, [activeFilter, sortField, sortDirection]);

  const sortIndicator = (field: SortField) =>
    sortField === field ? (sortDirection === 'asc' ? '↑' : '↓') : '';

  return (
    <div className="min-h-screen bg-cream-100">
      {/* Header */}
      <section className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-16">
          <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr] lg:items-end">
            <h1 className="font-display animate-fade-in stagger-1 text-[clamp(2.6rem,6vw,5rem)] leading-[1.02] tracking-tight text-ink-900">
              Reproducible<br />
              <span className="italic text-ink-700">rankings</span> by<br />
              scenario.
            </h1>
            <p className="animate-fade-in stagger-2 text-[1.1rem] leading-[1.6] text-ink-500 max-w-md">
              Side-by-side metrics, no composite weighting, no hidden tie-breakers.
              Each entry can be re-run with the same seed and will produce the
              same result under Tier 1 conditions.
            </p>
          </div>
        </div>
      </section>

      <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-12">
        {/* Filters */}
        <div className="animate-fade-in stagger-2 flex flex-wrap items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 mr-2">
            Scenario
          </span>
          {scenarios.map((scenario) => {
            const isActive = activeFilter === scenario;
            return (
              <button
                key={scenario}
                onClick={() => setActiveFilter(scenario)}
                className={`px-3.5 py-1.5 text-[0.85rem] font-medium rounded-full transition-colors ${
                  isActive
                    ? 'bg-ink-900 text-cream-50'
                    : 'text-ink-500 hover:text-ink-900 border border-cream-400/70 hover:border-ink-300'
                }`}
              >
                {scenario}
              </button>
            );
          })}
        </div>

        {/* Sort controls */}
        <div className="mt-6 flex flex-wrap items-center gap-2 animate-fade-in stagger-3">
          <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 mr-2">
            Sort by
          </span>
          {(
            [
              ['rank', 'Rank'],
              ['deliveryRate', 'Delivery'],
              ['dealRate', 'Deal'],
              ['latency', 'Latency'],
              ['agents', 'Agents'],
            ] as [SortField, string][]
          ).map(([field, label]) => {
            const isActive = sortField === field;
            return (
              <button
                key={field}
                onClick={() => handleSort(field)}
                className={`px-3 py-1.5 text-[0.85rem] font-medium transition-colors ${
                  isActive
                    ? 'text-ink-900'
                    : 'text-ink-400 hover:text-ink-900'
                }`}
              >
                <span className="border-b border-transparent" style={{
                  borderBottomColor: isActive ? 'var(--color-ink-900)' : 'transparent',
                }}>
                  {label} {sortIndicator(field)}
                </span>
              </button>
            );
          })}
        </div>

        {/* Table */}
        <div className="mt-10 animate-fade-in stagger-4">
          <div className="overflow-x-auto rounded-2xl border border-cream-400/70 bg-cream-50">
            <table className="w-full min-w-[820px] text-left">
              <thead>
                <tr className="border-b border-cream-400/70 bg-cream-200">
                  {[
                    'Rank',
                    'Name',
                    'Scenario',
                    'Agents',
                    'Delivery',
                    'Deal',
                    'Latency',
                    'Throughput',
                    'Date',
                  ].map((h) => (
                    <th
                      key={h}
                      className="px-5 py-4 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400 whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-cream-400/40">
                {filteredAndSorted.map((entry) => {
                  const badgeColor = scenarioColors[entry.scenario] || '#6B6557';
                  const barWidth = Math.min(entry.deliveryRate, 100);
                  const isTop = entry.rank <= 3;

                  return (
                    <tr
                      key={`${entry.rank}-${entry.name}`}
                      className="transition-colors hover:bg-cream-200/60"
                    >
                      {/* Rank — typographic, no emoji */}
                      <td className="px-5 py-4 whitespace-nowrap">
                        <span
                          className={`font-display text-[1.4rem] leading-none tabular-nums ${
                            isTop ? 'text-rust' : 'text-ink-900'
                          }`}
                        >
                          {String(entry.rank).padStart(2, '0')}
                        </span>
                      </td>

                      <td className="px-5 py-4">
                        <span className="text-[0.95rem] font-medium text-ink-900">
                          {entry.name}
                        </span>
                      </td>

                      <td className="px-5 py-4 whitespace-nowrap">
                        <span
                          className="font-mono text-[10px] uppercase tracking-[0.22em]"
                          style={{ color: badgeColor }}
                        >
                          {scenarioLabel[entry.scenario] || entry.scenario}
                        </span>
                      </td>

                      <td className="px-5 py-4 whitespace-nowrap">
                        <span className="text-[0.92rem] font-mono text-ink-500 tabular-nums">
                          {entry.agents}
                        </span>
                      </td>

                      <td className="px-5 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <span className="text-[0.92rem] font-mono text-ink-900 tabular-nums w-12">
                            {entry.deliveryRate}%
                          </span>
                          <div className="h-1 w-20 rounded-full bg-cream-300 overflow-hidden">
                            <div
                              className="h-1 rounded-full bg-rust"
                              style={{ width: `${barWidth}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      <td className="px-5 py-4 whitespace-nowrap">
                        <span className="text-[0.92rem] font-mono text-ink-500 tabular-nums">
                          {entry.dealRate !== null ? `${entry.dealRate}%` : '—'}
                        </span>
                      </td>

                      <td className="px-5 py-4 whitespace-nowrap">
                        <span className="text-[0.92rem] font-mono text-ink-500 tabular-nums">
                          {entry.latency}t
                        </span>
                      </td>

                      <td className="px-5 py-4 whitespace-nowrap">
                        <span className="text-[0.92rem] font-mono text-ink-500 tabular-nums">
                          {entry.throughput} m/t
                        </span>
                      </td>

                      <td className="px-5 py-4 whitespace-nowrap">
                        <span className="text-[0.82rem] text-ink-300">
                          {entry.date}
                        </span>
                      </td>
                    </tr>
                  );
                })}

                {filteredAndSorted.length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-5 py-20 text-center">
                      <p className="font-display italic text-[1.2rem] text-ink-400">
                        No entries match this filter.
                      </p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Reproducibility note */}
        <div className="mt-12 animate-fade-in stagger-5">
          <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-10 sm:p-12">
            <div className="grid gap-10 lg:grid-cols-[1fr_2fr] lg:items-start">
              <div>
                <p className="eyebrow">Methodology</p>
                <h2 className="font-display mt-4 text-[2rem] leading-[1.1] text-ink-900">
                  About these<br />
                  <span className="italic text-ink-700">rankings.</span>
                </h2>
              </div>
              <div>
                <div className="grid gap-px bg-cream-400/40 border border-cream-400/40 rounded-2xl overflow-hidden sm:grid-cols-2">
                  {[
                    {
                      label: 'Delivery rate',
                      desc: 'Fraction of sent messages that were received. Not a measure of protocol success.',
                    },
                    {
                      label: 'Deal rate',
                      desc: 'Percentage of buy requests that resulted in a successful trade. Marketplace and auction only.',
                    },
                    {
                      label: 'Latency',
                      desc: 'Mean ticks between send and receive for correlated message pairs.',
                    },
                    {
                      label: 'Throughput',
                      desc: 'Messages processed per tick across all agents.',
                    },
                  ].map((m) => (
                    <div key={m.label} className="bg-cream-50 p-6">
                      <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
                        {m.label}
                      </p>
                      <p className="mt-3 text-[0.9rem] leading-[1.55] text-ink-500">
                        {m.desc}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
