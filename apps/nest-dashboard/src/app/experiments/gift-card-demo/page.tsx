"use client";

import { useMemo, useState } from "react";

type PurchaseRow = {
  customer_id: string;
  gift_card: string;
  merchant: string;
  category: string;
  amount: number;
  notes: string;
};

type Recommendation = {
  giftCard: string;
  purchaseCount: number;
  averageAmount: number;
  matchedCategories: string[];
};

const purchaseHistory: PurchaseRow[] = [
  {
    customer_id: "c-101",
    gift_card: "Steam",
    merchant: "Steam",
    category: "gaming",
    amount: 50,
    notes: "teen birthday",
  },
  {
    customer_id: "c-102",
    gift_card: "Nintendo",
    merchant: "Nintendo",
    category: "gaming",
    amount: 40,
    notes: "family game night",
  },
  {
    customer_id: "c-103",
    gift_card: "Starbucks",
    merchant: "Starbucks",
    category: "coffee",
    amount: 25,
    notes: "coworker appreciation",
  },
  {
    customer_id: "c-104",
    gift_card: "Amazon",
    merchant: "Amazon",
    category: "shopping",
    amount: 75,
    notes: "new apartment",
  },
  {
    customer_id: "c-105",
    gift_card: "Steam",
    merchant: "Steam",
    category: "gaming",
    amount: 30,
    notes: "graduation gift",
  },
  {
    customer_id: "c-106",
    gift_card: "Sephora",
    merchant: "Sephora",
    category: "beauty",
    amount: 60,
    notes: "birthday surprise",
  },
  {
    customer_id: "c-107",
    gift_card: "Target",
    merchant: "Target",
    category: "shopping",
    amount: 45,
    notes: "back to school",
  },
  {
    customer_id: "c-108",
    gift_card: "Starbucks",
    merchant: "Starbucks",
    category: "coffee",
    amount: 20,
    notes: "teacher thank you",
  },
];

const quickQueries = [
  "teen birthday",
  "gaming",
  "coworker",
  "new apartment",
  "teacher",
];

function searchRows(rows: PurchaseRow[], query: string): PurchaseRow[] {
  const tokens = query
    .toLowerCase()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter(Boolean);

  if (tokens.length === 0) return rows;

  return rows.filter((row) => {
    const searchable = [
      row.customer_id,
      row.gift_card,
      row.merchant,
      row.category,
      row.notes,
    ]
      .join(" ")
      .toLowerCase();
    return tokens.every((token) => searchable.includes(token));
  });
}

function recommend(rows: PurchaseRow[], topK = 4): Recommendation[] {
  const byCard = new Map<string, { count: number; total: number; categories: Set<string> }>();

  for (const row of rows) {
    const current = byCard.get(row.gift_card) ?? {
      count: 0,
      total: 0,
      categories: new Set<string>(),
    };
    current.count += 1;
    current.total += row.amount;
    current.categories.add(row.category);
    byCard.set(row.gift_card, current);
  }

  return [...byCard.entries()]
    .map(([giftCard, value]) => ({
      giftCard,
      purchaseCount: value.count,
      averageAmount: value.total / value.count,
      matchedCategories: [...value.categories].sort(),
    }))
    .sort(
      (a, b) =>
        b.purchaseCount - a.purchaseCount ||
        b.averageAmount - a.averageAmount ||
        a.giftCard.localeCompare(b.giftCard),
    )
    .slice(0, topK);
}

export default function GiftCardRecommendationDemoPage() {
  const [query, setQuery] = useState("gaming teen");

  const matchedRows = useMemo(() => searchRows(purchaseHistory, query), [query]);
  const recommendations = useMemo(() => recommend(matchedRows), [matchedRows]);

  return (
    <div className="relative min-h-screen overflow-hidden bg-cream-100 pb-16">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-32 -left-24 h-72 w-72 rounded-full bg-rust/15 blur-3xl" />
        <div className="absolute top-40 -right-20 h-64 w-64 rounded-full bg-ink-300/20 blur-3xl" />
        <div className="absolute bottom-10 left-8 h-40 w-40 rounded-full bg-rust-soft/20 blur-2xl" />
      </div>

      <div className="relative mx-auto w-full max-w-md px-4 pt-8">
        <header className="animate-fade-in">
          <p className="eyebrow">Mobile demo</p>
          <h1 className="mt-3 font-display text-[2.25rem] leading-[0.98] tracking-[-0.02em] text-ink-900">
            Gift card
            <br />
            recommender
          </h1>
          <p className="mt-4 text-[0.98rem] leading-[1.55] text-ink-500">
            A phone-first interface for the gift card recommendation protocol.
            Search purchase history, then rank card suggestions.
          </p>
        </header>

        <section className="animate-slide-up stagger-1 mt-7 rounded-3xl border border-cream-400/70 bg-cream-50/95 p-4 shadow-[0_12px_30px_rgba(20,19,18,0.08)] backdrop-blur-sm">
          <label htmlFor="gift-query" className="eyebrow">
            Search intent
          </label>
          <div className="mt-2 flex items-center gap-2 rounded-2xl border border-cream-400 bg-cream-100 px-3 py-2">
            <svg
              aria-hidden="true"
              viewBox="0 0 24 24"
              className="h-4 w-4 shrink-0 text-ink-400"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
            >
              <circle cx="11" cy="11" r="7" />
              <path d="M20 20L16.65 16.65" />
            </svg>
            <input
              id="gift-query"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Try: teen birthday"
              className="w-full bg-transparent text-[0.95rem] text-ink-800 placeholder:text-ink-300 focus:outline-none"
            />
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            {quickQueries.map((q) => (
              <button
                key={q}
                type="button"
                onClick={() => setQuery(q)}
                className="rounded-full border border-cream-400 bg-cream-100 px-3 py-1.5 text-[0.75rem] font-medium text-ink-600 transition-colors hover:border-ink-300 hover:text-ink-900"
              >
                {q}
              </button>
            ))}
          </div>
        </section>

        <section className="animate-slide-up stagger-2 mt-5 rounded-3xl border border-ink-900/10 bg-gradient-to-br from-ink-900 to-ink-700 p-4 text-cream-50 shadow-[0_12px_30px_rgba(20,19,18,0.18)]">
          <div className="flex items-end justify-between">
            <h2 className="font-display text-[1.55rem] leading-tight">Top picks</h2>
            <p className="font-mono text-[0.64rem] uppercase tracking-[0.2em] text-ink-100/80">
              {matchedRows.length} matches
            </p>
          </div>

          <div className="mt-3 space-y-2.5">
            {recommendations.length === 0 && (
              <p className="rounded-2xl border border-cream-50/20 bg-cream-50/5 px-3 py-4 text-[0.9rem] text-cream-50/80">
                No matching purchases yet. Try a broader query.
              </p>
            )}

            {recommendations.map((item, index) => (
              <article
                key={item.giftCard}
                className="rounded-2xl border border-cream-50/20 bg-cream-50/10 px-3 py-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-[0.98rem] font-semibold">{item.giftCard}</p>
                    <p className="mt-0.5 text-[0.78rem] text-cream-50/75">
                      {item.matchedCategories.join(" · ")}
                    </p>
                  </div>
                  <span className="rounded-full border border-cream-50/30 px-2 py-1 font-mono text-[0.62rem] uppercase tracking-[0.18em] text-cream-50/80">
                    #{index + 1}
                  </span>
                </div>

                <div className="mt-3 grid grid-cols-2 gap-2">
                  <StatPill label="Purchases" value={String(item.purchaseCount)} />
                  <StatPill label="Avg amount" value={`$${item.averageAmount.toFixed(0)}`} />
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="animate-slide-up stagger-3 mt-5 rounded-3xl border border-cream-400/70 bg-cream-50 p-4 shadow-[0_10px_26px_rgba(20,19,18,0.07)]">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-[1.35rem] leading-tight text-ink-900">
              Protocol flow
            </h2>
            <p className="font-mono text-[0.62rem] uppercase tracking-[0.18em] text-ink-400">
              minimal
            </p>
          </div>

          <ol className="mt-3 space-y-2.5">
            {[
              "publish purchase_history_table",
              "search_purchase_history(query)",
              "recommend_gift_cards(top_k)",
            ].map((step, i) => (
              <li
                key={step}
                className="flex items-center gap-3 rounded-2xl border border-cream-400 bg-cream-100 px-3 py-2"
              >
                <span className="flex h-6 w-6 items-center justify-center rounded-full bg-rust text-[0.72rem] font-semibold text-cream-50">
                  {i + 1}
                </span>
                <span className="font-mono text-[0.76rem] text-ink-600">{step}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="animate-slide-up stagger-4 mt-5 rounded-3xl border border-cream-400/70 bg-cream-50 p-4">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-[1.25rem] text-ink-900">Matched history</h2>
            <span className="font-mono text-[0.62rem] uppercase tracking-[0.18em] text-ink-400">
              table view
            </span>
          </div>

          <div className="mt-3 max-h-64 space-y-2 overflow-auto pr-1">
            {matchedRows.map((row) => (
              <article
                key={`${row.customer_id}-${row.gift_card}-${row.amount}`}
                className="rounded-2xl border border-cream-400 bg-cream-100 px-3 py-2.5"
              >
                <div className="flex items-center justify-between">
                  <p className="text-[0.88rem] font-medium text-ink-800">{row.gift_card}</p>
                  <p className="text-[0.8rem] font-semibold text-rust">${row.amount}</p>
                </div>
                <p className="mt-0.5 text-[0.76rem] text-ink-500">
                  {row.category} · {row.notes}
                </p>
              </article>
            ))}
            {matchedRows.length === 0 && (
              <p className="rounded-2xl border border-dashed border-cream-400 px-3 py-4 text-[0.88rem] text-ink-400">
                No purchase rows match this query.
              </p>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function StatPill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-cream-50/20 bg-cream-50/10 px-2.5 py-2">
      <p className="font-mono text-[0.6rem] uppercase tracking-[0.16em] text-cream-50/70">{label}</p>
      <p className="mt-1 text-[0.9rem] font-semibold text-cream-50">{value}</p>
    </div>
  );
}
