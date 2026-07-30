"use client";

import { useMemo, useState } from "react";
import { EmptyState, SubmissionCard } from "@/components/hackathon-card";
import type { Submission } from "@/lib/hackathon-types";

type SortField = "date" | "author";

const SORTS: { field: SortField; label: string }[] = [
  { field: "date", label: "Date" },
  { field: "author", label: "Author" },
];

export function LayerSubmissions({
  submissions,
  layerLabel,
}: {
  submissions: Submission[];
  layerLabel: string;
}) {
  const [sort, setSort] = useState<SortField>("date");

  const sorted = useMemo(() => {
    const xs = [...submissions];
    xs.sort((a, b) => {
      // Merged PRs always lead — they're the showcased work.
      if (a.state !== b.state) return a.state === "merged" ? -1 : 1;
      if (sort === "date") {
        return b.created_at.localeCompare(a.created_at);
      }
      return a.author.handle.localeCompare(b.author.handle);
    });
    return xs;
  }, [submissions, sort]);

  if (submissions.length === 0) {
    return (
      <EmptyState
        title="Open for submissions."
        body={`No PRs have landed on the ${layerLabel} layer yet — first contribution gets the page to itself.`}
      />
    );
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2 mb-6">
        <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 mr-2">
          Sort by
        </span>
        {SORTS.map(({ field, label }) => {
          const isActive = sort === field;
          return (
            <button
              key={field}
              onClick={() => setSort(field)}
              className={
                "px-3 py-1.5 text-[0.85rem] font-medium transition-colors " +
                (isActive
                  ? "text-ink-900"
                  : "text-ink-400 hover:text-ink-900")
              }
            >
              <span
                className="border-b"
                style={{
                  borderBottomColor: isActive
                    ? "var(--color-ink-900)"
                    : "transparent",
                }}
              >
                {label}
              </span>
            </button>
          );
        })}
      </div>

      <div className="grid gap-5">
        {sorted.map((sub) => (
          <SubmissionCard key={sub.id} submission={sub} />
        ))}
      </div>
    </>
  );
}
