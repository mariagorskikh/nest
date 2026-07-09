/**
 * /hackathon — landing page for the marketplace.
 *
 * Shows the four headline aggregates the brief asked for (total
 * submissions, unique participants, layers covered, total lines
 * added), a few featured submissions, and a CTA into the layer
 * grid. Server-rendered: reads the static dataset and renders.
 */

import Link from "next/link";
import { formatLinesAdded, loadDataset } from "@/lib/hackathon";
import { EmptyState, SubmissionCard } from "@/components/hackathon-card";

export const revalidate = 300;

export const metadata = {
  title: "Hackathon Marketplace — Nanda Town",
  description:
    "Browse every protocol and plugin submitted to the Nanda Town hackathon, by layer, author, and judge score.",
};

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div>
      <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
        {label}
      </span>
      <p className="mt-3 font-display text-[2.2rem] leading-none text-ink-900 tabular-nums">
        {value}
      </p>
      {hint && (
        <span className="mt-2 block text-[0.85rem] text-ink-400">{hint}</span>
      )}
    </div>
  );
}

export default async function HackathonLandingPage() {
  const data = await loadDataset();
  const featured = data.submissions
    .slice()
    .sort((a, b) => {
      const sa = a.score?.total ?? -1;
      const sb = b.score?.total ?? -1;
      if (sa !== sb) return sb - sa;
      return (b.additions ?? 0) - (a.additions ?? 0);
    })
    .slice(0, 3);

  return (
    <div className="bg-cream-100">
      {/* Header */}
      <section className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-16">
          <div className="flex items-center gap-3 mb-10 animate-fade-in">
            <span className="inline-flex h-1.5 w-1.5 rounded-full bg-rust animate-pulse-dot" />
            <span className="eyebrow">Hackathon &middot; open submissions</span>
          </div>

          <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr] lg:items-start">
            <h1 className="font-display animate-fade-in stagger-1 text-[clamp(2.6rem,6vw,5rem)] leading-[1.02] tracking-tight text-ink-900">
              The marketplace
              <br />
              of <span className="italic text-ink-700">protocols</span>.
            </h1>

            <p className="animate-fade-in stagger-2 text-[1.1rem] leading-[1.6] text-ink-500 lg:pt-6 max-w-md">
              Every plugin and protocol pitched at the Nanda Town hackathon, with
              the author behind it, the layer it touches, and a judge score
              you can argue with. Open PRs only &mdash; nothing here is
              merged yet.
            </p>
          </div>

          <div className="mt-12 flex flex-wrap gap-3 animate-fade-in stagger-3">
            <Link href="/hackathon/layers" className="btn-primary">
              Browse by layer
            </Link>
            <a
              href="https://github.com/projnanda/nandatown/pulls"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary"
            >
              All open PRs on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-12 grid grid-cols-2 md:grid-cols-4 gap-10">
          <Stat
            label="Submissions"
            value={String(data.stats.total_submissions)}
            hint="across all 12 layers"
          />
          <Stat
            label="Participants"
            value={String(data.stats.unique_participants)}
            hint="unique handles"
          />
          <Stat
            label="Layers covered"
            value={`${data.stats.layers_covered}/${data.stats.layers_total}`}
            hint="layers with at least one PR"
          />
          <Stat
            label="Lines added"
            value={formatLinesAdded(data.stats.total_lines_added)}
            hint={`${data.stats.total_files_changed ?? 0} files touched`}
          />
        </div>
      </section>

      {/* Featured */}
      <section>
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-14">
          <div className="flex items-end justify-between gap-6 mb-8">
            <div>
              <p className="eyebrow">Featured submissions</p>
              <h2 className="mt-4 font-display text-[2rem] leading-[1.1] text-ink-900">
                Top of the<br />
                <span className="italic text-ink-700">stack</span>.
              </h2>
            </div>
            <Link
              href="/hackathon/layers"
              className="hidden sm:inline-flex font-mono text-[11px] uppercase tracking-[0.18em] text-ink-500 hover:text-ink-900"
            >
              Browse by layer →
            </Link>
          </div>

          {featured.length === 0 ? (
            <EmptyState
              title="No submissions yet."
              body="GitHub couldn't be reached when the dataset was last built, or no hackathon/* PRs are open. Try again in five minutes."
            />
          ) : (
            <div className="grid gap-5 lg:grid-cols-3">
              {featured.map((sub) => (
                <SubmissionCard key={sub.id} submission={sub} />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Footer rail */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-14 grid gap-10 lg:grid-cols-[1fr_2fr] lg:items-start">
          <div>
            <p className="eyebrow">How it works</p>
            <h2 className="mt-4 font-display text-[1.8rem] leading-[1.1] text-ink-900">
              Open PR →<br />
              <span className="italic text-ink-700">judge</span> → marketplace.
            </h2>
          </div>
          <div className="grid gap-px bg-cream-400/40 border border-cream-400/40 rounded-2xl overflow-hidden sm:grid-cols-3">
            {[
              {
                label: "01 — Submit",
                body: "Open a PR with branch hackathon/<handle>-<theme>. It appears here automatically.",
              },
              {
                label: "02 — Judge",
                body: "A judge panel scores each submission on correctness, realism, design, and docs. Missing scores read as “unscored”.",
              },
              {
                label: "03 — Try it",
                body: "Click any submission for the full breakdown — author, layer, PR diff, and score reasoning.",
              },
            ].map((step) => (
              <div key={step.label} className="bg-cream-50 p-6">
                <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
                  {step.label}
                </p>
                <p className="mt-3 text-[0.92rem] leading-[1.55] text-ink-500">
                  {step.body}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
