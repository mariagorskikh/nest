/**
 * /hackathon/submissions/[id] — full detail view for one PR.
 *
 * Header → author block → judge breakdown → diff stats → links out
 * to the PR and the raw diff.
 */

import Image from "next/image";
import Link from "next/link";
import { notFound } from "next/navigation";
import {
  findSubmissionById,
  formatLinesAdded,
  loadDataset,
} from "@/lib/hackathon";
import { AuthorBadge, StatusBadge } from "@/components/hackathon-card";

export const dynamic = "force-dynamic";


export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const data = await loadDataset();
  const sub = findSubmissionById(data, id);
  if (!sub) return { title: "Submission not found — Nanda Town" };
  return {
    title: `${sub.title.replace(/^\[Hackathon\]\s*/i, "")} — Nanda Town`,
    description: sub.short_description,
  };
}


export default async function SubmissionPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const data = await loadDataset();
  const sub = findSubmissionById(data, id);
  if (!sub) {
    notFound();
  }

  const layer = data.layers.find((l) => l.key === sub.layer);

  return (
    <div className="bg-cream-100">
      <section className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-16 pb-12">
          <div className="flex flex-wrap items-center gap-4 mb-8 animate-fade-in">
            <Link
              href="/prgallery"
              className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 hover:text-ink-900"
            >
              ← Protocols + Plugins
            </Link>
            {layer && (
              <Link
                href={`/prgallery/layers/${layer.key}`}
                className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 hover:text-ink-900"
              >
                ↳ {layer.label} layer
              </Link>
            )}
          </div>

          <div className="grid gap-10 lg:grid-cols-[1.5fr_1fr] lg:items-start">
            <div>
              <div className="flex flex-wrap items-center gap-2 mb-6">
                <StatusBadge submission={sub} />
                <AuthorBadge submission={sub} />
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
                  PR #{sub.pr_number}
                </span>
                {layer && (
                  <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
                    {layer.label}
                  </span>
                )}
              </div>
              <h1 className="font-display animate-fade-in stagger-1 text-[clamp(2rem,4.6vw,3.4rem)] leading-[1.06] tracking-tight text-ink-900">
                {sub.title.replace(/^\[Hackathon\]\s*/i, "")}
              </h1>
              <p className="mt-6 text-[1.05rem] leading-[1.65] text-ink-500 max-w-2xl">
                {sub.short_description || "No description provided."}
              </p>
            </div>

            {/* Author block */}
            <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-6">
              <p className="eyebrow">Author</p>
              <div className="mt-4 flex items-center gap-4">
                <Image
                  src={sub.author.avatar_url}
                  alt={`${sub.author.handle} avatar`}
                  width={64}
                  height={64}
                  className="h-16 w-16 rounded-full border border-cream-400/70 object-cover bg-cream-200"
                  unoptimized
                />
                <div className="min-w-0">
                  <p className="font-display text-[1.4rem] leading-tight text-ink-900">
                    @{sub.author.handle}
                  </p>
                  <a
                    href={sub.author.profile_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-400 hover:text-ink-900"
                  >
                    github profile →
                  </a>
                </div>
              </div>
              <dl className="mt-6 grid grid-cols-2 gap-x-4 gap-y-3 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-400">
                <div>
                  <dt>Status</dt>
                  <dd className="mt-1 font-display text-[1.15rem] leading-none text-ink-900">
                    {sub.state === "merged" ? "Merged" : "In review"}
                  </dd>
                </div>
                <div>
                  <dt>{sub.state === "merged" ? "Merged on" : "Opened on"}</dt>
                  <dd className="mt-1 font-display text-[1.15rem] leading-none text-ink-900 tabular-nums">
                    {new Date(
                      (sub.state === "merged" && sub.merged_at) || sub.created_at,
                    ).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                  </dd>
                </div>
                {sub.additions !== null && (
                  <div>
                    <dt>Lines added</dt>
                    <dd className="mt-1 font-display text-[1.15rem] leading-none text-ink-900 tabular-nums">
                      +{formatLinesAdded(sub.additions)}
                    </dd>
                  </div>
                )}
                <div className={sub.additions !== null ? "" : "col-span-2"}>
                  <dt>Branch</dt>
                  <dd className="mt-1 text-[0.78rem] text-ink-500 truncate normal-case tracking-normal font-mono">
                    {sub.branch}
                  </dd>
                </div>
              </dl>
            </div>
          </div>
        </div>
      </section>


      {/* Body + links */}
      <section>
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-12 grid gap-10 lg:grid-cols-[2fr_1fr]">
          <div>
            <p className="eyebrow">Description</p>
            <h2 className="mt-4 font-display text-[1.8rem] leading-[1.1] text-ink-900">
              The pitch.
            </h2>
            <pre className="mt-6 max-h-[60vh] overflow-auto rounded-2xl border border-cream-400/70 bg-cream-50 p-6 text-[0.88rem] leading-[1.55] text-ink-700 font-sans whitespace-pre-wrap">
              {sub.body_markdown || "No PR body provided."}
            </pre>
          </div>

          <div className="space-y-3">
            <p className="eyebrow">Try it</p>
            <a
              href={sub.pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary w-full justify-center"
            >
              Open PR on GitHub
            </a>
            <a
              href={sub.diff_url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary w-full justify-center"
            >
              View diff
            </a>
            <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-5 mt-6 text-[0.85rem] leading-[1.55] text-ink-500">
              <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
                Checkout locally
              </p>
              {/* Fetch by the numeric PR ref, never the raw branch name — on a
                  public repo the branch is attacker-controlled and would make
                  this copy-paste snippet a shell-injection vector. */}
              <code className="mt-3 block font-mono text-[0.78rem] text-ink-700 break-all">
                git fetch origin pull/{sub.pr_number}/head:pr-{sub.pr_number}
                <br />
                git checkout pr-{sub.pr_number}
              </code>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
