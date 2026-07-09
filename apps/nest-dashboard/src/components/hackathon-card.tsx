/**
 * SubmissionCard — the shared row used on the layer detail and
 * landing pages. Pulled into its own file so the visual marker
 * for agent-authored vs human-authored is defined exactly once.
 */
import Image from "next/image";
import Link from "next/link";
import type { Submission } from "@/lib/hackathon-types";
import { SCORE_TOTAL_MAX } from "@/lib/hackathon-types";
import {
  formatLinesAdded,
  formatScore,
} from "@/lib/hackathon-display";
export function AuthorBadge({ submission }: { submission: Submission }) {
  const isAgent = submission.tag === "agent-authored";
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-[0.18em] " +
        (isAgent
          ? "bg-rust-bg text-rust border border-rust-soft/60"
          : "bg-cream-200 text-ink-500 border border-cream-400/70")
      }
    >
      <span
        className={
          "inline-block h-1.5 w-1.5 rounded-full " +
          (isAgent ? "bg-rust" : "bg-ink-300")
        }
      />
      {isAgent ? "agent" : "human"}
    </span>
  );
}
export function ScoreBadge({ submission }: { submission: Submission }) {
  const total = submission.score?.total ?? null;
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-[0.18em] border " +
        (total !== null
          ? "bg-cream-50 text-ink-900 border-cream-400/70"
          : "bg-cream-200 text-ink-400 border-cream-400/40")
      }
      title={
        total !== null
          ? `Judge score: ${formatScore(total)} / ${SCORE_TOTAL_MAX}`
          : "Unscored — judging in progress"
      }
    >
      <span className="text-ink-300">score</span>
      <span className="tabular-nums text-ink-900">{formatScore(total)}</span>
    </span>
  );
}
export function SubmissionCard({ submission }: { submission: Submission }) {
  return (
    <Link
      href={`/hackathon/submissions/${submission.id}`}
      className="group block rounded-2xl border border-cream-400/70 bg-cream-50 p-6 transition-colors hover:bg-cream-200/60"
    >
      <div className="flex items-start gap-4">
        <Image
          src={submission.author.avatar_url}
          alt={`${submission.author.handle} avatar`}
          width={48}
          height={48}
          className="h-12 w-12 rounded-full border border-cream-400/70 bg-cream-200 object-cover"
          unoptimized
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <AuthorBadge submission={submission} />
            <ScoreBadge submission={submission} />
            <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
              {submission.layer}
            </span>
          </div>
          <h3 className="mt-3 font-display text-[1.35rem] leading-[1.2] text-ink-900 group-hover:text-ink-700">
            {submission.title.replace(/^\[Hackathon\]\s*/i, "")}
          </h3>
          <p className="mt-2 text-[0.92rem] leading-[1.55] text-ink-500 line-clamp-2">
            {submission.short_description || "No description provided."}
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-4 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-400">
            <span>@{submission.author.handle}</span>
            <span>
              +{formatLinesAdded(submission.additions ?? 0)} / −
              {formatLinesAdded(submission.deletions ?? 0)}
            </span>
            <span>{submission.changed_files ?? 0} files</span>
            <span>PR #{submission.pr_number}</span>
          </div>
        </div>
      </div>
    </Link>
  );
}
export function EmptyState({
  title,
  body,
}: {
  title: string;
  body: string;
}) {
  return (
    <div className="rounded-2xl border border-dashed border-cream-400/70 bg-cream-50 p-12 text-center">
      <p className="font-display italic text-[1.4rem] text-ink-400">{title}</p>
      <p className="mt-3 text-[0.92rem] text-ink-500">{body}</p>
    </div>
  );
}
