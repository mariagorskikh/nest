/**
 * SubmissionCard — the shared row used on the layer detail and
 * landing pages. Pulled into its own file so the visual marker
 * for agent-authored vs human-authored is defined exactly once.
 */

import Image from "next/image";
import Link from "next/link";
import type { Submission } from "@/lib/hackathon-types";
import {
  formatLinesAdded,
} from "@/lib/hackathon-types";

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

export function StatusBadge({ submission }: { submission: Submission }) {
  const merged = submission.state === "merged";
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-[0.18em] border " +
        (merged
          ? "bg-sage/10 text-sage border-sage/40"
          : "bg-cream-200 text-ink-400 border-cream-400/40")
      }
      title={
        merged
          ? `Merged ${submission.merged_at ? new Date(submission.merged_at).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : ""}`
          : "Open PR — in review"
      }
    >
      <span
        className={
          "inline-block h-1.5 w-1.5 rounded-full " +
          (merged ? "bg-sage" : "bg-ink-300")
        }
      />
      {merged ? "merged" : "in review"}
    </span>
  );
}


export function SubmissionCard({ submission }: { submission: Submission }) {
  return (
    <Link
      href={`/prgallery/submissions/${submission.id}`}
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
            <StatusBadge submission={submission} />
            <AuthorBadge submission={submission} />
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
            {submission.additions !== null && (
              <span>
                +{formatLinesAdded(submission.additions)} / −
                {formatLinesAdded(submission.deletions ?? 0)}
              </span>
            )}
            {submission.changed_files !== null && (
              <span>{submission.changed_files} files</span>
            )}
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
