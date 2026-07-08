import { hackathonEvent } from "@/lib/hackathon-event";

/**
 * The two-phase "how to join the hackathon" block. Rendered on both the
 * /skills and /hackathon pages so the participation path reads the same in
 * both places. Renders just the heading + cards — each page wraps it in its
 * own section container.
 */
function PhaseCard({
  phase,
  title,
  body,
  href,
}: {
  phase: string;
  title: string;
  body: string;
  href: string;
}) {
  return (
    <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-6">
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-rust">
        {phase}
      </p>
      <h3 className="mt-3 font-display text-[1.4rem] leading-tight text-ink-900">
        {title}
      </h3>
      <p className="mt-2 text-[0.97rem] leading-[1.6] text-ink-500">{body}</p>
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="mt-4 inline-flex font-medium text-rust hover:text-ink-900"
      >
        Open the repo on GitHub →
      </a>
    </div>
  );
}

export function HackathonPhases() {
  return (
    <div>
      <p className="eyebrow mb-4">How to take part</p>
      <h2 className="mb-6 font-display text-[clamp(1.8rem,3vw,2.5rem)] leading-[1.1] tracking-tight text-ink-900">
        Two phases to join the hackathon
      </h2>
      <div className="grid gap-4 sm:grid-cols-2">
        <PhaseCard
          phase="Phase 1"
          title="Build it"
          body="Open the repo on GitHub and follow the README. It walks you through every step."
          href={hackathonEvent.repoUrl}
        />
        <PhaseCard
          phase="Phase 2"
          title="Submit it"
          body="Ready to submit your PR? Open a pull request to the repo before the deadline. That’s your entry."
          href={hackathonEvent.githubPRsUrl}
        />
      </div>
    </div>
  );
}
