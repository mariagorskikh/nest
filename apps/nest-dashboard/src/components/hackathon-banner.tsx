import Link from "next/link";

/**
 * Site-wide announcement bar, rendered above the navbar on every page.
 * One line on desktop; wraps gracefully on mobile.
 */
export function HackathonBanner() {
  return (
    <div className="bg-ink-900 text-cream-100">
      <div className="mx-auto flex max-w-[1240px] flex-wrap items-center justify-center gap-x-5 gap-y-1 px-6 sm:px-10 py-2.5 text-center text-[0.85rem] leading-snug">
        <span>
          <span className="font-semibold text-cream-50">
            Vote for your favorite SkillMD.
          </span>{" "}
          <span className="text-cream-200">
            The submission with the most likes wins the{" "}
            <span className="font-semibold text-cream-50">
              $1,000 Audience Choice Award
            </span>
            .
          </span>
        </span>
        <span className="flex items-center gap-4">
          <Link
            href="/skills"
            className="font-medium underline underline-offset-4 decoration-cream-200/50 hover:decoration-cream-50 transition-colors"
          >
            Vote now &rarr;
          </Link>
        </span>
      </div>
    </div>
  );
}
