import Link from "next/link";
import { hackathonEvent } from "@/lib/hackathon-event";

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
            NandaHack is on — join virtually from anywhere.
          </span>{" "}
          <span className="text-cream-200">
            Submissions due {hackathonEvent.submissionDeadline}.
          </span>
        </span>
        <span className="flex items-center gap-4">
          <Link
            href="/hackathon"
            className="font-medium underline underline-offset-4 decoration-cream-200/50 hover:decoration-cream-50 transition-colors"
          >
            Details &amp; FAQs &rarr;
          </Link>
        </span>
      </div>
    </div>
  );
}
