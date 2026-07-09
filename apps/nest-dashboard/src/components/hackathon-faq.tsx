import type { FaqEntry } from "@/lib/hackathon-event";

/**
 * FAQ accordion built on native <details>/<summary> — works without
 * client JS, so it can sit inside any server component. Pass a subset
 * of entries for a compact version (e.g. the homepage teaser).
 */
export function HackathonFaq({ entries }: { entries: FaqEntry[] }) {
  return (
    <div className="grid gap-px bg-cream-400/40 border border-cream-400/40 rounded-2xl overflow-hidden">
      {entries.map((faq) => (
        <details key={faq.question} className="group bg-cream-50 open:bg-cream-200 transition-colors">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-6 px-7 py-5 [&::-webkit-details-marker]:hidden">
            <span className="font-display text-[1.2rem] leading-snug text-ink-900">
              {faq.question}
            </span>
            <span
              aria-hidden
              className="shrink-0 font-mono text-[1.1rem] leading-none text-rust transition-transform duration-200 group-open:rotate-45"
            >
              +
            </span>
          </summary>
          <p className="px-7 pb-6 max-w-2xl text-[0.95rem] leading-[1.6] text-ink-500">
            {faq.answer}
          </p>
        </details>
      ))}
    </div>
  );
}
