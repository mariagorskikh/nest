import Link from "next/link";
import { ImagePlaceholder } from "@/components/image-placeholder";
import { agenticCommerceEvent as event } from "@/lib/agentic-commerce-event";

export const metadata = {
  title: "Agentic Commerce Hackathon (concluded)",
  description: `Archive of the concluded ${event.dates} online event and its Project NANDA Prava-adapter track.`,
  alternates: { canonical: "/pravahack" },
  openGraph: {
    title: "Agentic Commerce Hackathon",
    description: event.tagline,
    images: [
      {
        url: "/agentic-commerce/hero.jpg",
        width: 2048,
        height: 1152,
        alt: "Agentic Commerce Hackathon — build AI agents that transact",
      },
    ],
  },
};

const eventJsonLd = {
  "@context": "https://schema.org",
  "@type": "Event",
  name: event.name,
  description: event.tagline,
  startDate: "2026-07-31",
  endDate: "2026-08-02",
  eventAttendanceMode: "https://schema.org/OnlineEventAttendanceMode",
  eventStatus: "https://schema.org/EventCompleted",
  location: {
    "@type": "VirtualLocation",
    url: event.applyUrl,
  },
  image: "https://nandatown.projectnanda.org/agentic-commerce/hero.jpg",
  organizer: {
    "@type": "Organization",
    name: "Agentic Commerce Hackathon (Devfolio)",
    url: "https://agentic-commerce.devfolio.co",
  },
  sponsor: { "@type": "Organization", name: "Project NANDA" },
  isAccessibleForFree: true,
  url: "https://nandatown.projectnanda.org/pravahack",
};

export default function AgenticCommercePage() {
  return (
    <div className="bg-cream-100">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(eventJsonLd) }}
      />
      {/* HERO */}
      <section className="relative paper-texture">
        <div className="relative mx-auto max-w-[1240px] px-6 sm:px-10 pt-16 pb-16 md:pt-20 md:pb-20">
          <h1 className="sr-only">{event.name}</h1>
          <a href={event.applyUrl} target="_blank" rel="noreferrer" className="block transition-opacity hover:opacity-90">
            <ImagePlaceholder
              id="01"
              ratio="16/9"
              prompt={event.tagline}
              src="/agentic-commerce/hero.jpg"
              alt={`${event.name} — ${event.dates}, ${event.format}. ${event.tagline}`}
              priority
            />
          </a>
          <div className="mt-6 flex flex-wrap items-center justify-between gap-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-ink-400">
              Concluded &middot; {event.dates} &middot; {event.format}
            </p>
            <div className="flex flex-wrap gap-3">
              <a href={event.applyUrl} target="_blank" rel="noreferrer" className="btn-primary">
                View event archive &rarr;
              </a>
              <a href="#submit" className="btn-secondary">
                How submissions worked &rarr;
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* PRIZE POOL */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-20 md:py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr] lg:items-start">
            <div>
              <p className="eyebrow">Prize pool</p>
              <p className="mt-6 font-display text-[2.4rem] leading-none text-ink-900">
                {event.prizePool.total}
              </p>
              <p className="mt-4 max-w-sm text-[0.95rem] leading-[1.6] text-ink-500">
                {event.prizePool.note}
              </p>
            </div>
            <div className="grid grid-cols-2 gap-px self-start overflow-hidden rounded-2xl border border-cream-400/50 bg-cream-400/50 sm:grid-cols-3">
              {event.prizePool.breakdown.map((p) => (
                <div key={p.sponsor} className="bg-cream-50 p-5">
                  <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
                    {p.sponsor}
                  </p>
                  <p className="mt-2 font-display text-[1.3rem] leading-tight text-ink-900">
                    {p.amount}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* PROJECT NANDA TRACK — Best Prava Adapter */}
      <section className="border-t border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-20 md:py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr] lg:items-start">
            <div>
              <p className="eyebrow">Project NANDA track &middot; {event.pravaTrack.prize}</p>
              <h2 className="font-display mt-5 text-[clamp(1.9rem,3.6vw,3rem)] leading-[1.08] tracking-[-0.015em] text-ink-900">
                {event.pravaTrack.title}
              </h2>
            </div>
            <div className="lg:pt-2">
              <p className="text-[1.02rem] leading-[1.7] text-ink-600">
                {event.pravaTrack.summary}
              </p>
              <p className="mt-4 text-[1.02rem] leading-[1.7] text-ink-600">
                {event.pravaTrack.stretch}
              </p>
              <p className="mt-6 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
                Submissions are evaluated on
              </p>
              <ul className="mt-3 space-y-2">
                {event.pravaTrack.criteria.map((c) => (
                  <li key={c} className="flex gap-3 text-[0.98rem] leading-[1.6] text-ink-600">
                    <span className="mt-[0.55em] h-px w-4 shrink-0 bg-rust" />
                    {c}
                  </li>
                ))}
              </ul>
              <p className="mt-6 text-[1.02rem] leading-[1.7] text-ink-600">
                {event.pravaTrack.closing}
              </p>
            </div>
          </div>

          <div id="submit" className="mt-12 scroll-mt-24 rounded-2xl border border-rust/40 bg-rust/[0.06] p-7 sm:p-10">
            <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
              Historical submission process
            </p>
            <p className="mt-3 max-w-2xl text-[1.02rem] leading-[1.65] text-ink-700">
              During the event, both the pull request and the Devfolio submission
              were required. These instructions are retained for provenance.
            </p>
            <ol className="mt-6 ml-5 max-w-3xl list-decimal space-y-4 text-[1.02rem] leading-[1.7] text-ink-600 marker:font-mono marker:text-rust">
              <li>
                <span className="font-semibold text-ink-900">Build the adapter as a Nanda Town payments-layer plugin.</span>{" "}
                The payments layer covers quote, pay, verify, and refund. Follow
                the{" "}
                <Link href="/docs" className="text-rust underline decoration-rust/40 underline-offset-4 hover:decoration-rust">
                  current Town manual
                </Link>{" "}
                for the rebuilt CLI and evidence boundaries. The event instructions
                below are preserved as historical material.
              </li>
              <li>
                <span className="font-semibold text-ink-900">Connect it to Prava&rsquo;s Agentic Payments Sandbox.</span>{" "}
                Show at least one successful sandbox transaction in a scenario
                run. Include the scenario and a test, and handle at least one
                failure case.
              </li>
              <li>
                <span className="font-semibold text-ink-900">Open a pull request to{" "}
                <a href="https://github.com/projnanda/nandatown" target="_blank" rel="noreferrer" className="text-rust underline decoration-rust/40 underline-offset-4 hover:decoration-rust">
                  github.com/projnanda/nandatown
                </a>.</span>{" "}
                It should carry the plugin, the scenario and test, and a README
                that explains installation and reuse. Your pull request shows up
                in the{" "}
                <Link href="/prgallery/layers/payments" className="text-rust underline decoration-rust/40 underline-offset-4 hover:decoration-rust">
                  Payments layer
                </Link>{" "}
                of the PR gallery.
              </li>
              <li>
                <span className="font-semibold text-ink-900">Submit your project on{" "}
                <a href={event.applyUrl} target="_blank" rel="noreferrer" className="text-rust underline decoration-rust/40 underline-offset-4 hover:decoration-rust">
                  Devfolio
                </a>{" "}
                as your official hackathon entry.</span>{" "}
                Link your pull request in the Devfolio submission so the judges
                can find the code.
              </li>
            </ol>
          </div>
        </div>
      </section>

      {/* WHAT TO BUILD */}
      <section className="border-t border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-20 md:py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr] lg:items-start">
            <div>
              <p className="eyebrow">What to build</p>
              <h2 className="font-display mt-5 text-[clamp(1.9rem,3.6vw,3rem)] leading-[1.08] tracking-[-0.015em] text-ink-900">
                Agents that <span className="italic text-ink-700">transact</span>.
              </h2>
            </div>
            <div className="lg:pt-2">
              <p className="text-[1.05rem] leading-[1.7] text-ink-500">{event.theme}</p>
              <p className="mt-6 text-[1.05rem] leading-[1.7] text-ink-500">
                {event.keyTech}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* HISTORICAL ELIGIBILITY + PARTICIPATION */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-20 md:py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr] lg:items-start">
            <div>
              <p className="eyebrow">Historical eligibility</p>
              <p className="mt-6 max-w-md text-[1.05rem] leading-[1.7] text-ink-500">
                {event.eligibility}
              </p>
            </div>
            <ol className="grid gap-4">
              {event.participationSteps.map((step, i) => (
                <li
                  key={step}
                  className="flex gap-4 rounded-2xl border border-cream-400/70 bg-cream-50 p-5"
                >
                  <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.2em] text-rust">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="text-[0.97rem] leading-[1.6] text-ink-700">{step}</span>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </section>

      {/* JUDGES */}
      <section className="border-t border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-20 md:py-24">
          <p className="eyebrow">Judges &amp; speakers</p>
          <div className="mt-8 grid gap-px overflow-hidden rounded-2xl border border-cream-400/50 bg-cream-400/50 sm:grid-cols-2 lg:grid-cols-4">
            {event.judges.map((j) => (
              <div key={j.name} className="bg-cream-50 p-6">
                <p className="font-display text-[1.15rem] leading-tight text-ink-900">
                  {j.name}
                </p>
                <p className="mt-2 text-[0.85rem] leading-[1.5] text-ink-500">
                  {j.affiliation}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-cream-400/70 bg-ink-900 text-cream-50">
        <div className="mx-auto flex max-w-[1240px] flex-wrap items-center justify-between gap-8 px-6 py-16 sm:px-10 md:py-20">
          <p className="font-display text-[clamp(1.6rem,3vw,2.4rem)] leading-tight">
            agentic-commerce.devfolio.co
          </p>
          <a
            href={event.applyUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center rounded-md bg-cream-50 px-5 py-2.5 text-[0.9rem] font-medium text-ink-900 transition-colors hover:bg-cream-200"
          >
            View event archive &rarr;
          </a>
        </div>
      </section>
    </div>
  );
}
