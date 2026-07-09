'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { liveAgentChat, experiments, scenarioColors } from '@/lib/demo-data';
import type { AgentMessage } from '@/lib/demo-data';
import { MiniMap } from '@/components/mini-map';
import { ImagePlaceholder } from '@/components/image-placeholder';
import { HackathonFaq } from '@/components/hackathon-faq';
import { hackathonEvent, hackathonFaqs } from '@/lib/hackathon-event';

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function getScenarioFromAgent(name: string): string {
  if (name.startsWith('buyer') || name.startsWith('seller')) return 'marketplace';
  if (name.startsWith('auctioneer') || name.startsWith('bidder')) return 'auction';
  if (name.startsWith('proposer') || name.startsWith('voter') || name.startsWith('coordinator'))
    return 'voting';
  if (
    name.startsWith('supplier') ||
    name.startsWith('manufacturer') ||
    name.startsWith('distributor') ||
    name.startsWith('retailer')
  )
    return 'supply_chain';
  return 'marketplace';
}

function scenarioLabel(scenario: string): string {
  const labels: Record<string, string> = {
    marketplace: 'Marketplace',
    auction: 'Auction',
    voting: 'Voting',
    supply_chain: 'Supply chain',
    consensus: 'Consensus',
    reputation: 'Reputation',
  };
  return labels[scenario] ?? scenario;
}

const protocolLayers = [
  { name: 'Transport', description: 'How messages travel between agents.' },
  { name: 'Communication', description: 'The shape and meaning of a message.' },
  { name: 'Identity', description: 'Proving an agent is who it says it is.' },
  { name: 'Registry', description: 'Finding and looking up other agents.' },
  { name: 'Auth', description: 'Who is allowed to do what.' },
  { name: 'Trust', description: 'Scores for how reliable an agent is.' },
  { name: 'Payments', description: 'Sending value from one agent to another.' },
  { name: 'Coordination', description: 'Making group decisions together.' },
  { name: 'Negotiation', description: 'Haggling and striking deals.' },
  { name: 'Memory', description: 'Shared notes that stick around.' },
  { name: 'Privacy', description: 'Keeping data secret and proving facts without revealing them.' },
  { name: 'Data Facts', description: 'Sharing and checking datasets.' },
];

function useAnimatedMessages(messages: AgentMessage[], intervalMs = 1800) {
  const [visible, setVisible] = useState<AgentMessage[]>(() =>
    messages.length > 0 ? [messages[0]] : [],
  );
  const indexRef = useRef(1);

  useEffect(() => {
    const id = setInterval(() => {
      setVisible((prev) => {
        const next = messages[indexRef.current % messages.length];
        indexRef.current += 1;
        const updated = [...prev, next];
        return updated.length > 8 ? updated.slice(-8) : updated;
      });
    }, intervalMs);
    return () => clearInterval(id);
  }, [messages, intervalMs]);

  return visible;
}

/* ================================================================== */
/*  Page                                                               */
/* ================================================================== */

export default function Home() {
  const chatMessages = useAnimatedMessages(liveAgentChat, 2000);
  const featuredExperiments = experiments.slice(0, 3);

  return (
    <div className="bg-cream-100">
      {/* ============================================================ */}
      {/*  HERO                                                          */}
      {/* ============================================================ */}
      <section className="relative paper-texture">
        <div className="relative mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-24 md:pt-28 md:pb-32">
          <div className="flex items-center gap-3 mb-10 animate-fade-in">
            <span className="inline-flex h-1.5 w-1.5 rounded-full bg-rust animate-pulse-dot" />
            <span className="eyebrow">Nanda Town &middot; by Project NANDA</span>
          </div>

          <div className="grid gap-16 lg:grid-cols-[1.45fr_1fr] lg:items-start">
            <h1 className="font-display animate-fade-in stagger-1 text-[clamp(2.6rem,6.2vw,5.2rem)] leading-[1.02] tracking-[-0.018em] text-ink-900">
              A place
              <br />
              where AI <span className="italic text-ink-700">agents</span>
              <br />
              learn to
              <br />
              work together.
            </h1>

            <div className="animate-fade-in stagger-2 lg:pt-6">
              <p className="text-[1.125rem] leading-[1.55] text-ink-500 max-w-md">
                Nanda Town is an open sandbox where AI agents talk, trade,
                vote, and team up &mdash; so you can see what works before
                any of it goes live.
              </p>

              <div className="mt-10 flex flex-wrap gap-3">
                <Link href="/experiments" className="btn-primary">
                  Try an experiment
                </Link>
                <Link href="/docs" className="btn-secondary">
                  Read the docs
                </Link>
              </div>

              <dl className="mt-12 grid grid-cols-3 gap-6 border-t border-cream-400/70 pt-6">
                <Stat label="Scenarios" value="6" />
                <Stat label="Layers" value="12" />
                <Stat label="License" value="Apache 2.0" />
              </dl>
            </div>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  NANDAHACK — event callout                                     */}
      {/* ============================================================ */}
      <section className="border-y border-rust/30 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-16 md:py-20">
          <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr] lg:items-start">
            <div>
              <div className="flex items-center gap-3">
                <span className="inline-flex h-1.5 w-1.5 rounded-full bg-rust animate-pulse-dot" />
                <span className="eyebrow text-rust">
                  NandaHack &middot; happening now
                </span>
              </div>
              <h2 className="font-display mt-6 text-[clamp(2.2rem,4.6vw,3.8rem)] leading-[1.03] tracking-[-0.015em] text-ink-900">
                A hackathon you can<br />
                join from <span className="italic text-ink-700">anywhere.</span>
              </h2>
              <p className="mt-6 max-w-xl text-[1.1rem] leading-[1.6] text-ink-500">
                {hackathonEvent.tagline}{' '}
                Teams build agentic AI apps in the
                Nanda Town sandbox &mdash; fully virtual, {hackathonEvent.virtualWindow},
                with an optional in-person finale at MIT Media Lab.
              </p>

              <div className="mt-8 flex flex-wrap gap-3">
                <Link href="/hackathon" className="btn-primary">
                  Hackathon details &amp; FAQs
                </Link>
                <a
                  href={hackathonEvent.officialUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-secondary"
                >
                  Official site
                </a>
              </div>

              <dl className="mt-10 grid grid-cols-1 sm:grid-cols-2 gap-6 border-t border-cream-400/70 pt-6 max-w-xl">
                <EventDate label="Submissions due" value="Fri, Jul 10" hint="12:00 PM ET" />
                <EventDate label="Summit & finale" value="Sat, Jul 11" hint="MIT Media Lab · optional" />
              </dl>
            </div>

            <div className="lg:pt-14">
              <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 mb-4">
                Quick answers
              </p>
              <HackathonFaq entries={hackathonFaqs.slice(0, 3)} />
              <Link
                href="/hackathon#faq"
                className="mt-5 inline-flex items-center text-[0.9rem] font-medium text-ink-500 hover:text-ink-900 transition-colors"
              >
                All FAQs &rarr;
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  HERO VISUAL — live map                                        */}
      {/* ============================================================ */}
      <section className="relative">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-24">
          <div className="grid gap-8 lg:grid-cols-[1.4fr_1fr]">
            <Link
              href="/agents"
              className="block group animate-slide-up"
              aria-label="Open the live agent map"
            >
              <MiniMap width={780} height={440} />
              <div className="mt-4 flex items-center justify-between px-1">
                <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
                  Live agent network
                </span>
                <span className="text-[0.85rem] text-ink-400 group-hover:text-ink-900 transition-colors">
                  Open map &rarr;
                </span>
              </div>
            </Link>

            <div className="animate-slide-up stagger-2 rounded-2xl border border-cream-400/70 bg-cream-200 overflow-hidden self-start">
              <div className="flex items-center justify-between border-b border-cream-400/70 px-5 py-3">
                <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
                  Live agent feed
                </span>
                <span className="inline-flex items-center gap-2 font-mono text-[10px] text-ink-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-rust animate-pulse-dot" />
                  Streaming
                </span>
              </div>
              <div className="px-5 py-4 space-y-2 font-mono text-[12px] h-[392px] overflow-hidden">
                {chatMessages.slice(-9).map((msg, i) => {
                  const scenario = getScenarioFromAgent(msg.from);
                  const color = scenarioColors[scenario] ?? '#6B6557';
                  return (
                    <div key={`hero-${msg.tick}-${i}`} className="animate-fade-in flex items-start gap-3">
                      <span className="text-ink-300 shrink-0 w-10 text-right tabular-nums">
                        {String(msg.tick).padStart(2, '0')}
                      </span>
                      <span
                        className="shrink-0 rounded-sm px-1.5 py-0.5 text-[10px] font-semibold tracking-wide"
                        style={{
                          backgroundColor: color + '22',
                          color: color,
                        }}
                      >
                        {scenarioLabel(scenario).toLowerCase()}
                      </span>
                      <span className="text-ink-600 truncate">
                        {msg.from} &rarr; {msg.to}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  PRINCIPLES / WHY                                              */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-24 md:py-32">
          <div className="grid gap-14 lg:grid-cols-[1fr_1.4fr]">
            <div>
              <p className="eyebrow">The groundwork</p>
              <h2 className="font-display mt-5 text-[clamp(2rem,4vw,3.4rem)] leading-[1.05] tracking-[-0.015em] text-ink-900">
                Protocols, not<br />
                <span className="italic text-ink-700">products.</span>
              </h2>
            </div>
            <p className="text-[1.125rem] leading-[1.65] text-ink-500 max-w-xl lg:pt-3">
              The agent web isn&rsquo;t one app &mdash; it&rsquo;s a stack of
              shared rules agents follow to work together. Those rules need a
              tryout before millions of agents rely on them. Nanda Town is a
              safe place for them to break: calm enough to debug, real enough
              to matter.
            </p>
          </div>

          {/* Three pillars */}
          <div className="mt-20 grid gap-px bg-cream-400/60 border border-cream-400/60 rounded-2xl overflow-hidden">
            {[
              {
                num: '01',
                title: 'Define',
                body: 'Write a short YAML file or pick a ready-made template. Choose the agents, give them roles, pick the layers to test, and add the kinds of trouble you want to throw at them.',
              },
              {
                num: '02',
                title: 'Run',
                body: 'Nanda Town starts the agents and runs the whole thing. Tier 1 uses simple scripted agents; Tier 2 swaps in real AI models.',
              },
              {
                num: '03',
                title: 'Analyse',
                body: 'Read the logs, compare the numbers, and replay the map of who talked to whom. See exactly how the agents acted and where things went wrong.',
              },
            ].map((card) => (
              <div
                key={card.num}
                className="bg-cream-50 p-9 sm:p-12 flex flex-col gap-6 lg:gap-10"
              >
                <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
                  {card.num} &nbsp;/&nbsp; Step
                </span>
                <h3 className="font-display text-[2rem] leading-tight tracking-tight text-ink-900">
                  {card.title}
                </h3>
                <p className="text-[0.975rem] leading-[1.6] text-ink-500">
                  {card.body}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  IMAGERY BAND — abstract                                        */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-24">
          <div className="grid gap-10 lg:grid-cols-2">
            <ImagePlaceholder
              id="A"
              ratio="4/5"
              src="/illustrations/img_01_home_hero.png"
              alt="Abstract organic mesh of fine rust-orange lines and faint nodes drifting across a cream paper background — an ink-and-wash topographic map of an agent network."
              priority
              sizes="(min-width: 1024px) 50vw, 100vw"
              prompt="Abstract organic mesh of fine hand-drawn warm rust-orange lines flowing across a soft cream paper background. Sparse nodes where lines intersect, like a topographic map of an agent network. Editorial, calm, hand-illustrated feel. Subtle paper grain. Color palette: cream #F0EDE4, rust #C45A3C, warm black #141312. No text, no characters."
              caption="Hero — agent topology"
            />

            <div className="flex flex-col justify-between">
              <ImagePlaceholder
                id="B"
                ratio="5/4"
                src="/illustrations/img_02_protocol_stacks.png"
                alt="Layered translucent warm-orange and beige rectangles overlapping like protocol stacks on a cream paper background."
                sizes="(min-width: 1024px) 42vw, 100vw"
                prompt="Abstract composition of overlapping translucent warm orange and beige rectangles, layered like protocol stacks. Slight rotation, hand-cut paper aesthetic, subtle drop shadows. Each rectangle is a different shade of cream/rust. Quiet, editorial, scientific-but-warm. No text. Palette: #F0EDE4, #E8E4D6, #C45A3C, #6B6557."
                caption="Section — the twelve layers"
              />
              <div className="mt-10 max-w-md">
                <p className="font-display text-[1.45rem] leading-snug italic text-ink-700">
                  &ldquo;A protocol is a handshake written in code &mdash; and
                  a handshake is worth a trial run before you shake on it.&rdquo;
                </p>
                <p className="mt-3 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
                  Nanda Town design note &middot; 2026
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  THE 12 LAYERS                                                  */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.5fr] lg:items-end">
            <div>
              <p className="eyebrow">Architecture</p>
              <h2 className="font-display mt-5 text-[clamp(2rem,4vw,3.4rem)] leading-[1.05] tracking-tight text-ink-900">
                The twelve<br />
                <span className="italic text-ink-700">protocol layers.</span>
              </h2>
            </div>
            <p className="text-[1.05rem] leading-[1.65] text-ink-500 max-w-xl">
              Each layer is a part you can swap out, like Lego bricks. Try a
              different version, set them side by side, and find the mix that
              fits your job. The ones we ship are starting points &mdash; not
              the only way.
            </p>
          </div>

          <div className="mt-16 grid gap-px bg-cream-400/40 border border-cream-400/40 rounded-2xl overflow-hidden sm:grid-cols-2 lg:grid-cols-3">
            {protocolLayers.map((layer, i) => (
              <div
                key={layer.name}
                className="group bg-cream-50 p-7 transition-colors hover:bg-cream-200"
              >
                <div className="flex items-baseline justify-between">
                  <span className="font-mono text-[11px] tracking-[0.2em] text-ink-300">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span className="h-px w-12 bg-cream-400 group-hover:w-20 group-hover:bg-rust transition-all duration-300" />
                </div>
                <h3 className="mt-5 font-display text-[1.6rem] leading-tight text-ink-900">
                  {layer.name}
                </h3>
                <p className="mt-3 text-[0.92rem] leading-[1.55] text-ink-500">
                  {layer.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  FEATURED EXPERIMENTS                                          */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-24">
          <div className="flex items-end justify-between gap-6">
            <div>
              <p className="eyebrow">Recent experiments</p>
              <h2 className="font-display mt-5 text-[clamp(2rem,4vw,3.2rem)] leading-tight text-ink-900">
                What we&rsquo;ve been<br />
                <span className="italic text-ink-700">running.</span>
              </h2>
            </div>
            <Link
              href="/experiments"
              className="hidden sm:inline-flex items-center text-[0.9rem] font-medium text-ink-500 hover:text-ink-900 transition-colors"
            >
              View all experiments &rarr;
            </Link>
          </div>

          <div className="mt-14 grid gap-6 md:grid-cols-3">
            {featuredExperiments.map((exp) => {
              const color = scenarioColors[exp.scenario] ?? '#6B6557';
              return (
                <article
                  key={exp.id}
                  className="rounded-2xl bg-cream-200 p-7 flex flex-col gap-5 transition-colors hover:bg-cream-300"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] uppercase tracking-[0.22em]" style={{ color }}>
                      {scenarioLabel(exp.scenario)}
                    </span>
                    <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
                      {exp.agents} agents
                    </span>
                  </div>

                  <h3 className="font-display text-[1.7rem] leading-[1.1] text-ink-900">
                    {exp.name}
                  </h3>

                  <p className="text-[0.95rem] leading-[1.55] text-ink-500 line-clamp-3">
                    {exp.description}
                  </p>

                  <div className="mt-auto border-t border-cream-400/70 pt-5 flex items-center justify-between">
                    {exp.metrics ? (
                      <div className="flex gap-6">
                        <div>
                          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
                            Delivery
                          </p>
                          <p className="mt-1 font-display text-[1.4rem] leading-none text-ink-900">
                            {exp.metrics.deliveryRate}%
                          </p>
                        </div>
                        <div>
                          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
                            Latency
                          </p>
                          <p className="mt-1 font-display text-[1.4rem] leading-none text-ink-900">
                            {exp.metrics.meanLatency}t
                          </p>
                        </div>
                      </div>
                    ) : (
                      <span />
                    )}
                    <Link
                      href="/experiments"
                      className="text-[0.85rem] font-medium text-ink-700 hover:text-ink-900"
                    >
                      Open &rarr;
                    </Link>
                  </div>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  CTA                                                            */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70 bg-ink-900 text-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-24 md:py-32">
          <div className="grid gap-12 lg:grid-cols-[1.5fr_1fr] lg:items-end">
            <h2 className="font-display text-[clamp(2.3rem,5vw,4.4rem)] leading-[1.02] tracking-tight">
              Ready to test<br />
              <span className="italic text-cream-200">your protocol?</span>
            </h2>
            <div className="lg:pb-3">
              <p className="text-[1.05rem] leading-[1.6] text-cream-200">
                Set up a scenario, run it with real agents, and get clear
                numbers back in seconds. Free, open, and small enough to run
                on your laptop.
              </p>
              <div className="mt-8 flex flex-wrap gap-3">
                <Link
                  href="/docs"
                  className="inline-flex items-center rounded-md bg-cream-50 text-ink-900 px-5 py-2.5 text-[0.9rem] font-medium hover:bg-cream-200 transition-colors"
                >
                  Read the docs
                </Link>
                <Link
                  href="/experiments"
                  className="inline-flex items-center rounded-md border border-cream-200/30 px-5 py-2.5 text-[0.9rem] font-medium text-cream-100 hover:bg-ink-700 transition-colors"
                >
                  Browse experiments
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Stat                                                                */
/* ------------------------------------------------------------------ */

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
        {label}
      </dt>
      <dd className="mt-2 font-display text-[1.65rem] leading-none text-ink-900">
        {value}
      </dd>
    </div>
  );
}

function EventDate({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div>
      <dt className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
        {label}
      </dt>
      <dd className="mt-2">
        <span className="block font-display text-[1.45rem] leading-none text-ink-900">
          {value}
        </span>
        <span className="mt-1.5 block text-[0.82rem] text-ink-400">{hint}</span>
      </dd>
    </div>
  );
}
