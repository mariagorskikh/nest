import Link from 'next/link';
import { loadDataset } from '@/lib/hackathon';

const REPO_URL = 'https://github.com/projnanda/nandatown';

const LAYERS = [
  'Transport',
  'Communication',
  'Identity',
  'Registry',
  'Auth',
  'Trust',
  'Payments',
  'Coordination',
  'Negotiation',
  'Memory',
  'Privacy',
  'Data facts',
];

function RepoButton({ dark = false }: { dark?: boolean }) {
  return (
    <a
      href={REPO_URL}
      target="_blank"
      rel="noreferrer"
      className={
        dark
          ? 'inline-flex items-center rounded-md bg-cream-50 text-ink-900 px-5 py-2.5 text-[0.9rem] font-medium hover:bg-cream-200 transition-colors'
          : 'btn-primary'
      }
    >
      github.com/projnanda/nandatown &rarr;
    </a>
  );
}

export default async function Home() {
  let prTotal: number | null = null;
  let prMerged: number | null = null;
  try {
    const data = await loadDataset();
    prTotal = data.stats.total_submissions;
    prMerged = data.stats.total_merged;
  } catch {
    // GitHub unreachable; hide the counters rather than guess.
  }

  return (
    <div className="bg-cream-100">
      {/* ============================================================ */}
      {/*  HERO                                                          */}
      {/* ============================================================ */}
      <section className="relative paper-texture">
        <div className="relative mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-20 md:pt-24 md:pb-24">
          <h1 className="font-display animate-fade-in max-w-[22ch] text-[clamp(2.2rem,5vw,4.2rem)] leading-[1.06] tracking-[-0.016em] text-ink-900">
            An open-source sandbox for{' '}
            <span className="italic text-ink-700">
              building and testing protocols
            </span>{' '}
            for AI agents.
          </h1>

          <div className="mt-10 grid gap-10 lg:grid-cols-[1.5fr_1fr] lg:items-start">
            <p className="animate-fade-in stagger-2 text-[1.12rem] leading-[1.65] text-ink-600">
              Nanda Town is an open project by Project NANDA. The protocol
              layers, reference plugins, scenarios, and tests all live in one
              public repository under the Apache 2.0 license.
            </p>

            <div className="animate-fade-in stagger-3 lg:pt-2">
              <RepoButton />
              <div className="mt-10 grid grid-cols-2 gap-6 border-t border-cream-400/70 pt-6">
                {prTotal !== null && (
                  <Stat label="Pull requests" value={String(prTotal)} href="/prgallery" />
                )}
                {prMerged !== null && (
                  <Stat label="Merged" value={String(prMerged)} href="/prgallery" />
                )}
                <Stat label="Protocol layers" value="12" />
                <Stat label="License" value="Apache 2.0" />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  THE TWELVE LAYERS                                             */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-20 md:py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr] lg:items-start">
            <div>
              <p className="eyebrow">The twelve protocol layers</p>
              <p className="mt-6 text-[1.05rem] leading-[1.7] text-ink-500 max-w-md">
                Agent-to-agent interaction is split into twelve protocol
                layers. Every contribution lands in one of them, or in Other
                if it fits none.
              </p>
              <div className="mt-7">
                <Link href="/prgallery/layers" className="btn-secondary">
                  Browse by layer &rarr;
                </Link>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-px bg-cream-400/50 border border-cream-400/50 rounded-2xl overflow-hidden self-start">
              {LAYERS.map((layer, i) => (
                <div key={layer} className="bg-cream-50 p-5">
                  <span className="font-mono text-[10px] tracking-[0.2em] text-ink-300">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <p className="mt-2 font-display text-[1.15rem] leading-tight text-ink-900">
                    {layer}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  HOW TO CONTRIBUTE                                             */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-20 md:py-24">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr] lg:items-start">
            <div>
              <p className="eyebrow">How to contribute</p>
              <h2 className="font-display mt-5 text-[clamp(1.9rem,3.6vw,3rem)] leading-[1.08] tracking-[-0.015em] text-ink-900">
                Open a <span className="italic text-ink-700">pull request</span>.
              </h2>
            </div>
            <div className="lg:pt-2">
              <p className="text-[1.05rem] leading-[1.7] text-ink-500">
                Contributions are ordinary pull requests to the repository. A
                pull request usually carries a protocol, which is the set of
                rules for one kind of interaction between agents, a plugin,
                which is the code that runs those rules inside one of the
                twelve layers, and a test that proves it holds up. Browse the
                merged pull requests to see the shape of a good one.
              </p>
              <div className="mt-8 flex flex-wrap gap-x-6 gap-y-2 text-[0.9rem] font-medium">
                <Link href="/prgallery" className="text-ink-700 hover:text-ink-900 transition-colors">
                  Browse merged PRs &rarr;
                </Link>
                <Link href="/docs" className="text-ink-700 hover:text-ink-900 transition-colors">
                  Writing a plugin &rarr;
                </Link>
                <a
                  href={`${REPO_URL}/blob/main/CONTRIBUTING.md`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-ink-700 hover:text-ink-900 transition-colors"
                >
                  CONTRIBUTING.md &rarr;
                </a>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/*  CTA                                                           */}
      {/* ============================================================ */}
      <section className="border-t border-cream-400/70 bg-ink-900 text-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-16 md:py-20 flex flex-wrap items-center justify-between gap-8">
          <p className="font-display text-[clamp(1.6rem,3vw,2.4rem)] leading-tight">
            github.com/projnanda/nandatown
          </p>
          <RepoButton dark />
        </div>
      </section>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Stat                                                                */
/* ------------------------------------------------------------------ */

function Stat({ label, value, href }: { label: string; value: string; href?: string }) {
  const inner = (
    <>
      <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
        {label}
      </p>
      <p className="mt-2 font-display text-[1.65rem] leading-none text-ink-900">
        {value}
      </p>
    </>
  );
  if (href) {
    return (
      <Link href={href} className="block transition-opacity hover:opacity-70">
        {inner}
      </Link>
    );
  }
  return <div>{inner}</div>;
}
