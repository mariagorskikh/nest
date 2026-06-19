'use client';

import { useState, useEffect, useCallback } from 'react';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface TocItem {
  id: string;
  label: string;
}

const TOC: TocItem[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'tiers', label: 'Tier 1 vs Tier 2' },
  { id: 'installation', label: 'Installation' },
  { id: 'first-experiment', label: 'Your first experiment' },
  { id: 'scenarios', label: 'Scenario YAML reference' },
  { id: 'layers', label: 'The twelve layers' },
  { id: 'metrics', label: 'Metrics' },
  { id: 'templates', label: 'Agent templates' },
  { id: 'plugins', label: 'Writing a plugin' },
  { id: 'cli', label: 'CLI reference' },
  { id: 'troubleshooting', label: 'Troubleshooting' },
  { id: 'faq', label: 'FAQ' },
];

/* ------------------------------------------------------------------ */
/*  Code blocks                                                        */
/* ------------------------------------------------------------------ */

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="absolute top-3 right-3 rounded-md border border-ink-700 bg-ink-800 px-2.5 py-1 text-[10px] font-medium font-mono uppercase tracking-[0.18em] text-cream-200 transition-all hover:bg-ink-600 hover:text-cream-50"
      aria-label="Copy to clipboard"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

function CodeBlock({
  children,
  title,
}: {
  children: string;
  title?: string;
}) {
  return (
    <div className="group relative my-5 overflow-hidden rounded-xl border border-ink-700 bg-ink-900">
      {title && (
        <div className="border-b border-ink-700 bg-ink-800 px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.2em] text-cream-200">
          {title}
        </div>
      )}
      <CopyButton text={children} />
      <pre className="overflow-x-auto p-5 pr-24 text-[0.85rem] leading-relaxed text-cream-100">
        <code className="font-mono">{children}</code>
      </pre>
    </div>
  );
}

function TerminalBlock({ children }: { children: string }) {
  return (
    <div className="group relative my-5 overflow-hidden rounded-xl border border-ink-700 bg-ink-900">
      <div className="flex items-center gap-2 border-b border-ink-700 bg-ink-800 px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-ink-600" />
        <span className="h-2.5 w-2.5 rounded-full bg-ink-600" />
        <span className="h-2.5 w-2.5 rounded-full bg-ink-600" />
        <span className="ml-2 font-mono text-[10px] uppercase tracking-[0.2em] text-cream-200">
          Terminal
        </span>
      </div>
      <pre className="overflow-x-auto p-5 text-[0.85rem] leading-relaxed text-cream-100">
        <code className="font-mono">{children}</code>
      </pre>
    </div>
  );
}

function InlineCode({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded-md border border-cream-400/70 bg-cream-200 px-1.5 py-0.5 text-[0.85em] font-mono text-rust">
      {children}
    </code>
  );
}

/* ------------------------------------------------------------------ */
/*  Section wrapper                                                    */
/* ------------------------------------------------------------------ */

function Section({
  id,
  eyebrow,
  title,
  children,
}: {
  id: string;
  eyebrow?: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-20 py-10 first:pt-2">
      {eyebrow && (
        <p className="eyebrow mb-4">{eyebrow}</p>
      )}
      <h2 className="font-display text-[clamp(1.9rem,3vw,2.6rem)] leading-[1.1] tracking-tight text-ink-900 mb-8">
        {title}
      </h2>
      {children}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/*  Sidebar                                                            */
/* ------------------------------------------------------------------ */

function Sidebar({
  activeId,
  open,
  onClose,
}: {
  activeId: string;
  open: boolean;
  onClose: () => void;
}) {
  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-40 bg-ink-900/40 backdrop-blur-sm lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={`
          fixed top-16 left-0 z-50 h-[calc(100vh-4rem)] w-72 transform border-r border-cream-400/70
          bg-cream-100/95 backdrop-blur-md transition-transform duration-300 ease-in-out
          lg:z-10 lg:translate-x-0 lg:bg-transparent
          ${open ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        <nav className="h-full overflow-y-auto px-7 py-10">
          <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 mb-6">
            Documentation
          </p>
          <ul className="space-y-0.5">
            {TOC.map((item) => {
              const isActive = activeId === item.id;
              return (
                <li key={item.id}>
                  <a
                    href={`#${item.id}`}
                    onClick={onClose}
                    className={`
                      flex items-center py-2 text-[0.92rem] transition-all
                      ${
                        isActive
                          ? 'text-ink-900 font-medium'
                          : 'text-ink-400 hover:text-ink-900'
                      }
                    `}
                  >
                    <span
                      className={`mr-3 h-px transition-all ${
                        isActive ? 'w-6 bg-rust' : 'w-3 bg-cream-400'
                      }`}
                    />
                    {item.label}
                  </a>
                </li>
              );
            })}
          </ul>

          <div className="mt-12 rounded-2xl border border-cream-400/70 bg-cream-200 p-5">
            <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
              Need help?
            </p>
            <p className="mt-3 text-[0.88rem] leading-relaxed text-ink-500">
              Open an issue on{' '}
              <a
                href="https://github.com/projnanda/nandatown/issues"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-rust hover:text-ink-900 transition-colors"
              >
                GitHub
              </a>
              , or read the source on the same repo.
            </p>
          </div>
        </nav>
      </aside>
    </>
  );
}

/* ------------------------------------------------------------------ */
/*  FAQ item                                                           */
/* ------------------------------------------------------------------ */

function FaqItem({
  question,
  answer,
}: {
  question: string;
  answer: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border-b border-cream-400/70 last:border-b-0">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between py-6 text-left transition-colors hover:text-rust"
      >
        <span className="font-display text-[1.3rem] leading-tight text-ink-900 pr-8">
          {question}
        </span>
        <span
          className="shrink-0 font-mono text-[0.95rem] text-ink-400 transition-transform"
          style={{ transform: open ? 'rotate(45deg)' : 'none' }}
        >
          +
        </span>
      </button>
      {open && (
        <div className="pb-6 text-[0.98rem] leading-[1.65] text-ink-500">
          {answer}
        </div>
      )}
    </div>
  );
}

function TroubleshootItem({
  title,
  cause,
  fix,
}: {
  title: string;
  cause: React.ReactNode;
  fix: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-6">
      <p className="font-mono text-[0.85rem] text-rust leading-snug mb-4">
        {title}
      </p>
      <p className="text-[0.92rem] leading-[1.65] text-ink-500">
        <strong className="text-ink-900">What it means: </strong>
        {cause}
      </p>
      <p className="mt-3 text-[0.92rem] leading-[1.65] text-ink-500">
        <strong className="text-ink-900">Fix: </strong>
        {fix}
      </p>
    </div>
  );
}

/* ================================================================== */
/*  Page                                                               */
/* ================================================================== */

export default function DocsPage() {
  const [activeId, setActiveId] = useState('overview');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    const ids = TOC.map((t) => t.id);
    const elements = ids
      .map((id) => document.getElementById(id))
      .filter(Boolean) as HTMLElement[];

    if (elements.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => {
            const aIdx = ids.indexOf(a.target.id);
            const bIdx = ids.indexOf(b.target.id);
            return aIdx - bIdx;
          });
        if (visible.length > 0) setActiveId(visible[0].target.id);
      },
      { rootMargin: '-80px 0px -60% 0px', threshold: 0 },
    );
    elements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  return (
    <div className="relative min-h-screen bg-cream-100">
      {/* Mobile menu button */}
      <button
        onClick={() => setSidebarOpen(true)}
        className="fixed bottom-6 left-6 z-50 flex items-center gap-2 rounded-full border border-cream-400/70 bg-cream-50 px-4 py-2.5 text-[0.85rem] font-medium text-ink-900 shadow-lg transition-all hover:bg-cream-200 lg:hidden"
        aria-label="Open navigation"
      >
        Contents
      </button>

      <Sidebar
        activeId={activeId}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      {/* Main content */}
      <div className="lg:ml-72">
        <div className="mx-auto max-w-3xl px-6 pb-24 pt-10 lg:px-12">
          {/* Overview */}
          <Section id="overview" title="Overview">
            <p className="mb-5 text-[1.05rem] leading-[1.7] text-ink-500">
              Nanda Town is a sandbox for testing how AI agents talk to each
              other. Think of it like a flight simulator, but for agents. You
              write a scenario in a YAML file &mdash; who the agents are, what
              roles they play, which rules they follow, and what can go wrong.
              Nanda Town runs it and saves every message to a JSONL file you
              can read back or replay later.
            </p>
            <p className="mb-5 text-[1.05rem] leading-[1.7] text-ink-500">
              Nanda Town is an open initiative by Project NANDA. It is
              free, open-source research software (Apache 2.0).
            </p>

            <div className="mb-8 rounded-2xl border border-rust/30 bg-rust/5 p-5">
              <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust mb-2">
                How Nanda Town runs
              </p>
              <p className="text-[0.95rem] leading-[1.65] text-ink-600">
                Nanda Town is a <strong className="text-ink-900">Python tool you install on your own computer</strong>. It runs on your machine and saves a JSONL file to disk. This website
                only shows the docs, some ready-made example runs in the
                Visualizer, and the Experiments gallery. It does
                not run scenarios in your browser. Follow the{' '}
                <a href="#installation" className="text-rust hover:text-rust/80 underline underline-offset-2">
                  Installation
                </a>{' '}
                steps below to get the <InlineCode>nest</InlineCode> command.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              {[
                { title: 'Researchers', desc: 'Watch how agents behave, where they get stuck or disagree, and how trust builds up. You can see everything that happens.' },
                { title: 'Protocol designers', desc: 'Test your agent rules hard. Turn on failures on purpose, and replay any run to get the same result every time.' },
                { title: 'Developers', desc: 'Build and fix multi-agent systems using JSONL files, metrics, and HTML reports.' },
                { title: 'Students', desc: 'Learn by doing: how agents work together, simple game theory, and how agents interact.' },
              ].map((card) => (
                <div key={card.title} className="rounded-xl bg-cream-200 p-6">
                  <p className="font-display text-[1.25rem] text-ink-900 leading-tight">
                    {card.title}
                  </p>
                  <p className="mt-2 text-[0.92rem] leading-[1.6] text-ink-500">
                    {card.desc}
                  </p>
                </div>
              ))}
            </div>
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Tiers */}
          <Section id="tiers" title="Tier 1 vs Tier 2">
            <p className="mb-8 text-[1.05rem] leading-[1.7] text-ink-500">
              Nanda Town has two ways to run. Both use the same scenario file,
              the same twelve layers, and the same trace file. The only
              difference is how the agents make their choices.
            </p>

            <div className="grid gap-5 md:grid-cols-2">
              {/* Tier 1 */}
              <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-7">
                <div className="flex items-center justify-between">
                  <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
                    Tier 01
                  </p>
                  <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
                    Same every time
                  </span>
                </div>
                <h3 className="mt-4 font-display text-[1.7rem] leading-tight text-ink-900">
                  Scripted agents.
                </h3>
                <p className="mt-3 text-[0.95rem] leading-[1.6] text-ink-500">
                  Agents follow fixed rules you set in advance. Use the same
                  seed number and you get the exact same run, every time.
                </p>
                <ul className="mt-6 space-y-2.5 text-[0.92rem] text-ink-500">
                  {[
                    ['Repeatable.', 'Same seed gives the exact same result, every time.'],
                    ['Fast.', '10,000+ agents on a laptop, runs in under a second.'],
                    ['Free.', 'No API keys, no internet, no cost per run.'],
                    ['Tests the rules, not the AI.', 'If something breaks, you know it is the rules, not the AI model.'],
                  ].map(([head, body]) => (
                    <li key={head} className="flex gap-2.5">
                      <span className="text-rust shrink-0 mt-1 leading-none">·</span>
                      <span>
                        <strong className="text-ink-900 font-medium">{head}</strong>{' '}
                        {body}
                      </span>
                    </li>
                  ))}
                  <li className="flex gap-2.5">
                    <span className="text-ink-300 shrink-0 mt-1 leading-none">·</span>
                    <span>Agents only follow the rules you set. They can not think or adapt.</span>
                  </li>
                </ul>

                <div className="mt-7 border-t border-cream-400/70 pt-5">
                  <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
                    Use Tier 1 to
                  </p>
                  <ul className="mt-3 space-y-1.5 text-[0.88rem] text-ink-500">
                    <li>— Check that your rules work before adding AI models</li>
                    <li>— Run big simulations (1000+ agents) fast</li>
                    <li>— Reproduce a bug the same way every time</li>
                    <li>— Try things going wrong on purpose (dropped messages, split networks)</li>
                  </ul>
                </div>
              </div>

              {/* Tier 2 */}
              <div className="rounded-2xl border border-rust/30 bg-rust-bg/40 p-7">
                <div className="flex items-center justify-between">
                  <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
                    Tier 02
                  </p>
                  <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
                    LLM-backed
                  </span>
                </div>
                <h3 className="mt-4 font-display text-[1.7rem] leading-tight text-ink-900">
                  Real AI agents.
                </h3>
                <p className="mt-3 text-[0.95rem] leading-[1.6] text-ink-500">
                  Agents are run by real AI models like GPT-4, Claude, or any
                  OpenAI-compatible service. Each agent gets the scenario
                  details as a prompt and chooses what to do on every turn.
                </p>
                <ul className="mt-6 space-y-2.5 text-[0.92rem] text-ink-500">
                  {[
                    ['Realistic.', 'Agents decide like real AI systems do.'],
                    ['Can surprise you.', 'Agents may do things you did not plan for.'],
                    ['Custom prompts.', 'YAML templates set each agent’s personality.'],
                  ].map(([head, body]) => (
                    <li key={head} className="flex gap-2.5">
                      <span className="text-rust shrink-0 mt-1 leading-none">·</span>
                      <span>
                        <strong className="text-ink-900 font-medium">{head}</strong>{' '}
                        {body}
                      </span>
                    </li>
                  ))}
                  {[
                    ['Not repeatable.', 'Each run can come out different.'],
                    ['Costs money.', 'Every agent turn is an API call.'],
                    ['Slow.', 'Held back by API speed and limits (10–100 agents).'],
                  ].map(([head, body]) => (
                    <li key={head} className="flex gap-2.5">
                      <span className="text-ink-300 shrink-0 mt-1 leading-none">·</span>
                      <span>
                        <strong className="text-ink-700 font-medium">{head}</strong>{' '}
                        {body}
                      </span>
                    </li>
                  ))}
                </ul>

                <div className="mt-7 border-t border-rust/30 pt-5">
                  <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
                    Use Tier 2 to
                  </p>
                  <ul className="mt-3 space-y-1.5 text-[0.88rem] text-ink-500">
                    <li>— See how AI models act when many agents work together</li>
                    <li>— Compare different models on the same scenario</li>
                    <li>— Watch how agents team up and plan ahead</li>
                    <li>— Check how well your prompts work for each agent role</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="mt-6 rounded-2xl bg-cream-200 p-6">
              <p className="text-[0.98rem] leading-[1.7] text-ink-500">
                <strong className="text-ink-900 font-medium">A good way to work.</strong> Start with Tier 1 to
                make sure your scenario and rules work. Then move to Tier 2 by
                changing <InlineCode>brain: state-machine</InlineCode> to{' '}
                <InlineCode>brain: llm</InlineCode> in your YAML. Nothing else
                changes &mdash; same layers, same metrics, same trace file.
              </p>
            </div>
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Installation */}
          <Section id="installation" title="Installation">
            <h3 className="text-[1.15rem] font-medium text-ink-900 mb-3">
              Prerequisites
            </h3>
            <p className="mb-3 text-[0.95rem] text-ink-500">
              Nanda Town needs <strong className="text-ink-900">Python 3.12 or newer</strong>. Check your version before you install:
            </p>
            <CodeBlock>python3 --version</CodeBlock>
            <p className="mt-3 mb-8 text-[0.92rem] text-ink-400">
              If you see <InlineCode>3.11</InlineCode> or older, install Python 3.12 first
              (<InlineCode>brew install python@3.12</InlineCode> on macOS,{' '}
              <InlineCode>sudo apt install python3.12</InlineCode> on Ubuntu, or use{' '}
              <InlineCode>pyenv</InlineCode>). Installing nest-core on an older Python will fail with a{' '}
              <InlineCode>requires-python</InlineCode> error.
            </p>

            <h3 className="text-[1.15rem] font-medium text-ink-900 mb-3">
              Quick install (from PyPI)
            </h3>
            <CodeBlock>
{`python3.12 -m venv .venv
source .venv/bin/activate
pip install "nest-core[plugins]"`}
            </CodeBlock>
            <p className="mt-3 mb-8 text-[0.95rem] text-ink-500">
              This installs the Nanda Town engine, the <InlineCode>nest</InlineCode>{' '}
              command, the plugins for all 12 layers, and the seven
              built-in scenarios. The venv keeps it separate from your other
              Python projects so nothing clashes.
            </p>
            <p className="mb-8 text-[0.92rem] text-ink-400">
              Prefer to skip the venv? Use{' '}
              <a
                href="https://pipx.pypa.io/latest/installation/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-rust hover:text-rust/80 underline underline-offset-2"
              >
                pipx
              </a>{' '}
              instead: <InlineCode>pipx install &quot;nest-core[plugins]&quot;</InlineCode>{' '}
              &mdash; this gives you the <InlineCode>nest</InlineCode> command everywhere without touching your system Python.
            </p>

            <h3 className="text-[1.15rem] font-medium text-ink-900 mb-3">
              Or: install from source (development)
            </h3>
            <p className="mb-3 text-[0.95rem] text-ink-500">
              To work on Nanda Town itself, clone the repo and use{' '}
              <a
                href="https://docs.astral.sh/uv/getting-started/installation/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-rust hover:text-rust/80 underline underline-offset-2"
              >
                uv
              </a>{' '}
              for the workspace install:
            </p>
            <CodeBlock>
{`git clone https://github.com/projnanda/nandatown.git
cd nandatown
uv sync
uv run nest doctor`}
            </CodeBlock>
            <p className="mt-3 text-[0.92rem] text-ink-400">
              With uv, every command becomes <InlineCode>uv run nest …</InlineCode> &mdash;
              no manual venv activation needed.
            </p>

            <h3 className="mt-8 text-[1.15rem] font-medium text-ink-900 mb-3">
              Verify your installation
            </h3>
            <CodeBlock>nest doctor</CodeBlock>

            <TerminalBlock>
{`$ nest doctor
Nanda Town doctor
========================================
  [OK] Python 3.12.9
  [OK] nest-core
  [OK] scenario loader
  [OK] plugin registry
  [OK] scenario runner
  [OK] simulator
  [OK] all 12 default plugins resolve
========================================
7/7 checks passed`}
            </TerminalBlock>
            <p className="mt-3 text-[0.92rem] text-ink-400">
              If you get <InlineCode>command not found: nest</InlineCode>, the venv
              isn&apos;t active or your shell&apos;s PATH doesn&apos;t include the
              install location. See{' '}
              <a href="#troubleshooting" className="text-rust hover:text-rust/80 underline underline-offset-2">
                Troubleshooting
              </a>.
            </p>

            <h3 className="mt-8 text-[1.15rem] font-medium text-ink-900 mb-3">
              For Tier 2 (LLM agents)
            </h3>
            <p className="mb-3 text-[0.95rem] text-ink-500">
              If you want to run LLM-backed agents, set your API key:
            </p>
            <CodeBlock>
{`# OpenAI
export OPENAI_API_KEY="sk-..."

# or Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."`}
            </CodeBlock>
            <p className="mt-3 text-[0.92rem] text-ink-400">
              Tier 1 scenarios (like <InlineCode>marketplace</InlineCode>) run
              entirely offline and never call an API.
            </p>
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* First experiment */}
          <Section id="first-experiment" title="Your first experiment">
            <p className="mb-5 text-[1.05rem] leading-[1.7] text-ink-500">
              Run a full marketplace simulation in three steps. Fifty buyers and
              fifty sellers haggle over prices across ten rounds.
            </p>

            <div className="mb-8 rounded-xl border border-cream-400/70 bg-cream-200/60 p-5 text-[0.92rem] leading-[1.6] text-ink-600">
              <p>
                <strong className="text-ink-900">Before you start:</strong> open a terminal,{' '}
                <InlineCode>cd</InlineCode> into the directory where you want
                output to land, and make sure your venv is active (or prefix
                each command with <InlineCode>uv run</InlineCode> if you installed
                from source). The simulator writes its trace to a{' '}
                <InlineCode>traces/</InlineCode> folder relative to your current
                working directory.
              </p>
            </div>

            {[
              {
                step: '01',
                title: 'Run the scenario',
                code: 'nest run marketplace',
                note: (
                  <>
                    This creates the agents, runs the simulation, and writes
                    the trace to <InlineCode>traces/marketplace.jsonl</InlineCode>.
                  </>
                ),
              },
              {
                step: '02',
                title: 'Inspect the trace',
                code: 'nest inspect traces/marketplace.jsonl',
                note: 'Shows a summary of every event: sends, receives, drops, per-agent stats, and timing.',
              },
              {
                step: '03',
                title: 'Generate an HTML report',
                code: 'nest report traces/marketplace.jsonl -o report.html',
                note: 'Produces an HTML page with delivery rate, deal rate, latency, throughput, per-agent breakdown, and event summary.',
              },
            ].map((step) => (
              <div key={step.step} className="mb-10">
                <div className="flex items-baseline gap-4">
                  <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust">
                    {step.step}
                  </span>
                  <h3 className="font-display text-[1.5rem] leading-tight text-ink-900">
                    {step.title}
                  </h3>
                </div>
                <CodeBlock>{step.code}</CodeBlock>
                <p className="mt-2 text-[0.9rem] text-ink-400">{step.note}</p>
              </div>
            ))}
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Scenarios */}
          <Section id="scenarios" title="Scenario YAML reference">
            <p className="mb-6 text-[1.05rem] leading-[1.7] text-ink-500">
              A scenario YAML file sets up everything about a run. Here is a
              full example with notes on each part. It matches the real format.
            </p>

            <CodeBlock title="scenarios/marketplace.yaml">
{`name: marketplace
description: "50 buyers and 50 sellers trading products."

tier: 1                           # 1 = scripted, 2 = AI model
seed: 42                          # seed number (same run every time)

agents:
  count: 100                      # how many agents in total
  brain: state-machine            # "state-machine" or "llm"
  # llm_provider: openai          # For Tier 2: openai or anthropic
  # llm_model: gpt-4o-mini        # For Tier 2: model name
  roles:
    - name: buyer
      count: 50
    - name: seller
      count: 50

layers:                           # which plugin to use for each layer
  transport: in_memory
  comms: nest_native
  identity: did_key
  registry: in_memory
  auth: jwt
  trust: score_average
  payments: prepaid_credits
  coordination: contract_net
  negotiation: alternating_offers
  memory: blackboard
  privacy: noop
  datafacts: datafacts_v1

task:
  type: marketplace               # which scenario to run
  config:
    rounds: 10                    # settings for this scenario

failures:                         # things that can go wrong
  message_drop: 0.0              # 0.0 = no drops, 0.1 = drop 1 in 10
  byzantine_agents: 0.0          # share of agents that send junk messages
  # network_partition:            # split agents into groups that can't reach each other
  #   groups: [["buyer-0"], ["seller-0"]]

duration: "ticks: 10000"          # most ticks the run can take

metrics:                          # which numbers to measure
  - delivery_rate
  - deal_rate
  - mean_latency
  - message_count
  - agent_count

output:
  trace: ./traces/marketplace.jsonl
  # report: ./reports/marketplace.html  # Optional HTML report`}
            </CodeBlock>

            <h3 className="mt-10 mb-4 text-[1.15rem] font-medium text-ink-900">
              Available scenarios
            </h3>
            <RefTable
              head={['File', 'Description', 'Agents']}
              rows={[
                ['marketplace.yaml', 'Buyers and sellers negotiate prices', '50 buyers + 50 sellers'],
                ['auction.yaml', 'Sealed-bid auction with auctioneer', '1 auctioneer + 49 bidders'],
                ['voting.yaml', 'Proposer, voters, and coordinator', '1 proposer + 20 voters + 1 coordinator'],
                ['consensus.yaml', 'Leader-based quorum voting', '1 leader + 19 followers'],
                ['supply_chain.yaml', '4-hop supply chain pipeline', 'supplier, manufacturer, distributor, retailer'],
                ['reputation.yaml', 'Honest and malicious traders with observer', '6 honest + 2 malicious + 1 observer'],
              ]}
              monoFirstCol
            />
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Layers */}
          <Section id="layers" title="The twelve layers">
            <p className="mb-6 text-[1.05rem] leading-[1.7] text-ink-500">
              Nanda Town splits what an agent can do into twelve layers. Think
              of them like floors in a building, each handling one job. Every
              layer comes with a default version you can swap for your own.
              Agents reach a layer with{' '}
              <InlineCode>ctx.plugins.get(&quot;layer_name&quot;)</InlineCode>.
            </p>

            <RefTable
              head={['Layer', 'What it does', 'Default']}
              rows={[
                ['Transport', 'Carries messages between agents', 'in_memory'],
                ['Comms', 'Sets the shape of each message', 'nest_native'],
                ['Identity', 'Gives each agent an ID and checks it', 'did_key'],
                ['Registry', 'Helps agents find each other', 'in_memory'],
                ['Auth', 'Handles logins and permissions', 'jwt'],
                ['Trust', 'Tracks how much agents trust each other', 'score_average'],
                ['Payments', 'Holds play-money balances and transfers', 'prepaid_credits'],
                ['Coordination', 'Helps agents divide up the work', 'contract_net'],
                ['Negotiation', 'Runs the back-and-forth of making deals', 'alternating_offers'],
                ['Memory', 'Saves and looks up what agents remember', 'blackboard'],
                ['Privacy', 'Sets limits on what data can be shared', 'noop'],
                ['Data Facts', 'Checks and vouches for data claims', 'datafacts_v1'],
              ]}
              monoLastCol
            />

            <p className="mt-5 text-[0.9rem] leading-[1.6] text-ink-400">
              Right now, the marketplace scenario uses the registry, identity,
              trust, and payments layers. Other scenarios load the layers but do
              not call them yet. Connecting more scenarios to the layers is still
              in progress.
            </p>
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Metrics */}
          <Section id="metrics" title="Metrics">
            <p className="mb-6 text-[1.05rem] leading-[1.7] text-ink-500">
              After each run, Nanda Town reads the JSONL file and works out the
              numbers. Pick which ones you want in the scenario YAML. There is no
              single overall score &mdash; each number tells you one thing.
            </p>

            <RefTable
              head={['Metric', 'What it measures']}
              rows={[
                ['delivery_rate', 'Fraction of sent messages that were received. 100% in Tier 1 with no message drops.'],
                ['deal_rate', 'Percentage of buy requests that resulted in a trade. Marketplace and auction only.'],
                ['rejection_rate', 'Percentage of buy requests that were rejected. Marketplace only.'],
                ['mean_rounds_to_deal', 'Average negotiation rounds before a successful trade.'],
                ['mean_latency', 'Average time (ticks) between a send and its correlated receive.'],
                ['message_count', 'Total number of send + receive events in the trace.'],
                ['dropped_count', 'Number of messages dropped by failure injection.'],
                ['agent_count', 'Number of distinct agents that participated.'],
                ['duration', 'Time span from first to last event (ticks).'],
                ['throughput', 'Messages per tick across all agents.'],
                ['unique_pairs', 'Number of unique agent pairs that exchanged messages.'],
              ]}
              monoFirstCol
            />
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Templates */}
          <Section id="templates" title="Agent templates (Tier 2)">
            <p className="mb-6 text-[1.05rem] leading-[1.7] text-ink-500">
              Templates are YAML files that set how an AI agent acts: its prompt,
              which provider and model to use, and a few settings. They only
              apply to Tier 2 scenarios.
            </p>

            <CodeBlock title="templates/agents/marketplace-buyer.yaml">
{`name: marketplace-buyer
description: "Buyer agent for marketplace scenarios."
provider: openai
model: gpt-4o-mini
temperature: 0.7
max_tokens: 256
system_prompt: |
  You are a buyer in a marketplace simulation.

  ACTION: send
  TO: <agent-id>
  MESSAGE: <message-content>

  Rules:
  - Send buy:<product>:<price> to purchase.
  - If rejected, increase your offer or try another seller.`}
            </CodeBlock>

            <h3 className="mt-8 mb-3 text-[1.15rem] font-medium text-ink-900">
              CLI commands
            </h3>
            <CodeBlock>
{`nest templates list              # List all templates
nest templates show <name>       # View a template
nest templates create <name>     # Create from scratch
nest templates duplicate <src> <dest>  # Copy and modify`}
            </CodeBlock>
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Plugins */}
          <Section id="plugins" title="Writing a plugin">
            <p className="mb-6 text-[1.05rem] leading-[1.7] text-ink-500">
              You can swap any of the twelve layers for your own version. A
              plugin is a Python class that has the methods the layer expects.
              You hook it in with Python entry points.
            </p>

            <h3 className="mb-3 text-[1.15rem] font-medium text-ink-900">
              Example: custom trust plugin
            </h3>
            <p className="mb-3 text-[0.95rem] text-ink-500">
              Look at the built-in versions in{' '}
              <InlineCode>packages/nest-plugins-reference/</InlineCode> to see
              what each layer expects. Here is a trust plugin:
            </p>
            <CodeBlock title="my_trust/plugin.py">
{`from nest_core.types import AgentId, Evidence, ReputationScore

class DecayTrust:
    """Custom trust layer with time decay."""

    def __init__(self, identity=None):
        self._scores: dict[AgentId, list[float]] = {}

    async def score(self, agent: AgentId) -> ReputationScore:
        entries = self._scores.get(agent, [])
        if not entries:
            return ReputationScore(
                agent_id=agent, score=0.5,
                confidence=0.0, sample_count=0,
            )
        avg = sum(entries) / len(entries)
        return ReputationScore(
            agent_id=agent, score=avg,
            confidence=min(1.0, len(entries) / 50),
            sample_count=len(entries),
        )

    async def report(self, agent: AgentId, evidence: Evidence):
        val = 1.0 if evidence.kind == "positive" else 0.0
        self._scores.setdefault(agent, []).append(val)`}
            </CodeBlock>

            <h3 className="mt-8 mb-3 text-[1.15rem] font-medium text-ink-900">
              Register via entry point
            </h3>
            <CodeBlock title="pyproject.toml">
{`[project]
name = "my-trust-plugin"
version = "0.1.0"
dependencies = ["nest-core"]

[project.entry-points."nest.plugins.trust"]
my_decay = "my_trust.plugin:DecayTrust"`}
            </CodeBlock>

            <p className="mt-4 text-[0.95rem] text-ink-500">
              Then reference it in your scenario YAML:
            </p>
            <CodeBlock>
{`layers:
  trust: my_decay  # Uses your custom plugin`}
            </CodeBlock>
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* CLI */}
          <Section id="cli" title="CLI reference">
            <p className="mb-6 text-[1.05rem] leading-[1.7] text-ink-500">
              Once you install with{' '}
              <InlineCode>pip install &quot;nest-core[plugins]&quot;</InlineCode>,
              you get all these commands through the <InlineCode>nest</InlineCode> command.
            </p>

            <RefTable
              head={['Command', 'Description']}
              rows={[
                ['nest run <name | path.yaml>', 'Run a built-in scenario by name, or your own YAML file, and save the trace'],
                ['nest scenarios list / show / cp', 'List, print, or copy the seven built-in scenarios'],
                ['nest inspect <trace.jsonl>', 'Print a summary of events and per-agent stats'],
                ['nest report <trace.jsonl>', 'Make an HTML report of the numbers'],
                ['nest init <name>', 'Start a new scenario YAML for you to fill in'],
                ['nest doctor', 'Check that your install and plugins are working'],
                ['nest version', 'Print the installed Nanda Town version'],
                ['nest dashboard [trace.jsonl]', 'Open the trace viewer in a browser'],
                ['nest plugins list', 'List all installed layer plugins'],
                ['nest templates list', 'List the agent templates you have'],
                ['nest templates show <name>', 'Show one template'],
                ['nest templates create <name>', 'Make a new agent template'],
                ['nest templates duplicate <src> <dest>', 'Copy a template'],
              ]}
              monoFirstCol
            />
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* Troubleshooting */}
          <Section id="troubleshooting" title="Troubleshooting">
            <p className="mb-6 text-[1.05rem] leading-[1.7] text-ink-500">
              Most install problems come down to four things: the wrong Python,
              no venv turned on, an out-of-date shell PATH, or running{' '}
              <InlineCode>nest</InlineCode> from the wrong folder. Find your
              problem in the list below.
            </p>

            <div className="space-y-5">
              <TroubleshootItem
                title="ERROR: Package 'nest-core' requires a different Python"
                cause={
                  <>
                    Your Python is older than 3.12. <InlineCode>pip</InlineCode> won&apos;t install because{' '}
                    <InlineCode>nest-core</InlineCode> needs{' '}
                    <InlineCode>requires-python &gt;=3.12</InlineCode>.
                  </>
                }
                fix={
                  <>
                    Install Python 3.12 (<InlineCode>brew install python@3.12</InlineCode>,{' '}
                    <InlineCode>sudo apt install python3.12</InlineCode>, or pyenv) and
                    create a venv with it explicitly:{' '}
                    <InlineCode>python3.12 -m venv .venv</InlineCode>, then{' '}
                    <InlineCode>source .venv/bin/activate</InlineCode> before pip-installing.
                  </>
                }
              />

              <TroubleshootItem
                title="zsh: command not found: nest"
                cause={
                  <>
                    Either your venv isn&apos;t turned on in this shell, or you
                    used <InlineCode>pip install --user</InlineCode> and{' '}
                    <InlineCode>~/.local/bin</InlineCode> isn&apos;t on your PATH.
                  </>
                }
                fix={
                  <>
                    Run <InlineCode>source .venv/bin/activate</InlineCode> in
                    the folder where you made the venv, then try again.
                    Or install with{' '}
                    <a
                      href="https://pipx.pypa.io/latest/installation/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-rust hover:text-rust/80 underline underline-offset-2"
                    >
                      pipx
                    </a>{' '}
                    (<InlineCode>pipx install &quot;nest-core[plugins]&quot;</InlineCode>) to
                    get a global <InlineCode>nest</InlineCode> binary.
                  </>
                }
              />

              <TroubleshootItem
                title="nest run marketplace: Scenario 'marketplace' not found"
                cause={
                  <>
                    You installed without the <InlineCode>[plugins]</InlineCode>{' '}
                    part, so the built-in scenarios are missing.
                  </>
                }
                fix={
                  <>
                    Install it again with the extra part:{' '}
                    <InlineCode>pip install &quot;nest-core[plugins]&quot;</InlineCode>{' '}
                    (the quotes matter on zsh &mdash; without them the shell
                    reads <InlineCode>[plugins]</InlineCode> as a file pattern). Then run{' '}
                    <InlineCode>nest scenarios list</InlineCode> to check
                    the seven built-in scenarios show up.
                  </>
                }
              />

              <TroubleshootItem
                title="Trace file isn't where I expected"
                cause={
                  <>
                    <InlineCode>nest run</InlineCode> saves to{' '}
                    <InlineCode>./traces/&lt;scenario&gt;.jsonl</InlineCode>{' '}
                    inside whatever folder you are in. If you ran it
                    from your home folder, that is where{' '}
                    <InlineCode>traces/</InlineCode> ended up.
                  </>
                }
                fix={
                  <>
                    <InlineCode>cd</InlineCode> into a project folder first,
                    or add <InlineCode>--out /path/to/trace.jsonl</InlineCode> to
                    choose where it goes. <InlineCode>nest run --help</InlineCode> shows
                    all the options.
                  </>
                }
              />

              <TroubleshootItem
                title="I can't find a 'Run' button on this website"
                cause={
                  <>
                    That is right &mdash; this website only shows ready-made JSONL
                    traces in the Visualizer and links to the docs. It does not
                    run the simulator. The simulator is the{' '}
                    <InlineCode>nest</InlineCode> command you installed above.
                  </>
                }
                fix={
                  <>
                    Run a scenario on your computer (<InlineCode>nest run marketplace</InlineCode>),
                    then drop the new{' '}
                    <InlineCode>traces/marketplace.jsonl</InlineCode> file into the{' '}
                    <a href="/visualizer" className="text-rust hover:text-rust/80 underline underline-offset-2">
                      Visualizer
                    </a>{' '}
                    to play it back.
                  </>
                }
              />
            </div>
          </Section>

          <div className="h-px bg-cream-400/70" />

          {/* FAQ */}
          <Section id="faq" title="FAQ">
            <div className="rounded-2xl border border-cream-400/70 bg-cream-50 px-7">
              <FaqItem
                question="Can I pip install this?"
                answer={
                  <p>
                    Yes &mdash; into a Python 3.12+ venv:{' '}
                    <InlineCode>pip install &quot;nest-core[plugins]&quot;</InlineCode>.
                    That installs the engine, the <InlineCode>nest</InlineCode>{' '}
                    CLI, and all twelve default plugins. See{' '}
                    <a href="#installation" className="text-rust hover:text-rust/80 underline underline-offset-2">
                      Installation
                    </a>{' '}
                    for the full walkthrough.
                  </p>
                }
              />
              <FaqItem
                question="Can I run scenarios in the browser?"
                answer={
                  <p>
                    Not on this website. It only shows ready-made JSONL traces
                    and links to the docs. The simulator itself is the{' '}
                    <InlineCode>nest</InlineCode> command on your computer. To play
                    your own runs, make a trace on your machine
                    (<InlineCode>nest run marketplace</InlineCode>) and load
                    it into the{' '}
                    <a href="/visualizer" className="text-rust hover:text-rust/80 underline underline-offset-2">
                      Visualizer
                    </a>.
                  </p>
                }
              />
              <FaqItem
                question="Do I need an API key?"
                answer={
                  <p>
                    Only for <strong className="text-ink-900">Tier 2</strong> (LLM-backed) scenarios. Set{' '}
                    <InlineCode>OPENAI_API_KEY</InlineCode> or{' '}
                    <InlineCode>ANTHROPIC_API_KEY</InlineCode>. Tier 1 runs
                    entirely locally with no API calls.
                  </p>
                }
              />
              <FaqItem
                question="How many agents can Nanda Town handle?"
                answer={
                  <p>
                    <strong className="text-ink-900">Tier 1:</strong> 10,000+ agents on a modern laptop,
                    each run under a second. <strong className="text-ink-900">Tier 2:</strong> 10&ndash;100
                    agents, held back by API limits and cost.
                  </p>
                }
              />
              <FaqItem
                question="Can I use my own LLM?"
                answer={
                  <p>
                    Yes. Set <InlineCode>llm_provider</InlineCode> and{' '}
                    <InlineCode>llm_model</InlineCode> in your scenario YAML.
                    Nanda Town works with OpenAI, Anthropic, and any
                    OpenAI-compatible service.
                  </p>
                }
              />
              <FaqItem
                question="Is Nanda Town ready for production?"
                answer={
                  <p>
                    No. Nanda Town is research software that is still being
                    built. It is great for trying things out and comparing
                    runs, but its APIs may change from one release to the next.
                  </p>
                }
              />
              <FaqItem
                question="What does Tier 1 actually test if agents are scripted?"
                answer={
                  <p>
                    Tier 1 tests the <em>rules</em>, not the agents. It asks:{' '}
                    <em>if every agent follows the rules exactly, do the rules
                    still hold up when messages get dropped, the network splits,
                    or some agents send junk?</em> It is the same idea as TLA+
                    model checking &mdash; prove the design works before you add
                    the messy real code on top.
                  </p>
                }
              />
            </div>
          </Section>

          {/* Footer CTA */}
          <div className="mt-12 rounded-2xl bg-ink-900 text-cream-50 p-10 sm:p-14 text-center">
            <h3 className="font-display text-[clamp(2rem,4vw,3rem)] leading-tight tracking-tight">
              Ready to start?
            </h3>
            <p className="mx-auto mt-4 max-w-md text-[1rem] leading-[1.65] text-cream-200">
              Clone the repo and run your first simulation in under two minutes.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <a
                href="#installation"
                className="inline-flex items-center justify-center rounded-md bg-cream-50 text-ink-900 px-6 py-2.5 text-[0.9rem] font-medium hover:bg-cream-200 transition-colors"
              >
                Get started
              </a>
              <a
                href="https://github.com/projnanda/nandatown"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center rounded-md border border-cream-200/30 px-6 py-2.5 text-[0.9rem] font-medium text-cream-100 hover:bg-ink-700 transition-colors"
              >
                View on GitHub
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Shared: reference table                                            */
/* ------------------------------------------------------------------ */

function RefTable({
  head,
  rows,
  monoFirstCol,
  monoLastCol,
}: {
  head: string[];
  rows: string[][];
  monoFirstCol?: boolean;
  monoLastCol?: boolean;
}) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-cream-400/70 bg-cream-50">
      <table className="w-full text-[0.92rem]">
        <thead>
          <tr className="border-b border-cream-400/70 bg-cream-200">
            {head.map((h) => (
              <th
                key={h}
                className="px-4 py-3.5 text-left font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-cream-400/40">
          {rows.map((row, i) => (
            <tr key={i} className="hover:bg-cream-200/60 transition-colors">
              {row.map((cell, j) => {
                const isFirst = j === 0;
                const isLast = j === row.length - 1;
                const isMono =
                  (monoFirstCol && isFirst) || (monoLastCol && isLast);
                return (
                  <td
                    key={j}
                    className={`px-4 py-3 ${
                      isMono
                        ? 'font-mono text-[0.82rem] text-rust whitespace-nowrap'
                        : isFirst
                          ? 'font-medium text-ink-900 whitespace-nowrap'
                          : 'text-ink-500'
                    }`}
                  >
                    {cell}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
