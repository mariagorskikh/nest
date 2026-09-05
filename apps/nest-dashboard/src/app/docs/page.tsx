import type { ReactNode } from "react";

const REPO = "https://github.com/projnanda/nandatown";

const sections = [
  ["overview", "What Town is"],
  ["installation", "Install and run"],
  ["modes", "Lab, Track, and Path"],
  ["evidence", "Evidence and reruns"],
  ["receipts", "Receipts and Proof"],
  ["adapters", "Bring an agent"],
  ["startups", "SkillMD catalog"],
  ["history", "History"],
] as const;

function Section({
  id,
  eyebrow,
  title,
  children,
}: {
  id: string;
  eyebrow: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-8 border-b border-cream-400/70 py-12 last:border-b-0">
      <p className="eyebrow">{eyebrow}</p>
      <h2 className="mt-4 font-display text-[clamp(1.9rem,4vw,2.8rem)] leading-tight tracking-tight text-ink-900">
        {title}
      </h2>
      <div className="mt-6 space-y-5 text-[1rem] leading-[1.7] text-ink-500">
        {children}
      </div>
    </section>
  );
}

function Command({ children }: { children: string }) {
  return (
    <pre className="overflow-x-auto rounded-xl border border-ink-700 bg-ink-900 p-5 text-[0.84rem] leading-relaxed text-cream-100">
      <code className="font-mono">{children}</code>
    </pre>
  );
}

function InlineCode({ children }: { children: ReactNode }) {
  return (
    <code className="rounded border border-cream-400/70 bg-cream-200 px-1.5 py-0.5 font-mono text-[0.86em] text-rust">
      {children}
    </code>
  );
}

function RepoLink({ path, children }: { path: string; children: ReactNode }) {
  return (
    <a
      href={`${REPO}/blob/main/${path}`}
      target="_blank"
      rel="noopener noreferrer"
      className="font-medium text-rust underline decoration-rust/30 underline-offset-4 hover:decoration-rust"
    >
      {children}
    </a>
  );
}

export default function DocsPage() {
  return (
    <div className="bg-cream-100">
      <header className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1120px] px-6 py-16 sm:px-10 md:py-20">
          <p className="eyebrow">Current manual</p>
          <h1 className="mt-5 max-w-[18ch] font-display text-[clamp(2.6rem,7vw,5.2rem)] leading-[1.02] tracking-tight text-ink-900">
            Reproducible evidence for an exact agent path.
          </h1>
          <p className="mt-8 max-w-3xl text-[1.1rem] leading-[1.7] text-ink-500">
            Nanda Town is a local-first integration lab. It runs a named workflow,
            records what happened at each stage, and leaves a bundle another
            operator can verify and inspect. A live rerun also needs the original
            agent setup and any inputs omitted from the bundle. The website documents and
            displays Town; the Python CLI performs the run.
          </p>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1120px] gap-12 px-6 py-10 sm:px-10 lg:grid-cols-[220px_minmax(0,1fr)]">
        <aside className="lg:sticky lg:top-8 lg:self-start">
          <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
            On this page
          </p>
          <nav className="mt-4" aria-label="Documentation sections">
            <ul className="space-y-1">
              {sections.map(([id, label]) => (
                <li key={id}>
                  <a
                    href={`#${id}`}
                    className="block rounded-md px-3 py-2 text-[0.9rem] text-ink-400 transition-colors hover:bg-cream-200 hover:text-ink-900"
                  >
                    {label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </aside>

        <main className="min-w-0">
          <Section id="overview" eyebrow="Scope" title="A lab, not an adoption claim">
            <p>
              Town exercises declared agent workflows and protocol simulations
              under three run modes. Each scenario or profile defines its own
              stages; missing evidence is not collapsed into success or failure.
            </p>
            <p>
              Town-authored fixtures, reference agents, local end-to-end runs, and
              CI establish that Town works against those fixtures. They do not show
              that an independently developed agent has adopted Town or that an
              outside operator found the result useful. That acceptance milestone
              still requires both.
            </p>
          </Section>

          <Section id="installation" eyebrow="Quick start" title="Install from the repository">
            <p>
              Nanda Town currently supports Python 3.11 and newer. Install the
              checked-out repository into an isolated environment, then ask the
              executable for the scenarios present in that checkout.
            </p>
            <Command>{`git clone https://github.com/projnanda/nandatown.git
cd nandatown
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
nandatown scenarios
nandatown run marketplace`}</Command>
            <p>
              Runs are written beneath <InlineCode>runs/</InlineCode> by default.
              Use <InlineCode>--out</InlineCode> to choose another evidence root and
              <InlineCode>--seed</InlineCode> to override a Lab scenario seed. The
              repository <RepoLink path="README.md">README</RepoLink> is the
              canonical command guide.
            </p>
          </Section>

          <Section id="modes" eyebrow="Execution" title="Lab, Track, and the exact Path">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-cream-400/70 bg-cream-50 p-5">
                <h3 className="font-display text-xl text-ink-900">Lab</h3>
                <p className="mt-2">
                  Deterministic, scripted local scenarios. Use it to reproduce
                  evaluator behavior and failure handling without claiming a live
                  external integration.
                </p>
                <p className="mt-3"><InlineCode>nandatown run marketplace</InlineCode></p>
              </div>
              <div className="rounded-xl border border-cream-400/70 bg-cream-50 p-5">
                <h3 className="font-display text-xl text-ink-900">Track</h3>
                <p className="mt-2">
                  Local HTTP coordination with subprocess or external
                  participants. Profiles state the harness and fault path being
                  exercised.
                </p>
                <p className="mt-3"><InlineCode>nandatown run quote-crash-restart</InlineCode></p>
              </div>
            </div>
            <p>
              Path testing narrows the claim to a versioned, observable route to
              one agent. For an already-running A2A endpoint, Town acts as the
              deterministic counterpart and observer:
            </p>
            <Command>{`nandatown test-agent --url http://127.0.0.1:9999`}</Command>
            <p>
              See <RepoLink path="docs/architecture.md">architecture</RepoLink> for
              the execution model and <RepoLink path="docs/operators.md">operator
              guidance</RepoLink> for exact run responsibilities.
            </p>
          </Section>

          <Section id="evidence" eyebrow="Artifacts" title="Five records, one manifest">
            <p>
              Each evidence bundle contains five canonical records:{" "}
              <InlineCode>profile.json</InlineCode>, <InlineCode>run.json</InlineCode>,{" "}
              <InlineCode>intents.jsonl</InlineCode>, <InlineCode>events.jsonl</InlineCode>,
              and <InlineCode>result.json</InlineCode>. <InlineCode>manifest.json</InlineCode>{" "}
              commits to those files. <InlineCode>report.md</InlineCode> is a human
              view, not an additional canonical record.
            </p>
            <p>
              Every evaluated stage is one of <InlineCode>passed</InlineCode>,{" "}
              <InlineCode>failed</InlineCode>, <InlineCode>not_enough_evidence</InlineCode>,{" "}
              <InlineCode>not_tested</InlineCode>, or <InlineCode>error</InlineCode>.
              The overall verdict is passed, failed, incomplete, or error.
            </p>
            <Command>{`nandatown verify runs/<run-id>
nandatown report runs/<run-id>
nandatown replay runs/<run-id>
nandatown visualize runs/<run-id>`}</Command>
            <p>
              Verification checks the bundle and independently reproduces its
              recorded evaluation with the matching evaluator version. Report and
              replay are read-only views; visualize writes an HTML view. Running
              the scenario or profile again creates a new bundle instead of
              rewriting the original evidence.
            </p>
          </Section>

          <Section id="receipts" eyebrow="Portable evidence" title="Partial evidence stays evidence">
            <p>
              A partial receipt can be signed and independently verified. Missing
              coverage remains explicit in the receipt; it is not converted to a
              pass. Generate and verify one with:
            </p>
            <Command>{`nandatown receipt runs/<run-id>
nandatown verify-receipt runs/<run-id>/receipt.json --bundle runs/<run-id>`}</Command>
            <p>
              Town Proof is deliberately stricter. Rendering a TOWN-TESTED badge
              requires a verified, fresh, passed result with every recorded stage
              covered; <InlineCode>coverage.not_tested</InlineCode> must be empty.
            </p>
            <Command>{`nandatown proof runs/<run-id>`}</Command>
            <p>
              A signature establishes commitment by a particular key. It does not
              establish independent observation, operational safety, authorization,
              ecosystem adoption, or endorsement.
            </p>
          </Section>

          <Section id="adapters" eyebrow="Integration boundary" title="Keep adapters thin">
            <p>
              HTTP is the canonical Track participant boundary. MCP can expose
              that surface as tools; its separate test command only probes
              initialization and tool listing. Path directly exercises a selected
              A2A workflow, not full protocol conformance. Pin the profile and
              agent role; preserve and resupply any command or endpoint omitted
              from rerun metadata so another operator can reproduce the same path.
            </p>
            <Command>{`nandatown test-agent --url https://agent.example/a2a --path-profile a2a-capability-fulfillment@0.3 --out runs`}</Command>
            <p>
              Remote-agent support is intentional. Treat a local command as trusted
              user code: Town coordinates it, but does not claim to sandbox hostile
              processes. Follow the canonical{" "}
              <RepoLink path="docs/testing-an-existing-agent.md">existing-agent guide</RepoLink>{" "}
              for the current default profile and acceptance procedure, and read{" "}
              <RepoLink path="docs/convergence.md">convergence</RepoLink> for what
              is current versus still proposed.
            </p>
          </Section>

          <Section id="startups" eyebrow="Discovery" title="The SkillMD catalog is only a catalog">
            <p>
              Registering a SkillMD only makes the catalog entry discoverable. It
              does not verify, install, authorize, endorse, or execute the submitted
              skill, agent, or service. For new URL and GitHub entries, the catalog
              stores the source link without fetching or hosting the linked content,
              agent, or service.
            </p>
            <p>
              Browse entries at{" "}
              <a href="/skills" className="font-medium text-rust underline underline-offset-4">/skills</a>{" "}
              or use <InlineCode>GET /api/skills</InlineCode>. New submissions have
              bounded request and field sizes; the listing endpoint preserves its
              complete-response compatibility. Production operators still need
              gateway-wide request/rate controls and database resource policy.
            </p>
          </Section>

          <Section id="history" eyebrow="Provenance" title="The earlier Town remains available">
            <p>
              The twelve-layer plugin gallery and bundled experiment traces are
              preserved as historical showcase material. They are useful provenance,
              but are not the current CLI, evidence schema, or external acceptance
              record.
            </p>
            <div className="flex flex-wrap gap-3">
              <a href={`${REPO}/tree/archive/legacy`} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                Legacy branch
              </a>
              <a href={`${REPO}/tree/v1-final`} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                Frozen v1-final tag
              </a>
              <a href="/prgallery" className="btn-secondary">
                Historical PR gallery
              </a>
            </div>
            <p>
              <InlineCode>nandatown import-pr &lt;number&gt;</InlineCode> can adapt a
              legacy contribution into a bounded local reference flow. It treats PR
              content as untrusted input and does not auto-install or execute the
              original plugin. A passing adapted run is not a pass for the original
              contribution.
            </p>
          </Section>
        </main>
      </div>
    </div>
  );
}
