import Image from "next/image";
import Link from "next/link";

export function Footer() {
  return (
    <footer className="border-t border-cream-400/70 bg-cream-100">
      <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-12">
        <div className="grid gap-12 lg:grid-cols-[1.5fr_1fr_1fr_1fr]">
          <div>
            <Link
              href="/"
              className="inline-flex items-center gap-3"
              aria-label="Nanda Town by Project NANDA — home"
            >
              <Image
                src="/brand/nandatown-logo.png"
                alt=""
                width={40}
                height={40}
                className="h-10 w-10 object-contain"
              />
              <span className="font-display text-2xl tracking-tight text-ink-900">
                Nanda Town
              </span>
            </Link>
            <p className="mt-5 max-w-xs text-[0.95rem] leading-relaxed text-ink-400">
              A sandbox where AI agents meet, talk, and work things out. An open project by Project NANDA.
            </p>
            <div className="mt-6 inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
              <Image
                src="/brand/nanda-logo.png"
                alt=""
                width={16}
                height={16}
                className="h-4 w-4 object-contain"
              />
              by Project NANDA
            </div>
            <p className="mt-8 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
              Apache 2.0 &middot; {new Date().getFullYear()}
            </p>
          </div>

          <FooterColumn title="Platform">
            <FooterLink href="/agents">Agents</FooterLink>
            <FooterLink href="/experiments">Experiments</FooterLink>
            <FooterLink href="/leaderboard">Leaderboard</FooterLink>
            <FooterLink href="/visualizer">Visualizer</FooterLink>
            <FooterLink href="/skills">Skills</FooterLink>
          </FooterColumn>

          <FooterColumn title="Resources">
            <FooterLink href="/docs">Documentation</FooterLink>
            <FooterLink href="https://github.com/projnanda/nandatown" external>
              GitHub
            </FooterLink>
            <FooterLink href="https://projectnanda.org" external>
              Project NANDA
            </FooterLink>
          </FooterColumn>

          <FooterColumn title="Community">
            <FooterLink
              href="https://github.com/projnanda/nandatown/issues"
              external
            >
              Report an issue
            </FooterLink>
          </FooterColumn>
        </div>

        <div className="mt-16 border-t border-cream-400/70 pt-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-[0.8rem] text-ink-300">
            &copy; {new Date().getFullYear()} Nanda Town · An open project by Project NANDA.
          </p>
          <p className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
            <Image
              src="/brand/nanda-logo.png"
              alt=""
              width={14}
              height={14}
              className="h-3.5 w-3.5 object-contain"
            />
            Nanda Town by Project NANDA
          </p>
        </div>
      </div>
    </footer>
  );
}

function FooterColumn({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
        {title}
      </h3>
      <ul className="mt-5 space-y-3">{children}</ul>
    </div>
  );
}

function FooterLink({
  href,
  external,
  children,
}: {
  href: string;
  external?: boolean;
  children: React.ReactNode;
}) {
  if (external) {
    return (
      <li>
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[0.95rem] text-ink-500 hover:text-ink-900 transition-colors"
        >
          {children}
        </a>
      </li>
    );
  }
  return (
    <li>
      <Link
        href={href}
        className="text-[0.95rem] text-ink-500 hover:text-ink-900 transition-colors"
      >
        {children}
      </Link>
    </li>
  );
}
