"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

type NavChild = { href: string; label: string };
type NavItem = {
  href: string;
  label: string;
  external?: boolean;
  children?: NavChild[];
};

const items: NavItem[] = [
  { href: "/agents", label: "Agents" },
  { href: "/prgallery", label: "PR Gallery" },
  { href: "/experiments", label: "Experiments" },
  { href: "/leaderboard", label: "Leaderboard" },
  {
    href: "https://nandahack.media.mit.edu",
    label: "NandaHack",
    external: true,
    children: [
      { href: "/skills", label: "Skills Registry (NandaHack)" },
    ],
  },
  { href: "/visualizer", label: "Visualizer" },
  { href: "/docs", label: "Docs" },
];

function NavList({
  pathname,
  onNavigate,
}: {
  pathname: string;
  onNavigate?: () => void;
}) {
  const linkCls = (active: boolean) =>
    `block rounded-md px-3 py-2 text-[0.92rem] font-medium transition-colors ${
      active ? "bg-cream-200 text-ink-900" : "text-ink-400 hover:bg-cream-200/60 hover:text-ink-900"
    }`;

  return (
    <ul className="space-y-0.5">
      {items.map((item) => {
        const active =
          !item.external &&
          (pathname === item.href || pathname.startsWith(item.href + "/"));
        return (
          <li key={item.label}>
            {item.external ? (
              <a href={item.href} className={linkCls(false)} onClick={onNavigate}>
                {item.label}
              </a>
            ) : (
              <Link href={item.href} className={linkCls(active)} onClick={onNavigate}>
                {item.label}
              </Link>
            )}
            {item.children && (
              <ul className="mt-0.5 mb-1.5 ml-4 space-y-0.5 border-l border-cream-400/60 pl-2">
                {item.children.map((child) => {
                  const childActive = pathname.startsWith(child.href);
                  const childCls = `block rounded-md px-3 py-1.5 text-[0.85rem] font-medium transition-colors ${
                    childActive ? "bg-cream-200 text-ink-900" : "text-ink-400 hover:bg-cream-200/60 hover:text-ink-900"
                  }`;
                  return (
                    <li key={child.href}>
                      {child.href.startsWith("http") ? (
                        <a
                          href={child.href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={childCls}
                          onClick={onNavigate}
                        >
                          {child.label}
                        </a>
                      ) : (
                        <Link href={child.href} className={childCls} onClick={onNavigate}>
                          {child.label}
                        </Link>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </li>
        );
      })}
    </ul>
  );
}

export function Navbar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (localStorage.getItem("nt-sidebar-collapsed") === "1") setCollapsed(true);
  }, []);

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  function toggle() {
    setCollapsed((c) => {
      localStorage.setItem("nt-sidebar-collapsed", c ? "0" : "1");
      return !c;
    });
  }

  const toggleBtnCls =
    "flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-cream-400/60 text-[15px] leading-none text-ink-400 transition-colors hover:bg-cream-200/60 hover:text-ink-900";

  return (
    <>
      {/* Slim top bar with menu button, mobile only */}
      <div className="sticky top-0 z-50 md:hidden">
        <div className="flex h-14 items-center justify-between border-b border-cream-400/60 bg-cream-100/85 px-5 backdrop-blur-xl">
          <Link href="/" className="flex items-center gap-2.5" aria-label="Nanda Town — home">
            <Image src="/brand/nandatown-logo.png" alt="" width={28} height={28} className="h-7 w-7 object-contain" />
            <span className="font-display text-[1.15rem] leading-none tracking-tight text-ink-900">Nanda Town</span>
          </Link>
          <button
            type="button"
            onClick={() => setMobileOpen((o) => !o)}
            className={toggleBtnCls}
            aria-label={mobileOpen ? "Close menu" : "Open menu"}
            aria-expanded={mobileOpen}
          >
            {mobileOpen ? "✕" : "☰"}
          </button>
        </div>

        {/* Slide-down menu anchored under the bar */}
        {mobileOpen && (
          <div className="absolute inset-x-0 top-14 max-h-[calc(100vh-3.5rem)] overflow-y-auto border-b border-cream-400/60 bg-cream-100 px-3 py-4 shadow-lg">
            <NavList pathname={pathname} onNavigate={() => setMobileOpen(false)} />
            <div className="mt-4 border-t border-cream-400/60 px-3 pt-4">
              <a
                href="https://github.com/projnanda/nandatown"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[0.85rem] font-medium text-ink-500 transition-colors hover:text-ink-900"
              >
                GitHub
              </a>
            </div>
          </div>
        )}
      </div>

      {/* Left sidebar, md and up */}
      <aside
        className={`sticky top-0 z-40 hidden h-screen shrink-0 flex-col border-r border-cream-400/60 bg-cream-100 transition-[width] duration-200 md:flex ${
          collapsed ? "w-14" : "w-60"
        }`}
      >
        {collapsed ? (
          <div className="flex flex-col items-center gap-3 px-2 pt-5">
            <Link href="/" aria-label="Nanda Town — home">
              <Image src="/brand/nandatown-logo.png" alt="" width={30} height={30} priority className="h-[30px] w-[30px] object-contain" />
            </Link>
            <button type="button" onClick={toggle} className={toggleBtnCls} aria-label="Expand sidebar" title="Expand sidebar">
              &raquo;
            </button>
          </div>
        ) : (
          <div className="flex items-start justify-between px-5 pt-6 pb-4">
            <Link href="/" className="flex items-center gap-3" aria-label="Nanda Town by Project NANDA — home">
              <Image src="/brand/nandatown-logo.png" alt="" width={34} height={34} priority className="h-[34px] w-[34px] object-contain" />
              <span className="flex flex-col">
                <span className="font-display text-[1.25rem] leading-none tracking-tight text-ink-900">Nanda Town</span>
                <span className="mt-1.5 font-mono text-[9px] uppercase leading-none tracking-[0.18em] text-ink-300">by Project NANDA</span>
              </span>
            </Link>
            <button type="button" onClick={toggle} className={toggleBtnCls} aria-label="Collapse sidebar" title="Collapse sidebar">
              &laquo;
            </button>
          </div>
        )}

        {collapsed ? (
          <div className="flex-1" />
        ) : (
          <nav className="flex-1 overflow-y-auto px-3 pb-4 pt-2">
            <NavList pathname={pathname} />
          </nav>
        )}

        {!collapsed && (
          <div className="border-t border-cream-400/60 px-5 py-4">
            <a
              href="https://github.com/projnanda/nandatown"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[0.85rem] font-medium text-ink-500 transition-colors hover:text-ink-900"
            >
              GitHub
            </a>
          </div>
        )}
      </aside>
    </>
  );
}
