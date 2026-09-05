"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useSyncExternalStore } from "react";

type NavChild = { href: string; label: string; sub?: boolean };
type NavItem = {
  href: string;
  label: string;
  external?: boolean;
  children?: NavChild[];
};

const items: NavItem[] = [
  { href: "/prgallery", label: "Protocols + Plugins (PRs)" },
  { href: "/docs", label: "Docs" },
  { href: "/experiments", label: "Experiments" },
  { href: "/leaderboard", label: "Leaderboard" },
  { href: "/visualizer", label: "Visualizer" },
  { href: "/agents", label: "Agents (demo)" },
  {
    href: "",
    label: "NandaHacks",
    children: [
      {
        href: "https://nandahack.media.mit.edu",
        label: "NandaHack x HCLTech",
      },
      { href: "/skills", label: "Skills Registry", sub: true },
      {
        href: "/pravahack",
        label: "NandaHack x Prava: Agentic Commerce Hackathon",
      },
    ],
  },
];

const SIDEBAR_STORAGE_KEY = "nt-sidebar-collapsed";
const SIDEBAR_CHANGE_EVENT = "nt-sidebar-collapsed-change";

function subscribeSidebarPreference(onStoreChange: () => void) {
  const onStorage = (event: StorageEvent) => {
    if (event.key === SIDEBAR_STORAGE_KEY) onStoreChange();
  };
  window.addEventListener("storage", onStorage);
  window.addEventListener(SIDEBAR_CHANGE_EVENT, onStoreChange);
  return () => {
    window.removeEventListener("storage", onStorage);
    window.removeEventListener(SIDEBAR_CHANGE_EVENT, onStoreChange);
  };
}

function sidebarPreferenceSnapshot() {
  return localStorage.getItem(SIDEBAR_STORAGE_KEY) === "1";
}

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
            {!item.href ? (
              <span className={linkCls(false)}>{item.label}</span>
            ) : item.external ? (
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
                    <li
                      key={child.href}
                      className={child.sub ? "ml-3 border-l border-cream-400/60 pl-2" : undefined}
                    >
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
  const collapsed = useSyncExternalStore(
    subscribeSidebarPreference,
    sidebarPreferenceSnapshot,
    () => false,
  );
  const [mobileOpenPath, setMobileOpenPath] = useState<string | null>(null);
  const mobileOpen = mobileOpenPath === pathname;

  function toggle() {
    localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? "0" : "1");
    window.dispatchEvent(new Event(SIDEBAR_CHANGE_EVENT));
  }

  const toggleBtnCls =
    "flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-cream-400/60 text-[15px] leading-none text-ink-400 transition-colors hover:bg-cream-200/60 hover:text-ink-900";

  return (
    <>
      {/* Slim top bar with menu button, mobile only */}
      <div className="sticky top-0 z-50 md:hidden">
        <div className="flex h-14 items-center justify-between border-b border-cream-400/60 bg-cream-100/85 px-5 backdrop-blur-xl">
          <Link href="/" className="flex items-center gap-2.5" aria-label="Nanda Town — home">
            <Image src="/brand/nanda-logo-color.png" alt="" width={28} height={28} className="h-7 w-7 object-contain" />
            <span className="font-display text-[1.15rem] leading-none tracking-tight text-ink-900">Nanda Town</span>
          </Link>
          <button
            type="button"
            onClick={() => setMobileOpenPath(mobileOpen ? null : pathname)}
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
            <NavList pathname={pathname} onNavigate={() => setMobileOpenPath(null)} />
            <div className="mt-4 flex items-center gap-5 border-t border-cream-400/60 px-3 pt-4">
              <a
                href="https://github.com/projnanda/nandatown"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[0.85rem] font-medium text-ink-500 transition-colors hover:text-ink-900"
              >
                GitHub
              </a>
              <a
                href="https://nanda.town"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[0.85rem] font-medium text-ink-500 transition-colors hover:text-ink-900"
              >
                nanda.town
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
              <Image src="/brand/nanda-logo-color.png" alt="" width={30} height={30} priority className="h-[30px] w-[30px] object-contain" />
            </Link>
            <button type="button" onClick={toggle} className={toggleBtnCls} aria-label="Expand sidebar" title="Expand sidebar">
              &raquo;
            </button>
          </div>
        ) : (
          <div className="flex items-start justify-between px-5 pt-6 pb-4">
            <Link href="/" className="flex items-center gap-3" aria-label="Nanda Town by Project NANDA — home">
              <Image src="/brand/nanda-logo-color.png" alt="" width={34} height={34} priority className="h-[34px] w-[34px] object-contain" />
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
          <div className="flex items-center gap-5 border-t border-cream-400/60 px-5 py-4">
            <a
              href="https://github.com/projnanda/nandatown"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[0.85rem] font-medium text-ink-500 transition-colors hover:text-ink-900"
            >
              GitHub
            </a>
            <a
              href="https://nanda.town"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[0.85rem] font-medium text-ink-500 transition-colors hover:text-ink-900"
            >
              nanda.town
            </a>
          </div>
        )}
      </aside>
    </>
  );
}
