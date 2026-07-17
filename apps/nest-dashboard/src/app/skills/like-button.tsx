"use client";

import { useEffect, useRef, useState } from "react";

interface Liker {
  name: string;
  avatar: string | null;
}

interface Props {
  skillId: string;
  initialCount: number;
  initialLikers: Liker[];
  initiallyLiked: boolean;
  viewer: { name: string; avatar: string | null } | null;
}

function HeartIcon({ filled }: { filled: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-[1.05rem] w-[1.05rem]"
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z" />
    </svg>
  );
}

/** Avatar with a broken-image fallback (Google photo URLs go stale). */
export function LikerAvatar({ name, avatar }: Liker) {
  const [failed, setFailed] = useState(false);
  if (!avatar || failed) {
    return (
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cream-300 font-mono text-[10px] text-ink-500">
        {name.charAt(0).toUpperCase()}
      </span>
    );
  }
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={avatar}
      alt=""
      referrerPolicy="no-referrer"
      onError={() => setFailed(true)}
      className="h-5 w-5 shrink-0 rounded-full border border-cream-400 object-cover"
    />
  );
}

/**
 * Audience-choice heart. Anyone sees the count and can open the list of
 * names; liking requires a Google sign-in (bot-proofing).
 * The server response is authoritative for both count and likers.
 */
export function LikeButton({
  skillId,
  initialCount,
  initialLikers,
  initiallyLiked,
  viewer,
}: Props) {
  const [liked, setLiked] = useState(initiallyLiked);
  const [count, setCount] = useState(initialCount);
  const [likers, setLikers] = useState<Liker[]>(initialLikers);
  const [showLikers, setShowLikers] = useState(false);
  const [showSignIn, setShowSignIn] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);

  // Close popovers on outside click or Escape.
  useEffect(() => {
    if (!showLikers && !showSignIn) return;
    function onDown(e: MouseEvent | TouchEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setShowLikers(false);
        setShowSignIn(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setShowLikers(false);
        setShowSignIn(false);
      }
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("touchstart", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("touchstart", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [showLikers, showSignIn]);

  async function toggle() {
    if (!viewer) {
      setShowSignIn((v) => !v);
      setShowLikers(false);
      return;
    }
    if (busy) return;
    setBusy(true);
    setError(null);

    const prevLiked = liked;
    const prevCount = count;
    const nextLiked = !liked;
    // Optimistic flip of the heart and count; the likers list waits for the
    // server, which returns the authoritative state (names collide, subs don't).
    setLiked(nextLiked);
    setCount((c) => Math.max(0, c + (nextLiked ? 1 : -1)));

    const rollback = () => {
      setLiked(prevLiked);
      setCount(prevCount);
    };

    try {
      const res = await fetch("/api/likes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ skillId, liked: nextLiked }),
      });
      if (res.status === 401) {
        rollback();
        setError("Your session expired — sign in again to vote.");
        setShowSignIn(true);
        return;
      }
      const data = (await res.json().catch(() => null)) as {
        count?: number;
        likers?: Liker[];
        error?: string;
      } | null;
      if (!res.ok) {
        rollback();
        setError(data?.error || "Couldn't save that. Try again.");
        return;
      }
      if (typeof data?.count === "number") setCount(data.count);
      if (Array.isArray(data?.likers)) setLikers(data.likers);
    } catch {
      rollback();
      setError("Couldn't save that. Try again.");
    } finally {
      setBusy(false);
    }
  }

  const signInHref = () => `/api/auth/google?next=${encodeURIComponent("/skills")}`;

  return (
    <div className="relative" ref={rootRef}>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={toggle}
          disabled={busy}
          aria-pressed={liked}
          aria-haspopup={viewer ? undefined : "menu"}
          aria-expanded={viewer ? undefined : showSignIn}
          aria-label={`${liked ? "Remove your like" : "Like this submission"} (${count} ${
            count === 1 ? "like" : "likes"
          })`}
          title={viewer ? (liked ? "Unlike" : "Like") : "Sign in to like"}
          className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[0.85rem] font-medium transition-colors ${
            liked
              ? "border-rust/40 bg-rust/10 text-rust"
              : "border-cream-400 bg-cream-50 text-ink-500 hover:border-rust/50 hover:text-rust"
          } ${busy ? "opacity-60" : ""}`}
        >
          <HeartIcon filled={liked} />
          <span className="tabular-nums">{count}</span>
        </button>
        {likers.length > 0 && (
          <button
            type="button"
            aria-haspopup="dialog"
            aria-expanded={showLikers}
            onClick={() => {
              setShowLikers((v) => !v);
              setShowSignIn(false);
            }}
            className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-400 underline-offset-4 hover:text-ink-900 hover:underline"
          >
            who?
          </button>
        )}
      </div>

      <p role="status" className={error ? "mt-1.5 text-[0.75rem] text-rust" : "sr-only"}>
        {error ?? ""}
      </p>

      {showSignIn && (
        <div className="absolute right-0 z-20 mt-2 w-60 rounded-2xl border border-cream-400 bg-cream-50 p-3 shadow-lg">
          <p className="mb-2.5 text-[0.82rem] leading-snug text-ink-500">
            Sign in to like — it keeps the audience-choice vote bot-free.
          </p>
          <div className="space-y-1.5">
            <a
              href={signInHref()}
              className="flex w-full items-center justify-center gap-2 rounded-full bg-ink-900 px-3 py-2 text-[0.85rem] font-medium text-cream-50 transition-opacity hover:opacity-85"
            >
              Continue with Google
            </a>
          </div>
        </div>
      )}

      {showLikers && likers.length > 0 && (
        <div className="absolute right-0 z-20 mt-2 max-h-56 w-56 overflow-y-auto rounded-2xl border border-cream-400 bg-cream-50 p-3 shadow-lg">
          <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-400">
            Liked by
          </p>
          <ul className="space-y-1.5">
            {likers.map((liker, i) => (
              <li key={`${liker.name}-${i}`} className="flex items-center gap-2">
                <LikerAvatar name={liker.name} avatar={liker.avatar} />
                <span className="truncate text-[0.85rem] text-ink-700">{liker.name}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
