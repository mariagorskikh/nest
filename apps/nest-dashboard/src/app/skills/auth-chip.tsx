"use client";

import { useState } from "react";

interface Props {
  viewer: { name: string; avatar: string | null; provider: string } | null;
}

/** "Voting as …" pill for the registry header, with sign-in/out. */
export function AuthChip({ viewer }: Props) {
  const [busy, setBusy] = useState(false);
  const [avatarFailed, setAvatarFailed] = useState(false);

  if (!viewer) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[0.82rem] text-ink-400">Sign in to vote:</span>
        <a
          href={`/api/auth/google?next=${encodeURIComponent("/skills")}`}
          className="rounded-full bg-ink-900 px-3.5 py-1.5 text-[0.82rem] font-medium text-cream-50 transition-opacity hover:opacity-85"
        >
          Google
        </a>
      </div>
    );
  }

  async function signOut() {
    setBusy(true);
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      window.location.reload();
    }
  }

  return (
    <div className="flex items-center gap-2.5">
      {viewer.avatar && !avatarFailed ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={viewer.avatar}
          alt=""
          referrerPolicy="no-referrer"
          onError={() => setAvatarFailed(true)}
          className="h-6 w-6 rounded-full border border-cream-400 object-cover"
        />
      ) : (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cream-300 font-mono text-[11px] text-ink-500">
          {viewer.name.charAt(0).toUpperCase()}
        </span>
      )}
      <span className="text-[0.85rem] text-ink-700">
        Voting as <strong className="font-semibold">{viewer.name}</strong>
      </span>
      <button
        type="button"
        onClick={signOut}
        disabled={busy}
        className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-400 underline-offset-4 hover:text-ink-900 hover:underline disabled:opacity-50"
      >
        sign out
      </button>
    </div>
  );
}
