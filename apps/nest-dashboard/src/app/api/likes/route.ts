import { NextRequest, NextResponse } from "next/server";
import { SESSION_COOKIE, decodeSession, sameOrigin } from "@/lib/auth";
import { revalidateTag } from "next/cache";
import { LIKES_CACHE_TAG, likeSkill, listAllLikesCached, listLikers, unlikeSkill } from "@/lib/likes";

export const dynamic = "force-dynamic";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Public read: like counts and liker names per skill.
 * Provider subs are intentionally stripped before the response.
 */
export async function GET() {
  const all = await listAllLikesCached();
  const likes: Record<string, { count: number; likers: { name: string; avatar: string | null }[] }> =
    {};
  for (const [skillId, entry] of Object.entries(all)) {
    likes[skillId] = { count: entry.count, likers: entry.likers };
  }
  return NextResponse.json({ likes });
}

/* Light per-user throttle. Single-container deployment, so in-memory is fine. */
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 30;
const buckets = new Map<string, { start: number; n: number }>();

function throttled(sub: string): boolean {
  const now = Date.now();
  const bucket = buckets.get(sub);
  if (!bucket || now - bucket.start > WINDOW_MS) {
    buckets.set(sub, { start: now, n: 1 });
    if (buckets.size > 5000) {
      for (const [key, b] of buckets) {
        if (now - b.start > WINDOW_MS) buckets.delete(key);
      }
    }
    return false;
  }
  bucket.n += 1;
  return bucket.n > MAX_PER_WINDOW;
}

/** Toggle a like. Requires a signed-in session (Google or GitHub). */
export async function POST(req: NextRequest) {
  const user = decodeSession(req.cookies.get(SESSION_COOKIE)?.value);
  if (!user) {
    return NextResponse.json(
      { error: "Sign in with Google or GitHub to like submissions." },
      { status: 401 },
    );
  }

  // Same-origin check on top of the SameSite=Lax cookie.
  if (!sameOrigin(req.headers.get("origin"), req.headers.get("host"))) {
    return NextResponse.json({ error: "Bad origin" }, { status: 403 });
  }

  if (throttled(user.sub)) {
    return NextResponse.json({ error: "Slow down a little." }, { status: 429 });
  }

  let body: { skillId?: unknown; liked?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const skillId = typeof body.skillId === "string" ? body.skillId : "";
  if (!UUID_RE.test(skillId) || typeof body.liked !== "boolean") {
    return NextResponse.json(
      { error: "Expected { skillId: uuid, liked: boolean }." },
      { status: 400 },
    );
  }

  if (body.liked) {
    const ok = await likeSkill(skillId, user);
    if (!ok) {
      return NextResponse.json({ error: "No such skill." }, { status: 404 });
    }
  } else {
    await unlikeSkill(skillId, user.sub);
  }

  revalidateTag(LIKES_CACHE_TAG, "max");
  // Return the authoritative list so the client never has to guess
  // (display names collide; provider subs stay server-side).
  const likers = await listLikers(skillId);
  return NextResponse.json({ count: likers.length, liked: body.liked, likers });
}
