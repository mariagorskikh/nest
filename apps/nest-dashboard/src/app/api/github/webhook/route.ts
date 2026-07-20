import { createHmac, timingSafeEqual } from "node:crypto";
import { revalidatePath, revalidateTag } from "next/cache";
import { NextRequest, NextResponse } from "next/server";
import { PR_CACHE_TAG } from "@/lib/hackathon-github";

export const dynamic = "force-dynamic";

const DEBOUNCE_MS = 60_000;
let lastRevalidate = 0;
let trailingTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * GitHub webhook receiver: the moment a hackathon PR is opened, merged,
 * reopened, or edited, bust the PR data cache and re-render every
 * /hackathon page. Between webhook deliveries the pages still self-refresh
 * on the normal revalidate window, so this is an accelerator, not a
 * dependency.
 *
 * Configure on the repo (Settings → Webhooks):
 *   Payload URL:  https://nandatown.projectnanda.org/api/github/webhook
 *   Content type: application/json
 *   Secret:       GITHUB_WEBHOOK_SECRET from /opt/nandatown/db.env
 *   Events:       Pull requests
 */

// Only these PR actions change what the marketplace shows. Notably absent:
// "synchronize" (fires on every push to any open PR) and review/label/assign
// churn — including them would let normal repo activity blow the anonymous
// GitHub rate budget for no visible change.
const REVALIDATING_ACTIONS = new Set([
  "opened",
  "reopened",
  "closed", // covers merges (merged=true) and plain closes
  "edited",
  "ready_for_review",
]);

function bust() {
  lastRevalidate = Date.now();
  revalidateTag(PR_CACHE_TAG, "max");
  // 'layout' invalidates /hackathon and everything beneath it (layers,
  // submissions) in one call.
  revalidatePath("/prgallery", "layout");
}

export async function POST(req: NextRequest) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    return NextResponse.json(
      { error: "Webhook not configured on this server." },
      { status: 503 },
    );
  }

  const payload = await req.text();
  const signature = req.headers.get("x-hub-signature-256") ?? "";
  const expected =
    "sha256=" + createHmac("sha256", secret).update(payload).digest("hex");
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return NextResponse.json({ error: "Bad signature" }, { status: 401 });
  }

  const event = req.headers.get("x-github-event") ?? "";
  if (event === "ping") {
    return NextResponse.json({ ok: true, pong: true });
  }
  if (event !== "pull_request") {
    return NextResponse.json({ ok: true, ignored: event });
  }

  let action = "unknown";
  let merged = false;
  try {
    const body = JSON.parse(payload) as {
      action?: string;
      pull_request?: { merged?: boolean };
    };
    action = body.action ?? "unknown";
    merged = body.pull_request?.merged === true;
  } catch {
    /* signature already verified; parse only informs routing below */
  }

  if (!REVALIDATING_ACTIONS.has(action)) {
    return NextResponse.json({ ok: true, ignored_action: action });
  }

  // A merge is the moment that matters most — never let the debounce swallow
  // it; bust immediately regardless of the window.
  if (merged) {
    if (trailingTimer) {
      clearTimeout(trailingTimer);
      trailingTimer = null;
    }
    bust();
    return NextResponse.json({ ok: true, revalidated: true, action, merged });
  }

  // Leading + trailing debounce: bust now if the window is clear, otherwise
  // schedule a single deferred bust so an event arriving mid-window (e.g. a
  // late edit) still lands instead of being silently dropped.
  const now = Date.now();
  if (now - lastRevalidate >= DEBOUNCE_MS) {
    bust();
    return NextResponse.json({ ok: true, revalidated: true, action });
  }

  if (!trailingTimer) {
    trailingTimer = setTimeout(() => {
      trailingTimer = null;
      bust();
    }, DEBOUNCE_MS - (now - lastRevalidate));
  }
  return NextResponse.json({ ok: true, debounced: true, action });
}
