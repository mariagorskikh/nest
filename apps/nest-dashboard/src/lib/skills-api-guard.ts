import type { NextRequest } from "next/server";
const MAX_SKILLS_BODY_BYTES = 256 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 30;
const hits = new Map<string, { count: number; resetAt: number }>();
function clientKey(request: NextRequest): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() || "unknown";
  }
  return request.headers.get("x-real-ip") || "local";
}
export function checkSkillsWriteRateLimit(request: NextRequest): Response | null {
  const key = clientKey(request);
  const now = Date.now();
  const bucket = hits.get(key);
  if (!bucket || now >= bucket.resetAt) {
    hits.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return null;
  }
  bucket.count += 1;
  if (bucket.count > RATE_LIMIT_MAX) {
    return Response.json({ error: "Rate limit exceeded. Try again later." }, { status: 429 });
  }
  return null;
}
export function requireSkillsWriteAuth(request: NextRequest): Response | null {
  const configured = process.env.NEST_SKILLS_API_KEY?.trim();
  if (!configured) {
    if (process.env.NODE_ENV === "production") {
      return Response.json(
        { error: "Skill writes are disabled until NEST_SKILLS_API_KEY is configured." },
        { status: 503 },
      );
    }
    return null;
  }
  const provided = request.headers.get("x-skills-api-key")?.trim();
  if (!provided || provided !== configured) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  return null;
}
export async function readSkillsJsonBody(
  request: NextRequest,
): Promise<{ body: Record<string, unknown> } | { error: Response }> {
  const lengthHeader = request.headers.get("content-length");
  if (lengthHeader) {
    const length = Number.parseInt(lengthHeader, 10);
    if (!Number.isNaN(length) && length > MAX_SKILLS_BODY_BYTES) {
      return {
        error: Response.json({ error: "Request body too large." }, { status: 413 }),
      };
    }
  }
  const raw = await request.text();
  if (raw.length > MAX_SKILLS_BODY_BYTES) {
    return {
      error: Response.json({ error: "Request body too large." }, { status: 413 }),
    };
  }
  try {
    return { body: JSON.parse(raw) as Record<string, unknown> };
  } catch {
    return { error: Response.json({ error: "Send a JSON body." }, { status: 400 }) };
  }
}
