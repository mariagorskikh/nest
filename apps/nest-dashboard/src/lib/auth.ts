import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";

/**
 * Minimal OAuth session layer for the audience-choice likes.
 *
 * Sessions are HMAC-SHA256-signed cookies (node:crypto only, no extra
 * dependencies). Google sign-in runs the standard server-side
 * authorization-code flow in src/app/api/auth/. Required env:
 *   AUTH_SECRET            random string, signs session cookies
 *   APP_BASE_URL           e.g. https://nandatown.projectnanda.org
 *   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
 */

export interface SessionUser {
  /** Stable per-provider id, e.g. "google:1234". */
  sub: string;
  name: string;
  avatar: string | null;
  provider: "google";
}

export const SESSION_COOKIE = "nt_session";
export const STATE_COOKIE = "nt_oauth_state";
export const SESSION_TTL_S = 60 * 60 * 24 * 30;

export function baseUrl(): string {
  return (process.env.APP_BASE_URL ?? "http://localhost:3000").replace(/\/+$/, "");
}

export function cookiesSecure(): boolean {
  return baseUrl().startsWith("https:");
}

function secret(): Buffer {
  const s = process.env.AUTH_SECRET;
  if (!s) throw new Error("AUTH_SECRET is not set");
  return Buffer.from(s, "utf8");
}

function sign(payload: string): string {
  return createHmac("sha256", secret()).update(payload).digest("base64url");
}

export function encodeSession(user: SessionUser): string {
  const body = Buffer.from(
    JSON.stringify({ ...user, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_S }),
  ).toString("base64url");
  return `${body}.${sign(body)}`;
}

export function decodeSession(token: string | undefined): SessionUser | null {
  if (!token) return null;
  try {
    const dot = token.lastIndexOf(".");
    if (dot < 0) return null;
    const body = token.slice(0, dot);
    const mac = Buffer.from(token.slice(dot + 1));
    const expected = Buffer.from(sign(body));
    if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) return null;
    const data = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (typeof data.exp !== "number" || data.exp * 1000 < Date.now()) return null;
    if (typeof data.sub !== "string" || typeof data.name !== "string") return null;
    if (data.provider !== "google") return null;
    return {
      sub: data.sub,
      name: data.name,
      avatar: typeof data.avatar === "string" ? data.avatar : null,
      provider: data.provider,
    };
  } catch {
    return null;
  }
}

/** Read the signed-in user inside a server component or server action. */
export async function getSessionUser(): Promise<SessionUser | null> {
  const jar = await cookies();
  return decodeSession(jar.get(SESSION_COOKIE)?.value);
}

export function newState(): string {
  return randomBytes(16).toString("hex");
}

/** Packs the CSRF state + post-login destination into one cookie value. */
export function encodeStateCookie(state: string, next: string): string {
  return Buffer.from(JSON.stringify({ state, next })).toString("base64url");
}

export function decodeStateCookie(
  raw: string | undefined,
): { state: string; next: string } | null {
  if (!raw) return null;
  try {
    const data = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
    if (typeof data.state !== "string" || typeof data.next !== "string") return null;
    return { state: data.state, next: safeNextPath(data.next) };
  } catch {
    return null;
  }
}

/**
 * CSRF backstop for state-changing POSTs. Compares the Origin header against
 * the configured public origin (APP_BASE_URL) and the raw Host header —
 * NOT req.nextUrl, which reflects the container's internal address behind
 * the reverse proxy.
 */
export function sameOrigin(originHeader: string | null, hostHeader: string | null): boolean {
  if (!originHeader) return true;
  try {
    const host = new URL(originHeader).host;
    return host === new URL(baseUrl()).host || (!!hostHeader && host === hostHeader);
  } catch {
    return false;
  }
}

/** Same-site absolute paths only — no "//evil.com", no full URLs. */
export function safeNextPath(raw: string | null): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) {
    return "/skills";
  }
  return raw;
}
