import { NextRequest, NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_TTL_S,
  STATE_COOKIE,
  baseUrl,
  cookiesSecure,
  decodeStateCookie,
  encodeSession,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

/** Step 2 of Google sign-in: exchange the code, set the session cookie. */
export async function GET(req: NextRequest) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

  const fail = (code: string) => {
    const res = NextResponse.redirect(
      `${baseUrl()}/skills?auth_error=${code}`,
    );
    res.cookies.set(STATE_COOKIE, "", { path: "/", maxAge: 0 });
    return res;
  };

  if (!clientId || !clientSecret || !process.env.AUTH_SECRET) {
    return fail("not_configured");
  }

  const code = req.nextUrl.searchParams.get("code");
  const state = req.nextUrl.searchParams.get("state");
  const stored = decodeStateCookie(req.cookies.get(STATE_COOKIE)?.value);
  if (!code || !state || !stored || stored.state !== state) {
    return fail("interrupted");
  }

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: `${baseUrl()}/api/auth/google/callback`,
      grant_type: "authorization_code",
    }),
  });
  if (!tokenRes.ok) return fail("rejected");

  const tokens = (await tokenRes.json()) as { id_token?: string };
  if (!tokens.id_token) return fail("no_identity");

  // The id_token arrived directly from Google's token endpoint over TLS in
  // this same request, so its payload is trusted without JWKS verification.
  let payload: { sub?: string; name?: string; picture?: string };
  try {
    payload = JSON.parse(
      Buffer.from(tokens.id_token.split(".")[1], "base64url").toString("utf8"),
    );
  } catch {
    return fail("no_identity");
  }
  if (!payload.sub) return fail("no_identity");

  const session = encodeSession({
    sub: `google:${payload.sub}`,
    name: payload.name?.trim() || "Google user",
    avatar: payload.picture ?? null,
    provider: "google",
  });

  const res = NextResponse.redirect(`${baseUrl()}${stored.next}`);
  res.cookies.set(SESSION_COOKIE, session, {
    httpOnly: true,
    secure: cookiesSecure(),
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL_S,
  });
  res.cookies.set(STATE_COOKIE, "", { path: "/", maxAge: 0 });
  return res;
}
