import { NextRequest, NextResponse } from "next/server";
import {
  STATE_COOKIE,
  baseUrl,
  cookiesSecure,
  encodeStateCookie,
  newState,
  safeNextPath,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

/** Step 1 of Google sign-in: bounce to Google's consent screen. */
export async function GET(req: NextRequest) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId || !process.env.AUTH_SECRET) {
    return NextResponse.json(
      { error: "Google sign-in is not configured on this server." },
      { status: 503 },
    );
  }

  const state = newState();
  const next = safeNextPath(req.nextUrl.searchParams.get("next"));

  const authorize = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", `${baseUrl()}/api/auth/google/callback`);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "openid profile");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("prompt", "select_account");

  const res = NextResponse.redirect(authorize);
  res.cookies.set(STATE_COOKIE, encodeStateCookie(state, next), {
    httpOnly: true,
    secure: cookiesSecure(),
    sameSite: "lax",
    path: "/",
    maxAge: 600,
  });
  return res;
}
