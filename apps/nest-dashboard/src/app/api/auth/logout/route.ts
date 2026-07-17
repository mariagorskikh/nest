import { NextRequest, NextResponse } from "next/server";
import { SESSION_COOKIE, sameOrigin } from "@/lib/auth";

export const dynamic = "force-dynamic";

/** Clears the session cookie. POST-only so a stray <img> tag can't log people out. */
export async function POST(req: NextRequest) {
  if (!sameOrigin(req.headers.get("origin"), req.headers.get("host"))) {
    return NextResponse.json({ error: "Bad origin" }, { status: 403 });
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.set(SESSION_COOKIE, "", { path: "/", maxAge: 0 });
  return res;
}
