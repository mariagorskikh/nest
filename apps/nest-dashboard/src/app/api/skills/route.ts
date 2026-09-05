import type { NextRequest } from "next/server";
import { revalidateTag } from "next/cache";
import { createSkill, listSkillsCached, SKILLS_CACHE_TAG } from "@/lib/skills";
import { readBoundedJson, RequestTooLargeError } from "@/lib/bounded-json";
import {
  MAX_SKILL_REQUEST_BYTES,
  validateSkillSubmission,
} from "@/lib/skill-submission";

// This registry is read/written at request time, never prerendered.
export const dynamic = "force-dynamic";

/**
 * GET /api/skills
 * Returns every submitted SkillMD as JSON. An agent can call this to
 * discover which skills are available.
 */
export async function GET() {
  const skills = await listSkillsCached();
  return Response.json({ count: skills.length, skills });
}

/**
 * POST /api/skills
 * Register a SkillMD programmatically. Body (JSON):
 *   { name, source_type: "url"|"github"|"content", source_url?, content?,
 *     author?, description?, endpoints?, tags? }
 */
export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await readBoundedJson(request, MAX_SKILL_REQUEST_BYTES);
  } catch (error) {
    if (error instanceof RequestTooLargeError) {
      return Response.json({ error: error.message }, { status: 413 });
    }
    return Response.json({ error: "Send a JSON body." }, { status: 400 });
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return Response.json({ error: "Send a JSON object." }, { status: 400 });
  }

  const forwarded = request.headers.get("x-forwarded-for");
  const submitterIp = forwarded
    ? forwarded.split(",")[0].trim() || null
    : request.headers.get("x-real-ip");
  const validated = validateSkillSubmission(body as Record<string, unknown>);
  if (!validated.ok) {
    return Response.json({ error: validated.error }, { status: 400 });
  }

  try {
    const skill = await createSkill({
      ...validated.value,
      submitter_ip: submitterIp,
    });
    revalidateTag(SKILLS_CACHE_TAG, "max");
    return Response.json({ skill }, { status: 201 });
  } catch (err) {
    console.error("POST /api/skills failed:", err);
    return Response.json({ error: "Failed to save the SkillMD." }, { status: 500 });
  }
}
