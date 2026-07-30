import type { NextRequest } from "next/server";
import { revalidateTag } from "next/cache";
import { createSkill, listSkillsCached, SKILLS_CACHE_TAG, type SkillSourceType } from "@/lib/skills";

// This registry is read/written at request time, never prerendered.
export const dynamic = "force-dynamic";

function s(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

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
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return Response.json({ error: "Send a JSON body." }, { status: 400 });
  }

  const name = s(body.name);
  const sourceType = s(body.source_type) as SkillSourceType;
  const sourceUrl = s(body.source_url);
  const content = typeof body.content === "string" ? body.content : "";
  const email = s(body.email);
  const githubUsername = s(body.github_username).replace(/^@/, "");
  const forwarded = request.headers.get("x-forwarded-for");
  const submitterIp = forwarded
    ? forwarded.split(",")[0].trim() || null
    : request.headers.get("x-real-ip");

  if (!name) {
    return Response.json({ error: "name is required" }, { status: 400 });
  }
  if (!["url", "github", "content"].includes(sourceType)) {
    return Response.json(
      { error: "source_type must be one of: url, github, content" },
      { status: 400 },
    );
  }
  if ((sourceType === "url" || sourceType === "github") && !sourceUrl) {
    return Response.json(
      { error: "source_url is required for url/github submissions" },
      { status: 400 },
    );
  }
  if (sourceType === "content" && content.trim().length < 20) {
    return Response.json(
      { error: "content is required (and must be the full SkillMD)" },
      { status: 400 },
    );
  }

  try {
    const skill = await createSkill({
      name,
      author: s(body.author) || null,
      description: s(body.description) || null,
      source_type: sourceType,
      source_url: sourceType === "content" ? null : sourceUrl,
      content: sourceType === "content" ? content : null,
      endpoints: s(body.endpoints) || null,
      tags: s(body.tags) || null,
      reachable: null,
      email: email || null,
      github_username: githubUsername || null,
      submitter_ip: submitterIp,
    });
    revalidateTag(SKILLS_CACHE_TAG, "max");
    return Response.json({ skill }, { status: 201 });
  } catch (err) {
    console.error("POST /api/skills failed:", err);
    return Response.json({ error: "Failed to save the SkillMD." }, { status: 500 });
  }
}
